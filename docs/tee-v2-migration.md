# Nyx — TEE v2 Migration Brief

> Authoritative migration doc for moving from the **MagicBlock PER + software-TEE** architecture to a **dedicated attested-TEE on Phala Cloud (Intel TDX via dstack)** architecture. Replaces the outdated `tee_v2_status_and_migration_brief.md` from 2026-05-11.
>
> **Last revised:** 2026-05-25 (revision 2 — incorporates the Phala/dstack docs deep-dive + the four locked v2 decisions).
> **Branch:** `nyx-v2-onchain-hardening`.
> **Read after:** [`CLAUDE.md`](../CLAUDE.md), [`docs/ARCHITECTURE.md`](ARCHITECTURE.md), [`CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md), [`docs/v3.5-migration.md`](v3.5-migration.md).
> **Pairs with:**
>   * [`docs/tee-api-openapi.yaml`](tee-api-openapi.yaml) — the wire contract.
>   * [`docs/tee-architecture.md`](tee-architecture.md) — the in-TEE design.
>   * [`docs/tee-attestation-flow.md`](tee-attestation-flow.md) — the attestation deep-dive (who verifies what, when, and what failure means).

---

## 0. TL;DR

The on-chain custody side has reached a stable, audited shape after v2 / v3 / v3.1 / v3.5 / Phase 1c-hard. The matching side is currently routed through MagicBlock's Ephemeral Rollup (PER) because that was the lowest-friction way to keep order intent off L1 during the v1 / hackathon-demo phase. **That phase is over.** The next architecture pins matching inside an Intel TDX attested enclave running on **Phala Cloud** (managed dstack), and *deletes* the PER matching plumbing entirely.

### Six decisions locked for v2 (do not re-litigate without explicit re-approval)

| # | Decision | Choice | Rationale |
|---|---|---|---|
| **D1** | Hosting | Phala Cloud (managed dstack, Intel TDX) | Fastest path to a real attested deployment. Same Docker image runs on dstack-cloud (GCP/AWS) or self-hosted bare metal later — not a lock-in. |
| **D2** | TEE pubkey rotation gate | Admin multisig (Squads 3-of-5) only — verifies TDX quote off-chain via `dstack-verifier` Docker image | Avoids the multi-week port of `dcap-qvl` to Solana BPF. On-chain quote verification deferred to v3. |
| **D3** | API edge | Custom domain via dstack-ingress (`api.nyx.example.com`) with RA-HTTPS + `/evidences/` | TLS terminates inside the enclave; cert private key never leaves the TEE; clients verify via the standard dstack-ingress evidence pattern. |
| **D4** | Groth16 prover location | Inside the TEE (ark-groth16) | Witness never leaves the enclave. ~5-10% TDX overhead is within budget. Phase-1 benchmark validates; fallback is TEE-signed-public-input + external prover. |
| **D5** | Matching cadence | Frequent-batch-auction with `BATCH_MS = 2000` default, tunable per market via on-chain `MatchingConfig.batch_ms` | Hot order book + batched clearing. The settle pipeline (~2-3 s finality) is the lower bound; ticking faster queues batches in memory. `VALID_MATCH_BATCH` + `BatchValidityMarker` are structurally batch primitives — continuous matching is incompatible without a circuit rewrite. UCP is the dark-pool privacy pattern (timing-uniform fills). |
| **D6** | Indexer architecture | Inside the TEE, shared in-memory state with the matcher via `tokio RwLock` | The TEE already holds the Merkle mirror + nullifier/lock sets in RAM. Exposing `/tree/*` + `/transparency` is essentially free. One deployment, one attestation chain. Clients who don't trust the TEE for reads retain the trustless fallback (read `VaultConfig.current_root` + PDAs directly from Solana, re-derive the Merkle path themselves). |

Trigger conditions for re-evaluating each decision are documented in [`docs/tee-architecture.md`](tee-architecture.md) §13.

What this document is for:

* A component-by-component classification of **what stays, what gets deleted, what gets replaced, and what's new**, so the agents and contributors who do the work don't have to re-derive this every time.
* The migration sequence, with explicit dependencies between phases.
* The risk register and rollback positions.
* The list of follow-ups that are deferred to *after* the TEE lands (e.g. Light Protocol nullifier integration).

What this document is **not** for:

* Detailed cryptographic specs — those live in [`CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md).
* The wire contract for the TEE API — that lives in [`docs/tee-api-openapi.yaml`](tee-api-openapi.yaml).
* Implementation guidance for specific Phala primitives — those will land in `docs/tee-architecture.md` once the TEE work begins.

---

## 1. Where we are right now (architecture audit, 2026-05-24)

### 1.1 What's on-chain and deployed (devnet, `nyx-v2-onchain-hardening`)

**Program IDs (post-Phase-1c-hard):**

* `vault` — `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`
* `matching_engine` — `6EasFxo6RCWrK4KAwcdUJqL4KjReLC3rtah8EtHgHSqe`

(The legacy v1 deployment on `main` lives at different program IDs and is unaffected.)

**Vault instructions (the custody layer — solid, stays unchanged across the migration):**

| Ix | Purpose |
|---|---|
| `initialize(tee_pubkey, root_key)` | global `VaultConfig` singleton |
| `rotate_root_key(new_root_key)` | PER root-key rotation; will pick up TEE-attestation gating in v2 |
| `realloc_vault_config()` | upgrade-safe size bump |
| `set_protocol_config(commitment, fee_bps)` | admin fee config |
| `reset_merkle_tree()` | devnet-only tree wipe |
| `create_wallet(commitment, proof)` | VALID_WALLET_CREATE → `WalletEntry` PDA |
| `deposit(amount, owner, nonce, blinding_r)` | SPL → note commitment leaf, `outstanding[mint]++` |
| `lock_note(commit, order_id, expiry, amount, mint, root, proof)` | VALID_INPUT-gated lock (v2) |
| `release_lock(commit)` | expired lock GC |
| `withdraw(commit, nullifier, root, amount, proof)` | VALID_SPEND → `outstanding[mint]--` + SPL out |
| `verify_match_batch(merkle_root, expiry, proof)` | v3.5: VALID_MATCH_BATCH → `BatchValidityMarker` PDA (one per batch) |
| `tee_forced_settle_batched(payload, match_index, merkle_proof)` | v3.5: Ed25519 + 4-level Merkle inclusion + atomic state mutation |
| `close_batch_validity_marker(merkle_root)` | v3.5: reclaim marker rent after last settle |

**Matching engine instructions (heavily PER-coupled — most will be deleted):**

| Ix | Status in v2 |
|---|---|
| `init_market(args)` | **KEEP** — markets are still discrete objects on-chain |
| `init_mock_oracle(twap)` | KEEP (devnet only) / replace with real Pyth in prod |
| `configure_access(members)` | KEEP for the moment; revisit when TEE auth lands |
| `delegate_dark_clob(market)` | **DELETE** — no MagicBlock delegation in v2 |
| `delegate_matching_config(market)` | **DELETE** |
| `delegate_batch_results(market)` | **DELETE** |
| `init_pending_order_slot(market, slot_idx)` | **DELETE** — no PendingOrder PDAs in v2 |
| `delegate_pending_order(market, slot_idx)` | **DELETE** |
| `submit_order(args)` | **DELETE** — moves into the TEE process as an authenticated REST/WS endpoint |
| `cancel_order(market, slot_idx)` | **DELETE** — same |
| `run_batch(market)` | **DELETE** — matching moves into the TEE |
| `commit_market_state()` | **DELETE** — no ER state commits in v2 |
| `undelegate_market()` | **DELETE** |

Net surviving matching_engine surface in v2: **just `init_market` + `init_mock_oracle` + `configure_access`**. The program shrinks from ~2000 LOC to ~200.

### 1.2 What works end-to-end today (validated on devnet, 2026-05-24)

The post-Phase-1c-hard validation set:

* `cargo test --workspace` — 93 tests pass (host-side unit + litesvm integration)
* `vitest run --root packages/sdk` — 95 passed / 17 skipped (devnet/ER/CN/PER auto-skip)
* `devnet-trade-flow.test.ts` — L1 happy path
* `change-note-flow.test.ts` — 5 scenarios (over-collateralised + change note, partial fill + re-lock, privacy regression, multi-batch continuation, real-fee withdrawal)
* `er-trade-flow.test.ts` — ER round-trip
* Litesvm regression test in `programs/matching_engine/tests/tee_forced_settle_batched.rs` exercising 2 real matches against 1 shared `BatchValidityMarker`

PTAU files (`powersOfTau28_hez_final_16.ptau` + `_18.ptau`) are SHA-256-pinned in `scripts/download-ptau.sh` since `a67419f` (2026-05-24).

### 1.3 What's already on the "not yet shipped" list

From [`ARCHITECTURE.md`](ARCHITECTURE.md#what-is-not-yet-shipped) + [`CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md#13-what-is-not-yet-implemented):

| Item | Disposition in v2 migration |
|---|---|
| Real Phase-2 ceremony (replace deterministic dev contribution) | Pre-mainnet ask; not blocking v2 migration. |
| Real TDX/SEV TEE + remote attestation | **This is the migration.** |
| Browser prover (`WebProverSuite`) | Out of scope for v2 migration. UX upgrade for later. |
| Indexer service | **Subsumed by TEE-as-indexer** — see §4. |
| `undelegate_pending_order` | DELETED in v2; PendingOrder PDAs go away entirely. |
| `force_undelegate_on_l1` admin ix | **Skipped** — PER goes away, so emergency-undelegate ix is moot. |
| Real protocol-owner keypair | Deferred to post-TEE governance setup. |
| Continuous ER↔L1 commit scheduler | DELETED — no ER in v2. |
| Oracle refresh in long-running ER sessions | DELETED. |
| PER JWT session manager | **Replaced** by TEE-authenticated REST + WS sessions. |
| Self-trade prevention | Moves from `run_batch` (deleted) into the TEE's matching loop. |
| Light Protocol compressed-nullifier integration | **Deferred** to post-TEE — see §10 (Appendix A). |

---

## 2. Why migrate (the problem statement, written so the answer is self-evident)

The PER + software-TEE architecture worked for the v1 / hackathon-demo phase, but four structural problems compound the longer we leave it:

1. **Trust hole.** The TEE is a software Ed25519 keypair. A compromised TEE host can deny liveness (refuse to match) and silently see all order intent (no attestation gate between client and matcher). On-chain custody invariants still hold — value can't be stolen — but the *privacy* property the product is built around is operationally trust-me. This is the biggest open trust gap in the system.
2. **The PendingOrder PDA model doesn't scale to market-makers.** Each user gets 4 slots per market. Each slot is an L1-init + L1-delegate transaction. An MM running ~100 concurrent quotes would need ~200 L1 setup txs before sending the first order, plus ~$50-100 in rent permanently locked. The model is structurally retail-only.
3. **No indexer means clients rebuild the shadow tree every session.** The "no-indexer tax" (Merkle replay + pending-slot probing + BatchResults ring scanning) is documented in `apps/demo/ARCHITECTURE.md` as ~40% of the demo's complexity. Every new SDK consumer re-pays this tax.
4. **MagicBlock is a dependency we don't fundamentally need.** PER gave us a "private compute substrate" for hidden order intent — but once we have a real attested TEE, the TEE itself is the compute substrate. Keeping PER on top would mean maintaining two privacy layers + two operational footprints.

A dedicated attested TEE solves all four:

* TEE attestation closes the trust hole at the operational level.
* In-TEE order book (RAM, not PDA-per-slot) supports MM-scale.
* TEE is the indexer (it already has all the state in memory; exposing it via REST + WS is free).
* MagicBlock dependency disappears entirely.

---

## 3. Component-by-component classification

This is the load-bearing section. Each row tells you exactly what happens to each piece of the system in the migration.

### 3.1 Vault program (`programs/vault/`)

**Disposition: UNCHANGED. Custody-side is stable.**

| Component | Disposition | Notes |
|---|---|---|
| `lib.rs` `#[program]` entrypoints | Keep 13 of 14 ixs as-is; **delete `rotate_root_key`** (PER artifact); **add `set_tee_pubkey`** (admin-multisig-gated). | The previous revision of this doc claimed `rotate_root_key` would be "attestation-gated" — that was wrong. `rotate_root_key` rotates `vault_config.root_key`, which is the MagicBlock Permission Group root, not the TEE signing key. It's PER-only and gets deleted with the rest of PER. |
| `vault_config.root_key` field | **Delete in Phase 5** | The "Permission Group root" was MagicBlock-specific. After PER is gone the field is dead weight. Schedule the removal via `realloc_vault_config` along with the other Phase 5 cleanups. |
| `state.rs` — `VaultConfig`, `WalletEntry`, `NullifierEntry`, `ConsumedNoteEntry`, `NoteLock`, `OutstandingMint`, `BatchValidityMarker` | Keep as-is | Custody state model is finalised post-Phase 1c-hard. |
| `merkle.rs` (Poseidon Merkle tree depth 20, 32-root ring buffer) | Keep as-is | The v3.5 batched circuit + leaf-hash arity is tightly coupled to this. |
| `instructions/` (all ixs including `tee_forced_settle_batched`, `verify_match_batch`, `close_batch_validity_marker`) | Keep as-is | Custody operations are TEE-driven, not PER-driven; works identically with the new TEE. |
| `zk/` (verifier keys for VALID_WALLET_CREATE, VALID_SPEND, VALID_INPUT, VALID_MATCH_BATCH N=16) | Keep as-is | Circuits don't change. |
| TEE pubkey rotation flow | **New ix: `set_tee_pubkey(new_pubkey)`** | Admin-multisig-gated (`vault_config.admin` must be a Squads multisig). The multisig verifies the new TEE's TDX quote off-chain via the `dstack-verifier` Docker image before signing — see [`docs/tee-attestation-flow.md`](tee-attestation-flow.md) §5. No on-chain quote verification in v2; deferred to v3 (see §6 R1 below). |

**Why this layer doesn't move:** every cryptographic invariant the on-chain code enforces (`outstanding[mint] ≤ vault_token`, conservation per-leg, `VALID_INPUT`-gated locks, `VALID_MATCH_BATCH`-gated settles, Merkle inclusion against `BatchValidityMarker`, nullifier replay protection) is custody-side, not matching-side. The TEE migration touches *who can sign* the `MatchResultPayload`, not *what the on-chain handler verifies*.

**Note on `vault_config.tee_pubkey` derivation under dstack.** The Ed25519 signer key is **deterministically derived** from a dstack-kms-issued seed: `dstack.getKey("nyx/ed25519-signer/v1")` → 32-byte seed → `ed25519_dalek::SigningKey::from_bytes(seed)`. Because `getKey` is a KDF over `(deployer_id, app_hash, path)`, the **same `compose_hash` produces the same signing key regardless of which TDX host the CVM runs on**. CVM restarts and hardware migrations require no on-chain action; only an image upgrade (new `compose_hash`) requires a `set_tee_pubkey` rotation. Full key-lifecycle matrix in [`docs/tee-attestation-flow.md`](tee-attestation-flow.md) §9.

### 3.2 ZK circuits (`circuits/`)

**Disposition: UNCHANGED.**

| Circuit | Disposition |
|---|---|
| `valid_wallet_create/` | Keep |
| `valid_spend/` | Keep |
| `valid_input/` | Keep |
| `match_batch_n2/`, `match_batch_n4/`, `match_batch_n16/` (+ `templates/match_batch.circom`) | Keep |
| `valid_create/`, `valid_price/` | Already deleted in Phase 1c-hard. Do not resurrect. |

The proof system + leaf-hash shape stays. The TEE submits `verify_match_batch` proofs the same way the current matcher does.

### 3.3 Note system (`crates/darkpool-crypto/`)

**Disposition: UNCHANGED.**

| Component | Disposition |
|---|---|
| Note commitment formula (`Poseidon6(mint_lo, mint_hi, amount, owner_commitment, nonce, blinding_r)`) | Keep |
| Nullifier formula (`Poseidon2(spending_key, note_commitment)`) | Keep |
| Owner commitment derivation (`Poseidon2(spending_key, r_owner)`) | Keep |
| Key derivation chain (master_seed → spending/viewing/root/trading + per-note blinding) | Keep |
| Canonical payload hash (`SHA-256("nyx-match-v5" || fields...)`) | Keep — the TEE signs the SAME message format the on-chain handler verifies |

These are cross-language byte-equality contracts (see CLAUDE.md §6); breaking them means re-verifying parity tests + on-chain handlers + circuits. **Don't.**

### 3.4 Matching engine program (`programs/matching_engine/`)

**Disposition: HEAVILY DELETED. ~90% of LOC goes away.**

| Component | Disposition |
|---|---|
| `instructions/init_market.rs` | Keep |
| `instructions/init_mock_oracle.rs` | Keep (devnet only) |
| `instructions/configure_access.rs` | Keep — TEE-side authentication may still want to consult this for membership |
| `state/dark_clob.rs` (`DarkCLOB`) | Keep — market metadata (mints, oracle, version) is still useful on-chain |
| `state/matching_config.rs` (`MatchingConfig`) | Keep — tick size, batch interval, circuit breaker bps live on-chain as public params the TEE reads at startup |
| `state/pending_order.rs` (`PendingOrder`) | **DELETE** — the entire state struct + state machine + `MAX_PENDING_SLOTS_PER_USER` cap |
| `state/batch_results.rs` (`BatchResults`) | **DELETE** — TEE submits settle txs directly with `MatchResultPayload`; no L1 ring buffer needed |
| `state/match_result.rs` (`MatchResult`) | **DELETE** — TEE constructs the payload in-process |
| `state/change_note.rs` | **DELETED** (TEE v2 PR 3, 2026-05-27) — moved into `darkpool_matcher::change_note`. The on-chain ix calls into the matcher; the SDK's TS port is unchanged. Cross-language byte-equality (matcher ↔ TS) gated by `tests/change_note_parity.rs`. |
| `state/fee_accumulator.rs` (`FeeAccumulator`) | **DELETE** — fee accrual happens in TEE memory |
| `state/order_record.rs` | **DELETE** |
| `state/pyth.rs` | Keep the parser; TEE reads Pyth on its own schedule |
| `instructions/init_pending_order_slot.rs` | **DELETE** |
| `instructions/delegate_pending_order.rs` | **DELETE** |
| `instructions/delegate_dark_clob.rs` | **DELETE** |
| `instructions/delegate_matching_config.rs` | **DELETE** |
| `instructions/delegate_batch_results.rs` | **DELETE** |
| `instructions/submit_order.rs` | **DELETE** — moves to TEE as `POST /orders` |
| `instructions/cancel_order.rs` | **DELETE** — moves to TEE as `DELETE /orders/{id}` |
| `instructions/run_batch.rs` | **DELETE** — matching loop moves into TEE process |
| `instructions/commit_market_state.rs` | **DELETE** |
| `instructions/undelegate_market.rs` | **DELETE** |
| All `ephemeral-rollups-sdk` dependencies | **DELETE** from Cargo.toml |

**The matching algorithm itself** (uniform-clearing-price batch auction with FIFO tie-break + Pyth-band circuit breaker) is **moved**, not deleted. It lives in the TEE process now, written in Rust against an in-memory order book.

### 3.5 SDK (`packages/sdk/`)

**Disposition: SIGNIFICANT REFACTOR. Vault-side stays, matching-side gets replaced.**

| Module | Disposition |
|---|---|
| `src/idl/seeds.ts` (vault PDA seeds: `WALLET_SEED`, `NULLIFIER_SEED`, `NOTE_LOCK_SEED`, `CONSUMED_NOTE_SEED`, `VAULT_TOKEN_SEED`, `OUTSTANDING_MINT_SEED`, `BATCH_VALIDITY_MARKER_SEED`) | Keep |
| `src/idl/vault-client.ts` (PDA helpers + ix builders for vault) | Keep |
| `src/idl/matching-engine-client.ts` (PendingOrder helpers, submit_order builder, delegate-*, run_batch, commit/undelegate, cancel_order) | **DELETE almost everything.** Keep only `initMarketInstruction` + the metadata PDAs (`DARK_CLOB_SEED`, `MATCHING_CONFIG_SEED`). |
| `src/idl/er-client.ts` (MagicBlock delegate/commit/undelegate helpers) | **DELETE entirely** |
| `src/orders/submit-order.ts` (high-level ER submit pipeline) | **REPLACE** — new module under `src/api/orders.ts` that hits the TEE's `POST /orders` |
| `src/orders/cancel-order.ts` | **REPLACE** — new module under `src/api/orders.ts` |
| `src/batch/inclusion-proof.ts` (BatchResults ring decode + MatchResult extraction) | **DELETE** — `BatchResults` doesn't exist anymore |
| `src/settlement/settle-builder.ts` (`MatchResultPayload`, `canonicalPayloadHash`, `buildSettleBatchedIx`, `buildEd25519VerifyIx`, `buildCloseBatchValidityMarkerIx`) | Keep — the TEE constructs payloads in the SAME format and the SDK's payload struct stays canonical |
| `src/settlement/settlement-watcher.ts` (poll on-chain settlement events) | **REPLACE** — new module that subscribes to TEE's `channel: settlement` WS or polls `GET /settlement/status/{batchId}` |
| `src/per/attestation.ts` (PER session attestation glue) | **REPLACE** — new `src/tee/attestation.ts` that verifies the TEE's attestation quote at session start |
| `src/per/session-manager.ts` (PER JWT session manager) | **REPLACE** — new `src/tee/session.ts` that handles OAuth2 token + E2E session key exchange |
| `src/keys/` (key derivation) | Keep |
| `src/utxo/` (note + deposit + withdraw helpers) | Keep — withdraw still uses VALID_SPEND on-chain |
| `src/zk/prover-suite.ts` (snarkjs adapter) | Keep |
| `tests/helpers/merkle-shadow.ts` (in-memory Merkle tree) | **DELETE** — replaced by REST client to TEE's `/tree/inclusion` endpoint (~50 lines instead of ~1000) |
| `tests/helpers/match-batch-prover.ts`, `valid-input-prover.ts` | Keep — prover helpers used by both client + (potentially) TEE |
| `tests/helpers/settle-v0.ts`, `verify-match-batch.ts`, `batched-settle.ts` | Keep — the on-chain settle assembly stays. The TEE invokes the same helpers, just from server-side. |
| `tests/helpers/e2e-helpers.ts` | Keep |
| `tests/devnet-trade-flow.test.ts`, `change-note-flow.test.ts`, `er-trade-flow.test.ts` | **REWRITE** — they currently drive the PER flow. New versions drive: client → TEE REST/WS → on-chain settle. |
| `tests/orders-submit.test.ts`, `orders-submit.devnet.test.ts`, `cancel-order.test.ts`, `inclusion-proof.test.ts`, `batch-watcher.test.ts` | **DELETE** — all PER-specific |
| `tests/*-parity.test.ts` (Poseidon, keys, nullifier, note-commitment, user-commitment) | Keep — cross-language byte-equality is unchanged |
| `tests/match-batch-prototype.test.ts`, `settle-builder-batched.test.ts`, `helpers/merkle-shadow.test.ts` | Keep |

The TS-side migration is the second-biggest piece of work after the TEE itself. About 1000 lines deleted, ~1500 lines added (the new `src/tee/` module + rewritten devnet tests).

### 3.6 Off-chain components

| Component | Disposition |
|---|---|
| MagicBlock ER (`https://devnet.magicblock.app`) | **NO LONGER USED.** The dependency disappears entirely. |
| Existing software-TEE Ed25519 keypair (`tee_authority.json`) | **TEMPORARY** — kept until the first attested-image rotation happens (Phase 3); then retired. |
| `scripts/setup-devnet.sh`, `scripts/deploy-devnet.sh` | **MOSTLY UNCHANGED.** Setup script's market-init logic stays; PendingOrder slot setup is deleted. |
| Helius RPC (devnet + mainnet) | Keep. The TEE process talks to Solana via Helius the same way the current SDK does. |
| **Phala Cloud account** | **NEW.** Devnet account in Phase 1 (free tier); production account before mainnet. |
| **dstack-simulator** | **NEW dev dependency.** Local Unix-socket simulator used for development without TDX hardware. See [`docs/tee-architecture.md`](tee-architecture.md) §12. |
| **dstack-verifier (Docker)** | **NEW** — used by admin multisig signers to verify TDX quotes off-chain before signing `set_tee_pubkey`. See [`docs/tee-attestation-flow.md`](tee-attestation-flow.md) §5. |
| **Squads multisig** | **NEW** — 3-of-5 on Solana. Owns `vault_config.admin`. Sole signer of `set_tee_pubkey` + protocol config changes. |
| **dstack-kms (Phala-managed)** | **NEW dependency.** Verifies our TDX quotes off-chain; derives our app keys; gates compose-hash allowlist. We can self-host later (open-source, ~3-of-5 MPC nodes) but Phala-hosted in v2. |
| **DNS provider with API access** (e.g. Cloudflare) | **NEW.** dstack-ingress needs DNS-01 ACME for the custom domain. API token supplied as an encrypted env var (Phala's dashboard does client-side encryption to the TEE's env-encrypt pubkey). |

---

## 4. What's new: the TEE process

The TEE is a Rust binary (`nyx-tee`) running inside an Intel TDX Confidential VM, deployed via Phala Cloud's managed dstack runtime. Full design lives in [`docs/tee-architecture.md`](tee-architecture.md); this section is the migration-relevant overview.

Major components inside the binary:

### 4.1 In-memory order book

A per-market data structure holding open orders. Probably a price-indexed B-tree or skip-list with secondary indices by `trading_key` (for cancel-by-id) and `expiry_slot` (for expiry sweeps). No on-chain footprint; lives entirely in TEE RAM.

Match-cycle: every `batch_interval` slots, the TEE runs the same uniform-clearing-price algorithm we currently run in `run_batch`, except in-process and without account-locking contention. Result is a list of up to N=16 matches, each carrying the v3.5 `MatchSlotWitness` fields.

### 4.2 Merkle-tree mirror

The TEE maintains a local mirror of the on-chain `VaultConfig.current_root` + the full leaf set (so it can build inclusion paths for clients building VALID_SPEND proofs). After every settle tx it submits, it appends the new leaves to its local mirror in the same order the on-chain handler appends them.

This is the same Merkle tree we already have in `programs/vault/src/merkle.rs`, just running in a second process. We can lift the existing Rust implementation directly into the TEE binary.

### 4.3 Settle scheduler

When a batch's match-cycle produces ≥1 real matches, the TEE:

1. Generates the `VALID_MATCH_BATCH` Groth16 proof for the batch (padded to N=16 with dummy slots — same as today).
2. Constructs `MatchResultPayload` for each real match.
3. Signs `canonical_payload_hash(payload)` for each match with the TEE's attestation-bound Ed25519 key.
4. Submits the on-chain settle sequence:
   - `verify_match_batch(merkle_root, expiry, proof)` — once per batch
   - per-batch ALT create + extend — once per batch (uses the existing `settleBatchViaBatched` helper logic, just from the TEE side)
   - `tee_forced_settle_batched(payload, match_index, merkle_proof)` — once per match, fired concurrently via `Promise.all`-equivalent
   - `close_batch_validity_marker(merkle_root)` — once per batch, after all settles confirm

The on-chain side of this is IDENTICAL to what we have today. The only thing that changes is the source of the TEE signature.

### 4.4 REST + WS API

See [`docs/tee-api-openapi.yaml`](tee-api-openapi.yaml) for the wire contract. High-level:

* TLS terminated **inside the enclave** by `dstack-ingress` (cert private key derived from dstack-kms; never exposed). The previous draft of the wire contract had an in-band X25519 envelope; **that is obsolete** — RA-HTTPS supersedes it.
* OAuth2 `client_credentials` for long-lived `api_key` → short-lived bearer token.
* REST for orders, account info, transparency, settlement status, tree inclusion.
* WS multiplexed (`op: login`, `op: order.place`, `channel: fills`, `channel: settlement`, etc.).
* `/evidences/` (served by dstack-ingress directly) — published TDX quote + cert + ACME account + checksum, for client-side RA-TLS verification per [`docs/tee-attestation-flow.md`](tee-attestation-flow.md) §4.

### 4.5 Attestation flow

The attestation chain is not a single step — it's five distinct verifications across different actors. Full reference in [`docs/tee-attestation-flow.md`](tee-attestation-flow.md). Quick summary for migration purposes:

1. **dstack-kms verifies our CVM at boot** — off-chain, before delivering app keys. Enforces compose-hash allowlist (Phala dashboard in v2; Onchain KMS on Base is a possible future enhancement).
2. **Admin multisig verifies the TDX quote off-chain** — before signing `set_tee_pubkey(new_pubkey)`. Uses `dstack-verifier` Docker image for the ECDSA P-256 cert-chain walk + RTMR3 replay + compose-hash comparison.
3. **Solana vault verifies the Ed25519 signature per settle** — unchanged from v3.5. Vault doesn't see the TDX quote, just the Ed25519 signature against `vault_config.tee_pubkey`.
4. **Clients verify the TEE per session** — fetch `/evidences/` + `/attestation`, run dcap-qvl (locally via WASM or via Phala's verify API), compare compose-hash against an SDK-baked constant. SDK ships `verifyTeeAttestation()` helper.
5. **External observers verify continuously** — `/transparency` publishes reserves + attestation + stats unauthenticated. Anyone can re-run the full chain.

The **earlier draft proposed a new on-chain ix `rotate_tee_pubkey_attested` that would verify TDX quotes on Solana via the `secp256r1` precompile + a BPF port of `dcap-qvl`. That is now v3 work, not v2.** v2 uses `set_tee_pubkey(new_pubkey)` gated by the admin multisig only.

---

## 5. Migration sequence

Ordered by dependency. Each phase produces a working state — a phase can be paused at any boundary.

### Phase 0 — Prerequisites (independent of TEE work)

* [x] **Phase 1c-hard cutover** (DONE — `29133e7`)
* [x] **PTAU SHA-256 pinning** (DONE — `a67419f`)
* [ ] **Decide platform**: Phala dstack on Intel TDX (recommended) vs self-hosted Azure DCsv5 + bare TDX (contingency).
* [ ] **Spec docs assembled**: this doc, the OpenAPI spec, the architecture-of-the-TEE-process doc, the attestation flow doc.

### Phase 1 — TEE foundation (no on-chain change)

* [ ] **Set up local dev environment using `dstack-simulator`.** Build the simulator from `github.com/Dstack-TEE/dstack/sdk/simulator/`; set `DSTACK_SIMULATOR_ENDPOINT` env var.
* [ ] **Sign up for Phala Cloud account.** Create a devnet workspace; deploy a "hello-world" attested container; retrieve a TDX quote; verify via `dstack-verifier` Docker image.
* [ ] **Decide custom domain.** Buy `api.nyx.example.com` (or pick a subdomain we own); set up DNS access (Cloudflare token); configure CAA stub.
* [ ] **Benchmark VALID_MATCH_BATCH N=16 proving time on Phala Cloud TDX-Lab tier vs bare metal.** Acceptance: ≤ 3× bare metal. If fail → flip D4 (move prover out of TEE; TEE signs public input). Phase-1 sign-off.
* [ ] **Skeleton `nyx-tee` binary**: cargo crate, dstack SDK integration, OAuth2 token issuer, REST + WS framework via axum + tokio-tungstenite, in-memory order book stub (no matching yet). Per [`docs/tee-architecture.md`](tee-architecture.md) §2.
* [x] **Lift matching algorithm out of `programs/matching_engine`** into a new crate `crates/darkpool-matcher/`. **DONE in PR 1 + PR 2 + PR 3** (2026-05-27). The matcher is Anchor-free; the on-chain `run_batch.rs` is now a thin adapter that builds an `OrderBook` from PendingOrder PDAs, calls `darkpool_matcher::run_batch(...)`, and writes the returned `RunBatchOutput` back to BatchResults + PendingOrder PDAs. Parity gates (matcher: 8 scenarios; on-chain ix: 12 litesvm scenarios) all green. `programs/matching_engine/src/state/change_note.rs` deleted — its content now lives in `darkpool_matcher::change_note`.
* [ ] **NOT in Phase 1:** the on-chain TDX quote verifier. Deferred to v3 — see §6 R1.

### Phase 2 — Read-only TEE-as-indexer

* [ ] **Lift the Rust Merkle-tree code into the TEE.** TEE maintains a synced mirror of `VaultConfig.current_root`.
* [ ] **Implement `/tree/root`, `/tree/inclusion`, `/tree/leaves` endpoints.** Read-only; no order-book state needed.
* [ ] **Implement `/transparency` endpoint.** Reads `VaultConfig`, all `OutstandingMint` PDAs, returns reserves + attestation quote + aggregate stats.
* [ ] **Migrate `MerkleShadow` SDK helper to a thin REST client.** Existing devnet tests get a flag to switch between SDK-shadow and TEE-served paths (similar to how `USE_BATCHED_PROOF` worked during v3.5 cutover — *but this time the flag is short-lived and we cut over completely at the end of Phase 2*).
* **State of the system at end of Phase 2:** PER still in use for matching; on-chain code unchanged; TEE serves read-only endpoints to speed up SDK; no trust impact yet (PER is still the trust root).

### Phase 3 — Admin-gated rotation to the attested enclave

* [ ] **Add `set_tee_pubkey(new_pubkey)` ix to `vault`.** Admin-multisig-gated (`vault_config.admin` must sign). Simple body: validate `new_pubkey != Pubkey::default()`, write to `vault_config.tee_pubkey`, emit event. Does NOT verify a TDX quote on-chain — that work is deferred to v3.
* [ ] **Set up Squads 3-of-5 admin multisig** on Solana devnet. Transfer `vault_config.admin` from the current single-key authority to the multisig (one-time admin call).
* [ ] **Document the rotation ceremony** in `docs/tee-attestation-flow.md` §5 (already done in revision 2). Add to `scripts/dev-commands.md` as `§13: TEE pubkey rotation procedure`.
* [ ] **First rotation: software keypair → attested enclave keypair.** Devnet deploy of a real CVM image, retrieve its derived Ed25519 pubkey from `/info`, verify the TDX quote, multisig signs `set_tee_pubkey(enclave_pubkey)`. The enclave now controls `vault_config.tee_pubkey`.
* [ ] **Sanity check**: the on-chain `tee_forced_settle_batched` accepts payloads signed by the enclave's key. (No code change needed — the on-chain handler doesn't care HOW the key is provisioned, only that the signature on `canonical_payload_hash` verifies.)
* **State of the system at end of Phase 3:** matching still in PER; settle signatures now come from an attested enclave key; software-keypair signing path is dead. Trust root has moved to the multisig + dstack-kms.

### Phase 4 — Matching moves into TEE (the big cutover)

* [ ] **Implement the in-TEE order book.** Per-market price-indexed structure; submit / cancel / mass-quote ops.
* [ ] **Implement the in-TEE matching loop.** Same uniform-clearing-price algorithm we currently run in `run_batch`. Output is a list of `MatchResultPayload`s ready for on-chain settle.
* [ ] **Implement `/orders`, `/orders/{id}`, `/orders/mass-quote`, WS trading channels.** End-to-end client → TEE → on-chain settle.
* [ ] **Rewrite the devnet integration tests** (`devnet-trade-flow.test.ts`, `change-note-flow.test.ts`, `er-trade-flow.test.ts`) to drive the new flow. They become `devnet-trade-flow.test.ts`, `change-note-flow.test.ts`, and `tee-trade-flow.test.ts` (replacing the ER variant).
* **State of the system at end of Phase 4:** PER and TEE are running in parallel against the same on-chain programs. Both produce valid settles. Clients can pick either.

### Phase 5 — Delete the PER side (the v2 equivalent of Phase 1c-hard)

* [ ] **Delete from `programs/matching_engine/`** every ix + state struct listed in §3.4 as "DELETE". The program shrinks to ~200 LOC.
* [ ] **Delete `ephemeral-rollups-sdk` dependency** from Cargo.toml.
* [ ] **Delete from `packages/sdk/`** every module listed in §3.5 as "DELETE" or "REPLACE-and-delete-old".
* [ ] **Delete `apps/demo` PER-specific UI paths.** The dapp gets simpler.
* [ ] **Update CLAUDE.md / ARCHITECTURE.md / CRYPTOGRAPHY.md / dev-commands.md** to reflect "TEE is the only matching path."
* [ ] **Redeploy `matching_engine`.** Same program ID. Clients calling the deleted ixs now get `InstructionFallbackNotFound`.

This is the v2-equivalent of Phase 1c-hard. Same discipline: delete cleanly, don't try to maintain both paths.

### Phase 6 (post-TEE) — Deferred follow-ups

See §10.

---

## 6. Risk register

Risks are listed in roughly decreasing order of impact-times-probability.

### R1 — On-chain TDX quote verification is v3 work, not v2 risk (resolved by D2)

**Status:** **NOT a v2 risk.** Deferred to v3 by D2.

The original framing assumed we'd write a Solana BPF port of `dcap-qvl` (Intel DCAP Quote Verification Library) and call it from a new `rotate_tee_pubkey_attested` ix. After reading the dstack docs we realised:

- The off-chain `dstack-verifier` Docker image already does this work, and we can rely on the admin multisig (3-of-5) to honestly run it before signing `set_tee_pubkey`.
- The on-chain port is multi-week work plus ongoing TCB-info maintenance (Intel updates the TCB allowlist periodically; we'd need a governance ix to push updates).
- Solana's `secp256r1` precompile (program ID `Secp256r1SigVerify1111111111111111111111111`, up to 8 sigs per ix, instructions-sysvar offsets) makes the math feasible — but the cert-chain walking + RTMR3 event-log replay + TCB parsing is non-trivial BPF code.

**v3 design sketch:** in [`docs/tee-attestation-flow.md`](tee-attestation-flow.md) §11. ~4-6 weeks engineering when we decide to do it. Trigger conditions:
- An auditor specifically flags the multisig as the trust concentration.
- A community `dcap-qvl-bpf` port lands publicly (saves most of the work).
- We want to drop the multisig from the rotation flow entirely.

**The v2 trust assumption that this risk is parked against:** the admin multisig honestly verifies the TDX quote off-chain before signing. Same trust assumption every TEE-on-Solana project uses today.

### R2 — TEE ZK-prover performance under TDX overhead

**Impact:** medium. **Probability:** low-medium.

Our `VALID_MATCH_BATCH` Groth16 generation takes ~6.7s on a modern laptop. TDX adds typically ~5-10% overhead, but AVX-heavy workloads (which Groth16 is) can be more sensitive. If we land at >15s per proof, our settle cadence suffers.

**Mitigation:** benchmark early (Phase 1). If overhead is unacceptable, options are (a) move proof generation outside the TEE — TEE signs over the proof's public input + payload hash, prover is separate — or (b) split the batched circuit so we can run multiple smaller proofs in parallel.

### R3 — Phala dstack vendor lock-in

**Impact:** medium. **Probability:** low (mitigated by open-source self-host).

dstack is Apache-2.0 and runs on bare-metal TDX. We *can* self-host on Azure DCsv5 or Google C3D if Phala disappears, but the cutover would be ops work.

**Mitigation:** validate the self-host path in Phase 1 (`docker run` the same image on Azure DCsv5 + confirm byte-identical attestation quote). Treat self-host as the contingency, not the primary.

### R4 — Migration of the existing devnet user base

**Impact:** low (we don't have one yet). **Probability:** n/a.

We're pre-launch. No external users to migrate. Devnet keypairs (`alice-er-*`, `bob-er-*`, etc.) can be regenerated post-cutover.

### R5 — Re-implementing the matching algorithm with bugs

**Impact:** medium. **Probability:** medium.

The current `run_batch` is litesvm-tested. Lifting it into a TEE Rust binary means re-deriving the same litesvm-style test coverage but server-side.

**Mitigation:** the matching algorithm in `run_batch.rs` is ~500 LOC. Move it verbatim into a `darkpool-matcher` crate that both the TEE and (during Phase 4 parallel-run) the existing PER code can use. The litesvm tests then exercise the same code from both sides — we keep parity until Phase 5 deletion.

### R6 — `BatchValidityMarker` rent leak under unreliable TEE liveness

**Impact:** low. **Probability:** medium.

If the TEE crashes between `verify_match_batch` and the matching `close_batch_validity_marker`, the marker stays open until its `expiry_slot` (currently 300 slots ≈ 2 min). Anyone can GC after expiry (this is the design); at-most-$0.0001-per-incident.

**Mitigation:** none needed at devnet scale. For mainnet, consider a background sweeper service.

### R7 — Existing migration brief (this doc) becomes stale

**Impact:** high (we just saw this with the 2026-05-11 version becoming useless by 2026-05-24). **Probability:** high if we don't track it.

**Mitigation:** treat this doc as load-bearing. Every PR that touches a row in §3 must update the corresponding row. Add a `last_revised:` field at the top + a `revised_in:` annotation per row when a row changes.

---

## 7. Rollback positions

Where can we pause the migration without leaving the system broken?

* **End of Phase 1** — TEE foundation is in place but nothing on-chain has changed. Rollback = abandon the TEE work. No code on-chain to undo.
* **End of Phase 2** — TEE serves read-only endpoints; PER still drives matching. Rollback = delete the TEE deployment + the SDK changes that point at it. On-chain code unchanged.
* **End of Phase 3** — Attestation-gated key rotation has happened. **This is a one-way door** — once the on-chain `tee_pubkey` has rotated to an attested key, "rolling back" means rotating to a new software keypair, which is technically possible but defeats the purpose. Treat the Phase 3 rotation as the production cutover for the trust layer.
* **End of Phase 4** — TEE matching + PER matching run in parallel. Rollback = stop using the TEE matching path; PER still works. Clean.
* **End of Phase 5** — PER code deleted. Rollback = revert the deletion commits (we know how to do this from the v3.5 Phase 1c-hard work). Marker: clear commit boundaries make this easy.

---

## 8. What this document is NOT covering (because something else does)

To avoid duplication and to keep this doc the single source of truth for *migration discipline*:

* **API wire contract** → [`docs/tee-api-openapi.yaml`](tee-api-openapi.yaml)
* **TEE-internal architecture (matching loop, order book data structure, in-process services)** → `docs/tee-architecture.md` (to be written during Phase 1)
* **Attestation flow detail (quote format, on-chain verifier specifics, rotation policy)** → `docs/tee-attestation-flow.md` (to be written during Phase 3)
* **Cryptographic invariants that don't change** → [`CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §§4-9
* **Custody-layer architecture** → [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)
* **Pre-PR validation gate + deletion-grep discipline** → [`CLAUDE.md`](../CLAUDE.md) §§2.6, 2.7
* **Phase 1c-hard precedent (how we did the v3.1 deletion)** → [`docs/v3.5-migration.md`](v3.5-migration.md)

---

## 9. Sequencing for the agents doing the work

Concrete reading + decision order for whoever picks up Phase 1:

1. Read this whole doc.
2. Read [`docs/tee-api-openapi.yaml`](tee-api-openapi.yaml).
3. Read [`CLAUDE.md`](../CLAUDE.md) §§4 + §10 + §6 (circuit-touch rules + the deletion checklist + cross-language byte equality).
4. Read [Phala dstack docs](https://docs.phala.network/dstack) end-to-end.
5. Read [Intel TDX attestation specs](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html) (focus on quote format).
6. Confirm or push back on the four caveats in `ARCHITECTURE.md` §"Deployment runbook" / earlier conversation: self-host path, attestation rotation API, ZK perf under TDX, pricing.
7. Open `docs/tee-architecture.md` and write up the internal design BEFORE writing TEE code.
8. THEN code.

---

## 10. Appendix A — Post-TEE deferred items

Things we've consciously deferred to after the TEE migration lands. Listed here so they don't get lost.

### A1 — Light Protocol compressed nullifier integration

**Context:** Light Protocol (zkcompression.com) provides a compressed-PDA nullifier program (`NFLx5WGPrTHHvdRNsidcrNcLxRruMC92E4yv7zhZBoT`) that costs ~15,000 lamports per nullifier vs ~890,880 lamports for a regular PDA — **~60× cheaper, permanently locked rent reduced**.

**Where it fits:** replace our `NullifierEntry` PDAs (created on every `withdraw`) and our `ConsumedNoteEntry` PDAs (created twice per `tee_forced_settle_batched`) with Light's compressed nullifier program. The 32-byte ID we pass is exactly our existing `nullifier = Poseidon2(spending_key, note_commitment)` (for `NullifierEntry`) or the raw note commitment (for `ConsumedNoteEntry`). No circuit changes, no leaf-format changes, no Merkle-tree changes.

**Cost-benefit:**

| | Regular `NullifierEntry` (current) | Light compressed nullifier |
|---|---|---|
| Per-nullifier rent | ~890,880 lamports (~$0.178) | ~15,000 lamports (~$0.003) |
| Reclaimable? | No | No |
| Tx overhead | ~32 B account-list entry | ~32 B + 128 B validity proof |
| CU overhead | ~30k for init | ~100-200k per compressed-PDA op |
| RPC dep | none | Helius / Triton ZK-compression support (already have Helius) |

Per-settle savings: ~$0.36 (2 `ConsumedNoteEntry` + 2 `NullifierEntry` × $0.178 minus $0.003 each). Per-withdraw savings: ~$0.18. At 1000 settles/day + 100 withdraws/day, **roughly $130k/year in rent that would otherwise be permanently locked**.

**Why deferred:**

1. CU budget tight today. Current `tee_forced_settle_batched` consumes ~600-650k CU; adding ~400k for two compressed-nullifier ops puts us at ~1M CU — under the 1.4M cap but with shrinking headroom.
2. The TEE migration restructures the settle ix anyway. Easier to fold in compressed nullifiers during that restructure than to do two cutovers.
3. Rent savings only matter at sustained volume. Below ~100 matches/day, the integration cost dwarfs the rent recovery.

**When to do it:** during Phase 4 of the TEE migration, when the settle ix is being touched for the TEE world. Land as a single PR.

**What NOT to do:**

* Do NOT migrate our Merkle tree to Light. Light's tree leaf format (`{DataHash, StateHash, Owner, Lamports}`) is incompatible with our v3.5 batched leaf-hash construction (`Poseidon12 + Poseidon9` with custom domain tags). Migrating would mean rewriting the v3.5 circuit + zkeys + on-chain VK consts. Not worth it; our tree is fine.
* Do NOT compress `BatchValidityMarker`. Its read-many semantics (read by N settles in a batch) work poorly with Light's UTXO-pattern compressed-PDA model.
* Do NOT compress `NoteLock`. Short-lived state with high write rate to specific accounts — explicitly flagged in Light's "considerations" doc as a bad fit.
* Do NOT compress `OutstandingMint`. Highest write rate per-account in the system.
* Do NOT compress `WalletEntry`. Init-once, read-many; the ~200k CU per compressed-read makes settle paths more expensive than the rent savings justify.

### A2 — Real Phase-2 ceremony for Groth16 trusted setup

Pre-mainnet ask. Not blocking v2 migration. See [`CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §13 #2.

### A3 — Real protocol-owner keypair / governance

Fee notes accumulate today but the protocol-owner commitment is a synthetic test value. Mainnet needs HSM-or-multisig governance over a real spending key. See [`CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §13 #6.

### A4 — Browser prover (`WebProverSuite`)

Replace `snarkjs` shell-out with an in-process WASM prover. UX-only, doesn't affect security or migration.

### A5 — MPC committee for matching (instead of single TEE)

godarkdex-style trust distribution. Strictly stronger than single-TEE but weeks of engineering. v3 of the matching layer at earliest. Not on the v2 critical path.

### A6 — Vault sharding

Multiple `VaultConfig` PDAs sharded by mint or market or commitment hash. The actual answer to "what comes after the ~10 settles/sec single-account ceiling." Real engineering work; depends on hitting the ceiling, which is months out.

---

*Maintained as the single source of truth for the v2 migration. Every PR that changes the disposition of a component in §3 must also update this doc.*

*Last revised: 2026-05-25 — revision 2, after the Phala/dstack docs deep-dive. Locked D1-D4 (Phala Cloud hosting, admin-multisig rotation, custom-domain dstack-ingress, in-TEE prover). Removed the on-chain `rotate_tee_pubkey_attested` ix design; replaced with `set_tee_pubkey` (admin-multisig-gated). Pair-doc references added: [`docs/tee-architecture.md`](tee-architecture.md) + [`docs/tee-attestation-flow.md`](tee-attestation-flow.md).*

*Revision 1 (2026-05-24): drafted the migration sequence from PER → dedicated TEE; pre-dated the dstack-docs ingest.*
