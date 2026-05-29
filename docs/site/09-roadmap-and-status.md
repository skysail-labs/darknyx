# Roadmap and status

> Where Nyx is right now, where it's going, and the six locked
> decisions that frame the v2 architecture. Status is updated
> per-PR; the structure below reflects the work in flight as of
> mid-2026.

---

## Where we are: the v3.5 + TEE v2 migration

Nyx's custody layer is **stable on Solana devnet** at v3.5
("batched-validity migration"). The matching layer is **in flight**
as the **TEE v2 migration** — moving from MagicBlock's Permission
Group Ephemeral Rollup (PER) to a dedicated Intel TDX
Confidential VM on Phala Cloud.

The migration is intentionally being executed as a chain of small,
independently-testable sub-PRs. Each landing leaves the system in
a deployable state; the cutover from v1 to v2 happens when every
sub-PR has landed and the multisig rotates the TEE pubkey on-chain.

---

## The six locked v2 decisions

The TEE v2 architecture is anchored in six decisions, all locked in
early 2026 after a multi-month design review. Each decision has an
explicit re-evaluation trigger; details in `docs/tee-architecture.md`
§14.

| # | Decision | Rationale | Re-evaluate when |
|---|---|---|---|
| **D1** | **Phala Cloud as the TDX provider** | Cheapest production-grade TDX with a real attestation chain. Per-minute pricing (~$0.003/min on tdx.small) enables disposable spot-check deploys. | We hit Phala's free-tier limits AND managed pricing exceeds $1.5k/mo, OR a security audit flags Phala's KMS-operator key handling, OR we close a fundraise enabling bare-metal procurement |
| **D2** | **Admin multisig rotates the registered TEE pubkey** | On-chain DCAP verification doesn't fit Solana's per-tx compute budget today. The multisig is a pragmatic intermediate; the v3 roadmap explores moving to on-chain attestation. | A working `dcap-qvl` port to Solana BPF appears (community or our own), OR a finding flags the multisig as the primary risk concentration, OR Solana ships a higher-CU-budget tx mode |
| **D3** | **Custom domain (not Phala's gateway domain)** | Lets hardware wallets pin the TLS endpoint; preserves the option to migrate operators without a client-visible URL change. | We want to support hardware wallets that pin the dstack-gateway domain natively, OR we want per-user subdomains for routing |
| **D4** | **In-TEE Groth16 prover** | Generating proofs inside the TEE means the match data never leaves attested code. The alternative (external prover with a TEE-signed witness) widens the trust surface. | Phase-1 benchmark shows ≥3× slowdown vs bare metal, OR TEE host RAM > 32 GB |
| **D5** | **Frequent-batch auction with `BATCH_MS = 2000` default** | Settle-pipeline latency floor is ~2-3 s; running matching faster than the pipeline pipelines up. Per-market tunable so liquid markets can dial faster (toward 500ms), thin markets slower (toward 30s), without code changes. | Phase-1 settle-pipeline benchmark shows finality consistently > 3 s — bump default; OR a specific market needs sub-second fills |
| **D6** | **TEE-as-indexer** | The TEE already holds the Merkle mirror + nullifier set + lock state in RAM for matching — exposing read endpoints (`/tree/*`, `/transparency`) off the same state is essentially free. One deployment, one attestation chain, one trust story. | TEE host RAM > 70% under load, OR we want read-replica scaling, OR a non-Nyx app wants to consume our indexer reads |

Each decision is small-scoped. None of them change the wire
contract, the on-chain code, or the cryptographic invariants;
each can be flipped independently without breaking the rest.

---

## Shipped (production-ready)

### Custody layer

- Vault program live on Solana devnet (program id
  `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`)
- All seven instructions implemented and tested:
  `create_wallet`, `deposit`, `lock_note`, `verify_match_batch`,
  `tee_forced_settle_batched`, `close_batch_validity_marker`,
  `withdraw`
- Six ZK circuits compiled with verifying keys on-chain
- v3.5 batched-validity hardening complete (Phase 1c-hard
  cutover: the v3.1 per-match settle path has been removed
  entirely)

### Matching algorithm

- `darkpool-matcher` crate is the single source of truth
- Uniform-clearing-price + FIFO tie-break + Pyth-band circuit
  breaker
- 8 parity scenarios in `crates/darkpool-matcher/tests/parity.rs`
- 4 cross-language byte-equality scenarios for change-note
  derivation

### Cryptography

- Cross-language byte-equality contracts pinned for: Poseidon
  arities, note commitments, nullifiers, key derivation chain,
  user commitments, canonical payload hashes, match leaf hashes
- Parity tests run in CI on every commit; any drift fails the
  build

### TypeScript SDK

- Six ZK provers (snarkjs-backed) for VALID_INPUT,
  VALID_WALLET_CREATE, VALID_SPEND, VALID_MATCH_BATCH (N=2/4/16)
- TEE attestation verifier
- Order canonical body encoder + signer (parity-tested vs Rust)
- Settle batched ix builder
- 106 tests passing, 17 env-gated devnet tests

---

## TEE v2 — work in flight

### Phase 1: foundation (complete)

| PR | What | Commit |
|---|---|---|
| 4a | dstack handshake + Ed25519 signer derivation | `ed462df` |
| 4b | Oracle module: Hermes client + Wormhole VAA verifier | `e753fa4` |
| 4c | Matcher book + tokio interval driver | `22b039f` |
| 4d | Minimal HTTP surface: `/health`, `/info`, `/attestation` | `4422de4` |

### Phase 2: orders + auth (complete)

| PR | What | Commit |
|---|---|---|
| 4e.1 | Canonical order body encoding + cross-language parity | `6875352` |
| 4e.2 | JWT issuance + bearer middleware | `a9fa385` |
| 4e.3 | POST / DELETE / GET /orders + Ed25519 sig verify | `7975497` |
| 4e.4 | Spawn matcher + oracle sync; HTTP→match e2e | `c2bc3af` |

### Phase 3: load-gen + observability (complete)

| PR | What | Commit |
|---|---|---|
| 4f.1 | Debug oracle-seed endpoint (feature-gated) | `fb21d1a` |
| 4f.2 | `nyx-tee-loadgen` crate + smoke test + BENCHMARK.md template | `8f32d2a` |

### Phase 4: settle pipeline (in flight)

| PR | What | Status |
|---|---|---|
| 4g.1 | SettleScheduler skeleton + status endpoint | ✅ `06b7207` |
| 4g.2 | Hand-rolled Solana JSON-RPC client + fee-payer derivation | ✅ `79166d0` |
| 4g.3 | lock_note ix builder + Tx A submission | ✅ `c016e05` |
| 4g.4a | VALID_MATCH_BATCH prover foundation (witness, leaves, root, constraints, stub Prover trait) | ✅ `e9962b0` |
| 4g.4b | ark-circom 0.5.0 wiring + Groth16 proof gen + format converter | ⏳ next |
| 4g.5 | Tx B (verify_match_batch) + Tx C (per-batch ALT) + Tx D (settle_batched) | ⏳ |
| 4g.6 | Tx E (close marker) + stage workers + end-to-end litesvm test | ⏳ |

### Phase 5: production cutover

After 4g.6 lands:

1. Spike on Phala devnet `tdx.small` with the `nyx-tee-loadgen`
   harness; populate the `BENCHMARK.md` report
2. Full attestation-rotation ceremony rehearsal against the new
   compose_hash
3. Multisig rotation cutover (v1 PER pubkey → v2 TDX pubkey)
4. v1 PER cluster decommission

---

## Future direction (post-v2)

### Near-term (next 6 months)

| Item | Why |
|---|---|
| In-browser ark-groth16 prover for user proofs | The current snarkjs path is slow; ark-groth16 in WASM is ~3× faster |
| **In-TEE prover perf swap (rapidsnark / circom-witness-rs)** | **The initial in-TEE prover (PR 4g.4b) uses `ark-circom` 0.5.0 — pure-Rust, wasmer-backed, drop-in for our arkworks 0.5 workspace. If the post-cutover CVM benchmark (D4's ≥3× re-evaluation trigger) shows VALID_MATCH_BATCH proving exceeds the matching cadence budget, swap the prover internals to rapidsnark (FFI) or circom-witness-rs (C++ witness calc via cxx). The `Prover` trait surface from 4g.4a stays stable — the swap is internal, no on-chain or wire changes. Gated on measured numbers, not assumed: we do not pay rapidsnark's C++ build-pipeline + compose-hash complexity cost until the benchmark justifies it.** |
| On-chain DCAP verifier in vault BPF | Eliminate the multisig (D2) from the trust chain |
| Per-batch ALT pool for production matchers | Amortize ALT creation cost at high throughput |
| Persistence layer for the in-TEE order book (LUKS-encrypted) | TEE restart should not lose open orders |
| Production-grade load-gen + published benchmarks | Quotable performance numbers |

### Medium-term (6-18 months)

| Item | Why |
|---|---|
| Multi-market support | Currently one market per matcher driver; production needs per-market drivers |
| Cross-margining + portfolio risk | Treat a user's notes as a portfolio rather than independent UTXOs |
| Limit-order book depth limits | DOS protection; book-size cap before the matcher slows |
| Integrated MM rebalancing toolkit | Make it easy for market makers to keep inventory neutral across markets |
| Mainnet program-id deployment (upgrade authority removed) | Truly immutable vault |

### Long-term (research)

| Item | Why |
|---|---|
| Post-quantum cryptography migration | All current SNARKs break under Shor; tracking the lattice-SNARK state of the art |
| Cross-chain bridging via the TEE | Trustless bridging if the TEE can verify external chain finality; multi-VM TEE clusters |
| Fully on-chain matching (after on-chain DCAP) | If on-chain DCAP works, why have a TEE at all? Re-evaluate the architecture |

---

## What we're explicitly NOT building

A few things we've decided to NOT do, with the reasoning:

- **A centralized exchange UI.** Nyx is infrastructure; user-facing
  trading UIs are best built by independent teams who specialize
  in trader UX. The SDK is the integration surface.

- **A custodial token (NYX, etc.).** No protocol token. The
  alignment between users and operators is enforced by the
  trust model, not by token incentives.

- **A bridge.** Cross-chain bridges are their own threat surface.
  Solana-native is the focus; users wanting other-chain assets
  use existing bridges to wrap-then-deposit.

- **Order types beyond limit / IOC / FOK.** Stop-loss, take-
  profit, trailing-stop, etc. are deferred to the SDK level (the
  SDK can implement them via cancel-and-resubmit). Keeping the
  on-TEE order types minimal keeps the matcher simple.

- **Fee subsidization or rebates.** Maker/taker fee asymmetry
  invites gaming. Flat fees on both sides; no rebates.

---

## How to contribute

The repo is open-source. Contributions land via PRs against the
active branch (`tee_v3_implementation` for the TEE v2 workstream).
CLAUDE.md is the engineer's contract: it documents the pre-PR
gate, the cross-language byte-equality contracts, the deletion
checklist, and the test-surface conventions.

Specific high-value contribution areas:

- **Phala devnet benchmarks.** Anyone can spin up a `tdx.small`,
  run the `nyx-tee-loadgen` harness, and publish numbers
- **Documentation typo fixes** — small but valuable
- **Cross-environment parity tests** — anywhere the byte-equality
  contract gates an invariant
- **Threat modelling additions** — flagging an attack vector we
  haven't documented

---

## Status as of this page's date

| Layer | Status |
|---|---|
| Custody (vault program) | ✅ Live on Solana devnet (v3.5) |
| Matching algorithm | ✅ Stable in `darkpool-matcher` crate |
| TEE v2 daemon (`nyx-tee`) | 🟡 ~60% complete; settle pipeline next |
| TypeScript SDK | ✅ Live; parity tested |
| Public docs site | 🟡 In progress (these pages) |
| Phala devnet deployment | 🟡 Spike-ready; full rotation ceremony pending 4g.6 |
| Mainnet | ⏳ Pending TEE v2 cutover + audit |

---

*Last updated 2026-05-29.*
</content>
