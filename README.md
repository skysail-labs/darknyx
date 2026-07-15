# Nyx Darkpool

A **dark pool on Solana** for SPL tokens. Order intent is matched and
settled **inside an Intel TDX confidential VM (a "CVM") on Phala Cloud** —
it never touches an L1 transaction. Settlement is atomic on L1 with a
TEE-signed payload, and balances are encrypted UTXO notes (Poseidon
commitments in an incremental Merkle tree). Note locking, matching, and
withdrawal each carry their own Groth16 ZK proof. **Per-trade amounts + the
execution price are hidden on-chain too** — the settle tx carries only note
commitments, and each trade's amount reaches its owner off-chain through an
auth'd fill memo (`fills` on `/v1/stream`, with on-chain recovery), never an L1 transaction.

> **Status:** functional on Solana **devnet**, validated end-to-end on a
> live Phala CVM (`cvm-settle-e2e` real settle + a load generator).
> **Not audited. Not for mainnet use.**

---

## At a glance

| Property                        | How                                                                  |
|---------------------------------|----------------------------------------------------------------------|
| Hidden order intent             | Orders are `POST`ed to the in-CVM matcher (`POST /orders`), never to L1 |
| Hidden balances                 | UTXO notes (Poseidon commitments) in a depth-20 Merkle tree          |
| Hidden trade amount + price     | Settlement carries note commitments only (no plaintext amounts/price); `VALID_MATCH_BATCH` range-checks amounts + enforces the fee floor in-circuit; the amount reaches the trader via the `/v1/stream` fills channel |
| Atomic settlement               | TEE Ed25519-signed `tee_forced_settle_batched` enforces conservation on L1 |
| TEE can't lock a note it doesn't own | `VALID_INPUT` Groth16 verified at `lock_note` time              |
| TEE can't misroute outputs      | `VALID_MATCH_BATCH` Groth16 verified at `verify_match_batch` time (N=16/batch) |
| Per-mint solvency invariant     | `outstanding[mint] ≤ vault_token_account.amount` after every ix      |
| Bounded censorship window       | `MAX_LOCK_TTL_SLOTS` (~30 min) ceiling on note locks                 |
| Trustless withdrawal            | Groth16 `VALID_SPEND` proof — no operator can move user funds        |
| Front-running protection        | Uniform clearing price + Pyth oracle band per batch                  |
| Partial-fill continuation       | The circuit derives the residual from the consumed input inner; the matcher re-locks and re-matches it without a client roundtrip |

For the full cryptographic walkthrough (key model, the four ZK
circuits, lifecycle, settlement mechanics) see
**[`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md)**.

---

## Architecture in 60 seconds

Three layers:

* **L1 (Solana)** — `programs/vault/` is the only on-chain program
  (Anchor 0.32). It owns custody, the incremental Merkle tree of note
  commitments, the nullifier / consumed-note sets, the Groth16 verifier,
  and the atomic batched settlement path (`lock_note → verify_match_batch
  → tee_forced_settle_batched → close_batch_validity_marker`, N=16
  matches per batch).
* **TEE (`crates/nyx-tee/`)** — the in-enclave matcher + settler. It owns
  hidden order intake, uniform-clearing-price matching, the full settle
  pipeline (signed by its dstack-derived Ed25519 key), a Merkle-mirror
  indexer, deterministic consumed-input-derived continuations, and the auth'd HTTP/WS
  surface.
* **Client (TypeScript SDK + snarkjs prover)** — `packages/sdk/` builds
  VALID_INPUT proofs and `POST`s orders to the CVM. `crates/darkpool-crypto/`
  is the host-side Rust crypto crate with byte-identical Poseidon / note /
  key derivation that the TS SDK has parity tests against.

There is **no on-chain CLOB and no Ephemeral Rollup** — the only on-chain
program is `vault`; the only matcher is the in-TEE one.

---

## Deployed programs (Solana devnet)

| Program | Address                                          |
|---------|--------------------------------------------------|
| `vault` | `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`   |

Verify on-chain:

```sh
solana program show C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx
```

---

## Quickstart

```sh
# 1. Install everything
npm install

# 2. Build the ZK circuits + Rust verifier-key consts
bash scripts/download-ptau.sh
bash scripts/build-circuits.sh

# 3. Build the on-chain program
#    (--features devnet-admin builds the dev/devnet admin ixs the litesvm tests
#     use; a mainnet build omits it — audit_1 F-01/F-02)
cargo build-sbf --manifest-path programs/vault/Cargo.toml --features devnet-admin

# 4. Run the full test gate (Rust unit/integ + SDK unit; env-gated devnet/CVM tests auto-skip)
cargo test --workspace
( cd packages/sdk && ../../node_modules/.bin/vitest run )
```

To build, deploy, and test against a live Phala CVM (the flagship
real-settle path), see [`scripts/dev-commands.md`](scripts/dev-commands.md)
§5–§7.

---

## Repo layout (one-liner per top-level dir)

| Path             | What's there                                                                |
|------------------|------------------------------------------------------------------------------|
| `programs/`      | On-chain Anchor program — `vault` (the only on-chain program)               |
| `crates/`        | `darkpool-crypto` (host Poseidon/key/note crypto), `darkpool-matcher` (the matching algorithm), `nyx-tee` (the in-CVM matcher/settler), `nyx-tee-loadgen` |
| `circuits/`      | Circom 2 ZK circuits — `valid_wallet_create`, `valid_spend`, `valid_input`, `valid_match_batch` |
| `packages/sdk/`  | `@nyx/sdk` — TypeScript client (ix builders, prover, order/settlement)      |
| `deploy/`        | Dockerfile + `docker-compose.yaml` for the Phala CVM image                  |
| `scripts/`       | Build / deploy / setup shell scripts + master dev cheat-sheet               |
| `docs/`          | Deep-dive design docs + the documentation site under `docs/site/`           |
| `.devnet/`       | Generated keypairs + e2e config (gitignored)                                 |

---

## Documentation map

| Document                                                       | Read it for…                                                |
|----------------------------------------------------------------|-------------------------------------------------------------|
| **[`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md)**                       | Cryptographic walkthrough — key model, the four ZK circuits, lifecycle, settlement mechanics. **Start here if you care about the crypto.** |
| **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**             | System overview: every component, PDA, flow, threat model  |
| **[`CLAUDE.md`](CLAUDE.md)**                                  | Agent / contributor onboarding: the build-validate cycle + the Phala CVM runbook + the byte-equality invariants |
| **[`scripts/dev-commands.md`](scripts/dev-commands.md)**       | Master command cheat-sheet — build, test, deploy, troubleshoot |
| **[`docs/tee-architecture.md`](docs/tee-architecture.md)**     | The in-TEE matcher/settler design (book, settle pipeline, auth) |
| **[`docs/fills-history-architecture.md`](docs/fills-history-architecture.md)** | Fills delivery + trade history: deterministic order_ids + per-account `/v1/stream` fill memos (the low-latency path) + durable on-chain ciphertext recovery; the off-TEE indexer is a commitment locator only |
| **[`docs/governance.md`](docs/governance.md)**                 | Authority model + the mainnet multisig runbook: upgrade / `admin` / `root_key` → Squads v4, the `initialize`-binding bootstrap order, attestation-gated TEE rotation (audit_1 F-03/F-10) |
| **[`DeepWiki`](https://deepwiki.com/skysail-labs/darknyx)**    | Indexed, code-linked walkthrough of the repo                |

The **authoritative** description of the live system is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md),
the indexed [DeepWiki](https://deepwiki.com/skysail-labs/darknyx), and the
source under `programs/`, `crates/`, and `packages/sdk/src/`.

---
