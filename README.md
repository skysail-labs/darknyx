# Nyx Darkpool

A **dark pool on Solana** for SPL tokens. Order intent stays inside a
MagicBlock Ephemeral Rollup (ER), settlement is atomic on L1 with a
TEE-signed payload, and balances are encrypted UTXO notes (Poseidon
commitments in an incremental Merkle tree). Lock, output-construction,
and withdrawal each carry their own Groth16 ZK proof.

> **Status:** functional on Solana **devnet**. Live ER + change-note +
> partial-fill flows are green end-to-end. **Not audited. Not for
> mainnet use.**

---

## At a glance

| Property                        | How                                                                  |
|---------------------------------|----------------------------------------------------------------------|
| Hidden order intent             | `submit_order` runs inside the MagicBlock ER, never on L1            |
| Hidden balances                 | UTXO notes (Poseidon commitments) in a depth-20 Merkle tree          |
| Atomic settlement               | TEE Ed25519-signed `tee_forced_settle` enforces conservation on L1   |
| TEE can't lock a note it doesn't own | `VALID_INPUT` Groth16 verified at `lock_note` time (v2)         |
| TEE can't misroute outputs      | `VALID_CREATE` Groth16 verified at `verify_valid_create` time (v3)   |
| Per-mint solvency invariant     | `outstanding[mint] ≤ vault_token_account.amount` after every ix (v2) |
| Bounded censorship window       | `MAX_LOCK_TTL_SLOTS` (~24h) ceiling on note locks (v2)               |
| Trustless withdrawal            | Groth16 `VALID_SPEND` proof — no operator can move user funds        |
| Front-running protection        | Uniform clearing price + Pyth circuit breaker per batch              |

For the full cryptographic walkthrough (key model, the four ZK
circuits, lifecycle, settlement mechanics) see
**[`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md)**.

---

## Deployed programs (Solana devnet)

| Program           | Address                                          |
|-------------------|--------------------------------------------------|
| `vault`           | `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`   |
| `matching_engine` | `6EasFxo6RCWrK4KAwcdUJqL4KjReLC3rtah8EtHgHSqe`   |

MagicBlock infra (used by the SDK):

| Thing                            | Address                                          |
|----------------------------------|--------------------------------------------------|
| Delegation program               | `DELeGGvXpWV2fqJUhqcF5ZSYMS4JTLjteaAMARRSaeSh`  |
| Magic program                    | `Magic11111111111111111111111111111111111111`  |
| Magic context                    | `MagicContext1111111111111111111111111111111`  |
| ER RPC (devnet)                  | `https://devnet.magicblock.app`                |

Verify on-chain:

```sh
solana program show C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx
solana program show 6EasFxo6RCWrK4KAwcdUJqL4KjReLC3rtah8EtHgHSqe
```

---

## Quickstart

```sh
# 1. Install everything
npm install

# 2. Build the ZK circuits + Rust verifier-key consts
bash scripts/build-circuits.sh

# 3. Build the on-chain programs
cargo build-sbf --manifest-path programs/vault/Cargo.toml
cargo build-sbf --manifest-path programs/matching_engine/Cargo.toml

# 4. Run the full test gate (~110 Rust unit/integ + 88 SDK unit + 17 env-gated devnet)
cargo test --workspace
( cd packages/sdk && ../../node_modules/.bin/vitest run )
```

To run the live devnet ER trade flow, see
[`scripts/dev-commands.md`](scripts/dev-commands.md) §10 / §11.

---

## Repo layout (one-liner per top-level dir)

| Path             | What's there                                                                |
|------------------|------------------------------------------------------------------------------|
| `programs/`      | On-chain Anchor programs — `vault` and `matching_engine`                    |
| `crates/`        | `darkpool-crypto` — host-side Poseidon / key derivation / note crypto       |
| `circuits/`      | Circom 2 ZK circuits — `valid_wallet_create`, `valid_spend`, `valid_input` (v2), `valid_create` (v3) |
| `packages/sdk/`  | `@nyx/sdk` — TypeScript client (ix builders, prover, settlement)            |
| `scripts/`       | Build / deploy / setup shell scripts + master dev cheat-sheet               |
| `docs/`          | Deep-dive design docs                                                        |
| `.devnet/`       | Generated keypairs + e2e config (gitignored)                                 |

---

## Documentation map

| Document                                                       | Read it for…                                                |
|----------------------------------------------------------------|-------------------------------------------------------------|
| **[`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md)**                       | Cryptographic walkthrough — key model, four ZK circuits, lifecycle, settlement mechanics. **Start here if you care about the crypto.** |
| **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**             | System overview: every component, PDA, flow, threat model  |
| **[`DeepWiki`](https://deepwiki.com/skysail-labs/darknyx)**    | Indexed, code-linked walkthrough of the repo                |
| **[`scripts/dev-commands.md`](scripts/dev-commands.md)**       | Master command cheat-sheet — build, test, deploy, troubleshoot |
| `tee_v2_status_and_migration_brief.md`                         | Snapshot of the v1 → v2 audit + migration plan              |
| `order_privacy_fix.md`                                         | Design note — why `submit_order` moved into the ER          |
| `partial_fill_and_fee_notes.md`                                | Design note — partial-fill collateral rotation + fee notes   |
| `change_note_implementation.md`                                | Design note — change-note schema for partial fills          |
| `darkpool_protocol_spec_v3_changed.md`                         | Original protocol spec (historical reference)                |

The `*.md` design notes at the repo root are historical and informative;
the **authoritative** description of the live system is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), the indexed
[DeepWiki](https://deepwiki.com/skysail-labs/darknyx), and in the source code under
`programs/` and `packages/sdk/src/`.

---