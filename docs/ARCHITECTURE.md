# Nyx Darkpool — Architecture

Nyx (aka **darknyx**) is a privacy-preserving CLOB-style darkpool on
Solana. Order intent (side, price, amount, the note backing it) never
appears on-chain; matching and settlement run **inside an Intel TDX
confidential VM (a "CVM") on Phala Cloud**.

This doc is the system-level map. For the cryptography see
[`CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md); for the agent build/deploy/test
contract see [`CLAUDE.md`](../CLAUDE.md); for commands see
[`scripts/dev-commands.md`](../scripts/dev-commands.md).

---

## System overview

Three layers, three trust boundaries:

| Layer | Tech | Owns |
|---|---|---|
| **L1 (Solana)** | `programs/vault` (Anchor 0.32) | Custody, the incremental note Merkle tree, the nullifier / consumed-note / lock PDA sets, the Groth16 verifier, atomic batched settlement |
| **TEE (CVM)** | `crates/nyx-tee` in a TDX CVM on Phala | Hidden order intake (`POST /orders`), uniform-clearing-price matching, the settle pipeline (signs with its dstack-derived key), the Merkle-mirror indexer, the per-order continuation anchor pool, the auth'd HTTP/WS surface |
| **Client** | `packages/sdk` (TypeScript) + snarkjs | Key derivation, VALID_INPUT proof generation, the anchor pool, ix builders, `POST` to the CVM |

```
  ┌──────────────┐  deposit (L1)            ┌────────────────────┐
  │  User wallet ├────────────────────────► │  vault::deposit    │  note → Merkle tree
  │  (browser)   │                          └────────────────────┘
  └──────┬───────┘
         │  POST /orders   (TLS to the CVM; auth'd; carries a VALID_INPUT proof
         │  ★ side / price / amount / note_commitment NEVER touch any L1 tx
         ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  TEE / CVM (crates/nyx-tee)                                  │
  │   • intake: verify trading-key sig + the note opening        │
  │   • match:  uniform clearing price (darkpool-matcher)        │
  │   • settle pipeline, signed by the enclave's Ed25519 key:    │
  └─────────────────────────────────────────────────────────────┘
         │  drives the vault settle ixs directly on L1 (per batch, ≤ N=16 matches)
         ▼
  Tx A  vault::lock_note ×2 / match            ── VALID_INPUT proof per input note
  Tx B  vault::verify_match_batch              ── ONE VALID_MATCH_BATCH Groth16 (≤16)
        (writes ONE BatchValidityMarker keyed by the batch merkle_root)
  Tx C  per-batch Address Lookup Table (create + extend)
  Tx D  vault::tee_forced_settle_batched / match ── Ed25519 + marker check + depth-4
        Merkle inclusion proof; appends note_c (buyer BASE) + note_d (seller QUOTE)
        + note_e/f (change, on partial fill) + base/quote fee notes. v0 + stacked ALTs.
  Tx E  vault::close_batch_validity_marker     ── ONCE after the batch; reclaims rent
         │
         │  withdraw (L1, VALID_SPEND proof)
         ▼
  SPL tokens released to the user wallet
```

There is **no on-chain CLOB and no MagicBlock Ephemeral Rollup** — the
in-CVM matcher replaced them. The only on-chain program is `vault`.

---

## Project layout

```
nyx-monorepo/
├── programs/vault/                  # The ONLY on-chain program (Anchor 0.32)
│   ├── src/
│   │   ├── lib.rs                    # #[program] entrypoints
│   │   ├── state.rs                  # VaultConfig, WalletEntry, NullifierEntry,
│   │   │                             #   ConsumedNoteEntry, NoteLock, OutstandingMint,
│   │   │                             #   BatchValidityMarker
│   │   ├── merkle.rs                 # Incremental Poseidon Merkle tree (depth 20)
│   │   ├── instructions/
│   │   │   ├── initialize.rs                  # Create the global VaultConfig singleton
│   │   │   ├── create_wallet.rs               # VALID_WALLET_CREATE proof → WalletEntry
│   │   │   ├── deposit.rs                      # Pull SPL → append note + outstanding[mint]++
│   │   │   ├── lock_note.rs                    # TEE-only, VALID_INPUT-gated pin of an input note
│   │   │   ├── release_lock.rs                 # Release an expired NoteLock
│   │   │   ├── verify_match_batch.rs           # VALID_MATCH_BATCH (N=16) → BatchValidityMarker
│   │   │   ├── tee_forced_settle_batched.rs    # Ed25519 + marker + depth-4 Merkle; the settle
│   │   │   ├── tee_forced_settle.rs            # SHARED: MatchResultPayload + canonical hash +
│   │   │   │                                   #   verify_tee_signature + create_relock_pda
│   │   │   ├── close_batch_validity_marker.rs  # Reclaim the 1:N marker's rent after the batch
│   │   │   ├── withdraw.rs                     # VALID_SPEND proof → outstanding[mint]-- → SPL out
│   │   │   ├── set_protocol_config.rs          # Admin: protocol-owner commitment / fee bps
│   │   │   ├── set_tee_pubkey.rs               # Admin: rotate the TEE signer (CVM rotation)
│   │   │   ├── rotate_root_key.rs              # Admin: rotate the permission-group root key
│   │   │   ├── realloc_vault_config.rs         # Admin: grow VaultConfig on a layout change
│   │   │   └── reset_merkle_tree.rs            # DEVNET-ONLY: tree wipe for tests
│   │   └── zk/                                 # Embedded Groth16 verifier-key consts
│   │       ├── verifier.rs  vk_valid_wallet_create.rs  vk_valid_spend.rs
│   │       ├── vk_valid_input.rs  vk_match_batch_n16.rs
│   └── tests/                                  # litesvm integration (loads vault.so)
│       ├── settle_harness/                     # shared harness for the settle tests
│       ├── tee_forced_settle_batched.rs        # 1:N marker lifecycle regression
│       ├── match_batch_verify.rs               # real N=16 proof → on-chain verify
│       ├── zk_roundtrip.rs  zk_spend_roundtrip.rs  merkle_host.rs
│       └── set_protocol_config.rs  set_tee_pubkey.rs  user_commitment_registration.rs
│
├── crates/
│   ├── darkpool-crypto/              # Host-side Poseidon / note / nullifier / keys
│   │                                 #   (byte-identical to the TS SDK, parity-tested)
│   ├── darkpool-matcher/             # The matching algorithm (single source of truth) +
│   │                                 #   order/cancel/anchor-topup canonical signing +
│   │                                 #   change_note::derive_inner
│   ├── nyx-tee/                      # The in-CVM engine (see below)
│   └── nyx-tee-loadgen/              # Host binary: load-tests the CVM's /orders intake
│
├── circuits/                        # circom + snarkjs Groth16 circuits
│   ├── valid_wallet_create/  valid_spend/  valid_input/
│   ├── match_batch_n16/ (+ n2, n4 dev/test instances)
│   ├── templates/                    # parameterised templates (MatchBatch(N), etc.)
│   └── build/                        # .wasm + circuit_final.zkey (.zkey committed)
│
├── packages/sdk/                    # TypeScript client (the integration surface)
├── deploy/docker-compose.yaml       # The CVM image + env reference
├── dstack/                          # dstack SDK + simulator (local TEE dev)
└── docs/                            # this file, tee-architecture, attestation-flow, the OpenAPI
```

### `crates/nyx-tee` (the in-CVM engine)

```
src/
├── boot.rs        # dstack handshake → derive the Ed25519 signer; cold-boot the Merkle mirror
├── config.rs      # env-driven config, fail-fast on malformed values
├── api/           # axum HTTP/WS: /health /info /attestation /auth/token /orders /ws/fills
├── keys/          # dstack-derived key material
├── matcher/       # the order book + the interval driver (tick → match → page → settle);
│                  #   the anchor pool + fill memos
├── merkle/        # the Merkle mirror (cold-boot sync + live poll of the on-chain tree)
├── oracle/        # Pyth Hermes price feed
├── prover/        # in-enclave Groth16 prover (VALID_MATCH_BATCH, N=16) + the leaf hasher
├── settle/        # the settle pipeline: lock → verify → ALT → settle → close
├── persistence/   # the encrypted state volume (auth snapshot, etc.)
└── solana_rpc/    # the RPC client (Helius on devnet)
```

---

## Privacy architecture

### What is hidden, what is public

| Hidden (never on-chain) | Public (on-chain) |
|---|---|
| Order side / price / amount | Note commitments (Poseidon hashes) as Merkle leaves |
| Which note backs an order | Nullifiers of consumed notes (unlinkable to the owner) |
| The owner of a note | SPL token amounts entering (`deposit`) / leaving (`withdraw`) the vault |
| The match graph (who traded with whom) | The TEE's settle txs (note commitments + amounts, already public) |

A note's **commitment** is `Poseidon6(DOMAIN_NOTE, mint_lo, mint_hi,
amount, owner_commitment, inner_hash)` — a hash that reveals nothing. Its
**nullifier** is `Poseidon3(DOMAIN_NULL, spending_key, inner_hash)`,
unlinkable to the commitment or the owner. See `CRYPTOGRAPHY.md` §4–§5.

### Why a TEE/CVM (not an on-chain CLOB)?

A public on-chain order book would leak every order. Earlier designs used
a MagicBlock Ephemeral Rollup to hide intent; that has been replaced by an
Intel TDX confidential VM:

* **Order intent never lands in any transaction.** Clients `POST /orders`
  over TLS directly to the enclave. The book lives in enclave memory; only
  the *settlement* (which references already-public note commitments + SPL
  amounts) touches L1.
* **The enclave is attestable.** Clients verify a TDX quote
  (`verifyTeeAttestation()`) binding the running code's measurement
  (`compose_hash` / MRTD) to a governance-approved set before trusting it
  with order data — see [`tee-attestation-flow.md`](tee-architecture.md).
* **The vault trusts only an attested signer.** Every TEE-authority ix
  (`lock_note`, `tee_forced_settle_batched`, …) checks the caller against
  `VaultConfig.tee_pubkey`, rotated to the CVM's dstack-derived key via the
  admin `set_tee_pubkey` ix.

The client's guard against a *misbehaving* TEE is the **settle-memo
integrity check** (`sdk/src/orders/fill-memo.ts`): the client recomputes
each change-note commitment from the reported `inner_hash` and rejects a
TEE that substituted one.

---

## Component walkthrough

### `programs/vault` — custody + Merkle tree + ZK + settlement

The single on-chain program. Holds the SPL token accounts, the incremental
Merkle tree of note commitments (depth 20, Poseidon2), and the replay-guard
PDA sets. Verifies four Groth16 circuits on-chain
(`VALID_WALLET_CREATE`, `VALID_SPEND`, `VALID_INPUT`, `VALID_MATCH_BATCH`)
via the embedded `groth16-solana` verifier. The settle path
(`lock_note → verify_match_batch → tee_forced_settle_batched → close`) is
TEE-authority-gated and processes up to N=16 matches per batch under one
`BatchValidityMarker`.

### `crates/nyx-tee` — the in-CVM engine

Runs inside the TDX CVM. On boot it does the dstack handshake (deriving its
Ed25519 signer + cold-booting the Merkle mirror), loads the N=16 proving
key, and starts: the matcher interval driver (tick → match → page into ≤16
batches → enqueue settle), the settle scheduler (assembles + drives each
batch through lock→prove→verify→ALT→settle→close, sequentially), the oracle
sync, the slot poller, and the HTTP/WS server. The Ed25519 signer is also
the Solana fee-payer for settle txs.

### `crates/darkpool-crypto` — host-side crypto

Poseidon, note commitment, nullifier, key derivation, user commitment, the
field-element split for mints. **Byte-identical to the TS SDK** — every
primitive has a parity test (`packages/sdk/tests/*-parity.test.ts`) that
shells out to example binaries and compares fixtures. Changing a Poseidon
arity / domain tag here without mirroring it in TS breaks the parity test.

### `crates/darkpool-matcher` — the matching algorithm

`run_batch` / `run_batch_capped` is the single source of truth for
uniform-clearing-price matching (price-time priority, circuit breaker, FIFO
tie-break, per-side fee-inclusive collateral, both fee notes). Also home to
`order_canonical.rs` (the order / cancel / anchor-topup signing contract,
parity-tested against the TS SDK) and `change_note::derive_inner` (the
amount-independent `inner_hash` derivation, triple-ported to TS + the
on-chain hashers).

### `circuits/` — the ZK circuits

| Circuit | Proves | Verified |
|---|---|---|
| `VALID_WALLET_CREATE` | a well-formed user commitment | on-chain (`create_wallet`) |
| `VALID_SPEND` | knowledge of a note's opening + its Merkle inclusion + correct nullifier | on-chain (`withdraw`) |
| `VALID_INPUT` | a note's opening + inclusion (gates `lock_note`) | on-chain (`lock_note`) |
| `VALID_MATCH_BATCH` (N=16) | conservation + correct output-note construction for ≤16 matches, hashed into one batch Merkle root | in-enclave prove → on-chain `verify_match_batch` |

(`MatchBatch(N)` is also instantiated at N=2/4 for dev/test only.)

### `packages/sdk` — TypeScript client

Key derivation, note construction (`noteCommitmentV2` / `nullifierV2`),
deposit/withdraw flows, the VALID_INPUT prover wrapper, the order canonical
signing + the anchor pool (`buildAnchorPool` / `buildAnchorTopUp`), fill-memo
verification + the change-note store, and the hand-coded `vault-client.ts`
(every discriminator + Borsh layout, no Anchor IDL runtime).

---

## End-to-end flow (one trade)

1. **Key gen (off-chain).** Client derives spending / viewing / trading keys
   + `user_commitment` from its master seed.
2. **`create_wallet` (L1).** Register the user commitment (VALID_WALLET_CREATE).
3. **`deposit` (L1).** Pull SPL into the vault; a note commitment is appended
   to the Merkle tree; `outstanding[mint]++`.
4. **`POST /orders` (CVM).** Client builds a VALID_INPUT proof for its note +
   signs the order canonical (binding the 10-anchor continuation pool) + posts
   to the CVM. Intake verifies the sig + the note opening, then books it.
5. **Match (CVM).** The interval tick finds a crossing pair at the uniform
   clearing price; if a side partially fills, the matcher consumes an anchor +
   rotates the residual to continue.
6. **Settle (CVM → L1).** The settle pipeline drives Tx A–E (above) on L1: the
   matched output notes (note_c/d), any change notes (note_e/f), and the
   base+quote protocol fee notes are appended to the tree.
7. **Fill memo (CVM → client).** The client receives the fill, runs the
   integrity check, and stores the change note for later spending.
8. **`withdraw` (L1).** Client spends an output note via a VALID_SPEND proof;
   the nullifier is recorded; SPL leaves the vault.

---

## Account / PDA reference (vault)

| PDA | Seeds | Purpose |
|---|---|---|
| `VaultConfig` | `[b"vault_config"]` | Singleton: Merkle root + leaf_count, `tee_pubkey`, admin, root key, protocol-owner commitment, fee bps |
| `WalletEntry` | `[b"wallet", user_commitment]` | Registered user commitment (1:1; `init` = replay guard) |
| `NullifierEntry` | `[b"nullifier", nullifier]` | A VALID_SPEND-consumed note |
| `ConsumedNoteEntry` | `[b"consumed", note_commitment]` | A TEE-settle-consumed input note |
| `NoteLock` | `[b"note_lock", note_commitment]` | The pin between match and settle (TTL-bounded) |
| `OutstandingMint` | `[b"outstanding", mint]` | Per-mint solvency counter (`deposit++`, `withdraw--`) |
| `BatchValidityMarker` | `[b"batch_marker", batch_merkle_root]` | **1:N** — one per batch, written by `verify_match_batch`, closed by `close_batch_validity_marker` |

Plus the per-mint `vault_token_account` PDAs (the actual SPL custody) and a
per-batch Address Lookup Table (created by the settle worker) holding the
payload-derivable settle PDAs.

---

## Security model

* **Custody soundness.** The vault releases SPL only against a valid
  VALID_SPEND proof of an unspent note, or a TEE-authority settle. The
  `outstanding[mint] ≤ vault_token_account.amount` check in `withdraw` is the
  solvency net.
* **Replay protection.** The `init` constraint on the per-leaf PDAs
  (`NullifierEntry`, `ConsumedNoteEntry`, `NoteLock`, `WalletEntry`) makes a
  second touch fail. The `BatchValidityMarker` binds a batch's matches to one
  verified proof.
* **TEE trust.** The vault trusts only `VaultConfig.tee_pubkey`. Clients
  verify the enclave's TDX attestation before sending order data. A
  misbehaving TEE cannot steal (spending keys never enter it) and is caught
  substituting note data by the client's settle-memo integrity check.
* **Privacy.** Order intent never leaves the enclave except as settlement
  referencing already-public note commitments.

Known gaps: the `/ws/fills` channel is currently fail-closed (unfiltered
broadcast — see [`fills-history-architecture.md`](fills-history-architecture.md));
settle-under-load is bounded by RPC capacity (Helius 429s), not the matcher.

---

## Deployment runbook

The authoritative step-by-step is in [`scripts/dev-commands.md`](../scripts/dev-commands.md)
and [`CLAUDE.md §2–§3`](../CLAUDE.md). Summary:

1. **Host setup** — `npm install`; `bash scripts/download-ptau.sh`;
   `bash scripts/build-circuits.sh`; `cargo build --examples -p darkpool-crypto`.
2. **Build + deploy the vault** — `cargo build-sbf --manifest-path
   programs/vault/Cargo.toml`; `bash scripts/deploy-devnet.sh` (idempotent
   upgrade; needs ≥ 5 devnet SOL).
3. **Devnet state** — `vitest run tests/devnet-setup.test.ts` (`RUN_DEVNET_E2E=1`)
   creates mints + the settle ALT + protocol config + resets the tree, writing
   `.devnet/e2e-config.json`. A tree reset is mandatory after any circuit/VK
   change or note-model migration.
4. **Build + deploy the CVM** — bump the image tag, push it (CI → ghcr),
   `phala deploy -e <env>`, rotate `tee_pubkey` to the CVM signer, fund it.
   Mind the mint regime (real-mint for `cvm-settle-e2e`, placeholder for the
   loadgen) — see `CLAUDE.md §3`.
5. **Validate** — `cvm-settle-e2e` (real settle through the CVM),
   `devnet-deposit-withdraw` (no-CVM deposit+withdraw), the loadgen (intake
   throughput). **Stop the CVM after** (it bills).

## Deployed program ids (devnet)

* vault: `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`

(The matching_engine program id is retired — the program was deleted.)
