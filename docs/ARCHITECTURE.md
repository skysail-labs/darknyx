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
  Tx A  vault::lock_note ×2 / match            ── VALID_INPUT proof per input note;
        sent CONCURRENTLY (bounded), fee-payer round-robined across the K shard keys
  Tx B  vault::verify_match_batch              ── ONE VALID_MATCH_BATCH Groth16 (≤16)
        (writes ONE BatchValidityMarker keyed by the batch merkle_root)
  Tx C  per-batch Address Lookup Table (create + CHUNKED extend, fired concurrently;
        canonical address order re-read from chain) holding the settle-derivable PDAs
  Tx D  vault::tee_forced_settle_batched / match ── Ed25519 + marker check + depth-4
        Merkle inclusion proof; appends note_c (buyer BASE) + note_d (seller QUOTE)
        + note_e/f (change, on partial fill) + base/quote fee notes to merkle_tree[tree_id].
        Each match round-robins (shard key[j], merkle_tree[j]) so the leader co-includes
        the batch's Tx D's in ONE block. v0 + stacked ALTs.
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
│   │   ├── state.rs                  # VaultConfig (global: tee_pubkeys[16], num_trees,
│   │   │                             #   zero_subtree_roots), MerkleTree (per-shard tree
│   │   │                             #   state), WalletEntry, NullifierEntry,
│   │   │                             #   ConsumedNoteEntry, NoteLock, OutstandingMint,
│   │   │                             #   BatchValidityMarker
│   │   ├── merkle.rs                 # Incremental Poseidon Merkle tree (depth 20), per shard
│   │   ├── instructions/
│   │   │   ├── initialize.rs                  # Create the global VaultConfig (num_trees)
│   │   │   ├── initialize_tree.rs             # Create one MerkleTree shard [tree_id]
│   │   │   ├── create_wallet.rs               # VALID_WALLET_CREATE proof → WalletEntry
│   │   │   ├── deposit.rs                      # Pull SPL → append note to merkle_tree[id] + outstanding[mint]++
│   │   │   ├── lock_note.rs                    # TEE-only, VALID_INPUT-gated pin of an input note
│   │   │   ├── merge.rs                        # VALID_MERGE(K=2/4): consolidate K notes → 1 (in-pool)
│   │   │   ├── release_lock.rs                 # Release an expired NoteLock
│   │   │   ├── verify_match_batch.rs           # VALID_MATCH_BATCH (N=16) → BatchValidityMarker
│   │   │   ├── tee_forced_settle_batched.rs    # Ed25519 + marker + depth-4 Merkle; the settle
│   │   │   ├── tee_forced_settle.rs            # SHARED: MatchResultPayload + canonical hash +
│   │   │   │                                   #   verify_tee_signature + create_relock_pda
│   │   │   ├── close_batch_validity_marker.rs  # Reclaim the 1:N marker's rent after the batch
│   │   │   ├── withdraw.rs                     # VALID_SPEND proof → outstanding[mint]-- → SPL out
│   │   │   ├── set_protocol_config.rs          # Admin: protocol-owner commitment / fee bps
│   │   │   ├── set_tee_pubkey.rs               # Admin: install the K authorized TEE signers (Vec)
│   │   │   ├── rotate_root_key.rs              # Admin: rotate the permission-group root key
│   │   │   ├── close_vault_config.rs           # DEVNET-ONLY: close VaultConfig for a layout migration
│   │   │   └── reset_merkle_tree.rs            # DEVNET-ONLY: per-shard tree wipe for tests
│   │   └── zk/                                 # Embedded Groth16 verifier-key consts
│   │       ├── verifier.rs  vk_valid_wallet_create.rs  vk_valid_spend.rs
│   │       ├── vk_valid_input.rs  vk_match_batch_n16.rs
│   │       ├── vk_valid_merge_k2.rs  vk_valid_merge_k4.rs
│   └── tests/                                  # litesvm integration (loads vault.so)
│       ├── settle_harness/                     # shared harness (K-shard aware) for the settle tests
│       ├── tee_forced_settle_batched.rs        # 1:N marker + sharding (distinct-shard / multi-key / per-shard reset)
│       ├── match_batch_verify.rs               # real N=16 proof → on-chain verify
│       ├── merge_verify.rs                      # VALID_MERGE(K=2/4) verify roundtrip
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
├── boot.rs        # dstack handshake → derive the shard-0 Ed25519 signer; cold-boot the mirrors
├── config.rs      # env-driven config (num_trees, prover backend, send concurrency), fail-fast
├── api/           # axum HTTP/WS: /health /info /attestation /auth/token /orders /ws/fills /tree
├── keys/          # dstack-derived key material (K shard signers at nyx/ed25519-signer/v1/{i})
├── matcher/       # the order book + the interval driver (tick → match → page → settle);
│                  #   the anchor pool + fill memos
├── merkle/        # K per-shard Merkle mirrors (cold-boot sync + live poll, routed by tree_id)
├── oracle/        # Pyth Hermes price feed
├── prover/        # in-enclave Groth16 prover (VALID_MATCH_BATCH, N=16) — ark | rapidsnark backend
├── settle/        # the settle pipeline: lock → prove → verify → ALT → settle → close;
│                  #   K fee-payer round-robin + the rolling per-batch ALT pool
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
* **The vault trusts only attested signers.** Every TEE-authority ix
  (`lock_note`, `tee_forced_settle_batched`, …) checks the caller against
  `VaultConfig.tee_pubkeys` (the K registered shard keys), installed from the
  CVM's dstack-derived signer set via the admin `set_tee_pubkey(Vec<Pubkey>)` ix.

The client's guard against a *misbehaving* TEE is the **settle-memo
integrity check** (`sdk/src/orders/fill-memo.ts`): the client recomputes
each change-note commitment from the reported `inner_hash` and rejects a
TEE that substituted one.

---

## Component walkthrough

### `programs/vault` — custody + Merkle tree + ZK + settlement

The single on-chain program. Holds the SPL token accounts, **K sharded
incremental Merkle trees** of note commitments (each depth 20, Poseidon2, in
its own `MerkleTree[tree_id]` account — the global `VaultConfig` keeps only the
tree-independent config + the shared `zero_subtree_roots`), and the replay-guard
PDA sets. Verifies the Groth16 circuits on-chain (`VALID_WALLET_CREATE`,
`VALID_SPEND`, `VALID_INPUT`, `VALID_MATCH_BATCH`, `VALID_MERGE`) via the
embedded `groth16-solana` verifier. The settle path
(`lock_note → verify_match_batch → tee_forced_settle_batched → close`) is
TEE-authority-gated (any of the K registered `tee_pubkeys`) and processes up to
N=16 matches per batch under one `BatchValidityMarker`. Each settle appends its
output notes to `merkle_tree[tree_id]`; rotating the output shard per match is
what lets the leader co-include a batch's settles in one block. Also home to
the in-pool **`merge`** ix (`VALID_MERGE(K=2/4)`): consolidate K fragmented
notes into one so an order can exceed any single note.

### `crates/nyx-tee` — the in-CVM engine

Runs inside the TDX CVM. On boot it does the dstack handshake (deriving its
**K shard Ed25519 signers** + cold-booting the K Merkle mirrors), loads the
N=16 proving key (`ark` or `rapidsnark` backend per `NYX_TEE_PROVER`), and
starts: the matcher interval driver (tick → match → page into ≤16 batches →
enqueue settle), the settle scheduler (assembles + drives each batch through
lock→prove→verify→ALT→settle→close), the oracle sync, the slot poller, the
priority-fee poller, and the HTTP/WS server. The locks (Tx A), the per-batch
ALT extends (Tx C), and the settle Tx D's are each fired **concurrently** within
a batch; the settle Tx D's round-robin the K shard keys (each is fee-payer +
`tee_authority` + Ed25519 settle-signer for its shard).

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
| `VALID_MERGE` (K=2/4) | K input notes (same owner+mint, each included) consolidate into one output note of the same total | on-chain (`merge`) |

(`MatchBatch(N)` is also instantiated at N=2/4 for dev/test only.) The
in-enclave `VALID_MATCH_BATCH` prover has two interchangeable backends — `ark`
(ark-circom, default) and `rapidsnark` (C++ FFI, ~1.4× on 8 vCPU) — selected
by `NYX_TEE_PROVER` on the SAME image. Witness gen is ark-circom either way.

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
| `VaultConfig` | `[b"vault_config"]` | Global singleton: `tee_pubkeys[16]` + `num_tee_keys`, `num_trees`, `zero_subtree_roots`, admin, root key, protocol-owner commitment, fee bps. Read-only on the settle hot path (no tree state). |
| `MerkleTree` | `[b"merkle_tree", &[tree_id]]` | **Per-shard** (K of them): `leaf_count` (offset 8), `current_root` (offset 16), the 64-root ring, the depth-20 right-path. Settles to different shards write distinct accounts. |
| `WalletEntry` | `[b"wallet", user_commitment]` | Registered user commitment (1:1; `init` = replay guard) |
| `NullifierEntry` | `[b"nullifier", nullifier]` | A VALID_SPEND / merge-consumed note |
| `ConsumedNoteEntry` | `[b"consumed_note", note_commitment]` | A TEE-settle-consumed input note |
| `NoteLock` | `[b"note_lock", note_commitment]` | The pin between match and settle (TTL-bounded) |
| `OutstandingMint` | `[b"outstanding_mint", mint]` | Per-mint solvency counter (`deposit++`, `withdraw--`; `merge` is value-preserving → unchanged) |
| `BatchValidityMarker` | `[b"batch_validity", batch_merkle_root]` | **1:N** — one per batch, written by `verify_match_batch`, closed by `close_batch_validity_marker` |

Plus the per-mint `vault_token_account` PDAs (the actual SPL custody) and a
rolling per-batch Address Lookup Table (managed by the settle worker) holding
the payload-derivable settle PDAs — the note-lock, consumed-note, nullifier,
and marker accounts — so each Tx D references them by 1-byte index. The K
`MerkleTree` PDAs live in the static settle ALT alongside `vault_config` +
sysvar + system program.

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
* **TEE trust.** The vault trusts only the keys in `VaultConfig.tee_pubkeys`.
  Clients verify the enclave's TDX attestation before sending order data. A
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
3. **Devnet state** — `vitest run tests/devnet-setup.test.ts` (`RUN_DEVNET_E2E=1`,
   `NYX_NUM_TREES=K`) creates mints + the K `MerkleTree` shards + the K-tree
   static settle ALT + protocol config + resets every shard, writing
   `.devnet/e2e-config.json` (incl. `numTrees` + `merkleTreePdas[]`). A tree
   reset is mandatory after any circuit/VK change or note-model migration; a
   `VaultConfig` layout change needs `close-vault-config.mjs` first (§4.4).
4. **Build + deploy the CVM** — bump the image tag, push it (CI → ghcr),
   `phala deploy -e <env>` (`NYX_TEE_NUM_TREES=K` matching), register the CVM's
   K shard signers (`rotate-tee-pubkey.mjs <K0..Kn>`), fund each
   (`fund-tee-keys.mjs`). Mind the mint regime (real-mint for `cvm-settle-e2e`,
   placeholder for the loadgen) — see `CLAUDE.md §3`.
5. **Validate** — `cvm-settle-e2e` (real settle through the CVM),
   `cvm-multimatch-settle` (settle-throughput / co-inclusion profile),
   `devnet-deposit-withdraw` + `devnet-merge` (no-CVM vault crypto), the loadgen
   (intake throughput). **Stop the CVM after** (it bills).

## Deployed program ids (devnet)

* vault: `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`

(The matching_engine program id is retired — the program was deleted.)
