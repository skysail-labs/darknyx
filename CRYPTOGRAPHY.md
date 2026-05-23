# Nyx Darkpool — Cryptographic Design Walkthrough

> A protocol-engineer's tour through the cryptography of Nyx as of the
> `nyx-v2-onchain-hardening` branch through the **v3.5 batched-validity
> migration**. Written for readers comfortable with ZK proofs and field
> arithmetic who have not seen this codebase before. Pairs with
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (system-level overview)
> and [`darkpool_protocol_spec_v3_changed.md`](darkpool_protocol_spec_v3_changed.md)
> (the original spec — note that the spec is partially out of date; this
> document is current).

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Threat model + invariants](#2-threat-model--invariants)
3. [Cryptographic primitives](#3-cryptographic-primitives)
4. [The key model](#4-the-key-model)
5. [The note system](#5-the-note-system)
6. [The incremental Merkle tree](#6-the-incremental-merkle-tree)
7. [The five ZK circuits](#7-the-five-zk-circuits)
8. [Lifecycle walkthrough — wallet to withdraw](#8-lifecycle-walkthrough)
9. [Settlement mechanics — what fits in a Solana tx and why](#9-settlement-mechanics)
10. [Solvency invariant](#10-solvency-invariant)
11. [Replay protection layered across PDAs](#11-replay-protection)
12. [Test coverage map](#12-test-coverage-map)
13. [What is deliberately NOT yet implemented](#13-what-is-not-yet-implemented)

---

## 1. Executive summary

Nyx is a privacy-preserving CLOB-like darkpool on Solana. The custody side is
shielded (UTXO notes, Groth16 proofs); the matching side runs in a TEE
(currently a software Ed25519 key, eventually an attested enclave) that signs
match payloads back to L1 for atomic settlement.

The protocol is layered as **L1 (Solana)** + **ER (MagicBlock Ephemeral
Rollup)** + **client (TypeScript SDK + snarkjs prover)**:

| Layer | Responsibility | Trust |
|---|---|---|
| **L1** | Custody, Merkle tree, ZK verifiers, atomic settlement | Trustless |
| **ER** | Hidden order intent + uniform-clearing-price match | Trustless except for liveness |
| **TEE** | Computes the match, signs the result | Trusted for fairness, **NOT** trusted for custody |
| **Client** | Key derivation, proof generation, ix builders | Local user trust |

The hardening work landed in four labelled phases. Each tightens the
on-chain trust surface so the TEE can no longer steal custody — only
deny liveness:

- **v2** — `VALID_INPUT` Groth16 (lock-time proof of leaf ownership +
  mint binding), `NoteLock.token_mint` cryptographically bound,
  `MAX_LOCK_TTL_SLOTS` ceiling, `outstanding[mint]` per-mint solvency
  counter. Closes phantom-locking, forever-locking, and TEE mint lies.
- **v3** — `VALID_CREATE` Groth16 + `ValidCreateMarker` PDA seeded by
  the binding hash. Closes "TEE misroutes Alice's trade leg to itself."
- **v3.1** — `VALID_PRICE` Groth16 + `ValidPriceMarker` PDA + the
  VersionedTransaction-with-ALT settle tx. Closes "TEE clears at any
  price inside the Pyth circuit-breaker tolerance" by moving the
  price guard from TEE-controlled `run_batch` into a Groth16 verified
  at settle time.
- **v3.5 (current)** — `VALID_MATCH_BATCH` Groth16 attests
  VALID_CREATE + VALID_PRICE for every match in a batch (N ≤ 16) at
  once. `verify_match_batch` writes one `BatchValidityMarker` PDA
  per batch (keyed by the Merkle root over per-slot leaves);
  `tee_forced_settle_batched` walks a depth-4 inclusion path against
  it; `close_batch_validity_marker` reclaims the marker's rent after
  the last settle. Net result on a full N=16 batch: ONE Groth16 + N
  Merkle-inclusion-checked settles + ONE close replace 2N verify ixs
  + N settles closing 2N markers. The v3.1 per-match ixs remain
  callable during a soft-cutover window so matchers can migrate per
  batch.

Everything is validated end-to-end against a real devnet deployment
under `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx` (vault) and
`6EasFxo6RCWrK4KAwcdUJqL4KjReLC3rtah8EtHgHSqe` (matching_engine).

---

## 2. Threat model + invariants

### Adversaries we defend against

| Adversary | Attack vector | Defender |
|---|---|---|
| Anonymous L1 observer | Front-running of unmatched orders | Order intent never on L1 (lives in ER) |
| Anonymous L1 observer | Linking deposits to withdrawals | Poseidon-commitment Merkle tree; Groth16 hides spending key |
| L1 anyone | Replay of TEE-signed settlement | `ConsumedNoteEntry` + `NullifierEntry` + `ValidCreateMarker` PDAs (init-time PDA collision) |
| L1 anyone | Withdraw without ownership proof | `VALID_SPEND` Groth16 verified on-chain |
| Compromised TEE | Phantom-lock a fake note commitment | `VALID_INPUT` proof at lock time (v2) |
| Compromised TEE | Forever-lock a real note (censorship) | `MAX_LOCK_TTL_SLOTS` cap (v2) |
| Compromised TEE | Misroute output legs / mis-mint outputs | `VALID_CREATE` proof at verify_valid_create time (v3) |
| Compromised TEE | Over-claim SPL pool via fake outputs | `outstanding[mint]` counter (v2) |
| Anyone | Double-withdraw the same note | `NullifierEntry` PDA |
| Anyone | Double-spend via lock + withdraw race | `NoteLock` PDA blocks withdraw while locked |

### Explicit non-goals (yet)

| Threat | Status |
|---|---|
| TEE clears at a bad price (within Pyth circuit-breaker tolerance) | **Open** — `VALID_PRICE` not implemented (spec §7.6). Today guarded by an oracle band check inside `run_batch`, which is itself TEE-controlled. |
| TEE-binary substitution | **Open** — `tee_pubkey` is a software Ed25519 key. Production must pin it to an attested enclave. |
| Trusted-setup ceremony soundness | **Open** — all four Groth16 circuits use a deterministic dev contribution. Real Phase-2 MPC required for mainnet. |
| Aggregate trade analytics after `BatchResults` commits | **By design** — match volume + clearing price are public per batch. |
| Network-level traffic analysis | Partially mitigated by PER JWT session manager; not fully eliminated. |

### Invariants the on-chain code maintains

Every state-transitioning instruction maintains:

1. **Conservation per-leg**:
   `lock_a.amount == quote_amount + buyer_change_amt + buyer_fee_amt`
   (and symmetrically for `lock_b`). Enforced with `u64::checked_add`.
2. **Conservation per-mint** (NEW in v2/v3):
   `outstanding[mint] ≤ vault_token_account.amount` for every mint, after
   every deposit / withdraw.
3. **Mint binding**: `lock.token_mint` is cryptographically pinned to the
   Merkle leaf via `VALID_INPUT`; recorded in the lock PDA; propagated into
   change-note relocks; bound into `VALID_CREATE`'s binding hash.
4. **Single-spend per note**: a note's `commitment` can either be consumed
   by `tee_forced_settle` (records a `ConsumedNoteEntry` keyed by
   commitment) or spent by `withdraw` (records a `NullifierEntry` keyed by
   nullifier), but not both. Cross-direction: `withdraw` refuses while a
   `NoteLock` or `ConsumedNoteEntry` is present.
5. **Bounded TTL**: every `NoteLock` and `ValidCreateMarker` has an
   `expiry_slot ≤ clock.slot + MAX_*_TTL_SLOTS`. No state hangs forever.

---

## 3. Cryptographic primitives

| Primitive | Where | Rationale |
|---|---|---|
| **BN254 Fr** | Field for all in-circuit arithmetic | Solana's `alt_bn128` syscalls give us groth16-solana on-chain; native EVM-compatible curve. |
| **Poseidon over BN254 Fr** | All note / nullifier / owner / user commitments + Merkle internal hash | SNARK-efficient (sub-100 constraints per round vs. thousands for SHA). Identical Rust (`light-poseidon`) and circom (`circomlib`) implementations — parity verified. |
| **SHA-256** | TEE-signed canonical payload hash, VALID_CREATE binding hash, prover-input encoding | Off-circuit ambient hash. Solana-native (no syscall surprises). |
| **HKDF-SHA256** | Spending key, root Ed25519 seed, trading-key offset derivation | RFC 5869 standard. 512-bit output → mod-p for BN254 keys, 256-bit output → Ed25519 seed. |
| **KMAC256** | Viewing key + per-note blinding factor | NIST SP 800-185. Used in lieu of HKDF for the viewing chain to match Umbra's pattern (KMAC256 is XOF-style — long outputs are cleaner). |
| **Ed25519** | TEE signature on match payload, trading-key signatures | Solana-native (built-in precompile for verification). |
| **Groth16** (BN254, snarkjs / `groth16-solana`) | All four ZK circuits | Constant-size proofs (256 bytes on-chain), constant-time verification, well-supported tooling. The proof system that fits Solana's CU budget. |

### Field-element representations

This part is a frequent source of cross-implementation bugs, so it's pinned
down everywhere:

- A BN254 Fr element is encoded as **32 bytes big-endian** in all on-chain
  account data, proof public inputs, and TS Buffer serialization.
- A `Pubkey` (32 bytes, e.g. an SPL mint or owner key) does *not* fit in one
  Fr (Fr ≈ 2^254). It's split into **two halves** as Poseidon/circuit inputs:
  `lo = bytes[16..32]` and `hi = bytes[0..16]`, each left-padded with 16 zero
  bytes to 32 bytes BE. Convention is consistent in `darkpool-crypto/src/field.rs::pubkey_to_fr_pair`,
  `packages/sdk/src/utxo/note.ts::pubkeyToFrPair`, and every on-chain
  ix-arg packer.
- A `u64` amount becomes a 32-byte BE Fr by left-padding 24 zero bytes,
  then 8 bytes BE.
- `fr_from_be_bytes` (strict) rejects out-of-field inputs with `NotInField`.
  `fr_from_uniform_bytes` (lenient) silently mod-p-reduces — used only for
  KDF outputs, where bias < 2^-256 from the 512-bit input is acceptable.

### Sampling soundness

- Keys derived from the 64-byte master seed go through HKDF or KMAC256
  outputting **512 bits**, then `mod p` reduction. For BN254 r ≈ 2^254, this
  gives a statistical bias of < 2^-256 — indistinguishable from uniform in
  practice. The choice of 64-byte master seed is mostly to ensure adequate
  initial entropy from any source.
- Blinding factors per note use the same 512-bit derivation (KMAC256 with a
  per-note counter), so each note has independent randomness even when
  derived from the same master seed.
- The spending key and viewing key use disjoint info strings
  (`"darkpool_spend_key_v1"` vs. `"darkpool_viewing_key_v1"`) so they're
  cryptographically independent even from the same seed.

---

## 4. The key model

Section 4 of the spec calls these the "four keys"; the implementation lives
in `crates/darkpool-crypto/src/keys.rs` and mirrors in
`packages/sdk/src/keys/key-generators.ts`.

### The four keys

| Key | Type | Domain | Purpose | Rotation? |
|---|---|---|---|---|
| **Root Key** | Ed25519 (Solana keypair) | L1 transactions | Cold custody, signs `create_wallet`. Optional — users with their own Solana wallet skip this. | Manual (admin-gated) |
| **Trading Key** | Ed25519 (Solana keypair) | ER `submit_order`, `cancel_order` | Hot wallet for order-side actions. Derived by `offset` so rotation doesn't invalidate `user_commitment`. | Free (offset++) |
| **Spending Key** | BN254 Fr scalar | In-circuit | Proves note ownership (`VALID_SPEND`, `VALID_INPUT`). Cold / HSM in production. | None — leaks ≡ funds loss |
| **Viewing Key** | BN254 Fr scalar | Off-chain encryption + compliance | Master viewing key for compliance disclosure (§13). | None for now |

### Derivation chain

```
master_seed (64 bytes, CSPRNG or wallet-signature derived)
  │
  ├── HKDF-SHA256("darkpool_root_key_v1", 32B)              → root_key (Ed25519 seed)
  ├── HKDF-SHA256("darkpool_trading_key_v1" ‖ offset_u64_le, 32B) → trading_key(offset) (Ed25519 seed)
  ├── HKDF-SHA256("darkpool_spend_key_v1", 512b) → mod p     → spending_key (Fr)
  └── KMAC256("darkpool_viewing_key_v1", 512b) → mod p       → viewing_key   (Fr)

Per-note blinding (independent from the above):
  KMAC256("note_blinding_v1" ‖ counter_u64_le, 512b) → mod p → blinding_r(counter) (Fr)
```

The 512-bit→mod-p path is statistically uniform per the sampling note in §3.

### Two commitments

The key chain produces **two important commitments** that appear on-chain or
in proofs:

#### `owner_commitment`

```
owner_commitment = Poseidon2(spending_key, r_owner)
```

Where `r_owner` (alternately `ownerCommitmentBlinding`) is a wallet-level
blinding factor. **Reused across every note the user creates.**

This is the field-element value the chain knows you by. It's part of every
note's preimage (so the chain can't link your notes to your Solana pubkey,
only to this owner_commitment). It's revealed never — it's a private witness
to every proof.

Why a single `r_owner` (rather than per-note `r_owner`)? Cryptographically,
the per-note `blinding_r` already provides note-level unlinkability. A
shared `r_owner` simplifies key management (no need to track per-note
ownership blinders). Two notes from the same user *would* be linkable if an
attacker had their `spending_key` — but in that case the attacker has full
authority anyway, so no marginal damage.

#### `user_commitment`

```
rootHash    = Poseidon3(root_pubkey_lo, root_pubkey_hi, r0)
spendHash   = Poseidon2(spending_key, r1)
viewHash    = Poseidon2(viewing_key, r2)
leafPair    = Poseidon2(rootHash, spendHash)
user_commitment = Poseidon2(leafPair, viewHash)
```

A Merkle-like 3-leaf commitment binding all three "long-lived" keys (root,
spending, viewing). Crucially, **the trading key is NOT in user_commitment**.
This means a trading-key rotation (just bumping the `offset`) does NOT
require regenerating `user_commitment` or re-running `create_wallet`.

`user_commitment` is the single 32-byte value stored in the `WalletEntry`
PDA on-chain after `create_wallet`.

### Why not just `owner_commitment = Poseidon(spending_key)`?

Without `r_owner`, two different users with the same spending key (if such
a degenerate case existed) would collide. More importantly, `r_owner`
provides a layer of indirection so that:
1. If the spending_key alone leaks (HSM compromise) but `r_owner` was kept
   separately, the attacker can't derive `owner_commitment` and hence can't
   identify which notes are yours.
2. `r_owner` can be rotated for a *new* identity (different owner_commitment)
   without changing the spending key — this is hypothetical key recovery
   path.

### Parity testing

Every key derivation has byte-for-byte cross-environment parity tests:

- `packages/sdk/tests/keys-parity.test.ts` — 12 cases covering spending,
  viewing, trading-with-offset, root, and per-counter blinding. Each one
  shells out to a Rust helper binary (`crates/darkpool-crypto/examples/derive-keys`)
  and asserts byte-equality.
- `packages/sdk/tests/user-commitment-parity.test.ts` — `user_commitment`
  must match across TS (`userCommitmentFromKeys`) and Rust
  (`user_commitment_from_keys`). The test explicitly verifies that the
  trading key is structurally excluded.

---

## 5. The note system

Nyx is a UTXO darkpool. Every shielded balance is a **note** — a logical
record of one (mint, amount, owner) holding, identified on-chain only by
its 32-byte Poseidon commitment.

### Note structure

```rust
struct Note {
    token_mint:       Pubkey,    // 32B — SPL mint
    amount:           u64,
    owner_commitment: [u8; 32],  // Fr — Poseidon2(spending_key, r_owner)
    nonce:            [u8; 32],  // Fr — per-note, unique
    blinding_r:       [u8; 32],  // Fr — per-note, random
}
```

The plaintext lives off-chain (in the user's local store, or in the TEE's
state for ER-resident notes). The chain only sees the commitment.

### The commitment formula

```
note_commitment = Poseidon6(
    mint_lo, mint_hi,           // pubkey split into two 128-bit halves
    amount,                     // u64 as Fr
    owner_commitment,           // Fr
    nonce,                      // Fr
    blinding_r,                 // Fr
)
```

A 6-input Poseidon hash, output is one Fr → 32 BE bytes.

Reference: `crates/darkpool-crypto/src/note.rs::commitment_from_fields`,
mirror in `packages/sdk/src/utxo/note.ts::noteCommitment`, identical
constraint in `circuits/valid_spend/circuit.circom:78-86` and
`circuits/valid_create/circuit.circom:106-114`. Parity test:
`packages/sdk/tests/note-commitment-parity.test.ts` (4 cases including
witness-sensitivity to every input field).

### The nullifier

```
nullifier = Poseidon2(spending_key, note_commitment)
```

Deterministic per (spending_key, note_commitment) pair. Public when a note
is spent (`withdraw`). Hidden until then.

**Important historical correction**: earlier versions of the spec / arch doc
described the nullifier as `Poseidon(spending_key, leaf_index)`. The circuit
has always used `Poseidon(spending_key, note_commitment)`. Binding to the
commitment is strictly stronger — two notes with identical contents but at
different leaf indices have different commitments (because per-note
`blinding_r` is per-leaf-counter), so they still have distinct nullifiers.
The architecture doc was updated to match the circuit.

Parity test: `packages/sdk/tests/nullifier-parity.test.ts` (3 cases).

### Types of notes generated by a single match

This is the trickiest part of the protocol because **up to FIVE distinct
notes are appended to the Merkle tree per matched pair of orders**. Once you
internalise this, the rest of the settlement code makes sense.

| Symbol | Mint | Amount | Owner | When | Role |
|---|---|---|---|---|---|
| `note_c` | base | `base_amount` | buyer's `owner_commitment` (= note_a's owner) | always | **Buyer's trade leg** — the BASE they bought |
| `note_d` | quote | `quote_amount` | seller's `owner_commitment` (= note_b's owner) | always | **Seller's trade leg** — the QUOTE they received |
| `note_e` | quote | `buyer_change_amt` | buyer's `owner_commitment` | `buyer_change_amt > 0` | **Buyer's change** — leftover quote when over-collateralised |
| `note_f` | base | `seller_change_amt` | seller's `owner_commitment` | `seller_change_amt > 0` | **Seller's change** — leftover base if the order didn't fully fill |
| `note_fee` | quote or base | `buyer_fee_amt` or `seller_fee_amt` | protocol's `owner_commitment` | flushed periodically (not every match) | **Protocol fee** — accumulates in a batch ring, flushed as a single note |

Plus the two input notes that get **consumed** (not literally removed from
the tree — once added a leaf is permanent — but their commitments are
marked in `ConsumedNoteEntry` PDAs):

| Symbol | Role |
|---|---|
| `note_a` | Buyer's input — locked then consumed at settle |
| `note_b` | Seller's input — locked then consumed at settle |

**Per-side conservation law**:

```
note_a.amount = quote_amount + buyer_change_amt + buyer_fee_amt
note_b.amount = base_amount  + seller_change_amt + seller_fee_amt
```

Enforced both **on-chain** (in `tee_forced_settle`, via `u64::checked_add`
on the `lock_a.amount` / `lock_b.amount` fields written at lock time) and
**in-circuit** (in `VALID_CREATE`, via direct equality constraints — see §7).

### Why `note_e` is in QUOTE and `note_f` is in BASE

It catches everyone the first time. A buyer pays QUOTE to receive BASE; any
unused QUOTE is their change (note_e in quote mint, addressed to the buyer).
The seller pays BASE to receive QUOTE; any unsold BASE is their change
(note_f in base mint, addressed to the seller). The mint of a change note
is the **same as the input it came from**.

This is also why `tee_forced_settle` reads `lock_a.token_mint` and
`lock_b.token_mint` and passes them to `create_relock_pda` — the relock for
note_e must have `lock_a.token_mint` (= quote mint), and note_f must have
`lock_b.token_mint` (= base mint). Misrouting a mint to the wrong change
note would break VALID_SPEND at withdraw time.

### Change-note re-lock (partial-fill continuation)

When an order partially fills, its residual stays "live" via the change
note. The seller of 100 BASE who only filled 30 has a residual 70 BASE
order. The change note `note_f` (70 BASE) gets created in this batch's
settlement; if the order is `LIMIT`-type, the TEE also requests an **atomic
re-lock** by populating `payload.seller_relock_order_id` + `expiry`. The
`tee_forced_settle` ix then creates a fresh `NoteLock` PDA seeded by
`note_f`'s commitment, bound to the same `order_id`, so the order
continues into the next batch without the user lifting a finger.

The re-lock is the same NoteLock PDA shape as `lock_note`'s output, but
created via direct system_program CPI (not init) inside `tee_forced_settle`.
This bundles the relock into the settlement atomically — if the relock
fails, the entire settle reverts (so a fee/conservation passing settle that
fails relock won't leave dangling state).

### The fee accumulator (why fees flush asynchronously)

Fees accumulate inside `BatchResults.fee_accumulators` across many matches
within a batch. The actual `note_fee` is only emitted on one settlement per
batch (typically the first one) — the others have `payload.note_fee_commitment
= [0;32]` and `payload.{buyer,seller}_fee_amt = 0`. This keeps per-match tx
sizes lower (a fee note is one extra Merkle leaf and another Poseidon).

The protocol's `owner_commitment` is set via the admin-only
`set_protocol_config` ix. The protocol owner uses a fee-derivation scheme
(see `crates/darkpool-crypto/src/viewing_keys.rs` for the role/mint-aware
nonce + blinding derivation) so that the operator can reconstruct the fee
notes deterministically and withdraw them via standard `VALID_SPEND`.

---

## 6. The incremental Merkle tree

### Shape

- **Depth 20**, so capacity is 2^20 = 1,048,576 leaves.
- Internal hash: `Poseidon2(left, right)` — output of one node becomes the
  left or right input of its parent.
- Empty subtree roots `zero_subtree_roots[i] = Poseidon2^i(0)` are
  precomputed and stored in `VaultConfig` so that the "right path" append
  algorithm only needs the rightmost filled node per level.
- Root history: a **ring buffer of the last 32 roots** in
  `VaultConfig.roots[32]`. A withdraw proof's `merkle_root` may reference
  the current root or any of the previous 32. This is the standard
  Tornado-style window to avoid griefing legitimate withdraws via racing
  deposits. With ~400 ms slots this gives roughly **2 minutes of freshness**.

### Storage trick

The chain only stores **O(depth)** state:

```rust
struct VaultConfig {
    // ...
    leaf_count:         u64,                      // monotonic counter
    current_root:       [u8; 32],
    roots:              [[u8; 32]; 32],           // ring buffer
    zero_subtree_roots: [[u8; 32]; 20],           // precomputed
    right_path:         [[u8; 32]; 20],           // rightmost filled per level
    roots_head:         u8,
    // ...
}
```

A new leaf is appended in `O(depth)` Poseidon hashes: walk up the tree,
hash with either the right_path sibling or a zero_subtree_root depending on
whether we're a left or right child at each level. The right_path is updated
in place.

Reference: `programs/vault/src/merkle.rs::append_leaf` (~30 lines).

### Off-chain "shadow tree" for proof generation

Withdrawals require an inclusion proof — i.e. the 20 siblings + indices for
a given leaf. The chain doesn't store these, so an off-chain replay is
necessary. The SDK's `packages/sdk/tests/helpers/merkle-shadow.ts` is the
reference impl: maintains a full leaf list in memory and computes any
witness in `O(n * depth)` (fine for ≤ 2^20 leaves).

In production, an indexer service walks the vault's transaction history
(`vault::deposit` + `vault::tee_forced_settle` ixs) and rebuilds the tree
incrementally. The demo dapp at `apps/demo` does this in the browser via
`getSignaturesForAddress` paging — see `apps/demo/src/lib/dapp/vault-leaf-history.ts`.
(There's a long section in `apps/demo/ARCHITECTURE.md` titled "the no-indexer
tax" explaining why this exists and what an indexer would change.)

### Why depth 20

A million notes is comfortably more than the protocol needs at MVP. The
trade-off is constraint count in `VALID_SPEND` and `VALID_INPUT`: each tree
level adds one `Poseidon2` (~150 constraints) and a `Switcher` (~3
constraints). 20 levels ≈ 3000 constraints, manageable. Going to depth 30
(1B leaves) would push spend proofs to ~5000 constraints — still fine.
The on-chain Merkle state grows linearly with depth (160 bytes/level), so
depth 30 ≈ 5KB extra in `VaultConfig` — also fine.

The depth is enforced consistently in:
- `programs/vault/src/state.rs::MERKLE_DEPTH = 20`
- `circuits/valid_spend/circuit.circom:105` → `ValidSpend(20)`
- `circuits/valid_input/circuit.circom:108` → `ValidInput(20)`
- `packages/sdk/tests/helpers/merkle-shadow.ts::TREE_DEPTH = 20`

---

## 7. The six ZK circuits

Six Groth16 circuits ship; the v3.5 batched-validity circuit
(`VALID_MATCH_BATCH`) subsumes VALID_CREATE + VALID_PRICE for an
entire batch in one proof.

| Circuit | Status | Constraints | Public inputs | Purpose |
|---|---|---|---|---|
| `VALID_WALLET_CREATE` | ✅ shipped (v1) | ~250 | 1 | Bind a `user_commitment` to (root, spending, viewing) keys |
| `VALID_SPEND` | ✅ shipped (v1) | ~7,000 | 5 | Prove note ownership + Merkle inclusion at withdraw time |
| `VALID_INPUT` | ✅ shipped (v2) | 5,500 | 5 | Prove note ownership + Merkle inclusion at **lock** time, without revealing a nullifier |
| `VALID_CREATE` | ✅ shipped (v3) | 2,148 | 16 | Prove the TEE constructed output notes correctly (right mint, amount, owner) |
| `VALID_PRICE` | ✅ shipped (v3.1) | ~10k | 1 | Prove the clearing price respects the oracle band |
| `VALID_MATCH_BATCH` | ✅ shipped (v3.5) | 162,947 (N=16) | 1 | Batched VALID_CREATE + VALID_PRICE for every match in a batch (N ∈ {2, 4, 16}; only N=16 wired on-chain) |

The first five circuits use the **`pot16` Powers-of-Tau** file
(`scripts/ptau/powersOfTau28_hez_final_16.ptau`, the Hermez ceremony,
2^16 constraint capacity). `VALID_MATCH_BATCH` at N=16 needs **`pot18`**
(`powersOfTau28_hez_final_18.ptau`, ~288 MB, 2^18 capacity) because its
total constraints exceed 2^16 — `scripts/download-ptau.sh` fetches both
automatically. All six circuits use the **same deterministic dev
contribution** (seeded with the string
`"nyx-phase1-dev-contribution-$name"`); v3.5 batched zkeys additionally
run `zkey beacon 0102…1f20 10` for 10 deterministic rounds so CI can
rebuild byte-identical VK consts from source. For mainnet, every
circuit needs a real Phase-2 MPC — flagged repeatedly throughout the
spec.

Verifier-key Rust constants are auto-generated from the snarkjs JSON via
`scripts/parse-vk-to-rust.js` and live at
`programs/vault/src/zk/vk_valid_*.rs`. The on-chain verifier is
`groth16-solana v0.2.0`, which uses Solana's `alt_bn128` syscalls (the
mainnet/devnet path) and consumes ~200k CU per proof.

### 7.1 `VALID_WALLET_CREATE`

**Public input** (1): `userCommitment` (32-byte BE Fr).

**Private witnesses** (7):
- `rootKey[2]` — 128-bit halves of the Solana Ed25519 pubkey
- `spendingKey`, `viewingKey` — Fr each
- `r0`, `r1`, `r2` — Fr each, blinding factors

**Constraints**:

```
rootHash    = Poseidon3(rootKey[0], rootKey[1], r0)
spendHash   = Poseidon2(spendingKey, r1)
viewHash    = Poseidon2(viewingKey, r2)
leafPair    = Poseidon2(rootHash, spendHash)
userCommitment === Poseidon2(leafPair, viewHash)
```

Use case: a user proves they know the (root, spending, viewing) tuple
behind `userCommitment` without revealing the tuple. The on-chain
`create_wallet` ix verifies this once and registers a `WalletEntry` PDA
seeded by `userCommitment`.

Note that wallet registration is **identity-only** — it isn't checked at
withdraw time. A user could skip `create_wallet` entirely; `VALID_SPEND`
doesn't reference the wallet registry. The registry's purpose is more
ergonomic than cryptographic (lets the chain know which `owner_commitment`s
exist).

### 7.2 `VALID_SPEND`

**Public inputs** (5):
1. `merkleRoot` — the tree root the proof was generated against (must be in
   the recent-roots ring buffer)
2. `nullifier` — `Poseidon2(spending_key, note_commitment)`, revealed to
   the chain's nullifier set
3. `tokenMint[0]` — low 128 bits of the SPL mint pubkey
4. `tokenMint[1]` — high 128 bits
5. `amount` — u64, the amount the chain will SPL-transfer out

**Private witnesses** (~24):
- `spendingKey`, `ownerCommitmentBlinding` (= r_owner)
- `nonce`, `blindingR` (per-note)
- `merklePath[20]`, `merkleIndices[20]` — Merkle witness

**Constraints**:

```circom
owner_commitment = Poseidon2(spendingKey, ownerCommitmentBlinding)
note_commitment  = Poseidon6(tokenMint[0], tokenMint[1], amount,
                             owner_commitment, nonce, blindingR)
MerkleTreeChecker(20)(leaf = note_commitment, root = merkleRoot,
                      pathElements = merklePath, pathIndices = merkleIndices)
nullifier        === Poseidon2(spendingKey, note_commitment)
```

What this proves to the chain: "I know a note whose Poseidon-commitment is
at `merkleRoot`, I'm the owner (since I know the spending_key), and here is
the nullifier — verify it isn't spent yet."

Reference: `circuits/valid_spend/circuit.circom` (105 lines), on-chain
verification in `programs/vault/src/instructions/withdraw.rs:131-144`.

### 7.3 `VALID_INPUT` (new in v2)

**Public inputs** (5):
1. `merkleRoot`
2. `noteCommitment` — exposed as public so the on-chain `lock_note`'s PDA
   seed matches
3. `tokenMint[0]`, `tokenMint[1]`
4. `amount`

**Private witnesses** (~24): same as VALID_SPEND minus the nullifier.

**Constraints**:

```circom
owner_commitment = Poseidon2(spendingKey, ownerCommitmentBlinding)
noteHash         = Poseidon6(tokenMint[0], tokenMint[1], amount,
                             owner_commitment, nonce, blindingR)
noteCommitment   === noteHash
MerkleTreeChecker(20)(leaf = noteCommitment, root = merkleRoot, ...)
```

Difference from VALID_SPEND: **no nullifier is computed or revealed**.
This is critical for the lock-then-match-then-settle flow:
- A user submits an order with a VALID_INPUT proof.
- The TEE locks the note via `lock_note(commitment, mint, amount, proof, merkleRoot)`.
- If the order doesn't match, the lock expires and the note remains
  spendable. No nullifier was burned.
- If the order does match, `tee_forced_settle` consumes the note via
  `ConsumedNoteEntry` (which is keyed by `note_commitment`, not by
  nullifier). The user's eventual `VALID_SPEND`-based withdraw of this same
  note would fail at the `consumed_note_slot` guard, so no double-spend
  risk.

What this proves to the chain at lock time: "I know an unspent note in the
tree, with these declared `mint` + `amount` + `commitment`, owned by me."

The TEE then *relays* this proof but cannot forge it (no spending key).
The TEE can choose **whether** to lock a user's note (liveness) but not
**which** commitment / amount / mint to lock — those are cryptographically
pinned by the proof.

Reference: `circuits/valid_input/circuit.circom` (118 lines), on-chain
verification in `programs/vault/src/instructions/lock_note.rs:80-115`.

#### Why VALID_INPUT keeps the ownership constraint

You might think you could drop the `owner_commitment = Poseidon2(spending_key, r_owner)`
constraint, since lock_note doesn't need to prove ownership (the proof is
just attesting that the leaf exists). But:

**Attack without ownership constraint**: a deposit's `owner_commitment`,
`nonce`, and `blinding_r` are all *public* on L1 (they're args to
`vault::deposit`). Anyone reading the deposit tx can reconstruct the note
opening. Without an ownership constraint, anyone could generate a
VALID_INPUT proof for Alice's note and lock it against an arbitrary order —
DoS griefing at minimum, potentially full theft if combined with a clever
match construction.

By requiring the prover know `spending_key` such that `Poseidon2(sk, r_owner)
== owner_commitment` (where `owner_commitment` is itself a private witness
because it goes into the note's preimage), the proof can only be generated
by someone who knows the spending key. The note's actual `owner_commitment`
becomes a tightly-bound private value, hence the prover must be the owner.

### 7.4 `VALID_CREATE` (new in v3)

**Public inputs** (16):
1. `note_a_commitment`, `note_b_commitment` — input notes
2. `note_c_commitment`, `note_d_commitment`, `note_e_commitment`, `note_f_commitment` — output notes (e and f may be zero)
3. `quote_mint[0]`, `quote_mint[1]` — buyer's mint, 128-bit halves
4. `base_mint[0]`, `base_mint[1]` — seller's mint, 128-bit halves
5. `base_amount`, `quote_amount`, `buyer_change_amt`, `seller_change_amt`,
   `buyer_fee_amt`, `seller_fee_amt` — six u64s

**Private witnesses** (16):
- `a_owner_commit`, `b_owner_commit` — input owners, **stay private**
- `a_amount`, `b_amount` — input amounts (proved equal to declared sums)
- `a_nonce`, `a_blinding`, `b_nonce`, `b_blinding` — input openings
- `c_nonce`, `c_blinding`, `d_nonce`, `d_blinding` — trade-leg outputs
- `e_nonce`, `e_blinding`, `f_nonce`, `f_blinding` — change-leg outputs

**Constraints**:

```circom
// (1) Input notes are correctly opened
note_a_commitment === Poseidon6(quote_mint, a_amount, a_owner_commit,
                                a_nonce, a_blinding)
note_b_commitment === Poseidon6(base_mint, b_amount, b_owner_commit,
                                b_nonce, b_blinding)

// (2) Per-side conservation (in-circuit + on-chain)
a_amount === quote_amount + buyer_change_amt + buyer_fee_amt
b_amount === base_amount  + seller_change_amt + seller_fee_amt

// (3) Trade-leg outputs addressed to the *correct* input owners
note_c_commitment === Poseidon6(base_mint, base_amount,  a_owner_commit, c_nonce, c_blinding)
note_d_commitment === Poseidon6(quote_mint, quote_amount, b_owner_commit, d_nonce, d_blinding)

// (4) Change-leg outputs — conditional via IsZero selector
buyer_change_is_zero = IsZero(buyer_change_amt)
expected_note_e      = (1 - buyer_change_is_zero) * Poseidon6(quote_mint,
                          buyer_change_amt, a_owner_commit, e_nonce, e_blinding)
note_e_commitment    === expected_note_e

seller_change_is_zero = IsZero(seller_change_amt)
expected_note_f       = (1 - seller_change_is_zero) * Poseidon6(base_mint,
                          seller_change_amt, b_owner_commit, f_nonce, f_blinding)
note_f_commitment     === expected_note_f
```

Three key properties this proves:

1. **Owner binding** — `a_owner_commit` is pinned by constraint (1) (it's
   what makes note_a's Poseidon match), then re-used in constraints (3) and
   (4). A malicious TEE cannot redirect note_c to its own
   `owner_commit` — that would change `note_c_commitment` to a value the
   public input doesn't match.

2. **Mint binding** — `quote_mint` and `base_mint` are public inputs. The
   chain knows them (they're stored in `lock_a.token_mint` /
   `lock_b.token_mint`, pinned by VALID_INPUT). The circuit enforces that
   note_c uses `base_mint`, note_d uses `quote_mint`, note_e uses
   `quote_mint`, note_f uses `base_mint`. A TEE cannot put USDC into a
   slot expecting SOL.

3. **Conditional change-note correctness** — the `IsZero` selector encodes:
   "either `buyer_change_amt == 0` and `note_e_commitment == 0`, or
   `buyer_change_amt > 0` and `note_e_commitment` is the correct Poseidon".
   This matches the on-chain check `has_e == (buyer_change_amt > 0)` in
   `tee_forced_settle` byte-for-byte.

**Important non-promise**: the fee note (`note_fee`) is **NOT** in this
circuit. A malformed fee note would forfeit the fee (the protocol's
`owner_commitment` couldn't reconstruct it), but no user funds are at risk
— the fee is < 1% of trade volume per the BPS bound. Worst case is a small
fee loss per batch; not worth the circuit-complexity cost of conditional
fee proving. Documented in `circuits/valid_create/circuit.circom:33-39`.

Reference: `circuits/valid_create/circuit.circom` (~170 lines), on-chain
verification in `programs/vault/src/instructions/verify_valid_create.rs`.

### 7.5 `VALID_PRICE` (new in v3.1)

Closes the original "TEE clears at any price inside the Pyth circuit-
breaker tolerance" gap. The pre-v3.1 mitigation lived in `run_batch`'s
TWAP-band check, which was itself TEE-controlled — a compromised TEE
could bypass it. `VALID_PRICE` moves the check into a Groth16 verified
at settle time so the verifier (not the TEE) decides.

```
                 ┌─────────────────────────────────────┐
                 │             VALID_PRICE             │
private inputs:  │  clearing_price                     │
  oracle_twap    │  circuit_breaker_bps                │
  oracle_slot    │                                     │
                 │  // Pyth-band soundness             │
                 │  assert |clearing_price -           │
                 │         oracle_twap| ≤              │
                 │         oracle_twap *               │
                 │         circuit_breaker_bps / 10000 │
                 │                                     │
                 │  // Bind public commitment          │
                 │  price_commitment :=                │
                 │      Poseidon2(domain,              │
                 │                 clearing_price,     │
                 │                 batch_slot)         │
                 └──────────────┬──────────────────────┘
                                ▼
                       price_commitment   ← public input
```

Public inputs (1):
- `price_commitment` — Poseidon2 of (domain tag, clearing_price ‖
  batch_slot). The settle handler recomputes this from the payload's
  clearing_price + batch_slot and asserts `ValidPriceMarker` exists at
  `[b"valid_price", price_commitment]`.

The marker PDA's seed is the price commitment, so the existence of the
marker at the derived address cryptographically attests that
`verify_valid_price` succeeded for that exact `(clearing_price,
batch_slot)` pair — same construction as VALID_CREATE's binding-hash
marker (see §9 for the soundness argument).

**Tests**:
[`zk_price_roundtrip.rs`](../programs/vault/tests/zk_price_roundtrip.rs)
(in-circuit verification round-trip via snarkjs),
[`valid-price-prover.test.ts`](../packages/sdk/tests/valid-price-prover.test.ts)
(TS-side prover smoke).

### 7.6 `VALID_MATCH_BATCH` (new in v3.5)

Folds VALID_CREATE + VALID_PRICE for every match in a batch into one
Groth16 + one marker. On a full N=16 batch this is a 32× reduction
in pre-settle verify txs (32 per-match verifies → 1 batched verify)
and a ~250× speedup in TEE-side proof generation (one 6.7 s proof
instead of 64 ~30 s per-match proofs).

```
            For each slot i ∈ [0, N):
            ┌────────────────────────────────────────┐
            │  MatchSlot(i)                          │
            │    • VALID_CREATE constraints for      │
            │      (note_a..f, mints, amounts)       │
            │    • VALID_PRICE constraints for       │
            │      (clearing_price, batch_slot)      │
            │    • leaf_i := H_leaf(slot witness)    │
            └────────────────┬───────────────────────┘
                             │
                             ▼     (leaves of size N, N ∈ {2, 4, 16})
                  ┌─────────────────────────────┐
                  │  MerkleRoot(N):             │
                  │    walk levels 0..log2(N),  │
                  │    each node :=             │
                  │      Poseidon3(DOMAIN_BATCH_│
                  │                 ROOT,       │
                  │                 left,       │
                  │                 right)      │
                  └────────────┬────────────────┘
                               ▼
                         merkle_root   ← public input
```

Public inputs (1):
- `merkle_root` — the depth-`log2(N)` Poseidon Merkle root over the
  per-slot leaves. The on-chain `verify_match_batch` uses this as the
  PDA seed for `BatchValidityMarker` at `[b"batch_validity",
  merkle_root]`.

Leaf-hash construction. The on-chain `light-poseidon` caps arity at
12 (its `MAX_X5_LEN` = 13 limit), so a single Poseidon over all 19
slot fields isn't feasible. The leaf is built in two stages:

```
h_inner = Poseidon12(DOMAIN_LEAF_INNER = 20,
                     note_a_commit, note_b_commit, note_c_commit,
                     note_d_commit, note_e_commit, note_f_commit,
                     quote_mint_lo, quote_mint_hi,
                     base_mint_lo,  base_mint_hi,
                     base_amount)

leaf    = Poseidon9 (DOMAIN_LEAF_TOP = 21,
                     h_inner,
                     quote_amount,
                     buyer_change, seller_change,
                     buyer_fee, seller_fee,
                     clearing_price, batch_slot)
```

Inner-node hashes use `Poseidon3(DOMAIN_BATCH_ROOT = 22, left, right)`.
Mint pubkeys are split into 128-bit halves (lo/hi) for the same
reason as in note commitments — a 256-bit pubkey doesn't fit in one
BN254 Fr element.

Padding semantics. The prover (`helpers/match-batch-prover.ts`) auto-
pads short batches to N=16 by repeating a fixed `dummySlot()`
witness with zero amounts + zero owners. Padding is necessary
because the on-chain handler walks a fixed depth-4 Merkle path
(`walk_merkle_path_n16`). Slot 0 is always real in current tests;
slots 1..15 are dummies unless the matcher provides real data.

Constraint count grew from VALID_CREATE+VALID_PRICE (~12 k) to
162 947 at N=16, dominated by the Merkle tree + 16 × per-slot
constraints. Total non-linear + linear constraints exceed 2^16 →
requires `pot18` for setup. On-host proof generation: ~6.7 s on a
modern laptop, ~1.5 s on-chain verification.

**Tests**:
[`match-batch-prototype.test.ts`](../packages/sdk/tests/match-batch-prototype.test.ts)
(N=2 / N=4 / N=16 in-circuit verification + leaf-byte parity with
the on-chain `compute_match_leaf`).
[`tee_forced_settle_batched.rs`](../programs/matching_engine/tests/tee_forced_settle_batched.rs)
(litesvm — drives two real matches through one shared marker;
catches the v3.1→v3.5 "close after every match" regression).

---

## 8. Lifecycle walkthrough

This section walks through one full trade end-to-end. We use Alice (buyer,
wants BASE) and Bob (seller, wants QUOTE) as personas. Each step lists:

- **What happens on-chain** (which ix, which accounts mutated)
- **Which cryptographic primitive is at play**
- **Why it's there**
- **The relevant tests**

### Step 1 — Key generation (off-chain)

Alice generates a 64-byte master seed (CSPRNG). From it she derives via
`packages/sdk/src/keys/key-generators.ts`:

- `spending_key` (Fr) via HKDF-SHA256
- `viewing_key` (Fr) via KMAC256
- `trading_key(offset=0)` (Ed25519) via HKDF-SHA256 with offset 0
- `root_key` (Ed25519) via HKDF-SHA256 (skipped if she's bringing her own
  Solana keypair — the demo dapp uses Phantom)

She picks blinding factors `r0`, `r1`, `r2`, `r_owner` (random Fr each).

She computes:

- `owner_commitment = Poseidon2(spending_key, r_owner)`
- `user_commitment` via the three-leaf Poseidon Merkle described in §4

Nothing on-chain yet. The seed lives on her device. The `r_owner` is the
single piece of state she has to keep persistent — losing it loses access
to all her notes (since `owner_commitment` becomes unrecoverable).

**Tests**: `keys-parity.test.ts` (TS ↔ Rust byte-equality across all
derivations); `user-commitment-parity.test.ts` (cross-env user commitment
matches).

### Step 2 — `create_wallet` (L1)

Alice generates a Groth16 proof for `VALID_WALLET_CREATE` and submits:

```rust
vault::create_wallet(
    commitment: [u8; 32]     = user_commitment,
    proof:      Groth16Proof,
)
```

Accounts:
- `owner` (signer = root_key or Solana wallet)
- `vault_config` (ro)
- `wallet_entry` (init, seeded by `[b"wallet", user_commitment]`)
- `system_program`

The on-chain handler verifies the proof (1 public input: `user_commitment`)
and inits the `WalletEntry` PDA.

**Cryptographic primitive**: Groth16 verification via Solana's `alt_bn128`
syscalls. Verifier-key constants at `programs/vault/src/zk/vk_valid_wallet_create.rs`.
~88k CU per verification.

**Why**: identity registration. Lets future ixs (and indexers) know that
this `user_commitment` is "claimed" by a specific Solana signer. Not
load-bearing for security — withdraws don't reference `WalletEntry`, only
`VALID_SPEND` does.

**Tests**:
- `tests/snarkjs-prover.test.ts::[fullprove_emits_pi_a_pi_b_pi_c_and_public_inputs]`
  — proves the prover helper produces the right byte layout
- `programs/vault/tests/zk_roundtrip.rs` (Rust litesvm) — full ZK roundtrip
  from prover to on-chain verifier

### Step 3 — `deposit` (L1)

Alice has 5,015 USDC and wants to enter the darkpool to BUY 50 BASE at 100
quote-per-base (so 5,000 + 15 fee = 5,015 total). She sends:

```rust
vault::deposit(
    amount:           u64       = 5_015,
    owner_commitment: [u8; 32]  = ALICE_OWNER_COMMIT,
    nonce:            [u8; 32]  = nonce_from_leaf_count,
    blinding_r:       [u8; 32]  = KMAC256("note_blinding_v1" ‖ leaf_count_le, 512b) mod p,
)
```

Accounts:
- `depositor` (signer + payer)
- `vault_config` (mut)
- `token_mint` (Account<Mint>)
- `depositor_token_account` (ATA, mut)
- `vault_token_account` (PDA at `[b"vault_token", mint]`, init_if_needed, mut)
- `outstanding_mint` (PDA at `[b"outstanding_mint", mint]`, init_if_needed, mut)
- `token_program`, `system_program`, `rent`

What happens in the handler:

1. SPL `transfer_checked` 5,015 USDC from Alice → vault_token_account.
2. Compute `note_commitment = Poseidon6(mint, amount, owner_commit, nonce, blinding_r)`.
3. `append_leaf(note_commitment)` — incremental Merkle update.
4. `outstanding_mint.outstanding += 5_015` (with `u64::checked_add`).
5. Assert `outstanding_mint.outstanding ≤ vault_token_account.amount` (post-reload).

**Cryptographic primitives**:
- **Poseidon6** for the note commitment.
- **Per-mint solvency counter** maintained as an on-chain invariant.

**Why**: this is the entry point for value into the darkpool. The
deposit's args (`owner_commitment`, `nonce`, `blinding_r`) ARE public —
that's an intentional design choice. The privacy comes later: the on-chain
note is just the 32-byte commitment, and any future spending of this note
requires a VALID_SPEND proof that doesn't reveal which specific deposit
it came from.

**Tests**:
- `tests/deposit-transport.test.ts` — ix builder byte layout
- All three e2e flows exercise deposit end-to-end with real SPL transfers

### Step 4 — Order submission (in ER)

Alice submits her order to the matching engine *inside* the MagicBlock
Ephemeral Rollup, not on L1. The ix is:

```rust
matching_engine::submit_order(args: SubmitOrderArgs)
```

Where `args` carries `side`, `price_limit`, `amount`, `note_commitment`,
`user_commitment`, etc. — the order intent.

Accounts:
- `trading_key` (signer)
- `pending_order` (PDA at `[b"pending_order", market, trading_key, slot_idx]`,
  delegated to the ER validator)
- `dark_clob` (PDA, delegated)
- ... market PDAs ...

**The order intent never appears on L1.** The delegation lifecycle is:

1. L1 (one-time per user-market pair): `init_pending_order_slot` creates an
   empty `PendingOrder` PDA; `delegate_pending_order` hands it to the ER
   validator. From here on the PDA is **writable only inside the ER**.

2. ER: `submit_order` writes Alice's intent into the delegated slot.
   This tx is in the ER's append-only state, never makes it to L1.

3. The PER (Permission Group) RPC gates ingress so only authenticated
   sessions can write. Privacy mitigation against network-level traffic
   analysis.

**Cryptographic primitives**:
- Ed25519 signature on `submit_order` by the `trading_key`. The trading key
  is rotatable via offset (see §4) so a user can use a fresh per-session
  trading key and burn it after the order, breaking long-term linkage.

**Why**: this is the core privacy property of Nyx. By keeping order intent
inside the ER, L1 observers see only deposits + matches, not the
unmatched orders themselves. The unmatched anonymity-set is every order
that entered the ER but didn't fill this batch.

**Tests**:
- `tests/orders-submit.test.ts` (10 cases) — ix builder
- `tests/orders-submit.devnet.test.ts` (8 cases, env-gated) — against real ER

### Step 5 — `run_batch` (ER)

The TEE-operated matching engine periodically runs:

```rust
matching_engine::run_batch(market: Pubkey)
```

passing all delegated `PendingOrder` PDAs as `remaining_accounts`. The
handler:

1. Reads each slot.
2. Sort bids descending by price, asks ascending.
3. Find the uniform clearing price that maximizes matched volume.
4. Tie-break by `arrival_slot` (FIFO at equal price).
5. **Circuit-breaker check**: compare clearing price against
   `pyth_at_match.twap`. If
   `|clearing_price - twap| > twap * circuit_breaker_bps / 10000`, skip
   this batch (no matches written).
6. Write up to 16 `MatchResult` entries into the delegated `BatchResults`
   PDA ring buffer. Each entry records:
   - `match_id`, `batch_slot`, `clearing_price`
   - `note_buyer`, `note_seller` (= note_a, note_b commitments)
   - `note_c`, `note_d` (computed via deterministic role-based nonce
     derivation — see `crates/darkpool-crypto/src/viewing_keys.rs::TRADE_ROLE_BUYER/SELLER`)
   - `note_e`, `note_f` for partial fills
   - Fee accumulator deltas

**No cryptographic primitives at this step** — it's all integer arithmetic
inside the ER. The crypto is back at settle time when these results have
to land on L1.

**Tests**:
- 23 `matching_engine` litesvm integration tests in
  `programs/matching_engine/tests/` cover the matching algorithm, circuit
  breaker, partial fills, relock, fee accrual, etc.

### Step 6 — `undelegate_market` (ER → L1)

Periodically (typically once per batch interval), the TEE submits:

```rust
matching_engine::undelegate_market()
```

This CPIs MagicBlock's `ScheduleCommitAndUndelegate`. The MagicBlock
validator then commits the new `DarkCLOB` / `MatchingConfig` /
`BatchResults` state back to L1 and returns ownership of those PDAs to
the matching_engine program.

`PendingOrder` slots stay delegated (so future batches can match without
re-delegation).

Once the commit lands, L1 sees the new `BatchResults` content — including
all the matched pairs from this batch. The SDK polls for the L1 owner
change to know commit is done.

**Cryptographic primitive**: none directly, but conceptually this is the
"observer trust handoff" — L1 now has a record of which matches occurred,
which the TEE will reference in its settlement payloads.

### Step 7 — `lock_note` × 2 (L1, v2-hardened)

For each match, the TEE-operated relayer submits **one L1 tx with two
`lock_note` ixs**, one per side. Each ix:

```rust
vault::lock_note(
    note_commitment: [u8; 32],
    order_id:        [u8; 16],
    expiry_slot:     u64,
    amount:          u64,
    token_mint:      Pubkey,        // v2 NEW
    merkle_root:     [u8; 32],      // v2 NEW
    proof:           Groth16Proof,  // v2 NEW
)
```

Accounts:
- `tee_authority` (signer = `vault_config.tee_pubkey`)
- `vault_config` (ro — read for tee_pubkey + root recency check)
- `note_lock` (PDA at `[b"note_lock", note_commitment]`, **init**)
- `system_program`

Handler steps (v2):

1. Assert `tee_authority.key() == vault_config.tee_pubkey`.
2. Assert `merkle_root` is in `vault_config.contains_root()` (current root
   or any of the previous 32).
3. Assert `expiry_slot > clock.slot` AND `expiry_slot ≤ clock.slot + MAX_LOCK_TTL_SLOTS`
   (= 216,000 slots ≈ 24h on 400ms-slot devnet).
4. Assert `amount > 0`.
5. Construct the VALID_INPUT public inputs:
   `[merkle_root, note_commitment, mint_lo, mint_hi, u64_be32(amount)]`.
6. **Verify the Groth16 proof** against `vk_valid_input` (~88k CU).
7. Write the lock:
   ```rust
   lock.note_commitment = note_commitment;
   lock.token_mint      = token_mint;          // v2 NEW
   lock.order_id        = order_id;
   lock.expiry_slot     = expiry_slot;
   lock.locked_by       = tee_authority.key();
   lock.amount          = amount;
   lock.bump            = ctx.bumps.note_lock;
   ```

The `init` constraint on the PDA prevents double-locking the same
commitment — the second `lock_note` for note_a would collide at account
allocation. This is layer-1 of the multi-layered replay protection (§11).

**Cryptographic primitives**:
- **VALID_INPUT Groth16** — proves the locked note is real and owned by
  the order submitter (whose proof the TEE relays).
- **Ed25519** signature by `tee_authority` (covered by Solana's runtime
  signature check on the signer).

**Why VALID_INPUT was added**: pre-v2, `lock_note` accepted any 32-byte
"commitment" with any u64 amount — the TEE could lie about both. The
post-v2 chain knows the commitment is a real Merkle leaf with that mint
and amount, owned by someone with the spending key.

**Why a per-tx CU budget of 400k**: two Groth16 verifications (~88k each)
+ overhead. Set via a `ComputeBudgetProgram.setComputeUnitLimit` ix at the
top of the lock tx.

**Tests**:
- `tests/valid-input-prover.test.ts` (3 cases) — prover helper, including
  a *negative* test where the prover fails to produce a witness for a
  misrouted leaf
- All three e2e flows exercise lock_note with real VALID_INPUT proofs

### Step 8 — validity verification (L1)

Before settle the TEE lands one or more verify ixs that write marker
PDAs the settle handler will later consume. Two coexisting paths:

* **v3.5 batched (recommended).** One Groth16 covers VALID_CREATE +
  VALID_PRICE for every match in the batch. One ix, one marker PDA
  per batch:

  ```rust
  vault::verify_match_batch(
      merkle_root:  [u8; 32],     // Poseidon Merkle root over per-slot leaves
      expiry_slot:  u64,
      proof:        Groth16Proof, // VALID_MATCH_BATCH at N=16
  )
  ```

  Accounts:
  - `payer` (signer — anyone can pay; auth is the proof)
  - `marker` (PDA at `[b"batch_validity", merkle_root]`, **init**)
  - `system_program`

  Handler:
  1. Assert `expiry_slot ∈ (clock.slot, clock.slot + 300]` (= 300
     slots ≈ 2 min — same TTL as the legacy per-match markers).
  2. Pack the single public input `[merkle_root]` and verify the
     Groth16 against `vk_match_batch_n16` (~200 k CU — same order of
     magnitude as the legacy VALID_CREATE because the verifier cost
     scales with public-input count, not constraint count).
  3. Init `BatchValidityMarker`:
     ```rust
     marker.payer        = payer.key();
     marker.expiry_slot  = expiry_slot;
     marker.bump         = ctx.bumps.marker;
     ```

  One marker covers all N matches sharing the same `merkle_root`. The
  matcher pads short batches to N=16 with dummy slots before
  generating the proof so the on-chain depth-4 walker has a
  consistent shape.

* **v3.1 legacy (still callable).** Two separate verify ixs, one per
  bound proof. Marker PDAs are per-match (not per-batch). Replaced
  by the batched path for new integrations.

#### v3.1 — `verify_valid_create`

```rust
vault::verify_valid_create(
    // The 14 fields the proof attested to:
    note_a_commitment .. note_f_commitment:  [u8; 32] × 6,
    quote_mint, base_mint:                   Pubkey × 2,
    base_amount, quote_amount,
    buyer_change_amt, seller_change_amt,
    buyer_fee_amt, seller_fee_amt:           u64 × 6,
    expiry_slot:                             u64,
    proof:                                   Groth16Proof,
)
```

Accounts:
- `payer` (signer — anyone can pay; auth is the proof)
- `marker` (PDA at `[b"valid_create", binding_hash]`, **init**)
- `system_program`

The `binding_hash` is:

```
binding_hash = SHA256(
    "nyx-create-bind-v1",
    note_a_commitment, note_b_commitment,
    note_c_commitment, note_d_commitment,
    note_e_commitment, note_f_commitment,
    quote_mint.to_bytes(), base_mint.to_bytes(),
    base_amount.to_le_bytes(), quote_amount.to_le_bytes(),
    buyer_change_amt.to_le_bytes(), seller_change_amt.to_le_bytes(),
    buyer_fee_amt.to_le_bytes(), seller_fee_amt.to_le_bytes(),
)
```

— a domain-tagged SHA-256 over exactly the 14 values the VALID_CREATE
circuit attests to. Computed identically in
`programs/vault/src/instructions/verify_valid_create.rs::valid_create_binding_hash`
and `packages/sdk/src/settlement/settle-builder.ts::validCreateBindingHash`.

Handler:

1. Assert `expiry_slot > clock.slot` and `≤ clock.slot + MAX_CREATE_MARKER_TTL_SLOTS`
   (= 300 slots ≈ 2 minutes).
2. Pack the 16 public inputs into the BE-32 vector groth16-solana expects.
3. **Verify the Groth16 proof** against `vk_valid_create` (~200k CU; this
   is the heaviest verify in the protocol because of 16 public inputs).
4. Init the `ValidCreateMarker` PDA:
   ```rust
   marker.payer        = payer.key();   // for rent refund on close
   marker.expiry_slot  = expiry_slot;
   marker.bump         = ctx.bumps.marker;
   ```

**Cryptographic primitives**:
- **VALID_CREATE Groth16** — proves output notes are correctly addressed
  and minted (see §7.4).
- **Domain-separated SHA-256** for the binding hash.

**Why this needs to be a separate tx**: tx size. The VALID_CREATE proof
is 256 bytes; adding it to the already-tight settle tx would push it over
the 1232-byte cap. So the proof lives in its own tx, and the settle tx
just references the marker PDA whose existence proves the verification
happened.

**Why the binding hash is the PDA seed (rather than a stored field)**: it's
a design trick that avoids a separate "binding" arg on the settle ix.
The settle handler **recomputes** the binding hash from its own view
(`payload` + `lock_a.token_mint` + `lock_b.token_mint`), derives the
expected PDA address, and asserts equality with the supplied
`valid_create_marker` account. If the TEE submitted a verify_valid_create
for a different set of 14 values than the settle's payload, the binding
hashes would diverge → different PDA address → marker account not found
at the expected seed → settle aborts. This means there is **no way** to
forge a marker that points to one set of values but is consumed by a
settle with a different set.

**Tests**:
- `tests/valid-create-prover.test.ts` (3 cases): exact-fill, with-change,
  and a misroute-rejection where snarkjs correctly fails to find a witness
  when the prover tries to assign note_c to a different owner_commit than
  note_a's
- `tests/change-note-flow.test.ts` Test A + B + E all exercise this ix
  against real devnet (drop `USE_BATCHED_PROOF` to take the v3.1
  path; the same tests also cover the v3.5 batched path)

#### v3.1 — `verify_valid_price`

Mirror construction for the v3.1 price guard:

```rust
vault::verify_valid_price(
    price_commitment: [u8; 32],   // Poseidon2(domain, clearing_price ‖ batch_slot)
    batch_slot:        u64,
    expiry_slot:       u64,
    proof:             Groth16Proof,
)
```

Marker PDA at `[b"valid_price", price_commitment]`. Handler verifies
the Groth16 against `vk_valid_price` and asserts the public input
matches the supplied commitment. v3.5's batched marker subsumes
this; v3.1 keeps it callable during cutover.

### Step 9 — settlement (L1)

The atomic per-match settlement, sent after the matcher's verify ixs
land. This is the heart of the protocol. The handler's body is the
same across v3.1 and v3.5; what differs is which marker PDA(s) it
reads + whether it closes them.

The tx contains **three ixs**:

```ts
[
  ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
  buildEd25519VerifyIx({ teePubkey, signature, message }),   // PRECOMPILE
  // v3.5 (recommended):
  buildSettleBatchedIx({ programId, teeAuthority, payload, matchIndex, merkleProof, merkleRoot }),
  // or v3.1 (legacy):
  // buildSettleIx({ programId, teeAuthority, payload, quoteMint, baseMint, priceCommitment }),
]
```

And it's sent as a **VersionedTransaction with stacked Address Lookup
Tables** (one static settle ALT created at devnet-setup + one per-batch
ALT holding the 5 derivable PDAs — see §9).

The settle ix is:

```rust
// v3.5 (recommended):
vault::tee_forced_settle_batched(
    payload:      MatchResultPayload,
    match_index:  u8,                 // 0..15, which slot in the batch
    merkle_proof: [[u8; 32]; 4],      // depth-4 inclusion path
)

// v3.1 (legacy):
vault::tee_forced_settle(payload: MatchResultPayload)
```

The payload is a 448-byte Borsh struct carrying 7 commitments, 2
nullifiers, 2 order IDs, 6 u64 amounts, 2 re-lock (order_id + expiry)
pairs, and clearing_price + batch_slot. The Rust struct definition is in
`programs/vault/src/instructions/tee_forced_settle.rs:42-80`.

Accounts (13 total, in this exact order — must match the Rust struct):

| # | Account | Role |
|---|---|---|
| 0 | `tee_authority` | signer = `vault_config.tee_pubkey` |
| 1 | `vault_config` | mut — Merkle state + tee_pubkey |
| 2 | `note_lock_a` | mut, close — input lock from step 7 |
| 3 | `note_lock_b` | mut, close — input lock from step 7 |
| 4 | `consumed_a` | init — replay protection for note_a |
| 5 | `consumed_b` | init — replay protection for note_b |
| 6 | `nullifier_a_entry` | init — nullifier recorded (belt-and-suspenders) |
| 7 | `nullifier_b_entry` | init — nullifier recorded |
| 8 | `note_lock_e` | unchecked, mut — relock destination for buyer's change |
| 9 | `note_lock_f` | unchecked, mut — relock destination for seller's change |
| 10 | `instructions_sysvar` | sysvar — for finding the Ed25519 precompile |
| 11 | `valid_create_marker` | mut — v3 marker from step 8, closed here |
| 12 | `system_program` | for CPIs |

Handler walkthrough:

1. **TEE authority check**: `tee_authority.key() == vault_config.tee_pubkey`.

2. **Ed25519 signature binding** (`verify_tee_signature`):
   walk the tx's instructions sysvar, find an `Ed25519Program` precompile
   ix, assert its inlined (pubkey, message) tuple equals
   `(tee_pubkey, canonical_payload_hash(payload))`. The precompile itself
   has already done the signature-bytes verification — the vault just
   binds it to the right key + message.

3. **Lock binding**: load `note_lock_a` and `note_lock_b`, assert their
   stored `order_id`s match the payload's. Capture
   `lock_a.token_mint` and `lock_b.token_mint` for later use.

4. **Validity marker check** — path-dependent.

   **v3.5 batched (`tee_forced_settle_batched`):**
   - Recompute the per-slot Merkle leaf via the same Poseidon12 +
     Poseidon9 stages the circuit uses (see §7.6):
     ```
     h_inner = Poseidon12(20, 6 note commits, 4 mint halves, base_amount)
     leaf    = Poseidon9 (21, h_inner, quote_amount, buyer_change,
                              seller_change, buyer_fee, seller_fee,
                              clearing_price, batch_slot)
     ```
   - Walk a depth-4 Merkle path with the caller-supplied 4 siblings +
     `match_index` (bits of `match_index` select left/right at each
     level, inner nodes = `Poseidon3(DOMAIN_BATCH_ROOT = 22, left,
     right)`).
   - Derive the expected marker PDA at
     `[b"batch_validity", computed_root]`, assert the supplied
     `batch_validity_marker.key()` matches, and assert it's
     owned-by-us + non-expired.
   - **Do NOT close it.** The marker covers all N matches in the
     batch and must remain present for matches `match_index + 1
     .. N-1`. Reclaiming the marker's rent is the job of the
     separate `close_batch_validity_marker` ix once the batch is
     fully settled (Step 9.5).

   **v3.1 per-match (`tee_forced_settle`):**
   - Recompute `binding_hash = SHA256(b"nyx-create-bind-v1" ‖ 14
     fields)` over the payload + lock mints. Derive
     `[b"valid_create", binding_hash]`, assert the supplied
     `valid_create_marker.key()` matches, owned + non-expired.
   - Recompute `price_commitment = Poseidon2(domain, clearing_price,
     batch_slot)`. Derive `[b"valid_price", price_commitment]`,
     assert the supplied `valid_price_marker.key()` matches, owned +
     non-expired.
   - Close both markers (Step 11 below).

5. **Conservation law** (existing):
   - `lock_a.amount == quote_amount + buyer_change_amt + buyer_fee_amt`
   - `lock_b.amount == base_amount + seller_change_amt + seller_fee_amt`
   - Both via `u64::checked_add` (so any overflow throws).

6. **Change-note structural binding** (existing):
   - `has_e = (note_e_commitment != [0;32])` must equal `(buyer_change_amt > 0)`
   - `has_f = (note_f_commitment != [0;32])` must equal `(seller_change_amt > 0)`
   - This prevents the TEE from claiming change without committing to a
     leaf, or vice versa.
   - Re-lock requires its corresponding change note exists.

7. **Consumed-note allocation**: `ConsumedNoteEntry` PDAs at
   `[b"consumed_note", note_a_commitment]` and `[b"consumed_note", note_b_commitment]`.
   `init` constraint → second-settle of the same input collides here.

8. **Nullifier allocation**: same pattern with `NullifierEntry` PDAs.
   Note: the chain stores `payload.nullifier_a` / `_b` without verifying
   they're the actual `Poseidon2(spending_key, note_a_commitment)`. The
   chain doesn't have spending_key. This is fine because the consumed-note
   PDAs are the real double-spend guard; the nullifier PDA is
   belt-and-suspenders for the future case where withdraw uses the *user-
   computed* nullifier (which would naturally collide with this PDA if the
   note were spent legitimately).

9. **Append output leaves to the Merkle tree**: in this order:
   - `note_c` (always)
   - `note_d` (always)
   - `note_e` (only if `buyer_change_amt > 0`)
   - `note_f` (only if `seller_change_amt > 0`)
   - `note_fee` (only if `note_fee_commitment != [0;32]` AND
     `vault_config.protocol_owner_commitment` is set)

   Each append updates `right_path`, increments `leaf_count`, and pushes
   the new root into the ring buffer.

10. **Atomic re-lock** (if requested by payload):
    - If `buyer_relock_order_id != [0;16]`: create a `NoteLock` PDA at
      `[b"note_lock", note_e_commitment]` with the new order ID. Uses
      `lock_a.token_mint` as the inherited mint. Done via direct
      `system_program::create_account` CPI (not Anchor `init`) because the
      account info `note_lock_e` is an `UncheckedAccount` (Anchor doesn't
      allow conditional init).
    - Same pattern for `seller_relock_order_id` → `note_lock_f` with
      `lock_b.token_mint`.

11. **Marker lifecycle** — path-dependent.

    **v3.5 batched**: do NOT touch the marker here. It's 1:N (one PDA
    keyed by the batch's Merkle root, covering up to 16 matches).
    Closing it would brick every subsequent match. Rent reclamation
    is the job of `close_batch_validity_marker` (Step 9.5).

    **v3.1 per-match**: close both `ValidCreateMarker` and
    `ValidPriceMarker` — read each marker's `payer`, transfer all
    lamports to it (or to `tee_authority` as fallback), zero the
    data. Each marker is 1:1 with the match, so closing them here is
    correct.

12. **Emit** `TradeSettled` event with all the leaf indices and new root.

**Cryptographic primitives at this step**:
- **Ed25519** verification via Solana precompile (the TEE's signature on
  the canonical payload hash)
- **SHA-256** binding hash recomputation
- **Poseidon2** for Merkle appends (5 hashes per match in the worst case
  ≈ 5 × ~120 CU = ~600 CU, trivial)
- **Multiple PDA `init` collisions** for replay protection

**Why this is split across THREE txs (lock + verify + settle)**: tx size.
Each Groth16 proof is 256 bytes; combining lock proofs + a settle proof +
the canonical-hash Ed25519 precompile + all the account keys + the 448-byte
payload would be ~1800 bytes total — way over the 1232 cap. By splitting:
- Lock tx (Solana legacy): 2 lock_notes with embedded VALID_INPUT proofs,
  ~1100 bytes.
- Verify tx (Solana legacy): 1 verify_valid_create with embedded
  VALID_CREATE proof, ~700 bytes.
- Settle tx (Solana V0 + ALT): Ed25519 precompile + tee_forced_settle, with
  3 static accounts hoisted into an Address Lookup Table to free up the
  ~60 bytes the marker account consumed. Around 1180 bytes.

See §9 for why the v0/ALT migration was specifically required.

**Tests**:
- `tests/devnet-trade-flow.test.ts` (exact-fill, no change) — full end-to-end
- `tests/er-trade-flow.test.ts` (ER round-trip + settle) — full end-to-end
- `tests/change-note-flow.test.ts` (5 cases including partial-fill + relock + fee)
- `tests/settle-builder.test.ts` (12 cases) — v3.1 wire-format unit tests:
  payload Borsh size (448 bytes), canonical hash byte-equality with the
  Rust fixed-vector test, Ed25519 precompile layout, account ordering.
- `tests/settle-builder-batched.test.ts` (15 cases) — v3.5 wire-format
  unit tests for `buildSettleBatchedIx` + `buildCloseBatchValidityMarkerIx`:
  13-account ordering, 585-byte ix data (disc + payload + match_index +
  4×32 siblings), Anchor `[[u8; 32]; 4]` encoding, `BatchValidityMarker`
  PDA derivation, `match_index` boundary validation [0, 15].
- `tests/tee_forced_settle_batched.rs` (litesvm, 3 cases) — v3.5
  regression test that seats two real matches at slots 0 and 1
  settling against the same marker; catches the v3.1→v3.5 "close
  after every match" regression.

### Step 9.5 — `close_batch_validity_marker` (L1, v3.5 NEW)

Lands once per batch after the last `tee_forced_settle_batched`
succeeds. Reclaims the marker's ~49-byte rent.

```rust
vault::close_batch_validity_marker(merkle_root: [u8; 32])
```

Accounts (3):
- `authority` (signer — either equals `marker.payer` for the
  fast-path, or any signer for the expiry-GC path)
- `payer` (mut — refund recipient, must equal `marker.payer`;
  Anchor `has_one = payer` enforces this)
- `marker` (mut, `close = payer`, seeded by `[b"batch_validity",
  merkle_root]`, validated via `bump = marker.bump`)

Handler:
1. If `authority.key() == marker.payer`, succeed immediately (fast
   path — the matcher closes its own marker right after the last
   settle).
2. Else, require `clock.slot > marker.expiry_slot` — anyone can
   sweep an expired marker, but the rent still flows back to
   `marker.payer` via the `has_one` constraint. This is the
   liveness-GC path: if the matcher crashes mid-batch and never
   closes, the marker isn't stranded forever.
3. Anchor's `close = payer` constraint moves the marker's lamports
   to `payer` and zeros the data.
4. Emit `BatchValidityMarkerClosed { payer, closed_by, expiry_slot }`.

The new `VaultError::BatchValidityMarkerNotExpired` covers the
"third-party signer tries to close before expiry" failure mode.

**Why this is a separate ix (not folded into settle).** The marker
is keyed by `merkle_root` — identical across all N matches in the
batch. If `tee_forced_settle_batched` closed it after each match
(as the v3.1 settle does for its 1:1 markers), match 0 would
succeed but match 1 would find the marker drained + zeroed and
fail with `BatchValidityMarkerExpired`. The v3.1→v3.5 carry-over
of this close was a real bug caught by an external PR-reviewer and
fixed; the litesvm regression test in `tee_forced_settle_batched.rs`
restores the buggy close + asserts it fails to make sure the
class-of-bug stays caught.

### Step 10 — `withdraw` (L1)

Alice now owns `note_c` (50 BASE), addressed to her `owner_commitment`. She
wants the BASE tokens on her ATA.

She generates a VALID_SPEND proof off-chain via snarkjs (witness
generation + proving takes ~2-4 seconds in Node, ~5-10 seconds in a
browser worker).

```rust
vault::withdraw(
    note_commitment: [u8; 32],
    nullifier:       [u8; 32],
    merkle_root:     [u8; 32],
    amount:          u64,
    proof:           Groth16Proof,
)
```

Accounts (10):
- `payer` (signer — anyone can pay)
- `vault_config` (mut)
- `token_mint`, `vault_token_account` (mut), `destination_token_account` (mut)
- `consumed_note_slot` (CHECK: must not exist)
- `note_lock_slot` (CHECK: must not exist)
- `nullifier_entry` (init)
- `outstanding_mint` (mut)
- `token_program`, `system_program`

Handler:

1. `amount > 0`.
2. **Layer-3 guard**: if `consumed_note_slot.owner == program_id`, this
   note was consumed by `tee_forced_settle`. Reject with `NoteAlreadyConsumed`.
   (This is exactly the "you can't spend a note that was already swapped
   for trade output legs" guard.)
3. **Layer-1 guard**: if `note_lock_slot.owner == program_id`, the note is
   currently locked to an active order. Reject with `NoteAlreadyLocked`.
4. **Recency check**: `vault_config.contains_root(&merkle_root)` — must be
   in the 32-root ring buffer.
5. **VALID_CREATE-style accounting precheck**: assert
   `outstanding_mint.outstanding >= amount`. (If it were less, the TEE
   created a phantom note for this mint and the counter rejects the
   withdraw before the SPL transfer-out.)
6. Allocate the `NullifierEntry` PDA (its `init` constraint guards against
   double-withdraw).
7. Decrement `outstanding_mint.outstanding -= amount`.
8. **Verify the Groth16 proof** against `vk_valid_spend`:
   `public_inputs = [merkle_root, nullifier, mint_lo, mint_hi, u64_be32(amount)]`.
9. SPL `transfer_checked` from `vault_token_account` → `destination_token_account`.
10. Reload `vault_token_account` and re-assert the solvency invariant.

**Cryptographic primitives**:
- **VALID_SPEND Groth16** — proves ownership + Merkle inclusion + nullifier
  derivation. ~200k CU on-chain.
- **PDA collision-based double-spend prevention**.

**Tests**:
- `tests/withdraw-transport.test.ts` (2 cases) — ix builder
- Every e2e flow ends with VALID_SPEND withdraws

### Recap — the whole flow

```
KEY GEN (off-chain)
    │  master_seed → spending_key, viewing_key, root_key, trading_key,
    │                user_commitment, owner_commitment
    ▼
CREATE_WALLET (L1, VALID_WALLET_CREATE proof)
    │  WalletEntry PDA created
    ▼
DEPOSIT (L1)
    │  SPL transferred in
    │  note_commitment = Poseidon6(...)
    │  appended to Merkle tree
    │  outstanding[mint] += amount
    ▼
SUBMIT_ORDER (ER, NOT visible on L1)
    │  PendingOrder slot delegated to ER validator
    │  trading_key signs
    ▼
RUN_BATCH (ER)
    │  Uniform clearing price match
    │  Circuit breaker against Pyth TWAP
    │  BatchResults written
    ▼
UNDELEGATE_MARKET (ER → L1)
    │  BatchResults committed back to L1
    ▼
LOCK_NOTE × 2 per match (L1, two VALID_INPUT proofs)
    │  NoteLock PDAs created at [b"note_lock", commitment]
    │  Each lock bound to (order_id, mint, amount) cryptographically
    ▼
─────────────────────────────────────────────────────────────
v3.5 batched (recommended)         │  v3.1 per-match (legacy)
─────────────────────────────────────────────────────────────
VERIFY_MATCH_BATCH (L1, 1 Groth16) │  VERIFY_VALID_CREATE +
    BatchValidityMarker PDA at     │  VERIFY_VALID_PRICE (L1)
    [b"batch_validity", merkle_root]│  ValidCreateMarker +
    Covers N matches.              │  ValidPriceMarker PDAs
                                   │  (one per match each)
─────────────────────────────────────────────────────────────
        ▼ (one per real match)
TEE_FORCED_SETTLE_BATCHED          │  TEE_FORCED_SETTLE
(L1, v0 + 2 ALTs)                  │  (L1, v0 + 1 ALT)
    Ed25519 + canonical hash       │  Ed25519 + canonical hash
    Leaf hash + 4-level Merkle     │  Binding hash + price
    inclusion path to marker       │  commitment marker checks
    Conservation + structural      │  Conservation + structural
    Consumed/Nullifier PDAs        │  Consumed/Nullifier PDAs
    Up to 5 output leaves          │  Up to 5 output leaves
    Atomic re-lock (if continuing) │  Atomic re-lock
    Marker NOT closed (1:N).       │  Both markers closed.
─────────────────────────────────────────────────────────────
        ▼ (once per batch — only v3.5)
CLOSE_BATCH_VALIDITY_MARKER (L1)
    Reclaims ~49 B rent to marker.payer.
    Pre-expiry: payer-only fast path.
    Post-expiry: any signer can sweep (rent still flows to payer).
─────────────────────────────────────────────────────────────
        ▼
WITHDRAW (L1, VALID_SPEND proof)
    │  outstanding[mint] -= amount  (rejects if insufficient)
    │  SPL transferred out
    │  NullifierEntry PDA allocated → permanent burn
```

---

## 9. Settlement mechanics

This section explains the Solana-specific implementation tricks that
keep the v3.5 settlement under the 1232-byte transaction cap. A
cryptographer reader can skip this section if they only care about the
cryptography, but the design constraints are interesting because they
explain why the protocol has the shape it does.

The v3.5 batched flow lands more txs per batch than v3.1, but FAR
fewer txs per N matches: one batched verify replaces 2N per-match
verifies, and one close replaces N per-match closes (which were folded
into v3.1 settles).

### Why multiple transactions?

A single tx that does {lock note_a, lock note_b, verify VALID_CREATE,
ed25519 precompile, tee_forced_settle} is well over the cap. Some napkin
math:

| Piece | Bytes |
|---|---|
| Tx headers + signature(s) + blockhash | ~80 |
| `ComputeBudgetProgram.setComputeUnitLimit` ix | ~20 |
| `lock_note` ix data (8 disc + 32 commit + 16 order_id + 8 expiry + 8 amount + 32 mint + 32 root + 256 proof) | 392 |
| `lock_note` accounts (4 × 32) | 128 |
| `verify_valid_create` ix data (8 disc + 6×32 commits + 2×32 mints + 6×8 amounts + 8 expiry + 256 proof) | 568 |
| Ed25519 precompile ix (header + pubkey + sig + 32-byte msg) | ~150 |
| `tee_forced_settle` ix data (8 disc + 448 payload) | 456 |
| Account keys for everything together (~13 distinct) | 416 |
| **TOTAL** | **~2200+** |

**v3.5 batched flow (recommended).** Per BATCH (one ALT + one verify
+ one close are amortised across N matches):

| Tx | Contents | Approx size | Cardinality |
|---|---|---|---|
| **Tx A — lock** | compute_budget + lock_note(a) + lock_note(b) | ~1050 B | N per batch (one per match) |
| **Tx B — verify_match_batch** | compute_budget + verify_match_batch (1 Groth16, 1 marker init) | ~640 B | 1 per batch |
| **Tx C — per-batch ALT** | createLookupTable + extendLookupTable(5 PDAs) | ~250 B | 1 per batch |
| **Tx D — settle_batched** | compute_budget + ed25519_precompile + tee_forced_settle_batched (v0 + 2 ALTs) | ~1130 B | N per batch |
| **Tx E — close** | compute_budget + close_batch_validity_marker | ~250 B | 1 per batch |

**v3.1 legacy flow (still callable).** Per MATCH:

| Tx | Contents | Approx size |
|---|---|---|
| **Tx A — lock** | compute_budget + lock_note(a) + lock_note(b) | ~1050 B |
| **Tx B1 — verify_valid_create** | compute_budget + verify_valid_create | ~720 B |
| **Tx B2 — verify_valid_price** | compute_budget + verify_valid_price | ~400 B |
| **Tx C — settle** | compute_budget + ed25519_precompile + tee_forced_settle (v0 + 1 ALT) | ~1120 B |

All fit comfortably under 1232 B. Atomic dependency is enforced by
account-existence requirements:

- `lock_note` before settle: settle's accounts list requires
  `note_lock_a` / `note_lock_b` to exist as initialized PDAs.
- `verify_match_batch` (v3.5) or `verify_valid_create + verify_valid_price`
  (v3.1) before settle: settle requires the marker PDA(s) to exist at
  addresses derived from the payload + lock mints.
- Per-batch ALT (v3.5 only) before settle: the settle tx references
  accounts via the ALT; an ALT created in the same slot is unusable,
  so the helper waits one slot after extend before sending the
  settle.

If any of these txs fail or are missing, settle aborts. The
multi-tx flow is **not atomic across txs** in the strict sense — a TEE
that lands the lock txs but never lands settle leaves rent-locked PDAs
until expiry. But the PDAs have TTLs (24h for locks, 2min for
markers), so abandoned state self-cleans.

### The marker PDA construction

The trick is that the marker PDA's *seed* is the binding hash, not its
data. The settle ix doesn't take "the binding hash" as an arg — it
recomputes it from the payload + lock mints and uses the recomputed
value to find the PDA. The flow:

```
Tx B (verify_valid_create):
    args: 14 fields                            ──┐
    binding_hash = SHA256("nyx-create-bind-v1"   │
                          ‖ 14 fields)           │ same 14 fields, same hash
    PDA seed = ["valid_create", binding_hash]    │
    marker created at this address ◀─────────────┘

Tx C (tee_forced_settle):
    payload contains 12 of the 14 fields (no mints — they come from locks)
    lock_a.token_mint, lock_b.token_mint give the 2 missing fields
    binding_hash' = SHA256("nyx-create-bind-v1" ‖ 14 fields recomputed)
    expected PDA  = find_program_address(["valid_create", binding_hash'])
    assert supplied marker.key() == expected PDA
    consume the marker ◀─── only possible if binding_hash == binding_hash'
```

**Why this is sound**: the only way for the marker at `[b"valid_create", X]`
to exist is if `verify_valid_create` was called with public inputs whose
binding hash is `X`. The settle handler recomputes `X` from its own view
of the trade (payload + lock mints, which are themselves cryptographically
pinned via VALID_INPUT). If a TEE submitted a verify_valid_create for
match Y but tried to use the resulting marker to settle match Z, the
binding hashes would differ → expected PDA address differs → the marker
account isn't there → settle aborts at `InvalidCreateBinding`.

**A subtle corner**: the marker doesn't *store* the binding hash, only the
payer and expiry. The seed alone proves the hash because PDAs are
deterministic: `find_program_address(seeds, program_id) → (pubkey, bump)`
is injective on `seeds` given a fixed program_id. So an attacker can't
trick the chain into thinking a marker at address A actually corresponds
to binding hash B — A is mathematically derived from B (+ the program id).

### Why VersionedTransaction + ALT

Test B in `change-note-flow.test.ts` exercises a partial fill with an
atomic re-lock. Its settle tx was 1243 bytes — exactly 11 over the cap.
The other settle paths (A, E) were 1232 or under.

Why the 11-byte difference? **Legacy tx serialization de-duplicates
account keys**. In the exact-fill paths, both `note_e_commitment` and
`note_f_commitment` are `[0;32]`. The `note_lock_e` PDA is derived from
`note_e_commitment`, and `note_lock_f` from `note_f_commitment` — so they
end up at the **same PDA address** (`find_program_address(&[b"note_lock", [0;32]], program_id)`).
The legacy tx encoder sees two account-key entries that hash identically
and merges them into one slot in the keys list, saving 32 bytes.

The moment `note_e ≠ 0` (any change-note path), the two PDAs become
distinct addresses and no dedup happens. Combined with the new
`ValidCreateMarker` account (also ~32 bytes), the settle tx is 32 bytes
fatter than the exact-fill case. That's enough to push it over 1232.

#### The fix: Address Lookup Table

A VersionedTransaction with an attached ALT replaces 32-byte account-key
entries with 1-byte indices into the ALT. The cost is a 32-byte ALT
pubkey reference + a few bytes of overhead in the tx header. Net: each
ALT-resolved account saves ~30 bytes.

What can be ALT'd? **Read-only and non-signer writable accounts that are
static across many txs**. Signer accounts must stay in the main key list
because their signatures need to be order-preserved. So the candidates for
the settle tx are:

| Account | Static? | In ALT? |
|---|---|---|
| `tee_authority` (signer) | varies | NO — signers can't be ALT'd |
| `vault_config` | always | ✅ |
| `note_lock_a/b/e/f` | per-match | NO |
| `consumed_a/b`, `nullifier_a/b_entry` | per-match | NO |
| `instructions_sysvar` | always | ✅ |
| `valid_create_marker` | per-match | NO |
| `system_program` | always | ✅ |

So we hoist three accounts (`vault_config`, `instructions_sysvar`,
`system_program`) into an ALT. Savings: 3 × 30 ≈ 90 bytes. More than
enough.

#### ALT setup

Created once at devnet-setup time:

```ts
const slot = await connection.getSlot("confirmed");
const [createAltIx, altPubkey] =
    AddressLookupTableProgram.createLookupTable({
        authority: admin.publicKey,
        payer:     admin.publicKey,
        recentSlot: slot,
    });
const extendIx = AddressLookupTableProgram.extendLookupTable({
    payer:        admin.publicKey,
    authority:    admin.publicKey,
    lookupTable:  altPubkey,
    addresses:    [vaultConfigPda, SYSVAR_INSTRUCTIONS_PUBKEY, SystemProgram.programId],
});
// Send both ixs in one tx, then wait one slot for the ALT to be referenceable.
```

The resulting ALT pubkey is written to `.devnet/e2e-config.json` as
`settleLookupTable` and reused by every settle tx forever.

#### v3.5: per-batch ALTs on top of the static one

The v3.5 settle adds a 1-byte `match_index` + 4 × 32-byte Merkle
siblings = 129 bytes to ix.data. That pushed `tee_forced_settle_batched`
over the 1232-byte cap even with the static settle ALT. Fix: stack a
second ALT, created once per batch, holding the 5 PDAs that vary per
match but are derivable from the payload alone:

| Account | Why it's in the per-batch ALT |
|---|---|
| `note_lock_a` | derived from `payload.note_a_commitment` |
| `note_lock_b` | derived from `payload.note_b_commitment` |
| `note_lock_e` | derived from `payload.note_e_commitment` (or zero) |
| `note_lock_f` | derived from `payload.note_f_commitment` (or zero) |
| `batch_validity_marker` | derived from the batch's `merkle_root` |

This saves another ~155 B (5 × ~30) per settle, bringing the tx
back to ~1130 B — comfortably under 1232.

Per-batch ALT creation is part of the `settleViaBatched` helper
(`packages/sdk/tests/helpers/batched-settle.ts`). Important gotcha:
`createLookupTable` requires the `recentSlot` arg to be a slot present
in the `SlotHashes` sysvar. Fetching via `getSlot("confirmed")`
occasionally picks a slot the leader skipped → `InvalidInstructionData`
("…is not a recent slot"). Use `getLatestBlockhashAndContext().context.slot`
instead — that slot is the one the blockhash was sampled at and is
therefore guaranteed to be in `SlotHashes`.

Production matchers should amortise both the per-batch ALT and the
`close_batch_validity_marker` across all N matches in the batch (one
ALT, one close per batch — not per match). For N = 16 matches this
turns 80+ per-match alt/close ops into 1 + 16 + 1 = 18 txs per batch.
ALT deactivation has a 512-slot (~3.5 minute) cooldown, so a rolling
pool of ≥ 2 ALTs is needed if batches run faster than that —
[`docs/v3.5-migration.md`](docs/v3.5-migration.md) has the full
analysis.

#### Sending a v0 tx

```ts
const lookup = await connection.getAddressLookupTable(altPubkey).then(r => r.value!);
const messageV0 = new TransactionMessage({
    payerKey:        teeKeypair.publicKey,
    recentBlockhash: blockhash,
    instructions:    [compute_budget, ed25519_ix, tee_forced_settle_ix],
}).compileToV0Message([lookup]);
const tx = new VersionedTransaction(messageV0);
tx.sign([teeKeypair]);
await connection.sendTransaction(tx);
```

The wrapper lives in `packages/sdk/tests/helpers/settle-v0.ts`. All three
e2e flows route their settle through it.

#### Result

| Test | Legacy tx size | v0 + ALT tx size |
|---|---|---|
| devnet-trade-flow (exact fill) | ~1180 | ~1100 |
| change-note-flow A (change buyer) | ~1212 | ~1130 |
| change-note-flow B (change + relock) | **1243 ❌** | ~1162 ✅ |
| change-note-flow E (fee flush) | ~1212 | ~1130 |

All five change-note tests now pass.

### The canonical payload hash

The TEE's Ed25519 signature is over a 32-byte SHA-256 hash, not the
448-byte payload directly. The hash construction (current version, post
the v6→v5 revert during devnet validation):

```rust
canonical_payload_hash(p) = SHA256(
    b"nyx-match-v5",
    p.match_id,
    p.note_a_commitment, p.note_b_commitment,
    p.note_c_commitment, p.note_d_commitment,
    p.note_e_commitment, p.note_f_commitment,
    p.note_fee_commitment,
    p.nullifier_a, p.nullifier_b,
    p.order_id_a, p.order_id_b,
    p.base_amount.to_le_bytes(),
    p.quote_amount.to_le_bytes(),
    p.buyer_change_amt.to_le_bytes(),
    p.seller_change_amt.to_le_bytes(),
    p.buyer_fee_amt.to_le_bytes(),
    p.seller_fee_amt.to_le_bytes(),
    p.buyer_relock_order_id,  p.buyer_relock_expiry.to_le_bytes(),
    p.seller_relock_order_id, p.seller_relock_expiry.to_le_bytes(),
    p.clearing_price.to_le_bytes(),
    p.batch_slot.to_le_bytes(),
)
```

Reference: `programs/vault/src/instructions/tee_forced_settle.rs::canonical_payload_hash`,
mirror in `packages/sdk/src/settlement/settle-builder.ts::canonicalPayloadHash`.
Cross-environment parity is locked down by a fixed-vector test in both:

- Rust: `canonical_payload_hash_fixed_vector` expects
  `0x0388E8...1F92` for a specific input.
- TS: `[hash_cross_env_parity]` in `settle-builder.test.ts` asserts the same
  bytes from the TS implementation.

If you ever change the payload shape, both sides must update in lock-step
or settlements will start failing across the board.

#### Why the v6 payload mints got reverted

The first cut of v3 added `quote_mint` and `base_mint` as fields in
`MatchResultPayload` and into the canonical hash (with a `b"nyx-match-v6"`
tag). The settle tx was then 1242/1232 — over the cap — because two
Pubkeys (64 bytes) had been added to the wire payload.

But the mints in the payload were **structurally redundant**:
`lock_a.token_mint` is already bound to the input note's mint via
VALID_INPUT, and the settle handler already reads it for the per-mint
conservation work. Adding the mint to the payload (and to the canonical
hash) was just duplicating information the chain could derive.

So the revert: `MatchResultPayload` shape goes back to v5, tag stays
`b"nyx-match-v5"`. Mints flow purely through the NoteLock PDAs. The
binding hash for the marker PDA (which is computed entirely on-chain
from payload + lock mints, see §8 step 8) is the one place mints are
included — it's separated from the wire payload so it doesn't bloat tx
bytes. Documentation lives in the commit message of `9e1f342`.

---

## 10. Solvency invariant

The `outstanding[mint]` counter is a per-mint PDA (one per SPL mint, seeded
by `[b"outstanding_mint", mint]`) carrying a `u64` and a recorded mint
pubkey + bump.

**Invariant**:
`outstanding_mint.outstanding ≤ vault_token_account.amount` after every
state transition.

**Maintenance**:
- `deposit(mint, amount)`: SPL transfer in → outstanding += amount → assert
  invariant.
- `withdraw(mint, amount)`: assert outstanding ≥ amount → outstanding -=
  amount → SPL transfer out → re-assert invariant.
- `tee_forced_settle`: net-zero change. Conservation per-side guarantees
  that for each mint involved, Σ inputs = Σ outputs.

**What it catches that nothing else does**: a malicious TEE attempting to
create output notes with a fake mint (one that the protocol doesn't hold
any SPL for). Without VALID_CREATE, the TEE could (say) write `note_c =
Poseidon6(USDC, 1e18, ...)` even when the trade was SOL/BASE. The vault
would have no USDC for the withdraw, but the SPL transfer would fail
*silently* and the user would never see their tokens.

With the outstanding counter, the withdraw rejects at
`InsufficientOutstanding` *before* attempting the SPL transfer — clean
error, clear logs.

Even with VALID_CREATE in place (v3), this remains useful as defence-in-
depth and as a clean error surface for off-by-one accounting bugs.

---

## 11. Replay protection

Layered. Each layer catches a different attempt to do "the same thing
twice."

| Layer | PDA | Seed | What it stops |
|---|---|---|---|
| 1 | `NoteLock` | `[b"note_lock", note_commitment]` | Second `lock_note` on the same commitment while the first is live |
| 2 | `ConsumedNoteEntry` | `[b"consumed_note", note_commitment]` | Second `tee_forced_settle` consuming the same input note |
| 3 | `NullifierEntry` | `[b"nullifier", nullifier]` | Second `withdraw` on the same note (via its nullifier) |
| 4 | `ValidCreateMarker` | `[b"valid_create", binding_hash]` | Second `verify_valid_create` for the same output set (via init collision) |

All four use Anchor's `init` constraint, which is `init-if-not-exists` —
specifically the *not-exists* part. Any attempt to init a PDA that already
has data fails atomically.

**Cross-layer**: `withdraw` *also* rejects if either `consumed_note_slot`
or `note_lock_slot` is initialized. This handles the cross-direction:
- Once a note is consumed by `tee_forced_settle` (layer 2 created), the
  user can no longer withdraw it via `VALID_SPEND` (layer 3 path blocked).
- Once a note is locked for an active order (layer 1 created), the user
  can't withdraw it out from under the lock.

The note can only "exit" once — either via settle (layer 2 + 3 combined)
or via withdraw (layer 3 alone).

---

## 12. Test coverage map

### Rust unit tests

| File | Tests |
|---|---|
| `programs/vault/src/lib.rs` | `test_id` (program ID smoke), `canonical_payload_hash_fixed_vector` (canonical hash byte-stability) |
| `crates/darkpool-crypto/src/poseidon.rs` | Poseidon round-trip determinism (4 cases) |
| `crates/darkpool-crypto/src/note.rs` | Note commitment determinism + field-sensitivity (4 cases) |
| `crates/darkpool-crypto/src/nullifier.rs` | Nullifier determinism + sensitivity (3 cases) |
| `crates/darkpool-crypto/src/user_commitment.rs` | Trading-key exclusion + 2 fixed-input fixtures |
| `crates/darkpool-crypto/src/field.rs` | `fr_from_be_bytes` strictness, edge values, mod-p reduction |
| `crates/darkpool-crypto/src/keys.rs` | Full derivation chain, distinct keys, KMAC256 output bias |

### Rust integration tests (litesvm — `programs/vault/tests/`)

| File | What it covers |
|---|---|
| `zk_roundtrip.rs` | VALID_WALLET_CREATE end-to-end (off-chain prove → on-chain verify) |
| `zk_spend_roundtrip.rs` | VALID_SPEND end-to-end including Poseidon parity across Rust + circomlib for Merkle tree |
| `user_commitment_registration.rs` | `create_wallet` flow with proof verification |
| `set_protocol_config.rs` | Admin-gated fee config; rejection of fee_rate > 10000 bps |

### Rust integration tests (litesvm — `programs/matching_engine/tests/`)

26 tests across files covering: market init, slot allocation, delegate
lifecycle, submit_order validation (size limits, mint binding, side
checks), `run_batch` (uniform clearing price, partial fills, circuit
breaker, FIFO tie-break), fee accumulator drain, change-note flow,
re-lock paths, cancel_order, expired-order pre-drain, **v3.5 multi-
match-per-marker + `close_batch_validity_marker` lifecycle**
(`tee_forced_settle_batched.rs`).

### SDK parity tests (TypeScript ↔ Rust byte equality)

| File | Cases | Tests |
|---|---|---|
| `poseidon-parity.test.ts` | 5 | Arities 2, 3, 5, 6, and the user-commitment shape |
| `keys-parity.test.ts` | 12 | Spending, viewing, trading-with-offset, root, per-counter blinding, plus distinctness asserts |
| `user-commitment-parity.test.ts` | 2 | Fixed input + varied blinding factors |
| `note-commitment-parity.test.ts` | 4 | Fixed canonical inputs, witness-sensitivity, amount edge cases (0, 1, u64::MAX), strict-vs-lenient field validation |
| `nullifier-parity.test.ts` | 3 | Fixed sk+commitment, sk/commitment sensitivity, spread of sk sizes |

### SDK ZK prover tests

| File | Cases | Tests |
|---|---|---|
| `helpers/snarkjs-prover.test.ts` | 1 | VALID_WALLET_CREATE full roundtrip via snarkjs-cli shell-out |
| `valid-input-prover.test.ts` | 3 | Exact match → proof verifies; misrouted witness → snarkjs fails; public-input ordering pinned |
| `valid-create-prover.test.ts` | 3 | Exact-fill, with-change branch, misroute-rejection (TEE assigning Alice's leg to itself → snarkjs unable to satisfy constraints) |
| `match-batch-prototype.test.ts` | 7 | v3.5 VALID_MATCH_BATCH at N=2 / N=4 / N=16, including mixed-shape coverage (one exact-fill + one over-collateralised with buyer change + fee), leaf-byte parity with on-chain `compute_match_leaf` |

### SDK unit tests (offline / RPC-free)

| File | Cases | Tests |
|---|---|---|
| `settle-builder.test.ts` | 12 | v3.1: payload Borsh size = 448 bytes, canonical hash deterministic + field-sensitive + cross-env-parity (Rust fixed vector), Ed25519 precompile layout, account ordering matches Rust struct, exact-fill + partial-fill + fee variants |
| `settle-builder-batched.test.ts` | 15 | v3.5: `buildSettleBatchedIx` 13-account layout, `tee_forced_settle_batched` discriminator, 585-byte ix.data (disc + payload + match_index + 4×32 siblings), Merkle-siblings encoding parity, `BatchValidityMarker` PDA derivation, `match_index` boundary validation, `note_lock_e/f` PDA collapse on exact-fill, plus 4 cases for `buildCloseBatchValidityMarkerIx` (account ordering, discriminator + 40-byte data, root validation, expiry-GC layout) |
| `orders-submit.test.ts` | 10 | Order submission ix wire format, including PER session glue |
| `cancel-order.test.ts` | 6 | Cancel flow + slot state transitions |
| `batch-watcher.test.ts` | 5 | `BatchResults` ring decode + watcher polling |
| `settlement-watcher.test.ts` | 8 | `Settled` event decoding + multi-batch progression |
| `inclusion-proof.test.ts` | 8 | MatchResult extraction from BatchResults |
| `deposit-transport.test.ts` | 3 | Deposit ix builder + accounts ordering |
| `withdraw-transport.test.ts` | 2 | VALID_SPEND public-input assembly + withdraw ix |
| `helpers/merkle-shadow.test.ts` | 2 | Shadow tree empty-root parity + leaf-witness shape |

### SDK end-to-end tests (env-gated, real devnet)

| File | Gate | What it does |
|---|---|---|
| `devnet-setup.test.ts` | `RUN_DEVNET_E2E=1` | Creates two SPL mints, runs `initialize` + `set_protocol_config` + `init_market` + `init_mock_oracle`, creates the v3 ALT, writes `.devnet/e2e-config.json` |
| `devnet-trade-flow.test.ts` | `RUN_DEVNET_E2E=1` | Pure-L1 trade flow: deposit → match → lock → (v3.1: verify_valid_create + verify_valid_price + settle) OR (v3.5: verify_match_batch + settle_batched + close) → withdraw |
| `er-trade-flow.test.ts` | `RUN_ER_E2E=1` | Full ER round-trip: delegate market PDAs → submit_order in ER → run_batch in ER → undelegate → settle on L1 (v3.1 or v3.5) |
| `change-note-flow.test.ts` | `RUN_CN_E2E=1` | 5 scenarios exercising change notes + atomic re-lock + privacy regression + multi-batch continuation + protocol-owner fee withdrawal — all support the batched-path toggle |
| `orders-submit.devnet.test.ts` | `RUN_DEVNET_E2E=1` | 8 cases against real ER endpoint |

### What's tested where, summary

Every cryptographic primitive has at least one parity test pinning its
byte-level behaviour across Rust + TS. Every on-chain check has at least
one integration test exercising both the happy path and (where applicable)
the failure path. Every Groth16 circuit has a prover-side test that
includes a *negative* case where the prover should fail to find a witness
— this is the most important kind of crypto test because it confirms the
constraint set is tight.

Roughly **110 tests** total in the default-CI suite (TS + Rust unit/integ),
plus **~17 env-gated devnet tests** that prove the live deployment
works. The default-CI suite covers both v3.1 and v3.5 wire formats at
the unit level; running the devnet suite twice — once without
`USE_BATCHED_PROOF` and once with — gates both production paths
end-to-end.

---

## 13. What is NOT yet implemented

Sorted roughly by cryptographic impact:

1. ~~**Phase 1c-hard cutover**~~ — DONE. v3.5 is the only on-chain
   settle path; v3.1's `verify_valid_create`, `verify_valid_price`,
   per-match `tee_forced_settle`, their state structs / VK consts /
   circom circuits, and the SDK builders that targeted them have all
   been removed. See [`docs/v3.5-migration.md`](docs/v3.5-migration.md).

2. **Real Phase-2 ceremony** — All six shipped Groth16 circuits use a
   deterministic dev contribution
   (`echo "nyx-phase1-dev-contribution-$name" | snarkjs zkey contribute`),
   plus the v3.5 batched zkeys run `zkey beacon 0102…1f20 10`. The
   toxic waste is therefore *recoverable from the build script*. This
   is fine for devnet but a hard mainnet blocker. Need a real MPC
   with ≥ 3 independent contributors and publicly verifiable
   transcripts. The PTAU files
   (`powersOfTau28_hez_final_16.ptau` + `_18.ptau`) ARE SHA-256-pinned
   in `scripts/download-ptau.sh` since 2026-05-24; that closes the
   supply-chain hole at download time but doesn't replace the
   need for a project-specific phase-2 MPC at mainnet.

3. **Real TEE attestation** — `vault_config.tee_pubkey` is just a software
   Ed25519 key. Production wants the key bound to attested enclave code
   measurements (Intel SGX/TDX, AMD SEV, or AWS Nitro). The on-chain code
   doesn't change much; the rotation mechanism (`rotate_root_key` style
   ix accepting an attestation quote and gating the rotation by code
   measurement) is what needs to be added.

4. **Indexer service** — Today the demo dapp rebuilds the Merkle tree
   in-browser by paging `getSignaturesForAddress`. Long section in
   `apps/demo/ARCHITECTURE.md` enumerates the "no-indexer tax." A real
   indexer with append-only postgres + a witness API would shrink
   `apps/demo/src/lib/dapp/*` by ~40%.

5. **`undelegate_pending_order`** — Let users release a slot back to L1
   to recover rent. Today slots stay delegated forever.

6. **`force_undelegate_on_l1`** admin ix — Emergency hatch if the ER is
   down. Without it, locked notes are stranded until expiry.

7. **Real protocol-owner keypair** — Fee notes accumulate but can't be
   withdrawn until the protocol owner is wired with a real keypair set.
   `change-note-flow` Test E exercises this path under a synthetic
   commitment.

8. **Browser prover** — `apps/demo` and the SDK shell out to
   `node_modules/.bin/snarkjs` via `execFileSync`. Fine on a server,
   unwieldy in a real browser extension. The fix is a `WebProverSuite`
   that loads snarkjs in-process via wasm-bindgen or similar.

9. **Continuous ER↔L1 commit scheduler** inside the TEE — Today commits
   happen at end-of-batch via `undelegate_market`. Production wants
   `commit_market_state` (preserves delegation) every N slots so
   settlement can pick up matches without a full undelegate cycle.

10. **Self-trade prevention** in `run_batch` — A user with two trading
    keys can match against themselves. Cheap to implement (just check same
    `user_commitment`), more about anti-leakage than soundness.

---

## Appendix A — File map

A walkthrough for someone diving into the code:

```
nyx-monorepo/
├── circuits/
│   ├── valid_wallet_create/circuit.circom    1 public input
│   ├── valid_spend/circuit.circom            5 public inputs
│   ├── valid_input/circuit.circom            5 public inputs (v2 NEW)
│   └── valid_create/circuit.circom           16 public inputs (v3 NEW)
│
├── crates/darkpool-crypto/                   The single source of truth
│   ├── src/poseidon.rs                       light-poseidon BN254 wrapper
│   ├── src/note.rs                           commitment_from_fields (Poseidon6)
│   ├── src/nullifier.rs                      Poseidon2(sk, commitment)
│   ├── src/keys.rs                           HKDF-SHA256 + KMAC256
│   ├── src/viewing_keys.rs                   role-aware nonce/blinding derivation
│   ├── src/user_commitment.rs                3-leaf Poseidon Merkle
│   ├── src/field.rs                          strict + lenient Fr conversions
│   └── examples/*                            CLI helpers for parity tests
│
├── programs/vault/                           L1 custody + ZK + settlement
│   ├── src/lib.rs                            #[program] entrypoints
│   ├── src/state.rs                          VaultConfig, NoteLock, NullifierEntry,
│   │                                          ConsumedNoteEntry, OutstandingMint (v2 NEW),
│   │                                          ValidCreateMarker (v3 NEW)
│   ├── src/errors.rs
│   ├── src/merkle.rs                         incremental tree, depth 20
│   ├── src/zk/verifier.rs                    groth16-solana wrapper
│   ├── src/zk/vk_valid_wallet_create.rs
│   ├── src/zk/vk_valid_spend.rs
│   ├── src/zk/vk_valid_input.rs              (v2 NEW)
│   ├── src/zk/vk_valid_create.rs             (v3 NEW)
│   └── src/instructions/
│       ├── initialize.rs                     VaultConfig singleton creation
│       ├── create_wallet.rs                  VALID_WALLET_CREATE verification
│       ├── deposit.rs                        SPL in + note commit + outstanding++
│       ├── lock_note.rs                      VALID_INPUT verify + NoteLock init (v2)
│       ├── release_lock.rs                   Reclaim expired locks
│       ├── verify_valid_create.rs            VALID_CREATE verify + marker init (v3 NEW)
│       ├── tee_forced_settle.rs              Ed25519 + marker + atomic state update
│       ├── withdraw.rs                       VALID_SPEND verify + SPL out + outstanding--
│       ├── set_protocol_config.rs            Admin: fee + protocol_owner
│       ├── rotate_root_key.rs                Permission Group root rotation
│       └── reset_merkle_tree.rs              DEVNET-ONLY tree wipe
│
├── programs/matching_engine/                 CLOB + ER glue (mostly non-crypto)
│
├── packages/sdk/                             TypeScript client library
│   ├── src/idl/vault-client.ts               Hand-rolled ix builders for every vault ix
│   ├── src/idl/matching-engine-client.ts     Same for matching engine
│   ├── src/idl/seeds.ts                      PDA seed constants (TS mirror of Rust)
│   ├── src/keys/*.ts                         Key derivation (TS mirror of darkpool-crypto)
│   ├── src/utxo/note.ts                      Note commitment + nullifier helpers
│   ├── src/settlement/settle-builder.ts      Payload Borsh + canonical hash + buildSettleIx
│   └── tests/
│       ├── helpers/snarkjs-prover.ts         Shell-out wrapper
│       ├── helpers/merkle-shadow.ts          Off-chain tree replay
│       ├── helpers/settle-v0.ts              v0 VersionedTransaction + ALT helper
│       ├── helpers/valid-input-prover.ts     VALID_INPUT prover (v2 NEW)
│       ├── helpers/valid-create-prover.ts    VALID_CREATE prover (v3 NEW)
│       └── *.test.ts                         the test suite enumerated in §12
│
├── scripts/
│   ├── build-circuits.sh                     Compile + ceremony for all four circuits
│   ├── parse-vk-to-rust.js                   snarkjs verification_key.json → Rust consts
│   ├── deploy-devnet.sh                      cargo build-sbf + solana program deploy
│   ├── setup-devnet.sh                       Fund test keypairs from local CLI wallet
│   └── download-ptau.sh                      Fetch Hermez pot16 (NOT yet hash-pinned)
│
└── .devnet/
    ├── keypairs/                             Persona keypairs (alice, bob, admin, tee, ...)
    └── e2e-config.json                       Per-deployment state (mints, PDAs, ALT pubkey)
```

---

## Appendix B — How to reproduce the devnet validation

```bash
# 0. Ensure Solana CLI points at devnet with a funded keypair
solana config set --url https://api.devnet.solana.com
solana balance       # need ≥ 20 SOL

# 1. One-time host setup
npm install                                # SDK + snarkjs + circomlib
bash scripts/download-ptau.sh              # pot16 + pot18 (~370 MB total)
bash scripts/build-circuits.sh             # compile all 6 circom circuits;
                                           #   regenerates vk_*.rs Rust consts

# 2. Build BPF + deploy (idempotent; reuses program-id keypairs in target/deploy/)
cargo build-sbf --manifest-path programs/vault/Cargo.toml
cargo build-sbf --manifest-path programs/matching_engine/Cargo.toml
bash scripts/deploy-devnet.sh

# 3. Setup devnet state (mints, ALT, market, reset Merkle tree)
RUN_DEVNET_E2E=1 \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  ROOT_KEY_KEYPAIR=.devnet/keypairs/root_key.json \
  node node_modules/vitest/vitest.mjs run \
    --root packages/sdk \
    tests/devnet-setup.test.ts

# 4. Run each e2e flow against the v3.5 batched path (USE_BATCHED_PROOF=1).
#    Drop the env var to run the v3.1 legacy path instead — both work
#    against the same deployed programs during the soft-cutover window.

RUN_DEVNET_E2E=1 \
  FUNDER_KEYPAIR=~/.config/solana/id.json \
  node node_modules/vitest/vitest.mjs run \
    --root packages/sdk \
    tests/devnet-trade-flow.test.ts

RUN_ER_E2E=1 \
  FUNDER_KEYPAIR=~/.config/solana/id.json \
  node node_modules/vitest/vitest.mjs run \
    --root packages/sdk \
    tests/er-trade-flow.test.ts

RUN_CN_E2E=1 \
  FUNDER_KEYPAIR=~/.config/solana/id.json \
  node node_modules/vitest/vitest.mjs run \
    --root packages/sdk \
    tests/change-note-flow.test.ts

# 5. Rust integration tests (litesvm, no devnet) — gated in CI by
#    pr-checks.yml's matching-engine-litesvm job
cargo test -p matching_engine \
    --test settle \
    --test run_batch \
    --test submit_order \
    --test tee_forced_settle_batched   # v3.5: multi-match + close ix
```

All flows should pass. The default-CI suite (without any RUN_* flag)
is:

```bash
node node_modules/vitest/vitest.mjs run --root packages/sdk
# ~110 tests pass, 17 env-gated skipped
```

CI gating:

* `pr-checks.yml` runs every commit — Rust workspace tests, all 6
  circuits compile, the SDK unit suite (covering both
  `buildSettleBatchedIx` and `buildCloseBatchValidityMarkerIx`), and
  the litesvm integration tests (including the v3.5 multi-match
  regression test).
* `nightly-devnet.yml` fires on cron + on PR comment `/test-devnet`.
  Default exercises the v3.1 path; append `--batched` (so:
  `/test-devnet --batched`) to gate v3.5 instead. Combine with
  `--partial-fill` / `--skip-er` as needed.

---

*Last updated: 2026-05-23 — v3.5 batched-validity migration:
`VALID_MATCH_BATCH` Groth16, `verify_match_batch` +
`tee_forced_settle_batched` + `close_batch_validity_marker` ixs,
`BatchValidityMarker` PDA (1:N keyed by Merkle root), per-batch ALT
pattern, multi-match litesvm regression test. Snapshot of
`nyx-v2-onchain-hardening`.*
