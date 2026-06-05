# Nyx Darkpool — Cryptographic Design Walkthrough

> A protocol-engineer's tour through the cryptography of Nyx in its
> current TEE architecture (vault + the in-CVM matcher/settler; v2
> `inner_hash` notes + the per-order anchor pool). Written for readers
> comfortable with ZK proofs and field arithmetic who have not seen this
> codebase before. Pairs with
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (system-level overview)
> and [`CLAUDE.md`](CLAUDE.md) (the agent build/deploy/test contract).

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Threat model + invariants](#2-threat-model--invariants)
3. [Cryptographic primitives](#3-cryptographic-primitives)
4. [The key model](#4-the-key-model)
5. [The note system](#5-the-note-system)
6. [The incremental Merkle tree](#6-the-incremental-merkle-tree)
7. [The four ZK circuits](#7-the-four-zk-circuits)
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

The protocol is layered as **L1 (Solana `vault`)** + **TEE (an in-CVM
matcher/settler)** + **client (TypeScript SDK + snarkjs prover)**:

| Layer | Responsibility | Trust |
|---|---|---|
| **L1** (`programs/vault`) | Custody, Merkle tree, ZK verifiers, atomic settlement | Trustless |
| **TEE** (CVM, `crates/nyx-tee`) | Hidden order intake, uniform-clearing-price match, signs the settle | Trusted for fairness + liveness, **NOT** for custody; attested via TDX quote |
| **Client** | Key derivation, proof generation, the anchor pool, ix builders | Local user trust |

The on-chain trust surface is tightened so the TEE can deny liveness but
**never steal custody**:

- **Lock-time proof.** `lock_note` is gated by a `VALID_INPUT` Groth16
  (the TEE proves it locked a real, owned leaf with the right mint, without
  revealing a nullifier). `NoteLock.token_mint` is cryptographically bound;
  `MAX_LOCK_TTL_SLOTS` bounds censorship; `outstanding[mint]` is the per-mint
  solvency counter. Closes phantom-locking, forever-locking, mint lies.
- **Settle-time proof.** `verify_match_batch` checks ONE `VALID_MATCH_BATCH`
  Groth16 covering up to N=16 matches — proving output-note construction
  (right mint/amount/owner), the clearing-price band, and per-leg
  conservation, all hashed into one batch Merkle root. It writes ONE
  `BatchValidityMarker` (keyed by that root); each `tee_forced_settle_batched`
  walks a depth-4 inclusion path against it; `close_batch_validity_marker`
  reclaims the marker's rent after the batch. Closes "TEE misroutes a leg /
  mis-mints / clears at a bad price." (Earlier designs split this into
  separate per-match `VALID_CREATE` + `VALID_PRICE` circuits; those were
  folded into the batched proof and removed.)
- **Signer pinning.** Every TEE-authority ix checks `VaultConfig.tee_pubkey`,
  rotated to the CVM's dstack-derived key; clients verify the enclave's TDX
  attestation before sending order data.

Validated end-to-end against a real devnet deployment under
`C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx` (vault — the only program),
through a Phala CVM (`cvm-settle-e2e`).

---

## 2. Threat model + invariants

### Adversaries we defend against

| Adversary | Attack vector | Defender |
|---|---|---|
| Anonymous L1 observer | Front-running of unmatched orders | Order intent never on L1 (lives in the CVM) |
| Anonymous L1 observer | Linking deposits to withdrawals | Poseidon-commitment Merkle tree; Groth16 hides spending key |
| L1 anyone | Replay of TEE-signed settlement | `ConsumedNoteEntry` + `NullifierEntry` + `BatchValidityMarker` PDAs (init-time PDA collision) |
| L1 anyone | Withdraw without ownership proof | `VALID_SPEND` Groth16 verified on-chain |
| Compromised TEE | Phantom-lock a fake note commitment | `VALID_INPUT` proof at lock time (v2) |
| Compromised TEE | Forever-lock a real note (censorship) | `MAX_LOCK_TTL_SLOTS` cap (v2) |
| Compromised TEE | Misroute output legs / mis-mint outputs | `VALID_MATCH_BATCH` proof at verify_match_batch time |
| Compromised TEE | Over-claim SPL pool via fake outputs | `outstanding[mint]` counter (v2) |
| Anyone | Double-withdraw the same note | `NullifierEntry` PDA |
| Anyone | Double-spend via lock + withdraw race | `NoteLock` PDA blocks withdraw while locked |

### Explicit non-goals (yet)

| Threat | Status |
|---|---|
| TEE clears at a bad price | **Closed** — the clearing-price band is a constraint inside `VALID_MATCH_BATCH`, verified on-chain by `verify_match_batch`. |
| TEE-binary substitution | **Open** — `tee_pubkey` is a software Ed25519 key. Production must pin it to an attested enclave. |
| Trusted-setup ceremony soundness | **Open** — all four Groth16 circuits use a deterministic dev contribution. Real Phase-2 MPC required for mainnet. |
| Aggregate trade analytics from settle txs | **By design** — match volume + clearing price are public per settled batch. |
| Network-level traffic analysis | Partially mitigated by TLS to the CVM + bearer auth; not fully eliminated. |

### Invariants the on-chain code maintains

Every state-transitioning instruction maintains:

1. **Conservation per-leg**:
   `lock_a.amount == quote_amount + buyer_change_amt + buyer_fee_amt`
   (and symmetrically for `lock_b`). Enforced with `u64::checked_add`.
2. **Conservation per-mint**:
   `outstanding[mint] ≤ vault_token_account.amount` for every mint, after
   every deposit / withdraw.
3. **Mint binding**: `lock.token_mint` is cryptographically pinned to the
   Merkle leaf via `VALID_INPUT`; recorded in the lock PDA; propagated into
   change-note relocks; bound into the `VALID_MATCH_BATCH` slot leaf.
4. **Single-spend per note**: a note's `commitment` can either be consumed
   by `tee_forced_settle_batched` (records a `ConsumedNoteEntry` keyed by
   commitment) or spent by `withdraw` (records a `NullifierEntry` keyed by
   nullifier), but not both. Cross-direction: `withdraw` refuses while a
   `NoteLock` or `ConsumedNoteEntry` is present.
5. **Bounded TTL**: every `NoteLock` and `BatchValidityMarker` has an
   `expiry_slot ≤ clock.slot + MAX_*_TTL_SLOTS`. No state hangs forever.

---

## 3. Cryptographic primitives

| Primitive | Where | Rationale |
|---|---|---|
| **BN254 Fr** | Field for all in-circuit arithmetic | Solana's `alt_bn128` syscalls give us groth16-solana on-chain; native EVM-compatible curve. |
| **Poseidon over BN254 Fr** | All note / nullifier / owner / user commitments + Merkle internal hash | SNARK-efficient (sub-100 constraints per round vs. thousands for SHA). Identical Rust (`light-poseidon`) and circom (`circomlib`) implementations — parity verified. |
| **SHA-256** | TEE-signed canonical payload hash, the batch leaf/root hashing, prover-input encoding | Off-circuit ambient hash. Solana-native (no syscall surprises). |
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
| **Trading Key** | Ed25519 (Solana keypair) | signs the order canonical (`POST /orders`) + cancels | Hot wallet for order-side actions. Derived by `offset` so rotation doesn't invalidate `user_commitment`. | Free (offset++) |
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

### Note structure (v2 — `inner_hash`)

```rust
struct Note {
    token_mint:       Pubkey,    // 32B — SPL mint
    amount:           u64,
    owner_commitment: [u8; 32],  // Fr — Poseidon2(spending_key, r_owner)
    inner_hash:       [u8; 32],  // Fr — the single per-note blinding (v2)
}
```

A note carries a **single** `inner_hash` (v2 collapsed the earlier
`(nonce, blinding_r)` pair into one field). The plaintext lives off-chain
(the user's local store, or a client-derived deterministic value); the chain
only sees the commitment. `inner_hash` is **recoverable**, not random — see
"Deriving `inner_hash`" below — so a client can regenerate every note from
its seed.

### The commitment formula

```
note_commitment = Poseidon6(
    DOMAIN_NOTE = 2,            // domain-separation tag
    mint_lo, mint_hi,          // pubkey split into two 128-bit halves
    amount,                    // u64 as Fr
    owner_commitment,          // Fr
    inner_hash,                // Fr
)
```

A 6-input Poseidon hash; output is one Fr → 32 BE bytes. **It keeps the mint
binding** (an earlier proposal to drop the mint to a Poseidon3 was a
regression — a note with no mint binding could be spent against the wrong
vault token account).

Reference: `crates/darkpool-crypto/src/note.rs::commitment_from_fields_v2`,
mirror in `packages/sdk/src/utxo/note.ts::noteCommitmentV2`, identical
constraint in `circuits/valid_spend/circuit.circom` +
`circuits/valid_input/circuit.circom` + the `MatchSlot()` template in
`circuits/templates/`. Parity test:
`packages/sdk/tests/note-commitment-parity.test.ts`.

### The nullifier

```
nullifier = Poseidon3(DOMAIN_NULL = 3, spending_key, inner_hash)
```

Crucially the nullifier is over `inner_hash`, **not** the commitment — so it
is **amount-independent**. This is the linchpin of partial-fill continuation:
because a change note's nullifier depends only on `(spending_key,
inner_hash)` and not on its (yet-unknown) amount, a client can **pre-compute
and pre-supply** the nullifiers for its future change notes at order time
(the "anchor pool", below). Public when a note is spent (`withdraw`); hidden
until then. Parity test: `packages/sdk/tests/nullifier-parity.test.ts`.

### Deriving `inner_hash` (recoverable, never random)

* **Deposit notes** — `inner_hash = deriveBlindingFactor(masterSeed,
  leafIndex)`; the client regenerates it from its seed + the on-chain leaf
  index.
* **Change / trade / fee notes** — `inner_hash = change_note::derive_inner(id,
  role)` = `SHA-256("nyx-change-inner" ‖ id_le ‖ role)` masked Fr-safe, where
  `id` is the match_id (change/trade) or slot (fee) and `role` is one of
  `CHANGE_ROLE_BUYER/SELLER`, `TRADE_ROLE_BUYER/SELLER`,
  `FEE_ROLE_BASE/QUOTE`. The client re-derives these from the match_id it
  learns in the fill memo.
* **Continuation change notes** — `inner_hash` comes from the order's
  **anchor pool** (below), so the client's pre-supplied nullifier matches.

This is a triple-ported byte-equality contract:
`darkpool_matcher::change_note::derive_inner` (Rust) ↔
`packages/sdk/tests/helpers/e2e-helpers.ts::deriveInner` (TS) ↔ the on-chain
`hashv` reference. KAT: `crates/darkpool-matcher/tests/change_note_parity.rs`
+ `packages/sdk/tests/change-note-inner-parity.test.ts`.

### Types of notes generated by a single match

**Up to SIX notes are appended to the Merkle tree per matched pair** (and
two input notes are consumed). Once you internalise this, the settlement
code makes sense.

| Symbol | Mint | Amount | Owner | When | Role |
|---|---|---|---|---|---|
| `note_c` | base | `base_amount` | buyer's `owner_commitment` | always | **Buyer's trade leg** — the BASE bought |
| `note_d` | quote | `quote_amount` | seller's `owner_commitment` | always | **Seller's trade leg** — the QUOTE received |
| `note_e` | quote | `buyer_change_amt` | buyer's `owner_commitment` | `buyer_change_amt > 0` | **Buyer's change** — leftover quote |
| `note_f` | base | `seller_change_amt` | seller's `owner_commitment` | `seller_change_amt > 0` | **Seller's change** — unfilled base |
| `note_fee_quote` | quote | quote-side fee | protocol's `owner_commitment` | per batch, fee-on | **Protocol fee (quote)** |
| `note_fee_base` | base | base-side fee | protocol's `owner_commitment` | per batch, fee-on | **Protocol fee (base)** |

Plus the two input notes **consumed** at settle (the leaf is permanent;
their commitments are marked in `ConsumedNoteEntry` PDAs): `note_a` (buyer's
input) + `note_b` (seller's input).

**Per-side conservation law**:

```
note_a.amount = quote_amount + buyer_change_amt + buyer_fee_amt
note_b.amount = base_amount  + seller_change_amt + seller_fee_amt
```

Enforced both **on-chain** (in `tee_forced_settle_batched`, via
`u64::checked_add` on the lock amounts written at lock time) and
**in-circuit** (`VALID_MATCH_BATCH` equality constraints — see §7).

### Why `note_e` is in QUOTE and `note_f` is in BASE

A buyer pays QUOTE to receive BASE; unused QUOTE is their change (note_e,
quote mint, to the buyer). The seller pays BASE to receive QUOTE; unsold
BASE is their change (note_f, base mint, to the seller). The mint of a change
note is the **same as the input it came from** — which is why
`tee_forced_settle_batched` reads `lock_a.token_mint` / `lock_b.token_mint`
and passes them to `create_relock_pda`. Misrouting a mint would break
VALID_SPEND at withdraw.

### Partial-fill continuation (the anchor pool)

When a LIMIT order partially fills, its residual stays live and **re-matches
without a client roundtrip**. The mechanism:

1. **At order time** the client submits a fixed pool of `ANCHOR_POOL_SIZE`
   (= 10) **anchors** — `(inner_hash, nullifier)` pairs it derived
   deterministically (`deriveAnchors` in `sdk/src/orders/anchor-pool.ts`).
   The pool's SHA-256 is bound into the signed order canonical (so the
   matcher can't be fed forged anchors).
2. **On a partial fill** the in-TEE matcher consumes the next anchor, builds
   the change note (note_e/f) with that anchor's `inner_hash`, rotates the
   residual order's collateral to the change note, and re-books it — all in
   enclave memory, no roundtrip.
3. **On-chain**, `tee_forced_settle_batched` creates a fresh `NoteLock` PDA
   (`create_relock_pda`) seeded by the change note's commitment, bound to the
   same order_id, atomically with the settle — so the residual is pinned and
   continues into the next batch.
4. Because the change note used the anchor's `inner_hash`, the client already
   knows that note's nullifier — so it can later spend the change note (and
   the matcher could re-match it) without ever asking the client for it.

When the pool drains the order pauses; a WebSocket top-up (`POST
/orders/{id}/anchors`, signed `AnchorTopUpCanonical`) replenishes it. This is
why decoupling the nullifier from the (amount-dependent) commitment matters:
it's what makes the pre-supplied anchors valid for notes whose amounts aren't
known until the fill.

### Protocol fee notes

Both legs pay their own protocol fee, and **both** fee notes mint per batch
(base + quote), addressed to the protocol's `owner_commitment` (set via the
admin `set_protocol_config` ix). The matcher's `flush_fee_notes` computes
them once per batch from the accumulated fees; `assemble_batch` attaches the
two commitments (`note_fee_base_commitment` + `note_fee_quote_commitment`) to
the first match's payload (the others carry `[0;32]`). The fee-note
`inner_hash` is `derive_inner(slot, FEE_ROLE_BASE/QUOTE)`, so the operator
reconstructs them deterministically and withdraws via standard `VALID_SPEND`.

Each order must lock **at least** `nominal + its own fee` collateral (intake
derives this floor in `orders.rs`) or `run_batch` rejects the match as
conservation-breaking. The CVM fee rate is `NYX_TEE_FEE_RATE_BPS` (default 30);
`VaultConfig.fee_rate_bps` is vestigial for the TEE settle path.

**Over-collateralization.** An order MAY lock a note larger than that floor —
e.g. point a 500-USDC deposit at a 50-USDC order. The client declares the
note's actual amount in the order's optional `collateral_amount` field (a
plaintext opening field, pinned to the already-signed `note_commitment` — not
in the canonical bytes); intake checks `collateral_amount ≥ floor` and the
matcher returns the surplus as a change note via the same `change = note_amount
− charge` path price-improvement already uses (`algorithm.rs`). So a user
deposits once and trades many sizes up to their largest single note; the
surplus rides the anchor-pool/fills path and is client-recoverable. (Orders
larger than any single note need the deferred in-pool note-**merge** primitive.)

**Tracking balance.** There is no account→balance server mapping (a privacy
choice). A user's balance is the sum of their own UNSPENT notes — deposits
(recorded at deposit time) + trade-change (recovered via the fills indexer) —
exactly like a wallet summing its UTXOs. "Unspent" is the on-chain note status
(`ConsumedNote`/`NoteLock` PDAs). The SDK `Wallet` (`packages/sdk/src/wallet/`)
exposes `getBalance` / `listNotes` / `selectCollateral`; everything is
recoverable from the seed + the indexer.

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

## 7. The four ZK circuits

Four Groth16 circuits ship. The matching/settlement validity proof,
`VALID_MATCH_BATCH`, proves **output-note construction + price-band +
conservation** for an entire batch (≤ N=16 matches) in one proof — it is
what earlier designs split across separate `VALID_CREATE` (output-note
correctness) and `VALID_PRICE` (oracle band) circuits, now folded inline
and verified on-chain by `verify_match_batch`. Those two standalone
circuits were removed.

| Circuit | Constraints | Public inputs | Purpose |
|---|---|---|---|
| `VALID_WALLET_CREATE` | ~250 | 1 | Bind a `user_commitment` to (root, spending, viewing) keys |
| `VALID_SPEND` | ~7,000 | 5 | Prove note ownership + Merkle inclusion at withdraw time |
| `VALID_INPUT` | ~5,500 | 5 | Prove note ownership + Merkle inclusion at **lock** time, without revealing a nullifier |
| `VALID_MATCH_BATCH` | 162,947 (N=16) | 1 | Output-note construction + price band + conservation for every match in a batch, hashed into one batch Merkle root (N ∈ {2, 4, 16}; only N=16 wired on-chain) |

The first three use the **`pot16` Powers-of-Tau** file
(`scripts/ptau/powersOfTau28_hez_final_16.ptau`, 2^16 capacity).
`VALID_MATCH_BATCH` at N=16 needs **`pot18`** (~288 MB, 2^18 capacity)
because its constraints exceed 2^16 — `scripts/download-ptau.sh` fetches
both. All circuits use the **same deterministic dev contribution**
(seeded `"nyx-phase1-dev-contribution-$name"`); the batched zkeys also run
`zkey beacon 0102…1f20 10` for 10 deterministic rounds so CI can rebuild
byte-identical VK consts. For mainnet, every circuit needs a real Phase-2 MPC.

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
note_commitment  = Poseidon6(DOMAIN_NOTE, tokenMint[0], tokenMint[1],
                             amount, owner_commitment, innerHash)
MerkleTreeChecker(20)(leaf = note_commitment, root = merkleRoot,
                      pathElements = merklePath, pathIndices = merkleIndices)
nullifier        === Poseidon2(spendingKey, note_commitment)
```

What this proves to the chain: "I know a note whose Poseidon-commitment is
at `merkleRoot`, I'm the owner (since I know the spending_key), and here is
the nullifier — verify it isn't spent yet."

Reference: `circuits/valid_spend/circuit.circom` (105 lines), on-chain
verification in `programs/vault/src/instructions/withdraw.rs:131-144`.

### 7.3 `VALID_INPUT`

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
noteHash         = Poseidon6(DOMAIN_NOTE, tokenMint[0], tokenMint[1],
                             amount, owner_commitment, innerHash)
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

### 7.4 `VALID_MATCH_BATCH`

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
[`tee_forced_settle_batched.rs`](../programs/vault/tests/tee_forced_settle_batched.rs)
(litesvm — drives two real matches through one shared marker;
catches the "close after every match" 1:N-marker regression).

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
2. Compute `note_commitment = Poseidon6(DOMAIN_NOTE, mint_lo, mint_hi, amount, owner_commit, inner_hash)`.
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

### Step 4 — Order submission (`POST /orders` → the CVM)

Alice submits her order over TLS directly to the enclave's HTTP surface —
it never touches any L1 transaction. The request body carries the order
intent (`side`, `price_limit`, `amount`, `note_commitment`,
`user_commitment`, `expiry_slot`, `arrival_nonce`), the input-note opening
(`owner_commitment`, `note_inner_hash`, `nullifier`, `merkle_root`) + a
relayed **VALID_INPUT** Groth16 proof, and the order's fixed **anchor pool**
(`ANCHOR_POOL_SIZE` = 10 `(inner_hash, nullifier)` pairs). It's signed by
the **trading key** over the order canonical (`darkpool_matcher::order_canonical`,
domain `nyx-order-v2`), whose SHA-256 of the anchor pool is bound into the
signed bytes.

Intake (`crates/nyx-tee/src/api/orders.rs`):

1. Verifies the trading-key Ed25519 signature over the canonical digest.
2. Re-derives the note commitment from the opening (`commitment_from_fields_v2`)
   and asserts it equals the signed `note_commitment` — pinning the opening
   to the signature + enforcing `note_amount == committed amount`.
3. Validates exactly 10 Fr-safe anchor `inner_hash`es; stashes the pool keyed
   by `order_id`.
4. Derives the fee-inclusive collateral (`nominal + own fee`) + books the order.

The trading key is rotatable via offset (§4) so a user can burn a per-session
key and break long-term linkage. **Why it's private:** order intent lives only
in enclave memory; L1 observers see deposits + settled outputs, never the
resting book. The anonymity set is every order in the book that didn't settle.

**Tests:** `tests/order-canonical-parity.test.ts` (the v2 canonical, byte-equal
to Rust) + `crates/nyx-tee/tests/orders_surface.rs` (intake: sig / opening /
anchor validation, the top-up endpoint).

### Step 5 — Matching (in the CVM)

The matcher interval driver (`crates/nyx-tee/src/matcher/interval.rs`) ticks
on a cadence (`BATCH_MS`). Each tick, over the in-memory book:

1. Sweeps expired orders; snapshots the book (skipping anchor-pool-paused
   orders).
2. Runs `darkpool_matcher::run_batch_capped`: sort bids desc / asks asc, find
   the uniform clearing price maximising matched volume, FIFO tie-break.
3. **Circuit breaker**: skip the batch if the clearing price deviates from the
   Pyth TWAP beyond the band.
4. **Partial-fill continuation**: for a relocking side, consume the order's
   next anchor, build the change note (note_e/f) with that anchor's
   `inner_hash`, rotate the residual's collateral to it, insert the rotated
   opening, and keep the order live (pause it if the pool drained). The matcher
   emits a `FillMemo` per consumed anchor.
5. **Pages** the cleared matches into ≤ N=16 settle batches
   (`MAX_PAGES_PER_TICK` guard) and enqueues each to the settle scheduler.

This is integer arithmetic + Poseidon over the change-note commitments — all
in enclave memory. The cryptography lands at settle time (Step 7+) when these
matches hit L1. **Tests:** `cargo test -p darkpool-matcher` (the algorithm +
parity) + `crates/nyx-tee/tests/{matcher_tick,order_to_match}.rs`.

### Step 6 — Settle handoff (the CVM drives the on-chain settle)

The settle scheduler dequeues each ≤16-match batch and `assemble_batch`
(`crates/nyx-tee/src/settle/assemble.rs`) builds the per-slot witnesses + the
`MatchResultPayload`s, then drives Steps 7–9.5 below **sequentially** (so a
change note relocked by one batch is on-chain before a later batch consumes
it). The enclave's dstack-derived Ed25519 key signs each settle payload and
pays the fees. Everything from here is on L1.

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

Before settle the TEE lands ONE verify ix per batch that writes the
`BatchValidityMarker` the settle handler later consumes. One Groth16
(VALID_MATCH_BATCH) proves output-note construction + the price band +
per-leg conservation for every match in the batch; it writes one marker:

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
1. Assert `expiry_slot ∈ (clock.slot, clock.slot + 300]` (≈ 2 min TTL).
2. Pack the single public input `[merkle_root]` and verify the Groth16
   against `vk_match_batch_n16` (~200 k CU — the verifier cost scales with
   public-input count, not constraint count).
3. Init `BatchValidityMarker { payer, expiry_slot, bump }`.

One marker covers all N matches sharing the same `merkle_root`. The matcher
pads short batches to N=16 with dummy slots before proving, so the on-chain
depth-4 inclusion walker has a consistent shape.

### Step 9 — settlement (L1)

The atomic per-match settlement, sent after the batch's verify ix lands.
This is the heart of the protocol.

The tx contains **three ixs**:

```ts
[
  ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
  buildEd25519VerifyIx({ teePubkey, signature, message }),   // PRECOMPILE
  buildSettleBatchedIx({ programId, teeAuthority, payload, matchIndex, merkleProof, merkleRoot }),
]
```

It's sent as a **VersionedTransaction with stacked Address Lookup Tables**
(one static settle ALT created at devnet-setup + one per-batch ALT holding
the 5 derivable PDAs — see below).

The settle ix is:

```rust
vault::tee_forced_settle_batched(
    payload:      MatchResultPayload,
    match_index:  u8,                 // 0..15, which slot in the batch
    merkle_proof: [[u8; 32]; 4],      // depth-4 inclusion path
)
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
| 11 | `batch_validity_marker` | the 1:N marker from step 8 — checked, NOT closed here |
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

4. **Validity marker check**:
   - Recompute the per-slot Merkle leaf via the same Poseidon12 +
     Poseidon9 stages the circuit uses (see §7.4):
     ```
     h_inner = Poseidon12(20, 6 note commits, 4 mint halves, base_amount)
     leaf    = Poseidon9 (21, h_inner, quote_amount, buyer_change,
                              seller_change, buyer_fee, seller_fee,
                              clearing_price, batch_slot)
     ```
   - Walk a depth-4 Merkle path with the caller-supplied 4 siblings +
     `match_index` (bits of `match_index` select left/right at each
     level, inner nodes = `Poseidon3(DOMAIN_BATCH_ROOT = 22, left, right)`).
   - Derive the expected marker PDA at `[b"batch_validity", computed_root]`,
     assert the supplied `batch_validity_marker.key()` matches, and assert
     it's owned-by-us + non-expired.
   - **Do NOT close it.** The marker covers all N matches in the batch and
     must remain present for matches `match_index + 1 .. N-1`. Reclaiming
     its rent is the job of `close_batch_validity_marker` once the batch is
     fully settled (Step 9.5).

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

11. **Marker lifecycle** — do NOT touch the `BatchValidityMarker` here.
    It's 1:N (one PDA keyed by the batch's Merkle root, covering up to 16
    matches). Closing it would brick every subsequent match in the batch.
    Rent reclamation is the job of `close_batch_validity_marker` (Step 9.5).

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
- Tx A (lock): 2 lock_notes with embedded VALID_INPUT proofs, ~1100 B.
- Tx B (verify): 1 verify_match_batch with the embedded VALID_MATCH_BATCH
  proof, ~640 B.
- Tx D (settle, V0 + stacked ALTs): Ed25519 precompile + tee_forced_settle_batched
  + the depth-4 inclusion proof, ~1130 B.

See §9 for why the v0/ALT stacking was specifically required.

**Tests**:
- `tests/cvm-settle-e2e.test.ts` — the live-CVM real settle (deposit → match → settle)
- `tests/devnet-deposit-withdraw.test.ts` — the no-CVM deposit + VALID_SPEND withdraw
- `programs/vault/tests/tee_forced_settle_batched.rs` — the 1:N marker lifecycle
- `tests/settle-builder-batched.test.ts` — the settle ix wire format (payload Borsh,
  canonical hash byte-equality with the Rust fixed vector, Ed25519 layout, account order).
- `tests/settle-builder-batched.test.ts` — settle ix wire-format
  unit tests for `buildSettleBatchedIx` + `buildCloseBatchValidityMarkerIx`:
  13-account ordering, 585-byte ix data (disc + payload + match_index +
  4×32 siblings), Anchor `[[u8; 32]; 4]` encoding, `BatchValidityMarker`
  PDA derivation, `match_index` boundary validation [0, 15].
- `programs/vault/tests/tee_forced_settle_batched.rs` (litesvm)
  regression test that seats two real matches at slots 0 and 1
  settling against the same marker; catches the "close
  after every match" regression.

### Step 9.5 — `close_batch_validity_marker` (L1)

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
batch. If `tee_forced_settle_batched` closed it after each match,
match 0 would succeed but match 1 would find the marker drained +
zeroed and fail with `BatchValidityMarkerExpired`. Closing the 1:N
marker per-match was a real bug caught by an external PR-reviewer and
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
POST /orders (TLS to the CVM, NOT visible on L1)
    │  trading_key signs the order canonical (binds the anchor pool)
    │  intake verifies sig + note opening; books in enclave memory
    ▼
MATCH (in the CVM)
    │  Uniform clearing price; circuit breaker against Pyth TWAP
    │  Partial fill → consume an anchor, rotate the residual, continue
    │  Page cleared matches into ≤ N=16 settle batches
    ▼
LOCK_NOTE × 2 per match (L1, two VALID_INPUT proofs)
    │  NoteLock PDAs at [b"note_lock", commitment]
    │  Each lock bound to (order_id, mint, amount) cryptographically
    ▼
VERIFY_MATCH_BATCH (L1, 1 Groth16 per batch)
    │  BatchValidityMarker PDA at [b"batch_validity", merkle_root]
    │  Covers up to N=16 matches.
    ▼ (one per real match)
TEE_FORCED_SETTLE_BATCHED (L1, v0 + stacked ALTs)
    │  Ed25519 + canonical hash
    │  Leaf hash + depth-4 Merkle inclusion path to the marker
    │  Conservation + structural checks; Consumed/Nullifier PDAs
    │  Up to 6 output leaves (note_c/d + change + base/quote fee)
    │  Atomic re-lock of the change note (if the order continues)
    │  Marker NOT closed (it's 1:N)
    ▼ (once per batch)
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
keep settlement under the 1232-byte transaction cap. A cryptographer can
skip it, but the constraints explain why the protocol has its shape.

The batched flow amortises across N matches: ONE verify + ONE close per
batch (≤16 matches), not per match.

### Why multiple transactions?

A single tx that does {lock note_a, lock note_b, verify, ed25519
precompile, settle} is well over the cap. Napkin math:

| Piece | Bytes |
|---|---|
| Tx headers + signature(s) + blockhash | ~80 |
| `ComputeBudgetProgram.setComputeUnitLimit` ix | ~20 |
| `lock_note` ix data (8 disc + 32 commit + 16 order_id + 8 expiry + 8 amount + 32 mint + 32 root + 256 proof) | 392 |
| `lock_note` accounts (4 × 32) | 128 |
| `verify_match_batch` ix data (8 disc + 32 root + 8 expiry + 256 proof) | ~304 |
| Ed25519 precompile ix (header + pubkey + sig + 32-byte msg) | ~150 |
| `tee_forced_settle_batched` ix data (8 disc + 448 payload + 1 match_index + 4×32 siblings) | ~585 |
| Account keys for everything together (~13 distinct) | 416 |
| **TOTAL** | **~2000+** |

So the settle is split into a pipeline, per batch (≤ N=16 matches):

| Tx | Contents | Approx size | Cardinality |
|---|---|---|---|
| **Tx A — lock** | compute_budget + lock_note(a) + lock_note(b) | ~1050 B | N per batch (one per match) |
| **Tx B — verify_match_batch** | compute_budget + verify_match_batch (1 Groth16, 1 marker init) | ~640 B | 1 per batch |
| **Tx C — per-batch ALT** | createLookupTable + extendLookupTable(5 PDAs) | ~250 B | 1 per batch |
| **Tx D — settle_batched** | compute_budget + ed25519_precompile + tee_forced_settle_batched (v0 + stacked ALTs) | ~1130 B | N per batch |
| **Tx E — close** | compute_budget + close_batch_validity_marker | ~250 B | 1 per batch |

All fit under 1232 B. Atomic dependency is enforced by account-existence
requirements:

- `lock_note` before settle: settle's accounts list requires
  `note_lock_a` / `note_lock_b` to exist as initialized PDAs.
- `verify_match_batch` before settle: settle requires the
  `BatchValidityMarker` PDA to exist at `[b"batch_validity", merkle_root]`.
- Per-batch ALT before settle: the settle tx references accounts via the
  ALT; an ALT created in the same slot is unusable, so the worker waits
  one slot after extend before sending the settle.

The multi-tx flow is **not atomic across txs** — a TEE that lands locks
but never settles leaves rent-locked PDAs until expiry. But the PDAs have
TTLs (locks ~24h, markers ~2 min), so abandoned state self-cleans.

### The marker PDA construction (binding by seed)

The `BatchValidityMarker`'s *seed* is the batch Merkle root, not its data.
`verify_match_batch` verifies the Groth16 over the single public input
`[merkle_root]` and inits the marker at `[b"batch_validity", merkle_root]`.
At settle, `tee_forced_settle_batched` recomputes the per-slot leaf from
the payload + lock mints, walks the depth-4 inclusion path to a root, and
requires the marker to exist at `[b"batch_validity", that_root]` — so a
match can only settle against a marker whose verified proof actually
covered it.

**Why this is sound**: the only way for a marker at `[b"batch_validity", R]`
to exist is if `verify_match_batch` accepted a `VALID_MATCH_BATCH` proof
whose public root is `R`. The settle handler re-derives `R` from its own
view of the match (payload + lock mints, themselves pinned via
VALID_INPUT) + the supplied siblings. A mismatch → the expected marker
address differs → the account isn't there → settle aborts. PDAs are
deterministic (`find_program_address` is injective on seeds for a fixed
program id), so an attacker can't fake "marker A corresponds to root B."

### Why VersionedTransaction + ALT

The change + re-lock settle path exercises a partial fill with an atomic re-lock — its settle tx was 1243 bytes — exactly 11 over the cap.
The other settle paths (A, E) were 1232 or under.

Why the 11-byte difference? **Legacy tx serialization de-duplicates
account keys**. In the exact-fill paths, both `note_e_commitment` and
`note_f_commitment` are `[0;32]`. The `note_lock_e` PDA is derived from
`note_e_commitment`, and `note_lock_f` from `note_f_commitment` — so they
end up at the **same PDA address** (`find_program_address(&[b"note_lock", [0;32]], program_id)`).
The legacy tx encoder sees two account-key entries that hash identically
and merges them into one slot in the keys list, saving 32 bytes.

The moment `note_e ≠ 0` (any change-note path), the two PDAs become
distinct addresses and no dedup happens — the settle tx is 32 bytes
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
| `batch_validity_marker` | per-batch (derivable from the payload) | ✅ per-batch ALT |
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

#### Per-batch ALTs on top of the static one

The settle adds a 1-byte `match_index` + 4 × 32-byte Merkle
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
the settle pipeline has the full
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
| change + relock (the largest variant) | **1243 ❌** | ~1162 ✅ |

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
- TS: `[hash_cross_env_parity]` in `settle-builder-batched.test.ts` asserts the same
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
| 4 | `BatchValidityMarker` | `[b"batch_validity", merkle_root]` | Second `verify_match_batch` for the same batch (via init collision) |

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
| `crates/darkpool-crypto/src/{poseidon,note,nullifier,user_commitment,field,keys}.rs` | Poseidon round-trips, v2 note commitment + nullifier determinism/sensitivity, user commitment, `fr_from_be_bytes` strictness, the key-derivation chain |
| `crates/darkpool-matcher/` | the matching algorithm (`run_batch`/`run_batch_capped`), `order_canonical` (order/cancel/anchor-topup signing), `change_note::derive_inner` KAT |

### Rust integration tests (litesvm — `programs/vault/tests/`)

| File | What it covers |
|---|---|
| `zk_roundtrip.rs` | VALID_WALLET_CREATE end-to-end (off-chain prove → on-chain verify) |
| `zk_spend_roundtrip.rs` | VALID_SPEND (v2 inner_hash) end-to-end + Poseidon parity vs circomlib |
| `user_commitment_registration.rs` | `create_wallet` flow with proof verification |
| `set_protocol_config.rs` / `set_tee_pubkey.rs` | admin-gated config + TEE-signer rotation |
| `merkle_host.rs` | pure-Rust Merkle invariants (poseidon2, zero-subtree, append) |
| `tee_forced_settle_batched.rs` | 1:N `BatchValidityMarker` lifecycle (two matches share one marker; the close-after-every-match regression) |
| `match_batch_verify.rs` | real N=16 proof → on-chain `verify_match_batch` acceptance (committed fixture) |

(The last two + the `settle_harness/` were migrated from the deleted
`matching_engine` crate.)

### `nyx-tee` tests (`cargo test -p nyx-tee`)

~180 lib + integration tests: the matcher tick + partial-fill continuation,
the settle pipeline + ALT pool, the Merkle mirror, the anchor pool, the
HTTP/auth surface (`orders_surface.rs`: intake sig/opening/anchor validation +
the top-up endpoint), the RPC client, and `n16_assemble_prove_verify.rs` (the
in-enclave N=16 prove → fixture dump).

### SDK parity tests (TypeScript ↔ Rust byte equality)

| File | Pins |
|---|---|
| `poseidon-parity.test.ts` | Poseidon arities 2/3/5/6 + the user-commitment shape |
| `keys-parity.test.ts` | spending / viewing / trading-offset / root / blinding derivation |
| `user-commitment-parity.test.ts` | fixed input + varied blinding |
| `note-commitment-parity.test.ts` | v2 `noteCommitmentV2` (canonical inputs, amount edges, field strictness) |
| `nullifier-parity.test.ts` | v2 `nullifierV2` (sk/inner_hash sensitivity) |
| `inner-hash-parity.test.ts` + `change-note-inner-parity.test.ts` | the `inner_hash` / `derive_inner` derivation (KAT) |
| `order-canonical-parity.test.ts` | the order/cancel/anchor-topup canonical digests + wrong-width guards |

### SDK ZK prover tests

| File | Pins |
|---|---|
| `helpers/snarkjs-prover.test.ts` | VALID_WALLET_CREATE roundtrip via snarkjs-cli |
| `valid-input-prover.test.ts` | VALID_INPUT (exact + misroute-rejection + public-input ordering) |
| `match-batch-prototype.test.ts` | VALID_MATCH_BATCH at N=2/4/16 (mixed-shape) + leaf-byte parity with on-chain `compute_match_leaf` |

### SDK unit tests (offline / RPC-free)

| File | Pins |
|---|---|
| `settle-builder-batched.test.ts` | `buildSettleBatchedIx` account layout + ix.data + Merkle-siblings + `BatchValidityMarker` PDA + `match_index` bounds + `buildCloseBatchValidityMarkerIx` |
| `anchor-pool-build.test.ts` | deterministic anchor-pool derivation + pool-hash parity + top-up digest signing |
| `settle-memo-integrity.test.ts` | the fill-memo integrity check (incl. the Vuln-4 inner_hash-substitution catch) |
| `settlement-watcher.test.ts` | vault `TradeSettled` event decoding |
| `deposit-transport.test.ts` / `withdraw-transport.test.ts` | deposit + VALID_SPEND withdraw ix builders (v2) |
| `helpers/merkle-shadow.test.ts` | shadow tree empty-root parity + witness shape |

### SDK end-to-end tests (env-gated, real devnet / CVM)

| File | Gate | What it does |
|---|---|---|
| `devnet-setup.test.ts` | `RUN_DEVNET_E2E=1` | mints + settle ALT + `reset_merkle_tree` + protocol config; writes `.devnet/e2e-config.json` |
| `devnet-deposit-withdraw.test.ts` | `RUN_DEVNET_DW=1` | isolated v2 deposit → VALID_SPEND withdraw round-trip on devnet (no CVM) |
| `cvm-settle-e2e.test.ts` | `RUN_CVM_E2E=1` | the flagship: deposit 2 notes → POST a crossing bid+ask to a live CVM → the CVM matches **and** settles → assert leaf_count grows |

Plus the **loadgen** (`crates/nyx-tee-loadgen`, a host binary) for intake
throughput + matcher paging (`scripts/dev-commands.md §7`).

### Summary

Every cryptographic primitive has a parity test pinning its byte-level
behaviour across Rust + TS; every on-chain check has an integration test
(happy + failure path); every circuit has a prover test with a *negative*
case (the constraint set is tight). The default-CI gate is the
"everything green" set in `CLAUDE.md §2.5`; the env-gated tests prove the
live devnet/CVM deployment.

---

## 13. What is NOT yet implemented

Sorted roughly by cryptographic impact:

1. **Real Phase-2 ceremony** — all four shipped Groth16 circuits use a
   deterministic dev contribution
   (`echo "nyx-phase1-dev-contribution-$name" | snarkjs zkey contribute`),
   plus the batched zkey runs `zkey beacon 0102…1f20 10`. The toxic waste
   is *recoverable from the build script* — fine for devnet, a hard
   mainnet blocker. Need a real MPC with ≥ 3 independent contributors and
   publicly verifiable transcripts. The PTAU files are SHA-256-pinned in
   `scripts/download-ptau.sh` (closes the supply-chain hole at download
   time, but not the need for a project-specific phase-2 MPC).

2. **Attested TEE-pubkey rotation** — `set_tee_pubkey` rotates
   `VaultConfig.tee_pubkey` to the CVM's dstack-derived key, and clients
   verify the enclave's TDX quote client-side before sending orders. The
   remaining gap is binding the *on-chain* rotation to a verified quote +
   a governance-approved measurement set (a multisig accepting the quote),
   so the chain itself enforces "only an attested enclave can be the
   signer." See `docs/tee-attestation-flow.md`.

3. **Fills delivery + trade history** — `/ws/fills` is currently a
   fail-closed unfiltered broadcast (gated behind `debug_endpoints`). The
   decided design — deterministic HD order_ids + per-account WS + an
   off-TEE indexer — is in
   [`docs/fills-history-architecture.md`](docs/fills-history-architecture.md),
   not yet built.

4. **Real protocol-owner keypair** — fee notes mint to the protocol's
   `owner_commitment`; withdrawing them needs a real owner keypair wired up
   (the operator re-derives the fee notes via `derive_inner(slot, FEE_ROLE_*)`).

5. **Browser prover** — the SDK shells out to `node_modules/.bin/snarkjs`
   via `execFileSync`. Fine on a server, unwieldy in a browser extension;
   the fix is an in-process `WebProverSuite` (wasm-bindgen or similar).

6. **Self-trade prevention** — a user with two trading keys could match
   against themselves; cheap to add to the in-TEE matcher (check same
   `user_commitment`), more anti-leakage than soundness.

---

## Appendix A — File map

```
nyx-monorepo/
├── circuits/
│   ├── valid_wallet_create/circuit.circom    1 public input
│   ├── valid_spend/circuit.circom            5 public inputs (v2 inner_hash)
│   ├── valid_input/circuit.circom            5 public inputs (v2 inner_hash)
│   └── match_batch_n16/  (+ n2, n4 dev)      VALID_MATCH_BATCH, 1 public input
│
├── crates/
│   ├── darkpool-crypto/                       single source of truth (host crypto)
│   │   ├── src/poseidon.rs                    light-poseidon BN254 wrapper
│   │   ├── src/note.rs                        commitment_from_fields_v2 (Poseidon6)
│   │   ├── src/nullifier.rs                   Poseidon3(DOMAIN_NULL, sk, inner_hash)
│   │   ├── src/keys.rs                        HKDF-SHA256 + KMAC256 + deriveBlindingFactor
│   │   ├── src/user_commitment.rs  src/field.rs  examples/*
│   ├── darkpool-matcher/                       run_batch(_capped) + order_canonical + change_note
│   ├── nyx-tee/                                the in-CVM engine (api/matcher/settle/prover/merkle/…)
│   └── nyx-tee-loadgen/                        host load-tester
│
├── programs/vault/                            the ONLY on-chain program
│   ├── src/state.rs                           VaultConfig, WalletEntry, NullifierEntry,
│   │                                           ConsumedNoteEntry, NoteLock, OutstandingMint,
│   │                                           BatchValidityMarker
│   ├── src/merkle.rs                          incremental tree, depth 20
│   ├── src/zk/{verifier,vk_valid_wallet_create,vk_valid_spend,vk_valid_input,vk_match_batch_n16}.rs
│   ├── src/instructions/                       initialize, create_wallet, deposit, lock_note,
│   │                                           release_lock, verify_match_batch,
│   │                                           tee_forced_settle(_batched), close_batch_validity_marker,
│   │                                           withdraw, set_protocol_config, set_tee_pubkey,
│   │                                           rotate_root_key, reset_merkle_tree
│   └── tests/                                  settle_harness/ + the litesvm suite (§12)
│
├── packages/sdk/
│   ├── src/idl/{vault-client,seeds}.ts        hand-rolled ix builders + PDA seeds
│   ├── src/keys/*.ts  src/utxo/{note,deposit,withdraw,note-store}.ts
│   ├── src/orders/{canonical,anchor-pool,fill-memo}.ts
│   ├── src/settlement/{settle-builder,settlement-watcher}.ts
│   └── tests/                                  the suite enumerated in §12
│
├── deploy/docker-compose.yaml                  the CVM image + env reference
├── dstack/                                     dstack SDK + simulator
└── scripts/                                    build-circuits, parse-vk-to-rust, deploy-devnet,
                                                reset-merkle-tree, rotate-tee-pubkey, download-ptau
```

---

## Appendix B — How to reproduce the validation

The authoritative runbook is [`CLAUDE.md §2–§3`](CLAUDE.md) +
[`scripts/dev-commands.md`](scripts/dev-commands.md). In brief:

```bash
# host setup
npm install && bash scripts/download-ptau.sh && bash scripts/build-circuits.sh
cargo build --examples -p darkpool-crypto

# the "everything green" gate (no devnet, no CVM)
cargo build-sbf --manifest-path programs/vault/Cargo.toml
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
cargo test --workspace
( cd packages/sdk && ../../node_modules/.bin/tsc -p tsconfig.json --noEmit && ../../node_modules/.bin/vitest run )

# devnet: deploy the vault + set up state (mints/ALT/reset/config)
bash scripts/deploy-devnet.sh
RUN_DEVNET_E2E=1 ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  ROOT_KEY_KEYPAIR=.devnet/keypairs/root_key.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-setup.test.ts )

# no-CVM on-chain check
RUN_DEVNET_DW=1 ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-deposit-withdraw.test.ts )

# the flagship: a live CVM matches AND settles (needs a deployed CVM — CLAUDE.md §3; STOP it after)
RUN_CVM_E2E=1 NYX_TEE_GATEWAY="$GW" SOLANA_RPC_URL="$HELIUS" \
  FUNDER_KEYPAIR=~/.config/solana/id.json ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/cvm-settle-e2e.test.ts )
```

CI: `pr-checks.yml` runs the everything-green gate (Rust workspace + clippy +
the 4 circuits + the SDK suite + the vault litesvm tests incl. the migrated
settle regression). `nightly-devnet.yml` fires on cron + the `/test-devnet` PR
comment for the full devnet E2E.

---

*Last updated: 2026-06-04 — current TEE architecture: `vault` (the only
on-chain program) + the in-CVM matcher/settler (`crates/nyx-tee`), validated
end-to-end on devnet through a Phala CVM. v2 `inner_hash` note model + the
per-order continuation anchor pool. The `matching_engine` / MagicBlock-ER /
PER path and the standalone `VALID_CREATE` / `VALID_PRICE` circuits have been
removed.*
