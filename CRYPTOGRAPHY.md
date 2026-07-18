# Darknyx Darkpool — Cryptographic Design Walkthrough

> A protocol-engineer's tour through the cryptography of Darknyx in its
> current TEE architecture (vault + the in-CVM matcher/settler; v2
> `inner_hash` notes + consumed-input-derived outputs). Written for readers
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
7. [The six ZK circuits](#7-the-zk-circuits)
8. [Lifecycle walkthrough — wallet to withdraw](#8-lifecycle-walkthrough)
9. [Settlement mechanics — what fits in a Solana tx and why](#9-settlement-mechanics)
10. [Solvency invariant](#10-solvency-invariant)
11. [Replay protection layered across PDAs](#11-replay-protection)
12. [Test coverage map](#12-test-coverage-map)
13. [What is deliberately NOT yet implemented](#13-what-is-not-yet-implemented)

---

## 1. Executive summary

Darknyx is a privacy-preserving CLOB-like darkpool on Solana. The custody side is
shielded (UTXO notes, Groth16 proofs); the matching side runs in a TEE
(currently a software Ed25519 key, eventually an attested enclave) that signs
match payloads back to L1 for atomic settlement.

The protocol is layered as **L1 (Solana `vault`)** + **TEE (an in-CVM
matcher/settler)** + **client (TypeScript SDK + snarkjs prover)**:

| Layer | Responsibility | Trust |
|---|---|---|
| **L1** (`programs/vault`) | Custody, Merkle tree, ZK verifiers, atomic settlement | Trustless |
| **TEE** (CVM, `crates/darknyx-tee`) | Hidden order intake, uniform-clearing-price match, signs the settle | Trusted for fairness + liveness, **NOT** for custody; attested via TDX quote |
| **Client** | Key derivation, proof generation, order signing, ix builders | Local user trust |

The on-chain trust surface is tightened so the TEE can deny liveness but
**never steal custody**:

- **Lock-time proof.** `lock_note` is gated by a `VALID_INPUT` Groth16
  (the TEE proves it locked a real, owned leaf with the right mint, without
  revealing a nullifier). `NoteLock.token_mint` is cryptographically bound;
  `MAX_LOCK_TTL_SLOTS` bounds censorship; `outstanding[mint]` is the per-mint
  solvency counter. Closes phantom-locking, forever-locking, mint lies.
- **Settle-time proof.** `verify_match_batch` checks ONE `VALID_MATCH_BATCH`
  Groth16 covering up to N=16 matches — proving output-note construction
  (right mint/amount/owner and deterministic inners derived from consumed
  inputs), per-leg conservation, scaled floor pricing, no value inflation,
  and per-match fees. Every active slot is bound to one enabled
  `MarketConfig`; the commitments are hashed into one batch Merkle root. It
  writes ONE `BatchValidityMarker` (keyed by that root);
  each `tee_forced_settle_batched` walks a depth-4 inclusion path against it;
  `close_batch_validity_marker` reclaims the marker's rent after the batch.
  Closes "TEE misroutes a leg / mis-mints / inflates value." It does **not**
  prove execution-price fairness — the clearing price is bound only to
  `quote = floor(base·price/price_scale)` (definitional), with no limit or
  oracle band, so price
  fairness stays **TEE-trusted** (see the §2 non-goals row). (Earlier designs
  split this into separate per-match `VALID_CREATE` + `VALID_PRICE` circuits;
  those were folded into the batched proof and removed.)
- **Signer pinning.** Every TEE-authority ix checks the signer against
  `VaultConfig.tee_pubkeys` (the set of K authorized shard fee-payer keys),
  each rotated to a CVM dstack-derived key; clients verify the enclave's TDX
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
| L1 anyone | Replay of TEE-signed settlement | `ConsumedNoteEntry` + `BatchValidityMarker` PDAs (init-time PDA collision) |
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
| TEE clears at a bad price | **TEE-trusted (accepted design decision)** — price fairness (limit compliance + the oracle band) is enforced inside the attested enclave by the `darkpool-matcher`, NOT by the proof. `VALID_MATCH_BATCH` binds `quote = floor(base·price/price_scale)` with a constrained remainder, conservation, ranges, market identity, and exact fees, but not the signed limits or oracle band. This is a *deliberate* trade-off, not an oversight — see **"Accepted design decision — price fairness is TEE-trusted"** below for the full rationale + compensating controls. |
| TEE clears off-tick / under min size / outside the circuit-breaker band (U-01) | **TEE-trusted** — `MarketConfig.tick_size`, `min_order_size`, and `circuit_breaker_bps` are governance-set rules the in-TEE matcher honours, but they are **not** `VALID_MATCH_BATCH` public inputs or leaf-bound. Only market identity + `price_scale` + conservation + the exact fee are proof-enforced. Same trust class as price fairness above; do not describe tick/min/breaker as on-chain-enforced. |
| TEE writes garbage on-chain fill-recovery ciphertext (U-04) | **TEE-trusted** — `MatchResultPayload.fill_recovery` is opaque and signed but never validated on-chain; the AEAD protects confidentiality, not correctness. A compromised TEE could sign a conserved settle whose recovery blob is unusable, stranding a client that relies solely on chain recovery. Redundancy: the live `/v1/stream` fills channel + history backfill (chain recovery is last-resort). |
| TEE-binary substitution | **Open** — `tee_pubkeys` are software Ed25519 keys. Production must pin them to an attested enclave. |
| Trusted-setup ceremony soundness | **Open** — all six Groth16 circuits use a deterministic dev contribution. Real Phase-2 MPC required for mainnet. |
| Aggregate trade analytics from settle txs | **By design** — match volume + clearing price are public per settled batch. |
| Network-level traffic analysis | Partially mitigated by TLS to the CVM + bearer auth; not fully eliminated. |

### Accepted design decision — price fairness is TEE-trusted

**Decision (2026-07-08).** Execution-price fairness — that a match respects each
trader's signed limit, and that the clearing price sits within the Pyth-TWAP band —
is enforced **inside the attested enclave** (the `darkpool-matcher`), **not** by
`VALID_MATCH_BATCH`. We evaluated binding it on-chain and deliberately chose not to.
This is an **accepted trust assumption**, recorded here so it is not mistaken for an
oversight. The proof still bounds a compromised TEE to **no value inflation +
liveness** (conservation + 64-bit range checks are proof-enforced); what it does not
bind is the *price* at which two consenting notes clear.

**Why the on-chain alternatives were rejected:**

- **Bind the traders' signed limits in-circuit.** The `clearing_price ≤ limit`
  comparison is trivial; the hard part is proving the limit is the one the trader
  actually *signed*. Verifying the Ed25519 order signature in-circuit is infeasible
  (~1.5M+ constraints per signature × 2 legs × 16 matches → tens of millions of
  constraints; the N=16 proof would blow up from ~6.7 s to minutes–hours). The only
  alternative is committing a client-signed limit **on L1**, which erodes the
  protocol's core property that **orders never touch L1** (privacy + no per-order
  gas). That is a deposit/lock **redesign**, not a circuit tweak.
- **Bind the oracle band on-chain.** Matching happens at T0 (the matcher's TWAP);
  `verify_match_batch` runs at T1 = T0 + lock + ~6.7 s prove + tx latency, when the
  Pyth price has already moved. A TEE-supplied T0 price is circular (TEE-trusted). A
  *real* on-chain price requires posting the Pyth pull-oracle update on-chain —
  net-new Pyth infra + extra verify CU + 1–2 more accounts on a settle Tx D already
  ~100 B from the 1232-byte cap — and the T0→T1 drift forces either a loose band
  (weak guarantee) or settle **failures** when the market moves (a liveness
  regression). And it still would not give per-trader limit compliance.

**Compensating controls that make TEE-trust acceptable:**

1. **Enclave attestation.** The matcher runs in an attested Intel TDX CVM whose
   `compose_hash`/MRTD is pinned to a governance allowlist — so "compromised TEE"
   means breaking TDX or subverting governance, not merely running modified code
   (see the *TEE-binary substitution* row + `docs/tee-attestation-flow.md`).
2. **Client-side detection.** Every fill carries a memo; the client recomputes its
   own fill and can reject/dispute a price outside its limit (the Vuln-4 memo
   guard) — detection + economic/legal/reputation deterrence even without on-chain
   prevention.
3. **Bounded loss.** A bad clear extracts at most the victim's order size; it can
   never inflate value or drain the vault (that IS proof-enforced).

**When we would revisit.** If institutional counterparties require *prevention* (not
detection) of limit violations, the path is a deliberate deposit/lock redesign that
commits a client-signed limit on-chain (accepting the privacy/UX cost), scoped with
the external circuit auditors — not a VK bump. Until then the honest posture is:
**price fairness is TEE-trusted, and that trust is anchored by enclave attestation.**

### Invariants the on-chain code maintains

Every state-transitioning instruction maintains:

1. **Conservation per-leg**: each private input amount equals the corresponding
   trade output + change + fee. `VALID_MATCH_BATCH` enforces this against the
   commitment-bound private openings; `NoteLock` does not store or reveal the
   amount.
2. **Conservation per-mint**:
   `outstanding[mint] ≤ vault_token_account.amount` for every mint, after
   every deposit / withdraw.
3. **Mint binding**: `lock.token_mint` is cryptographically pinned to the
   Merkle leaf via `VALID_INPUT`; recorded in the lock PDA; propagated into
   change-note relocks; bound into the `VALID_MATCH_BATCH` slot leaf.
4. **Single-spend per note**: a note's `commitment` can be consumed by
   `tee_forced_settle_batched` OR spent by `withdraw`, but not both, in either
   order. BOTH paths `init` the SAME commitment-keyed `ConsumedNoteEntry`
   (`[b"consumed_note", commitment]`), so whichever runs first blocks the other
   via an init-time PDA collision. Keying the guard on the commitment (public +
   circuit-bound) rather than the nullifier (TEE-supplied + unconstrained at
   settle) is what makes this symmetric — settle also records a `NullifierEntry`
   no longer, so it can't be relied on cross-path. `withdraw` additionally
   refuses while a `NoteLock` is present.
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
| **DarknyxShakeKdfV1** | Viewing key + per-note blinding factor | Versioned Darknyx-specific SHAKE256 construction retained byte-for-byte for existing keys and notes. It uses SP 800-185-style encodings but is not NIST KMAC or cSHAKE; fixed Rust/TS KATs pin its bytes. |
| **Ed25519** | TEE signature on match payload, trading-key signatures | Solana-native (built-in precompile for verification). |
| **Groth16** (BN254, snarkjs / `groth16-solana`) | All six ZK circuits | Constant-size proofs (256 bytes on-chain), constant-time verification, well-supported tooling. The proof system that fits Solana's CU budget. |

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

- Keys derived from the 64-byte master seed go through HKDF or DarknyxShakeKdfV1
  outputting **512 bits**, then `mod p` reduction. For BN254 r ≈ 2^254, this
  gives a statistical bias of < 2^-256 — indistinguishable from uniform in
  practice. The 64-byte master seed is sampled directly from a CSPRNG and kept
  in secure client storage, with only authenticated encrypted backups exported.
- Blinding factors per note use the same 512-bit derivation (DarknyxShakeKdfV1 with a
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
master_seed (64 bytes, CSPRNG; securely stored and backed up encrypted)
  │
  ├── HKDF-SHA256("darkpool_root_key_v1", 32B)              → root_key (Ed25519 seed)
  ├── HKDF-SHA256("darkpool_trading_key_v1" ‖ offset_u64_le, 32B) → trading_key(offset) (Ed25519 seed)
  ├── HKDF-SHA256("darkpool_spend_key_v1", 512b) → mod p     → spending_key (Fr)
  ├── DarknyxShakeKdfV1("darkpool_viewing_key_v1", 512b) → mod p → viewing_key   (Fr)
  └── deriveBlindingFactor(0xacc0_0000_0000)          → mod p → r_owner       (Fr)

Per-deposit recovery nonce (v2; independent from the above; keyed by deposit index):
  DarknyxShakeKdfV1("note_blinding_v1" ‖ deposit_index_u64_le, 512b) → mod p → recovery_nonce (Fr)
  Poseidon3(DOMAIN_DEPOSIT_INNER=27, owner_commitment, recovery_nonce) → inner_hash (Fr)
  (change / trade / fee / continuation notes derive inner_hash differently — see §5.)
```

The 512-bit→mod-p path is statistically uniform per the sampling note in §3.

### Two commitments

The key chain produces **two important commitments** that appear on-chain or
in proofs:

#### `owner_commitment`

```
owner_commitment = Poseidon3(DOMAIN_OWNER=1, spending_key, r_owner)
```

Where `r_owner` (alternately `ownerCommitmentBlinding`) is a wallet-level
blinding factor. **Reused across every note the user creates.** Canonical SDK
wallets derive it from the master seed at the reserved
`0xacc0_0000_0000` counter, separated from ordinary deposit indices. A caller
may override it only if that separate identity secret is backed up alongside
the seed; seed-only recovery uses the canonical derivation.

This is the field-element value the chain knows you by. It's part of every
note's preimage (so the chain can't link your notes to your Solana pubkey,
only to this owner_commitment). In the spend / order / merge proofs it's a
**private witness — never revealed there**.

`owner_commitment` is never a deposit instruction argument. `VALID_DEPOSIT`
proves the public note commitment was formed from the signer-held spending key
and owner blinding while keeping both `owner_commitment` and `inner_hash`
private. The public recovery nonce is pseudorandom and useful only together
with the seed-derived owner commitment. This closes audit C-06: the depositing
Solana signer is still public, as is the gross deposit amount, but the
wallet-wide shielded owner identity is no longer exposed or clustered there.

Why a single `r_owner` (rather than per-note `r_owner`)? Cryptographically,
the per-note `inner_hash` already provides note-level unlinkability. A
shared `r_owner` simplifies key management (no need to track per-note
ownership blinders). Two notes from the same user *would* be linkable if an
attacker had their `spending_key` — but in that case the attacker has full
authority anyway, so no marginal damage.

#### `user_commitment`

```
rootHash    = Poseidon4(DOMAIN_ROOT=10,  root_pubkey_lo, root_pubkey_hi, r0)
spendHash   = Poseidon3(DOMAIN_SPEND=11, spending_key, r1)
viewHash    = Poseidon3(DOMAIN_VIEW=12,  viewing_key, r2)
leafPair    = Poseidon3(DOMAIN_LEAF=13,  rootHash, spendHash)
user_commitment = Poseidon3(DOMAIN_TOP=14, leafPair, viewHash)
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

Darknyx is a UTXO darkpool. Every shielded balance is a **note** — a logical
record of one (mint, amount, owner) holding, identified on-chain only by
its 32-byte Poseidon commitment.

### Note structure (v2 — `inner_hash`)

```rust
struct Note {
    token_mint:       Pubkey,    // 32B — SPL mint
    amount:           u64,
    owner_commitment: [u8; 32],  // Fr — Poseidon3(DOMAIN_OWNER=1, spending_key, r_owner)
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
is **amount-independent**. It becomes public only when a note is spent
(`withdraw`) and stays hidden until then. VALID_MATCH_BATCH v3 derives match
outputs from the consumed opening, so their nullifiers are reconstructed from
the spending key plus that deterministic derived inner. Parity test:
`packages/sdk/tests/nullifier-parity.test.ts`.

### Deriving `inner_hash` (recoverable, never random)

* **Deposit notes** — `recovery_nonce = deriveBlindingFactor(masterSeed,
  depositIndex)`, then `inner_hash = Poseidon3(27, owner_commitment,
  recovery_nonce)`. The instruction publishes only the nonce, mint, gross
  amount, and commitment; the owner and inner remain private witnesses. Cold
  recovery derives the canonical owner from the seed, reconstructs the inner,
  and accepts the event only after recomputing the commitment byte-for-byte.
* **Match user outputs** — `Poseidon3(24, consumed_input_inner, role)` for
  trade and change roles.
* **Match fee outputs** — `Poseidon3(25, consumed_input_commitment, role)` for
  base/quote fee roles.
* **Merge outputs** — `Poseidon6(26, c0, c1, c2, c3, active_bitmap)`.

Rust/TS KATs and parity tests pin each construction; see §7 and the
cross-language contract table in CLAUDE.md.

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
| `note_fee_quote` | quote | this match's quote-side fee | protocol's `owner_commitment` | per match, fee-on | **Protocol fee (quote)** |
| `note_fee_base` | base | this match's base-side fee | protocol's `owner_commitment` | per match, fee-on | **Protocol fee (base)** |

Plus the two input notes **consumed** at settle (the leaf is permanent;
their commitments are marked in `ConsumedNoteEntry` PDAs): `note_a` (buyer's
input) + `note_b` (seller's input).

**Per-side conservation law**:

```
note_a.amount = quote_amount + buyer_change_amt + buyer_fee_amt
note_b.amount = base_amount  + seller_change_amt + seller_fee_amt
```

Enforced in **VALID_MATCH_BATCH** with u64 range checks on every term. Lock
amounts are private and absent from `NoteLock`, so the circuit is the
load-bearing conservation check (see §7).

### Why `note_e` is in QUOTE and `note_f` is in BASE

A buyer pays QUOTE to receive BASE; unused QUOTE is their change (note_e,
quote mint, to the buyer). The seller pays BASE to receive QUOTE; unsold
BASE is their change (note_f, base mint, to the seller). The mint of a change
note is the **same as the input it came from** — which is why
`tee_forced_settle_batched` reads `lock_a.token_mint` / `lock_b.token_mint`
and passes them to `create_relock_pda`. Misrouting a mint would break
VALID_SPEND at withdraw.

### Partial-fill continuation (derived outputs)

When a LIMIT order partially fills, its residual stays live and **re-matches
without a client roundtrip**. VALID_MATCH_BATCH v3 derives the change inner
from the exact consumed input opening:

```
note_e.inner = Poseidon3(24, note_a.inner, CHANGE_ROLE_BUYER)
note_f.inner = Poseidon3(24, note_b.inner, CHANGE_ROLE_SELLER)
```

The matcher rotates the residual to that derived commitment in enclave memory.
On-chain, `tee_forced_settle_batched` creates a fresh `NoteLock` PDA
   (`create_relock_pda`) seeded by the change note's commitment, bound to the
   same order_id, atomically with the settle — so the residual is pinned and
   continues into the next batch.

Output safety and liveness no longer depend on an anchor pool, a batch slot, or
a process-local counter. Canonical order v2 removed anchor fields and the
top-up endpoint.

**Durable recovery v3.** The unchanged 128-byte `fill_recovery` field is packed
as `ephemeral_pubkey(32) || buyer_enc(44) || seller_enc(44) || "DNYXREC3"`.
Buyer plaintext is `(trade_base, change_quote)`; seller plaintext is
`(trade_quote, change_base)`. Each 44-byte side blob is
`nonce(12) || ChaCha20-Poly1305(ciphertext(16), tag(16))`, keyed by X25519 +
HKDF domain `darknyx-fill-enc-v3`. The version trailer makes the clean cutover
reject legacy one-u64 blobs.

`recoverFillFromChain` resolves the payload's exact consumed commitment,
re-verifies that opening, decrypts the tuple, derives both output inners by role,
and accepts only byte-equal recomputed commitments. `recoverNotesFromChain`
then scans finalized vault instructions/events to bootstrap seed-owned deposits,
restore trade/change shard + leaf positions, and reconstruct merge outputs from
their consumed commitments. It iterates to a fixed point, so continuation and
merge chains recover without live stream history or RPC result ordering.

### Protocol fee notes

Both legs pay their own protocol fee. Each match derives its own fee inners from
the real commitments it consumes:

```
quote_fee.inner = Poseidon3(25, note_a.commitment, FEE_ROLE_QUOTE)
base_fee.inner  = Poseidon3(25, note_b.commitment, FEE_ROLE_BASE)
```

That match's Tx D appends the nonzero fee notes atomically with input
consumption. There is no aggregate flush slot and no slot/reboot-derived fee
opening. Both notes pay the protocol's governed `owner_commitment` and are
spendable through standard `VALID_SPEND`.

Each order must lock **at least** `nominal + its own fee` collateral (intake
derives this floor in `orders.rs`) or `run_batch` rejects the match as
conservation-breaking. `VaultConfig.fee_rate_bps` is the authoritative
on-chain fee rate; the CVM adopts it at boot over the
`DARKNYX_TEE_FEE_RATE_BPS` fallback (default 30).

**Over-collateralization.** An order MAY lock a note larger than that floor —
e.g. point a 500-USDC deposit at a 50-USDC order. The client declares the
note's actual amount in the order's optional `collateral_amount` field (a
plaintext opening field, pinned to the already-signed `note_commitment` — not
in the canonical bytes); intake checks `collateral_amount ≥ floor` and the
matcher returns the surplus as a change note via the same `change = note_amount
− charge` path price-improvement already uses (`algorithm.rs`). So a user
deposits once and trades many sizes up to their largest single note; the
surplus uses the same consumed-input-derived change construction.

**Note merge (orders larger than any single note).** An in-pool consolidation
primitive (`vault::merge` + the `VALID_MERGE(K)` circuit, K∈{2,4}): consume K
input notes (same owner + mint, each proven in the tree) and mint ONE output
note = their sum — no external transfer, `OutstandingMint` unchanged. The output
is a normal tree leaf whose inner is derived from the consumed commitments as
`Poseidon6(26, c0, c1, c2, c3, active_bitmap)`, so recovery needs no mutable
merge counter and the note is spendable like a deposit. The wallet's
`consolidate` greedily merges the
largest notes (fewest inputs → cheapest proof) and **chains** for >K, then the
merged note feeds an over-collateralized order. `VALID_MERGE` pads unused slots
(an `isActive[i]` flag, public commitment 0) so K=4 merges 2–4 notes; every
active amount is positive and u64-range-constrained, inactive amounts are
zero, and an all-dummy merge is impossible. Both K fit pot16. For every active
commitment the instruction also requires the
corresponding `NoteLock` PDA to be absent before proof verification or state
mutation, so a wallet cannot merge collateral reserved by a live order. See
§7.6.

**Tracking balance.** There is no account→balance server mapping (a privacy
choice). A user's balance is the sum of their own UNSPENT deposit, trade/change,
and merge notes, exactly like a wallet summing its UTXOs. "Unspent" is the
on-chain note status (`ConsumedNote`/`NoteLock` PDAs). The SDK `Wallet`
(`packages/sdk/src/wallet/`) exposes `getBalance` / `listNotes` /
`selectCollateral`; `recoverNotesFromChain` rebuilds the openings from the seed
and finalized chain history without an indexer.

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

### Storage trick (sharded across K trees)

The chain only stores **O(depth)** state per tree. The tree state was split
**out of `VaultConfig`** into **K per-shard `MerkleTree` accounts** (PDA
`[b"merkle_tree", &[tree_id]]`) — settles to different shards write distinct
accounts, so the leader can co-include a batch's settle txs (see §9). The
amount-independent `zero_subtree_roots` are identical for every shard, so they
stay **global** in `VaultConfig`; the per-tree append reads them.

```rust
// Global, read-only on the settle hot path:
struct VaultConfig {
    admin: Pubkey,
    tee_pubkeys: [Pubkey; 16],                    // the K authorized TEE signers
    root_key: Pubkey,
    zero_subtree_roots: [[u8; 32]; 20],           // precomputed, shared by all shards
    protocol_owner_commitment: [u8; 32],
    fee_rate_bps: u16, num_tee_keys: u8, num_trees: u8, bump: u8, /* ... */
}

// One per shard (K of them). leaf_count at byte offset 8, current_root at 16:
struct MerkleTree {
    leaf_count:   u64,                            // monotonic, PER-SHARD
    current_root: [u8; 32],
    roots:        [[u8; 32]; 64],                 // 64-root ring buffer
    right_path:   [[u8; 32]; 20],                 // rightmost filled per level
    roots_head:   u8, tree_id: u8, bump: u8, /* ... */
}
```

A new leaf is appended in `O(depth)` Poseidon hashes into `merkle_tree[tree_id]`:
walk up the tree, hash with either the right_path sibling or a zero_subtree_root
(read from `VaultConfig`) depending on whether we're a left or right child at
each level. The right_path is updated in place.

Reference: `programs/vault/src/merkle.rs::append_leaf(tree, zero_subtree_roots, leaf)`.

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

## 7. The ZK circuits

Five custody/trade-path Groth16 circuits ship, plus the auxiliary
`VALID_MERGE(K)` consolidation circuit (§7.6). The matching/settlement validity proof,
`VALID_MATCH_BATCH`, proves **output-note construction + per-leg conservation
+ no-inflation range checks + the fee floor** for an entire batch (≤ N=16
matches) in one proof — it is what earlier designs split across separate
`VALID_CREATE` (output-note correctness) and `VALID_PRICE` circuits, now folded
inline and verified on-chain by `verify_match_batch`. Those two standalone
circuits were removed. **NOTE:** the in-circuit `VALID_PRICE` part is only the
definitional `quote = floor(base·price/price_scale)` + range/remainder checks — it does **not** enforce an
oracle band or the traders' limit prices. That price-fairness check lives in
the in-enclave matcher (TEE-trusted), so a compromised TEE is not bound to a
fair execution price by the proof (see the §2 non-goals row).

| Circuit | Constraints | Public inputs | Purpose |
|---|---|---|---|
| `VALID_WALLET_CREATE` | ~250 | 1 | Bind a `user_commitment` to (root, spending, viewing) keys |
| `VALID_DEPOSIT` | 2,501 | 5 | Bind a recoverable note commitment to the public mint, amount, and recovery nonce while hiding owner + inner |
| `VALID_SPEND` | ~7,000 | 5 | Prove note ownership + Merkle inclusion at withdraw time |
| `VALID_INPUT` | 12,058 | 4 | Prove note ownership + Merkle inclusion at **lock** time while keeping the positive u64 amount and nullifier private |
| `VALID_MATCH_BATCH` | 232,806 (N=16) | 8 | Per-match fee notes, deterministic output inners, scaled floor pricing, conservation, and active-slot/market binding; public inputs are `[root, fee_rate_bps, protocol_owner, base_lo, base_hi, quote_lo, quote_hi, price_scale]` (N ∈ {2, 4, 16}; only N=16 wired on-chain) |
| `VALID_MERGE` (K=2) | 25,532 | 6 | In-pool note consolidation: positive active inputs (same owner+mint, Merkle-proven) → one summed output with commitment-derived inner (§5 / §7.6) |
| `VALID_MERGE` (K=4) | 48,458 | 8 | Same, up to 4 inputs (dummy-padded for 2–3); chained for >4 |

The first five are custody/trade-path circuits; `VALID_MERGE(K)` is an auxiliary
consolidation circuit (its own ix, `vault::merge`, not part of settle).
`VALID_WALLET_CREATE`, `VALID_DEPOSIT`, `VALID_SPEND`, `VALID_INPUT`,
and both `VALID_MERGE` variants use the **`pot16` Powers-of-Tau** file
(`scripts/ptau/powersOfTau28_hez_final_16.ptau`, 2^16 capacity).
`VALID_MATCH_BATCH` at N=16 needs **`pot18`** (~288 MB, 2^18 capacity)
because its constraints exceed 2^16 — `scripts/download-ptau.sh` fetches
both. All circuits use the **same deterministic dev contribution**
(seeded `"darknyx-phase1-dev-contribution-$name"`); the batched zkeys also run
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
rootHash    = Poseidon4(DOMAIN_ROOT=10,  rootKey[0], rootKey[1], r0)
spendHash   = Poseidon3(DOMAIN_SPEND=11, spendingKey, r1)
viewHash    = Poseidon3(DOMAIN_VIEW=12,  viewingKey, r2)
leafPair    = Poseidon3(DOMAIN_LEAF=13,  rootHash, spendHash)
userCommitment === Poseidon3(DOMAIN_TOP=14, leafPair, viewHash)
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

### 7.2 `VALID_DEPOSIT`

**Public inputs** (5), in exact verifier order:

1. `noteCommitment`
2. `tokenMint[0]`, `tokenMint[1]` — u128 halves
3. `amount` — positive u64 gross deposit amount
4. `recoveryNonce` — pseudorandom Fr derived from the seed + deposit index

**Private witnesses**: `spendingKey`, `ownerCommitmentBlinding`.

```circom
owner = Poseidon3(1, spendingKey, ownerCommitmentBlinding)
inner = Poseidon3(27, owner, recoveryNonce)
noteCommitment === Poseidon6(2, mint_lo, mint_hi, amount, owner, inner)
Num2Bits(128)(mint_lo); Num2Bits(128)(mint_hi)
Num2Bits(64)(amount); amount != 0
```

The vault verifies this proof **before** transferring SPL tokens or mutating
the Merkle tree/outstanding counter. Thus a tampered mint, amount, commitment,
nonce, key, or owner blinding cannot move custody or append a leaf. The public
nonce preserves seed-plus-chain recovery without publishing an ordered wallet
counter or either hidden note field.

Measured on the implementation spike: 2,501 constraints; 263.75 ms p95 full
Node/snarkjs proof (50.86 ms witness, 212.89 ms prove); 150,910 CU for a first
deposit; and an 845-byte signed transaction including a 300k-CU budget ix.

### 7.3 `VALID_SPEND`

**Public inputs** (5):
1. `merkleRoot` — the tree root the proof was generated against (must be in
   the recent-roots ring buffer)
2. `nullifier` — `Poseidon3(DOMAIN_NULL=3, spending_key, inner_hash)`, revealed to
   the chain's nullifier set
3. `tokenMint[0]` — low 128 bits of the SPL mint pubkey
4. `tokenMint[1]` — high 128 bits
5. `amount` — u64, the amount the chain will SPL-transfer out

**Private witnesses**:
- `spendingKey`, `ownerCommitmentBlinding` (= r_owner)
- `innerHash` (per-note; v2 — replaces the old `nonce`/`blindingR` pair)
- `merklePath[20]`, `merkleIndices[20]` — Merkle witness

**Constraints**:

```circom
owner_commitment = Poseidon3(DOMAIN_OWNER=1, spendingKey, ownerCommitmentBlinding)
note_commitment  = Poseidon6(DOMAIN_NOTE, tokenMint[0], tokenMint[1],
                             amount, owner_commitment, innerHash)
MerkleTreeChecker(20)(leaf = note_commitment, root = merkleRoot,
                      pathElements = merklePath, pathIndices = merkleIndices)
nullifier        === Poseidon3(DOMAIN_NULL=3, spendingKey, innerHash)
```

What this proves to the chain: "I know a note whose Poseidon-commitment is
at `merkleRoot`, I'm the owner (since I know the spending_key), and here is
the nullifier — verify it isn't spent yet."

Reference: `circuits/valid_spend/circuit.circom` (105 lines), on-chain
verification in `programs/vault/src/instructions/withdraw.rs:131-144`.

### 7.4 `VALID_INPUT`

**Public inputs** (4):
1. `merkleRoot`
2. `noteCommitment` — exposed as public so the on-chain `lock_note`'s PDA
   seed matches
3. `tokenMint[0]`, `tokenMint[1]`

**Private witnesses**: `amount`, the owner opening, and the 20-level Merkle
path. `amount` is constrained to `1..2^64-1` with `Num2Bits(64)` plus a
nonzero constraint.

**Constraints**:

```circom
owner_commitment = Poseidon3(DOMAIN_OWNER=1, spendingKey, ownerCommitmentBlinding)
noteHash         = Poseidon6(DOMAIN_NOTE, tokenMint[0], tokenMint[1],
                             amount, owner_commitment, innerHash)
noteCommitment   === noteHash
Num2Bits(64)(amount)
amount != 0
MerkleTreeChecker(20)(leaf = noteCommitment, root = merkleRoot, ...)
```

Difference from VALID_SPEND: **no nullifier is computed or revealed**.
This is critical for the lock-then-match-then-settle flow:
- A user submits an order with a VALID_INPUT proof.
- The TEE locks the note via `lock_note(commitment, mint, proof, merkleRoot)`;
  the amount never enters instruction or event data.
- If the order doesn't match, the lock expires and the note remains
  spendable. No nullifier was burned.
- If the order does match, `tee_forced_settle` consumes the note via
  `ConsumedNoteEntry` (which is keyed by `note_commitment`, not by
  nullifier). The user's eventual `VALID_SPEND`-based withdraw of this same
  note would fail at the `consumed_note_slot` guard, so no double-spend
  risk.

What this proves to the chain at lock time: "I know a note in the tree, with
this declared mint and commitment, owned by me, whose private amount is a
positive u64."

The TEE then *relays* this proof but cannot forge it (no spending key).
The TEE can choose **whether** to lock a user's note (liveness) but not
**which** commitment / mint to lock or substitute an invalid amount — those are
cryptographically pinned by the proof while the amount remains hidden.

Reference: `circuits/valid_input/circuit.circom` (118 lines), on-chain
verification in `programs/vault/src/instructions/lock_note.rs:80-115`.

#### Why VALID_INPUT keeps the ownership constraint

You might think you could drop the `owner_commitment = Poseidon3(DOMAIN_OWNER=1, spending_key, r_owner)`
constraint, since lock_note doesn't need to prove ownership (the proof is
just attesting that the leaf exists). But:

**Attack without ownership constraint**: a deposit's `owner_commitment`
and `inner_hash` are both *public* on L1 (they're args to
`vault::deposit`). Anyone reading the deposit tx can reconstruct the note
opening. Without an ownership constraint, anyone could generate a
VALID_INPUT proof for Alice's note and lock it against an arbitrary order —
DoS griefing at minimum, potentially full theft if combined with a clever
match construction.

By requiring the prover know `spending_key` such that `Poseidon3(DOMAIN_OWNER=1, sk, r_owner)
== owner_commitment` (where `owner_commitment` is itself a private witness
because it goes into the note's preimage), the proof can only be generated
by someone who knows the spending key. The note's actual `owner_commitment`
becomes a tightly-bound private value, hence the prover must be the owner.

### 7.5 `VALID_MATCH_BATCH`

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
            │    • scaled floor quote + remainder    │
            │    • conservation: a == quote+change+  │
            │      fee (+ seller leg)                 │
            │    • range checks: Num2Bits(64) on ALL │
            │      amounts (P1a — no inflation)       │
            │    • fee floor: (fee+1)*10000 >        │
            │      notional*fee_rate_bps (P1b)        │
            │    • fee-note binding: slot-0 fee notes│
            │      == Poseidon6(Σ fee, owner, …)     │
            │    • leaf_i := H_leaf(commitments)     │
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

Public inputs (8) — declaration order is load-bearing (matches the on-chain
`verify_groth16_proof::<8>` in `verify_match_batch`):
- `merkle_root` — the depth-`log2(N)` Poseidon Merkle root over the
  per-slot leaves. The on-chain `verify_match_batch` uses this as the
  PDA seed for `BatchValidityMarker` at `[b"batch_validity", merkle_root]`.
- `fee_rate_bps` — the protocol fee floor the circuit enforces per slot;
  `verify_match_batch` binds it to the authoritative `VaultConfig.fee_rate_bps`.
- `protocol_owner_commitment` — the owner the batch's fee notes are bound to;
  `verify_match_batch` binds it to `VaultConfig.protocol_owner_commitment`.
- `base_mint_lo`, `base_mint_hi`, `quote_mint_lo`, `quote_mint_hi` — the
  two 128-bit field halves of the enabled `MarketConfig` mint pair.
- `price_scale` — the nonzero governed fixed-point denominator from that market.

Leaf-hash construction. **Amount-privacy (P1b): the leaf is commitment-only.**
The note commitments transitively bind the amounts/mints/price (each is a
Poseidon6 of mint+amount+owner+inner), and conservation + the range checks are
proven over the private witness, so the leaf no longer needs to hash any
plaintext amount/mint/price. This replaced the old two-stage Poseidon12+Poseidon9
(which hashed `base_amount`/`quote_amount`/change/fee/`clearing_price` directly).
A single Poseidon11 fits under the on-chain `light-poseidon` arity cap of 12:

```
leaf = Poseidon11(DOMAIN_LEAF_V2 = 23, active,
                  note_a_commit, note_b_commit, note_c_commit,
                  note_d_commit, note_e_commit, note_f_commit,
                  note_fee_base_commit, note_fee_quote_commit,
                  batch_slot)
```

Inner-node hashes use `Poseidon3(DOMAIN_BATCH_ROOT = 22, left, right)`. The two
fee-note commitments are per-match. Each fee inner is
`Poseidon3(25, consumed_input_commitment, role)` and each user output inner is
`Poseidon3(24, consumed_input_inner, role)`, so a prover cannot select output
randomness or reuse a slot-derived fee inner across distinct consumed notes.

Padding semantics. The prover (`helpers/match-batch-prover.ts`) auto-
pads short batches to N=16 with canonical inactive slots (`active=0`) whose
amounts, commitments, owners, inners, mints, and fees are all zero. Padding is necessary
because the on-chain handler walks a fixed depth-4 Merkle path
(`walk_merkle_path_n16`). Slot 0 is always real in current tests;
slots 1..15 are dummies unless the matcher provides real data.

Constraint count at N=16 is dominated by the Merkle tree + 16 × per-slot
constraints. Amount-privacy (P1b) nets two opposing effects: the commitment-only
leaf REMOVED the amount-hashing Poseidon12+Poseidon9 stages, while the per-amount
`Num2Bits(64)` range checks + the in-circuit fee floor/binding ADDED constraints.
Net total still exceeds 2^16 → `pot18` is required for setup (don't edit
`download-ptau.sh` to skip it). On-host proof generation: ~6.7 s on a modern
laptop, ~1.5 s on-chain verification.

**Tests**:
[`match-batch-prototype.test.ts`](../packages/sdk/tests/match-batch-prototype.test.ts)
(N=2 / N=4 / N=16 in-circuit verification + leaf-byte parity with
the on-chain `compute_match_leaf`).
[`tee_forced_settle_batched.rs`](../programs/vault/tests/tee_forced_settle_batched.rs)
(litesvm — drives two real matches through one shared marker;
catches the "close after every match" 1:N-marker regression).

---

### 7.6 `VALID_MERGE(K)`

An **auxiliary** circuit (not part of settle): in-pool note consolidation.
It backs the `vault::merge` instruction, which consumes K input notes and
mints ONE output note = their sum. This is what lets a user trade an order
**larger than any single note** — the wallet consolidates fragments into one
note ≥ the order, then places it as an over-collateralized order (§5).

Instantiated at **K ∈ {2, 4}** (`circuits/valid_merge_k2`,
`valid_merge_k4`). The wallet picks K=2 for ≤2 inputs, K=4 for 3–4 (the
spare slots are dummy-padded), and **chains** merges for >4.

```
            For each slot i ∈ [0, K):
            ┌────────────────────────────────────────────┐
            │  isActive[i] ∈ {0,1}  (boolean-constrained) │
            │  commit_i := Poseidon6(DOMAIN_NOTE,         │
            │     mint_lo, mint_hi, amount[i],            │
            │     owner_commitment, innerHash[i])         │
            │  root_i := MerkleRootFromLeaf(commit_i,     │  ← compute-only;
            │              path[i], idx[i])               │     no hard assert
            │  isActive[i]·(root_i − merkleRoot) === 0    │  ← conditional bind
            │  inputCommitments[i] :=                     │
            │     isActive[i]·commit_i                    │  ← dummy ⇒ public 0
            │  Num2Bits(64)(amount[i])                    │
            │  active ⇒ amount[i] > 0                     │
            │  inactive ⇒ amount[i] = 0                   │
            └────────────────┬───────────────────────────┘
                             ▼
            outputAmount := Σ isActive[i]·amount[i]   (Num2Bits(64))
            require Σ isActive[i] > 0 and outputAmount > 0
            outputInner := Poseidon6(26, c0, c1, c2, c3, active_bitmap)
            outputCommitment === Poseidon6(DOMAIN_NOTE, mint_lo, mint_hi,
                                  outputAmount, owner_commitment,
                                  outputInner)
```

Public signals (circom output-first order, matching `merge.rs`'s `pi`
array): `outputCommitment`, `inputCommitments[K]`, then the public inputs
`merkleRoot`, `tokenMint[2]` (mint_lo, mint_hi) — **6 for K=2, 8 for K=4**.
Private: one shared
`spendingKey` + `ownerCommitmentBlinding` (this is what enforces *all K notes
belong to the same owner*) and per-slot `isActive`, `amount`, `innerHash`,
`merklePath[20]`, `merkleIndices[20]`. There is no caller-selected output-inner
witness.

The one real subtlety is the **dummy slots**. `MerkleTreeChecker` (used by
VALID_SPEND/INPUT) hard-asserts `root === computed`, which a padded slot
can't satisfy — so merge uses a compute-only `MerkleRootFromLeaf(depth)` (the
same Switcher/Poseidon2 ladder, but it *outputs* the root) and binds it
conditionally: `isActive[i]·(root_i − merkleRoot) === 0`. An inactive slot
sets `isActive[i]=0`, has zero amount, emits `inputCommitments[i]===0`, and
contributes 0 to the sum. The circuit rejects an all-dummy or zero-output
witness. The on-chain
`merge` ix creates a `ConsumedNoteEntry` PDA only for each **non-zero** input
commitment (the replay guard), so a padded slot can't smuggle a spend. Its
remaining accounts are two ordered runs: the writable consumed-note PDAs,
followed by the read-only `NoteLock` PDAs whose absence is required for those
same active commitments.

Conservation: K notes consumed + 1 minted, same mint, same total ⇒ **no
`OutstandingMint` change** (unlike withdraw — the pool still owes the same
total). The output note is a normal tree leaf with a commitment-derived
`inner_hash`, so it is recoverable without a restart-sensitive counter and is
spendable exactly like a deposit. This v3 circuit/VK cutover intentionally
requires a clean devnet tree reset; old merge proofs are invalid.

**Tests**:
[`merge-prover.test.ts`](../packages/sdk/tests/merge-prover.test.ts)
(snarkjs K=2 / padded-K=4 round-trip + tamper rejection),
[`merge_verify.rs`](../programs/vault/tests/merge_verify.rs) (on-chain
verify + public-input wire order),
[`devnet-merge.test.ts`](../packages/sdk/tests/devnet-merge.test.ts)
(deposit → merge → withdraw the consolidated note round-trips, gated
`RUN_DEVNET_MERGE`).

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
- `viewing_key` (Fr) via DarknyxShakeKdfV1
- `trading_key(offset=0)` (Ed25519) via HKDF-SHA256 with offset 0
- `root_key` (Ed25519) via HKDF-SHA256 (skipped if she's bringing her own
  Solana keypair — the demo dapp uses Phantom)

She picks blinding factors `r0`, `r1`, `r2`, `r_owner` (random Fr each).

She computes:

- `owner_commitment = Poseidon3(DOMAIN_OWNER=1, spending_key, r_owner)`
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
    tree_id:          u8        = 0,
    amount:           u64       = 5_015,
    note_commitment:  [u8; 32],
    recovery_nonce:   [u8; 32],
    proof:            Groth16Proof,  // VALID_DEPOSIT
)
```

Accounts:
- `depositor` (signer + payer)
- `vault_config` (read-only)
- `merkle_tree[tree_id]` (mut)
- `token_mint` (Account<Mint>)
- `depositor_token_account` (ATA, mut)
- `vault_token_account` (PDA at `[b"vault_token", mint]`, init_if_needed, mut)
- `outstanding_mint` (PDA at `[b"outstanding_mint", mint]`, init_if_needed, mut)
- `token_program`, `system_program`, `rent`

What happens in the handler:

1. Bind the account mint + instruction amount/commitment/nonce into the five
   `VALID_DEPOSIT` public inputs and verify the proof.
2. SPL `transfer_checked` 5,015 USDC from Alice → vault_token_account.
3. `append_leaf(note_commitment)` — incremental Merkle update.
4. `outstanding_mint.outstanding += 5_015` (with `u64::checked_add`).
5. Assert `outstanding_mint.outstanding ≤ vault_token_account.amount` (post-reload).

**Cryptographic primitives**:
- **VALID_DEPOSIT Groth16** for the hidden owner/inner construction.
- **Poseidon3 + Poseidon6** inside the proof.
- **Per-mint solvency counter** maintained as an on-chain invariant.

**Why**: this is the entry point for value into the darkpool. L1 necessarily
sees the depositing signer and gross SPL amount, but no longer sees the
wallet-wide `owner_commitment` or per-note `inner_hash`. The public recovery
nonce lets a replacement device reconstruct the hidden inner from seed + chain.

**Tests**:
- `tests/valid-deposit-prover.test.ts` — proof/public-input ordering and
  adversarial opening-field rejection
- `tests/deposit-transport.test.ts` — 337-byte ix builder layout
- `programs/vault/tests/deposit_with_proof.rs` — real proof, custody atomicity,
  845-byte transaction and 150,910-CU measurement gates
- All three e2e flows exercise deposit end-to-end with real SPL transfers

### Step 4 — Order submission (`POST /orders` → the CVM)

Alice submits her order over TLS directly to the enclave's HTTP surface —
it never touches any L1 transaction. The request body carries the order
intent (`side`, `price_limit`, `amount`, `note_commitment`,
`user_commitment`, `expiry_slot`, `arrival_nonce`), a required contributory
X25519 `viewing_pubkey`, the current 32-byte `/info.boot_session_id`, the input-note opening
(`owner_commitment`, `note_inner_hash`, `nullifier`, `merkle_root`) + a
relayed **VALID_INPUT** Groth16 proof.

Intake (`crates/darknyx-tee/src/api/orders.rs`):

1. Verifies the trading-key Ed25519 signature over the canonical digest,
   including the viewing key, boot session, and arrival nonce.
2. Re-derives the note commitment from the opening (`commitment_from_fields_v2`)
   and asserts it equals the signed `note_commitment` — pinning the opening
   to the signature + enforcing `note_amount == committed amount`.
3. Rejects stale boot sessions, non-contributory X25519 keys, and—after exact
   idempotency—non-increasing nonces for the same trading key.
4. Derives the fee-inclusive collateral (`nominal + own fee`) + books the order.

The trading key is rotatable via offset (§4) so a user can burn a per-session
key and break long-term linkage. **Why it's private:** order intent lives only
in enclave memory; L1 observers see deposits + settled outputs, never the
resting book. The anonymity set is every order in the book that didn't settle.

**Tests:** `tests/order-canonical-parity.test.ts` (the canonical order v2 wire,
byte-equal
to Rust) + `crates/darknyx-tee/tests/orders_surface.rs` (intake: sig / opening /
session / viewing-key / nonce validation).

### Step 5 — Matching (in the CVM)

The matcher interval driver (`crates/darknyx-tee/src/matcher/interval.rs`) ticks
on a cadence (`BATCH_MS`). Each tick, over the in-memory book:

1. Sweeps expired orders and freezes one book snapshot for the complete tick.
2. Builds `darkpool_matcher::PreparedMatchTick` once: sort bids desc / asks
   asc, aggregate quantities by price, then find each page's uniform clearing
   price with a suffix-demand/prefix-supply level sweep and FIFO tie-break.
3. **Circuit breaker**: skip the batch if the clearing price deviates from the
   Pyth TWAP beyond the band.
4. **Partial-fill continuation**: for a relocking side, derive note_e/f from
   the consumed input inner, rotate the residual's collateral to it, insert the
   rotated opening, and keep the order live. No anchor or reboot-local counter
   can influence the output.
5. **Pages** the cleared matches into ≤ N=16 settle batches
   (`MAX_PAGES_PER_TICK` guard), subtracting every reserved/cancelled order from
   the reusable level totals before the next page, and enqueues each to the
   settle scheduler. Orders arriving during paging wait for the next tick.

This is integer arithmetic + Poseidon over the change-note commitments — all
in enclave memory. The cryptography lands at settle time (Step 7+) when these
matches hit L1. **Tests:** `cargo test -p darkpool-matcher` (the algorithm +
parity) + `crates/darknyx-tee/tests/{matcher_tick,order_to_match}.rs`.

### Step 6 — Settle handoff (the CVM drives the on-chain settle)

The settle scheduler dequeues each ≤16-match batch and `assemble_batch`
(`crates/darknyx-tee/src/settle/assemble.rs`) builds the per-slot witnesses + the
`MatchResultPayload`s, then drives Steps 7–9.5 below **sequentially** (so a
change note relocked by one batch is on-chain before a later batch consumes
it). The enclave's dstack-derived Ed25519 key signs each settle payload and
pays the fees. Everything from here is on L1.

### Step 7 — `lock_note` × 2 (L1, v3 private-amount)

For each match, the TEE-operated relayer submits **two independent L1
transactions**, each containing one `lock_note` ix (buyer and seller are sent
concurrently). Each ix:

```rust
vault::lock_note(
    note_commitment: [u8; 32],
    order_id:        [u8; 16],
    expiry_slot:     u64,
    token_mint:      Pubkey,
    merkle_root:     [u8; 32],
    proof:           Groth16Proof,
)
```

Accounts:
- `tee_authority` (signer ∈ `vault_config.tee_pubkeys`)
- `vault_config` (ro — read for the authorized-signer check)
- `merkle_tree[tree_id]` (ro — root recency check on the shard the note lives in)
- `note_lock` (PDA at `[b"note_lock", note_commitment]`, **init**)
- `system_program`

(`tree_id` is a new leading ix arg under tree-sharding; back-compat
default 0.)

Handler steps (v3):

1. Assert `tee_authority.key() ∈ vault_config.tee_pubkeys`.
2. Assert `merkle_root` is in `merkle_tree.contains_root()` (current root
   or any of the previous 32 on that shard).
3. Assert `expiry_slot > clock.slot` AND `expiry_slot ≤ clock.slot + MAX_LOCK_TTL_SLOTS`
   (= 4,500 slots ≈ 30 min at 400 ms slots; a fixed slot count, so it naturally
   tightens to ~15 min after Alpenglow's 200 ms slots — F-05). Intake rejects
   orders beyond this up front, so the cap is a placement error, not a settle failure.
4. Construct the VALID_INPUT public inputs:
   `[merkle_root, note_commitment, mint_lo, mint_hi]`.
5. **Verify the Groth16 proof** against `vk_valid_input`; the proof privately
   enforces `amount ∈ [1, 2^64-1]` and binds it into `note_commitment`.
6. Write the lock:
   ```rust
   lock.note_commitment = note_commitment;
   lock.token_mint      = token_mint;          // v2 NEW
   lock.order_id        = order_id;
   lock.expiry_slot     = expiry_slot;
   lock.locked_by       = tee_authority.key();
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
post-v3 chain knows the commitment is a real Merkle leaf with that mint and a
private positive-u64 amount, owned by someone with the spending key. Neither
the instruction nor `NoteLocked` event reveals the amount.

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
(VALID_MATCH_BATCH) proves output-note construction + scaled floor pricing +
per-leg conservation and per-match fees for every active match in the batch;
it writes one marker:

```rust
vault::verify_match_batch(
    merkle_root:  [u8; 32],     // Poseidon Merkle root over per-slot leaves
    expiry_slot:  u64,
    proof:        Groth16Proof, // VALID_MATCH_BATCH at N=16
)
```

Accounts:
- `payer` (signer — anyone can pay; auth is the proof)
- `vault_config` (**ro** — source of the authoritative `fee_rate_bps` +
  `protocol_owner_commitment` bound into the proof's public inputs)
- `market_config` (**ro** — enabled mint pair + nonzero `price_scale` bound
  into public inputs 4–8)
- `marker` (PDA at `[b"batch_validity", merkle_root]`, **init**)
- `system_program`

Handler:
1. Assert `expiry_slot ∈ (clock.slot, clock.slot + 300]` (≈ 2 min TTL).
2. Read `fee_rate_bps` + `protocol_owner_commitment` from `vault_config`, require
   the supplied market enabled with a nonzero scale, pack the 8 public inputs
   `[root, fee_rate, owner, base_lo, base_hi, quote_lo, quote_hi, scale]`, and
   verify the Groth16 against `vk_match_batch_n16` via
   `verify_groth16_proof::<8>` (~132.5k CU in litesvm — the verifier cost scales with
   public-input count, not constraint count). Binding the fee rate + owner here
   is what makes the circuit's fee floor + fee-note binding enforce the
   protocol's actual config.
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
the 7 derivable PDAs per match — see below).

The settle ix is:

```rust
vault::tee_forced_settle_batched(
    tree_id:      u8,                 // which Merkle-tree shard the outputs append to
    payload:      MatchResultPayload,
    match_index:  u8,                 // 0..15, which slot in the batch
    merkle_proof: [[u8; 32]; 4],      // depth-4 inclusion path
)
```

The payload is a 488-byte Borsh struct (v9). It carries six user-note
commitments, two protocol fee-note commitments, two order IDs, two re-lock
(order_id + expiry) pairs, `batch_slot`, and the 128-byte fill-recovery
ciphertext. The seven plaintext amount fields were removed in v7, and the two
vestigial nullifiers were removed in v9. Amounts remain private circuit
witnesses; commitment-keyed `ConsumedNoteEntry` PDAs provide replay protection.
The Rust struct definition is in
`programs/vault/src/instructions/tee_forced_settle.rs`.

Accounts (12 total, in this exact order — must match the Rust struct).
Post-sharding `vault_config` is **read-only** and the writable tree state is
`merkle_tree[tree_id]` at slot 2:

| # | Account | Role |
|---|---|---|
| 0 | `tee_authority` | signer ∈ `vault_config.tee_pubkeys` (the shard's fee-payer key) |
| 1 | `vault_config` | **ro** — authorized-key check + protocol_owner + zero_subtree_roots |
| 2 | `merkle_tree[tree_id]` | **mut** — the output-shard the notes append to |
| 3 | `note_lock_a` | mut, close — input lock from step 7 |
| 4 | `note_lock_b` | mut, close — input lock from step 7 |
| 5 | `consumed_a` | init — the consume-once guard for note_a (shared with `withdraw`) |
| 6 | `consumed_b` | init — the consume-once guard for note_b |
| 7 | `note_lock_e` | unchecked — writable only when buyer relock is requested |
| 8 | `note_lock_f` | unchecked — writable only when seller relock is requested |
| 9 | `instructions_sysvar` | sysvar — for finding the Ed25519 precompile |
| 10 | `batch_validity_marker` | **ro** — the 1:N marker from step 8, checked and never closed here |
| 11 | `system_program` | for CPIs |

> The two per-match `nullifier_{a,b}_entry` accounts (formerly slots 7–8) and
> their vestigial payload fields are **removed**. Those TEE-supplied values were
> unconstrained (no nullifier signal in VALID_MATCH_BATCH; the leaf binds only
> commitments + `batch_slot`), so writing them provided no soundness — and it enabled a
> griefing **freeze**: a compromised TEE could `init` a `NullifierEntry` at a
> victim's future withdraw nullifier, permanently blocking that withdraw (whose
> own `nullifier_entry` init would then collide). The commitment-keyed
> `consumed_a/b` are the real double-spend guard, and `withdraw` now writes a
> matching `ConsumedNoteEntry` so the guard is symmetric across both paths.
> Dropping the two inits reclaimed 2 accounts + 2 CPIs. Payload v9 then removed
> the dead signed values themselves, reclaiming another 64 wire bytes.

ix data = disc(8) ‖ tree_id(1) ‖ payload(488) ‖ match_index(1) ‖ 4×32 siblings = 626 B.

Handler walkthrough:

1. **TEE authority check**: `vault_config.is_authorized_tee(tee_authority.key())`
   (the signer must be one of the K registered `tee_pubkeys`).

2. **Ed25519 signature binding** (`verify_tee_signature`):
   walk the tx's instructions sysvar, find an `Ed25519Program` precompile
   ix, assert its inlined (pubkey, message) tuple equals
   `(tee_authority.key(), canonical_payload_hash(payload))` — i.e. the
   signature is bound to *the same* registered shard key that signed the
   tx (one of the K `tee_pubkeys`). The precompile itself
   has already done the signature-bytes verification — the vault just
   binds it to the right key + message.

3. **Lock binding and lifetime**: load `note_lock_a` and `note_lock_b`, assert
   their stored `order_id`s match the payload's, and require the current slot
   to be strictly less than **both** individual `expiry_slot`s. Settlement is
   invalid at the exact expiry boundary where `release_lock` becomes valid.
   Capture `lock_a.token_mint` and `lock_b.token_mint` for later use.

4. **Validity marker check**:
   - Recompute the per-slot Merkle leaf via the same single Poseidon11 the
     circuit uses (see §7.5). Amount-privacy (P1b) made the leaf
     **commitment-only** — the note commitments transitively bind the
     amounts/mints/price, so the leaf no longer hashes them (it replaced the old
     two-stage Poseidon12+Poseidon9 that did):
     ```
     leaf = Poseidon11(DOMAIN_LEAF_V2 = 23, active = 1,
                       note_a, note_b, note_c, note_d, note_e, note_f,
                       note_fee_base, note_fee_quote, batch_slot)
     ```
   - Walk a depth-4 Merkle path with the caller-supplied 4 siblings +
     `match_index` (bits of `match_index` select left/right at each
     level, inner nodes = `Poseidon3(DOMAIN_BATCH_ROOT = 22, left, right)`).
   - Derive the expected marker PDA at `[b"batch_validity", computed_root]`,
     assert the supplied `batch_validity_marker.key()` matches, and assert
     it's owned-by-us + non-expired.
   - The marker is read-only in every Tx D builder. **Do NOT close it.** It
     covers all N matches in the batch and
     must remain present for matches `match_index + 1 .. N-1`. Reclaiming
     its rent is the job of `close_batch_validity_marker` at or after expiry
     (Step 9.5).

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
   `init` constraint → a second settle of the same input collides here. This is
   also the **cross-path** guard: `withdraw` now `init`s the same
   commitment-keyed PDA, so a settle cannot consume an already-withdrawn note
   (and vice-versa). The commitment is public AND circuit-bound, unlike the
   nullifier, which is why it — not the nullifier — is the trustless guard.

8. **(removed)** — the per-match `NullifierEntry` writes and payload nullifier
   fields were deleted. See the note under the account table above. Payload v9
   bumps the canonical signature domain, so no older signed layout is accepted.

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

11. **Marker lifecycle** — do not write the `BatchValidityMarker` here.
    It's 1:N (one PDA keyed by the batch's Merkle root, covering up to 16
    matches). It stays read-only across concurrent Tx Ds, eliminating the
    batch-wide writable-account conflict. Rent reclamation is the job of
    `close_batch_validity_marker` at or after expiry (Step 9.5).

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
the canonical-hash Ed25519 precompile + all the account keys + the 488-byte
payload would be ~1800 bytes total — way over the 1232 cap. By splitting:
- Tx A (lock): 2 lock_notes with embedded VALID_INPUT proofs, ~1100 B.
- Tx B (verify): 1 verify_match_batch with the embedded VALID_MATCH_BATCH
  proof, ~640 B.
- Tx D (settle, V0 + stacked ALTs): Ed25519 precompile + tee_forced_settle_batched
  + the depth-4 inclusion proof, 1109 B in the worst-case v9 regression fixture
  (123 B of headroom under the 1232-byte cap).

See §9 for why the v0/ALT stacking was specifically required.

**Tests**:
- `tests/cvm-settle-e2e.test.ts` — the live-CVM real settle (deposit → match → settle)
- `tests/devnet-deposit-withdraw.test.ts` — the no-CVM deposit + VALID_SPEND withdraw
- `programs/vault/tests/tee_forced_settle_batched.rs` — the 1:N marker lifecycle
- `tests/settle-builder-batched.test.ts` — the settle ix wire format (payload Borsh,
  canonical hash byte-equality with the Rust fixed vector, Ed25519 layout, account order).
- `tests/settle-builder-batched.test.ts` — settle ix wire-format
  unit tests for `buildSettleBatchedIx` + `buildCloseBatchValidityMarkerIx`:
  12-account ordering, 626-byte ix data (disc + tree_id + payload + match_index +
  4×32 siblings), Anchor `[[u8; 32]; 4]` encoding, `BatchValidityMarker`
  PDA derivation, `match_index` boundary validation [0, 15].
- `programs/vault/tests/tee_forced_settle_batched.rs` (litesvm)
  regression test that seats two real matches at slots 0 and 1
  settling against the same marker; catches the "close
  after every match" regression.

### Step 9.5 — `close_batch_validity_marker` (L1)

Lands once per batch at or after the marker's expiry. Reclaims the marker's
~49-byte rent without creating a payer-controlled early-close race against
pending Tx Ds.

```rust
vault::close_batch_validity_marker(merkle_root: [u8; 32])
```

Accounts (3):
- `authority` (any signer; no signer has a pre-expiry privilege)
- `payer` (mut — refund recipient, must equal `marker.payer`;
  Anchor `has_one = payer` enforces this)
- `marker` (mut, `close = payer`, seeded by `[b"batch_validity",
  merkle_root]`, validated via `bump = marker.bump`)

Handler:
1. Require `clock.slot >= marker.expiry_slot` for every authority, including
   the recorded payer. Tx D already requires `clock.slot < expiry_slot`, so
   the exact boundary is disjoint and safe.
2. Anchor's `close = payer` constraint moves the marker's lamports
   to `payer` and zeros the data.
3. Emit `BatchValidityMarkerClosed { payer, closed_by, expiry_slot }`.

`VaultError::BatchValidityMarkerNotExpired` covers every pre-expiry attempt,
whether submitted by the payer or a third party. The TEE sweeper reads each
marker and queues only expired accounts; missing accounts are removed from its
durable cleanup queue and transient RPC/layout failures are retried.

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
- `consumed_note` (init — the commitment-keyed consume-once guard)
- `note_lock_slot` (CHECK: must not exist)
- `nullifier_entry` (init)
- `outstanding_mint` (mut)
- `token_program`, `system_program`

Handler:

1. `amount > 0`.
2. **Layer-3 guard (now an `init`)**: the `consumed_note` account is `init`'d
   at `[b"consumed_note", note_commitment]`. If the note was already consumed —
   by a prior `withdraw` OR by `tee_forced_settle_batched` (which `init`s the
   SAME PDA) — the init collides and the withdraw reverts. This closes the
   double-spend in BOTH directions (the old code only *read* this PDA, so it
   caught settle→withdraw but NOT withdraw→settle: a settle could still consume
   an already-withdrawn note because withdraw left no consume guard).
3. **Layer-1 guard**: if `note_lock_slot.owner == program_id`, the note is
   currently locked to an active order. Reject with `NoteAlreadyLocked`.
4. **Recency check**: `vault_config.contains_root(&merkle_root)` — must be
   in the 32-root ring buffer.
5. **VALID_CREATE-style accounting precheck**: assert
   `outstanding_mint.outstanding >= amount`. (If it were less, the TEE
   created a phantom note for this mint and the counter rejects the
   withdraw before the SPL transfer-out.)
6. Allocate the `NullifierEntry` PDA (guards against double-withdraw via the
   nullifier) AND write the `consumed_note` entry from step 2 (the shared,
   commitment-keyed consume-once guard).
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
    │  trading_key signs the order canonical
    │  intake verifies sig + note opening; books in enclave memory
    ▼
MATCH (in the CVM)
    │  Uniform clearing price; circuit breaker against Pyth TWAP
    │  Partial fill → derive output from consumed input, rotate residual
    │  Page cleared matches into ≤ N=16 settle batches
    ▼
LOCK_NOTE × 2 per match (L1, two VALID_INPUT proofs)
    │  NoteLock PDAs at [b"note_lock", commitment]
    │  Each lock bound to (order_id, mint); amount stays private in proof
    ▼
VERIFY_MATCH_BATCH (L1, 1 Groth16 per batch)
    │  BatchValidityMarker PDA at [b"batch_validity", merkle_root]
    │  Covers up to N=16 matches.
    ▼ (one per real match)
TEE_FORCED_SETTLE_BATCHED (L1, v0 + stacked ALTs)
    │  Ed25519 + canonical hash
    │  Leaf hash + depth-4 Merkle inclusion path to the marker
    │  Conservation + structural checks; ConsumedNoteEntry PDAs
    │  Up to 6 output leaves (note_c/d + change + base/quote fee)
    │  Atomic re-lock of the change note (if the order continues)
    │  Marker NOT closed (it's 1:N)
    ▼ (once per batch)
CLOSE_BATCH_VALIDITY_MARKER (L1)
    Reclaims ~49 B rent to marker.payer.
    Pre-expiry: rejected for every signer.
    At/post-expiry: any signer can sweep (rent still flows to payer).
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
| `lock_note` ix data (8 disc + 1 tree + 32 commit + 16 order_id + 8 expiry + 32 mint + 32 root + 256 proof) | 385 |
| `lock_note` accounts (4 × 32) | 128 |
| `verify_match_batch` ix data (8 disc + 32 root + 8 expiry + 256 proof) | ~304 |
| Ed25519 precompile ix (header + pubkey + sig + 32-byte msg) | ~150 |
| `tee_forced_settle_batched` ix data (8 disc + 1 tree + 488 payload + 1 match_index + 4×32 siblings) | 626 |
| Account keys for everything together (~13 distinct) | 416 |
| **TOTAL** | **~2000+** |

So the settle is split into a pipeline, per batch (≤ N=16 matches):

| Tx | Contents | Approx size | Cardinality |
|---|---|---|---|
| **Tx A — lock** | compute_budget + one lock_note (buyer/seller sent independently) | size-guarded below 800 B | 2N per batch |
| **Tx B — verify_match_batch** | compute_budget + verify_match_batch (1 Groth16, 1 marker init) | ~640 B | 1 per batch |
| **Tx C — per-batch ALT** | createLookupTable + chunked extendLookupTable(7 PDAs per match) | amortized | 1 per batch |
| **Tx D — settle_batched** | compute_budget + ed25519_precompile + tee_forced_settle_batched (v0 + stacked ALTs) | 1109 B worst case (v9) | N per batch |
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
TTLs (locks ~30 min, markers ~2 min), so abandoned state self-cleans.

### The marker PDA construction (binding by seed)

The `BatchValidityMarker`'s *seed* is the batch Merkle root, not its data.
`verify_match_batch` verifies the Groth16 over the 8 public inputs
`[root, fee_rate, owner, base_lo, base_hi, quote_lo, quote_hi, price_scale]`
(fee/owner bound to `VaultConfig`, market fields bound to `MarketConfig`) and
inits the marker at `[b"batch_validity", merkle_root]`.
At settle, `tee_forced_settle_batched` recomputes the per-slot leaf from
the payload commitments, walks the depth-4 inclusion path to a root, and
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
| `consumed_a/b` | per-match | NO |
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
    addresses:    [vaultConfigPda, SYSVAR_INSTRUCTIONS_PUBKEY, SystemProgram.programId,
                   ...merkleTreePdas /* one per shard, tree 0..K-1 */],
});
// Send both ixs in one tx, then wait one slot for the ALT to be referenceable.
```

The resulting ALT pubkey is written to `.devnet/e2e-config.json` as
`settleLookupTable` and reused by every settle tx forever. With
tree-sharding the static ALT also lists the **K `merkle_tree` PDAs** —
every settle's writable `merkle_tree[tree_id]` (the per-shard tree the
match's outputs append to) resolves through this one ALT regardless of
which shard the worker round-robins the match onto, so no per-shard ALT
churn is needed.

#### Per-batch ALTs on top of the static one

The settle adds a 1-byte `match_index` + 4 × 32-byte Merkle
siblings = 129 bytes to ix.data. That pushed `tee_forced_settle_batched`
over the 1232-byte cap even with the static settle ALT. Fix: stack a
second ALT, created once per batch, holding the **7 PDAs** that vary
per match but are derivable from the payload alone:

| Account | Why it's in the per-batch ALT |
|---|---|
| `note_lock_a` | derived from `payload.note_a_commitment` |
| `note_lock_b` | derived from `payload.note_b_commitment` |
| `note_lock_e` | derived from `payload.note_e_commitment` (or zero) |
| `note_lock_f` | derived from `payload.note_f_commitment` (or zero) |
| `consumed_note_a` | derived from `payload.note_a_commitment` (consume-once guard) |
| `consumed_note_b` | derived from `payload.note_b_commitment` |
| `batch_validity_marker` | derived from the batch's `merkle_root` |

(The two `nullifier_{a,b}` PDAs were dropped from both the settle tx and
this ALT — see §9's account-table note.) Folding the consumed-note PDAs
into the ALT (they were inline before) is what keeps the
**continuation/change-note** settle — where `note_lock_e/f` are non-zero
so the exact-fill dedup disappears and the tx grows — under the cap. The
settle tx lands comfortably under 1232 for both exact-fill and
change-note paths. Payload v9 also removes the two dead nullifier values,
pinning the worst-case regression fixture at 1109 bytes (123 bytes headroom).

Because the per-batch ALT now carries 7 addresses per match (and a
batch packs up to N=16 matches → well past the ~30-address ceiling a
single `extendLookupTable` tx can hold), the extend is **chunked**:
`MAX_EXTEND_ADDRESSES = 25` addresses per extend tx (`settle/alt.rs::
build_extend_alt_ix_chunks`), and the chunks are fired **concurrently**
so the leader co-includes them in one block instead of paying one
confirmation per chunk. The worker then **re-reads the ALT's canonical
on-chain address order** (`parse_alt_addresses`, the account data at
byte offset 56 in 32-byte strides) before building any settle tx —
concurrent extends can land in a different order than they were issued,
and a v0 tx's account indices must match the ALT's real layout, not the
order the worker intended. If the re-read returns empty (the entries
haven't rooted yet) it falls back to the in-memory order.

`createLookupTable` requires the `recentSlot` arg to be a slot present
in the `SlotHashes` sysvar. Fetching via `getSlot("confirmed")`
occasionally picks a slot the leader skipped → `InvalidInstructionData`
("…is not a recent slot"). Use `getLatestBlockhashAndContext().context.slot`
instead — that slot is the one the blockhash was sampled at and is
therefore guaranteed to be in `SlotHashes`.

The per-batch ALT + `close_batch_validity_marker` are amortised across
all N matches in the batch (one ALT, one close per batch — not per
match). For N = 16 matches this turns 80+ per-match alt/close ops into
1 ALT-create + a few chunked extends + 16 settles + 1 close per batch.
ALT deactivation has a 512-slot (~3.5 minute) cooldown, so the settle
worker keeps a **rolling pool** of per-batch ALTs (`settle/alt_pool.rs`,
driven by `settle/worker.rs`) and recycles them once deactivation
clears, rather than creating-and-burning one per batch.

> **ALT activation finality.** Freshly-extended ALT entries only become
> *loadable* by a v0 tx ~1 slot after the extend roots. This one-slot
> wait — not darkpool compute — is the residual `settle_ms` tail you see
> in the CVM timings. Concurrent chunked extends collapse the *extend*
> cost into one block, but the activation wait is block-finality-bound
> and goes away under Alpenglow's sub-second finality, not via any
> code change here.

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
| change + relock (the largest v9 variant) | **1243 ❌** | **1109 ✅** (123 B headroom) |

All five change-note tests now pass.

### The canonical payload hash

The TEE's Ed25519 signature is over a 32-byte SHA-256 hash, not the
488-byte payload directly. The current construction is v9: v8 added the
128-byte fill-recovery ciphertext, and v9 removes the two unused nullifiers.

```rust
canonical_payload_hash(p) = SHA256(
    b"darknyx-match-v10",
    p.match_id,
    p.note_a_commitment, p.note_b_commitment,
    p.note_c_commitment, p.note_d_commitment,
    p.note_e_commitment, p.note_f_commitment,
    p.note_fee_base_commitment, p.note_fee_quote_commitment,
    p.order_id_a, p.order_id_b,
    p.buyer_relock_order_id,  p.buyer_relock_expiry.to_le_bytes(),
    p.seller_relock_order_id, p.seller_relock_expiry.to_le_bytes(),
    p.batch_slot.to_le_bytes(), p.fill_recovery,
)
```

The amounts (base/quote/buyer_change/seller_change/buyer_fee/seller_fee/
clearing_price) are GONE from the signed message — they're proven in-circuit
and bound by the note commitments, so the TEE no longer signs over them.

Reference: `programs/vault/src/instructions/tee_forced_settle.rs::canonical_payload_hash`,
mirror in `packages/sdk/src/settlement/settle-builder.ts::canonicalPayloadHash`.
Cross-environment parity is locked down by a fixed-vector test in both:

- Rust: `canonical_payload_hash_fixed_vector` expects
  `0x63A10A...CFA2` for a specific input.
- TS: `[hash_cross_env_parity]` in `settle-builder-batched.test.ts` asserts the same
  bytes from the TS implementation.

If you ever change the payload shape, both sides must update in lock-step
or settlements will start failing across the board.

#### Why the v6 payload mints got reverted

> **Historical** — the `v5`/`v6` tags below are from this earlier mints-revert
> episode. The tag has since advanced through v7 (amount privacy), v8
> (fill recovery), **v9** (dead-nullifier removal), and **v10** (the Darknyx
> namespace cutover). The CURRENT
> canonical hash is in *The canonical payload hash* above.

The first cut of v3 added `quote_mint` and `base_mint` as fields in
`MatchResultPayload` and into the canonical hash (under settlement-domain v6
tag). The settle tx was then 1242/1232 — over the cap — because two
Pubkeys (64 bytes) had been added to the wire payload.

But the mints in the payload were **structurally redundant**:
`lock_a.token_mint` is already bound to the input note's mint via
VALID_INPUT, and the settle handler already reads it for the per-mint
conservation work. Adding the mint to the payload (and to the canonical
hash) was just duplicating information the chain could derive.

So the revert: `MatchResultPayload` shape goes back to v5, tag stays
settlement domain v5. Mints flow purely through the NoteLock PDAs. The
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
| `crates/darkpool-crypto/src/{poseidon,note,nullifier,deposit,user_commitment,field,keys}.rs` | Poseidon round-trips, v2 note commitment + nullifier determinism/sensitivity, recoverable deposit-inner derivation, user commitment, `fr_from_be_bytes` strictness, the key-derivation chain |
| `crates/darkpool-matcher/` | the matching algorithm (`run_batch`/`run_batch_capped`), `order_canonical` (order/cancel signing), `change_note::derive_inner` KAT |

### Rust integration tests (litesvm — `programs/vault/tests/`)

| File | What it covers |
|---|---|
| `zk_roundtrip.rs` | VALID_WALLET_CREATE end-to-end (off-chain prove → on-chain verify) |
| `zk_spend_roundtrip.rs` | VALID_SPEND (v2 inner_hash) end-to-end + Poseidon parity vs circomlib |
| `deposit_with_proof.rs` | VALID_DEPOSIT real proof + SPL/Merkle atomicity, wire-size and CU gates |
| `user_commitment_registration.rs` | `create_wallet` flow with proof verification |
| `set_protocol_config.rs` / `set_tee_pubkey.rs` | admin-gated config + TEE-signer rotation (the whole K-key `tee_pubkeys` set in one ix) |
| `initialize_governance.rs` / `market_config.rs` | split-authority bootstrap, exact K-key invariant, and mint/decimal/scale/bounds governance |
| `merkle_host.rs` | pure-Rust Merkle invariants (poseidon2, zero-subtree, append) |
| `tee_forced_settle_batched.rs` | 1:N `BatchValidityMarker` lifecycle (two matches share one marker; the close-after-every-match regression) |
| `match_batch_verify.rs` | real N=16 proof → on-chain `verify_match_batch` acceptance (committed fixture) |

(The last two + the `settle_harness/` were migrated from the deleted
`matching_engine` crate.)

### `darknyx-tee` tests (`cargo test -p darknyx-tee`)

~180 lib + integration tests: the matcher tick + partial-fill continuation,
the settle pipeline + ALT pool, the Merkle mirror, the
HTTP/auth surface (`orders_surface.rs`: intake sig/opening/session/nonce/X25519
validation), the RPC client, and `n16_assemble_prove_verify.rs` (the
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
| `deposit-inner-parity.test.ts` | `Poseidon3(27, owner, recovery_nonce)` Rust/TS byte equality |
| `order-canonical-parity.test.ts` | the order/cancel canonical digests + signed viewing/session fields + wrong-width guards |

### SDK ZK prover tests

| File | Pins |
|---|---|
| `helpers/snarkjs-prover.test.ts` | VALID_WALLET_CREATE roundtrip via snarkjs-cli |
| `valid-deposit-prover.test.ts` | VALID_DEPOSIT public-input order + altered mint/amount/commitment/nonce/key/blinding rejection |
| `valid-input-prover.test.ts` | VALID_INPUT (exact + misroute-rejection + public-input ordering) |
| `match-batch-prototype.test.ts` | VALID_MATCH_BATCH at N=2/4/16 (mixed-shape) + leaf-byte parity with on-chain `compute_match_leaf` |

### SDK unit tests (offline / RPC-free)

| File | Pins |
|---|---|
| `settle-builder-batched.test.ts` | `buildSettleBatchedIx` account layout + ix.data + Merkle-siblings + `BatchValidityMarker` PDA + `match_index` bounds + `buildCloseBatchValidityMarkerIx` |
| `build-order-parity.test.ts` | signed order assembly, viewing-key/session binding, and Rust canonical parity |
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

Plus the **loadgen** (`crates/darknyx-tee-loadgen`, a host binary) for intake
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

1. **Real Phase-2 ceremony** — every shipped Groth16 circuit uses a
   deterministic dev contribution
   (`echo "darknyx-phase1-dev-contribution-$name" | snarkjs zkey contribute`),
   plus the batched zkey runs `zkey beacon 0102…1f20 10`. The toxic waste
   is *recoverable from the build script* — fine for devnet, a hard
   mainnet blocker. Need a real MPC with ≥ 3 independent contributors and
   publicly verifiable transcripts. The PTAU files are SHA-256-pinned in
   `scripts/download-ptau.sh` (closes the supply-chain hole at download
   time, but not the need for a project-specific phase-2 MPC). NOTE: amount
   privacy raised the stakes here — `VALID_MATCH_BATCH` is now the SOLE
   conservation guarantor (the on-chain amount checks were removed), so a
   forged proof from recovered toxic waste could mint value with no on-chain
   backstop. Soundness, not privacy: a leaked trapdoor breaks no-inflation,
   not zero-knowledge.

2. **Attested TEE-pubkey rotation** — `set_tee_pubkey` rotates
   `VaultConfig.tee_pubkeys` (the K shard signer keys) to the CVM's
   dstack-derived keys, and clients
   verify the enclave's TDX quote client-side before sending orders. The
   remaining gap is binding the *on-chain* rotation to a verified quote +
   a governance-approved measurement set (a multisig accepting the quote),
   so the chain itself enforces "only an attested enclave can be the
   signer." See `docs/tee-attestation-flow.md`.

3. **Real protocol-owner keypair** — fee notes mint to the protocol's
   `owner_commitment`; withdrawing them needs a real owner keypair wired up
   (the operator re-derives the fee notes via `derive_inner(slot, FEE_ROLE_*)`).

4. **Production browser proving performance** — the demo Web Worker supports
   VALID_WALLET_CREATE, VALID_DEPOSIT, and VALID_SPEND, while the SDK exposes
   Node/snarkjs adapters. VALID_INPUT still needs a production-optimized browser
   backend (or delegated attested proving) to eliminate its current UX latency.

### Recently shipped (formerly in this list)

- **Fills delivery + trade history — DONE (P4/P7).** The `fills` subscription on
  `/v1/stream` is **per-account routed** (each order's `FillMemo` goes only to
  its owner's authenticated session), with deterministic HD `order_id`s
  (`deriveOrderId`) and an optional off-TEE commitment-locator indexer
  (`packages/indexer`). Durable recovery v3 comes from the settlement's on-chain
  encrypted `(trade, change)` tuples plus confirmed deposit/merge/settlement
  instructions and events; `recoverNotesFromChain` rebuilds every user note
  class from seed + chain. The live memo is the low-latency path. See
  [`docs/fills-history-architecture.md`](docs/fills-history-architecture.md).

- **Self-trade prevention — DONE (owner-level, note-bound).** The matcher
  (`darkpool_matcher::algorithm::generate_matches`) never crosses two orders from
  the same owner, keyed on the note-**bound** `owner_commitment`
  (`Poseidon3(DOMAIN_OWNER=1, spending_key, r_owner)`, pinned to the collateral note at intake by
  `verify_commitment`, reused across all of a user's notes). So it catches one
  user trading under *two trading keys* (a free `offset` rotation, deliberately
  NOT part of the owner identity), and — because `owner_commitment` is bound, not
  client-asserted — a *settling* wash cannot lie about its owner. `trading_key`
  equality is kept as a cheap belt-and-suspenders. **Caveat:** still best-effort,
  not a hard guarantee — a user can register a SECOND wallet (a distinct
  `owner_commitment`, or notes under a different `r_owner`) and wash across the
  two; that Sybil case is out of scope for any matcher rule.

---

## Appendix A — File map

```
darknyx-monorepo/
├── circuits/
│   ├── valid_wallet_create/circuit.circom    1 public input
│   ├── valid_deposit/circuit.circom          5 public inputs (owner + inner private)
│   ├── valid_spend/circuit.circom            5 public inputs (v2 inner_hash)
│   ├── valid_input/circuit.circom            5 public inputs (v2 inner_hash)
│   └── match_batch_n16/  (+ n2, n4 dev)      VALID_MATCH_BATCH, 8 public inputs
│                                              (root, fee, owner, mint halves, scale)
│
├── crates/
│   ├── darkpool-crypto/                       single source of truth (host crypto)
│   │   ├── src/poseidon.rs                    light-poseidon BN254 wrapper
│   │   ├── src/note.rs                        commitment_from_fields_v2 (Poseidon6)
│   │   ├── src/nullifier.rs                   Poseidon3(DOMAIN_NULL, sk, inner_hash)
│   │   ├── src/keys.rs                        HKDF-SHA256 + DarknyxShakeKdfV1 + deriveBlindingFactor
│   │   ├── src/user_commitment.rs  src/field.rs  examples/*
│   ├── darkpool-matcher/                       run_batch(_capped) + order_canonical + change_note
│   ├── darknyx-tee/                                the in-CVM engine (api/matcher/settle/prover/merkle/…)
│   └── darknyx-tee-loadgen/                        host load-tester
│
├── programs/vault/                            the ONLY on-chain program
│   ├── src/state.rs                           VaultConfig (global), MerkleTree (per-shard),
│   │                                           WalletEntry, NullifierEntry, ConsumedNoteEntry,
│   │                                           NoteLock, OutstandingMint, BatchValidityMarker
│   ├── src/merkle.rs                          incremental tree, depth 20
│   ├── src/zk/{verifier,vk_valid_wallet_create,vk_valid_spend,vk_valid_input,vk_valid_merge_k2,vk_valid_merge_k4,vk_match_batch_n16}.rs
│   ├── src/instructions/                       initialize, initialize_tree, create_wallet, deposit,
│   │                                           lock_note, release_lock, verify_match_batch,
│   │                                           tee_forced_settle(_batched), close_batch_validity_marker,
│   │                                           merge, withdraw, set_protocol_config, set_tee_pubkey,
│   │                                           rotate_root_key, reset_merkle_tree, close_vault_config
│   └── tests/                                  settle_harness/ + the litesvm suite (§12)
│
├── packages/sdk/
│   ├── src/idl/{vault-client,seeds}.ts        hand-rolled ix builders + PDA seeds
│   ├── src/keys/*.ts  src/utxo/{note,deposit,withdraw,note-store}.ts
│   ├── src/orders/{canonical,build-order,fill-memo}.ts
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
cargo build-sbf --manifest-path programs/vault/Cargo.toml --features devnet-admin  # F-01/F-02: OFF by default for mainnet
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
RUN_CVM_E2E=1 DARKNYX_TEE_GATEWAY="$GW" SOLANA_RPC_URL="$HELIUS" \
  FUNDER_KEYPAIR=~/.config/solana/id.json ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/cvm-settle-e2e.test.ts )
```

CI: `pr-checks.yml` runs the everything-green gate (Rust workspace + clippy +
the 4 circuits + the SDK suite + the vault litesvm tests incl. the migrated
settle regression). `nightly-devnet.yml` fires on cron + the `/test-devnet` PR
comment for the full devnet E2E.

---

*Last updated: 2026-07-16 — current TEE architecture: `vault` (the only
on-chain program) + the in-CVM matcher/settler (`crates/darknyx-tee`), validated
end-to-end on devnet through a Phala CVM. v2 `inner_hash` note model with
consumed-input-derived outputs and canonical order v2. The `matching_engine` / MagicBlock-ER /
PER path and the standalone `VALID_CREATE` / `VALID_PRICE` circuits have been
removed.*
