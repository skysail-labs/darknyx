# P0 — Settlement Amount Privacy: circuit soundness audit (the gate)

> **⚠️ SUPERSEDED — the P1 changes this audit gated have all SHIPPED.** Historical
> analysis doc, accurate as of 2026-06-20. The circuit now range-checks all six
> previously-unbound terms (`buyer/seller_change_amt`, `buyer/seller_fee_amt`,
> `a_amount`, `b_amount`), binds the two protocol fee notes in-circuit (closing the §7
> over-mint gap), uses a commitment-only `Poseidon11` leaf with an activation bit,
> derives output/fee inners in-circuit, and exposes 8 public inputs
> `[root, fee_rate, protocol_owner, base_lo, base_hi, quote_lo, quote_hi, price_scale]`.
> "P1a in progress" / future
> tense below is lineage only — see `match_batch.circom` + `CRYPTOGRAPHY.md` for the
> as-built state. (The external circuit audit remains the one open pre-mainnet item.)
>
> **Status:** ANALYSIS ONLY — no code changed. This is the gating deliverable of the
> settlement-amount-privacy project (`docs/settlement-amount-privacy.md`, phase P0).
> **Date:** 2026-06-20. **Branch:** `settlement_amount_privacy`.
>
> **Purpose.** Removing the on-chain plaintext amounts means deleting the on-chain `u64` +
> `checked_add` conservation backstop in `tee_forced_settle_batched`. After that, the
> **`VALID_MATCH_BATCH` circuit becomes the *sole* guarantor of value conservation (no inflation).**
> This doc proves exactly which in-circuit range checks make that safe, so P1 adds the right ones and
> not by guesswork. **It must be reviewed before any circuit/VK/payload change.**

---

## 1. Threat model

A malicious prover (equivalently, a compromised TEE that can run the prover) wants to **mint value
from nothing**: produce a batch whose output notes are collectively worth more than the input notes
it consumes, for some mint. The proof verifies on-chain (`verify_match_batch`), so whatever the
circuit *fails to constrain* is what an attacker is free to choose.

All arithmetic in the circuit is over the BN254 scalar field `Fr` (`p ≈ 2.0e76`, `⌊log2 p⌋ = 253`).
Every "amount" is a field element the prover supplies as a witness; nothing is a `u64` unless the
circuit *forces* it into `[0, 2^64)` via `Num2Bits(64)`.

---

## 2. Per-mint value conservation = exactly what the circuit proves

Map every note in a slot to its mint and direction (`circuits/templates/match_batch.circom`,
`MatchSlot()` openings `hashA..hashF`):

| Note | Mint | Dir | Amount signal | Owner |
|---|---|---|---|---|
| A (`note_a_commitment`) | quote | **input** (consumed) | `a_amount` | buyer |
| B (`note_b_commitment`) | base | **input** (consumed) | `b_amount` | seller |
| C (`note_c_commitment`) | base | output (buyer receives) | `base_amount` | buyer |
| D (`note_d_commitment`) | quote | output (seller receives) | `quote_amount` | seller |
| E (`note_e_commitment`) | quote | output (buyer change) | `buyer_change_amt` | buyer |
| F (`note_f_commitment`) | base | output (seller change) | `seller_change_amt` | seller |
| fee-quote (`note_fee_quote`) | quote | output (protocol) | `buyer_fee_amt` | protocol |
| fee-base (`note_fee_base`) | base | output (protocol) | `seller_fee_amt` | protocol |

No-inflation, per mint, requires:

```
quote:  a_amount  == quote_amount + buyer_change_amt  + buyer_fee_amt      (Q)
base:   b_amount  == base_amount  + seller_change_amt + seller_fee_amt     (B)
```

These are **already constrained in-circuit** at `match_batch.circom:144-145`:
```
a_amount === quote_amount + buyer_change_amt  + buyer_fee_amt;
b_amount === base_amount  + seller_change_amt + seller_fee_amt;
```
So the circuit already states the right equations. The danger is purely that they hold over **`Fr`**,
not over the integers — i.e. **field wraparound**.

---

## 3. The wraparound gap (why `Fr`-equality ≠ `u64`-equality without range checks)

Take the quote leg (Q): `a_amount ≡ quote_amount + buyer_change_amt + buyer_fee_amt (mod p)`.

Today this is also enforced on-chain in `u64` with `checked_add` (so the sum can't even reach
`2^64`). Remove that, and (Q) is only a congruence mod `p`. If `buyer_change_amt` / `buyer_fee_amt`
are unconstrained field elements, a prover can pick, e.g.:

```
a_amount        = 10            (a tiny, legit-looking input note)
quote_amount    = 10
buyer_change_amt = X            (a huge field element)
buyer_fee_amt    = p − X        (so the three sum ≡ 10 + X + (p−X) ≡ 10 (mod p))
```

(Q) holds in `Fr`, but the *intended* integer change note E now carries `X` quote — value minted
from nothing. The note-E opening `note_e_commitment = Poseidon6(2, qm_lo, qm_hi, buyer_change_amt,
…)` happily commits to the huge `X`; nothing stops it. **This is the inflation bug we must close.**

### 3.1 Current range-check coverage (`match_batch.circom:198-205`)
```
priceBits = Num2Bits(64);  priceBits.in <== clearing_price;   // ✓
baseBits  = Num2Bits(64);  baseBits.in  <== base_amount;      // ✓
quoteBits = Num2Bits(64);  quoteBits.in <== quote_amount;     // ✓
quote_amount === base_amount * clearing_price;
```
Range-bound today: **`clearing_price`, `base_amount`, `quote_amount`** (the trade *outputs* C and D,
and the price). **Not** range-bound: `buyer_change_amt`, `seller_change_amt`, `buyer_fee_amt`,
`seller_fee_amt`, `a_amount`, `b_amount`.

---

## 4. The fix and why it is sufficient

**Claim.** If, in addition to `quote_amount`/`base_amount` (already done), we range-check
`a_amount`, `buyer_change_amt`, `buyer_fee_amt` to `[0, 2^64)`, then (Q) over `Fr` ⟹ (Q) over the
integers with no overflow. (Symmetrically for (B) with `b_amount`, `seller_change_amt`,
`seller_fee_amt`.)

**Proof.** With all four of `a_amount, quote_amount, buyer_change_amt, buyer_fee_amt` in `[0, 2^64)`:
- RHS as integers: `quote_amount + buyer_change_amt + buyer_fee_amt < 3·2^64 < 2^66 ≪ p`. So the RHS
  does **not** wrap mod `p` — its residue equals its integer value.
- LHS: `a_amount < 2^64 < p` — its residue equals its integer value.
- (Q) says the two residues are equal, hence the **integer** values are equal:
  `a_amount = quote_amount + buyer_change_amt + buyer_fee_amt` exactly.
- Since `a_amount < 2^64`, the integer sum is `< 2^64` — no `u64` overflow either. ∎

This is *exactly* the guarantee the on-chain `checked_add` gave, now discharged in-circuit. The
`base_amount * clearing_price` product (L205) is a separate price-validity check and is unaffected
(both factors are 64-bit; the product is verified as a field equation against `quote_amount`, which
is itself range-bound).

---

## 5. The exact `Num2Bits(64)` list for P1

Two tiers:

### 5.1 LOAD-BEARING — fresh outputs created by this circuit (MUST add)
`buyer_change_amt`, `seller_change_amt`, `buyer_fee_amt`, `seller_fee_amt`.

These are **new values minted by this match**. They are bound only by (Q)/(B) and by their output-note
Poseidon openings (E/F and — see §7 — the fee notes). Nothing upstream has ever range-checked them.
Per §3.1 they are *unconstrained*; per §4 they are the signals whose range checks close the gap. **If
P1 adds nothing else, it must add these four.**

### 5.2 INSURANCE — input amounts (SHOULD add; cheap)
`a_amount`, `b_amount`.

These are **transitively** range-bound: each is the Poseidon preimage amount of `note_a/b_commitment`
(`hashA`/`hashB`), and that commitment was produced by a prior deposit (`valid_input`) or settle that
*did* range-check the amount. Poseidon collision-resistance means the only `a_amount` satisfying the
fixed input commitment is the real `u64` value. So they are effectively `u64` already — **but the
circuit doesn't assert it**, and the §4 proof is cleanest when *all* terms of (Q)/(B) are explicitly
bound. At ~64 constraints each (negligible vs the ~163k-constraint N=16 circuit) there is no reason
not to; it removes the dependency on "every upstream creation path range-checks," which is exactly the
kind of implicit invariant an audit dislikes.

**Recommendation: add all six.** (4 load-bearing + 2 insurance) × 16 slots.

### 5.3 Signals that do NOT need a range check
- `clearing_price`, `base_amount`, `quote_amount` — already range-checked (L198-203).
- `batch_slot` — a slot number, not a conserved amount; it enters only the leaf (and marker expiry,
  which is independently bounded on-chain in `verify_match_batch`). No conservation role.
- Commitments, owner commitments, inner hashes, mint halves (`qm_lo/hi`, `bm_lo/hi`) — not amounts;
  the mint halves are 128-bit pubkey splits, `< Fr` by construction (`pubkey_to_fr_pair`).

---

## 6. Where the input-amount binding moves (NoteLock.amount removal)

Today the input-leg conservation reads `lock_a.amount` / `lock_b.amount` — a plaintext `u64` copied
into the `NoteLock` PDA at `lock_note` time. P3 drops `NoteLock.amount`. The binding moves cleanly:
- The circuit binds `a_amount` to `note_a_commitment` (the `hashA` opening) and proves (Q) over it.
- The settle handler binds `note_a_commitment` to the lock (the lock PDA is seeded by the commitment).
- `lock_note` already verified, via the `VALID_INPUT` Groth16 proof, that the locked commitment opens
  to a range-checked `u64` amount.

So "input amount is a `u64` and feeds conservation" is preserved end-to-end **without** storing the
plaintext on the lock. (Adding the §5.2 `a_amount`/`b_amount` range check makes this self-contained
within `VALID_MATCH_BATCH` rather than relying on `lock_note`'s upstream check.)

---

## 7. Caveat carried forward (NOT introduced by this change): fee-note amount binding

The two **protocol fee notes** (`note_fee_quote`, `note_fee_base`) are **not** inputs to
`MatchSlot()` — they are payload-only commitments the on-chain handler appends as leaves. The circuit
constrains `buyer_fee_amt` / `seller_fee_amt` via conservation (Q)/(B) and (P1) the fee floor, but it
does **not** prove that the *minted fee note's* amount equals `buyer_fee_amt` / `seller_fee_amt`.

- This is a **pre-existing** property, identical before and after amount privacy: the on-chain
  conservation we remove never bound the fee-note amount either (it appends the commitment without
  recomputing it). So this change does not regress it.
- **Sub-analysis (the real inflation vector):** note D (seller's quote) + note E (buyer change) + the
  quote fee note all come out of `a_amount` (the only quote input). The circuit forces
  `a_amount = quote_amount + buyer_change_amt + buyer_fee_amt`. The on-chain handler appends
  `note_fee_quote` whose amount is *not* checked against `buyer_fee_amt`. If the TEE mints
  `note_fee_quote` with amount `> Σ buyer_fee_amt`, total quote output `> Σ a_amount` ⟹ inflation that
  neither the circuit nor the old on-chain `u64` conservation catches (both only ever look at the
  *signal* `buyer_fee_amt`, never the minted note). The excess note is owned by `protocol_owner` and
  withdrawable for real SPL → vault drained. **Real, pre-existing gap.**

**Decision (taken with the user 2026-06-20): CLOSE IT IN P1.** Bind the fee notes in-circuit.

**Design (confirmed against the fee-flush mechanics):** the fee notes are **batch-aggregated, not
per-match** — `flush_fee_notes` (`darkpool-matcher/src/algorithm.rs:590`) commits
`Poseidon6(mint, Σ accumulated_fees, protocol_owner, derive_inner(batch_slot, FEE_ROLE))`, and
`assemble.rs:430` attaches both fee notes to **`matches.first_mut()` → slot 0 deterministically**
(all other slots carry `[0;32]`). So the binding is NOT a per-slot opening; it is:
1. At the batch level, `total_buyer_fee := Σ_i buyer_fee_amt[i]`, `total_seller_fee := Σ_i seller_fee_amt[i]`
   (linear combinations — ~free in constraints).
2. On **slot 0**, with the same `IsZero` conditional note E uses (zero fee ⇒ `[0;32]` note):
   `note_fee_quote_commitment[0] === (1−isZero(total_buyer_fee))·Poseidon6(2, qm_lo, qm_hi, total_buyer_fee, protocol_owner, fee_quote_inner)`
   and the base analogue with `total_seller_fee`/`bm_*`/`fee_base_inner`.
3. On slots 1..N−1, force `note_fee_*_commitment[i] === 0` (non-flush slots mint no fee note).
4. Make **`protocol_owner_commitment` a public input** too (bound on-chain to
   `VaultConfig.protocol_owner_commitment`), so the binding also closes a *second* leak — a TEE
   minting the fee note to its OWN owner instead of the protocol's (fee-theft, distinct from
   over-mint). `fee_quote_inner`/`fee_base_inner` stay private witnesses.
5. Include both fee commitments in the **new commitment-only leaf** (so the on-chain recompute +
   marker bind them): `leaf = Poseidon10(DOMAIN_LEAF_V2=23, note_a..note_f, note_fee_base, note_fee_quote, batch_slot)`.
   The on-chain handler's blind `append_leaf` of the fee notes (`tee_forced_settle_batched.rs:542-553`)
   then becomes proof-backed (the fee notes are part of slot 0's verified leaf).

Cost: 2 extra Poseidon6 on slot 0 only (~600 constraints for the whole batch) + a third public input.
Constraint-cheap; the work is the leaf-format + lockstep change, done once with the commitment-only
leaf anyway.

---

## 8. Fee-floor formula correction (for P1)

The design doc proposed proving `buyer_fee_amt·10000 ≥ quote_amount·rate`. **That is too strict** and
would reject legitimate fees: the matcher *floors* (`fee = ⌊notional·rate/10000⌋`), so
`fee·10000 ≤ quote·rate`, often strictly. The on-chain floor we remove is `fee ≥ ⌊quote·rate/10000⌋`
(integer division). Its exact division-free equivalent:

> `fee ≥ ⌊x/10000⌋  ⟺  (fee+1)·10000 > x`, where `x = quote_amount·rate`.
>
> *Proof.* Let `q = ⌊x/10000⌋`, so `q·10000 ≤ x < (q+1)·10000`.
> (⟸) `(fee+1)·10000 > x ≥ q·10000 ⟹ fee+1 > q ⟹ fee ≥ q`.
> (⟹) `fee ≥ q ⟹ (fee+1)·10000 ≥ (q+1)·10000 > x`. ∎

So P1 constrains, with `fee_rate_bps` a **public input** (bound on-chain to `VaultConfig.fee_rate_bps`):
```
(buyer_fee_amt  + 1) · 10000  >  quote_amount · fee_rate_bps
(seller_fee_amt + 1) · 10000  >  base_amount  · fee_rate_bps
```
via circomlib `GreaterThan(n)` with `n ≈ 80` (operands `< 2^64 · 2^14 = 2^78`). Gate the constraint
on `fee_rate_bps > 0` (mirror the on-chain `if rate > 0`) so the default rate-0 path is a no-op and
existing fee-free tests stay valid. (Note: with §7's fee-note binding, the floor + the binding
together fully pin both the charged fee and the minted note.)

---

## 9. Output / hand-off to P1

P1 must, in one lockstep circuit change:
1. Add `Num2Bits(64)` for **`buyer_change_amt, seller_change_amt, buyer_fee_amt, seller_fee_amt`**
   (load-bearing) and **`a_amount, b_amount`** (insurance). §5.
2. Add the in-circuit **fee floor** with `fee_rate_bps` as a public input, using the
   `(fee+1)·10000 > notional·rate` form. §8.
3. **Bind the two fee notes in-circuit** (§7, decided): batch-summed fee binding on slot 0 +
   `protocol_owner_commitment` as a public input + fee commitments in the new leaf.
4. Commitment-only leaf `Poseidon10(23, note_a..f, note_fee_base, note_fee_quote, batch_slot)` +
   public inputs `[merkle_root, fee_rate_bps, protocol_owner_commitment]` are P1's other changes (not
   soundness-gating on their own; the fee-note binding rides on them).

**Sequencing within P1 (to keep each step reviewable):**
- **P1a — range checks ONLY** (this §5 list). Constraint-additive: the leaf, the single
  `[merkle_root]` public input, the payload, and all 4 ports are UNCHANGED — only the VK + the
  committed N=16 fixture regenerate. This is the self-contained inflation-gap fix and lands first.
- **P1b — the leaf rewrite + fee floor + fee-note binding** (commitment-only `Poseidon10` leaf,
  in-circuit fee floor with the `(fee+1)·10000 > notional·rate` form, fee-note binding, and the
  `[merkle_root, fee_rate_bps, protocol_owner_commitment]` 3-input public). This is the lockstep
  change that ripples into P2 (4 ports), P3 (vault verify + leaf + payload), P4 (indexer).

**P0 changed no executable code.** Reviewed + approved; P1a in progress.
