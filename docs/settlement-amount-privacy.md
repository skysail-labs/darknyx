# Settlement Amount Privacy — Design Doc

> **⚠️ SUPERSEDED — IMPLEMENTED (P0→P7 shipped + devnet/CVM-validated).** This is a
> historical design doc; the "Status: PROPOSED / today / future-tense plan" text below
> describes the *before* state and was accurate as of 2026-06-20. The work has since
> landed: the leaf is a single commitment-only `Poseidon10(DOMAIN_LEAF_V2=23, …)`, the
> 7 plaintext amounts are gone from `MatchResultPayload` (canonical tag now
> `nyx-match-v9` after the later dead-nullifier removal), the 6 `Num2Bits(64)` range checks + in-circuit fee floor + fee-note
> binding are in the circuit, and `verify_match_batch` takes 3 public inputs
> `[merkle_root, fee_rate_bps, protocol_owner_commitment]`. For current behavior see
> `CRYPTOGRAPHY.md` + the circuit/handler code; read the plan below as lineage only.
>
> **Status:** PROPOSED (design + phased plan). No code changed yet.
> **Author/date:** 2026-06-20.
> **Goal:** stop revealing trade **amounts** and the **execution price** on-chain at
> `tee_forced_settle_batched`, matching the privacy bar of dark-pool peers (Renegade,
> GoDarkDEX) which hide *amount + price*, not just identity — **using our existing ZK
> moat, not MPC.**

---

## 0. TL;DR

Today we hide *who* trades (owner commitments + nullifiers are unlinkable) but **reveal the
trade size and execution price in plaintext** in the settle instruction. That plaintext is
**redundant**: the `VALID_MATCH_BATCH` circuit already proves value conservation + price
validity over *private* amounts, and the note commitments already bind the amounts. We keep the
plaintext only as (a) a leaf-recompute convenience and (b) an on-chain defense-in-depth backstop.

The fix is to **remove the redundant plaintext** and let the proof be the sole binder:
make the match leaf **commitment-only**, **range-check every amount in-circuit** (the security
gate), move the **fee floor in-circuit**, and drop amounts/price from the settle payload + the
`NoteLock`. This is an engineering project on a proven ZK foundation — and it *shrinks* the
settle tx. MPC/Arcium buys nothing here (the TEE already sees the amounts; the chain-hiding is a
ZK problem) and is only relevant for a different, later goal (decentralizing TEE trust).

---

## 1. Context & motivation

### 1.1 What prompted this
We initially treated on-chain amount visibility as acceptable — even desirable for
**auditability/compliance**. But the competitive bar for a dark pool is to obfuscate the
**settlement amount + price**, not just identity (Renegade hides everything via collaborative
SNARKs; GoDarkDEX runs a shielded pool with hidden settlement amounts — see
`godarkdex_docs_md/…_shielded-pool.md`). Revealing execution prices/sizes leaks alpha and is a
real competitive and MEV exposure.

### 1.2 Compliance is not a reason to keep the leak
"Auditable" ≠ "publicly plaintext." Our key model already has a **`viewingKey`**, so a user (or
the protocol) can **selectively disclose** specific trades to an auditor without broadcasting them
to the whole chain. Amount privacy + viewing-key disclosure gives the compliance story *without*
the public leak.

---

## 2. What is revealed today (the precise leak)

The note model already hides amounts in the steady state — a note is
`commitment = Poseidon6(DOMAIN_NOTE, mint_lo, mint_hi, amount, owner_commitment, inner_hash)`,
and the Merkle tree stores only commitments; spends reveal only a nullifier. The leak is **at the
settle moment**, in three places:

1. **`NoteLock.amount: u64` is plaintext** — `programs/vault/src/state.rs:180`. The size of every
   note entering a trade is public on its lock PDA.
2. **`MatchResultPayload` carries plaintext `u64`s** in the settle ix data —
   `base_amount`, `quote_amount`, `clearing_price`, `buyer/seller_change_amt`,
   `buyer/seller_fee_amt` (`programs/vault/src/instructions/tee_forced_settle.rs:42-97`).
3. **The match leaf hashes those plaintext amounts** —
   `crates/nyx-tee/src/prover/leaf.rs:60-97`:
   ```
   h1   = Poseidon12(DOMAIN_LEAF_INNER, note_a..note_f, qm_lo,qm_hi,bm_lo,bm_hi, base_amount)
   leaf = Poseidon9 (DOMAIN_LEAF_TOP,  h1, quote_amount, buyer_change, seller_change,
                                            buyer_fee, seller_fee, clearing_price, batch_slot)
   ```
   Because the leaf binds the amounts, the on-chain handler must recompute it **from the plaintext
   payload** (`tee_forced_settle_batched.rs::compute_match_leaf`, ~L118-150) → the amounts must be
   in the tx in cleartext.

An on-chain observer therefore sees, per settle: the traded base/quote sizes, the execution
price, change sizes, and fees — just not *who*.

---

## 3. Why it was built this way (priority ordering, not a mistake)

- **Amount privacy was not a v1 requirement.** v1 prioritized *identity* privacy (done), getting
  settlement working, and **auditability** — which made plaintext amounts feel like a feature.
- **Simplest proof-binding.** The easy way to bind a settle to a batched proof is "hash everything
  the chain needs into the leaf, recompute it on-chain, check Merkle inclusion." Putting amounts in
  the leaf is the obvious version; a **commitment-only** leaf (relying on "commitments transitively
  bind amounts") is a non-obvious optimization you only reach for once hiding amounts is a goal.
- **Defense-in-depth.** Re-checking conservation on-chain in `u64` (`checked_add`) is a cheap
  backstop against a circuit/prover bug — sensible when correctness > privacy.
- **Lineage.** It evolved v3.1 (per-match `VALID_CREATE`/`VALID_PRICE` plaintext markers) → v3.5
  (batched `VALID_MATCH_BATCH` + leaf), carrying the plaintext forward.

---

## 4. The key insight — the plaintext is redundant

Every on-chain use of a plaintext amount is **already proven in the circuit** or **replaceable by
the commitment**:

| On-chain use (`tee_forced_settle_batched`) | Replacement |
|---|---|
| Leaf recompute (`compute_match_leaf`) | Commitment-only leaf — the 6 note commitments are also in the leaf, and each **is** a hash of its amount. |
| Conservation `lock.amount == quote+change+fee` (L414-428) | Already in-circuit: `a_amount === quote_amount + buyer_change_amt + buyer_fee_amt` (`match_batch.circom:144-145`). |
| Change-note presence `has_e == (change>0)` (L460-464) | Already in-circuit (`note_e === (1-isZero(change))·hash(change,…)`, L165-176); on-chain reads `note_e_commitment == [0;32]`. |
| Price validity | Already in-circuit: `quote_amount === base_amount · clearing_price` (L205); price is bound via the committed `note_c/note_d` outputs. |
| **Fee floor** (shipped commit `d86a3be`) | The only genuinely on-chain-only check → **move in-circuit**. |

The circuit's only public input is `merkle_root` (`verify_match_batch.rs:77`); all amounts are
private `signal input`s. **The privacy machinery is ~80% built; the leak is redundant plaintext.**

---

## 5. Design: ZK, not MPC

### 5.1 Why ZK
Our architecture is **TEE-match + ZK-settle**. The conservation proof already exists; we extend it
(range checks, in-circuit fee floor) and stop carrying the redundant plaintext. No new crypto, no
new trust domain, and the settle tx gets *smaller* (relieving the 1232-byte budget, incl. the
deferred 1956-byte continuation issue).

### 5.2 Why not MPC / Arcium
MPC hides inputs from the *computing* parties. But **the TEE already sees the amounts** (we chose
TEE matching) — secret-sharing them to Arcium hides them from no one new, while adding a second
liveness + trust domain and a settlement-state rewrite. The chain-hiding problem is a "prove a
hidden relation" problem = ZK, which we already mostly solve. (Umbra, the comparison raised, in
fact uses ZK + encryption, not MPC.) **MPC is only the right tool for a different goal —
decentralizing trust away from the single TEE for the amounts — a v2 trust-model decision, out of
scope here (see §11).**

---

## 6. The concrete changes (blast radius)

### 6.1 Circuit — `circuits/templates/match_batch.circom` (+ `match_batch_n16/circuit.circom`)
1. **Commitment-only leaf:** the leaf hashes only the 6 note commitments + the mints (drop
   `base_amount`, `quote_amount`, changes, fees, `clearing_price` from the leaf). `batch_slot` may
   stay if the marker still needs it.
2. **Range-check every amount (the soundness gate, §7):** add `Num2Bits(64)` for
   `buyer_change_amt`, `seller_change_amt`, `buyer_fee_amt`, `seller_fee_amt` (today only
   `base_amount`, `quote_amount`, `clearing_price` are checked, L198-203). Add `a_amount`/`b_amount`
   for insurance (they're boundary-checked at deposit/spend, but cheap here).
3. **Fee floor in-circuit:** prove `buyer_fee_amt·10000 ≥ quote_amount·rate` and the seller
   analogue (no division), with **`fee_rate_bps` as a new public input** so the verifier binds the
   circuit's rate to `VaultConfig.fee_rate_bps`.
4. Regenerate `.zkey` + `.wasm` + `vk_match_batch_n16.rs` for N=2/4/16; regenerate the committed
   N=16 proof fixture (`programs/vault/tests/fixtures/match_batch_n16_proof.bin`). Full §5 discipline.

### 6.2 The leaf — 4-port byte-equality lockstep (the fragile part)
Move all four to the commitment-only layout *in one commit*:
`circuit` ↔ `crates/nyx-tee/src/prover/leaf.rs::compute_batch_leaf` ↔
`packages/sdk/tests/helpers/match-batch-prover.ts::computeBatchLeaf` ↔
`programs/vault/src/instructions/tee_forced_settle_batched.rs::compute_match_leaf`.

### 6.3 Vault — `programs/vault/`
- `tee_forced_settle_batched.rs`: delete the conservation block (L400-429) and the fee-floor block
  (L443-454); commitment-only `compute_match_leaf`; derive change-presence from
  `note_*_commitment == [0;32]`.
- `verify_match_batch.rs`: public inputs `[merkle_root]` → `[merkle_root, fee_rate_bps]`.
- `state.rs`: drop `NoteLock.amount`; `lock_note.rs` binds the commitment (not a plaintext amount).
- `MatchResultPayload` (`tee_forced_settle.rs:42-97`): **drop** `base_amount`, `quote_amount`,
  `buyer/seller_change_amt`, `buyer/seller_fee_amt`, `clearing_price`. **Keep** `match_id`,
  `note_*_commitment` (incl. fee notes), `nullifier_a/b`, `order_id_a/b`, relock fields,
  `batch_slot`. → **smaller settle tx** (free win on §6's byte budget).
- `errors.rs`: `ConservationViolation` + `InsufficientFeeCharge` become unused on this path (keep or
  repurpose).

### 6.4 Canonical payload hash (the TEE-signed message)
`canonical_payload_hash` is over the payload; shrinking it changes the hash → **byte-equality
cascade** across vault (`tee_forced_settle.rs`) + TEE (`crates/nyx-tee/src/settle/payload.rs`) + SDK
(`settle-builder.ts::canonicalPayloadHash`), with a **domain-tag bump** (precedent: the prior
`nyx-match-v5 → v6`). The amounts don't need to be *signed* — the proof binds them; the signature
binds the commitments/nullifiers/order_ids.

### 6.5 TEE — `crates/nyx-tee/`
- `settle/assemble.rs`: amounts stay in the **witness** (private inputs to the proof), leave the
  **payload**. `settle/payload.rs`: smaller payload + new canonical hash. The prover's public-inputs
  vector gains `fee_rate_bps`.
- The settle worker builds the smaller ix.

### 6.6 SDK — `packages/sdk/`
- `settlement/settle-builder.ts`: `serializePayload` (drop amounts), `canonicalPayloadHash` (new
  layout/domain), `buildSettleBatchedIx` (smaller payload).
- Client memo-integrity guard (Vuln-4): the client recomputes the change-note commitment from the
  **FillMemo** (`change_amount` + `inner_hash`, delivered on `/v1/stream`'s fills channel) rather than the public
  payload — the memo is already the private channel for the user's own amounts.

### 6.7 Indexer + fills model (the biggest ripple — and it's *more* private)
`packages/indexer/src/decode.ts` currently reads `change_amount`/`clearing_price` from the payload.
After this change **the untrusted off-TEE indexer can no longer see amounts** (correct — it never
should). It indexes commitments + `order_id` for routing; **amounts move to the per-account
`FillMemo`** over the authenticated `/v1/stream` fills channel, decryptable by the user with their keys.
`fills-history-architecture.md` shifts to "indexer = commitment locator; amounts = client-
reconstructed." `FillRow.change_amount`/`clearing_price` columns go away (or become null). The
`change_amount > 0` assertion in `cvm-settle-e2e` moves to the **memo** side.

### 6.8 Loadgen — `crates/nyx-tee-loadgen/`
Minor — it submits orders; only its real-settle settle-builder mirror tracks the payload change.

---

## 7. Soundness analysis (the gating item — do not get this wrong)

The conservation `a_amount === quote_amount + buyer_change_amt + buyer_fee_amt` is over the
BN254 field. Today the **on-chain `u64` + `checked_add`** guarantees no wraparound. Removing it
means the **circuit** must guarantee it. The circuit currently range-checks `base_amount`,
`quote_amount`, `clearing_price` (L198-203) — i.e. the **trade outputs** are range-safe — but **not**
`change`/`fee`. Without range-checking those, a malicious prover could field-wrap `change`/`fee` so
Fr-conservation holds while the implied `u64` values don't.

- The worst case today is **self-harm** (an out-of-range change/fee note is unspendable because
  `VALID_SPEND` range-checks at spend time), not inflation — but **we must not rely on that.** A
  shielded pool's invariant is "no inflation," and the on-chain `u64` check is what enforces it now.
- **Requirement:** range-check **all** amount signals to 64 bits in-circuit so Fr-conservation ⇔
  `u64`-conservation. This is the explicit security milestone and the thing an **external circuit
  audit** must sign off before mainnet.

Cost: ~4-6 extra `Num2Bits(64)` per slot ≈ +300-400 constraints/slot on a ~2,100-constraint slot
(~20%), ×16 slots — absorbed by the ICICLE/GPU prover work already underway.

---

## 8. Phased implementation plan

Each phase is independently reviewable; the circuit change (P1-P2) lands as one lockstep unit per
`CLAUDE.md §5`.

- **P0 — Soundness audit (gate).** Enumerate every amount signal in `MatchSlot`; prove which are
  range-bound and which are not. Output: the exact list of `Num2Bits(64)` to add. *No behavior
  change.* (Cheapest, highest-leverage first step.)
- **P1 — Circuit.** Add the range checks (P0 list) + commitment-only leaf + in-circuit fee floor +
  `fee_rate_bps` public input. Regenerate zkey/vk/fixtures. Validate with the circuit prove→verify
  tests + `match_batch_verify`.
- **P2 — The 4-port leaf + payload/canonical-hash.** Update `leaf.rs`, `match-batch-prover.ts`,
  on-chain `compute_match_leaf`, and `MatchResultPayload` + `canonical_payload_hash` (domain bump)
  in lockstep. Re-pin all parity + fixed-vector tests.
- **P3 — Vault simplification.** Remove the on-chain conservation + fee-floor blocks; drop
  `NoteLock.amount`; `verify_match_batch` 2-input public. `build-sbf` + litesvm + deploy-devnet +
  tree reset.
- **P4 — Fills/indexer amount→memo shift.** Indexer becomes commitment-only; amounts flow via the
  `FillMemo`; SDK memo-integrity uses the memo. Update `fills-history-architecture.md`.
- **P5 — TEE + SDK + loadgen** wiring to the smaller payload; the prover's public-inputs vector.
- **P6 — CVM e2e + audit gate.** `cvm-settle-e2e` green (settle + memo-side amount assertions);
  **external circuit audit** of the conservation/range soundness before any mainnet path.

---

## 9. Testing & validation strategy

- **Circuit:** prove→verify against the zkey VK for: exact-fill, partial-fill (change notes),
  fee-bearing, and **negative** cases (under-charged fee must be unprovable; out-of-range
  change/fee must be unprovable). The negative cases replace the litesvm fee-floor +
  conservation tests we move out of the vault.
- **Lockstep parity:** leaf-byte equality across the 4 ports; `canonical_payload_hash` fixed-vector
  re-pinned in Rust + TS.
- **Vault litesvm:** the `tee_forced_settle_batched` suite (incl. `test_two_matches_share_one_marker`)
  passes with the commitment-only leaf + 2-input verify.
- **Indexer:** decode tests assert commitments + order_id only (no amounts).
- **Live (one CVM):** `cvm-settle-e2e` — settle lands, the on-chain tx carries **no** plaintext
  amounts, and the buyer's change amount arrives via the **memo** (not the indexer/payload).

## 10. Risks & open questions

1. **Range-proof soundness (P0/P7)** — the one un-skippable item; mis-scoped → inflation bug.
   *Mitigation: P0 audit + external circuit audit gate.*
2. **4-port lockstep + canonical-hash** — error-prone; *mitigation: parity tests + §5 discipline.*
3. **Loss of on-chain defense-in-depth** — the circuit becomes the sole conservation guarantor
   (standard for shielded pools, but raises the audit bar).
4. **Fills/indexer model shift** — a genuine design change (amounts → client-reconstructed from the
   memo); needs `fills-history-architecture.md` revision + buy-in.
5. **Prover cost** (~20% more constraints) — absorbed by ICICLE/GPU; confirm post-P1.
6. **Open:** does `batch_slot` need to stay in the leaf/payload for the marker, or can it drop too?
   (P2 decides.)

## 11. Out of scope / future work

- **Deposit/withdraw boundary privacy.** This change hides amounts/price **within** the pool; it
  does **not** hide deposit/withdraw amounts (the SPL transfers at the pool boundary are public —
  the anonymity set is the pool). Hiding those is a separate, harder problem (fixed denominations /
  confidential-token) and is out of scope.
- **MPC/Arcium for TEE-trust decentralization.** A different *trust-model* goal (no single enclave
  sees cleartext), not the amount-cloaking fix here. Revisit only if decentralizing the matcher.
- **Full metadata privacy (Renegade-level).** Even with amounts hidden, the trade *graph*
  (commitments/nullifiers), the *number* of output notes (partial vs full fill via change-note
  presence), and timing still leak structure. Padding/fixed-shape settlements are a later step.

---

## Appendix — key file/line references (as of 2026-06-20)

- Leak surface: `programs/vault/src/state.rs:180` (NoteLock.amount);
  `tee_forced_settle.rs:42-97` (MatchResultPayload);
  `crates/nyx-tee/src/prover/leaf.rs:60-97` (leaf hashes amounts).
- Already-in-circuit: `circuits/templates/match_batch.circom:144-145` (conservation),
  `:165-189` (change-note conditional), `:198-205` (range checks on base/quote/price + price mul).
- On-chain plaintext readers: `tee_forced_settle_batched.rs:126-150` (leaf recompute),
  `:414-428` (conservation), `:443-454` (fee floor, commit d86a3be), `:460-464` (change presence).
- Verify public input: `verify_match_batch.rs:77` (`[merkle_root]`).
- 4-port leaf lockstep + the byte-equality contracts: `CLAUDE.md §5`, §7.
