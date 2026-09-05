pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

// ============================================================================
// match_batch — parameterised batched validity templates
// ============================================================================
//
// Shared template body for the VALID_MATCH_BATCH v3 proofs. Per-N main
// files (`match_batch_n2/`, `match_batch_n4/`, `match_batch_n16/`) just
// instantiate `MatchBatch(N)` at their chosen size. The same MatchSlot
// body services every batch size — only the Merkle tree depth changes.
//
// Constraint budget (measured on the N=16 instantiation):
//   101,422 nonlinear + 132,603 linear = 234,025 constraints,
//   with 2 public inputs. Output-inner derivation,
//   per-match fee notes, activation bits, and scaled-floor pricing are
//   included in that total.
//
// Setup requirements by N:
//   - N=2  / N=4   → pot16 (`powersOfTau28_hez_final_16.ptau`,
//                    2^16 cap) is sufficient. Used by
//                    `match-batch-prototype.test.ts` only.
//   - N=16         → **pot18 required** (`powersOfTau28_hez_final_18.ptau`,
//                    ~288 MB, 2^18 cap) — total constraints
//                    (234,025) exceed the pot16 ceiling.
//                    `scripts/download-ptau.sh` fetches both files
//                    automatically; the build script picks the right
//                    one per circuit instantiation.
//
// Leaf-hash arity (single Poseidon12 — amount-privacy P1b + note unlinkability):
//   The on-chain Poseidon implementation is `light-poseidon`, which
//   caps Poseidon arity at 12 inputs (its `MAX_X5_LEN = 13` limit).
//   The leaf binds 2 consumed USE TAGS + 4 output commitments + 2 fee-note
//   commitments + active bit + batch_slot + relock digest + a domain tag
//   = 12 inputs, EXACTLY at the cap. The relock digest exists precisely to
//   stay there: binding tag_e and tag_f separately would need 13.
//   The commitments are each a
//   Poseidon6 of (mint, amount, owner, inner), so they bind the
//   amounts/mints/price transitively; the leaf no longer hashes the
//   plaintext amounts the old two-stage (Poseidon12→Poseidon9) leaf did,
//   which is what lets those amounts leave the settle payload (P3). DO NOT
//   add bound fields back past 12 inputs — that would force the two-stage
//   split again, and the on-chain `compute_match_leaf` (which mirrors this
//   verbatim) caps at 12.
//
// Why the plaintext (clearing_price, amounts) are not in the leaf:
//   They're proven in-circuit (conservation + range checks + the headline
//   `base*price = quote*scale + remainder`, `remainder < scale`) and bound
//   inside the note commitments, so the
//   leaf doesn't need them and the on-chain handler can recompute it from
//   the amount-free payload.
//
// Domain tags (must stay in sync with the TS prover helper in
// `packages/sdk/tests/helpers/match-batch-prover.ts` AND with the
// on-chain leaf walker in
// `programs/vault/src/instructions/tee_forced_settle_batched.rs`):
//   DOMAIN_NOTE       =  2   (note commitment Poseidon6 v2 — inner_hash)
//   DOMAIN_LEAF_V3    = 31   (single Poseidon(12) leaf: consumed slots carry
//                             USE TAGS, output slots carry commitments)
//   DOMAIN_MATCH_OUTPUT_INNER = 24 (output inner from consumed input inner + role)
//   DOMAIN_FEE_KEY_BINDING = 35 (public binding of the private epoch key)
//   DOMAIN_FEE_INNER_V2 = 36 (fee inner from epoch key + consumed use tag + role)
//   DOMAIN_BATCH_ROOT = 22   (Merkle internal node, Poseidon(3))
//   DOMAIN_MATCH_CONFIG_V2 = 37 (governed config digest, Poseidon(10))
//   DOMAIN_NOTE_USE   = 29   (public consume handle, Poseidon3(29, commitment,
//                             inner_hash) — see darkpool-crypto/src/note_use.rs)
//   DOMAIN_RELOCK_DIGEST = 30 (Poseidon3(30, tag_e, tag_f); folds the two
//                             relock tags into one leaf field to stay at the
//                             12-input Poseidon cap)
//   (DOMAIN_LEAF_INNER=20 / DOMAIN_LEAF_TOP=21 = the retired two-stage leaf.
//    DOMAIN_LEAF_V2=23 = the retired Poseidon(11) commitment-only leaf.)

// ----------------------------------------------------------------------------
// MatchSlot — per-slot constraints + leaf hash. Output: `leaf`.
// ----------------------------------------------------------------------------
template MatchSlot() {
    // ============================================================
    // PER-SLOT INPUTS (all private at the batch level — the leaf
    // hash commits to every field the on-chain handler will need
    // to re-derive from the settle payload).
    // ============================================================

    // ----- VALID_CREATE-equivalent public fields (16) -----
    signal input note_a_commitment;
    signal input note_b_commitment;
    signal input note_c_commitment;
    signal input note_d_commitment;
    signal input note_e_commitment;
    signal input note_f_commitment;
    // Per-match protocol fee notes (amount-privacy, P1b). Each active slot
    // derives them from that match's consumed commitments. A zero fee has a
    // canonical zero commitment. Hashed into the leaf so Tx D's atomic append
    // is proof-backed.
    signal input note_fee_base_commitment;
    signal input note_fee_quote_commitment;
    // Market identity is fanned in from the MatchBatch config-digest preimage.
    // There are no prover-selected per-slot mint signals.
    signal input quote_mint_lo;
    signal input quote_mint_hi;
    signal input base_mint_lo;
    signal input base_mint_hi;
    signal input base_amount;
    signal input quote_amount;
    signal input buyer_change_amt;
    signal input seller_change_amt;
    signal input buyer_fee_amt;
    signal input seller_fee_amt;

    // ----- VALID_PRICE-equivalent fields -----
    // clearing_price + the amounts are PRIVATE; the commitment-only leaf no
    // longer binds them (amount-privacy, P1b) — the per-slot conservation +
    // range constraints prove them, and the note commitments bind them.
    signal input clearing_price;
    // `base * price = quote * scale + remainder`, 0 <= remainder < scale.
    signal input price_remainder;
    signal input batch_slot;
    // Private activation bit, hashed into the leaf. Tx D always recomputes a
    // leaf with active=1, so canonical inactive padding can never be settled.
    signal input is_active;
    // Protocol fee rate (basis points), a MatchBatch-level digest-bound input
    // fanned to every slot. Drives the in-circuit fee floor below.
    signal input fee_rate_bps;

    // ----- VALID_CREATE private witnesses (v2: one inner_hash per note) -----
    signal input a_owner_commit;
    signal input b_owner_commit;
    signal input a_amount;
    signal input b_amount;
    signal input a_inner;
    signal input b_inner;
    signal input price_scale;
    signal input protocol_owner_commitment;
    signal input fee_epoch_key;

    // ============================================================
    // OUTPUT: leaf hash binding all per-slot fields the on-chain
    // settle handler will need to re-derive.
    // ============================================================
    signal output leaf;

    // ─────────────────────────────────────────────────────────────────
    // VALID_CREATE constraints — note openings + conservation laws +
    // conditional change-note encoding. Identical to
    // `template ValidCreate()` from circuits/valid_create/circuit.circom.
    // ─────────────────────────────────────────────────────────────────

    component hashA = Poseidon(6);
    hashA.inputs[0] <== 2;   // DOMAIN_NOTE
    hashA.inputs[1] <== quote_mint_lo;
    hashA.inputs[2] <== quote_mint_hi;
    hashA.inputs[3] <== a_amount;
    hashA.inputs[4] <== a_owner_commit;
    hashA.inputs[5] <== a_inner;
    is_active * (note_a_commitment - hashA.out) === 0;

    component hashB = Poseidon(6);
    hashB.inputs[0] <== 2;
    hashB.inputs[1] <== base_mint_lo;
    hashB.inputs[2] <== base_mint_hi;
    hashB.inputs[3] <== b_amount;
    hashB.inputs[4] <== b_owner_commit;
    hashB.inputs[5] <== b_inner;
    is_active * (note_b_commitment - hashB.out) === 0;

    is_active * (a_amount - quote_amount - buyer_change_amt - buyer_fee_amt) === 0;
    is_active * (b_amount - base_amount - seller_change_amt - seller_fee_amt) === 0;

    // User output inners are no longer free witnesses. They are derived from
    // the exact consumed input opening and a role tag:
    //   Poseidon3(DOMAIN_MATCH_OUTPUT_INNER=24, input_inner, role).
    component cInnerHash = Poseidon(3);
    cInnerHash.inputs[0] <== 24;
    cInnerHash.inputs[1] <== a_inner;
    cInnerHash.inputs[2] <== 0xC1;
    component dInnerHash = Poseidon(3);
    dInnerHash.inputs[0] <== 24;
    dInnerHash.inputs[1] <== b_inner;
    dInnerHash.inputs[2] <== 0xD1;
    component eInnerHash = Poseidon(3);
    eInnerHash.inputs[0] <== 24;
    eInnerHash.inputs[1] <== a_inner;
    eInnerHash.inputs[2] <== 0xB1;
    component fInnerHash = Poseidon(3);
    fInnerHash.inputs[0] <== 24;
    fInnerHash.inputs[1] <== b_inner;
    fInnerHash.inputs[2] <== 0x5E;

    component hashC = Poseidon(6);
    hashC.inputs[0] <== 2;
    hashC.inputs[1] <== base_mint_lo;
    hashC.inputs[2] <== base_mint_hi;
    hashC.inputs[3] <== base_amount;
    hashC.inputs[4] <== a_owner_commit;
    hashC.inputs[5] <== cInnerHash.out;
    is_active * (note_c_commitment - hashC.out) === 0;

    component hashD = Poseidon(6);
    hashD.inputs[0] <== 2;
    hashD.inputs[1] <== quote_mint_lo;
    hashD.inputs[2] <== quote_mint_hi;
    hashD.inputs[3] <== quote_amount;
    hashD.inputs[4] <== b_owner_commit;
    hashD.inputs[5] <== dInnerHash.out;
    is_active * (note_d_commitment - hashD.out) === 0;

    component buyerChangeIsZero = IsZero();
    buyerChangeIsZero.in <== buyer_change_amt;
    component hashE = Poseidon(6);
    hashE.inputs[0] <== 2;
    hashE.inputs[1] <== quote_mint_lo;
    hashE.inputs[2] <== quote_mint_hi;
    hashE.inputs[3] <== buyer_change_amt;
    hashE.inputs[4] <== a_owner_commit;
    hashE.inputs[5] <== eInnerHash.out;
    signal expectedNoteE;
    expectedNoteE <== (1 - buyerChangeIsZero.out) * hashE.out;
    is_active * (note_e_commitment - expectedNoteE) === 0;

    component sellerChangeIsZero = IsZero();
    sellerChangeIsZero.in <== seller_change_amt;
    component hashF = Poseidon(6);
    hashF.inputs[0] <== 2;
    hashF.inputs[1] <== base_mint_lo;
    hashF.inputs[2] <== base_mint_hi;
    hashF.inputs[3] <== seller_change_amt;
    hashF.inputs[4] <== b_owner_commit;
    hashF.inputs[5] <== fInnerHash.out;
    signal expectedNoteF;
    expectedNoteF <== (1 - sellerChangeIsZero.out) * hashF.out;
    is_active * (note_f_commitment - expectedNoteF) === 0;

    // ─────────────────────────────────────────────────────────────────
    // Note-use tags — the PUBLIC handles that replaced note commitments
    // wherever a note is locked or consumed on chain.
    //
    //   tag = Poseidon3(DOMAIN_NOTE_USE=29, note_commitment, inner_hash)
    //
    // The commitment is an input, not just the inner. Above, each input
    // commitment is only constrained as `is_active * (note_x - hash.out) === 0`
    // and is otherwise a PRIVATE witness — so the published handle is the sole
    // anchor tying amount / owner / mint to the note that was actually locked.
    // A tag over `inner_hash` alone would leave `a_amount` free: a prover could
    // pair a real lock with an inflated amount, satisfy every constraint here,
    // and mint value on the outputs.
    //
    // a/b are the CONSUMED inputs. e/f are the change notes this settle creates
    // and immediately RE-LOCKS for the continuation order — that relock takes no
    // proof of its own, so its tag has to be bound here or the enclave could
    // lock an arbitrary note (censorship, bounded only by MAX_LOCK_TTL_SLOTS).
    // ─────────────────────────────────────────────────────────────────

    component tagA = Poseidon(3);
    tagA.inputs[0] <== 29;   // DOMAIN_NOTE_USE
    tagA.inputs[1] <== note_a_commitment;
    tagA.inputs[2] <== a_inner;
    signal note_a_use_tag;
    note_a_use_tag <== tagA.out;

    component tagB = Poseidon(3);
    tagB.inputs[0] <== 29;
    tagB.inputs[1] <== note_b_commitment;
    tagB.inputs[2] <== b_inner;
    signal note_b_use_tag;
    note_b_use_tag <== tagB.out;

    // e/f are masked exactly like their commitments: a slot with no change has
    // note_e_commitment = 0, and must publish tag 0 too, so the on-chain settle
    // never derives a relock PDA for a note that does not exist.
    component tagE = Poseidon(3);
    tagE.inputs[0] <== 29;
    tagE.inputs[1] <== hashE.out;
    tagE.inputs[2] <== eInnerHash.out;
    signal note_e_use_tag;
    note_e_use_tag <== (1 - buyerChangeIsZero.out) * tagE.out;

    component tagF = Poseidon(3);
    tagF.inputs[0] <== 29;
    tagF.inputs[1] <== hashF.out;
    tagF.inputs[2] <== fInnerHash.out;
    signal note_f_use_tag;
    note_f_use_tag <== (1 - sellerChangeIsZero.out) * tagF.out;

    // ─────────────────────────────────────────────────────────────────
    // VALID_PRICE constraints — range checks + headline mul check.
    // There is no separate Poseidon price-commitment binding: in the batched
    // flow, (clearing_price, batch_slot) are committed directly via the leaf
    // hash, which is both more useful and cheaper.
    // ─────────────────────────────────────────────────────────────────

    component priceBits = Num2Bits(64);
    priceBits.in <== clearing_price;
    component baseBits = Num2Bits(64);
    baseBits.in <== base_amount;
    component quoteBits = Num2Bits(64);
    quoteBits.in <== quote_amount;
    component remainderBits = Num2Bits(64);
    remainderBits.in <== price_remainder;

    // ── Amount-privacy soundness gate (P1a, see
    //    docs/settlement-amount-privacy-p0-soundness.md) ──────────────────
    // When the on-chain settle drops its plaintext `u64` + `checked_add`
    // conservation backstop, THIS circuit becomes the sole no-inflation
    // guarantor. Conservation (`a_amount === quote + buyer_change + buyer_fee`,
    // `b_amount === base + seller_change + seller_fee`) holds over BN254 Fr, so
    // without a range check a prover could field-WRAP `change`/`fee` to satisfy
    // it while the implied u64 values mint value from nothing. Range-checking
    // every term of each conservation equation to 64 bits forces Fr-equality to
    // imply exact u64-equality with no overflow (sum of three 64-bit terms is
    // < 3·2^64 ≪ Fr). `base_amount`/`quote_amount` are already checked above;
    // these six are the previously-unchecked terms:
    //   LOAD-BEARING (fresh outputs only bound by conservation + their note hash)
    component buyerChangeBits = Num2Bits(64);
    buyerChangeBits.in <== buyer_change_amt;
    component sellerChangeBits = Num2Bits(64);
    sellerChangeBits.in <== seller_change_amt;
    component buyerFeeBits = Num2Bits(64);
    buyerFeeBits.in <== buyer_fee_amt;
    component sellerFeeBits = Num2Bits(64);
    sellerFeeBits.in <== seller_fee_amt;
    //   INSURANCE (transitively bound via the input-note commitment, but cheap
    //   to assert so conservation is self-contained in THIS circuit)
    component aAmountBits = Num2Bits(64);
    aAmountBits.in <== a_amount;
    component bAmountBits = Num2Bits(64);
    bAmountBits.in <== b_amount;

    signal price_product;
    price_product <== base_amount * clearing_price;
    signal scaled_quote;
    scaled_quote <== quote_amount * price_scale;
    price_product === scaled_quote + price_remainder;
    component remainderBelowScale = LessThan(64);
    remainderBelowScale.in[0] <== price_remainder;
    remainderBelowScale.in[1] <== price_scale;
    remainderBelowScale.out === 1;

    // An active match must consume a positive base quantity at a positive
    // scaled price. Inactive slots are canonical all-zero padding.
    component baseIsZero = IsZero();
    baseIsZero.in <== base_amount;
    is_active * baseIsZero.out === 0;
    component priceIsZero = IsZero();
    priceIsZero.in <== clearing_price;
    is_active * priceIsZero.out === 0;
    // U-03: an active match must also produce a positive quote. Without this a
    // clear whose scaled floor yields `quote_amount = 0` (base·price < scale)
    // still verifies and mints a zero-amount quote note (`note_d`) that
    // `withdraw` (`amount > 0`) can never spend — permanent dead Merkle weight.
    // Mirror of `baseIsZero`. The matcher also refuses zero-quote clears (U-06),
    // so no honest path ever hits this constraint.
    component quoteIsZero = IsZero();
    quoteIsZero.in <== quote_amount;
    is_active * quoteIsZero.out === 0;

    // ─────────────────────────────────────────────────────────────────
    // EXACT FEE (amount-privacy P1b + C-04 audit) — the fee is pinned to
    // EXACTLY `⌊notional·rate/10000⌋`, not merely floored. `fee_rate_bps` is
    // bound through config_digest to VaultConfig.fee_rate_bps, so the verifier
    // pins the rate.
    //
    // FLOOR  `(fee+1)·10000 > notional·rate`  ⇒ fee ≥ ⌊notional·rate/10000⌋
    // CEIL   `fee·10000 <= notional·rate`      ⇒ fee ≤ ⌊notional·rate/10000⌋
    // together ⇒ fee == ⌊notional·rate/10000⌋ (proof of the floor half in
    // docs/settlement-amount-privacy-p0-soundness.md §8; the ceil is symmetric).
    //
    // C-04: WITHOUT the ceiling the circuit only lower-bounds the fee, so a
    // malicious TEE could set a fee as large as the whole input note and
    // confiscate up to ~100% of the trade into the protocol-owned fee notes
    // (conservation still holds — the value just goes to fees). The ceiling
    // removes that band; the matcher already charges exactly the floor, so no
    // honest path changes. rate=0 ⇒ RHS=0 ⇒ floor holds for any fee≥0 AND the
    // ceiling forces fee==0, so the fee-free path is exact too.
    // GreaterThan/LessEqThan(96): both operands are < 2^80 (fee/notional < 2^64
    // range-checked, rate < 2^16).
    component buyerFeeFloor = GreaterThan(96);
    buyerFeeFloor.in[0] <== buyer_fee_amt * 10000 + 10000;
    buyerFeeFloor.in[1] <== quote_amount * fee_rate_bps;
    buyerFeeFloor.out === 1;
    component buyerFeeCeil = LessEqThan(96);
    buyerFeeCeil.in[0] <== buyer_fee_amt * 10000;
    buyerFeeCeil.in[1] <== quote_amount * fee_rate_bps;
    buyerFeeCeil.out === 1;

    component sellerFeeFloor = GreaterThan(96);
    sellerFeeFloor.in[0] <== seller_fee_amt * 10000 + 10000;
    sellerFeeFloor.in[1] <== base_amount * fee_rate_bps;
    sellerFeeFloor.out === 1;
    component sellerFeeCeil = LessEqThan(96);
    sellerFeeCeil.in[0] <== seller_fee_amt * 10000;
    sellerFeeCeil.in[1] <== base_amount * fee_rate_bps;
    sellerFeeCeil.out === 1;

    // Per-match fee inners preserve private lineage entropy through the
    // governed epoch key while binding the exact proof-derived consumed tag.
    component quoteFeeInner = Poseidon(4);
    quoteFeeInner.inputs[0] <== 36; // DOMAIN_FEE_INNER_V2
    quoteFeeInner.inputs[1] <== fee_epoch_key;
    quoteFeeInner.inputs[2] <== note_a_use_tag;
    quoteFeeInner.inputs[3] <== 0xFC;
    component buyerFeeIsZero = IsZero();
    buyerFeeIsZero.in <== buyer_fee_amt;
    component feeQuoteHash = Poseidon(6);
    feeQuoteHash.inputs[0] <== 2;
    feeQuoteHash.inputs[1] <== quote_mint_lo;
    feeQuoteHash.inputs[2] <== quote_mint_hi;
    feeQuoteHash.inputs[3] <== buyer_fee_amt;
    feeQuoteHash.inputs[4] <== protocol_owner_commitment;
    feeQuoteHash.inputs[5] <== quoteFeeInner.out;
    signal expectedFeeQuote;
    expectedFeeQuote <== (1 - buyerFeeIsZero.out) * feeQuoteHash.out;
    is_active * (note_fee_quote_commitment - expectedFeeQuote) === 0;

    component baseFeeInner = Poseidon(4);
    baseFeeInner.inputs[0] <== 36; // DOMAIN_FEE_INNER_V2
    baseFeeInner.inputs[1] <== fee_epoch_key;
    baseFeeInner.inputs[2] <== note_b_use_tag;
    baseFeeInner.inputs[3] <== 0xFB;
    component sellerFeeIsZero = IsZero();
    sellerFeeIsZero.in <== seller_fee_amt;
    component feeBaseHash = Poseidon(6);
    feeBaseHash.inputs[0] <== 2;
    feeBaseHash.inputs[1] <== base_mint_lo;
    feeBaseHash.inputs[2] <== base_mint_hi;
    feeBaseHash.inputs[3] <== seller_fee_amt;
    feeBaseHash.inputs[4] <== protocol_owner_commitment;
    feeBaseHash.inputs[5] <== baseFeeInner.out;
    signal expectedFeeBase;
    expectedFeeBase <== (1 - sellerFeeIsZero.out) * feeBaseHash.out;
    is_active * (note_fee_base_commitment - expectedFeeBase) === 0;

    // Canonical inactive padding: every leaf-visible commitment and every
    // private amount/opening is zero. This prevents padding from hiding a
    // second market or fee claim while keeping the active path fully checked.
    is_active * (is_active - 1) === 0;
    signal inactive;
    inactive <== 1 - is_active;
    inactive * note_a_commitment === 0;
    inactive * note_b_commitment === 0;
    inactive * note_c_commitment === 0;
    inactive * note_d_commitment === 0;
    inactive * note_e_commitment === 0;
    inactive * note_f_commitment === 0;
    inactive * note_fee_base_commitment === 0;
    inactive * note_fee_quote_commitment === 0;
    inactive * base_amount === 0;
    inactive * quote_amount === 0;
    inactive * buyer_change_amt === 0;
    inactive * seller_change_amt === 0;
    inactive * buyer_fee_amt === 0;
    inactive * seller_fee_amt === 0;
    inactive * clearing_price === 0;
    inactive * price_remainder === 0;
    inactive * a_owner_commit === 0;
    inactive * b_owner_commit === 0;
    inactive * a_amount === 0;
    inactive * b_amount === 0;
    inactive * a_inner === 0;
    inactive * b_inner === 0;

    // ─────────────────────────────────────────────────────────────────
    // LEAF HASH — commitment-only (amount-privacy, P1b).
    //
    // The leaf binds ONLY the activation bit, eight note commitments, and
    // batch_slot — NOT
    // the plaintext amounts/mints/price the old two-stage leaf hashed.
    // Each note commitment is itself a Poseidon6 of (mint, amount, owner,
    // inner_hash), so the commitments transitively bind the amounts +
    // mints without putting them in the clear; the per-slot conservation
    // + range constraints above prove they're consistent. This lets the
    // on-chain handler recompute the leaf from the (amount-free) settle
    // payload, so the amounts can leave the payload entirely (P3).
    //
    // The CONSUMED slots bind their use TAGS, not their commitments — that is
    // what stops the settle republishing the two values an observer would use to
    // link the inputs back to their Merkle leaves. c/d/e/f stay commitments
    // because they are appended to the tree as new leaves, so the leaf value is
    // what the handler needs.
    //
    // The two relock tags are folded into ONE field rather than added as two.
    // Twelve is the light-poseidon width cap (MAX_X5_LEN = 13); binding them
    // separately would need 13 and force the retired two-stage
    // Poseidon12+Poseidon9 split back. This lands at exactly 12.
    //
    //   relock_digest = Poseidon3(DOMAIN_RELOCK_DIGEST=30, tag_e, tag_f)
    //   leaf = Poseidon12(DOMAIN_LEAF_V3=31, active,
    //                     tag_a, tag_b, note_c, note_d, note_e, note_f,
    //                     note_fee_base, note_fee_quote,
    //                     batch_slot, relock_digest)
    //
    // >>> THIS CONSUMES THE LAST SLOT. Adding any further leaf field forces the
    // >>> two-stage split back. `compute_match_leaf` on chain asserts the arity.
    // ─────────────────────────────────────────────────────────────────

    component relockDigest = Poseidon(3);
    relockDigest.inputs[0] <== 30;   // DOMAIN_RELOCK_DIGEST
    relockDigest.inputs[1] <== note_e_use_tag;
    relockDigest.inputs[2] <== note_f_use_tag;

    component leafH = Poseidon(12);
    leafH.inputs[0] <== 31;   // DOMAIN_LEAF_V3
    leafH.inputs[1] <== is_active;
    leafH.inputs[2] <== note_a_use_tag;
    leafH.inputs[3] <== note_b_use_tag;
    leafH.inputs[4] <== note_c_commitment;
    leafH.inputs[5] <== note_d_commitment;
    leafH.inputs[6] <== note_e_commitment;
    leafH.inputs[7] <== note_f_commitment;
    leafH.inputs[8] <== note_fee_base_commitment;
    leafH.inputs[9] <== note_fee_quote_commitment;
    leafH.inputs[10] <== batch_slot;
    leafH.inputs[11] <== relockDigest.out;

    leaf <== leafH.out;
}

// ----------------------------------------------------------------------------
// MerkleRoot(N) — domain-tagged binary Merkle root over N leaves.
// N must be a power of 2 (caller's responsibility — circom doesn't have a way
// to assert this nicely at template-instantiation time).
//
// Layout: `tree[0..N-1]` are the leaves, `tree[N..2N-2]` are internal nodes
// in level-order. Each internal node `i` (counting from 0) at flat index
// `N + i` is the hash of `tree[2*i]` and `tree[2*i + 1]`. The Merkle root
// is `tree[2*N - 2]`.
// ----------------------------------------------------------------------------
template MerkleRoot(N) {
    signal input leaves[N];
    signal output root;

    signal tree[2*N - 1];
    component hashers[N - 1];

    for (var i = 0; i < N; i++) {
        tree[i] <== leaves[i];
    }
    for (var i = 0; i < N - 1; i++) {
        hashers[i] = Poseidon(3);
        hashers[i].inputs[0] <== 22;            // DOMAIN_BATCH_ROOT
        hashers[i].inputs[1] <== tree[2*i];
        hashers[i].inputs[2] <== tree[2*i + 1];
        tree[N + i] <== hashers[i].out;
    }

    root <== tree[2*N - 2];
}

// ----------------------------------------------------------------------------
// MatchBatch(N) — main template for N=2/4/8/16 batches. Two public inputs bind
// the computed root plus a Poseidon digest of governed protocol/market
// configuration. The preimage fields remain circuit inputs and drive every
// slot; the vault recomputes the same digest from authoritative accounts.
// ----------------------------------------------------------------------------
template MatchBatch(N) {
    signal input merkle_root;
    signal input config_digest;
    // Protocol fee rate (bps), bound through config_digest to
    // VaultConfig.fee_rate_bps. Range-bound to 16 bits so the per-slot
    // fee-floor products stay < 2^80.
    signal input fee_rate_bps;
    component feeRateBits = Num2Bits(16);
    feeRateBits.in <== fee_rate_bps;
    // Protocol fee-note owner — bound through config_digest to
    // VaultConfig.protocol_owner_commitment so the minted fee notes can only
    // pay the protocol's owner.
    signal input protocol_owner_commitment;
    signal input fee_key_binding;
    signal input fee_key_epoch;
    signal input fee_epoch_key;
    // Governed MarketConfig values, bound through config_digest.
    signal input base_mint_lo;
    signal input base_mint_hi;
    signal input quote_mint_lo;
    signal input quote_mint_hi;
    signal input price_scale;
    component priceScaleBits = Num2Bits(64);
    priceScaleBits.in <== price_scale;
    component priceScaleIsZero = IsZero();
    priceScaleIsZero.in <== price_scale;
    priceScaleIsZero.out === 0;

    component feeKeyHash = Poseidon(2);
    feeKeyHash.inputs[0] <== 35; // DOMAIN_FEE_KEY_BINDING
    feeKeyHash.inputs[1] <== fee_epoch_key;
    fee_key_binding === feeKeyHash.out;

    component feeEpochBits = Num2Bits(64);
    feeEpochBits.in <== fee_key_epoch;

    // Public-statement compression: the vault recomputes this Poseidon10 from
    // VaultConfig + MarketConfig before Groth16 verification. This preserves
    // exact binding while shrinking the verifier MSM from eight inputs to two.
    component configHash = Poseidon(10);
    configHash.inputs[0] <== 37; // DOMAIN_MATCH_CONFIG_V2
    configHash.inputs[1] <== fee_rate_bps;
    configHash.inputs[2] <== protocol_owner_commitment;
    configHash.inputs[3] <== base_mint_lo;
    configHash.inputs[4] <== base_mint_hi;
    configHash.inputs[5] <== quote_mint_lo;
    configHash.inputs[6] <== quote_mint_hi;
    configHash.inputs[7] <== price_scale;
    configHash.inputs[8] <== fee_key_binding;
    configHash.inputs[9] <== fee_key_epoch;
    config_digest === configHash.out;

    // ----- Per-slot root-bound fields -----
    signal input note_a_commitment[N];
    signal input note_b_commitment[N];
    signal input note_c_commitment[N];
    signal input note_d_commitment[N];
    signal input note_e_commitment[N];
    signal input note_f_commitment[N];
    signal input note_fee_base_commitment[N];
    signal input note_fee_quote_commitment[N];
    signal input base_amount[N];
    signal input quote_amount[N];
    signal input buyer_change_amt[N];
    signal input seller_change_amt[N];
    signal input buyer_fee_amt[N];
    signal input seller_fee_amt[N];
    signal input batch_slot[N];
    signal input is_active[N];

    // ----- VALID_CREATE private witnesses (v2: one inner_hash per note) -----
    signal input a_owner_commit[N];
    signal input b_owner_commit[N];
    signal input a_amount[N];
    signal input b_amount[N];
    signal input a_inner[N];
    signal input b_inner[N];

    // ----- VALID_PRICE private witness -----
    signal input clearing_price[N];
    signal input price_remainder[N];

    component slot[N];
    for (var i = 0; i < N; i++) {
        slot[i] = MatchSlot();
        slot[i].note_a_commitment <== note_a_commitment[i];
        slot[i].note_b_commitment <== note_b_commitment[i];
        slot[i].note_c_commitment <== note_c_commitment[i];
        slot[i].note_d_commitment <== note_d_commitment[i];
        slot[i].note_e_commitment <== note_e_commitment[i];
        slot[i].note_f_commitment <== note_f_commitment[i];
        slot[i].note_fee_base_commitment  <== note_fee_base_commitment[i];
        slot[i].note_fee_quote_commitment <== note_fee_quote_commitment[i];
        slot[i].quote_mint_lo     <== quote_mint_lo;
        slot[i].quote_mint_hi     <== quote_mint_hi;
        slot[i].base_mint_lo      <== base_mint_lo;
        slot[i].base_mint_hi      <== base_mint_hi;
        slot[i].base_amount       <== base_amount[i];
        slot[i].quote_amount      <== quote_amount[i];
        slot[i].buyer_change_amt  <== buyer_change_amt[i];
        slot[i].seller_change_amt <== seller_change_amt[i];
        slot[i].buyer_fee_amt     <== buyer_fee_amt[i];
        slot[i].seller_fee_amt    <== seller_fee_amt[i];
        // C-08: pin each slot's `batch_slot` to its index. It feeds the leaf
        // hash, and the on-chain settle recomputes the leaf from
        // `payload.batch_slot` while proving inclusion at position `match_index`
        // — so binding `batch_slot[i] === i` here (+ the on-chain
        // `payload.batch_slot == match_index` assert) makes the value a reliable
        // slot identifier instead of a free per-slot input. ALL slots, including
        // dummy pad slots, must carry `batch_slot = i` (the prover pad path sets
        // it; previously pads used 0).
        batch_slot[i] === i;
        slot[i].batch_slot        <== batch_slot[i];
        slot[i].is_active         <== is_active[i];
        slot[i].fee_rate_bps      <== fee_rate_bps;
        slot[i].price_scale       <== price_scale;
        slot[i].protocol_owner_commitment <== protocol_owner_commitment;
        slot[i].fee_epoch_key     <== fee_epoch_key;
        slot[i].a_owner_commit    <== a_owner_commit[i];
        slot[i].b_owner_commit    <== b_owner_commit[i];
        slot[i].a_amount          <== a_amount[i];
        slot[i].b_amount          <== b_amount[i];
        slot[i].a_inner           <== a_inner[i];
        slot[i].b_inner           <== b_inner[i];
        slot[i].clearing_price    <== clearing_price[i];
        slot[i].price_remainder   <== price_remainder[i];
    }

    component merkle = MerkleRoot(N);
    for (var i = 0; i < N; i++) {
        merkle.leaves[i] <== slot[i].leaf;
    }
    merkle_root === merkle.root;
}
