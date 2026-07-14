pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

// ============================================================================
// match_batch — parameterised batched validity templates
// ============================================================================
//
// Shared template body for the v3.5 batched validity proofs. Per-N main
// files (`match_batch_n2/`, `match_batch_n4/`, `match_batch_n16/`) just
// instantiate `MatchBatch(N)` at their chosen size. The same MatchSlot
// body services every batch size — only the Merkle tree depth changes.
//
// Constraint budget (measured on the N=16 instantiation —
// `circuits/match_batch_n16/`):
//   - VALID_CREATE constraints (6 Poseidon6 note hashes + IsZero
//     selectors + per-leg conservation)             ~2,100
//   - VALID_PRICE  constraints (3 Num2Bits(64), one mul check)
//                                                   ~  200
//   - Leaf hash    (single Poseidon(10), commitment-only — see the
//     leaf-hash section below + CRYPTOGRAPHY.md)     ~  600
//   ──────────────────────────────────────────────────────
//   Per slot total (dominated by VALID_PRICE 64-bit decomp) ~ 10 k
//   N=16 batch + Merkle (15 internal nodes × Poseidon3) ≈ 163 k
//
// Setup requirements by N:
//   - N=2  / N=4   → pot16 (`powersOfTau28_hez_final_16.ptau`,
//                    2^16 cap) is sufficient. Used by
//                    `match-batch-prototype.test.ts` only.
//   - N=16         → **pot18 required** (`powersOfTau28_hez_final_18.ptau`,
//                    ~288 MB, 2^18 cap) — total constraints
//                    (162,947) exceed the pot16 ceiling.
//                    `scripts/download-ptau.sh` fetches both files
//                    automatically; the build script picks the right
//                    one per circuit instantiation.
//
// Leaf-hash arity (single Poseidon10, commitment-only — amount-privacy P1b):
//   The on-chain Poseidon implementation is `light-poseidon`, which
//   caps Poseidon arity at 12 inputs (its `MAX_X5_LEN = 13` limit).
//   The leaf binds only the 6 note commitments + 2 fee-note commitments
//   + batch_slot + a domain tag = 10 inputs ≤ 12, so a SINGLE Poseidon(10)
//   fits — no two-stage split needed. The note commitments are each a
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
//   `quote === base*price`) and bound inside the note commitments, so the
//   leaf doesn't need them and the on-chain handler can recompute it from
//   the amount-free payload.
//
// Domain tags (must stay in sync with the TS prover helper in
// `packages/sdk/tests/helpers/match-batch-prover.ts` AND with the
// on-chain leaf walker in
// `programs/vault/src/instructions/tee_forced_settle_batched.rs`):
//   DOMAIN_NOTE       =  2   (note commitment Poseidon6 v2 — inner_hash)
//   DOMAIN_LEAF_V2    = 23   (single Poseidon(10) commitment-only leaf)
//   DOMAIN_BATCH_ROOT = 22   (Merkle internal node, Poseidon(3))
//   (DOMAIN_LEAF_INNER=20 / DOMAIN_LEAF_TOP=21 = the retired two-stage leaf.)

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
    // Protocol fee notes (amount-privacy, P1b). Per-slot inputs but non-zero
    // only on the batch's flush slot (slot 0); bound to the batch fee sums at
    // the MatchBatch level. Hashed into the leaf so the on-chain settle's
    // append of these commitments is proof-backed.
    signal input note_fee_base_commitment;
    signal input note_fee_quote_commitment;
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
    signal input batch_slot;
    // Protocol fee rate (basis points), a MatchBatch-level PUBLIC input fanned
    // to every slot, bound on-chain to VaultConfig.fee_rate_bps. Drives the
    // in-circuit fee floor below.
    signal input fee_rate_bps;

    // ----- VALID_CREATE private witnesses (v2: one inner_hash per note) -----
    signal input a_owner_commit;
    signal input b_owner_commit;
    signal input a_amount;
    signal input b_amount;
    signal input a_inner;
    signal input b_inner;
    signal input c_inner;
    signal input d_inner;
    signal input e_inner;
    signal input f_inner;

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
    note_a_commitment === hashA.out;

    component hashB = Poseidon(6);
    hashB.inputs[0] <== 2;
    hashB.inputs[1] <== base_mint_lo;
    hashB.inputs[2] <== base_mint_hi;
    hashB.inputs[3] <== b_amount;
    hashB.inputs[4] <== b_owner_commit;
    hashB.inputs[5] <== b_inner;
    note_b_commitment === hashB.out;

    a_amount === quote_amount + buyer_change_amt + buyer_fee_amt;
    b_amount === base_amount + seller_change_amt + seller_fee_amt;

    component hashC = Poseidon(6);
    hashC.inputs[0] <== 2;
    hashC.inputs[1] <== base_mint_lo;
    hashC.inputs[2] <== base_mint_hi;
    hashC.inputs[3] <== base_amount;
    hashC.inputs[4] <== a_owner_commit;
    hashC.inputs[5] <== c_inner;
    note_c_commitment === hashC.out;

    component hashD = Poseidon(6);
    hashD.inputs[0] <== 2;
    hashD.inputs[1] <== quote_mint_lo;
    hashD.inputs[2] <== quote_mint_hi;
    hashD.inputs[3] <== quote_amount;
    hashD.inputs[4] <== b_owner_commit;
    hashD.inputs[5] <== d_inner;
    note_d_commitment === hashD.out;

    component buyerChangeIsZero = IsZero();
    buyerChangeIsZero.in <== buyer_change_amt;
    component hashE = Poseidon(6);
    hashE.inputs[0] <== 2;
    hashE.inputs[1] <== quote_mint_lo;
    hashE.inputs[2] <== quote_mint_hi;
    hashE.inputs[3] <== buyer_change_amt;
    hashE.inputs[4] <== a_owner_commit;
    hashE.inputs[5] <== e_inner;
    signal expectedNoteE;
    expectedNoteE <== (1 - buyerChangeIsZero.out) * hashE.out;
    note_e_commitment === expectedNoteE;

    component sellerChangeIsZero = IsZero();
    sellerChangeIsZero.in <== seller_change_amt;
    component hashF = Poseidon(6);
    hashF.inputs[0] <== 2;
    hashF.inputs[1] <== base_mint_lo;
    hashF.inputs[2] <== base_mint_hi;
    hashF.inputs[3] <== seller_change_amt;
    hashF.inputs[4] <== b_owner_commit;
    hashF.inputs[5] <== f_inner;
    signal expectedNoteF;
    expectedNoteF <== (1 - sellerChangeIsZero.out) * hashF.out;
    note_f_commitment === expectedNoteF;

    // ─────────────────────────────────────────────────────────────────
    // VALID_PRICE constraints — range checks + headline mul check.
    // The Poseidon3 price_commitment binding from the old VALID_PRICE
    // template is GONE: in the batched flow, (clearing_price, batch_slot)
    // are committed directly via the leaf hash (more useful + cheaper).
    // ─────────────────────────────────────────────────────────────────

    component priceBits = Num2Bits(64);
    priceBits.in <== clearing_price;
    component baseBits = Num2Bits(64);
    baseBits.in <== base_amount;
    component quoteBits = Num2Bits(64);
    quoteBits.in <== quote_amount;

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

    quote_amount === base_amount * clearing_price;

    // ─────────────────────────────────────────────────────────────────
    // EXACT FEE (amount-privacy P1b + C-04 audit) — the fee is pinned to
    // EXACTLY `⌊notional·rate/10000⌋`, not merely floored. `fee_rate_bps` is a
    // PUBLIC input bound to VaultConfig.fee_rate_bps, so the verifier pins the
    // rate.
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

    // ─────────────────────────────────────────────────────────────────
    // LEAF HASH — commitment-only (amount-privacy, P1b).
    //
    // The leaf binds ONLY the six note commitments + batch_slot — NOT
    // the plaintext amounts/mints/price the old two-stage leaf hashed.
    // Each note commitment is itself a Poseidon6 of (mint, amount, owner,
    // inner_hash), so the commitments transitively bind the amounts +
    // mints without putting them in the clear; the per-slot conservation
    // + range constraints above prove they're consistent. This lets the
    // on-chain handler recompute the leaf from the (amount-free) settle
    // payload, so the amounts can leave the payload entirely (P3).
    //
    // Single Poseidon10 (1 domain + 8 commitments + batch_slot = 10 ≤ 12,
    // the light-poseidon width cap), so no two-stage split is needed. The two
    // fee-note commitments are included so the on-chain settle's append of them
    // (slot 0 only) is bound by the proof.
    //
    //   leaf = Poseidon10(DOMAIN_LEAF_V2=23,
    //                     note_a, note_b, note_c, note_d, note_e, note_f,
    //                     note_fee_base, note_fee_quote,
    //                     batch_slot)
    // ─────────────────────────────────────────────────────────────────

    component leafH = Poseidon(10);
    leafH.inputs[0] <== 23;   // DOMAIN_LEAF_V2
    leafH.inputs[1] <== note_a_commitment;
    leafH.inputs[2] <== note_b_commitment;
    leafH.inputs[3] <== note_c_commitment;
    leafH.inputs[4] <== note_d_commitment;
    leafH.inputs[5] <== note_e_commitment;
    leafH.inputs[6] <== note_f_commitment;
    leafH.inputs[7] <== note_fee_base_commitment;
    leafH.inputs[8] <== note_fee_quote_commitment;
    leafH.inputs[9] <== batch_slot;

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
// MatchBatch(N) — main template for N=2/4/8/16 batches. Single public
// input (merkle_root); the prover supplies it and the circuit re-derives
// it from the slot leaves, asserting equality. Standard "computed value
// as public input" pattern.
// ----------------------------------------------------------------------------
template MatchBatch(N) {
    signal input merkle_root;
    // Protocol fee rate (bps), PUBLIC — bound on-chain to
    // VaultConfig.fee_rate_bps. Declared right after merkle_root so the public
    // signal order is [merkle_root, fee_rate_bps]. Range-bound to 16 bits so the
    // per-slot fee-floor products stay < 2^80.
    signal input fee_rate_bps;
    component feeRateBits = Num2Bits(16);
    feeRateBits.in <== fee_rate_bps;
    // Protocol fee-note owner, PUBLIC — bound on-chain to
    // VaultConfig.protocol_owner_commitment so the minted fee notes can only
    // pay the protocol's owner. Public order:
    // [merkle_root, fee_rate_bps, protocol_owner_commitment].
    signal input protocol_owner_commitment;
    // Fee-note inner_hashes (private; meaningful only on the flush slot).
    signal input fee_base_inner;
    signal input fee_quote_inner;

    // ----- Per-slot public-bound fields -----
    signal input note_a_commitment[N];
    signal input note_b_commitment[N];
    signal input note_c_commitment[N];
    signal input note_d_commitment[N];
    signal input note_e_commitment[N];
    signal input note_f_commitment[N];
    signal input note_fee_base_commitment[N];
    signal input note_fee_quote_commitment[N];
    signal input quote_mint_lo[N];
    signal input quote_mint_hi[N];
    signal input base_mint_lo[N];
    signal input base_mint_hi[N];
    signal input base_amount[N];
    signal input quote_amount[N];
    signal input buyer_change_amt[N];
    signal input seller_change_amt[N];
    signal input buyer_fee_amt[N];
    signal input seller_fee_amt[N];
    signal input batch_slot[N];

    // ----- VALID_CREATE private witnesses (v2: one inner_hash per note) -----
    signal input a_owner_commit[N];
    signal input b_owner_commit[N];
    signal input a_amount[N];
    signal input b_amount[N];
    signal input a_inner[N];
    signal input b_inner[N];
    signal input c_inner[N];
    signal input d_inner[N];
    signal input e_inner[N];
    signal input f_inner[N];

    // ----- VALID_PRICE private witness -----
    signal input clearing_price[N];

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
        slot[i].quote_mint_lo     <== quote_mint_lo[i];
        slot[i].quote_mint_hi     <== quote_mint_hi[i];
        slot[i].base_mint_lo      <== base_mint_lo[i];
        slot[i].base_mint_hi      <== base_mint_hi[i];
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
        slot[i].fee_rate_bps      <== fee_rate_bps;
        slot[i].a_owner_commit    <== a_owner_commit[i];
        slot[i].b_owner_commit    <== b_owner_commit[i];
        slot[i].a_amount          <== a_amount[i];
        slot[i].b_amount          <== b_amount[i];
        slot[i].a_inner           <== a_inner[i];
        slot[i].b_inner           <== b_inner[i];
        slot[i].c_inner           <== c_inner[i];
        slot[i].d_inner           <== d_inner[i];
        slot[i].e_inner           <== e_inner[i];
        slot[i].f_inner           <== f_inner[i];
        slot[i].clearing_price    <== clearing_price[i];
    }

    // ── Fee-note binding (amount-privacy, P1b) ────────────────────────────
    // The protocol fee notes are batch-aggregated — the matcher's
    // flush_fee_notes mints ONE note per mint over the whole batch and attaches
    // both to the FIRST match (slot 0). Bind those commitments to the batch fee
    // sums so a malicious/buggy prover can't mint a fee note worth more than the
    // fees conservation accounts for, nor to a non-protocol owner (the over-mint
    // / wrong-owner inflation gap surfaced in the P0 audit §7).
    signal partialBuyerFee[N];
    signal partialSellerFee[N];
    partialBuyerFee[0]  <== buyer_fee_amt[0];
    partialSellerFee[0] <== seller_fee_amt[0];
    for (var i = 1; i < N; i++) {
        partialBuyerFee[i]  <== partialBuyerFee[i-1]  + buyer_fee_amt[i];
        partialSellerFee[i] <== partialSellerFee[i-1] + seller_fee_amt[i];
    }
    signal total_buyer_fee;
    signal total_seller_fee;
    total_buyer_fee  <== partialBuyerFee[N-1];
    total_seller_fee <== partialSellerFee[N-1];
    // The minted fee note's amount must be a u64 to stay spendable: each
    // per-slot fee is 64-bit (MatchSlot range checks), but a sum of up to N
    // could in principle exceed 2^64 — range-check the totals too.
    component totalBuyerFeeBits = Num2Bits(64);
    totalBuyerFeeBits.in <== total_buyer_fee;
    component totalSellerFeeBits = Num2Bits(64);
    totalSellerFeeBits.in <== total_seller_fee;

    // Slot 0's quote fee note === Poseidon6(DOMAIN_NOTE, quote_mint, total_buyer_fee,
    // protocol_owner, fee_quote_inner), zeroed when there are no fees (same
    // IsZero gate note_e/note_f use → a zero-fee batch mints [0;32]).
    component buyerFeeIsZero = IsZero();
    buyerFeeIsZero.in <== total_buyer_fee;
    component feeQuoteHash = Poseidon(6);
    feeQuoteHash.inputs[0] <== 2;                       // DOMAIN_NOTE
    feeQuoteHash.inputs[1] <== quote_mint_lo[0];
    feeQuoteHash.inputs[2] <== quote_mint_hi[0];
    feeQuoteHash.inputs[3] <== total_buyer_fee;
    feeQuoteHash.inputs[4] <== protocol_owner_commitment;
    feeQuoteHash.inputs[5] <== fee_quote_inner;
    signal expectedFeeQuote;
    expectedFeeQuote <== (1 - buyerFeeIsZero.out) * feeQuoteHash.out;
    note_fee_quote_commitment[0] === expectedFeeQuote;

    component sellerFeeIsZero = IsZero();
    sellerFeeIsZero.in <== total_seller_fee;
    component feeBaseHash = Poseidon(6);
    feeBaseHash.inputs[0] <== 2;                        // DOMAIN_NOTE
    feeBaseHash.inputs[1] <== base_mint_lo[0];
    feeBaseHash.inputs[2] <== base_mint_hi[0];
    feeBaseHash.inputs[3] <== total_seller_fee;
    feeBaseHash.inputs[4] <== protocol_owner_commitment;
    feeBaseHash.inputs[5] <== fee_base_inner;
    signal expectedFeeBase;
    expectedFeeBase <== (1 - sellerFeeIsZero.out) * feeBaseHash.out;
    note_fee_base_commitment[0] === expectedFeeBase;

    // Non-flush slots (1..N-1) carry no fee notes.
    for (var i = 1; i < N; i++) {
        note_fee_base_commitment[i] === 0;
        note_fee_quote_commitment[i] === 0;
    }

    component merkle = MerkleRoot(N);
    for (var i = 0; i < N; i++) {
        merkle.leaves[i] <== slot[i].leaf;
    }
    merkle_root === merkle.root;
}
