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
// Constraint budget (approx, per slot, post-optimisation):
//   - VALID_CREATE constraints (6 Poseidon7 + IsZero gates + conservation)
//                                      ~2,100
//   - VALID_PRICE  constraints (3 Num2Bits(64), one mul check)
//                                      ~ 200
//   - Leaf hash    (Poseidon16 + Poseidon5)
//                                      ~ 940
//   ──────────────────────────────────────
//   Per slot total                     ~3,240
//   N=16 batch (16 × 3,240) + Merkle (15 × Poseidon3 ~ 264 each)
//                                      ~55,800
//   Fits PTAU-16's 65,536 cap with ~10k margin.
//
// Optimisation note (vs. the v3.5-N=2 prototype landed in f1e671b):
//   The earlier leaf hash chained three Poseidon7s + one Poseidon4
//   = ~1,443 constraints/slot. This version uses one Poseidon16 + one
//   Poseidon5 = ~940 constraints/slot. We also drop `price_commitment`
//   from both the leaf and the VALID_PRICE circuit body: the
//   (clearing_price, batch_slot) pair the leaf now binds directly is
//   strictly more useful than the Poseidon3-derived price_commitment
//   (the on-chain handler has both in the payload either way), and we
//   save another Poseidon3 (~264) per slot by dropping the
//   `price_commitment === Poseidon3(5, clearing_price, batch_slot)`
//   binding constraint.
//
// Domain tags (must stay in sync with the TS prover helper):
//   DOMAIN_NOTE       =  2   (note commitment Poseidon7, existing)
//   DOMAIN_LEAF_INNER = 20   (Poseidon16 inside leaf)
//   DOMAIN_LEAF_TOP   = 21   (Poseidon5 outer leaf)
//   DOMAIN_BATCH_ROOT = 22   (Merkle internal node)

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
    // clearing_price was private in the old VALID_PRICE; it's still private
    // to the circuit, but the leaf binds it directly (the on-chain handler
    // reads it from the settle payload, where it's been public since v3).
    signal input clearing_price;
    signal input batch_slot;

    // ----- VALID_CREATE private witnesses -----
    signal input a_owner_commit;
    signal input b_owner_commit;
    signal input a_amount;
    signal input b_amount;
    signal input a_nonce;
    signal input a_blinding;
    signal input b_nonce;
    signal input b_blinding;
    signal input c_nonce;
    signal input c_blinding;
    signal input d_nonce;
    signal input d_blinding;
    signal input e_nonce;
    signal input e_blinding;
    signal input f_nonce;
    signal input f_blinding;

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

    component hashA = Poseidon(7);
    hashA.inputs[0] <== 2;   // DOMAIN_NOTE
    hashA.inputs[1] <== quote_mint_lo;
    hashA.inputs[2] <== quote_mint_hi;
    hashA.inputs[3] <== a_amount;
    hashA.inputs[4] <== a_owner_commit;
    hashA.inputs[5] <== a_nonce;
    hashA.inputs[6] <== a_blinding;
    note_a_commitment === hashA.out;

    component hashB = Poseidon(7);
    hashB.inputs[0] <== 2;
    hashB.inputs[1] <== base_mint_lo;
    hashB.inputs[2] <== base_mint_hi;
    hashB.inputs[3] <== b_amount;
    hashB.inputs[4] <== b_owner_commit;
    hashB.inputs[5] <== b_nonce;
    hashB.inputs[6] <== b_blinding;
    note_b_commitment === hashB.out;

    a_amount === quote_amount + buyer_change_amt + buyer_fee_amt;
    b_amount === base_amount + seller_change_amt + seller_fee_amt;

    component hashC = Poseidon(7);
    hashC.inputs[0] <== 2;
    hashC.inputs[1] <== base_mint_lo;
    hashC.inputs[2] <== base_mint_hi;
    hashC.inputs[3] <== base_amount;
    hashC.inputs[4] <== a_owner_commit;
    hashC.inputs[5] <== c_nonce;
    hashC.inputs[6] <== c_blinding;
    note_c_commitment === hashC.out;

    component hashD = Poseidon(7);
    hashD.inputs[0] <== 2;
    hashD.inputs[1] <== quote_mint_lo;
    hashD.inputs[2] <== quote_mint_hi;
    hashD.inputs[3] <== quote_amount;
    hashD.inputs[4] <== b_owner_commit;
    hashD.inputs[5] <== d_nonce;
    hashD.inputs[6] <== d_blinding;
    note_d_commitment === hashD.out;

    component buyerChangeIsZero = IsZero();
    buyerChangeIsZero.in <== buyer_change_amt;
    component hashE = Poseidon(7);
    hashE.inputs[0] <== 2;
    hashE.inputs[1] <== quote_mint_lo;
    hashE.inputs[2] <== quote_mint_hi;
    hashE.inputs[3] <== buyer_change_amt;
    hashE.inputs[4] <== a_owner_commit;
    hashE.inputs[5] <== e_nonce;
    hashE.inputs[6] <== e_blinding;
    signal expectedNoteE;
    expectedNoteE <== (1 - buyerChangeIsZero.out) * hashE.out;
    note_e_commitment === expectedNoteE;

    component sellerChangeIsZero = IsZero();
    sellerChangeIsZero.in <== seller_change_amt;
    component hashF = Poseidon(7);
    hashF.inputs[0] <== 2;
    hashF.inputs[1] <== base_mint_lo;
    hashF.inputs[2] <== base_mint_hi;
    hashF.inputs[3] <== seller_change_amt;
    hashF.inputs[4] <== b_owner_commit;
    hashF.inputs[5] <== f_nonce;
    hashF.inputs[6] <== f_blinding;
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

    quote_amount === base_amount * clearing_price;

    // ─────────────────────────────────────────────────────────────────
    // LEAF HASH — Poseidon12 + Poseidon9.
    //
    // Why this arity, not bigger: solana_poseidon (via light-poseidon)
    // caps at width 13, i.e. max nInputs = 12. The on-chain handler
    // re-derives this exact hash from the settle payload to look up
    // the BatchValidityMarker PDA, so the in-circuit arities have to
    // stay ≤ 12 for parity.
    //
    //   h1   = Poseidon12(DOMAIN_LEAF_INNER,
    //                     note_a, note_b, note_c, note_d, note_e, note_f,
    //                     qm_lo, qm_hi, bm_lo, bm_hi,
    //                     base_amount)
    //   leaf = Poseidon9 (DOMAIN_LEAF_TOP, h1,
    //                     quote_amount,
    //                     buyer_change, seller_change,
    //                     buyer_fee, seller_fee,
    //                     clearing_price, batch_slot)
    //
    // Eighteen data fields bound across the two hashes (11 in h1,
    // 7 in the top hash).
    // ─────────────────────────────────────────────────────────────────

    component leafH1 = Poseidon(12);
    leafH1.inputs[0]  <== 20;   // DOMAIN_LEAF_INNER
    leafH1.inputs[1]  <== note_a_commitment;
    leafH1.inputs[2]  <== note_b_commitment;
    leafH1.inputs[3]  <== note_c_commitment;
    leafH1.inputs[4]  <== note_d_commitment;
    leafH1.inputs[5]  <== note_e_commitment;
    leafH1.inputs[6]  <== note_f_commitment;
    leafH1.inputs[7]  <== quote_mint_lo;
    leafH1.inputs[8]  <== quote_mint_hi;
    leafH1.inputs[9]  <== base_mint_lo;
    leafH1.inputs[10] <== base_mint_hi;
    leafH1.inputs[11] <== base_amount;

    component leafTop = Poseidon(9);
    leafTop.inputs[0] <== 21;   // DOMAIN_LEAF_TOP
    leafTop.inputs[1] <== leafH1.out;
    leafTop.inputs[2] <== quote_amount;
    leafTop.inputs[3] <== buyer_change_amt;
    leafTop.inputs[4] <== seller_change_amt;
    leafTop.inputs[5] <== buyer_fee_amt;
    leafTop.inputs[6] <== seller_fee_amt;
    leafTop.inputs[7] <== clearing_price;
    leafTop.inputs[8] <== batch_slot;

    leaf <== leafTop.out;
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

    // ----- Per-slot public-bound fields -----
    signal input note_a_commitment[N];
    signal input note_b_commitment[N];
    signal input note_c_commitment[N];
    signal input note_d_commitment[N];
    signal input note_e_commitment[N];
    signal input note_f_commitment[N];
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

    // ----- VALID_CREATE private witnesses -----
    signal input a_owner_commit[N];
    signal input b_owner_commit[N];
    signal input a_amount[N];
    signal input b_amount[N];
    signal input a_nonce[N];
    signal input a_blinding[N];
    signal input b_nonce[N];
    signal input b_blinding[N];
    signal input c_nonce[N];
    signal input c_blinding[N];
    signal input d_nonce[N];
    signal input d_blinding[N];
    signal input e_nonce[N];
    signal input e_blinding[N];
    signal input f_nonce[N];
    signal input f_blinding[N];

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
        slot[i].batch_slot        <== batch_slot[i];
        slot[i].a_owner_commit    <== a_owner_commit[i];
        slot[i].b_owner_commit    <== b_owner_commit[i];
        slot[i].a_amount          <== a_amount[i];
        slot[i].b_amount          <== b_amount[i];
        slot[i].a_nonce           <== a_nonce[i];
        slot[i].a_blinding        <== a_blinding[i];
        slot[i].b_nonce           <== b_nonce[i];
        slot[i].b_blinding        <== b_blinding[i];
        slot[i].c_nonce           <== c_nonce[i];
        slot[i].c_blinding        <== c_blinding[i];
        slot[i].d_nonce           <== d_nonce[i];
        slot[i].d_blinding        <== d_blinding[i];
        slot[i].e_nonce           <== e_nonce[i];
        slot[i].e_blinding        <== e_blinding[i];
        slot[i].f_nonce           <== f_nonce[i];
        slot[i].f_blinding        <== f_blinding[i];
        slot[i].clearing_price    <== clearing_price[i];
    }

    component merkle = MerkleRoot(N);
    for (var i = 0; i < N; i++) {
        merkle.leaves[i] <== slot[i].leaf;
    }
    merkle_root === merkle.root;
}
