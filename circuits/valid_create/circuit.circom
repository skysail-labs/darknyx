pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// VALID_CREATE
//
// Proves, at settlement time, that the TEE constructed the output notes
// CORRECTLY:
//
//   1. note_c (buyer's trade leg) is addressed to the BUYER (= the owner of
//      note_a) in the BASE mint at base_amount.
//   2. note_d (seller's trade leg) is addressed to the SELLER (= owner of
//      note_b) in the QUOTE mint at quote_amount.
//   3. note_e (buyer's change) is in the QUOTE mint at buyer_change_amt
//      addressed to the BUYER — IFF buyer_change_amt > 0. Otherwise
//      note_e_commitment must be zero.
//   4. note_f (seller's change) is in the BASE mint at seller_change_amt
//      addressed to the SELLER — IFF seller_change_amt > 0. Otherwise
//      note_f_commitment must be zero.
//   5. Conservation per side: a_amount = quote_amount + buyer_change + buyer_fee.
//      b_amount = base_amount + seller_change + seller_fee.
//
// Owner commitments stay private — the proof leaks NOTHING about who is
// involved beyond what was already public (the input commitments, the
// declared amounts, the mints). It only proves the TEE didn't redirect or
// re-denominate any output leg.
//
// (The fee note is intentionally out of scope. A malformed fee note is
// recoverable — at worst the protocol forfeits a single batch's fee.
// User funds are protected by the trade-leg + change-leg constraints
// above plus the on-chain conservation check on lock amounts.)
//
// Public inputs (16):
//   note_a_commitment, note_b_commitment
//   note_c_commitment, note_d_commitment, note_e_commitment, note_f_commitment
//   quote_mint[2], base_mint[2]   (lo, hi 128-bit halves)
//   base_amount, quote_amount, buyer_change_amt, seller_change_amt,
//   buyer_fee_amt, seller_fee_amt
//
// Private witnesses (14):
//   a_owner_commit, b_owner_commit
//   a_amount, b_amount
//   a_nonce, a_blinding
//   b_nonce, b_blinding
//   c_nonce, c_blinding
//   d_nonce, d_blinding
//   e_nonce, e_blinding   (only meaningful when buyer_change_amt > 0; else unused)
//   f_nonce, f_blinding   (only meaningful when seller_change_amt > 0; else unused)
template ValidCreate() {
    // ----- Public inputs -----
    signal input note_a_commitment;
    signal input note_b_commitment;
    signal input note_c_commitment;
    signal input note_d_commitment;
    signal input note_e_commitment;
    signal input note_f_commitment;
    signal input quote_mint[2];
    signal input base_mint[2];
    signal input base_amount;
    signal input quote_amount;
    signal input buyer_change_amt;
    signal input seller_change_amt;
    signal input buyer_fee_amt;
    signal input seller_fee_amt;

    // ----- Private witnesses -----
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

    // -----------------------------------------------------------------------
    // (1) note_a is a real note opening — binds (a_owner_commit, a_amount,
    //     quote_mint, a_nonce, a_blinding) to the public note_a_commitment.
    //     The chain already knows note_a_commitment is in the Merkle tree
    //     (via lock_note's VALID_INPUT proof). This circuit chains to that.
    // -----------------------------------------------------------------------
    component hashA = Poseidon(7);
    hashA.inputs[0] <== 2;   // DOMAIN_NOTE
    hashA.inputs[1] <== quote_mint[0];
    hashA.inputs[2] <== quote_mint[1];
    hashA.inputs[3] <== a_amount;
    hashA.inputs[4] <== a_owner_commit;
    hashA.inputs[5] <== a_nonce;
    hashA.inputs[6] <== a_blinding;
    note_a_commitment === hashA.out;

    // -----------------------------------------------------------------------
    // (2) Same for note_b on the seller side.
    // -----------------------------------------------------------------------
    component hashB = Poseidon(7);
    hashB.inputs[0] <== 2;   // DOMAIN_NOTE
    hashB.inputs[1] <== base_mint[0];
    hashB.inputs[2] <== base_mint[1];
    hashB.inputs[3] <== b_amount;
    hashB.inputs[4] <== b_owner_commit;
    hashB.inputs[5] <== b_nonce;
    hashB.inputs[6] <== b_blinding;
    note_b_commitment === hashB.out;

    // -----------------------------------------------------------------------
    // (3) Conservation on the BUYER side. Force the input amount to equal
    //     the sum of the trade leg, change, and fee. Same on seller side.
    //     (The chain enforces the same against lock.amount, but the circuit
    //     must too so the prover can't sneak a smaller a_amount into the
    //     note_c constraint.)
    // -----------------------------------------------------------------------
    a_amount === quote_amount + buyer_change_amt + buyer_fee_amt;
    b_amount === base_amount + seller_change_amt + seller_fee_amt;

    // -----------------------------------------------------------------------
    // (4) note_c: buyer's TRADE leg. In BASE mint, amount = base_amount,
    //     addressed to the BUYER (a_owner_commit). This is the constraint
    //     that prevents output misrouting — `a_owner_commit` is forced by
    //     hashA to equal the value used in note_a. The TEE can't lie about
    //     who note_c goes to.
    // -----------------------------------------------------------------------
    component hashC = Poseidon(7);
    hashC.inputs[0] <== 2;   // DOMAIN_NOTE
    hashC.inputs[1] <== base_mint[0];
    hashC.inputs[2] <== base_mint[1];
    hashC.inputs[3] <== base_amount;
    hashC.inputs[4] <== a_owner_commit;
    hashC.inputs[5] <== c_nonce;
    hashC.inputs[6] <== c_blinding;
    note_c_commitment === hashC.out;

    // -----------------------------------------------------------------------
    // (5) note_d: seller's TRADE leg. In QUOTE mint, amount = quote_amount,
    //     addressed to the SELLER (b_owner_commit).
    // -----------------------------------------------------------------------
    component hashD = Poseidon(7);
    hashD.inputs[0] <== 2;   // DOMAIN_NOTE
    hashD.inputs[1] <== quote_mint[0];
    hashD.inputs[2] <== quote_mint[1];
    hashD.inputs[3] <== quote_amount;
    hashD.inputs[4] <== b_owner_commit;
    hashD.inputs[5] <== d_nonce;
    hashD.inputs[6] <== d_blinding;
    note_d_commitment === hashD.out;

    // -----------------------------------------------------------------------
    // (6) note_e: buyer's CHANGE leg. In QUOTE mint, addressed to the BUYER.
    //
    //     Conditional encoding:
    //       - If buyer_change_amt == 0: note_e_commitment must equal 0.
    //       - If buyer_change_amt != 0: note_e_commitment must equal
    //         Poseidon6(quote_mint, buyer_change_amt, a_owner_commit, e_nonce, e_blinding).
    //
    //     Using IsZero(buyer_change_amt) as a binary selector:
    //       selector = 1 when amt == 0, 0 otherwise
    //       expected = (1 - selector) * computed_hash + selector * 0
    //                = (1 - selector) * computed_hash
    //
    //     We then enforce note_e_commitment === expected.
    // -----------------------------------------------------------------------
    component buyerChangeIsZero = IsZero();
    buyerChangeIsZero.in <== buyer_change_amt;

    component hashE = Poseidon(7);
    hashE.inputs[0] <== 2;   // DOMAIN_NOTE
    hashE.inputs[1] <== quote_mint[0];
    hashE.inputs[2] <== quote_mint[1];
    hashE.inputs[3] <== buyer_change_amt;
    hashE.inputs[4] <== a_owner_commit;
    hashE.inputs[5] <== e_nonce;
    hashE.inputs[6] <== e_blinding;

    signal expectedNoteE;
    expectedNoteE <== (1 - buyerChangeIsZero.out) * hashE.out;
    note_e_commitment === expectedNoteE;

    // -----------------------------------------------------------------------
    // (7) note_f: seller's CHANGE leg. In BASE mint, addressed to the SELLER.
    //     Symmetric to note_e.
    // -----------------------------------------------------------------------
    component sellerChangeIsZero = IsZero();
    sellerChangeIsZero.in <== seller_change_amt;

    component hashF = Poseidon(7);
    hashF.inputs[0] <== 2;   // DOMAIN_NOTE
    hashF.inputs[1] <== base_mint[0];
    hashF.inputs[2] <== base_mint[1];
    hashF.inputs[3] <== seller_change_amt;
    hashF.inputs[4] <== b_owner_commit;
    hashF.inputs[5] <== f_nonce;
    hashF.inputs[6] <== f_blinding;

    signal expectedNoteF;
    expectedNoteF <== (1 - sellerChangeIsZero.out) * hashF.out;
    note_f_commitment === expectedNoteF;
}

component main { public [
    note_a_commitment,
    note_b_commitment,
    note_c_commitment,
    note_d_commitment,
    note_e_commitment,
    note_f_commitment,
    quote_mint,
    base_mint,
    base_amount,
    quote_amount,
    buyer_change_amt,
    seller_change_amt,
    buyer_fee_amt,
    seller_fee_amt
] } = ValidCreate();
