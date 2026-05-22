pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

// ============================================================================
// MATCH_BATCH (N=2 prototype)
// ============================================================================
//
// Batched validity proof — one Groth16 attesting BOTH `VALID_CREATE` AND
// `VALID_PRICE` for N=2 matches simultaneously, with a single public output:
// the Merkle root of the leaves committing to all per-slot bound values.
//
// The on-chain `tee_forced_settle` handler recomputes the leaf for the
// match it sees, walks a Merkle inclusion path, derives the
// `BatchValidityMarker` PDA address (seeded by the root), and asserts the
// marker exists at that address.
//
// This is the N=2 PROTOTYPE. Once cross-validated against the per-match
// `valid_create` + `valid_price` circuits, we'll generalise via
// `template MatchBatch(N, depth)` and instantiate at N=4 → N=16.
//
// Per-slot constraints (~3800):
//   - VALID_CREATE: a/b/c/d/e/f note-commitment openings, conservation laws.
//     Same Poseidon-7 chains the per-match circuit uses, with the same
//     `DOMAIN_NOTE=2` tag.
//   - VALID_PRICE:  quote == base × price, range checks (Num2Bits 64),
//     price_commitment == Poseidon3(DOMAIN_PRICE=5, clearing_price, batch_slot).
//   - LEAF HASH:    three Poseidon-7 chains + a Poseidon-4 root tag, binding
//     every public field the per-match circuit exposes (16 values total).
//
// Aggregator constraints:
//   - Merkle root over N=2 leaves: 1× Poseidon-2.
//   - Total: ~7800 constraints. Well under PTAU-16 (65k).
//
// Domain tags:
//   DOMAIN_NOTE       = 2   (matches existing valid_create / valid_input / valid_spend)
//   DOMAIN_PRICE      = 5   (matches existing valid_price)
//   DOMAIN_LEAF_INNER = 20  (NEW — for the inner chain hashes in the leaf)
//   DOMAIN_LEAF_TOP   = 21  (NEW — for the top-level leaf hash)
//   DOMAIN_BATCH_ROOT = 22  (NEW — for the Merkle internal-node hashing)
//
// Public output: merkle_root.
// Private inputs: everything else (per-slot arrays of length N=2).

template MatchSlot() {
    // ============================================================
    // PER-SLOT INPUTS (all private at the batch level; the leaf
    // hash commits to the subset the on-chain handler will reread
    // from the settle payload).
    // ============================================================

    // ----- The 14 fields VALID_CREATE made public per match -----
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

    // ----- The 2 fields VALID_PRICE made public per match -----
    signal input price_commitment;
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

    // ----- VALID_PRICE private witnesses -----
    signal input clearing_price;
    // base_amount and quote_amount are reused from VALID_CREATE — same
    // values, same name; we just feed them into VALID_PRICE below.

    // ============================================================
    // OUTPUT: the leaf hash binding all the per-slot public fields.
    // ============================================================
    signal output leaf;

    // ─────────────────────────────────────────────────────────────────
    // VALID_CREATE constraints — copy of `template ValidCreate()` body
    // from circuits/valid_create/circuit.circom. Inlined rather than
    // imported because circom's `include` would also pull in that
    // file's own `component main`. (Refactor to a shared template
    // file can come after the prototype is validated.)
    // ─────────────────────────────────────────────────────────────────

    // (1) note_a opening
    component hashA = Poseidon(7);
    hashA.inputs[0] <== 2;   // DOMAIN_NOTE
    hashA.inputs[1] <== quote_mint_lo;
    hashA.inputs[2] <== quote_mint_hi;
    hashA.inputs[3] <== a_amount;
    hashA.inputs[4] <== a_owner_commit;
    hashA.inputs[5] <== a_nonce;
    hashA.inputs[6] <== a_blinding;
    note_a_commitment === hashA.out;

    // (2) note_b opening
    component hashB = Poseidon(7);
    hashB.inputs[0] <== 2;
    hashB.inputs[1] <== base_mint_lo;
    hashB.inputs[2] <== base_mint_hi;
    hashB.inputs[3] <== b_amount;
    hashB.inputs[4] <== b_owner_commit;
    hashB.inputs[5] <== b_nonce;
    hashB.inputs[6] <== b_blinding;
    note_b_commitment === hashB.out;

    // (3) Conservation per side
    a_amount === quote_amount + buyer_change_amt + buyer_fee_amt;
    b_amount === base_amount + seller_change_amt + seller_fee_amt;

    // (4) note_c — buyer's trade leg
    component hashC = Poseidon(7);
    hashC.inputs[0] <== 2;
    hashC.inputs[1] <== base_mint_lo;
    hashC.inputs[2] <== base_mint_hi;
    hashC.inputs[3] <== base_amount;
    hashC.inputs[4] <== a_owner_commit;
    hashC.inputs[5] <== c_nonce;
    hashC.inputs[6] <== c_blinding;
    note_c_commitment === hashC.out;

    // (5) note_d — seller's trade leg
    component hashD = Poseidon(7);
    hashD.inputs[0] <== 2;
    hashD.inputs[1] <== quote_mint_lo;
    hashD.inputs[2] <== quote_mint_hi;
    hashD.inputs[3] <== quote_amount;
    hashD.inputs[4] <== b_owner_commit;
    hashD.inputs[5] <== d_nonce;
    hashD.inputs[6] <== d_blinding;
    note_d_commitment === hashD.out;

    // (6) note_e — buyer's change (conditional on buyer_change_amt != 0)
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

    // (7) note_f — seller's change (conditional on seller_change_amt != 0)
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
    // VALID_PRICE constraints — body of `template ValidPrice()`.
    // ─────────────────────────────────────────────────────────────────

    // Range checks (u64) on the three values that go into the
    // multiplication constraint below. base_amount and quote_amount
    // already round-trip through the VALID_CREATE constraints above,
    // but the range check is cheap and protects against the prover
    // sneaking a field-overflowing value.
    component priceBits = Num2Bits(64);
    priceBits.in <== clearing_price;

    component baseBits = Num2Bits(64);
    baseBits.in <== base_amount;

    component quoteBits = Num2Bits(64);
    quoteBits.in <== quote_amount;

    // The headline constraint: amounts match the claimed price exactly.
    quote_amount === base_amount * clearing_price;

    // price_commitment = Poseidon3(DOMAIN_PRICE, clearing_price, batch_slot).
    component priceHasher = Poseidon(3);
    priceHasher.inputs[0] <== 5;   // DOMAIN_PRICE
    priceHasher.inputs[1] <== clearing_price;
    priceHasher.inputs[2] <== batch_slot;
    price_commitment === priceHasher.out;

    // ─────────────────────────────────────────────────────────────────
    // LEAF HASH — Poseidon chain over every public field the per-match
    // circuit exposed. The on-chain handler recomputes the same hash
    // from the settle payload it sees, walks the Merkle path, and
    // asserts the root matches the BatchValidityMarker's seed.
    //
    // Chain layout (3 × Poseidon7 + 1 × Poseidon4):
    //   h1 = P7(DOMAIN_LEAF_INNER, note_a, note_b, note_c, note_d, note_e, note_f)
    //   h2 = P7(h1, qm_lo, qm_hi, bm_lo, bm_hi, base_amount, quote_amount)
    //   h3 = P7(h2, buyer_change, seller_change, buyer_fee, seller_fee, 0, 0)
    //   leaf = P4(DOMAIN_LEAF_TOP, h3, price_commitment, batch_slot)
    // ─────────────────────────────────────────────────────────────────

    component leafH1 = Poseidon(7);
    leafH1.inputs[0] <== 20;   // DOMAIN_LEAF_INNER
    leafH1.inputs[1] <== note_a_commitment;
    leafH1.inputs[2] <== note_b_commitment;
    leafH1.inputs[3] <== note_c_commitment;
    leafH1.inputs[4] <== note_d_commitment;
    leafH1.inputs[5] <== note_e_commitment;
    leafH1.inputs[6] <== note_f_commitment;

    component leafH2 = Poseidon(7);
    leafH2.inputs[0] <== leafH1.out;
    leafH2.inputs[1] <== quote_mint_lo;
    leafH2.inputs[2] <== quote_mint_hi;
    leafH2.inputs[3] <== base_mint_lo;
    leafH2.inputs[4] <== base_mint_hi;
    leafH2.inputs[5] <== base_amount;
    leafH2.inputs[6] <== quote_amount;

    component leafH3 = Poseidon(7);
    leafH3.inputs[0] <== leafH2.out;
    leafH3.inputs[1] <== buyer_change_amt;
    leafH3.inputs[2] <== seller_change_amt;
    leafH3.inputs[3] <== buyer_fee_amt;
    leafH3.inputs[4] <== seller_fee_amt;
    leafH3.inputs[5] <== 0;
    leafH3.inputs[6] <== 0;

    component leafTop = Poseidon(4);
    leafTop.inputs[0] <== 21;   // DOMAIN_LEAF_TOP
    leafTop.inputs[1] <== leafH3.out;
    leafTop.inputs[2] <== price_commitment;
    leafTop.inputs[3] <== batch_slot;

    leaf <== leafTop.out;
}


// ============================================================================
// MatchBatch (N=2 prototype)
// ============================================================================
//
// Two slots, single Poseidon(2) at the root. The merkle_root is supplied as
// a PUBLIC input — the prover computes it off-chain and feeds it in; the
// circuit re-derives it from the two leaves and asserts equality. (This is
// the standard pattern for "expose a computed value as a public input"
// in circom — there's no `signal public output`.)
//
// Internal Merkle hash is also domain-tagged so collisions with leaf hashes
// or other Poseidon outputs are not possible.

template MatchBatch2() {
    // ----- Public output (via input-equality pattern) -----
    signal input merkle_root;

    // ----- Per-slot inputs (arrays of length 2) -----
    // VALID_CREATE public fields
    signal input note_a_commitment[2];
    signal input note_b_commitment[2];
    signal input note_c_commitment[2];
    signal input note_d_commitment[2];
    signal input note_e_commitment[2];
    signal input note_f_commitment[2];
    signal input quote_mint_lo[2];
    signal input quote_mint_hi[2];
    signal input base_mint_lo[2];
    signal input base_mint_hi[2];
    signal input base_amount[2];
    signal input quote_amount[2];
    signal input buyer_change_amt[2];
    signal input seller_change_amt[2];
    signal input buyer_fee_amt[2];
    signal input seller_fee_amt[2];
    // VALID_PRICE public fields
    signal input price_commitment[2];
    signal input batch_slot[2];

    // VALID_CREATE private witnesses
    signal input a_owner_commit[2];
    signal input b_owner_commit[2];
    signal input a_amount[2];
    signal input b_amount[2];
    signal input a_nonce[2];
    signal input a_blinding[2];
    signal input b_nonce[2];
    signal input b_blinding[2];
    signal input c_nonce[2];
    signal input c_blinding[2];
    signal input d_nonce[2];
    signal input d_blinding[2];
    signal input e_nonce[2];
    signal input e_blinding[2];
    signal input f_nonce[2];
    signal input f_blinding[2];

    // VALID_PRICE private witnesses
    signal input clearing_price[2];

    // Instantiate two slot validators + wire all inputs.
    component slot[2];
    slot[0] = MatchSlot();
    slot[1] = MatchSlot();

    for (var i = 0; i < 2; i++) {
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
        slot[i].price_commitment  <== price_commitment[i];
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

    // Merkle root: Poseidon(DOMAIN_BATCH_ROOT, leaf0, leaf1).
    // Domain-tagged so internal nodes can't collide with leaves.
    component root = Poseidon(3);
    root.inputs[0] <== 22;   // DOMAIN_BATCH_ROOT
    root.inputs[1] <== slot[0].leaf;
    root.inputs[2] <== slot[1].leaf;

    merkle_root === root.out;
}

component main { public [merkle_root] } = MatchBatch2();
