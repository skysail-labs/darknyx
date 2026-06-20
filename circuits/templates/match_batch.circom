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
//   - Leaf hash    (Poseidon(12) + Poseidon(9), see §7.6 of
//     CRYPTOGRAPHY.md for the field ordering)       ~  930
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
// Leaf-hash arity rationale (NOT a single Poseidon hash):
//   The on-chain Poseidon implementation is `light-poseidon`, which
//   caps Poseidon arity at 12 inputs (its `MAX_X5_LEN = 13` limit).
//   The leaf binds 19 fields, so it has to be split. Splitting as
//   Poseidon(12) feeding into Poseidon(9) — exactly 12 + (8 leaf
//   fields + 1 domain tag) = 12 + 9 inputs — fits inside the cap
//   while keeping the constraint cost ~930/slot. DO NOT collapse
//   this to a single Poseidon(N>12); it will compile fine but the
//   on-chain `compute_match_leaf` (which mirrors this construction
//   verbatim) will fail at runtime inside light-poseidon.
//
// Why `price_commitment` is not bound here (changed from f1e671b):
//   The (clearing_price, batch_slot) pair is folded directly into
//   the top-stage Poseidon(9) instead of via a separate
//   Poseidon3-derived `price_commitment`. The on-chain handler has
//   both fields in the payload already, so the indirection just
//   cost a per-slot Poseidon3 (~264 constraints) and added a
//   binding check the verifier doesn't need.
//
// Domain tags (must stay in sync with the TS prover helper in
// `packages/sdk/tests/helpers/match-batch-prover.ts` AND with the
// on-chain leaf walker in
// `programs/vault/src/instructions/tee_forced_settle_batched.rs`):
//   DOMAIN_NOTE       =  2   (note commitment Poseidon6 v2 — inner_hash)
//   DOMAIN_LEAF_INNER = 20   (Poseidon(12) inner stage of leaf)
//   DOMAIN_LEAF_TOP   = 21   (Poseidon(9) outer stage of leaf)
//   DOMAIN_BATCH_ROOT = 22   (Merkle internal node, Poseidon(3))

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
        slot[i].a_inner           <== a_inner[i];
        slot[i].b_inner           <== b_inner[i];
        slot[i].c_inner           <== c_inner[i];
        slot[i].d_inner           <== d_inner[i];
        slot[i].e_inner           <== e_inner[i];
        slot[i].f_inner           <== f_inner[i];
        slot[i].clearing_price    <== clearing_price[i];
    }

    component merkle = MerkleRoot(N);
    for (var i = 0; i < N; i++) {
        merkle.leaves[i] <== slot[i].leaf;
    }
    merkle_root === merkle.root;
}
