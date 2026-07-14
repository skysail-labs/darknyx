pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "./merkle.circom";

// VALID_MERGE(K) — in-pool note consolidation (K inputs → 1 output).
//
// Proves the prover owns K input notes (all the SAME owner + mint, each in the
// on-chain Merkle tree) and mints ONE output note whose amount is their sum.
// There is NO external transfer — pure consolidation. The merged note is then
// used as an over-collateralized order; the trade returns any surplus as change.
//
// DUMMY-SLOT PADDING. A K-slot circuit can merge FEWER than K real notes: an
// inactive slot (`isActive[i] == 0`) skips its membership binding, contributes
// 0 to the sum, and emits a public input-commitment of 0 (a real commitment is
// a Poseidon6 output, never 0). So K=4 can merge 2–4 notes, and the wallet pads;
// orders larger than K notes chain merges.
//
// SHARED OWNER. A single (spendingKey, ownerCommitmentBlinding) proves all
// active inputs belong to the same owner. Each slot has its own
// (amount, innerHash, Merkle path).
//
// Domain tags (match VALID_SPEND / darkpool-crypto):
//   DOMAIN_OWNER = 1, DOMAIN_NOTE = 2.
//
// Public signals (snarkjs order: outputs first, then public inputs):
//   outputCommitment, inputCommitments[0..K-1], merkleRoot, tokenMint[0], tokenMint[1]
//   → NR = 4 + K  (K=2 → 6, K=4 → 8).
//
// C-01 (audit): the K input-note commitments are PUBLIC outputs (dummy slots
// emit 0) so the on-chain merge inits a commitment-keyed `ConsumedNoteEntry`
// per active input — the SAME consume-once guard `withdraw` + settle use.
// Previously merge exposed per-input NULLIFIERS and keyed a `NullifierEntry`, a
// guard disjoint from settle's `ConsumedNoteEntry`, so the same note could be
// consumed once by merge and once by settle (double-spend). The nullifier is
// unnecessary here: ownership is proven by the owner-bound note commitment's
// Merkle membership, and double-spend is now guarded on the commitment.

template ValidMerge(K, merkleDepth) {
    // ----- Public inputs -----
    signal input merkleRoot;
    signal input tokenMint[2];      // [lo_u128, hi_u128] — one mint for all

    // ----- Public outputs -----
    signal output outputCommitment;      // the merged note (= sum of active inputs)
    signal output inputCommitments[K];   // active slots: the note commitment; dummy slots: 0

    // ----- Private witnesses -----
    signal input spendingKey;             // shared owner
    signal input ownerCommitmentBlinding; // r_owner (shared)
    signal input outputInnerHash;         // recoverable inner_hash of the merged note
    signal input isActive[K];             // 1 = real note, 0 = dummy padding
    signal input amount[K];
    signal input innerHash[K];
    signal input merklePath[K][merkleDepth];
    signal input merkleIndices[K][merkleDepth];

    // ── Shared owner commitment = Poseidon(DOMAIN_OWNER, sk, r_owner) ──────────
    component ownerHash = Poseidon(3);
    ownerHash.inputs[0] <== 1; // DOMAIN_OWNER
    ownerHash.inputs[1] <== spendingKey;
    ownerHash.inputs[2] <== ownerCommitmentBlinding;
    signal ownerCommit;
    ownerCommit <== ownerHash.out;

    component amtBits[K];
    component noteHash[K];
    component rootFromLeaf[K];

    signal computedNote[K];
    signal computedRoot[K];
    signal contrib[K];
    signal sumAcc[K + 1];
    sumAcc[0] <== 0;

    for (var i = 0; i < K; i++) {
        // isActive is boolean.
        isActive[i] * (1 - isActive[i]) === 0;

        // Amount must fit 64 bits (dummy slots set amount = 0).
        amtBits[i] = Num2Bits(64);
        amtBits[i].in <== amount[i];

        // Input note commitment = Poseidon(DOMAIN_NOTE, mint, amount, owner, inner).
        noteHash[i] = Poseidon(6);
        noteHash[i].inputs[0] <== 2; // DOMAIN_NOTE
        noteHash[i].inputs[1] <== tokenMint[0];
        noteHash[i].inputs[2] <== tokenMint[1];
        noteHash[i].inputs[3] <== amount[i];
        noteHash[i].inputs[4] <== ownerCommit;
        noteHash[i].inputs[5] <== innerHash[i];
        computedNote[i] <== noteHash[i].out;

        // Compute this leaf's Merkle root; bind it ONLY for active slots.
        rootFromLeaf[i] = MerkleRootFromLeaf(merkleDepth);
        rootFromLeaf[i].leaf <== computedNote[i];
        for (var j = 0; j < merkleDepth; j++) {
            rootFromLeaf[i].pathElements[j] <== merklePath[i][j];
            rootFromLeaf[i].pathIndices[j]  <== merkleIndices[i][j];
        }
        computedRoot[i] <== rootFromLeaf[i].root;
        isActive[i] * (computedRoot[i] - merkleRoot) === 0;

        // C-01: PUBLIC input commitment. Active slot → the real note commitment
        // (a non-zero Poseidon6 output the on-chain guard consumes); dummy slot
        // → 0 (skipped on-chain, mirroring the old zero-nullifier convention).
        inputCommitments[i] <== isActive[i] * computedNote[i];

        // Sum only active amounts.
        contrib[i] <== isActive[i] * amount[i];
        sumAcc[i + 1] <== sumAcc[i] + contrib[i];
    }

    // Output note: same owner + mint, amount = Σ active inputs (≤ 2^64).
    signal outputAmount;
    outputAmount <== sumAcc[K];
    component outAmtBits = Num2Bits(64);
    outAmtBits.in <== outputAmount;

    component outHash = Poseidon(6);
    outHash.inputs[0] <== 2; // DOMAIN_NOTE
    outHash.inputs[1] <== tokenMint[0];
    outHash.inputs[2] <== tokenMint[1];
    outHash.inputs[3] <== outputAmount;
    outHash.inputs[4] <== ownerCommit;
    outHash.inputs[5] <== outputInnerHash;
    outputCommitment <== outHash.out;
}
