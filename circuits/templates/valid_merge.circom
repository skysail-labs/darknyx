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
// inactive slot (`isActive[i] == 0`) skips its membership + nullifier binding,
// contributes 0 to the sum, and MUST carry a public nullifier of 0 (a real
// nullifier is a Poseidon3 output, never 0). So K=4 can merge 2–4 notes, and the
// wallet pads; orders larger than K notes chain merges.
//
// SHARED OWNER. A single (spendingKey, ownerCommitmentBlinding) proves all
// active inputs belong to the same owner. Each slot has its own
// (amount, innerHash, Merkle path).
//
// Domain tags (match VALID_SPEND / darkpool-crypto):
//   DOMAIN_OWNER = 1, DOMAIN_NOTE = 2, DOMAIN_NULL = 3.
//
// Public signals (snarkjs order: outputs first, then public inputs):
//   outputCommitment, merkleRoot, tokenMint[0], tokenMint[1], nullifiers[0..K-1]
//   → NR = 4 + K  (K=2 → 6, K=4 → 8).

template ValidMerge(K, merkleDepth) {
    // ----- Public inputs -----
    signal input merkleRoot;
    signal input tokenMint[2];      // [lo_u128, hi_u128] — one mint for all
    signal input nullifiers[K];     // active slots: real; dummy slots: 0

    // ----- Public output -----
    signal output outputCommitment; // the merged note (= sum of active inputs)

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
    component nullHash[K];

    signal computedNote[K];
    signal computedRoot[K];
    signal computedNull[K];
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

        // Nullifier = Poseidon(DOMAIN_NULL, sk, inner). Active: must equal the
        // public nullifier. Inactive: the public nullifier must be 0.
        nullHash[i] = Poseidon(3);
        nullHash[i].inputs[0] <== 3; // DOMAIN_NULL
        nullHash[i].inputs[1] <== spendingKey;
        nullHash[i].inputs[2] <== innerHash[i];
        computedNull[i] <== nullHash[i].out;
        isActive[i] * (computedNull[i] - nullifiers[i]) === 0;
        (1 - isActive[i]) * nullifiers[i] === 0;

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
