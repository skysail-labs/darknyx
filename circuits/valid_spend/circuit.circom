pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../templates/merkle.circom";

// VALID_SPEND
//
// Proves:
//   1. Prover knows a note plaintext whose commitment is in the on-chain Merkle tree.
//   2. Prover knows the spending key that owns the note.
//   3. Nullifier is correctly derived from (spendingKey, noteCommitment).
//   4. Amount is in [0, 2^64) — enforced by Num2Bits(64).
//   5. noteCommitment is exposed as a public output so the on-chain withdraw
//      instruction can bind the caller-supplied note_commitment to this proof,
//      closing the "arbitrary note_commitment bypass" vulnerability.
//
// Public inputs/outputs (in order passed to verifier):
//   merkleRoot, nullifier, tokenMint[0], tokenMint[1], amount, noteCommitment
//
// Private witnesses:
//   spendingKey, ownerCommitmentBlinding, nonce, blindingR,
//   merklePath[depth], merkleIndices[depth]
//
// Domain tags — each Poseidon role gets a distinct constant first-input
// to prevent cross-context second-preimage collisions.
// Tag values are arbitrary non-zero field constants; they are committed
// in the circuit so swapping roles would change the VK.
//   DOMAIN_OWNER  = 1   (owner_commitment = Poseidon3(DOMAIN_OWNER, sk, r_owner))
//   DOMAIN_NOTE   = 2   (noteCommitment   = Poseidon7(DOMAIN_NOTE,  mint_lo, mint_hi, amount, owner, nonce, r))
//   DOMAIN_NULL   = 3   (nullifier        = Poseidon3(DOMAIN_NULL,  sk, noteCommitment))

template ValidSpend(merkleDepth) {
    // ----- Public inputs / outputs -----
    signal input  merkleRoot;
    signal input  nullifier;
    signal input  tokenMint[2];     // [lo_u128, hi_u128]
    signal input  amount;
    signal output noteCommitment;   // exposed so on-chain ix can bind to proof

    // ----- Private witnesses -----
    signal input spendingKey;
    signal input ownerCommitmentBlinding;  // r_owner
    signal input nonce;
    signal input blindingR;
    signal input merklePath[merkleDepth];
    signal input merkleIndices[merkleDepth];

    // ── Range check: amount must fit in 64 bits ──────────────────────────────
    // Prevents field-wrap attacks where a prover supplies amount ≈ p − N to
    // satisfy the in-circuit hash while the on-chain u64 encodes something
    // entirely different.
    component amtBits = Num2Bits(64);
    amtBits.in <== amount;

    // ── owner_commitment = Poseidon(DOMAIN_OWNER, spendingKey, r_owner) ─────
    component ownerHash = Poseidon(3);
    ownerHash.inputs[0] <== 1;   // DOMAIN_OWNER
    ownerHash.inputs[1] <== spendingKey;
    ownerHash.inputs[2] <== ownerCommitmentBlinding;
    signal ownerCommit;
    ownerCommit <== ownerHash.out;

    // ── noteCommitment = Poseidon(DOMAIN_NOTE, mint_lo, mint_hi, amount,
    //                             ownerCommit, nonce, blindingR) ────────────
    component noteHash = Poseidon(7);
    noteHash.inputs[0] <== 2;   // DOMAIN_NOTE
    noteHash.inputs[1] <== tokenMint[0];
    noteHash.inputs[2] <== tokenMint[1];
    noteHash.inputs[3] <== amount;
    noteHash.inputs[4] <== ownerCommit;
    noteHash.inputs[5] <== nonce;
    noteHash.inputs[6] <== blindingR;
    noteCommitment <== noteHash.out;

    // ── Merkle inclusion ─────────────────────────────────────────────────────
    component merkle = MerkleTreeChecker(merkleDepth);
    merkle.leaf <== noteCommitment;
    merkle.root <== merkleRoot;
    for (var i = 0; i < merkleDepth; i++) {
        merkle.pathElements[i] <== merklePath[i];
        merkle.pathIndices[i]  <== merkleIndices[i];
    }

    // ── nullifier = Poseidon(DOMAIN_NULL, spendingKey, noteCommitment) ───────
    component nullifierHash = Poseidon(3);
    nullifierHash.inputs[0] <== 3;   // DOMAIN_NULL
    nullifierHash.inputs[1] <== spendingKey;
    nullifierHash.inputs[2] <== noteCommitment;
    nullifier === nullifierHash.out;
}

// Depth 20 → 2^20 ≈ 1M notes.
// Public signals order: merkleRoot, nullifier, tokenMint[0], tokenMint[1], amount, noteCommitment
component main { public [merkleRoot, nullifier, tokenMint, amount] } = ValidSpend(20);
