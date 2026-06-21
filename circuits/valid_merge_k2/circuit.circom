pragma circom 2.2.2;

include "../templates/valid_merge.circom";

// VALID_MERGE, K=2 (merge 2 notes; 1 real + 1 dummy also valid).
// Public signals: outputCommitment, merkleRoot, tokenMint[0..1], nullifiers[0..1] (NR=6).
component main { public [merkleRoot, tokenMint, nullifiers] } = ValidMerge(2, 20);
