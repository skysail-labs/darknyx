pragma circom 2.2.2;

include "../templates/valid_merge.circom";

// VALID_MERGE, K=4 (merge 2–4 notes; unused slots are dummy-padded).
// Public signals: outputCommitment, merkleRoot, tokenMint[0..1], nullifiers[0..3] (NR=8).
component main { public [merkleRoot, tokenMint, nullifiers] } = ValidMerge(4, 20);
