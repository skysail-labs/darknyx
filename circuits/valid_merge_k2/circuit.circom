pragma circom 2.2.2;

include "../templates/valid_merge.circom";

// VALID_MERGE, K=2 (merge 1–2 positive notes; all-dummy is invalid).
// Public signals: outputCommitment, inputCommitments[0..1], merkleRoot, tokenMint[0..1] (NR=6).
component main { public [merkleRoot, tokenMint] } = ValidMerge(2, 20);
