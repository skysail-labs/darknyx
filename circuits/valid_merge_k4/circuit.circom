pragma circom 2.2.2;

include "../templates/valid_merge.circom";

// VALID_MERGE, K=4 (merge 1–4 positive notes; unused slots are dummy-padded).
// Public signals: outputCommitment, inputUseTags[0..3], merkleRoot, tokenMint[0..1] (NR=8).
component main { public [merkleRoot, tokenMint] } = ValidMerge(4, 20);
