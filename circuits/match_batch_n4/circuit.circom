pragma circom 2.2.2;

include "../templates/match_batch.circom";

// N=4 — intermediate batch size. Useful as a scaling-validation step
// between the N=2 prototype and the N=16 production instance.
component main { public [merkle_root, config_digest] } = MatchBatch(4);
