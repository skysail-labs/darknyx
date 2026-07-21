pragma circom 2.2.2;

include "../templates/match_batch.circom";

// N=16 — production batch size. The in-TEE matcher pages at most 16 matches
// into one proof/marker batch.
component main { public [merkle_root, config_digest] } = MatchBatch(16);
