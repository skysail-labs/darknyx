pragma circom 2.2.2;

include "../templates/match_batch.circom";

// N=2 instantiation — smallest non-trivial batch. Used as the
// cross-validation gate against the per-match valid_create + valid_price
// circuits during Phase 1a. Once N=16 is the default, N=2 stays around
// for fast unit tests and as a documentation-grade reference instance.
component main { public [merkle_root, config_digest] } = MatchBatch(2);
