pragma circom 2.2.2;

include "../templates/match_batch.circom";

// N=16 — production batch size. Matches `BATCH_RESULTS_CAPACITY` in
// programs/matching_engine/src/state/batch_results.rs (the on-chain
// batch buffer is sized for 16 matches per `run_batch` call).
component main { public [merkle_root] } = MatchBatch(16);
