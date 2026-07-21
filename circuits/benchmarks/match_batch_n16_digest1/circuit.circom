pragma circom 2.2.2;

include "../templates/match_batch_statement_digest.circom";

// Maximum-compression comparison: one digest over root + governed config.
component main { public [statement_digest] } = MatchBatchStatementDigest(16, 1);
