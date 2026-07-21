pragma circom 2.2.2;

include "../templates/match_batch_statement_digest.circom";

// Proposed conservative layout: [batch_root, governed-config digest].
component main { public [merkle_root, statement_digest] } = MatchBatchStatementDigest(16, 2);
