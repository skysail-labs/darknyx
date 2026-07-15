pragma circom 2.2.2;

include "../templates/match_batch.circom";

// N=16 — production batch size. The in-TEE matcher pages at most 16 matches
// into one proof/marker batch.
component main { public [merkle_root, fee_rate_bps, protocol_owner_commitment, base_mint_lo, base_mint_hi, quote_mint_lo, quote_mint_hi, price_scale] } = MatchBatch(16);
