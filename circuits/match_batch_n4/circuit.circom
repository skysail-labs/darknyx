pragma circom 2.2.2;

include "../templates/match_batch.circom";

// N=4 — intermediate batch size. Useful as a scaling-validation step
// between the N=2 prototype and the N=16 production instance.
component main { public [merkle_root, fee_rate_bps, protocol_owner_commitment, base_mint_lo, base_mint_hi, quote_mint_lo, quote_mint_hi, price_scale] } = MatchBatch(4);
