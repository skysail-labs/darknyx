pragma circom 2.2.2;

// Synthetic verifier probe for the current eight-public-input layout. The
// private sum keeps every public signal constrained without adding a public
// output. It is intentionally tiny: the litesvm test isolates verifier cost.
template VerifierPi8() {
    signal input merkle_root;
    signal input fee_rate_bps;
    signal input protocol_owner_commitment;
    signal input base_mint_lo;
    signal input base_mint_hi;
    signal input quote_mint_lo;
    signal input quote_mint_hi;
    signal input price_scale;
    signal input private_sum;

    private_sum === merkle_root + fee_rate_bps + protocol_owner_commitment
        + base_mint_lo + base_mint_hi + quote_mint_lo + quote_mint_hi
        + price_scale;
}

component main { public [merkle_root, fee_rate_bps, protocol_owner_commitment, base_mint_lo, base_mint_hi, quote_mint_lo, quote_mint_hi, price_scale] } = VerifierPi8();
