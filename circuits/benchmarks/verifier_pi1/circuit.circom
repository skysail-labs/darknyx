pragma circom 2.2.2;

include "../../../node_modules/circomlib/circuits/poseidon.circom";

template VerifierPi1() {
    signal input statement_digest;
    signal input merkle_root;
    signal input fee_rate_bps;
    signal input protocol_owner_commitment;
    signal input base_mint_lo;
    signal input base_mint_hi;
    signal input quote_mint_lo;
    signal input quote_mint_hi;
    signal input price_scale;

    component digest = Poseidon(9);
    digest.inputs[0] <== 1002;
    digest.inputs[1] <== merkle_root;
    digest.inputs[2] <== fee_rate_bps;
    digest.inputs[3] <== protocol_owner_commitment;
    digest.inputs[4] <== base_mint_lo;
    digest.inputs[5] <== base_mint_hi;
    digest.inputs[6] <== quote_mint_lo;
    digest.inputs[7] <== quote_mint_hi;
    digest.inputs[8] <== price_scale;
    statement_digest === digest.out;
}

component main { public [statement_digest] } = VerifierPi1();
