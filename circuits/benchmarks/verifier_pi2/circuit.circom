pragma circom 2.2.2;

include "../../../node_modules/circomlib/circuits/poseidon.circom";

template VerifierPi2() {
    signal input merkle_root;
    signal input statement_digest;
    signal input fee_rate_bps;
    signal input protocol_owner_commitment;
    signal input base_mint_lo;
    signal input base_mint_hi;
    signal input quote_mint_lo;
    signal input quote_mint_hi;
    signal input price_scale;
    signal input private_root_copy;

    private_root_copy === merkle_root;
    component digest = Poseidon(8);
    digest.inputs[0] <== 1001;
    digest.inputs[1] <== fee_rate_bps;
    digest.inputs[2] <== protocol_owner_commitment;
    digest.inputs[3] <== base_mint_lo;
    digest.inputs[4] <== base_mint_hi;
    digest.inputs[5] <== quote_mint_lo;
    digest.inputs[6] <== quote_mint_hi;
    digest.inputs[7] <== price_scale;
    statement_digest === digest.out;
}

component main { public [merkle_root, statement_digest] } = VerifierPi2();
