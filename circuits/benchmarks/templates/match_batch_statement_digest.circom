pragma circom 2.2.2;

include "../../templates/match_batch.circom";

// Benchmark-only wrapper around the production MatchBatch template.
//
// It deliberately leaves MatchBatch itself untouched and changes only which
// top-level signals are public. MODE=2 keeps the per-batch Merkle root public
// and replaces the seven governed fields with one Poseidon digest. MODE=1
// replaces all eight fields with one digest. The large production constraint
// body is therefore byte-for-byte the same source in every benchmark arm.
//
template MatchBatchStatementDigest(N, MODE) {
    signal input merkle_root;
    signal input statement_digest;
    signal input fee_rate_bps;
    signal input protocol_owner_commitment;
    signal input base_mint_lo;
    signal input base_mint_hi;
    signal input quote_mint_lo;
    signal input quote_mint_hi;
    signal input price_scale;

    signal input note_a_commitment[N];
    signal input note_b_commitment[N];
    signal input note_c_commitment[N];
    signal input note_d_commitment[N];
    signal input note_e_commitment[N];
    signal input note_f_commitment[N];
    signal input note_fee_base_commitment[N];
    signal input note_fee_quote_commitment[N];
    signal input base_amount[N];
    signal input quote_amount[N];
    signal input buyer_change_amt[N];
    signal input seller_change_amt[N];
    signal input buyer_fee_amt[N];
    signal input seller_fee_amt[N];
    signal input batch_slot[N];
    signal input is_active[N];

    signal input a_owner_commit[N];
    signal input b_owner_commit[N];
    signal input a_amount[N];
    signal input b_amount[N];
    signal input a_inner[N];
    signal input b_inner[N];
    signal input clearing_price[N];
    signal input price_remainder[N];

    component batch = MatchBatch(N);
    batch.merkle_root <== merkle_root;
    batch.fee_rate_bps <== fee_rate_bps;
    batch.protocol_owner_commitment <== protocol_owner_commitment;
    batch.base_mint_lo <== base_mint_lo;
    batch.base_mint_hi <== base_mint_hi;
    batch.quote_mint_lo <== quote_mint_lo;
    batch.quote_mint_hi <== quote_mint_hi;
    batch.price_scale <== price_scale;

    for (var i = 0; i < N; i++) {
        batch.note_a_commitment[i] <== note_a_commitment[i];
        batch.note_b_commitment[i] <== note_b_commitment[i];
        batch.note_c_commitment[i] <== note_c_commitment[i];
        batch.note_d_commitment[i] <== note_d_commitment[i];
        batch.note_e_commitment[i] <== note_e_commitment[i];
        batch.note_f_commitment[i] <== note_f_commitment[i];
        batch.note_fee_base_commitment[i] <== note_fee_base_commitment[i];
        batch.note_fee_quote_commitment[i] <== note_fee_quote_commitment[i];
        batch.base_amount[i] <== base_amount[i];
        batch.quote_amount[i] <== quote_amount[i];
        batch.buyer_change_amt[i] <== buyer_change_amt[i];
        batch.seller_change_amt[i] <== seller_change_amt[i];
        batch.buyer_fee_amt[i] <== buyer_fee_amt[i];
        batch.seller_fee_amt[i] <== seller_fee_amt[i];
        batch.batch_slot[i] <== batch_slot[i];
        batch.is_active[i] <== is_active[i];
        batch.a_owner_commit[i] <== a_owner_commit[i];
        batch.b_owner_commit[i] <== b_owner_commit[i];
        batch.a_amount[i] <== a_amount[i];
        batch.b_amount[i] <== b_amount[i];
        batch.a_inner[i] <== a_inner[i];
        batch.b_inner[i] <== b_inner[i];
        batch.clearing_price[i] <== clearing_price[i];
        batch.price_remainder[i] <== price_remainder[i];
    }

    if (MODE == 2) {
        component config_digest = Poseidon(8);
        // Benchmark-local value; this is NOT a reserved protocol domain tag.
        config_digest.inputs[0] <== 1001;
        config_digest.inputs[1] <== fee_rate_bps;
        config_digest.inputs[2] <== protocol_owner_commitment;
        config_digest.inputs[3] <== base_mint_lo;
        config_digest.inputs[4] <== base_mint_hi;
        config_digest.inputs[5] <== quote_mint_lo;
        config_digest.inputs[6] <== quote_mint_hi;
        config_digest.inputs[7] <== price_scale;
        statement_digest === config_digest.out;
    }

    if (MODE == 1) {
        component full_digest = Poseidon(9);
        // Benchmark-local value; this is NOT a reserved protocol domain tag.
        full_digest.inputs[0] <== 1002;
        full_digest.inputs[1] <== merkle_root;
        full_digest.inputs[2] <== fee_rate_bps;
        full_digest.inputs[3] <== protocol_owner_commitment;
        full_digest.inputs[4] <== base_mint_lo;
        full_digest.inputs[5] <== base_mint_hi;
        full_digest.inputs[6] <== quote_mint_lo;
        full_digest.inputs[7] <== quote_mint_hi;
        full_digest.inputs[8] <== price_scale;
        statement_digest === full_digest.out;
    }
}
