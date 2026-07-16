pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// VALID_DEPOSIT
//
// Proves that a public deposit commitment is a well-formed, recoverable note
// for the public mint and amount without exposing its wallet-wide
// owner_commitment or its per-note inner_hash.
//
// Public inputs:
//   noteCommitment, tokenMint[2], amount, recoveryNonce
// Private inputs:
//   spendingKey, ownerCommitmentBlinding
//
// owner_commitment = Poseidon3(DOMAIN_OWNER=1, spendingKey, r_owner)
// inner_hash       = Poseidon3(DOMAIN_DEPOSIT_INNER=27,
//                              owner_commitment, recoveryNonce)
// note_commitment  = Poseidon6(DOMAIN_NOTE=2, mint_lo, mint_hi, amount,
//                              owner_commitment, inner_hash)
//
// recoveryNonce is a field-safe pseudorandom value derived client-side from
// the master seed + deposit index and published with the deposit. A recovering
// wallet re-derives owner_commitment from its seed, then reconstructs the
// hidden inner_hash from this nonce. Observers learn neither private value.
template ValidDeposit() {
    // ----- Public -----
    signal input noteCommitment;
    signal input tokenMint[2];       // Solana mint [lo_u128, hi_u128]
    signal input amount;
    signal input recoveryNonce;

    // ----- Private -----
    signal input spendingKey;
    signal input ownerCommitmentBlinding;

    // Mint halves are semantic u128 values, not arbitrary Fr elements.
    component mintLoBits = Num2Bits(128);
    mintLoBits.in <== tokenMint[0];
    component mintHiBits = Num2Bits(128);
    mintHiBits.in <== tokenMint[1];

    // The instruction carries a u64 and rejects zero. Repeat both constraints
    // in-circuit so the proof remains self-contained and audit-friendly.
    component amountBits = Num2Bits(64);
    amountBits.in <== amount;
    component amountIsZero = IsZero();
    amountIsZero.in <== amount;
    amountIsZero.out === 0;

    component ownerHash = Poseidon(3);
    ownerHash.inputs[0] <== 1;  // DOMAIN_OWNER
    ownerHash.inputs[1] <== spendingKey;
    ownerHash.inputs[2] <== ownerCommitmentBlinding;

    component innerHash = Poseidon(3);
    innerHash.inputs[0] <== 27; // DOMAIN_DEPOSIT_INNER
    innerHash.inputs[1] <== ownerHash.out;
    innerHash.inputs[2] <== recoveryNonce;

    component noteHash = Poseidon(6);
    noteHash.inputs[0] <== 2;   // DOMAIN_NOTE
    noteHash.inputs[1] <== tokenMint[0];
    noteHash.inputs[2] <== tokenMint[1];
    noteHash.inputs[3] <== amount;
    noteHash.inputs[4] <== ownerHash.out;
    noteHash.inputs[5] <== innerHash.out;

    noteCommitment === noteHash.out;
}

component main { public [noteCommitment, tokenMint, amount, recoveryNonce] } =
    ValidDeposit();
