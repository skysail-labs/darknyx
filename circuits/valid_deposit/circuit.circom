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
//   spendingKey, noteSecret
//
// owner_commitment = Poseidon2(DOMAIN_OWNER_V2=32, spendingKey)
// inner_hash       = Poseidon3(DOMAIN_DEPOSIT_INNER_V2=33,
//                              recoveryNonce, noteSecret)
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
    // Seed-derived, keyed on the PUBLIC recoveryNonce so cold recovery can
    // rebuild it from seed + chain with nothing persisted. Without it the inner
    // hash — and therefore the note-use tag derived from it downstream — would
    // be a function of on-chain data plus the wallet-wide ownerCommitment, so
    // one leaked value would recompute a user's whole history. See
    // crates/darkpool-crypto/src/deposit.rs.
    signal input noteSecret;

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

    component ownerHash = Poseidon(2);
    ownerHash.inputs[0] <== 32; // DOMAIN_OWNER_V2
    ownerHash.inputs[1] <== spendingKey;

    component innerHash = Poseidon(3);
    innerHash.inputs[0] <== 33; // DOMAIN_DEPOSIT_INNER_V2
    innerHash.inputs[1] <== recoveryNonce;
    innerHash.inputs[2] <== noteSecret;

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
