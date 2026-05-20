pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

// VALID_PRICE
//
// Proves that a TEE-computed clearing price is consistent with the matched
// order legs — i.e. that:
//
//   quote_amount == base_amount * clearing_price   (integer, no rounding)
//
// This closes the gap where a compromised TEE could lie about the clearing
// price without being detected by the on-chain conservation law (which only
// checks that input amounts equal output amounts, not how they were split).
//
// Additionally proves range containment for all u64 inputs to prevent
// field-wrap attacks identical to the one blocked in VALID_SPEND:
//   clearing_price in [0, 2^64)
//   base_amount    in [0, 2^64)
//   quote_amount   in [0, 2^64)
//
// Finally, a price_commitment binds this proof to a specific settlement via
// Poseidon3(DOMAIN_PRICE=5, clearing_price, batch_slot), preventing proof
// replay across batches.
//
// Public inputs:  price_commitment, batch_slot
// Private inputs: clearing_price, base_amount, quote_amount
//
// Domain tag:
//   DOMAIN_PRICE = 5   (price_commitment = Poseidon3(DOMAIN_PRICE, clearing_price, batch_slot))
//
// Note: quote_amount = base_amount * clearing_price must hold exactly. The
// circuit uses a quadratic constraint:
//   quote_amount === base_amount * clearing_price
// This is one R1CS constraint and requires no extra components.
//
// Overflow guard: base_amount and clearing_price are both 64-bit, so their
// product is at most 2^128 — well within BN254 Fr (~2^254). No overflow is
// possible in the field arithmetic.

template ValidPrice() {
    // ----- Public -----
    signal input price_commitment;
    signal input batch_slot;

    // ----- Private -----
    signal input clearing_price;
    signal input base_amount;
    signal input quote_amount;

    // ── Range checks: all three are u64 values ────────────────────────────────
    component priceBits = Num2Bits(64);
    priceBits.in <== clearing_price;

    component baseBits = Num2Bits(64);
    baseBits.in <== base_amount;

    component quoteBits = Num2Bits(64);
    quoteBits.in <== quote_amount;

    // ── Price consistency: quote == base * price ─────────────────────────────
    // One quadratic constraint. Both sides are < 2^128 so no field wrap.
    quote_amount === base_amount * clearing_price;

    // ── price_commitment = Poseidon3(DOMAIN_PRICE=5, clearing_price, batch_slot) ─
    // Binds this proof to a specific (price, batch) pair. The on-chain handler
    // checks this commitment matches the payload's clearing_price and batch_slot,
    // preventing proof reuse across batches or price substitution.
    component commitHasher = Poseidon(3);
    commitHasher.inputs[0] <== 5;   // DOMAIN_PRICE
    commitHasher.inputs[1] <== clearing_price;
    commitHasher.inputs[2] <== batch_slot;
    price_commitment === commitHasher.out;
}

// Public signals order (wire index order):
//   wire 1: price_commitment
//   wire 2: batch_slot
component main { public [price_commitment, batch_slot] } = ValidPrice();
