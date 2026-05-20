pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

// VALID_WALLET_CREATE
//
// Proves the prover correctly computed a User Commitment from knowledge of
// three keys plus their individual blinding factors.
//
// User Commitment construction:
//   rootHash   = Poseidon(DOMAIN_ROOT,  rootKey[0], rootKey[1], r0)
//   spendHash  = Poseidon(DOMAIN_SPEND, spendingKey, r1)
//   viewHash   = Poseidon(DOMAIN_VIEW,  viewingKey,  r2)
//   leafRoot   = Poseidon(DOMAIN_LEAF,  rootHash, spendHash)
//   userCommit = Poseidon(DOMAIN_TOP,   leafRoot, viewHash)
//
// Domain tags prevent cross-role second-preimage collisions across the five
// distinct Poseidon calls:
//   DOMAIN_ROOT  = 10
//   DOMAIN_SPEND = 11
//   DOMAIN_VIEW  = 12
//   DOMAIN_LEAF  = 13
//   DOMAIN_TOP   = 14
//
// Range constraints:
//   rootKey[0] and rootKey[1] are 128-bit halves of an Ed25519 pubkey.
//   Without Num2Bits(128) a prover could supply out-of-range halves that
//   reduce to the same Fr — making user_commitment malleable. The range check
//   closes that gap.
//   NOTE: Range checks on field elements are NOT automatic in circom. They
//   must be added explicitly for every signal that is semantically bounded
//   (e.g. amounts, key halves). The field arithmetic only guarantees values
//   live in Fr = [0, p); sub-field ranges require explicit bit decomposition.
//
// Public inputs:  userCommitment
// Private inputs: rootKey[2], spendingKey, viewingKey, r0, r1, r2

template ValidWalletCreate() {
    // ----- Public -----
    signal input userCommitment;

    // ----- Private -----
    signal input rootKey[2];   // Ed25519 pubkey split [lo_u128, hi_u128]
    signal input spendingKey;
    signal input viewingKey;
    signal input r0;
    signal input r1;
    signal input r2;

    // ── Range checks on rootKey halves ───────────────────────────────────────
    // Each half is a 128-bit integer. Without this check a prover could supply
    // rootKey[0] = p + k for any k < 2^128 and produce a distinct witness that
    // hashes identically (because p + k ≡ k mod p). That makes the registered
    // user_commitment reachable by multiple distinct key representations.
    component rkLoBits = Num2Bits(128);
    rkLoBits.in <== rootKey[0];

    component rkHiBits = Num2Bits(128);
    rkHiBits.in <== rootKey[1];

    // ── rootHash = Poseidon(DOMAIN_ROOT, rootKey[0], rootKey[1], r0) ─────────
    component rootHasher = Poseidon(4);
    rootHasher.inputs[0] <== 10;  // DOMAIN_ROOT
    rootHasher.inputs[1] <== rootKey[0];
    rootHasher.inputs[2] <== rootKey[1];
    rootHasher.inputs[3] <== r0;

    // ── spendHash = Poseidon(DOMAIN_SPEND, spendingKey, r1) ──────────────────
    component spendHasher = Poseidon(3);
    spendHasher.inputs[0] <== 11; // DOMAIN_SPEND
    spendHasher.inputs[1] <== spendingKey;
    spendHasher.inputs[2] <== r1;

    // ── viewHash = Poseidon(DOMAIN_VIEW, viewingKey, r2) ─────────────────────
    component viewHasher = Poseidon(3);
    viewHasher.inputs[0] <== 12; // DOMAIN_VIEW
    viewHasher.inputs[1] <== viewingKey;
    viewHasher.inputs[2] <== r2;

    // ── leafRoot = Poseidon(DOMAIN_LEAF, rootHash, spendHash) ────────────────
    component leafPair = Poseidon(3);
    leafPair.inputs[0] <== 13; // DOMAIN_LEAF
    leafPair.inputs[1] <== rootHasher.out;
    leafPair.inputs[2] <== spendHasher.out;

    // ── userCommitment = Poseidon(DOMAIN_TOP, leafRoot, viewHash) ────────────
    component topHasher = Poseidon(3);
    topHasher.inputs[0] <== 14; // DOMAIN_TOP
    topHasher.inputs[1] <== leafPair.out;
    topHasher.inputs[2] <== viewHasher.out;

    userCommitment === topHasher.out;
}

component main { public [userCommitment] } = ValidWalletCreate();
