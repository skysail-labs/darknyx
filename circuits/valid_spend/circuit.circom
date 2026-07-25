pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../templates/merkle.circom";

// VALID_SPEND  (v2 — inner_hash note construction)
//
// Proves:
//   1. Prover knows a note plaintext whose commitment is in the on-chain Merkle tree.
//   2. Prover knows the spending key that owns the note.
//   3. Nullifier is correctly derived from (spendingKey, innerHash).
//   4. Amount is in [0, 2^64) — enforced by Num2Bits(64).
//   5. noteCommitment is exposed as a public output so the on-chain withdraw
//      instruction can bind the caller-supplied note_commitment to this proof,
//      closing the "arbitrary note_commitment bypass" vulnerability.
//
// Public inputs/outputs (in order passed to verifier):
//   merkleRoot, nullifier, tokenMint[0], tokenMint[1], amount, noteCommitment
//
// Private witnesses:
//   spendingKey, ownerCommitmentBlinding, innerHash,
//   merklePath[depth], merkleIndices[depth]
//
// Domain tags — each Poseidon role gets a distinct constant first-input
// to prevent cross-context second-preimage collisions.
// Tag values are arbitrary non-zero field constants; they are committed
// in the circuit so swapping roles would change the VK.
//   DOMAIN_OWNER  = 1   (owner_commitment = Poseidon3(DOMAIN_OWNER, sk, r_owner))
//   DOMAIN_NOTE   = 2   (noteCommitment   = Poseidon6(DOMAIN_NOTE,  mint_lo, mint_hi, amount, owner, innerHash))
//   DOMAIN_NULL   = 3   (nullifier        = Poseidon3(DOMAIN_NULL,  sk, innerHash))
//
// v2 change: the per-note (nonce, blindingR) pair collapses into a single
// `innerHash`, and the nullifier anchors on `innerHash` (amount-independent)
// rather than the commitment. Keeps the mint binding. See
// crates/darkpool-crypto/src/{note,nullifier}.rs `*_v2`.

template ValidSpend(merkleDepth) {
    // ----- Public inputs / outputs -----
    signal input  merkleRoot;
    signal input  nullifier;
    signal input  tokenMint[2];     // [lo_u128, hi_u128]
    signal input  amount;
    // Destination the withdrawn SPL tokens must land in, as [lo_u128, hi_u128]
    // halves of the token-account pubkey (a 256-bit key does not fit one
    // BN254 Fr element — same split as tokenMint). See the binding constraint
    // below; audit 2026-07-25 S-01.
    signal input  recipient[2];
    signal output noteCommitment;   // exposed so on-chain ix can bind to proof

    // ----- Private witnesses -----
    signal input spendingKey;
    signal input ownerCommitmentBlinding;  // r_owner
    signal input innerHash;
    signal input merklePath[merkleDepth];
    signal input merkleIndices[merkleDepth];

    // ── Range check: amount must fit in 64 bits ──────────────────────────────
    // Prevents field-wrap attacks where a prover supplies amount ≈ p − N to
    // satisfy the in-circuit hash while the on-chain u64 encodes something
    // entirely different.
    component amtBits = Num2Bits(64);
    amtBits.in <== amount;

    // ── owner_commitment = Poseidon(DOMAIN_OWNER, spendingKey, r_owner) ─────
    component ownerHash = Poseidon(3);
    ownerHash.inputs[0] <== 1;   // DOMAIN_OWNER
    ownerHash.inputs[1] <== spendingKey;
    ownerHash.inputs[2] <== ownerCommitmentBlinding;
    signal ownerCommit;
    ownerCommit <== ownerHash.out;

    // ── noteCommitment = Poseidon(DOMAIN_NOTE, mint_lo, mint_hi, amount,
    //                             ownerCommit, innerHash) ──────────────────
    component noteHash = Poseidon(6);
    noteHash.inputs[0] <== 2;   // DOMAIN_NOTE
    noteHash.inputs[1] <== tokenMint[0];
    noteHash.inputs[2] <== tokenMint[1];
    noteHash.inputs[3] <== amount;
    noteHash.inputs[4] <== ownerCommit;
    noteHash.inputs[5] <== innerHash;
    noteCommitment <== noteHash.out;

    // ── Merkle inclusion ─────────────────────────────────────────────────────
    component merkle = MerkleTreeChecker(merkleDepth);
    merkle.leaf <== noteCommitment;
    merkle.root <== merkleRoot;
    for (var i = 0; i < merkleDepth; i++) {
        merkle.pathElements[i] <== merklePath[i];
        merkle.pathIndices[i]  <== merkleIndices[i];
    }

    // ── nullifier = Poseidon(DOMAIN_NULL, spendingKey, innerHash) ───────────
    component nullifierHash = Poseidon(3);
    nullifierHash.inputs[0] <== 3;   // DOMAIN_NULL
    nullifierHash.inputs[1] <== spendingKey;
    nullifierHash.inputs[2] <== innerHash;
    nullifier === nullifierHash.out;

    // ── Recipient binding (S-01) ────────────────────────────────────────────
    //
    // WHY THIS EXISTS. Before it, a VALID_SPEND proof authorised "destroy this
    // note for this amount of this mint" and said NOTHING about where the money
    // goes; the vault sent it wherever the instruction's account list pointed.
    // The tuple (note_commitment, nullifier, merkle_root, amount, proof) was
    // therefore a BEARER INSTRUMENT — possession was authorisation, and the
    // legitimate owner held no cryptographic advantage over anyone else holding
    // the same bytes. Exploitable by front-running, and — needing no privileged
    // network position at all — by replaying any withdraw transaction that
    // LANDS AND REVERTS, since a reverted tx publishes the full proof in the
    // ledger permanently while creating neither guard PDA.
    //
    // WHY A DUMMY SQUARE. Declaring a public input is not enough. A signal that
    // appears in no constraint has a zero QAP polynomial, so its IC point does
    // not contribute to the verifier's `vk_x` accumulation and ANY value would
    // satisfy the pairing — the binding would be vacuous. Multiplying it by
    // itself forces it into the constraint system at a cost of one constraint
    // each. This is the standard Tornado-class construction.
    //
    // The squares are intentionally unused afterwards; `<==` both assigns and
    // constrains, which is the whole point.
    signal recipientLoSquare;
    signal recipientHiSquare;
    recipientLoSquare <== recipient[0] * recipient[0];
    recipientHiSquare <== recipient[1] * recipient[1];
}

// Depth 20 → 2^20 ≈ 1M notes.
//
// PUBLIC SIGNAL ORDER (circom emits the OUTPUT first, then public inputs in
// TEMPLATE DECLARATION order — not in the order of the `public [...]` list):
//
//   0 noteCommitment  (output)
//   1 merkleRoot
//   2 nullifier
//   3 tokenMint[0]  (lo)
//   4 tokenMint[1]  (hi)
//   5 amount
//   6 recipient[0]  (lo)
//   7 recipient[1]  (hi)
//
// `withdraw.rs` builds its public-input array in exactly this order and
// `zk_spend_roundtrip.rs` pins it. Reordering the declarations above silently
// permutes what the on-chain verifier checks.
component main { public [merkleRoot, nullifier, tokenMint, amount, recipient] } = ValidSpend(20);
