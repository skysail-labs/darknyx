pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../templates/merkle.circom";

// VALID_SPEND
//
// Proves:
//   1. Prover knows a note plaintext whose commitment is in the on-chain Merkle tree.
//   2. Prover knows the spending key that owns the note.
//   3. Amount is in [0, 2^64) — enforced by Num2Bits(64).
//   4. noteUseTag is exposed as a public output so the on-chain withdraw
//      instruction can bind the caller-supplied handle to this proof, closing
//      the "arbitrary note_commitment bypass" vulnerability. The tag, not the
//      commitment: publishing the commitment here would relink the withdrawal
//      to the note's Merkle leaf and to every earlier use of that note.
//
// Public inputs/outputs: SEVEN signals, with `noteUseTag` FIRST (it is an
// output, and circom emits outputs ahead of inputs). The canonical, numbered
// ordering lives beside the `component main` declaration at the bottom of this
// file — see it there rather than trusting a second copy here, because a
// duplicate list is exactly what went stale when S-01 added `recipient`.
//
// Private witnesses:
//   spendingKey, innerHash,
//   merklePath[depth], merkleIndices[depth]
//
// Domain tags — each Poseidon role gets a distinct constant first-input
// to prevent cross-context second-preimage collisions.
// Tag values are arbitrary non-zero field constants; they are committed
// in the circuit so swapping roles would change the VK.
//   DOMAIN_OWNER_V2 = 32 (owner_commitment = Poseidon2(32, sk))
//   DOMAIN_NOTE   = 2   (noteCommitment   = Poseidon6(DOMAIN_NOTE,  mint_lo, mint_hi, amount, owner, innerHash))
//   DOMAIN_NOTE_USE = 29 (noteUseTag      = Poseidon3(29, noteCommitment, innerHash))

template ValidSpend(merkleDepth) {
    // ----- Public inputs / outputs -----
    signal input  merkleRoot;
    signal input  tokenMint[2];     // [lo_u128, hi_u128]
    signal input  amount;
    // Destination the withdrawn SPL tokens must land in, as [lo_u128, hi_u128]
    // halves of the token-account pubkey (a 256-bit key does not fit one
    // BN254 Fr element — same split as tokenMint). See the binding constraint
    // below; audit 2026-07-25 S-01.
    signal input  recipient[2];
    // The public handle the withdraw instruction binds to. NOT the commitment:
    // publishing that would relink the note to its Merkle leaf and undo the
    // unlinkability the tag exists for. The commitment is still computed below
    // and still anchors the Merkle proof — it just stays inside the circuit.
    signal output noteUseTag;

    // ----- Private witnesses -----
    signal input spendingKey;
    signal input innerHash;
    signal input merklePath[merkleDepth];
    signal input merkleIndices[merkleDepth];

    // ── Range check: amount must fit in 64 bits ──────────────────────────────
    // Prevents field-wrap attacks where a prover supplies amount ≈ p − N to
    // satisfy the in-circuit hash while the on-chain u64 encodes something
    // entirely different.
    component amtBits = Num2Bits(64);
    amtBits.in <== amount;

    // ── owner_commitment = Poseidon2(DOMAIN_OWNER_V2, spendingKey) ──────────
    component ownerHash = Poseidon(2);
    ownerHash.inputs[0] <== 32;  // DOMAIN_OWNER_V2
    ownerHash.inputs[1] <== spendingKey;
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
    signal noteCommitment;
    noteCommitment <== noteHash.out;

    // ── noteUseTag = Poseidon(DOMAIN_NOTE_USE, noteCommitment, innerHash) ────
    //
    // The commitment is an input, not just innerHash: it is what binds amount,
    // owner and mint, so a tag over the inner alone would leave those
    // unconstrained wherever the commitment is private.
    component useTagHash = Poseidon(3);
    useTagHash.inputs[0] <== 29;   // DOMAIN_NOTE_USE
    useTagHash.inputs[1] <== noteCommitment;
    useTagHash.inputs[2] <== innerHash;
    noteUseTag <== useTagHash.out;

    // ── Merkle inclusion ─────────────────────────────────────────────────────
    component merkle = MerkleTreeChecker(merkleDepth);
    merkle.leaf <== noteCommitment;
    merkle.root <== merkleRoot;
    for (var i = 0; i < merkleDepth; i++) {
        merkle.pathElements[i] <== merklePath[i];
        merkle.pathIndices[i]  <== merkleIndices[i];
    }

    // ── Recipient binding (S-01) ────────────────────────────────────────────
    //
    // WHY THIS EXISTS. Before it, a VALID_SPEND proof authorised "destroy this
    // note for this amount of this mint" and said NOTHING about where the money
    // goes; the vault sent it wherever the instruction's account list pointed.
    // The tuple (note-use tag, merkle root, amount, proof) would otherwise be
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
//   0 noteUseTag  (output)
//   1 merkleRoot
//   2 tokenMint[0]  (lo)
//   3 tokenMint[1]  (hi)
//   4 amount
//   5 recipient[0]  (lo)
//   6 recipient[1]  (hi)
//
// `withdraw.rs` builds its public-input array in exactly this order and
// `zk_spend_roundtrip.rs` pins it. Reordering the declarations above silently
// permutes what the on-chain verifier checks.
component main { public [merkleRoot, tokenMint, amount, recipient] } = ValidSpend(20);
