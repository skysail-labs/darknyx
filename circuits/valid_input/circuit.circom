pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/switcher.circom";

// Merkle tree membership proof using Poseidon(arity=2) per level.
// Identical to the equivalent template in valid_spend/circuit.circom — kept
// inline here so each circuit is self-contained for easier auditing.
template MerkleTreeChecker(depth) {
    signal input leaf;
    signal input root;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    component hashers[depth];
    component switchers[depth];

    signal levelHashes[depth + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        switchers[i] = Switcher();
        switchers[i].sel <== pathIndices[i];
        switchers[i].L <== levelHashes[i];
        switchers[i].R <== pathElements[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        levelHashes[i + 1] <== hashers[i].out;
    }

    root === levelHashes[depth];
}

// VALID_INPUT
//
// Proves, at lock-note time, that:
//   1. The prover OWNS the note (knows the spending key whose
//      owner_commitment hashes into the note).
//   2. The note exists in the on-chain Merkle tree at a known recent root.
//   3. The note's (mint, amount, commitment) match what's being declared
//      publicly to `lock_note`.
//
// This is the input-side counterpart to VALID_SPEND. The difference from
// VALID_SPEND:
//   - No nullifier is computed or revealed. The note is not being SPENT here,
//     only locked. Nullification happens later in tee_forced_settle (via
//     ConsumedNoteEntry PDAs) or in withdraw (via NullifierEntry PDAs).
//   - `noteCommitment` is now a PUBLIC input. The on-chain `lock_note`
//     instruction uses it as the seed for the NoteLock PDA, so it must agree
//     with the proof. (In VALID_SPEND it's a private intermediate.)
//
// The mint, amount, and merkle_root leak at lock time — the same information
// is anyway about to be revealed by `tee_forced_settle`. The owner_commitment
// stays private; the lock does not deanonymise the user beyond what the
// match itself reveals.
//
// Public inputs:  merkleRoot, noteCommitment, tokenMint[2] (lo|hi 128-bit
//                 halves of the Solana mint pubkey), amount
// Private inputs: spendingKey, ownerCommitmentBlinding, innerHash,
//                 merklePath[depth], merkleIndices[depth]
//
// v2 change: (nonce, blindingR) collapse into a single `innerHash`; the
// commitment becomes Poseidon6. Mirrors VALID_SPEND v2 +
// crates/darkpool-crypto/src/note.rs::commitment_from_fields_v2.
template ValidInput(merkleDepth) {
    // ----- Public -----
    signal input merkleRoot;
    signal input noteCommitment;
    signal input tokenMint[2];   // [lo_u128, hi_u128]
    signal input amount;

    // ----- Private -----
    signal input spendingKey;
    signal input ownerCommitmentBlinding;  // r_owner used in owner_commitment
    signal input innerHash;
    signal input merklePath[merkleDepth];
    signal input merkleIndices[merkleDepth];

    // owner_commitment = Poseidon3(DOMAIN_OWNER=1, spendingKey, ownerCommitmentBlinding)
    // Domain tag matches crates/darkpool-crypto/src/note.rs::DOMAIN_OWNER.
    component ownerHash = Poseidon(3);
    ownerHash.inputs[0] <== 1;   // DOMAIN_OWNER
    ownerHash.inputs[1] <== spendingKey;
    ownerHash.inputs[2] <== ownerCommitmentBlinding;
    signal ownerCommitment;
    ownerCommitment <== ownerHash.out;

    // noteCommitment = Poseidon6(DOMAIN_NOTE=2, mint_lo, mint_hi, amount, owner, innerHash)
    // Domain tag matches crates/darkpool-crypto/src/note.rs::DOMAIN_NOTE.
    component noteHash = Poseidon(6);
    noteHash.inputs[0] <== 2;   // DOMAIN_NOTE
    noteHash.inputs[1] <== tokenMint[0];
    noteHash.inputs[2] <== tokenMint[1];
    noteHash.inputs[3] <== amount;
    noteHash.inputs[4] <== ownerCommitment;
    noteHash.inputs[5] <== innerHash;
    noteCommitment === noteHash.out;

    // Constraint: note is in the Merkle tree at merkleRoot.
    component merkle = MerkleTreeChecker(merkleDepth);
    merkle.leaf <== noteCommitment;
    merkle.root <== merkleRoot;
    for (var i = 0; i < merkleDepth; i++) {
        merkle.pathElements[i] <== merklePath[i];
        merkle.pathIndices[i]  <== merkleIndices[i];
    }
}

// Tree depth 20 — must match programs/vault/src/state.rs::MERKLE_DEPTH.
component main { public [merkleRoot, noteCommitment, tokenMint, amount] } = ValidInput(20);
