pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/switcher.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

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
//   3. The note's mint + commitment match what's being declared publicly to
//      `lock_note`, while its positive u64 amount remains private.
//
// This is the input-side counterpart to VALID_SPEND. The difference from
// VALID_SPEND:
//   - No nullifier is computed or revealed. The note is not being SPENT here,
//     only locked. Nullification happens later in tee_forced_settle (via
//     ConsumedNoteEntry PDAs) or in withdraw (via NullifierEntry PDAs).
//   - The public handle is `noteUseTag`, not the commitment. The on-chain
//     `lock_note` instruction seeds the NoteLock PDA with it, so it must agree
//     with the proof. The commitment stays a private intermediate here, as it
//     already was in VALID_SPEND.
//
// The mint + merkle_root leak at lock time. The amount and owner_commitment stay
// private; settlement conservation is proven separately by VALID_MATCH_BATCH.
//
// Public inputs:  merkleRoot, noteUseTag, tokenMint[2] (lo|hi 128-bit
//                 halves of the Solana mint pubkey)
// Private inputs: amount, spendingKey, ownerCommitmentBlinding, innerHash,
//                 merklePath[depth], merkleIndices[depth]
//
// The note commitment is NOT public. It is recomputed inside the circuit from
// the private opening, anchors the Merkle proof, and feeds the tag — but a chain
// observer sees only the tag, which they cannot link back to the leaf without
// innerHash. Rationale: crates/darkpool-crypto/src/note_use.rs.
//
// v2 change: (nonce, blindingR) collapse into a single `innerHash`; the
// commitment becomes Poseidon6. Mirrors VALID_SPEND v2 +
// crates/darkpool-crypto/src/note.rs::commitment_from_fields_v2.
template ValidInput(merkleDepth) {
    // ----- Public -----
    signal input merkleRoot;
    signal input noteUseTag;
    signal input tokenMint[2];   // [lo_u128, hi_u128]

    // ----- Private -----
    signal input amount;
    signal input spendingKey;
    signal input ownerCommitmentBlinding;  // r_owner used in owner_commitment
    signal input innerHash;
    signal input merklePath[merkleDepth];
    signal input merkleIndices[merkleDepth];

    // The instruction no longer carries amount as a u64, so the circuit must
    // enforce the same domain itself: a real locked note has 1..2^64-1 units.
    component amountBits = Num2Bits(64);
    amountBits.in <== amount;
    component amountIsZero = IsZero();
    amountIsZero.in <== amount;
    amountIsZero.out === 0;

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
    //
    // PRIVATE now. It used to be the public input the chain keyed the lock on,
    // which is exactly what made a note's lineage followable: the same 32 bytes
    // appeared at deposit, lock, settle and withdraw. It is still computed here
    // and still anchors the Merkle proof — it just never leaves the circuit.
    component noteHash = Poseidon(6);
    noteHash.inputs[0] <== 2;   // DOMAIN_NOTE
    noteHash.inputs[1] <== tokenMint[0];
    noteHash.inputs[2] <== tokenMint[1];
    noteHash.inputs[3] <== amount;
    noteHash.inputs[4] <== ownerCommitment;
    noteHash.inputs[5] <== innerHash;
    signal noteCommitment;
    noteCommitment <== noteHash.out;

    // noteUseTag = Poseidon3(DOMAIN_NOTE_USE=29, noteCommitment, innerHash)
    // Domain tag matches crates/darkpool-crypto/src/note_use.rs::DOMAIN_NOTE_USE.
    //
    // The commitment is an input, not just innerHash. It is what binds amount,
    // owner and mint together, so a tag over innerHash alone would leave those
    // unconstrained at settle — where the input commitment is only a private
    // witness — and let a real lock be paired with an inflated amount.
    component tagHash = Poseidon(3);
    tagHash.inputs[0] <== 29;   // DOMAIN_NOTE_USE
    tagHash.inputs[1] <== noteCommitment;
    tagHash.inputs[2] <== innerHash;
    noteUseTag === tagHash.out;

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
component main { public [merkleRoot, noteUseTag, tokenMint] } = ValidInput(20);
