pragma circom 2.2.2;

// Paths resolve relative to the project root via -l node_modules at compile time.
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/switcher.circom";

// Merkle tree membership proof using Poseidon(arity=2) at each level.
// Matches the on-chain light-concurrent-merkle-tree node hashing convention:
//   parent = Poseidon(left, right)
//
// Extracted from the per-circuit files to avoid drift between valid_spend and
// valid_input — any fix here applies to both.
template MerkleTreeChecker(depth) {
    signal input leaf;
    signal input root;
    signal input pathElements[depth];
    // pathIndices[i] = 0  → sibling is on the right  (current node is left child)
    // pathIndices[i] = 1  → sibling is on the left   (current node is right child)
    signal input pathIndices[depth];

    component hashers[depth];
    component switchers[depth];

    signal levelHashes[depth + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // Boolean constraint on path selector.
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        switchers[i] = Switcher();
        switchers[i].sel <== pathIndices[i];
        switchers[i].L   <== levelHashes[i];
        switchers[i].R   <== pathElements[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        levelHashes[i + 1] <== hashers[i].out;
    }

    root === levelHashes[depth];
}

// Same Merkle hashing as MerkleTreeChecker, but COMPUTES the root from the leaf
// + path instead of asserting it equals a given root. Used by VALID_MERGE, where
// each input slot's membership must be bound CONDITIONALLY (an inactive/dummy
// padding slot has no real membership), so the caller does
// `isActive[i] * (computedRoot[i] - merkleRoot) === 0` rather than a hard `===`.
template MerkleRootFromLeaf(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    component hashers[depth];
    component switchers[depth];

    signal levelHashes[depth + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        switchers[i] = Switcher();
        switchers[i].sel <== pathIndices[i];
        switchers[i].L   <== levelHashes[i];
        switchers[i].R   <== pathElements[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[depth];
}
