//! Host-side unit tests for the incremental Merkle tree implementation.
//!
//! We only exercise the pure-Rust `poseidon2` and `append_leaf` logic — not any
//! on-chain syscalls. These tests verify the tree math matches the expected
//! shape of the VALID_SPEND circom circuit (depth 20, Poseidon2 at each level).

use vault::merkle::{append_leaf, compute_zero_subtree_roots, empty_root, poseidon2};
use vault::state::{MerkleTree, MERKLE_DEPTH, ROOT_HISTORY_SIZE};

/// A fresh empty shard + the (global) zero-subtree roots `append_leaf` reads.
fn fresh_tree() -> (MerkleTree, [[u8; 32]; MERKLE_DEPTH as usize]) {
    let zeros = compute_zero_subtree_roots().unwrap();
    let tree = MerkleTree {
        leaf_count: 0,
        current_root: empty_root(&zeros).unwrap(),
        roots: [[0u8; 32]; ROOT_HISTORY_SIZE],
        right_path: [[0u8; 32]; MERKLE_DEPTH as usize],
        roots_head: 0,
        tree_id: 0,
        bump: 0,
        _padding: [0u8; 5],
    };
    (tree, zeros)
}

#[test]
fn poseidon2_zero_inputs_not_zero() {
    let z = [0u8; 32];
    let h = poseidon2(&z, &z).unwrap();
    assert_ne!(h, z, "Poseidon(0, 0) must not be zero");
}

#[test]
fn zero_subtree_roots_monotone() {
    let z = compute_zero_subtree_roots().unwrap();
    // Each level's zero root must differ from its neighbours (they're distinct Poseidon outputs).
    for i in 1..z.len() {
        assert_ne!(z[i], z[i - 1], "zero roots collision at level {i}");
    }
}

#[test]
fn append_leaf_increments_count_and_root() {
    let (mut tree, zsr) = fresh_tree();
    let initial_root = tree.current_root;

    let leaf1 = {
        let mut b = [0u8; 32];
        b[31] = 0xaa;
        b
    };
    let new_root = append_leaf(&mut tree, &zsr, leaf1).unwrap();
    assert_eq!(tree.leaf_count, 1);
    assert_ne!(new_root, initial_root);
    assert_eq!(tree.current_root, new_root);
}

#[test]
fn append_two_leaves_root_changes_each_time() {
    let (mut tree, zsr) = fresh_tree();
    let leaf1 = {
        let mut b = [0u8; 32];
        b[31] = 1;
        b
    };
    let leaf2 = {
        let mut b = [0u8; 32];
        b[31] = 2;
        b
    };
    let r1 = append_leaf(&mut tree, &zsr, leaf1).unwrap();
    let r2 = append_leaf(&mut tree, &zsr, leaf2).unwrap();
    assert_eq!(tree.leaf_count, 2);
    assert_ne!(r1, r2);
}

#[test]
fn root_history_ring_buffer_contains_roots() {
    let (mut tree, zsr) = fresh_tree();
    let empty = tree.current_root;

    let leaf = {
        let mut b = [0u8; 32];
        b[31] = 7;
        b
    };
    let r1 = append_leaf(&mut tree, &zsr, leaf).unwrap();

    assert!(tree.contains_root(&r1), "current root should be present");
    assert!(
        tree.contains_root(&empty),
        "prior root should be in history"
    );
}

#[test]
fn deterministic_tree_root_across_two_runs() {
    let leaves: Vec<[u8; 32]> = (0..5)
        .map(|i| {
            let mut b = [0u8; 32];
            b[31] = i as u8;
            b
        })
        .collect();

    let (mut tree1, zsr1) = fresh_tree();
    let (mut tree2, zsr2) = fresh_tree();
    let mut root1 = [0u8; 32];
    let mut root2 = [0u8; 32];
    for leaf in &leaves {
        root1 = append_leaf(&mut tree1, &zsr1, *leaf).unwrap();
        root2 = append_leaf(&mut tree2, &zsr2, *leaf).unwrap();
    }
    assert_eq!(root1, root2);
    assert_eq!(tree1.current_root, tree2.current_root);
}
