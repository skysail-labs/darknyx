//! Host-side unit tests for the incremental Merkle tree implementation.
//!
//! We only exercise the pure-Rust `poseidon2` and `append_leaf` logic — not any
//! on-chain syscalls. These tests verify the tree math matches the expected
//! shape of the VALID_SPEND circom circuit (depth 20, Poseidon2 at each level).

use vault::merkle::{
    append_leaf, append_leaves, compute_zero_subtree_roots, empty_root, poseidon2, MAX_BATCH_APPEND,
};
use vault::state::{MerkleTree, MERKLE_DEPTH, ROOT_HISTORY_SIZE};

/// A fresh empty shard + the (global) zero-subtree roots `append_leaf` reads.
fn fresh_tree() -> (MerkleTree, [[u8; 32]; MERKLE_DEPTH as usize]) {
    let zeros = compute_zero_subtree_roots().unwrap();
    let tree = MerkleTree {
        leaf_count: 0u64.into(),
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

/// An Fr-safe-ish leaf: top byte zero so light-poseidon (host) accepts it.
fn leaf(seed: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[1..9].copy_from_slice(&seed.to_be_bytes());
    b[24..32].copy_from_slice(&seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_be_bytes());
    b
}

/// THE correctness gate for the CU-1 batch-append optimization.
///
/// `append_leaves` MUST be byte-identical to N sequential `append_leaf` calls
/// in every persisted field (`leaf_count`, `right_path`, `current_root`) for an
/// arbitrary starting `leaf_count` and batch size. The sequential `append_leaf`
/// (validated by the other tests in this file) is the oracle. We sweep starts
/// that hit every tricky index alignment — powers of two, their neighbours,
/// odd/even boundaries — crossed with every batch size 1..=MAX_BATCH_APPEND.
#[test]
fn append_leaves_matches_sequential_append_leaf() {
    // Starts chosen to exercise: empty tree, odd/even first index, the carry
    // boundaries at 2^l and 2^l±1, and a deep index so the final walk-up spans
    // many real (non-zero) right_path levels.
    let starts: &[u64] = &[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14, 15, 16, 17, 30, 31, 32, 33, 62, 63, 64, 65, 127, 128,
        129, 250, 255, 256, 257, 1000, 1023, 1024,
    ];

    for &start in starts {
        // Build the shared prefix ONCE, then clone for each batch size.
        let (mut base, zsr) = fresh_tree();
        for i in 0..start {
            append_leaf(&mut base, &zsr, leaf(i)).unwrap();
        }

        for k in 1..=MAX_BATCH_APPEND {
            // Two leaf patterns per (start, k): a "spread" set and a set whose
            // low bytes alias, to be sure pairing keys off the index not value.
            for pattern in 0..2u64 {
                let batch: Vec<[u8; 32]> = (0..k as u64)
                    .map(|j| leaf(0x1000 + start * 16 + j + pattern * 7))
                    .collect();

                // `MerkleTree` is `Copy`; plain assignment snapshots `base`.
                let mut seq = base;
                let mut seq_root = [0u8; 32];
                for lf in &batch {
                    seq_root = append_leaf(&mut seq, &zsr, *lf).unwrap();
                }

                let mut bat = base;
                let bat_root = append_leaves(&mut bat, &zsr, &batch).unwrap();

                assert_eq!(
                    bat_root, seq_root,
                    "root mismatch at start={start} k={k} pattern={pattern}"
                );
                assert_eq!(
                    bat.current_root, seq.current_root,
                    "current_root mismatch at start={start} k={k} pattern={pattern}"
                );
                assert_eq!(
                    bat.leaf_count, seq.leaf_count,
                    "leaf_count mismatch at start={start} k={k} pattern={pattern}"
                );
                assert_eq!(
                    bat.right_path, seq.right_path,
                    "right_path mismatch at start={start} k={k} pattern={pattern}"
                );
                // The final root must be spendable (present in the ring).
                assert!(
                    bat.contains_root(&bat_root),
                    "batch final root must be in the recent-roots ring \
                     (start={start} k={k} pattern={pattern})"
                );
                // The pre-batch root must survive in history too (a client
                // mid-flight against it can still spend).
                assert!(
                    bat.contains_root(&base.current_root),
                    "pre-batch root must remain in history (start={start} k={k})"
                );
            }
        }
    }
}

/// A zero-length batch is a no-op that returns the current root unchanged.
#[test]
fn append_leaves_empty_is_noop() {
    let (mut tree, zsr) = fresh_tree();
    append_leaf(&mut tree, &zsr, leaf(42)).unwrap();
    let before_root = tree.current_root;
    let before_count = tree.leaf_count;
    let before_rp = tree.right_path;
    let r = append_leaves(&mut tree, &zsr, &[]).unwrap();
    assert_eq!(r, before_root);
    assert_eq!(tree.current_root, before_root);
    assert_eq!(tree.leaf_count, before_count);
    assert_eq!(tree.right_path, before_rp);
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
