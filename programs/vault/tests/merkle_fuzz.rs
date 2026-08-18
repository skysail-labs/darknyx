//! Property-based ("fuzz") tests for the Merkle **index handling** — the two
//! pieces of pure index/bit arithmetic that compute tree roots and would break
//! silently (wrong root → stuck funds / bad proof) rather than panic:
//!
//!   * `merkle::append_leaves` — the batched incremental append (CU-1). Its
//!     whole contract is "byte-identical to N sequential `append_leaf`", so the
//!     trusted-simple `append_leaf` is the **oracle**: we sweep randomized
//!     `(start, batch)` and assert every persisted field matches. This is the
//!     fixed `merkle_host.rs::append_leaves_matches_sequential_append_leaf`
//!     turned into an unbounded, shrinking, random-*byte* sweep.
//!   * `walk_merkle_path_n16` — the N=16 batch-root path walk. Oracle = a naive
//!     full 4-level tree built with the byte-identical host Poseidon
//!     (`darkpool_crypto::poseidon_hash_bytes`); every leaf's path must
//!     reconstruct that tree's root. Plus index-bounds + never-panic invariants.
//!
//! proptest (not cargo-fuzz): the oracles are cheap differentials, so a plain
//! `cargo test` that CI already runs — with minimal-repro shrinking — gets ~all
//! the value with none of the nightly/`fuzz/`-crate infra.

use darkpool_crypto::poseidon::poseidon_hash_bytes;
use proptest::prelude::*;
use vault::instructions::tee_forced_settle_batched::walk_merkle_path_n16;
use vault::merkle::{
    append_leaf, append_leaves, compute_zero_subtree_roots, empty_root, MAX_BATCH_APPEND,
};
use vault::state::{MerkleTree, MERKLE_DEPTH, ROOT_HISTORY_SIZE};

/// `DOMAIN_BATCH_ROOT` — must match `walk_merkle_path_n16`'s `u64_be32(22)`.
const DOMAIN_BATCH_ROOT: u64 = 22;

/// A fresh empty shard + the (global) zero-subtree roots (mirrors merkle_host).
fn fresh_tree() -> (MerkleTree, [[u8; 32]; MERKLE_DEPTH as usize]) {
    let zeros = compute_zero_subtree_roots().unwrap();
    let tree = MerkleTree {
        leaf_count: 0.into(),
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

/// Force a 32-byte value below the BN254 Fr modulus (top byte 0 → < 2^248) so
/// the host Poseidon accepts it — otherwise `poseidon_n`/`poseidon_hash_bytes`
/// return an error, which is a separate (also-tested) path.
fn fr_safe(mut b: [u8; 32]) -> [u8; 32] {
    b[0] = 0;
    b
}

/// A deterministic Fr-safe leaf for building a tree prefix.
fn det_leaf(seed: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[1..9].copy_from_slice(&seed.to_be_bytes());
    b[24..32].copy_from_slice(&seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_be_bytes());
    b
}

/// Big-endian 32-byte encoding of a small u64 (mirrors the private `u64_be32`).
fn u64_be32(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

proptest! {
    // The prefix build is the cost driver — up to `start` sequential appends per
    // case, and host `light-poseidon` is ~350µs/hash. The fixed merkle_host test
    // already sweeps large/boundary starts exhaustively; this proptest's added
    // value is random *bytes* + shrinking, so a modest start range + case count
    // keeps it a ~10s CI test while still crossing the low carry boundaries.
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// **Differential oracle:** `append_leaves` == N sequential `append_leaf`,
    /// byte-for-byte, for a random start index and a random 1..=8-leaf batch.
    #[test]
    fn prop_append_leaves_matches_sequential(
        start in 0u64..=64,
        raw in proptest::collection::vec(proptest::array::uniform32(any::<u8>()), 1..=MAX_BATCH_APPEND),
    ) {
        let (mut base, zsr) = fresh_tree();
        for i in 0..start {
            append_leaf(&mut base, &zsr, det_leaf(i)).unwrap();
        }
        let batch: Vec<[u8; 32]> = raw.into_iter().map(fr_safe).collect();

        // `MerkleTree` is Copy — plain assignment snapshots `base`.
        let mut seq = base;
        let mut seq_root = [0u8; 32];
        for lf in &batch {
            seq_root = append_leaf(&mut seq, &zsr, *lf).unwrap();
        }

        let mut bat = base;
        let bat_root = append_leaves(&mut bat, &zsr, &batch).unwrap();

        prop_assert_eq!(bat_root, seq_root, "root mismatch (start={}, k={})", start, batch.len());
        prop_assert_eq!(bat.current_root, seq.current_root);
        prop_assert_eq!(bat.leaf_count, seq.leaf_count);
        prop_assert_eq!(bat.right_path, seq.right_path);
        // The final root must be spendable, the pre-batch root must survive.
        prop_assert!(bat.contains_root(&bat_root));
        prop_assert!(bat.contains_root(&base.current_root));
    }
}

proptest! {
    /// **Index bounds:** for Fr-safe inputs, `match_index < 16` always succeeds
    /// and `match_index >= 16` is always rejected — never an out-of-range index.
    #[test]
    fn prop_walk_index_bounds(
        leaf in proptest::array::uniform32(any::<u8>()),
        match_index in any::<u8>(),
        proof in proptest::array::uniform4(proptest::array::uniform32(any::<u8>())),
    ) {
        let leaf = fr_safe(leaf);
        let proof = proof.map(fr_safe);
        let r = walk_merkle_path_n16(&leaf, match_index, &proof);
        if match_index >= 16 {
            prop_assert!(r.is_err(), "match_index {} >= 16 must be rejected", match_index);
        } else {
            prop_assert!(r.is_ok(), "Fr-safe input with match_index {} must succeed", match_index);
        }
    }

    /// **Never panics:** arbitrary (possibly ≥ Fr modulus) bytes must return
    /// Ok/Err, never panic or index out of bounds.
    #[test]
    fn prop_walk_never_panics(
        leaf in proptest::array::uniform32(any::<u8>()),
        match_index in any::<u8>(),
        proof in proptest::array::uniform4(proptest::array::uniform32(any::<u8>())),
    ) {
        // Reaching the assert == no panic.
        let _ = walk_merkle_path_n16(&leaf, match_index, &proof);
        prop_assert!(true);
    }

    /// **Differential round-trip:** build a naive 4-level batch tree over 16
    /// random leaves with the byte-identical host Poseidon; every leaf's path
    /// (its 4 siblings) must make `walk_merkle_path_n16` reconstruct that root.
    #[test]
    fn prop_walk_roundtrip_vs_reference(
        raw in proptest::array::uniform16(proptest::array::uniform32(any::<u8>())),
    ) {
        let leaves: [[u8; 32]; 16] = raw.map(fr_safe);
        let domain = u64_be32(DOMAIN_BATCH_ROOT);

        // levels[0] = 16 leaves, levels[l+1] = pairwise Poseidon(domain, L, R).
        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaves.to_vec()];
        for l in 0..4usize {
            let prev = &levels[l];
            let mut next = Vec::with_capacity(prev.len() / 2);
            for pair in prev.chunks(2) {
                next.push(poseidon_hash_bytes(&[domain, pair[0], pair[1]]).unwrap());
            }
            levels.push(next);
        }
        let ref_root = levels[4][0];

        for (i, leaf) in leaves.iter().enumerate() {
            // siblings along leaf i's path: at level l, the ancestor is i>>l and
            // its sibling is (i>>l) ^ 1.
            let mut sibs = [[0u8; 32]; 4];
            let mut idx = i;
            for (l, s) in sibs.iter_mut().enumerate() {
                *s = levels[l][idx ^ 1];
                idx >>= 1;
            }
            let got = walk_merkle_path_n16(leaf, i as u8, &sibs).unwrap();
            prop_assert_eq!(got, ref_root, "leaf {} path did not reconstruct the batch root", i);
        }
    }
}

/// The depth-20 capacity guard is INCLUSIVE-correct: the last slot is allowed,
/// one past is rejected — for both the single and batched append. (Deterministic,
/// not proptest: reaching leaf_count = 2^20 by real appends is infeasible; the
/// guard fires on the count check before touching the frontier.)
#[test]
fn tree_full_boundary_is_rejected() {
    let cap = 1u64 << MERKLE_DEPTH;
    let (mut tree, zsr) = fresh_tree();

    // Exactly full → single append rejected.
    tree.leaf_count = cap.into();
    assert!(append_leaf(&mut tree, &zsr, det_leaf(1)).is_err());

    // One short of full → a 2-leaf batch overflows (last_index == cap).
    tree.leaf_count = (cap - 1).into();
    assert!(append_leaves(&mut tree, &zsr, &[det_leaf(1), det_leaf(2)]).is_err());

    // One short of full → a single append fills the last slot (allowed).
    let mut t2 = tree;
    assert!(append_leaf(&mut t2, &zsr, det_leaf(9)).is_ok());
    assert_eq!(t2.leaf_count, cap);
}
