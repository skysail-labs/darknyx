//! Leaf + root + Merkle inclusion path computation for
//! VALID_MATCH_BATCH.
//!
//! Rust port of `computeBatchLeaf`, `computeBatchRoot`, and the batch
//! inclusion-path construction in
//! `packages/sdk/tests/helpers/match-batch-prover.ts`. Every
//! Poseidon call goes through `darkpool_crypto::poseidon_hash_bytes`
//! (which delegates to `light-poseidon` host-side, byte-equivalent
//! with circomlibjs).
//!
//! Wire spec — leaf hash layout MUST match `template MatchSlot()`
//! in `circuits/templates/match_batch.circom`:
//!
//! ```text
//!   leaf = Poseidon11(
//!     DOMAIN_LEAF_V2 (= 23),
//!     is_active,
//!     note_a, note_b, note_c, note_d, note_e, note_f,
//!     note_fee_base, note_fee_quote,
//!     batch_slot,
//!   )
//! ```
//!
//! Internal Merkle node: `Poseidon3(DOMAIN_BATCH_ROOT = 22, left,
//! right)`.
//!
//! Commitment-only (amount-privacy, P1b): the six note commitments + two fee
//! notes bind the amounts/mints/price transitively (each commitment is itself
//! a Poseidon6 of mint+amount+owner+inner), so the leaf no longer hashes the
//! plaintext amounts the old two-stage (Poseidon12+Poseidon9) leaf did — and
//! they can leave the settle payload entirely. 11 inputs ≤ 12
//! (= `light-poseidon::MAX_X5_LEN - 1`), so a single Poseidon suffices and the
//! on-chain handler can re-derive it via `solana_poseidon::hashv`; keep it
//! ≤ 12 (CLAUDE.md §5.3).

use darkpool_crypto::{poseidon_hash_bytes, CryptoError};

use super::witness::{u64_to_be32, u8_tag_to_be32, MatchSlotWitness};

// ── Domain-separation tags. MUST match the circuit constants. ───
pub const DOMAIN_BATCH_ROOT: u8 = 22;
/// Commitment-only leaf (amount-privacy, P1b). A fresh tag avoids any
/// overlap with the old two-stage leaf (the retired DOMAIN_LEAF_INNER=20 /
/// DOMAIN_LEAF_TOP=21 tags, removed when the leaf collapsed to one Poseidon11).
pub const DOMAIN_LEAF_V2: u8 = 23;
/// The production circuit is instantiated at N=16. Smaller powers of two are
/// used by unit/integration tests and share this implementation.
pub const MAX_BATCH_LEAVES: usize = 16;
/// log2(MAX_BATCH_LEAVES). The settle instruction carries this many siblings.
pub const MAX_BATCH_DEPTH: usize = 4;

#[derive(thiserror::Error, Debug)]
pub enum LeafError {
    #[error("Poseidon failed: {0}")]
    Poseidon(#[from] CryptoError),
    #[error("N (= {0}) must be a power of two and at least 1")]
    InvalidBatchSize(usize),
    #[error("N (= {0}) exceeds the supported maximum of 16 leaves")]
    BatchTooLarge(usize),
    #[error("index {idx} out of range for N={n}")]
    IndexOutOfRange { idx: usize, n: usize },
    #[error("slot {idx} does not match the batch market/protocol public inputs")]
    MixedBatchConfig { idx: usize },
}

/// Compute one slot's leaf. Identical bytes as the circuit's
/// `template MatchSlot()` output.
///
/// Commitment-only (amount-privacy, P1b): `Poseidon11(DOMAIN_LEAF_V2,
/// is_active, note_a..note_f, note_fee_base, note_fee_quote, batch_slot)`. The
/// amounts/mints/price the old two-stage leaf hashed are bound transitively
/// through the note commitments, so they no longer appear in the leaf (and can
/// leave the settle payload). The two fee-note commitments are included so the
/// every match's atomic on-chain append of them is proof-backed.
pub fn compute_batch_leaf(slot: &MatchSlotWitness) -> Result<[u8; 32], LeafError> {
    let leaf = poseidon_hash_bytes(&[
        u8_tag_to_be32(DOMAIN_LEAF_V2),
        u64_to_be32(u64::from(slot.is_active)),
        slot.note_a_commitment,
        slot.note_b_commitment,
        slot.note_c_commitment,
        slot.note_d_commitment,
        slot.note_e_commitment,
        slot.note_f_commitment,
        slot.note_fee_base_commitment,
        slot.note_fee_quote_commitment,
        u64_to_be32(slot.batch_slot),
    ])?;
    Ok(leaf)
}

/// Compute the binary-tree Merkle root over `leaves`. `leaves.len()`
/// must be a power of two ≥ 1. Internal node hash:
/// `Poseidon3(DOMAIN_BATCH_ROOT, left, right)`.
pub fn compute_batch_root(leaves: &[[u8; 32]]) -> Result<[u8; 32], LeafError> {
    let n = leaves.len();
    if n == 0 || (n & (n - 1)) != 0 {
        return Err(LeafError::InvalidBatchSize(n));
    }
    if n == 1 {
        // A 1-leaf "tree" is just the leaf itself; no Poseidon
        // round runs. Matches the TS loop's early-out shape.
        return Ok(leaves[0]);
    }

    let tag = u8_tag_to_be32(DOMAIN_BATCH_ROOT);
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks_exact(2) {
            let parent = poseidon_hash_bytes(&[tag, chunk[0], chunk[1]])?;
            next.push(parent);
        }
        level = next;
    }
    Ok(level[0])
}

/// One batch tree's root and every inclusion path. Constructing this value
/// hashes each internal node exactly once (15 hashes at production N=16), then
/// extracts all paths from the retained levels. The prior per-index helper
/// rebuilt the whole tree 16 times (240 hashes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchMerklePaths {
    root: [u8; 32],
    paths: [[[u8; 32]; MAX_BATCH_DEPTH]; MAX_BATCH_LEAVES],
    leaf_count: usize,
    depth: usize,
    internal_hash_count: usize,
}

impl BatchMerklePaths {
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Fixed-width sibling array consumed directly by Tx D. Entries beyond
    /// `depth()` are zero for the smaller N=1/2/4/8 test circuits.
    pub fn path(&self, index: usize) -> Result<&[[u8; 32]; MAX_BATCH_DEPTH], LeafError> {
        if index >= self.leaf_count {
            return Err(LeafError::IndexOutOfRange {
                idx: index,
                n: self.leaf_count,
            });
        }
        Ok(&self.paths[index])
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Exposed for the performance regression: a full binary tree has N-1
    /// internal nodes and this builder hashes each one once.
    pub fn internal_hash_count(&self) -> usize {
        self.internal_hash_count
    }
}

/// Build the binary tree once and extract every inclusion path from its saved
/// levels. Storage is stack-backed for the maximum 16-leaf circuit: 16 leaves
/// + 8 + 4 + 2 + 1 = 31 nodes.
pub fn build_batch_merkle_paths(leaves: &[[u8; 32]]) -> Result<BatchMerklePaths, LeafError> {
    let n = leaves.len();
    if n == 0 || (n & (n - 1)) != 0 {
        return Err(LeafError::InvalidBatchSize(n));
    }
    if n > MAX_BATCH_LEAVES {
        return Err(LeafError::BatchTooLarge(n));
    }

    let tag = u8_tag_to_be32(DOMAIN_BATCH_ROOT);
    let depth = n.trailing_zeros() as usize;
    let mut nodes = [[0u8; 32]; 2 * MAX_BATCH_LEAVES - 1];
    nodes[..n].copy_from_slice(leaves);
    let mut level_offsets = [0usize; MAX_BATCH_DEPTH + 1];
    let mut level_offset = 0usize;
    let mut next_offset = n;
    let mut width = n;
    let mut internal_hash_count = 0usize;

    for saved_offset in level_offsets.iter_mut().take(depth) {
        *saved_offset = level_offset;
        for pair in 0..(width / 2) {
            let left = nodes[level_offset + pair * 2];
            let right = nodes[level_offset + pair * 2 + 1];
            nodes[next_offset + pair] = poseidon_hash_bytes(&[tag, left, right])?;
            internal_hash_count += 1;
        }
        level_offset = next_offset;
        width /= 2;
        next_offset += width;
    }
    level_offsets[depth] = level_offset;

    let root = nodes[level_offset];
    let mut paths = [[[0u8; 32]; MAX_BATCH_DEPTH]; MAX_BATCH_LEAVES];
    for (leaf_index, path) in paths.iter_mut().enumerate().take(n) {
        let mut node_index = leaf_index;
        for level in 0..depth {
            path[level] = nodes[level_offsets[level] + (node_index ^ 1)];
            node_index >>= 1;
        }
    }

    Ok(BatchMerklePaths {
        root,
        paths,
        leaf_count: n,
        depth,
        internal_hash_count,
    })
}

/// Deliberately slow reference implementation retained only to prove the
/// optimized all-path builder is byte-identical at every supported N/index.
#[cfg(test)]
fn merkle_inclusion_path_reference(
    leaves: &[[u8; 32]],
    index: usize,
) -> Result<(Vec<[u8; 32]>, Vec<u8>), LeafError> {
    let n = leaves.len();
    if n == 0 || (n & (n - 1)) != 0 {
        return Err(LeafError::InvalidBatchSize(n));
    }
    if index >= n {
        return Err(LeafError::IndexOutOfRange { idx: index, n });
    }

    let tag = u8_tag_to_be32(DOMAIN_BATCH_ROOT);
    let mut current_level = leaves.to_vec();
    let mut current_index = index;
    let mut siblings = Vec::new();
    let mut indices = Vec::new();
    while current_level.len() > 1 {
        siblings.push(current_level[current_index ^ 1]);
        indices.push((current_index & 1) as u8);
        current_level = current_level
            .chunks_exact(2)
            .map(|pair| poseidon_hash_bytes(&[tag, pair[0], pair[1]]))
            .collect::<Result<Vec<_>, _>>()?;
        current_index >>= 1;
    }

    Ok((siblings, indices))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::witness::dummy_slot;

    /// Pinned leaf for the all-zero `dummy_slot()`. If this value
    /// drifts, EITHER the Poseidon implementation in
    /// `darkpool-crypto` has changed (cross-environment break) OR
    /// this module's tag/arity ordering has drifted from the
    /// circuit (would silently break VALID_MATCH_BATCH on-chain).
    /// Either way: fail loud, fix at the source.
    const DUMMY_LEAF_HEX: &str = "11a820f978145dacd319f64f0fa544500ea5d0069ff25d9015fb01f1b3edd35c";

    #[test]
    fn dummy_slot_leaf_is_pinned() {
        let leaf = compute_batch_leaf(&dummy_slot()).unwrap();
        assert_eq!(hex::encode(leaf), DUMMY_LEAF_HEX);
    }

    #[test]
    fn batch_root_of_one_leaf_is_the_leaf() {
        let leaf = compute_batch_leaf(&dummy_slot()).unwrap();
        let root = compute_batch_root(&[leaf]).unwrap();
        assert_eq!(root, leaf);
    }

    /// Pin the root of a 2-leaf tree of identical dummy slots so
    /// the Poseidon3(DOMAIN_BATCH_ROOT, leaf, leaf) call is
    /// regression-guarded. Drifts would silently break inclusion
    /// proofs on-chain.
    #[test]
    fn batch_root_of_two_identical_dummies_is_pinned() {
        let leaf = compute_batch_leaf(&dummy_slot()).unwrap();
        let root = compute_batch_root(&[leaf, leaf]).unwrap();
        let want = "1c078cbfb951f80d3773c82adb49bd4339cbf5e1b08b18fe6cb87763b2b0fd5b";
        // Pin the value byte-for-byte so a future Poseidon refactor
        // surfaces here. (The prior literal was a dead pin —
        // `let _ = want` with no assertion — and had drifted from the
        // real root; captured fresh from this code path, which the
        // N=2/N=16 prover roundtrips cross-validate against the
        // circuit's own root.)
        assert_eq!(hex::encode(root), want, "batch-root pin drifted");
        // Sanity: not the same as the leaf (Poseidon3 is non-
        // trivial even with identical inputs).
        assert_ne!(root, leaf);
    }

    #[test]
    fn batch_root_size_must_be_power_of_two() {
        let leaf = compute_batch_leaf(&dummy_slot()).unwrap();
        let three = vec![leaf, leaf, leaf];
        let err = compute_batch_root(&three).unwrap_err();
        assert!(matches!(err, LeafError::InvalidBatchSize(3)));

        let zero: Vec<[u8; 32]> = vec![];
        let err = compute_batch_root(&zero).unwrap_err();
        assert!(matches!(err, LeafError::InvalidBatchSize(0)));
    }

    #[test]
    fn inclusion_path_depth_matches_log2_n() {
        let leaf = compute_batch_leaf(&dummy_slot()).unwrap();
        // N=8 → depth=3.
        let leaves = vec![leaf; 8];
        let tree = build_batch_merkle_paths(&leaves).unwrap();
        assert_eq!(tree.depth(), 3);
        assert_eq!(tree.path(0).unwrap()[3], [0u8; 32]);
    }

    #[test]
    fn inclusion_path_index_out_of_range() {
        let leaf = compute_batch_leaf(&dummy_slot()).unwrap();
        let leaves = vec![leaf; 4];
        let tree = build_batch_merkle_paths(&leaves).unwrap();
        let err = tree.path(4).unwrap_err();
        assert!(matches!(err, LeafError::IndexOutOfRange { idx: 4, n: 4 }));
    }

    #[test]
    fn optimized_paths_match_reference_and_reconstruct_root() {
        let tag = u8_tag_to_be32(DOMAIN_BATCH_ROOT);
        for n in [1usize, 2, 4, 8, 16] {
            let mut leaves = Vec::with_capacity(n);
            for i in 0..n {
                let mut slot = dummy_slot();
                slot.batch_slot = i as u64 + 1;
                leaves.push(compute_batch_leaf(&slot).unwrap());
            }
            let root = compute_batch_root(&leaves).unwrap();
            let tree = build_batch_merkle_paths(&leaves).unwrap();
            assert_eq!(tree.root(), root, "root differs at N={n}");

            for idx in 0..n {
                let (reference_siblings, reference_indices) =
                    merkle_inclusion_path_reference(&leaves, idx).unwrap();
                assert_eq!(
                    &tree.path(idx).unwrap()[..tree.depth()],
                    reference_siblings.as_slice(),
                    "siblings differ at N={n}, index={idx}"
                );

                let mut current = leaves[idx];
                for (level, sibling) in tree.path(idx).unwrap()[..tree.depth()].iter().enumerate() {
                    let direction = ((idx >> level) & 1) as u8;
                    assert_eq!(direction, reference_indices[level]);
                    let (left, right) = if direction == 0 {
                        (current, *sibling)
                    } else {
                        (*sibling, current)
                    };
                    current = poseidon_hash_bytes(&[tag, left, right]).unwrap();
                }
                assert_eq!(current, root, "path fails at N={n}, index={idx}");
            }
        }
    }

    #[test]
    fn n16_tree_hashes_each_internal_node_once() {
        let leaf = compute_batch_leaf(&dummy_slot()).unwrap();
        let tree = build_batch_merkle_paths(&[leaf; 16]).unwrap();
        assert_eq!(tree.internal_hash_count(), 15);
        assert_eq!(tree.leaf_count(), 16);
        assert_eq!(tree.depth(), 4);
        // The removed per-index construction performed this 15-hash build for
        // every leaf: 16 * 15 = 240 hashes.
        assert_eq!(16 * tree.internal_hash_count(), 240);
    }

    #[test]
    fn all_path_builder_rejects_more_than_the_circuit_maximum() {
        let leaf = compute_batch_leaf(&dummy_slot()).unwrap();
        let err = build_batch_merkle_paths(&[leaf; 32]).unwrap_err();
        assert!(matches!(err, LeafError::BatchTooLarge(32)));
    }

    #[test]
    fn distinct_slots_produce_distinct_leaves() {
        let mut s1 = dummy_slot();
        let mut s2 = dummy_slot();
        s1.batch_slot = 1;
        s2.batch_slot = 2;
        let leaf1 = compute_batch_leaf(&s1).unwrap();
        let leaf2 = compute_batch_leaf(&s2).unwrap();
        assert_ne!(leaf1, leaf2);
    }

    #[test]
    fn changing_a_note_commitment_changes_leaf() {
        // The commitment-only leaf (P1b) binds the note commitments, NOT the
        // mints/amounts directly — those are bound transitively inside each
        // commitment. So a different note commitment must change the leaf
        // (whereas mutating only `quote_mint`, which no longer feeds the leaf,
        // would not).
        let mut s1 = dummy_slot();
        let mut s2 = dummy_slot();
        // Fr-safe commitments (top byte 0 keeps them below the BN254 modulus,
        // so the leaf Poseidon accepts them).
        let mut c1 = [0xAA; 32];
        c1[0] = 0;
        let mut c2 = [0xBB; 32];
        c2[0] = 0;
        s1.note_c_commitment = c1;
        s2.note_c_commitment = c2;
        let leaf1 = compute_batch_leaf(&s1).unwrap();
        let leaf2 = compute_batch_leaf(&s2).unwrap();
        assert_ne!(leaf1, leaf2);
    }
}
