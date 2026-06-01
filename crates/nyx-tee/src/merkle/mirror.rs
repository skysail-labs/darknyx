//! In-memory mirror of the on-chain incremental Merkle tree.
//!
//! Byte-for-byte parity with `programs/vault/src/merkle.rs`:
//!   - depth-20 tree, internal node = `poseidon2(left, right)` over
//!     big-endian field encodings (light-poseidon `new_circom(2)`),
//!   - `zero_subtree_roots[i] = poseidon2^i(0)`,
//!   - leaves appended left-to-right; the root after each append is
//!     computed via the same `right_path` walk the vault uses.
//!
//! Unlike the on-chain `VaultConfig` (which stores ONLY `right_path` +
//! the root ring — too expensive to keep every leaf), the mirror keeps
//! the full leaf set so it can serve **inclusion proofs** — the
//! replacement for the SDK's `MerkleShadow.witness()`. The witness
//! algorithm here is a direct port of that helper (which itself mirrors
//! `merkle_witness` in `programs/vault/tests/zk_spend_roundtrip.rs`), so
//! a proof produced here verifies in the on-chain VALID_SPEND circuit.
//!
//! Powers the `/tree/*` indexer endpoints (D6, `docs/tee-architecture.md`
//! §5.5). The mirror is fed by the sync task (`super::sync`, Phase 2b);
//! until that wires up it simply starts empty.

use std::collections::HashMap;

use darkpool_crypto::poseidon::poseidon_hash_bytes;

/// Tree depth — MUST equal `programs/vault/src/state.rs::MERKLE_DEPTH`.
/// A divergence here silently produces roots the on-chain program will
/// never match. Pinned by `parity_empty_root_matches_recompute` +
/// the append-parity test below.
pub const MERKLE_DEPTH: usize = 20;

/// Errors from mirror operations. The only failure mode is a Poseidon
/// hash over a non-BN254-Fr-safe input — which never happens for
/// on-chain-sourced leaves (they're all Poseidon outputs or Fr-safe
/// commitments), so this surfaces as a 500 if it ever fires.
#[derive(Debug, thiserror::Error)]
pub enum MirrorError {
    #[error("poseidon hash failed: {0}")]
    Poseidon(#[from] darkpool_crypto::CryptoError),
    #[error("merkle tree full (2^{MERKLE_DEPTH} leaves)")]
    TreeFull,
}

/// A depth-20 inclusion proof for one leaf. `siblings[d]` is the
/// sibling hash at level `d` (0 = leaf level); `indices[d]` is the
/// path bit (0 = the leaf/subtree is the LEFT child at that level).
/// Re-hashing `note_commitment` up through `siblings` yields
/// `merkle_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub note_commitment: [u8; 32],
    pub leaf_index: u64,
    pub merkle_root: [u8; 32],
    pub siblings: [[u8; 32]; MERKLE_DEPTH],
    pub indices: [u8; MERKLE_DEPTH],
}

/// `poseidon2(left, right)` — the internal-node hash. Identical bytes
/// to `programs/vault/src/merkle.rs::poseidon2`.
fn poseidon2(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], MirrorError> {
    Ok(poseidon_hash_bytes(&[*left, *right])?)
}

/// Compute `zero_subtree_roots`: `z[0] = 0`, `z[i+1] = poseidon2(z[i], z[i])`.
fn compute_zero_subtree_roots() -> Result<[[u8; 32]; MERKLE_DEPTH], MirrorError> {
    let mut roots = [[0u8; 32]; MERKLE_DEPTH];
    let mut cur = [0u8; 32];
    for slot in roots.iter_mut() {
        *slot = cur;
        cur = poseidon2(&cur, &cur)?;
    }
    Ok(roots)
}

/// In-memory mirror of the on-chain incremental Merkle tree.
#[derive(Debug, Clone)]
pub struct MerkleMirror {
    /// Every leaf appended, in insertion order. `leaves[i]` is the
    /// commitment at `leaf_index = i`.
    leaves: Vec<[u8; 32]>,
    /// `poseidon2^i(0)` for each level — the root of an all-zero
    /// subtree of depth `i`. Used as the sibling when a node has no
    /// right child yet.
    zero_subtree_roots: [[u8; 32]; MERKLE_DEPTH],
    /// Rightmost hash at each level (the on-chain `right_path`).
    /// Maintained incrementally so `root()` is O(1).
    right_path: [[u8; 32]; MERKLE_DEPTH],
    /// Current root — equal to on-chain `VaultConfig.current_root`
    /// once the mirror is fully synced.
    root: [u8; 32],
    /// `commitment -> leaf_index`, so `/tree/inclusion?commitment=…`
    /// can resolve a leaf without scanning. First write wins on a
    /// (cryptographically impossible) duplicate commitment.
    index_by_commitment: HashMap<[u8; 32], u64>,
    /// Solana slot at which the mirror was last synced from on-chain
    /// `VaultConfig`. Stamped by the sync task (Phase 2b); 0 until then.
    on_chain_slot: u64,
}

impl Default for MerkleMirror {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleMirror {
    /// A fresh, empty mirror. The zero-subtree roots + empty-tree root
    /// are computed over fixed inputs (0 and its self-hashes), all
    /// trivially Fr-safe, so this never fails in practice — a Poseidon
    /// error here would be a build-level regression, hence the panic.
    pub fn new() -> Self {
        let zero_subtree_roots =
            compute_zero_subtree_roots().expect("zero-subtree roots over fixed inputs never fail");
        // Empty-tree root: one more Poseidon2 above the last stored level.
        let last = zero_subtree_roots[MERKLE_DEPTH - 1];
        let root = poseidon2(&last, &last).expect("empty root over fixed inputs never fails");
        Self {
            leaves: Vec::new(),
            zero_subtree_roots,
            right_path: [[0u8; 32]; MERKLE_DEPTH],
            root,
            index_by_commitment: HashMap::new(),
            on_chain_slot: 0,
        }
    }

    /// Append a leaf, updating `right_path` + `root` exactly as the
    /// on-chain `append_leaf` does. Returns the new leaf's index.
    pub fn append_leaf(&mut self, leaf: [u8; 32]) -> Result<u64, MirrorError> {
        let leaf_index = self.leaves.len() as u64;
        if leaf_index >= (1u64 << MERKLE_DEPTH) {
            return Err(MirrorError::TreeFull);
        }

        let mut current = leaf;
        let mut idx = leaf_index;
        for level in 0..MERKLE_DEPTH {
            if idx & 1 == 1 {
                // Right child: left sibling is already in right_path.
                current = poseidon2(&self.right_path[level], &current)?;
            } else {
                // Left child: sibling is the empty subtree at this level.
                self.right_path[level] = current;
                current = poseidon2(&current, &self.zero_subtree_roots[level])?;
            }
            idx >>= 1;
        }

        self.root = current;
        self.leaves.push(leaf);
        // Keep the first index for a given commitment (duplicates are
        // cryptographically impossible for real note commitments).
        self.index_by_commitment.entry(leaf).or_insert(leaf_index);
        Ok(leaf_index)
    }

    /// Current Merkle root.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Number of leaves appended.
    pub fn leaf_count(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Slot of the last on-chain sync (0 until the sync task runs).
    pub fn on_chain_slot(&self) -> u64 {
        self.on_chain_slot
    }

    /// Record the slot the mirror is now consistent with. Called by
    /// the sync task after applying a batch of leaves.
    pub fn set_on_chain_slot(&mut self, slot: u64) {
        self.on_chain_slot = slot;
    }

    /// Leaf index for a commitment, if present.
    pub fn leaf_index_of(&self, commitment: &[u8; 32]) -> Option<u64> {
        self.index_by_commitment.get(commitment).copied()
    }

    /// A half-open slice of leaves `[from, to)`, clamped to the
    /// available range. Backs `/tree/leaves?from=&to=` pagination for
    /// cold-syncing clients. Returns `(start_index, leaves)`.
    pub fn leaves_range(&self, from: u64, to: u64) -> (u64, Vec<[u8; 32]>) {
        let n = self.leaves.len() as u64;
        let start = from.min(n);
        let end = to.min(n).max(start);
        (start, self.leaves[start as usize..end as usize].to_vec())
    }

    /// Build a depth-20 inclusion proof for `commitment`. `None` if the
    /// commitment isn't in the tree. The returned `merkle_root` equals
    /// [`Self::root`] (asserted by the parity test).
    ///
    /// Direct port of `MerkleShadow.witness()` (TS) /
    /// `merkle_witness` (vault test): build the minimal power-of-two
    /// subtree over the leaves seen so far, collect siblings up to its
    /// depth, then extend with zero-subtree roots on the right edge.
    pub fn inclusion_proof(
        &self,
        commitment: &[u8; 32],
    ) -> Result<Option<InclusionProof>, MirrorError> {
        let Some(leaf_index) = self.leaf_index_of(commitment) else {
            return Ok(None);
        };

        let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
        let mut indices = [0u8; MERKLE_DEPTH];

        // Smallest power-of-two ≥ leaf_count, min depth 1 so there's
        // always a sibling at level 0.
        let n = self.leaves.len();
        let mut small = 1usize;
        let mut small_depth = 0usize;
        while small < n {
            small <<= 1;
            small_depth += 1;
        }
        if small_depth == 0 {
            small_depth = 1;
        }

        // Pad the leaf level out to the power of two with zero leaves.
        let padded = 1usize << small_depth;
        let mut level: Vec<[u8; 32]> = self.leaves.clone();
        level.resize(padded, [0u8; 32]);

        let mut idx = leaf_index as usize;
        for (d, sib) in siblings.iter_mut().enumerate().take(small_depth) {
            let sibling_idx = idx ^ 1;
            *sib = level[sibling_idx];
            indices[d] = (idx & 1) as u8;
            idx >>= 1;
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks_exact(2) {
                next.push(poseidon2(&pair[0], &pair[1])?);
            }
            level = next;
        }

        // Above the small subtree, the path always goes left (we're on
        // the growing right edge): sibling = zero-subtree root.
        let mut current = level[0];
        for (d, sib) in siblings.iter_mut().enumerate().skip(small_depth) {
            *sib = self.zero_subtree_roots[d];
            indices[d] = 0;
            current = poseidon2(&current, &self.zero_subtree_roots[d])?;
        }

        debug_assert_eq!(
            current, self.root,
            "inclusion-proof root must equal the incremental root"
        );

        Ok(Some(InclusionProof {
            note_commitment: *commitment,
            leaf_index,
            merkle_root: current,
            siblings,
            indices,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recompute the root from scratch (the O(n·depth) reference path,
    /// mirroring `MerkleShadow.computeRoot`) to cross-check the
    /// incremental `right_path` root.
    fn recompute_root(m: &MerkleMirror) -> [u8; 32] {
        let mut level = m.leaves.clone();
        if level.is_empty() {
            let last = m.zero_subtree_roots[MERKLE_DEPTH - 1];
            return poseidon2(&last, &last).unwrap();
        }
        for d in 0..MERKLE_DEPTH {
            let mut next = Vec::new();
            let mut i = 0;
            while i < level.len() {
                let l = level[i];
                let r = if i + 1 < level.len() {
                    level[i + 1]
                } else {
                    m.zero_subtree_roots[d]
                };
                next.push(poseidon2(&l, &r).unwrap());
                i += 2;
            }
            level = next;
        }
        level[0]
    }

    fn fr_safe(seed: u8) -> [u8; 32] {
        let mut b = [seed; 32];
        b[0] = 0; // top byte zero → BN254-Fr-safe
        b
    }

    #[test]
    fn empty_root_matches_recompute() {
        let m = MerkleMirror::new();
        assert_eq!(m.leaf_count(), 0);
        assert_eq!(m.root(), recompute_root(&m));
    }

    #[test]
    fn incremental_root_matches_recompute_each_append() {
        let mut m = MerkleMirror::new();
        for i in 1..=10u8 {
            let idx = m.append_leaf(fr_safe(i)).unwrap();
            assert_eq!(idx, (i - 1) as u64);
            assert_eq!(
                m.root(),
                recompute_root(&m),
                "incremental root diverged from recompute at {i} leaves"
            );
        }
        assert_eq!(m.leaf_count(), 10);
    }

    #[test]
    fn inclusion_proof_verifies_against_root() {
        let mut m = MerkleMirror::new();
        let mut commits = vec![];
        for i in 1..=7u8 {
            let c = fr_safe(i);
            m.append_leaf(c).unwrap();
            commits.push(c);
        }
        // Every leaf's proof re-hashes up to the current root.
        for (i, c) in commits.iter().enumerate() {
            let proof = m.inclusion_proof(c).unwrap().expect("leaf present");
            assert_eq!(proof.leaf_index, i as u64);
            assert_eq!(proof.merkle_root, m.root());

            // Re-fold leaf + siblings using the path bits.
            let mut acc = *c;
            for d in 0..MERKLE_DEPTH {
                acc = if proof.indices[d] == 0 {
                    poseidon2(&acc, &proof.siblings[d]).unwrap()
                } else {
                    poseidon2(&proof.siblings[d], &acc).unwrap()
                };
            }
            assert_eq!(acc, m.root(), "leaf {i} proof did not fold to root");
        }
    }

    #[test]
    fn inclusion_proof_unknown_commitment_is_none() {
        let mut m = MerkleMirror::new();
        m.append_leaf(fr_safe(1)).unwrap();
        assert!(m.inclusion_proof(&fr_safe(99)).unwrap().is_none());
    }

    #[test]
    fn leaves_range_clamps_and_paginates() {
        let mut m = MerkleMirror::new();
        for i in 1..=5u8 {
            m.append_leaf(fr_safe(i)).unwrap();
        }
        let (start, page) = m.leaves_range(1, 3);
        assert_eq!(start, 1);
        assert_eq!(page, vec![fr_safe(2), fr_safe(3)]);
        // Over-range is clamped, not panicking.
        let (start, page) = m.leaves_range(4, 999);
        assert_eq!(start, 4);
        assert_eq!(page, vec![fr_safe(5)]);
        let (start, page) = m.leaves_range(100, 200);
        assert_eq!(start, 5);
        assert!(page.is_empty());
    }
}
