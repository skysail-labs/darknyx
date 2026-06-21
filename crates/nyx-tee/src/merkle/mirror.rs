//! In-memory mirror of the on-chain incremental Merkle tree.
//!
//! Byte-for-byte parity with `programs/vault/src/merkle.rs`:
//!   - depth-20 tree, internal node = `poseidon2(left, right)` over
//!     big-endian field encodings (light-poseidon `new_circom(2)`),
//!   - `zero_subtree_roots[i] = poseidon2^i(0)`,
//!   - leaves appended left-to-right; the root is the top of an
//!     incrementally-maintained internal-node cache (the right-edge
//!     nodes it updates per append are exactly the vault's `right_path`).
//!
//! Unlike the on-chain `VaultConfig` (which stores ONLY `right_path` +
//! the root ring — too expensive to keep every leaf), the mirror keeps
//! the full leaf set PLUS the internal-node cache so it can serve
//! **inclusion proofs** — the replacement for the SDK's
//! `MerkleShadow.witness()`. Rather than re-fold the whole tree per
//! request (the original O(n) port of that helper), `inclusion_proof`
//! reads its siblings straight from the cache in O(depth); the cached
//! nodes are byte-identical to the zero-leaf-padded fold, so a proof
//! produced here still verifies in the on-chain VALID_SPEND circuit
//! (cross-checked against the recompute reference in tests).
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
    /// Internal-node cache, one `Vec` per level above the leaves:
    /// `internal[d - 1]` holds the level-`d` nodes (`d = 1..=MERKLE_DEPTH`),
    /// position-indexed. Each node is `poseidon2(left, right)` with the
    /// right child padded by `zero_subtree_roots[d - 1]` when absent —
    /// byte-identical to folding the zero-leaf-padded tree. Only the
    /// O(MERKLE_DEPTH) right-edge nodes on a new leaf's path change per
    /// append (the same set the on-chain `right_path` tracks), so this
    /// is maintained in O(depth) per append while letting
    /// `inclusion_proof` read its siblings in O(depth) instead of
    /// re-folding all `n` leaves (O(n)). The top level holds the single
    /// root node.
    internal: Vec<Vec<[u8; 32]>>,
    /// Current root — equal to on-chain `VaultConfig.current_root`
    /// once the mirror is fully synced. Cached for O(1) `root()`;
    /// equals `internal[MERKLE_DEPTH - 1][0]` once any leaf is present.
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
            internal: vec![Vec::new(); MERKLE_DEPTH],
            root,
            index_by_commitment: HashMap::new(),
            on_chain_slot: 0,
        }
    }

    /// Value of the node at (`level`, `pos`), or `None` if that position
    /// is not populated yet (its subtree is entirely empty → the caller
    /// substitutes `zero_subtree_roots[level]`). Level 0 is the leaf row.
    fn node_at(&self, level: usize, pos: usize) -> Option<[u8; 32]> {
        if level == 0 {
            self.leaves.get(pos).copied()
        } else {
            self.internal[level - 1].get(pos).copied()
        }
    }

    /// Append a leaf, updating the internal-node cache + `root`. Produces
    /// the same root the on-chain `append_leaf` does (guarded by the
    /// recompute-parity test). Returns the new leaf's index.
    pub fn append_leaf(&mut self, leaf: [u8; 32]) -> Result<u64, MirrorError> {
        let leaf_index = self.leaves.len() as u64;
        if leaf_index >= (1u64 << MERKLE_DEPTH) {
            return Err(MirrorError::TreeFull);
        }
        self.leaves.push(leaf);
        // Keep the first index for a given commitment (duplicates are
        // cryptographically impossible for real note commitments).
        self.index_by_commitment.entry(leaf).or_insert(leaf_index);

        // Recompute the right-edge path nodes from the new leaf up to the
        // root. At level `d` the path node is position `i >> d`; its left
        // child always exists, its right child is the zero-subtree root
        // when absent. Only these O(MERKLE_DEPTH) nodes change per append
        // — the rest of the cache is already final.
        let i = leaf_index as usize;
        for d in 1..=MERKLE_DEPTH {
            let p = i >> d;
            let left = self
                .node_at(d - 1, 2 * p)
                .expect("left child on the path always exists");
            let right = self
                .node_at(d - 1, 2 * p + 1)
                .unwrap_or(self.zero_subtree_roots[d - 1]);
            let node = poseidon2(&left, &right)?;
            let level = &mut self.internal[d - 1];
            if p < level.len() {
                level[p] = node; // still on the growing right edge
            } else {
                debug_assert_eq!(p, level.len(), "path positions advance by one");
                level.push(node);
            }
        }
        self.root = self.internal[MERKLE_DEPTH - 1][0];
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
    /// [`Self::root`].
    ///
    /// O(MERKLE_DEPTH): each level's sibling is read straight from the
    /// internal-node cache (or the zero-subtree root if that subtree is
    /// empty) — no leaf clone, no re-folding. The cache is maintained by
    /// [`Self::append_leaf`], so the siblings are exactly those of the
    /// canonical zero-leaf-padded tree the SDK `MerkleShadow.witness()`
    /// would build. The `Result` is retained for API stability; the body
    /// no longer hashes, so it can't actually error.
    pub fn inclusion_proof(
        &self,
        commitment: &[u8; 32],
    ) -> Result<Option<InclusionProof>, MirrorError> {
        let Some(leaf_index) = self.leaf_index_of(commitment) else {
            return Ok(None);
        };

        let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
        let mut indices = [0u8; MERKLE_DEPTH];

        let i = leaf_index as usize;
        for (d, (sib, ix)) in siblings.iter_mut().zip(indices.iter_mut()).enumerate() {
            let p = i >> d; // path-node position at level d
            *ix = (p & 1) as u8;
            // Sibling = the node beside the path node; an absent position
            // is an all-zero subtree → its root for this level.
            *sib = self.node_at(d, p ^ 1).unwrap_or(self.zero_subtree_roots[d]);
        }

        Ok(Some(InclusionProof {
            note_commitment: *commitment,
            leaf_index,
            merkle_root: self.root,
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

    /// Fold a proof's leaf up through its siblings using the path bits.
    fn fold_to_root(leaf: &[u8; 32], proof: &InclusionProof) -> [u8; 32] {
        let mut acc = *leaf;
        for d in 0..MERKLE_DEPTH {
            acc = if proof.indices[d] == 0 {
                poseidon2(&acc, &proof.siblings[d]).unwrap()
            } else {
                poseidon2(&proof.siblings[d], &acc).unwrap()
            };
        }
        acc
    }

    /// The cache must keep EVERY existing leaf's proof valid as the tree
    /// grows — appending shifts the right edge, so older leaves' siblings
    /// (the right-edge subtrees) change and must be re-read correctly.
    /// Walks past several power-of-two boundaries (1,2,4,8,16,32).
    #[test]
    fn inclusion_proofs_stay_valid_across_growth() {
        let mut m = MerkleMirror::new();
        let mut commits = vec![];
        for i in 0..40u8 {
            let c = fr_safe(i + 1);
            m.append_leaf(c).unwrap();
            commits.push(c);

            // Cache-derived root tracks the independent recompute.
            assert_eq!(
                m.root(),
                recompute_root(&m),
                "root diverged at {} leaves",
                i + 1
            );

            // Every leaf so far folds to the CURRENT root.
            for (j, c) in commits.iter().enumerate() {
                let proof = m.inclusion_proof(c).unwrap().expect("leaf present");
                assert_eq!(proof.leaf_index, j as u64);
                assert_eq!(proof.merkle_root, m.root());
                assert_eq!(
                    fold_to_root(c, &proof),
                    m.root(),
                    "leaf {j} proof stale after {} appends",
                    i + 1
                );
            }
        }
        assert_eq!(m.leaf_count(), 40);
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
