//! On-chain incremental Merkle tree using `sol_poseidon` for parity with the
//! circom VALID_SPEND circuit.
//!
//! We store only `right_path[level]` — the rightmost hash at each level — and
//! the `zero_subtree_roots[level]` — the hash of an all-zero subtree of that
//! depth. When we insert a new leaf, we walk from the leaf up, combining the
//! new node with either `right_path` (if our position is a right child) or
//! `zero_subtree_roots` (if our position is a left child with no sibling yet).

use crate::errors::VaultError;
use crate::state::{MerkleTree, MERKLE_DEPTH};
use anchor_lang::prelude::*;
#[cfg(not(target_os = "solana"))]
use ark_bn254::Fr;
#[cfg(not(target_os = "solana"))]
use light_poseidon::{Poseidon, PoseidonBytesHasher};
#[cfg(target_os = "solana")]
use solana_poseidon::{hashv, Endianness, Parameters};

/// Compute Poseidon2(left, right). We use `light-poseidon` both on-chain and
/// off-chain so byte outputs are guaranteed identical. The on-chain BPF
/// version of light-poseidon uses pure Rust arithmetic (no syscalls).
pub fn poseidon2(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32]> {
    #[cfg(target_os = "solana")]
    {
        return hashv(
            Parameters::Bn254X5,
            Endianness::BigEndian,
            &[left.as_slice(), right.as_slice()],
        )
        .map(|h| h.to_bytes())
        .map_err(|_| Error::from(VaultError::InvalidProof));
    }

    #[cfg(not(target_os = "solana"))]
    {
        let mut h = Poseidon::<Fr>::new_circom(2).map_err(|_| Error::from(VaultError::InvalidProof))?;
        h.hash_bytes_be(&[left.as_slice(), right.as_slice()])
            .map_err(|_| Error::from(VaultError::InvalidProof))
    }
}

/// Initialize zero_subtree_roots using Poseidon: z0 = 0, z_{i+1} = Poseidon2(z_i, z_i).
pub fn compute_zero_subtree_roots() -> Result<[[u8; 32]; MERKLE_DEPTH as usize]> {
    let mut roots = [[0u8; 32]; MERKLE_DEPTH as usize];
    let mut cur = [0u8; 32];
    for (i, slot) in roots.iter_mut().enumerate() {
        *slot = cur;
        cur = poseidon2(&cur, &cur)?;
        let _ = i;
    }
    Ok(roots)
}

/// The root of a fully-empty tree of depth MERKLE_DEPTH.
pub fn empty_root(zero_subtree_roots: &[[u8; 32]; MERKLE_DEPTH as usize]) -> Result<[u8; 32]> {
    // One more Poseidon2(z_{depth-1}, z_{depth-1}) from the last stored level.
    let last = zero_subtree_roots[MERKLE_DEPTH as usize - 1];
    poseidon2(&last, &last)
}

/// Append a leaf to a Merkle-tree SHARD and return the new root. Updates the
/// shard's `right_path` + recent-root ring in-place. `zero_subtree_roots` are
/// the global (tree-independent) empty-subtree roots from `VaultConfig`.
// The loop indexes BOTH `tree.right_path` and `zero_subtree_roots` by `level`,
// so the iterator form would be less readable than the explicit index.
#[allow(clippy::needless_range_loop)]
pub fn append_leaf(
    tree: &mut MerkleTree,
    zero_subtree_roots: &[[u8; 32]; MERKLE_DEPTH as usize],
    leaf: [u8; 32],
) -> Result<[u8; 32]> {
    let leaf_index = tree.leaf_count;
    require!(
        leaf_index < (1u64 << MERKLE_DEPTH),
        VaultError::MerkleTreeFull
    );

    let mut current = leaf;
    let mut idx = leaf_index;

    for level in 0..(MERKLE_DEPTH as usize) {
        let is_right_child = idx & 1 == 1;
        if is_right_child {
            // Left sibling is already in right_path (from when a previous leaf
            // was a left child at this level).
            current = poseidon2(&tree.right_path[level], &current)?;
        } else {
            // We're a left child — sibling is the empty subtree.
            tree.right_path[level] = current;
            current = poseidon2(&current, &zero_subtree_roots[level])?;
        }
        idx >>= 1;
    }

    tree.leaf_count = leaf_index
        .checked_add(1)
        .ok_or(Error::from(VaultError::ArithmeticOverflow))?;
    tree.push_root(current);
    Ok(current)
}

/// Max leaves a single `append_leaves` call may insert. The settle handler
/// appends at most SIX output notes (note_c, note_d, buyer-change note_e,
/// seller-change note_f, base-fee note, quote-fee note), so 6 is the real
/// ceiling; 8 gives headroom and keeps the working buffers a power of two.
pub const MAX_BATCH_APPEND: usize = 8;

/// Append up to [`MAX_BATCH_APPEND`] leaves at CONSECUTIVE indices in ONE pass,
/// sharing Merkle-path recomputation across them, and return the new root.
///
/// This is a CU optimization over calling [`append_leaf`] N times. Sequential
/// appends re-walk all `MERKLE_DEPTH` levels per leaf, and for every leaf but
/// the last that walk is almost entirely **provisional** — it hashes the new
/// node against zero-subtrees up to the root only to have the next leaf
/// overwrite those `right_path` entries before anything reads them. A 6-leaf
/// settle does 6×20 = 120 Poseidon2; the minimal node set is ~2-dozen. We
/// compute that minimal set bottom-up:
///
///   * Level 0 holds the K new leaves at consecutive indices `[start, start+K)`.
///   * At each level we pair adjacent nodes into parents:
///       - a LEFT child (even index) updates `right_path[level]` (last writer
///         wins — exactly as the sequential code's most-recent left-child
///         write), then pairs with its right sibling if that sibling is also
///         new (in our set), else with the zero-subtree (a provisional parent
///         that only the final walk-up consumes);
///       - a lone RIGHT child (only ever the first node at a level, when `start`
///         is odd) pairs with the EXISTING `right_path[level]` frontier — the
///         same left sibling the sequential code would read.
///   * After `MERKLE_DEPTH` levels exactly one node remains: the new root.
///
/// **Correctness contract** (proven exhaustively by `merkle_host.rs`'s
/// differential test against `append_leaf`): for any `(leaf_count, leaves)`,
/// this produces a byte-identical final `right_path`, `leaf_count`, and
/// `current_root` as `leaves.len()` sequential `append_leaf` calls.
///
/// **One deliberate behavioral difference:** it pushes only the FINAL root into
/// the recent-roots ring (one `push_root`), not the K-1 intermediate roots a
/// sequence of `append_leaf` calls would. Those intermediates are unobservable
/// — a settle is one atomic tx, so the only root any client can witness (and
/// later supply to `contains_root`) is the committed final root. Dropping the
/// intermediates is safe AND leaves more room in the ring for distinct
/// observable roots. The pre-batch root is still pushed, so a client mid-flight
/// against it can still spend.
#[allow(clippy::needless_range_loop)]
pub fn append_leaves(
    tree: &mut MerkleTree,
    zero_subtree_roots: &[[u8; 32]; MERKLE_DEPTH as usize],
    leaves: &[[u8; 32]],
) -> Result<[u8; 32]> {
    let k = leaves.len();
    if k == 0 {
        return Ok(tree.current_root);
    }
    require!(k <= MAX_BATCH_APPEND, VaultError::MerkleTreeFull);

    let start = tree.leaf_count;
    // `start + k - 1` is the index of the last new leaf; it must fit the tree.
    let last_index = start
        .checked_add(k as u64 - 1)
        .ok_or(Error::from(VaultError::ArithmeticOverflow))?;
    require!(
        last_index < (1u64 << MERKLE_DEPTH),
        VaultError::MerkleTreeFull
    );

    // Ping-pong working buffers of (index_at_level, node_value). `cur` holds
    // this level's nodes in increasing-index order; `nxt` collects parents.
    let mut cur: [(u64, [u8; 32]); MAX_BATCH_APPEND] = [(0, [0u8; 32]); MAX_BATCH_APPEND];
    let mut nxt: [(u64, [u8; 32]); MAX_BATCH_APPEND] = [(0, [0u8; 32]); MAX_BATCH_APPEND];
    for j in 0..k {
        cur[j] = (start.get() + j as u64, leaves[j]);
    }
    let mut cur_len = k;

    for level in 0..(MERKLE_DEPTH as usize) {
        let mut nxt_len = 0usize;
        let mut i = 0usize;
        while i < cur_len {
            let (idx, val) = cur[i];
            if idx & 1 == 1 {
                // Lone right child (its left sibling is not in our new-node set):
                // pair with the existing frontier. This can only be the first
                // node at a level, so `right_path[level]` is still the pre-batch
                // value the sequential code would read here.
                let parent = poseidon2(&tree.right_path[level], &val)?;
                nxt[nxt_len] = (idx >> 1, parent);
                nxt_len += 1;
                i += 1;
            } else {
                // Left child — record it as the frontier (last writer wins).
                tree.right_path[level] = val;
                if i + 1 < cur_len && cur[i + 1].0 == idx + 1 {
                    // Right sibling is also new → pair the two new nodes.
                    let parent = poseidon2(&val, &cur[i + 1].1)?;
                    nxt[nxt_len] = (idx >> 1, parent);
                    nxt_len += 1;
                    i += 2;
                } else {
                    // No right sibling yet → provisional parent against the
                    // zero-subtree; only the final walk-up consumes it.
                    let parent = poseidon2(&val, &zero_subtree_roots[level])?;
                    nxt[nxt_len] = (idx >> 1, parent);
                    nxt_len += 1;
                    i += 1;
                }
            }
        }
        cur[..nxt_len].copy_from_slice(&nxt[..nxt_len]);
        cur_len = nxt_len;
    }

    // Exactly one node survives to the top: the new root.
    let new_root = cur[0].1;
    tree.leaf_count = start
        .checked_add(k as u64)
        .ok_or(Error::from(VaultError::ArithmeticOverflow))?;
    tree.push_root(new_root);
    Ok(new_root)
}
