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
        .map_err(|_| error!(VaultError::InvalidProof));
    }

    #[cfg(not(target_os = "solana"))]
    {
        let mut h = Poseidon::<Fr>::new_circom(2).map_err(|_| error!(VaultError::InvalidProof))?;
        h.hash_bytes_be(&[left.as_slice(), right.as_slice()])
            .map_err(|_| error!(VaultError::InvalidProof))
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
        .ok_or(error!(VaultError::ArithmeticOverflow))?;
    tree.push_root(current);
    Ok(current)
}
