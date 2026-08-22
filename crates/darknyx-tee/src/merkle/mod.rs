//! Local mirror of the on-chain Merkle tree.
//!
//! The same depth-20 Poseidon incremental tree as `programs/vault/src/merkle.rs`,
//! rebuilt inside the enclave from on-chain leaf-append events (deposit, withdraw,
//! `tee_forced_settle_batched`). One mirror exists per shard. It backs the
//! `/tree/*` reads and supplies the inclusion paths the settle pipeline needs.
//!
//! ```text
//!   mirror.rs   the tree itself: append, root, inclusion paths, recent-roots ring
//!   events.rs   decoding leaf-append events from transaction logs
//!   sync.rs     the catch-up and follow loop against Solana
//! ```
//!
//! **The mirror is append-only and cannot rewind.** Resetting the on-chain tree
//! does not empty it: it replays from `DARKNYX_TEE_SYNC_FROM_SLOT`, so a tree reset
//! must be paired with an env-only redeploy that moves that floor past the reset,
//! and a cold boot. Skipping that is why a "reset" tree can still serve stale
//! leaves — see `docs/settlement-recovery-drill.md`.
//!
//! A root computed here that disagrees with the chain surfaces downstream as
//! `StaleMerkleRoot (6004)` on the first spend, not as an error in this module.

pub mod events;
pub mod mirror;
pub mod sync;

pub use events::{extract_appended_leaves, AppendedLeaf, TreeAppendEvent};
pub use mirror::{InclusionProof, MerkleMirror, MirrorError, MERKLE_DEPTH};
pub use sync::{MerkleSync, MerkleSyncConfig, SyncError};
