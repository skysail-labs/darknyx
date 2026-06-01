//! Local Merkle-tree mirror — same depth-20 Poseidon incremental
//! tree as `programs/vault/src/merkle.rs`, lifted into this crate
//! when the parity is set up. Synced from on-chain leaf-append
//! events (deposit / withdraw / tee_forced_settle_batched).
//!
//! Powers `/tree/*` indexer endpoints (D6). See
//! `docs/tee-architecture.md` §5.5.

pub mod events;
pub mod mirror;
pub mod sync;

pub use events::{extract_appended_leaves, AppendedLeaf};
pub use mirror::{InclusionProof, MerkleMirror, MirrorError, MERKLE_DEPTH};
pub use sync::{MerkleSync, MerkleSyncConfig, SyncError};
