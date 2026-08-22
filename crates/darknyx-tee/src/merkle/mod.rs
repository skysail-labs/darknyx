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
//! Divergence from the chain **fails closed** rather than being served: the
//! `/tree/*` read sites answer `503` for a diverged shard and new trading is
//! paused, so a caller sees the divergence instead of silently receiving a bad
//! proof. Divergence does not clear on its own, because the mirror cannot rewind.
//! `StaleMerkleRoot (6004)` is the on-chain backstop if a stale proof is relayed
//! anyway — not the primary signal, and not what incident response should wait
//! for.

pub mod events;
pub mod mirror;
pub mod sync;

pub use events::{extract_appended_leaves, AppendedLeaf, TreeAppendEvent};
pub use mirror::{InclusionProof, MerkleMirror, MirrorError, MERKLE_DEPTH};
pub use sync::{MerkleSync, MerkleSyncConfig, SyncError};
