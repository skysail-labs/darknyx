//! LUKS-encrypted disk snapshots. Disk encryption key is derived by
//! dstack-kms from the app root key, so snapshots survive CVM
//! migration (transparent to this code — see `docs/tee-architecture.md`
//! §8). Two scopes:
//!
//! - [`auth`] (Phase 1b, live): the Layer-A account registry + JWT
//!   revocation denylist → `accounts.db`, write-on-change. The auth
//!   API surface uses these via the re-exports below.
//! - [`snapshot`] (scaffold): the higher-churn order book + Merkle
//!   leaves + settle outbox, 5 s periodic. Lands in a later PR.

pub mod auth;
pub mod snapshot;

// Re-export the auth-persistence surface at the module root so call
// sites use `crate::persistence::{load_auth_snapshot, ...}`.
pub use auth::{
    accounts_db_path, load_auth_snapshot, save_auth_snapshot, state_dir_from_env, AuthSnapshot,
    ACCOUNTS_DB_FILE, DEFAULT_STATE_DIR,
};
