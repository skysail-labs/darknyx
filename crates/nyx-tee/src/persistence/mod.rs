//! LUKS-encrypted disk snapshots. Disk encryption key is derived by
//! dstack-kms from the app root key, so snapshots survive CVM
//! migration (transparent to this code — see `docs/tee-architecture.md`
//! §8). Two scopes:
//!
//! - [`auth`] (Phase 1b, live): the Layer-A account registry + JWT
//!   revocation denylist → `accounts.db`, write-on-change. The auth
//!   API surface uses these via the re-exports below.
//! - [`fills`] (P7, live): the durable per-account fill-memo log → `fills.db`,
//!   for `GET /fills/replay` memo recovery (amount-privacy made memos the only
//!   amount source, so they must survive a disconnect/restart).
//! - [`snapshot`] (scaffold): the higher-churn order book + Merkle
//!   leaves + settle outbox, 5 s periodic. Lands in a later PR.

pub mod auth;
pub mod fills;
pub mod snapshot;

// Re-export the auth-persistence surface at the module root so call
// sites use `crate::persistence::{load_auth_snapshot, ...}`.
pub use auth::{
    accounts_db_path, load_auth_snapshot, save_auth_snapshot, state_dir_from_env, AuthSnapshot,
    ACCOUNTS_DB_FILE, DEFAULT_STATE_DIR,
};

// Re-export the fill-log surface at the module root.
pub use fills::{
    fills_db_path, load_fill_log, save_fill_log, FillLog, FillLogSnapshot, FILLS_DB_FILE,
};
