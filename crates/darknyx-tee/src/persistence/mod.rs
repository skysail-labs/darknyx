//! LUKS-encrypted disk snapshots. Disk encryption key is derived by
//! dstack-kms from the app root key, so snapshots survive CVM
//! migration (transparent to this code — see `docs/tee-architecture.md`
//! §8). Two scopes:
//!
//! - [`auth`] (Phase 1b, live): the Layer-A account registry + JWT
//!   revocation denylist → `accounts.db`, write-on-change. The auth
//!   API surface uses these via the re-exports below.
//! - [`journal`] (T-06): the write-ahead journal of IN-FLIGHT settlements —
//!   openings, match identity, and submitted signatures, written before each
//!   external side effect so a restart can reconcile against the chain instead
//!   of stranding user collateral behind a lock it can no longer use.
//! - [`snapshot`] (scaffold): the higher-churn order book + Merkle
//!   leaves, 5 s periodic. Resting orders are deliberately NOT restored from
//!   disk (see the T-06 decisions); the daemon resubmits a fresh signed order.
//!
//! (The P7 durable per-account fill-memo log + `GET /fills/replay` were retired
//! once recovery v3 put both output amounts on-chain encrypted —
//! the chain is now the permanent recovery source, so only the live `fills`
//! push remains.)

pub mod auth;
pub mod journal;
pub mod markers;
pub mod snapshot;

// Re-export the auth-persistence surface at the module root so call
// sites use `crate::persistence::{load_auth_snapshot, ...}`.
pub use auth::{
    accounts_db_path, load_auth_snapshot, save_auth_snapshot, state_dir_from_env, AuthSnapshot,
    ACCOUNTS_DB_FILE, DEFAULT_STATE_DIR,
};
// Pending settle-marker roots (close = Tx E, swept asynchronously off the
// settle critical path — see `settle::marker_sweep`).
pub use markers::{markers_db_path, PendingMarkers, PendingSet, LOCKS_DB_FILE, MARKERS_DB_FILE};
// In-flight settlement journal (T-06) — durable across restart/redeploy.
pub use journal::{JournalEntry, JournalLoad, JournalStage, SettleJournal, JOURNAL_DB_FILE};
