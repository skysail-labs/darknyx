//! Encrypted on-disk state.
//!
//! Everything here lives on the dstack LUKS mount. The disk-encryption key is
//! derived by dstack-kms from the app root key, so state survives CVM migration
//! without this code participating — see `docs/tee-architecture.md` §8.
//!
//!   - [`auth`] — the account registry and JWT revocation denylist, written to
//!     `accounts.db` on change.
//!   - [`journal`] — the write-ahead journal of **in-flight settlements**:
//!     openings, match identity, and submitted signatures, each written *before*
//!     the external side effect it describes. This ordering is the whole point. It
//!     lets a restart reconcile against the chain rather than stranding user
//!     collateral behind a lock the enclave can no longer use (audit T-06).
//!   - [`snapshot`] — scaffold for the higher-churn order book and Merkle leaves.
//!
//! **Resting orders are deliberately not restored from disk.** An order is a signed
//! client intent carrying a nonce and a session binding; resurrecting one after an
//! arbitrary gap would re-enter the book on the client's behalf at a price chosen
//! under different conditions. The daemon observes the restart and submits a fresh
//! signed order instead. This is a recorded decision, not a gap — see
//! [`crate::settle::recover`].
//!
//! The journal's schema version gates boot: an upgrade across a version bump
//! requires `POST /admin/drain` and a confirmed `safe_to_stop` first, or the
//! enclave reports the journal `Damaged` and waits for an operator.
//!
//! The durable per-account fill-memo log and `GET /fills/replay` were retired once
//! recovery put both output amounts on-chain encrypted. The chain is the permanent
//! recovery source; only the live `fills` push remains.

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
pub use journal::{
    JournalEntry, JournalLoad, JournalStage, JournalWriteStats, SettleJournal, JOURNAL_DB_FILE,
};
