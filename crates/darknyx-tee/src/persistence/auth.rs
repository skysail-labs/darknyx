//! Best-effort persistence of the operational **auth state**:
//! the account registry + the JWT revocation denylist, so a TEE
//! restart doesn't drop registered accounts or un-revoke tokens.
//!
//! The TEE's authoritative state is on-chain (settled balances, note
//! ownership) + client-signed order intent. Local persistence is a
//! **convenience + crash-recovery aid, never the source of truth**
//! (`docs/tee-architecture.md` §8). The higher-churn book /
//! Merkle-leaf / settle-outbox snapshots (§8's 5 s periodic part)
//! live alongside this in [`super::snapshot`] and land in a later PR.
//!
//! ## Encryption
//!
//! There is **no app-level crypto here**. In production the snapshot
//! file lives on a dstack-kms-provisioned LUKS volume (key
//! deterministic from `app_id`), so encryption-at-rest is transparent
//! to this code — we just do plain file I/O. Locally / in tests the
//! directory is an ordinary path (or `None`, disabling persistence).
//!
//! ## Durability model
//!
//! - **Write-on-change.** Auth state is low-churn (registrations +
//!   revocations are rare), so we snapshot right after each mutation
//!   rather than on a timer — simpler and loss-free for this state.
//! - **Atomic.** Each save writes a sibling `*.tmp`, fsyncs it, then
//!   `rename`s over the target (atomic on the same filesystem), so a
//!   crash mid-write can never leave a torn `accounts.db`.
//! - **Best-effort reads.** A missing / corrupt / version-mismatched
//!   file deserialises to `None` — the caller falls back to the env
//!   bootstrap admin. We never panic on a bad snapshot.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::api::auth::ApiCredentials;

/// Snapshot file name within the configured state directory.
pub const ACCOUNTS_DB_FILE: &str = "accounts.db";

/// Default state directory when `DARKNYX_TEE_STATE_DIR` is unset. In a
/// production CVM this is the mount point of the LUKS volume.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/darknyx-tee";

/// Bumped whenever the on-disk layout of [`AuthSnapshot`] changes in a
/// non-backward-compatible way. A snapshot with a different version is
/// treated as absent (best-effort) rather than mis-decoded.
///
/// The encoding is bincode: positional and NOT self-describing. There is no
/// field-name framing, so `#[serde(default)]` on a newly added field does not
/// make an older payload decodable. Every field added anywhere in this struct
/// or in [`ApiCredentials`] therefore requires a bump here.
///
/// v2 added account suspension + per-account token invalidation to
/// `ApiCredentials`, and gave each revoked token id its expiry.
///
/// **This constant does less than it appears to.** `version` is checked AFTER
/// the payload has been deserialised, so a field added to a NESTED struct
/// derails the decode long before the version is read: the v1→v2 upgrade was
/// observed on a live enclave failing as
/// `invalid u8 while decoding bool, expected 0 or 1, found 40`, not as a
/// version mismatch. The outcome is the same only because
/// [`load_auth_snapshot`] maps every decode error to `None`. Anyone adding a
/// real migration must therefore read the version from the leading bytes
/// BEFORE attempting a typed decode — dispatching on `snapshot.version` will
/// never be reached for this class of change.
///
/// ⚠️ A BUMP DISCARDS THE EXISTING FILE. That is acceptable only while the
/// registry holds nothing but the bootstrap admin, which is re-seeded from the
/// deploy environment on every boot — true during development, when no account
/// has ever been registered through the API. Once real accounts exist, dropping
/// them is data loss and the NEXT change must decode the old version and
/// migrate it forward instead of bumping past it.
const SNAPSHOT_VERSION: u32 = 2;

/// The persisted Layer-A auth state. Serialised with `bincode`.
///
/// Only argon2id hashes are stored (inside [`ApiCredentials`]) — never
/// plaintext secrets. The `revoked_jtis` set keeps revocations durable
/// across restarts (without it, a revoked token would become valid
/// again until its `exp`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSnapshot {
    pub version: u32,
    pub accounts: Vec<ApiCredentials>,
    /// Revoked token ids paired with the expiry of the token each one belongs
    /// to (unix seconds). The expiry is what allows an entry to be dropped once
    /// the token would be refused as expired anyway — without it this list only
    /// ever grew, across every restart, for the life of the deployment.
    pub revoked_jtis: Vec<(String, u64)>,
}

impl AuthSnapshot {
    /// Build a snapshot from live state. `revoked` is flattened into a
    /// `Vec` for a stable wire shape.
    pub fn new(accounts: Vec<ApiCredentials>, revoked: &HashMap<String, u64>) -> Self {
        Self {
            version: SNAPSHOT_VERSION,
            accounts,
            revoked_jtis: revoked.iter().map(|(k, v)| (k.clone(), *v)).collect(),
        }
    }
}

/// Resolve the configured state directory from `DARKNYX_TEE_STATE_DIR`.
/// `None` (persistence disabled) when the var is unset or empty — used
/// by `ApiState::for_tests` and any deploy that doesn't mount a volume.
pub fn state_dir_from_env() -> Option<PathBuf> {
    match std::env::var("DARKNYX_TEE_STATE_DIR") {
        Ok(s) if !s.is_empty() => Some(PathBuf::from(s)),
        _ => None,
    }
}

/// Full path to the accounts snapshot within `state_dir`.
pub fn accounts_db_path(state_dir: &Path) -> PathBuf {
    state_dir.join(ACCOUNTS_DB_FILE)
}

/// Load the auth snapshot from `path`, best-effort.
///
/// Returns `None` when the file is absent, unreadable, undecodable, or
/// carries a different [`SNAPSHOT_VERSION`] — in every case the caller
/// proceeds as if there were no prior state (and re-seeds from env).
pub fn load_auth_snapshot(path: &Path) -> Option<AuthSnapshot> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %path.display(), error = %e, "auth snapshot read failed; ignoring");
            }
            return None;
        }
    };
    match bincode::deserialize::<AuthSnapshot>(&bytes) {
        Ok(snap) if snap.version == SNAPSHOT_VERSION => Some(snap),
        Ok(snap) => {
            tracing::warn!(
                found = snap.version,
                expected = SNAPSHOT_VERSION,
                "auth snapshot version mismatch; ignoring (treating as no prior state)"
            );
            None
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "auth snapshot decode failed; ignoring");
            None
        }
    }
}

/// Atomically persist `snapshot` to `path`: write a sibling `*.tmp`,
/// fsync it, then rename over the target. Creates the parent directory
/// if needed. Errors are returned (the caller logs + continues —
/// persistence is best-effort).
pub fn save_auth_snapshot(path: &Path, snapshot: &AuthSnapshot) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = bincode::serialize(snapshot)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // `*.tmp` sibling on the SAME directory so the rename is atomic
    // (rename across filesystems is not).
    let tmp = path.with_extension("db.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::ApiCredentials;
    use std::collections::HashSet;

    fn sample_creds(key: &str, admin: bool) -> ApiCredentials {
        ApiCredentials::from_plaintext(key, "secret", "pass", admin).expect("hash")
    }

    #[test]
    fn roundtrip_preserves_accounts_and_jtis() {
        let dir = tempfile::tempdir().unwrap();
        let path = accounts_db_path(dir.path());

        let mut revoked = HashMap::new();
        revoked.insert("jti-abc".to_string(), 1_900_000_000);
        revoked.insert("jti-def".to_string(), 1_900_000_001);
        let snap = AuthSnapshot::new(
            vec![sample_creds("admin", true), sample_creds("bob", false)],
            &revoked,
        );

        save_auth_snapshot(&path, &snap).unwrap();
        let loaded = load_auth_snapshot(&path).expect("snapshot present");

        // Accounts compare as sets (HashMap iteration order is
        // unspecified), so sort by api_key before comparing.
        let mut a = snap.accounts.clone();
        let mut b = loaded.accounts.clone();
        a.sort_by(|x, y| x.api_key.cmp(&y.api_key));
        b.sort_by(|x, y| x.api_key.cmp(&y.api_key));
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.api_key, y.api_key);
            assert_eq!(x.secret_hash, y.secret_hash);
            assert_eq!(x.passphrase_hash, y.passphrase_hash);
            assert_eq!(x.is_admin, y.is_admin);
        }

        let ra: HashSet<_> = snap.revoked_jtis.iter().collect();
        let rb: HashSet<_> = loaded.revoked_jtis.iter().collect();
        assert_eq!(ra, rb);
    }

    #[test]
    fn missing_file_loads_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_auth_snapshot(&accounts_db_path(dir.path())).is_none());
    }

    #[test]
    fn corrupt_file_loads_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = accounts_db_path(dir.path());
        std::fs::write(&path, b"not a valid bincode snapshot").unwrap();
        assert!(load_auth_snapshot(&path).is_none());
    }

    #[test]
    fn version_mismatch_loads_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = accounts_db_path(dir.path());
        let bad = AuthSnapshot {
            version: SNAPSHOT_VERSION + 99,
            accounts: vec![],
            revoked_jtis: vec![],
        };
        // Write it directly (save_auth_snapshot would stamp the real
        // version), then confirm load rejects it.
        std::fs::write(&path, bincode::serialize(&bad).unwrap()).unwrap();
        assert!(load_auth_snapshot(&path).is_none());
    }

    #[test]
    fn save_is_atomic_no_tmp_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = accounts_db_path(dir.path());
        let snap = AuthSnapshot::new(vec![sample_creds("admin", true)], &HashMap::new());
        save_auth_snapshot(&path, &snap).unwrap();
        // The temp sibling must not survive a successful save.
        assert!(!path.with_extension("db.tmp").exists());
        assert!(path.exists());
    }
}
