//! Best-effort persistence of the settle pipeline's PENDING marker roots — the
//! batch Merkle roots whose `BatchValidityMarker` PDA has settled but not yet
//! been rent-reclaimed. The settle worker enqueues a root when its Tx Ds confirm;
//! [`super::super::settle::marker_sweep`] reads the on-chain expiry and closes it
//! asynchronously only once it is no longer usable.
//!
//! This log lets the sweep survive a CVM restart / redeploy: on boot the sweeper
//! replays the un-closed roots and reclaims their rent. Pure bookkeeping — never
//! user funds, never settlement finality.
//!
//! Same durability model as [`super::auth`]: a `bincode` snapshot on the dstack
//! LUKS volume, atomic tmp → fsync → rename, best-effort (a missing / corrupt /
//! version-mismatched file → an empty set; `path == None` disables persistence
//! entirely, e.g. tests / no-volume deploys — the set still works in memory, it
//! just doesn't survive a restart).

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Snapshot file name within the configured state dir.
pub const MARKERS_DB_FILE: &str = "pending_markers.db";

/// Snapshot file for the pending-LOCK set (S-03(B)). A sibling file rather
/// than a second module: the set is the same shape (32-byte keys awaiting a
/// permissionless on-chain close), only the keys differ — batch roots vs note
/// commitments — so it shares this crash-recovery code instead of duplicating
/// it.
pub const LOCKS_DB_FILE: &str = "pending_locks.db";

/// Bumped on any non-backward-compatible change to [`MarkersSnapshot`].
const SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MarkersSnapshot {
    version: u32,
    pending: Vec<[u8; 32]>,
}

/// Full path to the pending-markers snapshot within `state_dir`.
pub fn markers_db_path(state_dir: &Path) -> PathBuf {
    state_dir.join(MARKERS_DB_FILE)
}

/// In-memory pending set + its backing file.
///
/// Used for both the batch-marker sweeper and the note-lock sweeper; the two
/// keep SEPARATE files so a corrupt or version-skewed snapshot of one cannot
/// take the other down.
#[derive(Debug, Default)]
pub struct PendingSet {
    /// `None` disables persistence (in-memory only).
    path: Option<PathBuf>,
    set: HashSet<[u8; 32]>,
}

/// Backwards-compatible alias — the marker sweeper's original name.
pub type PendingMarkers = PendingSet;

impl PendingSet {
    /// Load the pending MARKER set from `state_dir` (best-effort). `None` → an
    /// empty, non-persistent set.
    pub fn load(state_dir: Option<&Path>) -> Self {
        Self::load_named(state_dir, MARKERS_DB_FILE)
    }

    /// Load a pending set backed by `file_name` within `state_dir`.
    pub fn load_named(state_dir: Option<&Path>, file_name: &str) -> Self {
        let path = state_dir.map(|d| d.join(file_name));
        let set = match &path {
            Some(p) => load_snapshot(p)
                .map(|s| s.pending.into_iter().collect())
                .unwrap_or_default(),
            None => HashSet::new(),
        };
        Self { path, set }
    }

    /// Mark a root pending and persist. No-op (no disk write) if already present.
    pub fn add(&mut self, root: [u8; 32]) {
        if self.set.insert(root) {
            self.persist();
        }
    }

    /// Drop a closed root and persist. No-op if absent.
    pub fn remove(&mut self, root: &[u8; 32]) {
        if self.set.remove(root) {
            self.persist();
        }
    }

    /// Snapshot of every pending root (order unspecified).
    pub fn all(&self) -> Vec<[u8; 32]> {
        self.set.iter().copied().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    fn persist(&self) {
        let Some(path) = &self.path else { return };
        let snap = MarkersSnapshot {
            version: SNAPSHOT_VERSION,
            pending: self.set.iter().copied().collect(),
        };
        if let Err(e) = save_snapshot(path, &snap) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "pending-markers persist failed (best-effort; in-memory state intact)"
            );
        }
    }
}

/// Load + version-check a snapshot, best-effort (`None` on any problem).
fn load_snapshot(path: &Path) -> Option<MarkersSnapshot> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %path.display(), error = %e, "pending-markers read failed; ignoring");
            }
            return None;
        }
    };
    match bincode::deserialize::<MarkersSnapshot>(&bytes) {
        Ok(s) if s.version == SNAPSHOT_VERSION => Some(s),
        Ok(s) => {
            tracing::warn!(
                found = s.version,
                expected = SNAPSHOT_VERSION,
                "pending-markers version mismatch; ignoring (treating as empty)"
            );
            None
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "pending-markers decode failed; ignoring");
            None
        }
    }
}

/// Atomic write: sibling `*.tmp` → fsync → rename. Mirrors `auth::save_auth_snapshot`.
fn save_snapshot(path: &Path, snap: &MarkersSnapshot) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = bincode::serialize(snap)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
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

    #[test]
    fn add_remove_all_in_memory() {
        let mut m = PendingMarkers::load(None);
        assert!(m.is_empty());
        m.add([1u8; 32]);
        m.add([2u8; 32]);
        m.add([1u8; 32]); // dup → no-op
        assert_eq!(m.len(), 2);
        m.remove(&[1u8; 32]);
        assert_eq!(m.all(), vec![[2u8; 32]]);
    }

    #[test]
    fn persists_and_reloads_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut m = PendingMarkers::load(Some(dir.path()));
            m.add([7u8; 32]);
            m.add([9u8; 32]);
            m.remove(&[7u8; 32]);
        } // dropped — simulate restart
        let reloaded = PendingMarkers::load(Some(dir.path()));
        assert_eq!(reloaded.all(), vec![[9u8; 32]]);
        // No torn temp left behind.
        assert!(!markers_db_path(dir.path())
            .with_extension("db.tmp")
            .exists());
    }

    #[test]
    fn missing_and_corrupt_load_empty() {
        let dir = tempfile::tempdir().unwrap();
        // Missing file → empty.
        assert!(PendingMarkers::load(Some(dir.path())).is_empty());
        // Corrupt file → empty (never panics).
        std::fs::write(markers_db_path(dir.path()), b"not bincode").unwrap();
        assert!(PendingMarkers::load(Some(dir.path())).is_empty());
    }

    #[test]
    fn version_mismatch_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let bad = MarkersSnapshot {
            version: SNAPSHOT_VERSION + 99,
            pending: vec![[3u8; 32]],
        };
        std::fs::write(
            markers_db_path(dir.path()),
            bincode::serialize(&bad).unwrap(),
        )
        .unwrap();
        assert!(PendingMarkers::load(Some(dir.path())).is_empty());
    }
}
