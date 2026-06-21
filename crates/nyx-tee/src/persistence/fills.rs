//! P7 — durable per-account fill-memo log for memo replay.
//!
//! Amount-privacy (P3b/P4) moved trade amounts off-chain into the per-account
//! `FillMemo`. Those memos were ephemeral (an in-memory broadcast, dropped if no
//! `/ws/fills` client was attached, wiped on restart), so a client offline when
//! a fill settled could LOCATE its change-note commitment via the indexer but
//! never recover the amount → a stranded, unspendable note.
//!
//! This module makes the memos durable + replayable. Every routed memo is
//! appended here with a per-account monotonic `seq`; `GET /fills/replay?since=`
//! serves `seq > since`. The on-disk form is bincode on the same LUKS-encrypted
//! volume as the auth snapshot (`persistence::auth`) — encrypted-at-rest,
//! atomic write-rename, version-gated, best-effort. Memos NEVER leave the
//! enclave except over the authenticated per-account channel.
//!
//! Retention (P7d, v1): a per-account ring cap [`MAX_MEMOS_PER_ACCOUNT`] + a
//! [`MEMO_TTL_SECS`] age cap, both applied on append. A note left unspent past
//! the TTL loses replay (rare; its commitment is still on-chain + locatable).
//!
//! Integrity is unchanged: a replayed memo runs the SAME client-side
//! `verifyFillMemo` (Vuln-4) guard as a live one, so a corrupted log can't
//! inject a spendable note — the recomputed commitment wouldn't match the
//! on-chain one.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::matcher::FillMemo;

/// Snapshot file name within the configured state directory.
pub const FILLS_DB_FILE: &str = "fills.db";

/// Bumped on any non-backward-compatible change to the on-disk layout. A
/// snapshot with a different version is treated as absent (best-effort).
const FILLS_SNAPSHOT_VERSION: u32 = 1;

/// Per-account ring cap — at most this many most-recent memos are retained.
pub const MAX_MEMOS_PER_ACCOUNT: usize = 512;

/// Age cap for a stored memo (seconds). 30 days.
pub const MEMO_TTL_SECS: u64 = 30 * 24 * 3600;

/// One persisted memo + its routing metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredMemo {
    /// Per-account monotonic sequence (also mirrored into `memo.seq`).
    pub seq: u64,
    /// Unix seconds at append time — drives the TTL prune.
    pub stored_at: u64,
    /// The routed memo (carries `seq = Some(seq)`).
    pub memo: FillMemo,
}

/// One account's durable memo log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountFillLog {
    pub account_id: String,
    /// Next seq to assign (monotonic, never reused while persisted).
    pub next_seq: u64,
    /// Retained memos, oldest first (ring + TTL pruned on append).
    pub memos: Vec<StoredMemo>,
}

/// The full on-disk snapshot. Serialised with bincode.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FillLogSnapshot {
    pub version: u32,
    pub accounts: Vec<AccountFillLog>,
}

/// In-memory runtime form of the fill log: the source of truth for replay,
/// flushed to disk best-effort. Wrapped in a lock by `ApiState`.
#[derive(Debug, Default)]
pub struct FillLog {
    accounts: HashMap<String, AccountFillLog>,
}

impl FillLog {
    /// Rebuild the runtime log from a loaded snapshot.
    pub fn from_snapshot(snap: FillLogSnapshot) -> Self {
        let accounts = snap
            .accounts
            .into_iter()
            .map(|a| (a.account_id.clone(), a))
            .collect();
        Self { accounts }
    }

    /// Materialise the current state into a serialisable snapshot.
    pub fn to_snapshot(&self) -> FillLogSnapshot {
        FillLogSnapshot {
            version: FILLS_SNAPSHOT_VERSION,
            accounts: self.accounts.values().cloned().collect(),
        }
    }

    /// Append `memo` for `account_id`, stamping + returning the routed memo with
    /// its assigned `seq`. Applies the ring + TTL retention. `now` is unix secs.
    pub fn append(&mut self, account_id: &str, mut memo: FillMemo, now: u64) -> FillMemo {
        // seq is 1-based: seq 0 is reserved as the client's "no cursor / give me
        // everything" sentinel (`replay_since(.., 0)` returns all, since every
        // real memo has seq >= 1).
        let log = self
            .accounts
            .entry(account_id.to_string())
            .or_insert_with(|| AccountFillLog {
                account_id: account_id.to_string(),
                next_seq: 1,
                memos: Vec::new(),
            });
        let seq = log.next_seq;
        log.next_seq = log.next_seq.saturating_add(1);
        memo.seq = Some(seq);
        log.memos.push(StoredMemo {
            seq,
            stored_at: now,
            memo: memo.clone(),
        });
        prune(log, now);
        memo
    }

    /// All retained memos for `account_id` with `seq > since`, oldest first.
    /// Empty when the account is unknown or fully caught up. The client passes
    /// `since = 0` for a first/no-cursor sync (every real memo has `seq >= 1`),
    /// then `since = <max seq it has stored>` thereafter.
    pub fn replay_since(&self, account_id: &str, since: u64) -> Vec<FillMemo> {
        self.accounts
            .get(account_id)
            .map(|log| {
                log.memos
                    .iter()
                    .filter(|m| m.seq > since)
                    .map(|m| m.memo.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Number of retained memos for an account (test/observability helper).
    pub fn len_for(&self, account_id: &str) -> usize {
        self.accounts.get(account_id).map_or(0, |l| l.memos.len())
    }
}

/// Drop memos older than the TTL, then trim the oldest down to the ring cap.
fn prune(log: &mut AccountFillLog, now: u64) {
    log.memos
        .retain(|m| now.saturating_sub(m.stored_at) < MEMO_TTL_SECS);
    if log.memos.len() > MAX_MEMOS_PER_ACCOUNT {
        let overflow = log.memos.len() - MAX_MEMOS_PER_ACCOUNT;
        log.memos.drain(0..overflow);
    }
}

/// Full path to the fill-log snapshot within `state_dir`.
pub fn fills_db_path(state_dir: &Path) -> PathBuf {
    state_dir.join(FILLS_DB_FILE)
}

/// Load the fill-log snapshot, best-effort. `None` on absent / unreadable /
/// undecodable / version-mismatch (the caller starts with an empty log).
pub fn load_fill_log(path: &Path) -> Option<FillLogSnapshot> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %path.display(), error = %e, "fill-log read failed; ignoring");
            }
            return None;
        }
    };
    match bincode::deserialize::<FillLogSnapshot>(&bytes) {
        Ok(snap) if snap.version == FILLS_SNAPSHOT_VERSION => Some(snap),
        Ok(snap) => {
            tracing::warn!(
                found = snap.version,
                expected = FILLS_SNAPSHOT_VERSION,
                "fill-log version mismatch; ignoring (treating as no prior memos)"
            );
            None
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "fill-log decode failed; ignoring");
            None
        }
    }
}

/// Atomically persist `snapshot` to `path` (write `*.tmp`, fsync, rename over).
/// Mirrors `persistence::auth::save_auth_snapshot`.
pub fn save_fill_log(path: &Path, snapshot: &FillLogSnapshot) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = bincode::serialize(snapshot)
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

    fn memo(order: &str, amount: u64) -> FillMemo {
        FillMemo {
            seq: None,
            order_id: order.to_string(),
            anchor_index: 0,
            change_amount: amount,
            change_note_commitment: "cc".repeat(32),
            mint: "11".repeat(32),
            inner_hash: "22".repeat(32),
        }
    }

    #[test]
    fn append_assigns_monotonic_seq_per_account() {
        let mut log = FillLog::default();
        let a0 = log.append("alice", memo("01", 100), 1000);
        let a1 = log.append("alice", memo("02", 200), 1001);
        let b0 = log.append("bob", memo("03", 300), 1002);
        // 1-based, per-account: alice gets 1,2; bob's first is also 1.
        assert_eq!(a0.seq, Some(1));
        assert_eq!(a1.seq, Some(2));
        assert_eq!(b0.seq, Some(1));
    }

    #[test]
    fn replay_since_filters_by_cursor_and_isolates_accounts() {
        let mut log = FillLog::default();
        log.append("alice", memo("01", 100), 1000); // seq 1
        log.append("alice", memo("02", 200), 1001); // seq 2
        log.append("alice", memo("03", 300), 1002); // seq 3
        log.append("bob", memo("99", 999), 1003); // bob seq 1

        // since = 0 is the "no cursor / give me everything" first sync.
        let from_start = log.replay_since("alice", 0);
        assert_eq!(from_start.len(), 3);
        assert_eq!(from_start[0].seq, Some(1));
        assert_eq!(from_start[2].seq, Some(3));

        // Incremental: cursor at the 2nd memo → only the 3rd is new.
        let incremental = log.replay_since("alice", 2);
        assert_eq!(incremental.len(), 1);
        assert_eq!(incremental[0].seq, Some(3));

        // Caught up.
        assert!(log.replay_since("alice", 3).is_empty());

        // Account isolation: bob sees only his own one memo.
        let bob = log.replay_since("bob", 0);
        assert_eq!(bob.len(), 1);
        assert_eq!(bob[0].change_amount, 999);
        assert_eq!(log.len_for("bob"), 1);
        // Unknown account is empty, not a panic.
        assert!(log.replay_since("carol", 0).is_empty());
    }

    #[test]
    fn ring_cap_keeps_the_newest() {
        let mut log = FillLog::default();
        for i in 0..(MAX_MEMOS_PER_ACCOUNT + 50) {
            log.append("alice", memo("aa", i as u64), 1000);
        }
        assert_eq!(log.len_for("alice"), MAX_MEMOS_PER_ACCOUNT);
        // The oldest 50 (seqs 1..=50) were dropped; surviving seqs start at 51
        // and the newest (seq MAX+50) is preserved.
        let all = log.replay_since("alice", 0);
        assert_eq!(all.first().unwrap().seq, Some(51));
        assert_eq!(
            all.last().unwrap().seq,
            Some((MAX_MEMOS_PER_ACCOUNT + 50) as u64)
        );
    }

    #[test]
    fn ttl_prune_drops_aged_memos() {
        let mut log = FillLog::default();
        log.append("alice", memo("01", 1), 1000); // ancient (seq 1)
                                                  // A much later memo triggers the TTL prune of the ancient one.
        let late = log.append("alice", memo("02", 2), 1000 + MEMO_TTL_SECS + 1);
        assert_eq!(log.len_for("alice"), 1);
        // Only the late memo survives; seq still advanced (2, not reused).
        assert_eq!(late.seq, Some(2));
        assert_eq!(log.replay_since("alice", 0).len(), 1);
    }

    #[test]
    fn snapshot_roundtrip_preserves_seq_and_memos() {
        let dir = tempfile::tempdir().unwrap();
        let path = fills_db_path(dir.path());
        let mut log = FillLog::default();
        log.append("alice", memo("01", 100), 1000); // seq 1
        log.append("alice", memo("02", 200), 1001); // seq 2
        save_fill_log(&path, &log.to_snapshot()).expect("save");

        let mut loaded = FillLog::from_snapshot(load_fill_log(&path).expect("present"));
        assert_eq!(loaded.len_for("alice"), 2);
        // next_seq carried forward → a post-reload append continues at 3.
        let next = loaded.append("alice", memo("03", 300), 1002);
        assert_eq!(next.seq, Some(3));
    }

    #[test]
    fn missing_or_corrupt_file_loads_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = fills_db_path(dir.path());
        assert!(load_fill_log(&path).is_none());
        std::fs::write(&path, b"not bincode").unwrap();
        assert!(load_fill_log(&path).is_none());
    }
}
