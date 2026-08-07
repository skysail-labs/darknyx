//! Write-ahead journal for in-flight settlements (audit finding T-06).
//!
//! # The gap this closes
//!
//! `OpeningStore` held the only copy of each order's note opening — owner
//! commitment, inner hash, amount, viewing key, and the relayed `VALID_INPUT`
//! proof — and it lived in memory alone. The asymmetry is what makes this a
//! funds-availability problem rather than an inconvenience: **the on-chain
//! `NoteLock` survives a restart and the enclave's ability to use or release it
//! does not.** After a redeploy the enclave has no record that it locked those
//! notes, so it can neither assemble their settle nor release them early. Every
//! affected user's collateral stays frozen until lock expiry (~30 min), with no
//! fill, no cancel, and no order update — and they cannot re-place against the
//! same note, because the surviving on-chain lock blocks a fresh `lock_note`.
//!
//! A redeploy is a routine operation. It is the documented way to change env or
//! roll an image.
//!
//! # Why write-ahead, and why the ordering is the whole design
//!
//! Recording state *after* an external side effect is worthless for recovery:
//! the crash window that matters is exactly between "we sent something" and "we
//! wrote down that we sent it". A transaction submitted but not journaled is
//! unrecoverable — on restart the enclave cannot even name the signature to ask
//! the chain about, so it cannot distinguish "never sent" from "sent and
//! landed".
//!
//! So every durable transition is written BEFORE its side effect, and the settle
//! signature is journaled BEFORE submission rather than after. (Only the settle
//! signature: it is the one whose orphan is unrecoverable.) That is possible
//! because a Solana transaction's signature is fully determined once it is
//! signed, which happens before it is sent. The invariant we get:
//!
//! > If a transaction reached the network, its signature is already on disk.
//!
//! Reconciliation depends entirely on that invariant. Weaken it — journal after
//! send "because it is simpler" — and a crash in the window leaves an orphan
//! transaction that recovery cannot reason about.
//!
//! # Durability: why `fsync` on the file is not enough
//!
//! The existing helpers (`persistence::auth`, `persistence::markers`) write
//! tmp → `sync_all` → `rename`. That makes the *contents* durable but not the
//! *rename*: the directory entry lives in the parent directory's own metadata,
//! and after a crash the rename can be lost even though the data was synced —
//! leaving the previous version, or on some filesystems no entry at all. Those
//! helpers hold best-effort bookkeeping, where losing the last update costs a
//! rent sweep. This journal is the difference between releasing a user's
//! collateral and freezing it, so it also fsyncs the parent directory after the
//! rename. Recorded as a deliberate difference, not an inconsistency; the older
//! helpers are worth upgrading separately.
//!
//! # This file holds user secrets
//!
//! Journaled entries include note commitments, order ids, and each side's
//! relayed `VALID_INPUT` proof — data that links a user to a position. That is a
//! deliberate, recorded decision: the state directory is the dstack-sealed LUKS
//! volume whose key is released only to the attested measurement, which is the
//! same protection the account registry (`persistence::auth`) already relies on.
//! No new trust assumption is introduced — but it does mean this file must never
//! be written outside `DARKNYX_TEE_STATE_DIR`, and `path == None` (tests, deploys
//! with no volume) must keep everything in memory rather than falling back to a
//! temporary directory.
//!
//! # Shape
//!
//! A snapshot of the in-flight set, rewritten per transition, rather than an
//! append-only log. Terminal jobs are evicted immediately, so the set stays
//! bounded by concurrent batches × matches-per-batch and the rewrite stays
//! small. The snapshot form also avoids torn-tail recovery, which an append-only
//! log would need to handle correctly to be worth its lower write amplification.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::settle::payload::MatchResultPayload;
use crate::settle::submit_lock::LockSideInputs;

/// Journal file name within the configured state dir.
pub const JOURNAL_DB_FILE: &str = "settle_journal.db";

/// Bumped on any non-backward-compatible change to [`JournalSnapshot`].
///
/// v1 -> v2 (2026-08): `MatchResultPayload` replaced its two consumed
/// commitments with note-use TAGS and grew by the two relock tags (488 -> 552
/// bytes), and `LockSideInputs` follows. A v1 entry decoded as v2 would
/// misattribute every field after the change.
///
/// OPERATIONAL CONSEQUENCE: a version mismatch is `Damaged`, NOT "start empty"
/// (deliberately — see [`JournalLoad`]). So an enclave upgraded across this
/// bump with entries still in flight demands an operator. **Drain before
/// upgrading**: `POST /admin/drain`, wait for `safe_to_stop`, then deploy.
///
/// A version mismatch is NOT treated as "start empty" the way the best-effort
/// bookkeeping snapshots are — see [`JournalLoad`].
const JOURNAL_VERSION: u32 = 2;

/// Where a job had got to when it was last journaled. Deliberately a small
/// closed enum rather than a reuse of `SettleJobStage`: this is an on-disk
/// schema, and an internal refactor of the pipeline's stage type must not
/// silently change what previously-written files mean.
/// `use_discriminant = true` is required, not incidental: these numbers ARE the
/// on-disk encoding. With the default (positional) encoding, reordering the
/// variants would silently reinterpret every previously-written journal — a
/// `Settling` entry could load back as `Locking` and recovery would redrive a
/// transaction that had already been sent. Pinning the discriminants means a
/// variant may be appended but never reordered or renumbered.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
pub enum JournalStage {
    /// Openings captured, nothing submitted yet.
    Prepared = 0,
    /// `lock_note` submitted (signatures recorded).
    Locking = 1,
    /// Proof generated, `verify_match_batch` submitted.
    Verifying = 2,
    /// `tee_forced_settle_batched` signed and about to be, or already, sent.
    Settling = 3,
    /// Tx D observed confirmed. Retained only until reconciliation drops it.
    Settled = 4,
}

impl JournalStage {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Locking => "locking",
            Self::Verifying => "verifying",
            Self::Settling => "settling",
            Self::Settled => "settled",
        }
    }
}

/// One in-flight settlement, with everything needed to reconcile it against the
/// chain after a restart without consulting any in-memory state.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct JournalEntry {
    pub batch_id: u64,
    pub match_idx: u8,
    pub stage: JournalStage,
    /// The settle payload — the Tx D instruction argument, and the source of
    /// the two consumed-note commitments recovery reconciles against. Journaling
    /// the payload rather than the matcher's `MatchPair` is deliberate: this is
    /// exactly what the settle path consumes, so a recovered entry rebuilds the
    /// transaction without re-deriving anything that could drift.
    pub payload: MatchResultPayload,
    /// `lock_note` inputs for each side, including the relayed VALID_INPUT
    /// proof. Without these a restart cannot reissue Tx A, which is what leaves
    /// collateral frozen behind a lock the enclave can no longer use.
    pub buyer_lock: LockSideInputs,
    pub seller_lock: LockSideInputs,
    /// Batch Merkle root — derives the `BatchValidityMarker` PDA.
    ///
    /// `match_idx` above doubles as the position-in-batch that selects the
    /// Merkle inclusion path; they were previously two fields holding the same
    /// value, which is a redundant invariant an on-disk schema should not
    /// encode. If the two ever need to differ, add the second field back
    /// deliberately rather than letting them drift.
    pub batch_root: Option<[u8; 32]>,
    /// Slot after which the notes' locks expire and are permissionlessly
    /// releasable.
    pub lock_expiry_slot: u64,
    /// `BatchValidityMarker` expiry, known only once `verify_match_batch`
    /// lands. `None` means verify never landed, so no marker PDA exists and
    /// there is nothing a redrive could settle against.
    ///
    /// This is the BINDING bound, not the lock expiry: the marker TTL is 300
    /// slots (~2 min) against the lock's ~30 min, and `tee_forced_settle_batched`
    /// reads the marker. Recovery that considered only the lock would authorise
    /// redrives that revert on the marker check.
    pub marker_expiry_slot: Option<u64>,
    /// The settle transaction's signature, written BEFORE the transaction is
    /// submitted.
    ///
    /// Only the SETTLE signature is journaled. Lock and verify signatures were
    /// once fields here and were never written — dead weight in an on-disk
    /// schema, which is worse than dead code because it invites a reader to
    /// believe recovery consults them. Recovery does not need them: the
    /// consumed-note PDAs decide whether a settle landed, and a lock or verify
    /// that did not land simply leaves nothing to reconcile.
    pub settle_sig: Option<String>,
    /// Unix ms of the last durable write, for staleness reporting on boot.
    pub updated_at_ms: u64,
}

impl JournalEntry {
    pub fn key(&self) -> (u64, u8) {
        (self.batch_id, self.match_idx)
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct JournalSnapshot {
    version: u32,
    entries: Vec<JournalEntry>,
}

/// Outcome of reading the journal at boot.
///
/// Unlike the best-effort bookkeeping snapshots, a damaged journal is NOT
/// silently treated as empty. "Empty" and "unreadable" mean opposite things
/// here: empty says *no settlement was in flight, nothing to reconcile*, while
/// unreadable says *settlements may be in flight and their record is gone*.
/// Collapsing the second into the first would let a boot conclude there is
/// nothing to recover precisely when recovery matters most — the same
/// "reports success without checking" failure this codebase keeps finding.
/// The caller decides what to do; it must not be able to ignore the difference
/// by accident.
#[derive(Debug)]
pub enum JournalLoad {
    /// No journal file — a clean first boot, or the previous run ended with
    /// nothing in flight.
    Fresh,
    /// A readable journal with zero or more entries to reconcile.
    Recovered(Vec<JournalEntry>),
    /// The file exists but could not be understood. Carries the reason for the
    /// operator; the enclave must not assume nothing was in flight.
    Damaged { reason: String },
}

/// How many recent `record` durations are retained for percentiles.
///
/// Percentiles need the samples themselves, and this is the whole point of
/// bounding them: a full 16-match batch writes on the order of tens of times, so
/// 512 covers several batches while costing ~4 KiB and a sort of at most 512
/// `u64`s per emit.
const WRITE_SAMPLES: usize = 512;

/// At most one summary line per this interval, and only when new samples exist.
///
/// The drill reads these out of `phala logs`, so the cadence has to be short
/// enough that a run interrupted after a handful of writes still produces a
/// line, and long enough that a production settle loop does not spam. Ten
/// seconds gives the drill its data within one poll and caps production at six
/// lines a minute.
const WRITE_SUMMARY_EVERY: Duration = Duration::from_secs(10);

/// Durable-write cost for the journal (T-06's missing measurement).
///
/// The recovery drill's cost table lists per-transition write p50/p95 as a
/// mandatory closing measurement, and it was never captured — T-06 closed on an
/// explicitly recorded waiver instead. Three end-to-end settle samples are not
/// percentiles, so this measures the write itself.
///
/// Scoped to [`SettleJournal::record`] deliberately. That is the write-ahead
/// cost that sits on the settle critical path: it happens BEFORE the side effect
/// it protects, so it is latency the settle actually pays. `forget` and
/// `forget_batch` also flush, but they run after the outcome is known and only
/// shrink the file; folding them in would drag the distribution toward a cheaper
/// operation and misreport exactly the number this exists to establish.
#[derive(Debug, Default)]
struct WriteStats {
    /// Lifetime count — NOT `samples.len()`, which saturates at the ring size.
    count: u64,
    /// Most recent durations, oldest first, capped at [`WRITE_SAMPLES`].
    samples: VecDeque<u64>,
    /// Lifetime extremes, unaffected by the ring evicting old samples.
    max_us: u64,
    /// When the last summary was emitted; `None` until the first write.
    last_emit: Option<Instant>,
}

impl WriteStats {
    fn record(&mut self, us: u64) {
        self.count += 1;
        self.max_us = self.max_us.max(us);
        if self.samples.len() == WRITE_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(us);
    }

    /// `(p50, p95)` over the retained samples, or `None` if there are none.
    ///
    /// Nearest-rank on a sorted copy. With at most 512 `u64`s this is cheaper
    /// than maintaining an ordered structure, and it keeps the samples in
    /// arrival order so the ring can evict the oldest.
    fn percentiles(&self) -> Option<(u64, u64)> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted: Vec<u64> = self.samples.iter().copied().collect();
        sorted.sort_unstable();
        let at = |q: f64| -> u64 {
            let rank = ((sorted.len() as f64) * q).ceil() as usize;
            sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
        };
        Some((at(0.50), at(0.95)))
    }

    /// True at most once per [`WRITE_SUMMARY_EVERY`], and only with new data.
    ///
    /// `emitted_at` must be the time of the EMISSION DECISION, not the start of
    /// the work being measured — stamping `last_emit` with a pre-flush instant
    /// leaves the throttle already expired after any flush longer than the
    /// interval.
    fn should_emit(&mut self, emitted_at: Instant) -> bool {
        match self.last_emit {
            Some(t) if emitted_at.duration_since(t) < WRITE_SUMMARY_EVERY => false,
            _ => {
                self.last_emit = Some(emitted_at);
                true
            }
        }
    }
}

/// A point-in-time view of the journal's durable-write cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct JournalWriteStats {
    pub count: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub max_us: u64,
}

/// The durable in-flight settlement set.
#[derive(Debug, Default)]
pub struct SettleJournal {
    /// `None` disables persistence entirely (in-memory only).
    path: Option<PathBuf>,
    /// Ordered so the on-disk byte sequence is a deterministic function of the
    /// contents — an unordered map would make otherwise-identical journals
    /// differ, which makes diffing a recovered file needlessly hard.
    entries: BTreeMap<(u64, u8), JournalEntry>,
    /// Durable-write cost. See [`WriteStats`].
    write_stats: WriteStats,
}

impl SettleJournal {
    /// An in-memory-only journal (no state dir configured).
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Open the journal in `state_dir`, reporting what was found.
    ///
    /// Returns the journal (always usable) alongside the load outcome the caller
    /// must act on.
    pub fn open(state_dir: Option<&Path>) -> (Self, JournalLoad) {
        let Some(dir) = state_dir else {
            return (Self::in_memory(), JournalLoad::Fresh);
        };
        let path = dir.join(JOURNAL_DB_FILE);
        let load = read_snapshot(&path);
        // A damaged file is the only thing an operator has to investigate with,
        // and the very next batch would rename a fresh snapshot over it. Move it
        // aside first so the new journal starts clean WITHOUT destroying the
        // evidence that just paged someone — including the partially-decodable
        // bytes of the realistic power-loss case.
        if let JournalLoad::Damaged { .. } = &load {
            let aside = dir.join(format!("{JOURNAL_DB_FILE}.damaged-{}", now_unix_ms()));
            match std::fs::rename(&path, &aside) {
                Ok(()) => tracing::error!(
                    preserved = %aside.display(),
                    "damaged settle journal moved aside for investigation"
                ),
                Err(e) => tracing::error!(
                    error = %e,
                    path = %path.display(),
                    "could not preserve the damaged settle journal; the next write \
                     will overwrite it"
                ),
            }
        }
        let entries = match &load {
            JournalLoad::Recovered(v) => v.iter().map(|e| (e.key(), e.clone())).collect(),
            _ => BTreeMap::new(),
        };
        (
            Self {
                path: Some(path),
                entries,
                write_stats: WriteStats::default(),
            },
            load,
        )
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, batch_id: u64, match_idx: u8) -> Option<&JournalEntry> {
        self.entries.get(&(batch_id, match_idx))
    }

    pub fn all(&self) -> Vec<JournalEntry> {
        self.entries.values().cloned().collect()
    }

    /// Whether this journal writes to disk at all.
    pub fn is_persistent(&self) -> bool {
        self.path.is_some()
    }

    /// Record or replace an entry and make it durable.
    ///
    /// Returns the io error rather than logging and continuing. A caller about
    /// to submit a transaction MUST treat a failed journal write as a reason not
    /// to submit: proceeding would create exactly the un-reconcilable orphan the
    /// write-ahead ordering exists to prevent. That is why this is not the
    /// best-effort `persist()` the bookkeeping snapshots use.
    pub fn record(&mut self, mut entry: JournalEntry) -> std::io::Result<()> {
        entry.updated_at_ms = now_unix_ms();
        self.entries.insert(entry.key(), entry);

        self.flush_measured()
    }

    /// Record or replace a group of entries with one durable snapshot.
    ///
    /// Settlement transitions are batch-shaped. Flushing once per match made
    /// an N=16 transition serialize an ever-growing journal sixteen times and
    /// issue thirty-two fsyncs. The snapshot is already the atomic unit, so
    /// inserting the whole transition and flushing once preserves the same
    /// write-ahead boundary without the O(N²) work (PF-12).
    pub fn record_many<I>(&mut self, entries: I) -> std::io::Result<()>
    where
        I: IntoIterator<Item = JournalEntry>,
    {
        let updated_at_ms = now_unix_ms();
        let mut changed = false;
        for mut entry in entries {
            entry.updated_at_ms = updated_at_ms;
            self.entries.insert(entry.key(), entry);
            changed = true;
        }
        if !changed {
            return Ok(());
        }

        self.flush_measured()
    }

    fn flush_measured(&mut self) -> std::io::Result<()> {
        // Time the FLUSH, not the map insert: the cost being measured is
        // tmp-write → fsync(file) → rename → fsync(dir), which is what the
        // settle waits on before it may submit.
        let started = Instant::now();
        let result = self.flush();
        // ONE timestamp taken after the flush, used for both the duration and
        // the throttle. Passing `started` to `should_emit` was wrong: it stamps
        // `last_emit` with a time from BEFORE the write, so a flush that took
        // longer than the interval — exactly the degraded-storage case the
        // summary exists to reveal — would leave the throttle already expired
        // and let the next write emit immediately, breaking the documented
        // one-line-per-interval bound precisely when logs matter most.
        let finished = Instant::now();
        let elapsed_us = finished
            .duration_since(started)
            .as_micros()
            .min(u64::MAX as u128) as u64;

        // A FAILED write is not a sample of what a write costs — it may have
        // aborted early — and counting it would pull the distribution toward
        // whatever the failure mode happens to cost. The failure is already
        // surfaced by returning the error, which the caller must treat as a
        // reason not to submit.
        if result.is_ok() {
            self.write_stats.record(elapsed_us);
            if self.write_stats.should_emit(finished) {
                if let Some((p50, p95)) = self.write_stats.percentiles() {
                    tracing::info!(
                        writes = self.write_stats.count,
                        entries = self.entries.len(),
                        p50_us = p50,
                        p95_us = p95,
                        max_us = self.write_stats.max_us,
                        "settle-journal durable write cost"
                    );
                }
            }
        }
        result
    }

    /// Snapshot of the durable-write cost, or `None` before the first
    /// successful write.
    ///
    /// Exposed so the measurement can be asserted in tests and read by a future
    /// admin surface without parsing log lines.
    pub fn write_stats(&self) -> Option<JournalWriteStats> {
        let (p50_us, p95_us) = self.write_stats.percentiles()?;
        Some(JournalWriteStats {
            count: self.write_stats.count,
            p50_us,
            p95_us,
            max_us: self.write_stats.max_us,
        })
    }

    /// Drop a settled or abandoned entry and make the removal durable.
    ///
    /// Removal failure is best-effort by contrast: a stale entry that survives
    /// is re-examined on the next boot and found already settled, which costs a
    /// reconciliation query and nothing else.
    pub fn forget(&mut self, batch_id: u64, match_idx: u8) {
        self.forget_many([(batch_id, match_idx)]);
    }

    /// Drop terminal entries with one best-effort durable snapshot.
    pub fn forget_many<I>(&mut self, keys: I)
    where
        I: IntoIterator<Item = (u64, u8)>,
    {
        let mut removed = 0usize;
        for key in keys {
            removed += usize::from(self.entries.remove(&key).is_some());
        }
        if removed > 0 {
            if let Err(e) = self.flush() {
                tracing::warn!(
                    removed,
                    error = %e,
                    "settle-journal removals failed; entries will be re-reconciled on next boot"
                );
            }
        }
    }

    /// Drop every entry for a batch (all matches terminal).
    pub fn forget_batch(&mut self, batch_id: u64) {
        let before = self.entries.len();
        self.entries.retain(|(b, _), _| *b != batch_id);
        if self.entries.len() != before {
            if let Err(e) = self.flush() {
                tracing::warn!(batch_id, error = %e, "settle-journal batch removal failed");
            }
        }
    }

    fn flush(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let snap = JournalSnapshot {
            version: JOURNAL_VERSION,
            entries: self.entries.values().cloned().collect(),
        };
        write_snapshot(path, &snap)
    }
}

/// Atomic, genuinely durable write: tmp → fsync(file) → rename → fsync(dir).
///
/// The trailing directory sync is what distinguishes this from the best-effort
/// helpers; see the module docs.
fn write_snapshot(path: &Path, snap: &JournalSnapshot) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("journal path has no parent directory"))?;
    std::fs::create_dir_all(parent)?;

    let bytes =
        borsh::to_vec(snap).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let tmp = path.with_extension("db.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        // Contents durable before the rename can publish them.
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;

    // Rename durable. Without this the entry can be lost on power failure even
    // though the bytes were synced, which would silently roll the journal back
    // to its previous state — the one case where "mostly durable" is the same as
    // "not durable", because recovery would then act on stale truth.
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn read_snapshot(path: &Path) -> JournalLoad {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return JournalLoad::Fresh,
        Err(e) => {
            return JournalLoad::Damaged {
                reason: format!("read failed: {e}"),
            }
        }
    };
    match JournalSnapshot::try_from_slice(&bytes) {
        Ok(s) if s.version == JOURNAL_VERSION => JournalLoad::Recovered(s.entries),
        Ok(s) => JournalLoad::Damaged {
            reason: format!(
                "version {} on disk, this build writes {JOURNAL_VERSION}",
                s.version
            ),
        },
        Err(e) => JournalLoad::Damaged {
            reason: format!("decode failed (truncated or corrupt): {e}"),
        },
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::settle::lock_note::Groth16ProofBytes;

    fn proof() -> Groth16ProofBytes {
        Groth16ProofBytes {
            pi_a: [0x11; 64],
            pi_b: [0x22; 128],
            pi_c: [0x33; 64],
        }
    }

    fn lock_side(note: u8, order: u8) -> LockSideInputs {
        LockSideInputs {
            tree_id: 2,
            note_use_tag: [note; 32],
            order_id: [order; 16],
            expiry_slot: 1_000,
            token_mint: [0x0F; 32],
            merkle_root: [0x7C; 32],
            proof: proof(),
            already_locked: false,
        }
    }

    fn payload(match_id: u8) -> MatchResultPayload {
        MatchResultPayload {
            match_id: [match_id; 16],
            note_a_use_tag: [0xA1; 32],
            note_b_use_tag: [0xB1; 32],
            note_c_commitment: [0xC1; 32],
            note_d_commitment: [0xD1; 32],
            note_e_commitment: [0xE1; 32],
            note_f_commitment: [0xF1; 32],
            order_id_a: [0x01; 16],
            order_id_b: [0x02; 16],
            note_fee_base_commitment: [0; 32],
            note_fee_quote_commitment: [0; 32],
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
            note_e_use_tag: [0u8; 32],
            note_f_use_tag: [0u8; 32],
            batch_slot: 7,
            fill_recovery: [0u8; 128],
        }
    }

    pub(super) fn entry(batch_id: u64, match_idx: u8, stage: JournalStage) -> JournalEntry {
        JournalEntry {
            batch_id,
            match_idx,
            stage,
            payload: payload(match_idx),
            buyer_lock: lock_side(0xA1, 0x01),
            seller_lock: lock_side(0xB1, 0x02),
            batch_root: Some([0xAB; 32]),
            lock_expiry_slot: 1_000,
            marker_expiry_slot: Some(1_000),
            settle_sig: None,
            updated_at_ms: 0,
        }
    }

    #[test]
    fn no_state_dir_stays_in_memory_and_writes_nothing() {
        let (mut j, load) = SettleJournal::open(None);
        assert!(matches!(load, JournalLoad::Fresh));
        assert!(!j.is_persistent());
        j.record(entry(1, 0, JournalStage::Prepared)).unwrap();
        assert_eq!(j.len(), 1, "still tracked in memory");
    }

    #[test]
    fn entries_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut j, load) = SettleJournal::open(Some(dir.path()));
            assert!(matches!(load, JournalLoad::Fresh), "first boot is fresh");
            let mut e = entry(7, 2, JournalStage::Settling);
            e.settle_sig = Some("sig-abc".into());
            j.record(e).unwrap();
        } // dropped — simulates the crash/restart boundary

        let (j, load) = SettleJournal::open(Some(dir.path()));
        match load {
            JournalLoad::Recovered(v) => assert_eq!(v.len(), 1),
            other => panic!("expected Recovered, got {other:?}"),
        }
        let e = j.get(7, 2).expect("entry recovered");
        assert_eq!(e.stage, JournalStage::Settling);
        assert_eq!(e.settle_sig.as_deref(), Some("sig-abc"));
        assert_eq!(e.payload.note_a_use_tag, [0xA1; 32]);
    }

    /// THE load-bearing property: a signature written before submission is on
    /// disk even if the process dies immediately after. Without it, recovery
    /// cannot name the transaction to ask the chain about.
    #[test]
    fn a_signature_recorded_before_send_survives_an_immediate_crash() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut j, _) = SettleJournal::open(Some(dir.path()));
            let mut e = entry(3, 0, JournalStage::Settling);
            e.settle_sig = Some("would-have-been-sent".into());
            j.record(e).unwrap();
            // No clean shutdown, no further flush — this is the crash.
        }
        let (j, _) = SettleJournal::open(Some(dir.path()));
        assert_eq!(
            j.get(3, 0).unwrap().settle_sig.as_deref(),
            Some("would-have-been-sent"),
        );
    }

    /// The settle path cannot be rebuilt without the relayed VALID_INPUT proof,
    /// so losing it across a restart is the difference between reissuing Tx A
    /// and stranding the user's collateral behind a lock.
    #[test]
    fn lock_inputs_including_the_relayed_proof_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut j, _) = SettleJournal::open(Some(dir.path()));
            j.record(entry(4, 0, JournalStage::Locking)).unwrap();
        }
        let (j, _) = SettleJournal::open(Some(dir.path()));
        let e = j.get(4, 0).unwrap();
        assert_eq!(e.buyer_lock.note_use_tag, [0xA1; 32]);
        assert_eq!(e.buyer_lock.order_id, [0x01; 16]);
        assert_eq!(e.buyer_lock.tree_id, 2);
        assert_eq!(e.seller_lock.note_use_tag, [0xB1; 32]);
        assert_eq!(
            e.buyer_lock.proof.pi_b,
            proof().pi_b,
            "the relayed VALID_INPUT proof must survive — without it the lock \
             cannot be reissued after a restart"
        );
    }

    #[test]
    fn forget_removes_durably() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut j, _) = SettleJournal::open(Some(dir.path()));
            j.record(entry(1, 0, JournalStage::Prepared)).unwrap();
            j.record(entry(1, 1, JournalStage::Prepared)).unwrap();
            j.forget(1, 0);
        }
        let (j, _) = SettleJournal::open(Some(dir.path()));
        assert_eq!(j.len(), 1);
        assert!(j.get(1, 0).is_none());
        assert!(j.get(1, 1).is_some());
    }

    #[test]
    fn batch_transition_is_one_durable_write() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut j, _) = SettleJournal::open(Some(dir.path()));
            j.record_many((0..16).map(|idx| entry(8, idx, JournalStage::Locking)))
                .unwrap();
            assert_eq!(j.len(), 16);
            assert_eq!(
                j.write_stats().unwrap().count,
                1,
                "an N=16 transition must flush one snapshot, not one per match"
            );
        }
        let (j, load) = SettleJournal::open(Some(dir.path()));
        assert!(matches!(load, JournalLoad::Recovered(entries) if entries.len() == 16));
        assert_eq!(j.len(), 16);
    }

    #[test]
    fn forget_many_removes_one_batch_transition_durably() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut j, _) = SettleJournal::open(Some(dir.path()));
            j.record_many((0..4).map(|idx| entry(9, idx, JournalStage::Settling)))
                .unwrap();
            j.forget_many((0..4).map(|idx| (9, idx)));
        }
        let (j, load) = SettleJournal::open(Some(dir.path()));
        assert!(matches!(load, JournalLoad::Recovered(entries) if entries.is_empty()));
        assert!(j.is_empty());
    }

    #[test]
    fn forget_batch_clears_every_match() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut j, _) = SettleJournal::open(Some(dir.path()));
            for idx in 0..4 {
                j.record(entry(5, idx, JournalStage::Verifying)).unwrap();
            }
            j.record(entry(6, 0, JournalStage::Verifying)).unwrap();
            j.forget_batch(5);
        }
        let (j, _) = SettleJournal::open(Some(dir.path()));
        assert_eq!(j.len(), 1);
        assert!(j.get(6, 0).is_some(), "other batches untouched");
    }

    /// A corrupt journal must NOT read as "nothing was in flight". Those two
    /// states have opposite consequences, and conflating them is how a boot
    /// concludes there is nothing to recover exactly when there is.
    #[test]
    fn a_corrupt_journal_is_damaged_not_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(JOURNAL_DB_FILE), b"not borsh at all").unwrap();
        let (_, load) = SettleJournal::open(Some(dir.path()));
        match load {
            JournalLoad::Damaged { reason } => assert!(
                reason.contains("decode failed"),
                "reason should name the cause, got: {reason}"
            ),
            other => panic!("expected Damaged, got {other:?}"),
        }
    }

    /// Truncation is the realistic corruption: a write interrupted by power
    /// loss. It must also be Damaged, not silently short.
    #[test]
    fn a_truncated_journal_is_damaged_not_silently_short() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(JOURNAL_DB_FILE);
        {
            let (mut j, _) = SettleJournal::open(Some(dir.path()));
            for idx in 0..3 {
                j.record(entry(9, idx, JournalStage::Settling)).unwrap();
            }
        }
        let full = std::fs::read(&path).unwrap();
        std::fs::write(&path, &full[..full.len() / 2]).unwrap();

        let (_, load) = SettleJournal::open(Some(dir.path()));
        assert!(
            matches!(load, JournalLoad::Damaged { .. }),
            "a half-written journal must be reported damaged"
        );
    }

    #[test]
    fn a_version_mismatch_is_damaged_not_empty() {
        let dir = tempfile::tempdir().unwrap();
        let bad = JournalSnapshot {
            version: JOURNAL_VERSION + 42,
            entries: vec![entry(1, 0, JournalStage::Prepared)],
        };
        std::fs::write(
            dir.path().join(JOURNAL_DB_FILE),
            borsh::to_vec(&bad).unwrap(),
        )
        .unwrap();
        let (_, load) = SettleJournal::open(Some(dir.path()));
        match load {
            JournalLoad::Damaged { reason } => {
                assert!(reason.contains("version"), "got: {reason}")
            }
            other => panic!("expected Damaged, got {other:?}"),
        }
    }

    /// A damaged journal is the only artefact an operator has to investigate
    /// with, and the very next batch would rename a fresh snapshot over it.
    #[test]
    fn a_damaged_journal_is_preserved_instead_of_being_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(JOURNAL_DB_FILE);
        std::fs::write(&path, b"corrupt bytes worth keeping").unwrap();

        let (mut j, load) = SettleJournal::open(Some(dir.path()));
        assert!(matches!(load, JournalLoad::Damaged { .. }));

        // The next write must not destroy the evidence.
        j.record(entry(1, 0, JournalStage::Prepared)).unwrap();

        let preserved: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".damaged-"))
            .collect();
        assert_eq!(
            preserved.len(),
            1,
            "the corrupt file must be moved aside, found: {preserved:?}"
        );
        let kept = std::fs::read(dir.path().join(&preserved[0])).unwrap();
        assert_eq!(
            kept, b"corrupt bytes worth keeping",
            "the preserved copy must be the original bytes, not a rewrite"
        );
        // And the live journal is usable again.
        let (reopened, _) = SettleJournal::open(Some(dir.path()));
        assert_eq!(reopened.len(), 1);
    }

    #[test]
    fn no_temp_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let (mut j, _) = SettleJournal::open(Some(dir.path()));
        j.record(entry(1, 0, JournalStage::Prepared)).unwrap();
        let tmp = dir.path().join(JOURNAL_DB_FILE).with_extension("db.tmp");
        assert!(!tmp.exists(), "atomic rename must consume the temp file");
    }

    /// Recovered order must depend only on contents, not on insertion order, so
    /// a recovered journal is directly comparable across runs.
    #[test]
    fn recovered_order_is_insertion_order_independent() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        {
            let (mut j, _) = SettleJournal::open(Some(a.path()));
            j.record(entry(1, 0, JournalStage::Prepared)).unwrap();
            j.record(entry(2, 1, JournalStage::Prepared)).unwrap();
        }
        {
            let (mut j, _) = SettleJournal::open(Some(b.path()));
            j.record(entry(2, 1, JournalStage::Prepared)).unwrap();
            j.record(entry(1, 0, JournalStage::Prepared)).unwrap();
        }
        let keys = |d: &std::path::Path| {
            let (j, _) = SettleJournal::open(Some(d));
            j.all().iter().map(|e| e.key()).collect::<Vec<_>>()
        };
        assert_eq!(
            keys(a.path()),
            keys(b.path()),
            "entry order must be canonical"
        );
    }
}

/// T-06's missing measurement: per-transition durable-write cost.
///
/// The recovery drill's cost table lists write p50/p95 as a *mandatory* closing
/// measurement and it was never captured, so T-06 closed on an explicitly
/// recorded waiver. These pin the instrumentation that replaces it — including
/// the properties that make the number trustworthy rather than merely present,
/// because a percentile that quietly measures the wrong thing is worse than a
/// missing one: it closes the waiver without closing the gap.
#[cfg(test)]
mod write_stats_tests {
    use super::*;

    fn journal_in(dir: &std::path::Path) -> SettleJournal {
        SettleJournal::open(Some(dir)).0
    }

    #[test]
    fn no_stats_before_the_first_write() {
        // `None`, not a zeroed struct: "we have not measured" and "the write
        // cost zero" must not render identically on an admin surface.
        let dir = tempfile::tempdir().unwrap();
        assert!(journal_in(dir.path()).write_stats().is_none());
    }

    #[test]
    fn a_write_is_counted_and_summarised() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = journal_in(dir.path());
        j.record(tests::entry(1, 0, JournalStage::Prepared))
            .unwrap();

        let s = j.write_stats().expect("one write recorded");
        assert_eq!(s.count, 1);
        // A real fsync'd rename cannot take zero microseconds; a zero here means
        // the timer is not wrapping the flush.
        assert!(s.p50_us > 0, "p50 must reflect a real write, got {s:?}");
        assert!(s.max_us >= s.p95_us && s.p95_us >= s.p50_us, "{s:?}");
    }

    /// The PUBLIC getter must report the lifetime count too.
    ///
    /// The internal-field test below does not cover this: `write_stats()` maps
    /// `WriteStats` onto `JournalWriteStats`, and that mapping can regress on
    /// its own. Mutating the getter to `samples.len()` left the internal test
    /// green, which is how this gap was found — so the assertion goes through
    /// the surface an operator actually reads.
    ///
    /// In-memory so the flush is a no-op: this measures the counter, not the
    /// disk, and 500+ real fsyncs would make it a slow test for no extra signal.
    #[test]
    fn the_public_getter_reports_lifetime_count_not_window_size() {
        let mut j = SettleJournal::in_memory();
        let writes = WRITE_SAMPLES + 37;
        for i in 0..writes {
            j.record(tests::entry(1, (i % 250) as u8, JournalStage::Prepared))
                .unwrap();
        }
        let s = j.write_stats().expect("counted");
        assert_eq!(
            s.count, writes as u64,
            "the getter must report every write, not just the retained window"
        );
    }

    #[test]
    fn the_lifetime_count_survives_ring_eviction() {
        // `count` must NOT be `samples.len()`. Past the ring size the two
        // diverge, and reporting the ring length would silently under-report
        // total writes for the whole rest of the process.
        let mut stats = WriteStats::default();
        for i in 0..(WRITE_SAMPLES as u64 + 25) {
            stats.record(i + 1);
        }
        assert_eq!(stats.count, WRITE_SAMPLES as u64 + 25);
        assert_eq!(stats.samples.len(), WRITE_SAMPLES, "ring stays bounded");
    }

    #[test]
    fn the_ring_evicts_the_oldest_sample() {
        // Order matters for percentiles over a moving window: evicting the
        // newest would freeze the distribution at start-up behaviour.
        let mut stats = WriteStats::default();
        for i in 0..WRITE_SAMPLES {
            stats.record(1_000 + i as u64);
        }
        stats.record(7);
        assert_eq!(*stats.samples.back().unwrap(), 7, "newest is retained");
        assert_eq!(
            *stats.samples.front().unwrap(),
            1_001,
            "the OLDEST sample is the one dropped"
        );
    }

    #[test]
    fn percentiles_are_nearest_rank_over_the_retained_samples() {
        // 1..=100 inserted out of order, so a bug that assumes arrival order is
        // sorted order shows up here rather than on a real machine.
        let mut stats = WriteStats::default();
        for i in (1..=100u64).rev() {
            stats.record(i);
        }
        let (p50, p95) = stats.percentiles().unwrap();
        assert_eq!(p50, 50);
        assert_eq!(p95, 95);
    }

    #[test]
    fn max_is_lifetime_and_not_capped_by_the_ring() {
        // The slowest write is the one an operator most wants to see, and it is
        // exactly the one a bounded window forgets. Kept separately.
        let mut stats = WriteStats::default();
        stats.record(999_999);
        for _ in 0..(WRITE_SAMPLES + 10) {
            stats.record(1);
        }
        assert_eq!(stats.max_us, 999_999, "the outlier must survive eviction");
        assert!(!stats.samples.contains(&999_999), "…even once evicted");
    }

    #[test]
    fn a_failed_write_is_not_sampled() {
        // A failed flush may have aborted early, so its duration is not a sample
        // of what a write costs. Counting it would pull the distribution toward
        // the failure mode — reporting a FASTER journal precisely when the disk
        // is broken. Induced by pointing the journal at a path whose parent
        // cannot be created.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let mut j = journal_in(&file.join("nested"));

        assert!(
            j.record(tests::entry(1, 0, JournalStage::Prepared))
                .is_err(),
            "the fixture must actually fail, or this proves nothing"
        );
        assert!(
            j.write_stats().is_none(),
            "a failed write must not be counted as a sample"
        );
    }

    #[test]
    fn an_in_memory_journal_still_reports_its_writes() {
        // `path: None` skips the flush entirely, so these samples measure ~0.
        // That is honest for a deployment with no volume; what must not happen
        // is a panic or a missing count.
        let mut j = SettleJournal::in_memory();
        j.record(tests::entry(1, 0, JournalStage::Prepared))
            .unwrap();
        assert_eq!(j.write_stats().expect("counted").count, 1);
    }

    #[test]
    fn the_summary_is_throttled_but_always_fires_first() {
        // The drill reads these from `phala logs` after a run that may only
        // write a handful of times, so the FIRST write must emit rather than
        // waiting out an interval. Subsequent writes inside the window must not.
        let mut stats = WriteStats::default();
        let t0 = Instant::now();
        assert!(stats.should_emit(t0), "first write must emit immediately");
        assert!(!stats.should_emit(t0), "a second write in-window must not");
        assert!(
            stats.should_emit(t0 + WRITE_SUMMARY_EVERY),
            "the next interval must emit again"
        );
    }
}
