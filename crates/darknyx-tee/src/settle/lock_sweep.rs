//! Background sweeper that releases EXPIRED `NoteLock` PDAs (audit
//! 2026-07-25, S-03(B)).
//!
//! # Why this exists, and why it is not urgent
//!
//! `release_lock` has been correct and permissionless on-chain since the lock
//! lifecycle landed, but had NO caller in any shipped component — no SDK
//! builder, no TEE task, no script, no test. The 2026-07-20 D-01 analysis of
//! the settle-failure freeze concluded the recovery path was "`release_lock` +
//! re-place", which was not implemented anywhere.
//!
//! S-03(C) changed the shape of the problem: `withdraw` and `merge` now reject
//! only a LIVE lock, so a stranded lock no longer blocks anything once its
//! expiry passes. That demotes this sweeper from a **liveness recovery
//! mechanism** to **rent reclamation** — which is why it is built after that
//! relaxation rather than before it, and why a failure here is a cost issue,
//! not a user-facing one.
//!
//! # Differences from the marker sweeper it mirrors
//!
//! `settle::marker_sweep` must use the PRIMARY shard key, because
//! `close_batch_validity_marker` enforces `has_one = payer`. `release_lock` has
//! no such constraint (`close = rent_receiver`, with no binding to whoever
//! created the lock), so ANY shard key can pay — and whoever submits receives
//! the reclaimed rent.
//!
//! Both sweepers keep their own snapshot file so a corrupt or version-skewed
//! snapshot of one cannot take the other down.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use solana_keypair::Keypair;
use solana_signer::Signer;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::submit::{confirm_signatures, submit_ixs};
use super::vault::{note_lock_pda, vault_program_id};
use crate::persistence::{PendingSet, LOCKS_DB_FILE};
use crate::solana_rpc::SolanaRpcClient;

use solana_instruction::{AccountMeta, Instruction};

/// How often the sweeper drains the pending set and fires releases.
pub const LOCK_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Max release ixs packed into one transaction.
///
/// Solana dedups account keys across a transaction's instructions, so the
/// signer is counted ONCE and each extra release adds only its own lock PDA:
/// 32 B key + 40 B data (8 disc + 32 commitment) + ~5 B framing = ~77 B.
/// Ten of those plus ~128 B of fixed overhead (signature, header, blockhash,
/// fee payer) is ~900 B — comfortably under the 1232-byte cap, pinned by
/// `max_per_tx_fits_the_transaction_budget`.
pub const LOCK_SWEEP_MAX_PER_TX: usize = 10;

/// How long a freshly registered commitment is immune to the "lock account is
/// absent, so it must already be released" rule.
///
/// The worker registers commitments OPTIMISTICALLY, before the `lock_note`
/// transaction is even sent (see `worker.rs`'s `lock_branch`). So for the first
/// second or two of a commitment's life the lock PDA genuinely does not exist
/// yet, and an unguarded sweep would read `Ok(None)`, conclude the lock was
/// already released, and drop the entry permanently. The lock then lands with
/// nothing tracking it — and if that batch's settle later fails, its rent is
/// never reclaimed, which is the one thing this sweeper exists to prevent.
///
/// The window is real: locks confirm in ~1.3 s against a 30 s sweep interval,
/// so absent a grace period roughly one batch in twenty is exposed.
///
/// Sized well above the observed confirmation time (and above Tx D's ~10 s
/// worst case with rebroadcasts) because the cost of being generous is one
/// extra `getAccountInfo` per young entry per tick, while the cost of being
/// stingy is silently leaked rent. Entries restored from disk are NOT given
/// the grace — a lock recorded in a previous boot resolved long ago.
const LOCK_REGISTRATION_GRACE: Duration = Duration::from_secs(90);

/// Anchor account layout:
/// discriminator(8) || note_commitment(32) || token_mint(32) || order_id(16)
/// || expiry_slot(8 LE) || locked_by(32) || bump(1) || _padding(7).
/// Mirrors `programs/vault/src/state.rs::NoteLock`.
const LOCK_EXPIRY_OFFSET: usize = 8 + 32 + 32 + 16;
const LOCK_EXPIRY_END: usize = LOCK_EXPIRY_OFFSET + 8;

static NOTE_LOCK_DISCRIMINATOR: LazyLock<[u8; 8]> = LazyLock::new(|| {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(b"account:NoteLock");
    let mut discriminator = [0u8; 8];
    discriminator.copy_from_slice(&hash[..8]);
    discriminator
});

static RELEASE_LOCK_DISCRIMINATOR: LazyLock<[u8; 8]> = LazyLock::new(|| {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(b"global:release_lock");
    let mut discriminator = [0u8; 8];
    discriminator.copy_from_slice(&hash[..8]);
    discriminator
});

/// `release_lock(note_commitment)`.
///
/// Accounts, mirroring `ReleaseLock<'info>`:
///   `[0]` `rent_receiver` — signer + writable; receives the reclaimed rent.
///   `[1]` `note_lock`     — writable (closed).
pub fn build_release_lock_ix(
    rent_receiver: &solana_pubkey::Pubkey,
    note_commitment: &[u8; 32],
) -> Instruction {
    let (lock_pda, _) = note_lock_pda(note_commitment);
    let mut data = Vec::with_capacity(8 + 32);
    data.extend_from_slice(&*RELEASE_LOCK_DISCRIMINATOR);
    data.extend_from_slice(note_commitment);
    Instruction {
        program_id: vault_program_id(),
        accounts: vec![
            AccountMeta::new(*rent_receiver, true),
            AccountMeta::new(lock_pda, false),
        ],
        data,
    }
}

/// Read `expiry_slot` out of a `NoteLock` account, validating owner,
/// discriminator and length first. `None` ⇒ not a lock we should act on.
fn lock_expiry_slot(account: &crate::solana_rpc::RpcAccountInfo) -> Option<u64> {
    if account.owner != vault_program_id()
        || account.data.len() < LOCK_EXPIRY_END
        || account.data[..8] != *NOTE_LOCK_DISCRIMINATOR
    {
        return None;
    }
    Some(u64::from_le_bytes(
        account.data[LOCK_EXPIRY_OFFSET..LOCK_EXPIRY_END]
            .try_into()
            .ok()?,
    ))
}

/// The on-chain check is `clock.slot >= expiry_slot` — a lock is releasable AT
/// its expiry (the CS-09 boundary settlement must land strictly before).
fn lock_has_expired(current_slot: u64, expiry_slot: u64) -> bool {
    current_slot >= expiry_slot
}

/// Spawn the background lock sweeper. Runs until every sender is dropped, then
/// performs a final best-effort sweep.
pub fn spawn_lock_sweeper(
    rpc: SolanaRpcClient,
    keypair: Arc<Keypair>,
    rx: mpsc::UnboundedReceiver<[u8; 32]>,
    state_dir: Option<PathBuf>,
    confirm_timeout: Duration,
) -> JoinHandle<()> {
    tokio::spawn(run(rpc, keypair, rx, state_dir, confirm_timeout))
}

async fn run(
    rpc: SolanaRpcClient,
    keypair: Arc<Keypair>,
    mut rx: mpsc::UnboundedReceiver<[u8; 32]>,
    state_dir: Option<PathBuf>,
    confirm_timeout: Duration,
) {
    let mut pending = PendingSet::load_named(state_dir.as_deref(), LOCKS_DB_FILE);
    if !pending.is_empty() {
        tracing::info!(
            n = pending.len(),
            "lock sweeper: replaying un-released note locks from disk"
        );
    }
    let mut ticker = tokio::time::interval(LOCK_SWEEP_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // In-memory only, and deliberately so: it exists to distinguish "this lock
    // has not been created YET" from "this lock is already gone", which is a
    // question that only has meaning within the boot that registered it. On
    // restart the map is empty and every disk-restored entry is treated as
    // mature, which is the correct reading.
    let mut registered_at: HashMap<[u8; 32], Instant> = HashMap::new();

    loop {
        tokio::select! {
            recv = rx.recv() => match recv {
                Some(commitment) => {
                    pending.add(commitment);
                    registered_at.entry(commitment).or_insert_with(Instant::now);
                }
                None => {
                    sweep(&rpc, &keypair, &mut pending, &mut registered_at, confirm_timeout).await;
                    return;
                }
            },
            _ = ticker.tick() => {
                sweep(&rpc, &keypair, &mut pending, &mut registered_at, confirm_timeout).await;
            }
        }
    }
}

/// One pass: drop already-released locks, retain live ones, release expired
/// ones in packed chunks. Anything that fails stays pending for the next tick.
async fn sweep(
    rpc: &SolanaRpcClient,
    keypair: &Arc<Keypair>,
    pending: &mut PendingSet,
    registered_at: &mut HashMap<[u8; 32], Instant>,
    confirm_timeout: Duration,
) {
    let commitments = pending.all();
    if commitments.is_empty() {
        return;
    }

    // Read the confirmed slot ONCE. Submitting a pre-expiry release would just
    // fail `LockNotExpired` every tick for the whole lock TTL.
    let current_slot = match rpc.get_latest_blockhash().await {
        Ok(blockhash) => blockhash.context_slot,
        Err(e) => {
            tracing::warn!(error = %e, "lock sweep slot read failed; will retry");
            return;
        }
    };

    let mut expired: Vec<[u8; 32]> = Vec::with_capacity(commitments.len());
    for commitment in commitments {
        let (lock_pda, _) = note_lock_pda(&commitment);
        match rpc.get_account_info(&lock_pda).await {
            // Absent. Usually that means gone-for-good: settled (the settle
            // closes it), withdrawn, or released by someone else.
            //
            // But it ALSO means "not created yet" for a commitment registered
            // moments ago, because registration is optimistic and precedes the
            // lock transaction. Dropping one of those is unrecoverable — the
            // lock lands untracked and its rent is never reclaimed. So young
            // entries are retained and re-checked next tick.
            Ok(None) => {
                let young = registered_at
                    .get(&commitment)
                    .is_some_and(|t| t.elapsed() < LOCK_REGISTRATION_GRACE);
                if young {
                    tracing::debug!(
                        lock = %lock_pda,
                        "note-lock absent but registration is recent; \
                         assuming the lock tx is still in flight"
                    );
                } else {
                    pending.remove(&commitment);
                    registered_at.remove(&commitment);
                }
            }
            Ok(Some(account)) => match lock_expiry_slot(&account) {
                Some(expiry_slot) if lock_has_expired(current_slot, expiry_slot) => {
                    expired.push(commitment)
                }
                Some(_) => {}
                None => tracing::warn!(
                    lock = %lock_pda,
                    "note-lock account layout/owner invalid; retaining for retry"
                ),
            },
            Err(e) => {
                tracing::warn!(error = %e, "note-lock existence check failed; will retry");
            }
        }
    }
    if expired.is_empty() {
        return;
    }

    // Any shard key may pay — `release_lock` has no `has_one = payer` — and the
    // reclaimed rent goes to whoever submits.
    let receiver = keypair.pubkey();
    for chunk in expired.chunks(LOCK_SWEEP_MAX_PER_TX) {
        let ixs: Vec<_> = chunk
            .iter()
            .map(|c| build_release_lock_ix(&receiver, c))
            .collect();
        match submit_ixs(rpc, keypair, &ixs).await {
            Ok(sig) => {
                match confirm_signatures(rpc, std::slice::from_ref(&sig), confirm_timeout).await {
                    Ok(()) => {
                        for c in chunk {
                            pending.remove(c);
                            registered_at.remove(c);
                        }
                        tracing::debug!(n = chunk.len(), %sig, "released expired note locks");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "lock release confirm failed; retrying next tick")
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "lock release submit failed; retrying next tick"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_account(
        expiry: u64,
        owner_ok: bool,
        disc_ok: bool,
        len: usize,
    ) -> crate::solana_rpc::RpcAccountInfo {
        let mut data = vec![0u8; len];
        if disc_ok && len >= 8 {
            data[..8].copy_from_slice(&*NOTE_LOCK_DISCRIMINATOR);
        }
        if len >= LOCK_EXPIRY_END {
            data[LOCK_EXPIRY_OFFSET..LOCK_EXPIRY_END].copy_from_slice(&expiry.to_le_bytes());
        }
        crate::solana_rpc::RpcAccountInfo {
            owner: if owner_ok {
                vault_program_id()
            } else {
                solana_pubkey::Pubkey::new_from_array([0x99; 32])
            },
            lamports: 1,
            data,
            executable: false,
            rent_epoch: 0,
        }
    }

    /// Pins the offset against `state.rs::NoteLock`. A field inserted before
    /// `expiry_slot` would make the sweeper read garbage and either release
    /// live locks or never release dead ones.
    #[test]
    fn expiry_offset_matches_the_on_chain_layout() {
        assert_eq!(LOCK_EXPIRY_OFFSET, 8 + 32 + 32 + 16);
        let acct = lock_account(123_456, true, true, LOCK_EXPIRY_END + 40);
        assert_eq!(lock_expiry_slot(&acct), Some(123_456));
    }

    #[test]
    fn rejects_foreign_owner_bad_discriminator_and_short_data() {
        assert_eq!(
            lock_expiry_slot(&lock_account(1, false, true, LOCK_EXPIRY_END + 40)),
            None,
            "an account owned by another program must be ignored"
        );
        assert_eq!(
            lock_expiry_slot(&lock_account(1, true, false, LOCK_EXPIRY_END + 40)),
            None,
            "a non-NoteLock discriminator must be ignored"
        );
        assert_eq!(
            lock_expiry_slot(&lock_account(1, true, true, LOCK_EXPIRY_END - 1)),
            None,
            "a truncated account must be ignored, not read past its end"
        );
    }

    /// The boundary `release_lock` itself uses: releasable AT expiry.
    #[test]
    fn expiry_boundary_is_inclusive() {
        assert!(!lock_has_expired(99, 100));
        assert!(lock_has_expired(100, 100));
        assert!(lock_has_expired(101, 100));
    }

    #[test]
    fn release_ix_shape_and_pda_binding() {
        let payer = solana_pubkey::Pubkey::new_from_array([0x11; 32]);
        let commitment = [0x22u8; 32];
        let ix = build_release_lock_ix(&payer, &commitment);

        assert_eq!(ix.program_id, vault_program_id());
        assert_eq!(ix.data.len(), 8 + 32);
        assert_eq!(&ix.data[..8], &*RELEASE_LOCK_DISCRIMINATOR);
        assert_eq!(&ix.data[8..], &commitment[..]);

        assert_eq!(ix.accounts.len(), 2);
        // Rent receiver signs and is credited; the lock is closed so it must be
        // writable.
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert_eq!(ix.accounts[0].pubkey, payer);
        assert!(!ix.accounts[1].is_signer && ix.accounts[1].is_writable);
        assert_eq!(ix.accounts[1].pubkey, note_lock_pda(&commitment).0);
    }

    /// A full chunk must stay inside the 1232-byte transaction cap.
    #[test]
    fn max_per_tx_fits_the_transaction_budget() {
        // Account keys dedup ACROSS instructions, so the signer is counted once
        // and each release contributes only its own lock PDA.
        const FIXED_OVERHEAD: usize = 128; // signature + header + blockhash + fee payer
        const PER_RELEASE: usize = 32 + 40 + 5; // lock PDA + (disc + commitment) + framing
        let worst_case = FIXED_OVERHEAD + LOCK_SWEEP_MAX_PER_TX * PER_RELEASE;
        assert!(
            worst_case < 1232,
            "packing {LOCK_SWEEP_MAX_PER_TX} releases is {worst_case} B, over the 1232-byte cap"
        );
        // Keep real headroom rather than sitting on the boundary.
        assert!(
            worst_case < 1_000,
            "packing {LOCK_SWEEP_MAX_PER_TX} releases ({worst_case} B) leaves too little headroom"
        );
    }
}
