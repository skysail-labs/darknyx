//! Asynchronous close of `BatchValidityMarker` PDAs (Tx E) — OFF the settle
//! critical path.
//!
//! The marker is 1:N rent-reclaim bookkeeping (one per batch, seeded by the
//! batch root). The settle worker used to send + confirm the close INLINE at the
//! batch tail (`worker.rs`), which — under the serial pipeline
//! (`SETTLE_CONCURRENCY=1`) — blocked the next batch on a full confirmation
//! (~1 slot on mainnet, ~10 s on devnet via drop+rebroadcast) for a tx that
//! touches no user funds and that nothing downstream depends on: the next batch
//! always has a different Merkle root → a different marker PDA (the tree is
//! monotonic), and `verify_match_batch` inits a fresh marker per root.
//!
//! Now the worker enqueues the root (≈0 ms) and this background task batches the
//! closes: every [`MARKER_SWEEP_INTERVAL`] it packs up to
//! [`MARKER_SWEEP_MAX_PER_TX`] close ixs into one tx, confirms, and persists the
//! pending set ([`PendingMarkers`]) so a CVM restart / redeploy replays any
//! un-closed roots and reclaims their rent.
//!
//! Closing is idempotent: before packing a tx the sweeper drops any root whose
//! marker no longer exists (a confirmed retry, or closed by another path), so a
//! single stale root can never poison a packed (atomic) close tx.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use solana_keypair::Keypair;
use solana_signer::Signer;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::close_marker::build_close_marker_ix;
use super::submit::{confirm_signatures, submit_ixs};
use super::vault::batch_validity_marker_pda;
use crate::persistence::PendingMarkers;
use crate::solana_rpc::SolanaRpcClient;

/// How often the sweeper drains the pending set and fires closes.
pub const MARKER_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Max close ixs packed into one Tx E. Each is ~120 B (3 accounts + 8-byte
/// discriminator + 32-byte root), so 8 stays well under the 1232-byte cap while
/// cutting the close-tx count ~8× vs the old one-per-batch path.
pub const MARKER_SWEEP_MAX_PER_TX: usize = 8;

/// Spawn the background marker sweeper.
///
/// `state_dir` is the dstack LUKS mount (`None` → in-memory only, no
/// crash-recovery — fine for dev/tests). `keypair` MUST be the PRIMARY (shard-0)
/// TEE key: it pays for `verify_match_batch`, so it is every marker's `payer`
/// (the on-chain close enforces `has_one = payer`). The task runs until every
/// sender (`marker_sweep_tx`) is dropped, then does a final best-effort sweep.
pub fn spawn_marker_sweeper(
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
    let mut pending = PendingMarkers::load(state_dir.as_deref());
    if !pending.is_empty() {
        tracing::info!(
            n = pending.len(),
            "marker sweeper: replaying un-closed markers from disk"
        );
    }
    let mut ticker = tokio::time::interval(MARKER_SWEEP_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            recv = rx.recv() => match recv {
                Some(root) => pending.add(root),
                None => {
                    // All senders dropped (shutdown) — best-effort final sweep, then exit.
                    sweep(&rpc, &keypair, &mut pending, confirm_timeout).await;
                    return;
                }
            },
            _ = ticker.tick() => {
                sweep(&rpc, &keypair, &mut pending, confirm_timeout).await;
            }
        }
    }
}

/// One sweep pass: drop already-closed roots, then close the rest in packed
/// chunks. Failures stay pending and retry on the next tick.
async fn sweep(
    rpc: &SolanaRpcClient,
    keypair: &Arc<Keypair>,
    pending: &mut PendingMarkers,
    confirm_timeout: Duration,
) {
    let roots = pending.all();
    if roots.is_empty() {
        return;
    }

    // Skip markers that no longer exist (already closed) — reclaims them from
    // the set for free AND prevents a stale root from failing a packed tx.
    let mut live: Vec<[u8; 32]> = Vec::with_capacity(roots.len());
    for root in roots {
        let (marker, _) = batch_validity_marker_pda(&root);
        match rpc.get_account_info(&marker).await {
            Ok(None) => pending.remove(&root),
            Ok(Some(_)) => live.push(root),
            Err(e) => {
                // Treat an existence-check error as "still live" — retry later.
                tracing::warn!(error = %e, "marker existence check failed; will retry");
                live.push(root);
            }
        }
    }
    if live.is_empty() {
        return;
    }

    let primary = keypair.pubkey();
    for chunk in live.chunks(MARKER_SWEEP_MAX_PER_TX) {
        let ixs: Vec<_> = chunk
            .iter()
            .map(|r| build_close_marker_ix(&primary, &primary, r))
            .collect();
        match submit_ixs(rpc, keypair, &ixs).await {
            Ok(sig) => {
                match confirm_signatures(rpc, std::slice::from_ref(&sig), confirm_timeout).await {
                    Ok(()) => {
                        for r in chunk {
                            pending.remove(r);
                        }
                        tracing::debug!(n = chunk.len(), %sig, "closed batch markers (async sweep)");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "marker close confirm failed; retrying next tick")
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "marker close submit failed; retrying next tick"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Distinct roots → distinct marker PDAs (sanity for the pack-by-root logic).
    #[test]
    fn distinct_roots_map_to_distinct_markers() {
        let (m1, _) = batch_validity_marker_pda(&[1u8; 32]);
        let (m2, _) = batch_validity_marker_pda(&[2u8; 32]);
        assert_ne!(m1, m2);
    }

    // The packing math the sweep loop relies on: N roots → ceil(N / MAX) txs.
    #[test]
    fn chunking_packs_under_the_per_tx_cap() {
        for n in [1usize, 8, 9, 16, 17, 100] {
            let roots: Vec<[u8; 32]> = (0..n).map(|i| [i as u8; 32]).collect();
            let chunks: Vec<&[[u8; 32]]> = roots.chunks(MARKER_SWEEP_MAX_PER_TX).collect();
            let expected = n.div_ceil(MARKER_SWEEP_MAX_PER_TX);
            assert_eq!(chunks.len(), expected, "n={n}");
            assert!(chunks.iter().all(|c| c.len() <= MARKER_SWEEP_MAX_PER_TX));
            assert_eq!(chunks.iter().map(|c| c.len()).sum::<usize>(), n);
        }
    }

    // Each close ix is small enough that MAX_PER_TX fit a 1232-byte tx with room.
    #[test]
    fn packed_close_ixs_fit_the_tx_budget() {
        let primary = batch_validity_marker_pda(&[0u8; 32]).0; // any address
        let total: usize = (0..MARKER_SWEEP_MAX_PER_TX)
            .map(|i| {
                let ix = build_close_marker_ix(&primary, &primary, &[i as u8; 32]);
                // accounts (32 B each) + ix data (8 disc + 32 root) — a generous
                // per-ix upper bound ignoring shared-account dedup.
                ix.accounts.len() * 32 + ix.data.len()
            })
            .sum();
        assert!(
            total < 1232,
            "packed close ixs ({total} B) must fit the tx cap"
        );
    }
}
