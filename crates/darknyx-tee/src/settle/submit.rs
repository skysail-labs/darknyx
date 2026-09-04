//! Shared transaction build / sign / send / confirm helpers.
//!
//! Every settle-pipeline transaction follows the same lifecycle: compose the
//! instructions, sign with the TEE keypair, bincode and base64 the result, send it,
//! then poll `getSignatureStatuses`. This module is the single home for that
//! machinery so each builder owns only its instruction construction.
//!
//! The TEE keypair fills two roles at once on every transaction — Solana fee-payer
//! and the `tee_authority` signer the vault checks against
//! `vault_config.tee_pubkeys`. They are deliberately the same key; see
//! [`crate::keys::ed25519::DerivedSigner::solana_keypair`].
//!
//! The helpers here build legacy transactions, which remain sufficient for Tx
//! A/B/E. Tx D uses v1 so it can carry the settlement payload and every account
//! inline; it is assembled in [`super::pipeline`] instead.

use base64::Engine as _;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_transaction::Transaction;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::solana_rpc::{RpcError, SolanaRpcClient};

/// Build a legacy transaction from `ixs`, sign with `payer` (also
/// the fee-payer), bincode+base64 encode, and submit via
/// `sendTransaction`. Returns the base58 signature as soon as the
/// RPC accepts it (NOT after confirmation — use
/// [`confirm_signatures`] for that).
///
/// One blockhash fetch happens here; callers submitting multiple
/// independent txs that should share a blockhash fetch it once and
/// use [`submit_ixs_with_blockhash`] instead.
pub async fn submit_ixs(
    rpc: &SolanaRpcClient,
    payer: &Keypair,
    ixs: &[Instruction],
) -> Result<String, RpcError> {
    let bh = rpc.get_latest_blockhash().await?;
    let blockhash = Hash::new_from_array(bh.blockhash);
    submit_ixs_with_blockhash(rpc, payer, ixs, blockhash).await
}

/// Same as [`submit_ixs`] but with a caller-provided blockhash —
/// lets a caller batch the `getLatestBlockhash` fetch across
/// several txs.
pub async fn submit_ixs_with_blockhash(
    rpc: &SolanaRpcClient,
    payer: &Keypair,
    ixs: &[Instruction],
    blockhash: Hash,
) -> Result<String, RpcError> {
    let tx_b64 = build_tx_b64(payer, ixs, blockhash)?;
    rpc.send_transaction(&tx_b64).await
}

/// Build + sign a legacy tx → base64 wire (does NOT send). Lets a caller fire
/// many txs CONCURRENTLY (sharing one blockhash) and confirm them together —
/// the lock pass uses this to avoid paying one confirmation window per note.
pub fn build_tx_b64(
    payer: &Keypair,
    ixs: &[Instruction],
    blockhash: Hash,
) -> Result<String, RpcError> {
    use solana_signer::Signer;
    let payer_pubkey = payer.pubkey();
    let tx = Transaction::new_signed_with_payer(ixs, Some(&payer_pubkey), &[payer], blockhash);
    let wire = bincode::serialize(&tx)
        .map_err(|e| RpcError::Schema(format!("tx bincode serialise failed: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(&wire))
}

/// Send a pre-built base64 tx, then poll until it confirms at the client's
/// commitment, REBROADCASTING the identical signed tx every `resend_every`
/// until it lands. Returns the (stable) signature once confirmed.
///
/// Devnet RPCs and leaders can drop an accepted transaction before it lands.
/// Re-pushing the identical signed bytes on a bounded cadence avoids relying
/// on the RPC provider's lazy rebroadcast loop. Resends use `skip_preflight`
/// because the first send already ran preflight; the network deduplicates by
/// signature, so retries are idempotent.
///
/// Errors if the tx reverts (carries the on-chain err) or `timeout` elapses.
/// Returns `(signature, confirmed_slot)`. The slot lets the settle worker
/// measure block CO-INCLUSION (many settle txs sharing a slot = the leader
/// batched them, so they confirm together — the concurrent-send throughput
/// lever). `confirmed_slot` is `None` only if the RPC omitted it.
pub async fn send_and_confirm_with_rebroadcast(
    rpc: &SolanaRpcClient,
    tx_b64: &str,
    timeout: std::time::Duration,
    resend_every: std::time::Duration,
) -> Result<(String, Option<u64>), RpcError> {
    let start = std::time::Instant::now();
    // First send WITH preflight — validates the tx once.
    let sig = rpc.send_transaction(tx_b64).await?;
    let mut last_send = std::time::Instant::now();
    let mut resends = 0u32;
    let mut interval = std::time::Duration::from_millis(250);

    loop {
        let statuses = rpc
            .get_signature_statuses(std::slice::from_ref(&sig))
            .await?;
        match statuses.first() {
            Some(Some(s)) if s.err.is_some() => {
                return Err(RpcError::Schema(format!(
                    "settle tx ({sig}) reverted: err={:?}",
                    s.err
                )));
            }
            Some(Some(s)) if s.confirmed_at_commitment == Some(true) => {
                if resends > 0 {
                    tracing::debug!(
                        %sig,
                        resends,
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        "settle tx confirmed after rebroadcast(s)"
                    );
                }
                return Ok((sig, s.slot));
            }
            _ => {}
        }
        if start.elapsed() >= timeout {
            return Err(RpcError::Schema(format!(
                "settle tx ({sig}) did not confirm within {timeout:?} ({resends} rebroadcast(s))"
            )));
        }
        // Rebroadcast the identical tx (skip preflight) so a leader that dropped
        // the first copy gets another chance. Transient resend errors are
        // non-fatal — keep polling the canonical signature.
        if last_send.elapsed() >= resend_every {
            if rpc.send_transaction_opts(tx_b64, true).await.is_ok() {
                resends += 1;
            }
            last_send = std::time::Instant::now();
        }
        tokio::time::sleep(interval).await;
        interval = (interval * 2).min(std::time::Duration::from_secs(1));
    }
}

/// One confirmed transaction returned by
/// [`send_and_confirm_many_with_rebroadcast`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedTransaction {
    /// Stable caller-provided index, used to map the result back to its match.
    pub transaction_index: usize,
    pub signature: String,
    pub slot: Option<u64>,
    pub elapsed_ms: u64,
    pub rebroadcasts: u32,
}

/// Per-transaction result from the batched Tx D confirmation state machine.
///
/// A rejected transaction has a confirmed on-chain error and is safe to treat
/// as terminal after the worker reconciles the two consumed-note PDAs. An
/// ambiguous transaction covers transport/RPC failures, an initial send whose
/// acceptance is unknown, or a confirmation timeout. The worker must reconcile
/// those PDAs and may redrive the transaction while its batch marker and input
/// locks remain valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionConfirmationOutcome {
    Confirmed(ConfirmedTransaction),
    Rejected {
        transaction_index: usize,
        signature: String,
        reason: String,
    },
    Ambiguous {
        transaction_index: usize,
        signature: Option<String>,
        reason: String,
    },
}

impl TransactionConfirmationOutcome {
    pub fn transaction_index(&self) -> usize {
        match self {
            Self::Confirmed(tx) => tx.transaction_index,
            Self::Rejected {
                transaction_index, ..
            }
            | Self::Ambiguous {
                transaction_index, ..
            } => *transaction_index,
        }
    }
}

struct PendingTransaction {
    transaction_index: usize,
    tx_b64: String,
    signature: String,
    started_at: Instant,
    last_send: Instant,
    rebroadcasts: u32,
}

/// Send independent signed transactions with bounded concurrency, then drive
/// them through one shrinking confirmation state machine.
///
/// Every polling round makes exactly one `getSignatureStatuses` request for
/// all transactions still pending. Confirmed entries are removed immediately,
/// and only overdue pending transactions are rebroadcast (also with bounded
/// concurrency). For N=16 Tx D this replaces up to sixteen independent status
/// RPC loops with one batched request per backoff round.
pub async fn send_and_confirm_many_with_rebroadcast(
    rpc: &SolanaRpcClient,
    txs: Vec<(usize, String)>,
    timeout: Duration,
    resend_every: Duration,
    send_concurrency: usize,
) -> Vec<TransactionConfirmationOutcome> {
    if txs.is_empty() {
        return Vec::new();
    }

    let batch_started_at = Instant::now();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(send_concurrency.max(1)));
    let mut initial_sends = tokio::task::JoinSet::new();
    let mut outcomes = Vec::with_capacity(txs.len());
    for (transaction_index, tx_b64) in txs {
        let rpc = rpc.clone();
        let semaphore = semaphore.clone();
        initial_sends.spawn(async move {
            let started_at = Instant::now();
            let result = match semaphore.acquire_owned().await {
                Ok(_permit) => rpc.send_transaction(&tx_b64).await,
                Err(e) => Err(RpcError::Schema(format!(
                    "settle send semaphore closed: {e}"
                ))),
            };
            (transaction_index, tx_b64, started_at, result)
        });
    }

    let mut pending = Vec::with_capacity(initial_sends.len());
    while let Some(joined) = initial_sends.join_next().await {
        match joined {
            Ok((transaction_index, tx_b64, started_at, Ok(signature))) => {
                pending.push(PendingTransaction {
                    transaction_index,
                    tx_b64,
                    signature,
                    started_at,
                    last_send: Instant::now(),
                    rebroadcasts: 0,
                });
            }
            Ok((transaction_index, _tx_b64, _started_at, Err(error))) => {
                outcomes.push(TransactionConfirmationOutcome::Ambiguous {
                    transaction_index,
                    signature: None,
                    reason: format!("initial send outcome unknown: {error}"),
                });
            }
            Err(error) => {
                // A task panic cannot be attributed to a stable transaction
                // index. Keep gathering every attributable result; the worker
                // notices any missing index and marks it ambiguous.
                tracing::error!(%error, "settle initial-send task failed");
            }
        }
    }
    // RPC request order and error indices stay deterministic even though the
    // bounded initial sends can complete in any order.
    pending.sort_unstable_by_key(|tx| tx.transaction_index);

    let mut poll_interval = Duration::from_millis(250);
    while !pending.is_empty() {
        let signatures: Vec<String> = pending.iter().map(|tx| tx.signature.clone()).collect();
        let statuses = match rpc.get_signature_statuses(&signatures).await {
            Ok(statuses) => statuses,
            Err(error) => {
                for tx in pending.drain(..) {
                    outcomes.push(TransactionConfirmationOutcome::Ambiguous {
                        transaction_index: tx.transaction_index,
                        signature: Some(tx.signature),
                        reason: format!("signature-status RPC failed: {error}"),
                    });
                }
                break;
            }
        };
        let mut still_pending = Vec::with_capacity(pending.len());

        for (position, tx) in pending.into_iter().enumerate() {
            let status = statuses.get(position).and_then(Option::as_ref);
            match status {
                Some(status) if status.err.is_some() => {
                    outcomes.push(TransactionConfirmationOutcome::Rejected {
                        transaction_index: tx.transaction_index,
                        signature: tx.signature.clone(),
                        reason: format!(
                            "settle tx[{}] ({}) reverted: err={:?}",
                            tx.transaction_index, tx.signature, status.err
                        ),
                    });
                }
                Some(status) if status.confirmed_at_commitment == Some(true) => {
                    if tx.rebroadcasts > 0 {
                        tracing::debug!(
                            signature = %tx.signature,
                            transaction_index = tx.transaction_index,
                            rebroadcasts = tx.rebroadcasts,
                            elapsed_ms = tx.started_at.elapsed().as_millis() as u64,
                            "settle tx confirmed after batched rebroadcast(s)"
                        );
                    }
                    outcomes.push(TransactionConfirmationOutcome::Confirmed(
                        ConfirmedTransaction {
                            transaction_index: tx.transaction_index,
                            signature: tx.signature,
                            slot: status.slot,
                            elapsed_ms: tx.started_at.elapsed().as_millis() as u64,
                            rebroadcasts: tx.rebroadcasts,
                        },
                    ));
                }
                _ => still_pending.push(tx),
            }
        }
        pending = still_pending;

        if pending.is_empty() {
            break;
        }
        if batch_started_at.elapsed() >= timeout {
            for tx in pending.drain(..) {
                outcomes.push(TransactionConfirmationOutcome::Ambiguous {
                    transaction_index: tx.transaction_index,
                    signature: Some(tx.signature.clone()),
                    reason: format!(
                        "settle tx[{}] ({}) did not confirm within {timeout:?} ({} rebroadcast(s))",
                        tx.transaction_index, tx.signature, tx.rebroadcasts
                    ),
                });
            }
            break;
        }

        // Mark the resend time before launching so a transient RPC failure
        // cannot cause a tight resend loop. Failed rebroadcasts remain pending
        // and are retried after the normal cadence.
        let now = Instant::now();
        let overdue: Vec<usize> = pending
            .iter()
            .enumerate()
            .filter_map(|(position, tx)| {
                (now.duration_since(tx.last_send) >= resend_every).then_some(position)
            })
            .collect();
        let mut rebroadcasts = tokio::task::JoinSet::new();
        for position in overdue {
            pending[position].last_send = now;
            let rpc = rpc.clone();
            let tx_b64 = pending[position].tx_b64.clone();
            let semaphore = semaphore.clone();
            rebroadcasts.spawn(async move {
                let permit = semaphore.acquire_owned().await;
                let result = match permit {
                    Ok(_permit) => rpc.send_transaction_opts(&tx_b64, true).await,
                    Err(e) => Err(RpcError::Schema(format!(
                        "settle rebroadcast semaphore closed: {e}"
                    ))),
                };
                (position, result)
            });
        }
        while let Some(joined) = rebroadcasts.join_next().await {
            match joined {
                Ok((position, result)) if result.is_ok() => {
                    pending[position].rebroadcasts += 1;
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, "settle rebroadcast task failed");
                }
            }
        }

        tokio::time::sleep(poll_interval).await;
        poll_interval = (poll_interval * 2).min(Duration::from_secs(1));
    }

    outcomes.sort_unstable_by_key(TransactionConfirmationOutcome::transaction_index);
    outcomes
}

/// Poll `getSignatureStatuses` until every signature in `sigs` is
/// confirmed at the client's commitment OR `timeout` elapses.
/// Returns `Ok(())` once all confirm; `Err` if any tx reverts
/// (carries the failing index + the on-chain err) or the deadline
/// passes. Poll interval grows 250ms → 1s with exponential
/// backoff.
pub async fn confirm_signatures(
    rpc: &SolanaRpcClient,
    sigs: &[String],
    timeout: std::time::Duration,
) -> Result<(), RpcError> {
    if sigs.is_empty() {
        return Ok(());
    }
    let start = std::time::Instant::now();
    let mut interval = std::time::Duration::from_millis(250);

    loop {
        let statuses = rpc.get_signature_statuses(sigs).await?;
        let mut all_confirmed = true;
        for (i, status) in statuses.iter().enumerate() {
            match status {
                Some(s) if s.err.is_some() => {
                    return Err(RpcError::Schema(format!(
                        "tx[{i}] ({}) reverted: err={:?}",
                        sigs.get(i).map(String::as_str).unwrap_or("?"),
                        s.err
                    )));
                }
                Some(s) if s.confirmed_at_commitment == Some(true) => { /* good */ }
                _ => all_confirmed = false,
            }
        }
        if all_confirmed {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(RpcError::Schema(format!(
                "{} signature(s) did not confirm within {:?}: {:?}",
                sigs.len(),
                timeout,
                statuses
            )));
        }
        tokio::time::sleep(interval).await;
        interval = (interval * 2).min(std::time::Duration::from_secs(1));
    }
}
