//! Shared transaction build/sign/send + confirmation helpers.
//!
//! Every settle-pipeline tx (lock_note, verify_match_batch,
//! settle_batched, close_marker) follows the same lifecycle:
//! compose instruction(s) → sign with the TEE keypair (which is
//! BOTH the fee-payer AND the `tee_authority` signer) → bincode +
//! base64 → `sendTransaction` → poll `getSignatureStatuses`. This
//! module is the single home for that machinery so each builder
//! only owns its instruction construction.
//!
//! The TEE keypair plays the fee-payer role for every tx (PR 4g.3
//! walk-back unified it with the Ed25519 settle signer); legacy
//! (pre-v0) transactions are used here. The v0 + ALT path for the
//! tx-size-constrained settle tx (Tx D) lands in PR 4g.5c.

use base64::Engine as _;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_transaction::Transaction;

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
    use solana_signer::Signer;
    let payer_pubkey = payer.pubkey();
    let tx = Transaction::new_signed_with_payer(ixs, Some(&payer_pubkey), &[payer], blockhash);
    let wire = bincode::serialize(&tx)
        .map_err(|e| RpcError::Schema(format!("tx bincode serialise failed: {e}")))?;
    let tx_b64 = base64::engine::general_purpose::STANDARD.encode(&wire);
    rpc.send_transaction(&tx_b64).await
}

/// Send a pre-built base64 tx, then poll until it confirms at the client's
/// commitment, REBROADCASTING the identical signed tx every `resend_every`
/// until it lands. Returns the (stable) signature once confirmed.
///
/// This is the fix for the per-batch-ALT settle stall (Tx D): a freshly
/// created/extended Address Lookup Table's new entries can take several slots
/// to become loadable network-wide, so the leader that receives the first
/// broadcast often drops the tx (it can't resolve the ALT yet) — and the lone
/// initial `send_transaction` then relies on the RPC node's own lazy
/// rebroadcast cadence, which on devnet leaves Tx D unconfirmed for ~10-14 s.
/// Re-pushing the same signature every ~1.5 s lets the tx land the moment the
/// ALT activates instead of waiting on the RPC. Resends use `skip_preflight`
/// (the first send already validated via preflight; the network dedups by
/// signature, so resends are idempotent and cheap).
///
/// Errors if the tx reverts (carries the on-chain err) or `timeout` elapses.
pub async fn send_and_confirm_with_rebroadcast(
    rpc: &SolanaRpcClient,
    tx_b64: &str,
    timeout: std::time::Duration,
    resend_every: std::time::Duration,
) -> Result<String, RpcError> {
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
                return Ok(sig);
            }
            _ => {}
        }
        if start.elapsed() >= timeout {
            return Err(RpcError::Schema(format!(
                "settle tx ({sig}) did not confirm within {timeout:?} ({resends} rebroadcast(s))"
            )));
        }
        // Rebroadcast the identical tx (skip preflight) so a leader that dropped
        // the first copy gets another chance once the ALT is loadable. Resend
        // errors (e.g. transient RPC) are non-fatal — keep polling.
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
