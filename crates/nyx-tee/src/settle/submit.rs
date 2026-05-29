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
