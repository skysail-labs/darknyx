//! Build, sign, submit, and confirm the two `lock_note` transactions for one match.
//!
//! Each match locks two input notes — the buyer's and the seller's — as **two
//! separate transactions, not one batched transaction.** Two reasons, and the
//! second is the durable one:
//!
//!   - Batching both locks into a single transaction only fits under the
//!     1232-byte cap with ALT-based account deduplication.
//!   - The two transactions are independent. If one fails — proof rejected,
//!     blockhash expired — the other has already landed and only the failed side is
//!     resubmitted. A batched transaction turns any single-side failure into a
//!     resend of both, including the proof bytes that were already accepted.
//!
//! Both are signed with the same TEE keypair, acting as both `tee_authority` and
//! fee-payer; see [`super::submit`].

use base64::Engine as _;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_address::Address;
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;

use super::lock_note::{build_lock_note_ix, Groth16ProofBytes, LockNoteArgs};
use super::pipeline::{budget_ixs, LOCK_COMPUTE_UNIT_LIMIT};
use crate::solana_rpc::{RpcError, SolanaRpcClient};

/// Per-side inputs the TEE needs to construct one `lock_note` ix.
/// `note_use_tag` typically comes from the `MatchPair` the matcher emitted;
/// `token_mint` + `expiry_slot` are config-
/// or order-derived; `merkle_root` + `proof` are the user-supplied
/// VALID_INPUT inputs the TEE relays (see the proof
/// integration gap).
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct LockSideInputs {
    /// The Merkle-tree shard this input note lives in (its home tree). Selects
    /// the `merkle_tree` account whose recent-roots ring `lock_note` checks
    /// `merkle_root` against. A fresh deposit's home tree is its deposit tree;
    /// a relocked continuation's home tree is the shard the prior settle
    /// appended its change note to.
    pub tree_id: u8,
    pub note_use_tag: [u8; 32],
    pub order_id: [u8; 16],
    pub expiry_slot: u64,
    pub token_mint: [u8; 32],
    pub merkle_root: [u8; 32],
    pub proof: Groth16ProofBytes,
    /// True when this input is a relocked continuation note: a PRIOR
    /// batch's `tee_forced_settle_batched` already created its `NoteLock`
    /// PDA (the re-lock), so issuing `lock_note` again would collide
    /// ("Allocate: account already in use"). The existing relock pins the
    /// note for this settle, so the lock is SKIPPED for this side.
    pub already_locked: bool,
}

impl From<LockSideInputs> for LockNoteArgs {
    fn from(s: LockSideInputs) -> Self {
        Self {
            tree_id: s.tree_id,
            note_use_tag: s.note_use_tag,
            order_id: s.order_id,
            expiry_slot: s.expiry_slot,
            token_mint: s.token_mint,
            merkle_root: s.merkle_root,
            proof: s.proof,
        }
    }
}

/// Outcome of submitting both lock_note txs for one match.
#[derive(Clone, Debug)]
pub struct LockPairOutcome {
    /// Base58 signature of the buyer's lock_note tx, populated as
    /// soon as `sendTransaction` returned (NOT after confirmation —
    /// see [`confirm_lock_pair`] for the polling helper). `None` when
    /// the side was a relocked continuation note (lock skipped).
    pub buyer_sig: Option<String>,
    pub seller_sig: Option<String>,
}

/// Build + sign + submit both `lock_note` txs for one match.
///
/// Returns the two base58 signatures as soon as both
/// `sendTransaction` calls succeed. Confirmation polling is a
/// separate step — see [`confirm_lock_pair`] — so callers can
/// orchestrate the wait themselves (e.g. concurrently with the
/// prover task).
///
/// The two txs share the same blockhash, fetched once via
/// `getLatestBlockhash`. If the blockhash expires between submit
/// and confirm, the caller resubmits.
pub async fn submit_lock_note_pair(
    rpc: &SolanaRpcClient,
    tee_keypair: &Keypair,
    buyer: LockSideInputs,
    seller: LockSideInputs,
    priority_fee: u64,
) -> Result<LockPairOutcome, RpcError> {
    // A relocked continuation input is already locked by the prior batch's
    // re-lock PDA — skip its lock_note (re-init would collide). If BOTH sides
    // are relocked there's nothing to send.
    let tee_pubkey = tee_keypair.pubkey();
    let blockhash = if buyer.already_locked && seller.already_locked {
        None
    } else {
        Some(Hash::new_from_array(
            rpc.get_latest_blockhash().await?.blockhash,
        ))
    };

    let buyer_sig = if buyer.already_locked {
        None
    } else {
        Some(
            build_sign_send(
                rpc,
                tee_keypair,
                &tee_pubkey,
                blockhash.unwrap(),
                buyer,
                priority_fee,
            )
            .await?,
        )
    };
    let seller_sig = if seller.already_locked {
        None
    } else {
        Some(
            build_sign_send(
                rpc,
                tee_keypair,
                &tee_pubkey,
                blockhash.unwrap(),
                seller,
                priority_fee,
            )
            .await?,
        )
    };

    Ok(LockPairOutcome {
        buyer_sig,
        seller_sig,
    })
}

/// Build + sign ONE `lock_note` tx → base64 wire form. Does NOT send — the
/// caller can fire many concurrently (sharing `blockhash`) and confirm them
/// together (see the worker's concurrent lock pass). `keypair` is the shard's
/// fee-payer AND `tee_authority` AND signer (one key, one signature). Returns
/// `None` for an `already_locked` continuation side (no lock to issue).
pub fn build_lock_tx_b64(
    keypair: &Keypair,
    blockhash: Hash,
    side: &LockSideInputs,
    priority_fee: u64,
) -> Result<Option<String>, RpcError> {
    if side.already_locked {
        return Ok(None);
    }
    let tee_pubkey = keypair.pubkey();
    let ix = build_lock_note_ix(&tee_pubkey, side.clone().into());
    // lock_note runs a full 26-level Merkle inclusion check (~118k CU,
    // tight under the 200k/ix default) — request a right-sized explicit
    // limit (+ the priority-fee price ix) so the tx is bid on a tight CU
    // footprint and packs predictably.
    let mut ixs = budget_ixs(LOCK_COMPUTE_UNIT_LIMIT, priority_fee);
    ixs.push(ix);
    // `new_signed_with_payer` sets `account_keys[0]` to the payer (the shard
    // key), and signs in one shot — that key plays `tee_authority` AND
    // fee-payer, so one keypair satisfies both constraints.
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&tee_pubkey), &[keypair], blockhash);
    let wire = bincode::serialize(&tx)
        .map_err(|e| RpcError::Schema(format!("tx bincode serialise failed: {e}")))?;
    Ok(Some(
        base64::engine::general_purpose::STANDARD.encode(&wire),
    ))
}

async fn build_sign_send(
    rpc: &SolanaRpcClient,
    keypair: &Keypair,
    _tee_pubkey: &Address,
    blockhash: Hash,
    side: LockSideInputs,
    priority_fee: u64,
) -> Result<String, RpcError> {
    // `already_locked` is handled by the caller here (the side is only passed
    // when there's a lock to send), so `build_lock_tx_b64` always returns Some.
    let tx_b64 = build_lock_tx_b64(keypair, blockhash, &side, priority_fee)?
        .expect("build_sign_send called for an already_locked side");
    rpc.send_transaction(&tx_b64).await
}

/// Poll [`SolanaRpcClient::get_signature_statuses`] until both
/// sigs are confirmed at the client's commitment OR `deadline`
/// elapses.
///
/// Returns `Ok(())` once both confirm; `Err` if either tx surfaces
/// an on-chain error or the deadline passes without confirmation.
/// The poll interval grows from 250ms → 1s with exponential
/// backoff; same shape the existing TS SDK helper uses.
pub async fn confirm_lock_pair(
    rpc: &SolanaRpcClient,
    outcome: &LockPairOutcome,
    timeout: std::time::Duration,
) -> Result<(), RpcError> {
    let start = std::time::Instant::now();
    let mut interval = std::time::Duration::from_millis(250);
    // Only the sides that were actually locked have a sig to confirm; a
    // relocked continuation side was skipped (None). If both were skipped
    // there is nothing to confirm.
    let labeled: Vec<(&str, String)> = [
        ("buyer", outcome.buyer_sig.clone()),
        ("seller", outcome.seller_sig.clone()),
    ]
    .into_iter()
    .filter_map(|(l, s)| s.map(|s| (l, s)))
    .collect();
    if labeled.is_empty() {
        return Ok(());
    }
    let sigs: Vec<String> = labeled.iter().map(|(_, s)| s.clone()).collect();

    loop {
        let statuses = rpc.get_signature_statuses(&sigs).await?;
        // 4 possible per-sig states: None (unknown / not yet seen),
        // Some + confirmed_at_commitment=false (lower commitment
        // than we want), Some + confirmed_at_commitment=true,
        // Some + err=Some.
        let mut all_confirmed = true;
        // Index via `.get()` rather than `statuses[i]`: a non-compliant RPC
        // could return a shorter array than we requested, and raw indexing
        // would panic. A missing entry is treated as "not yet confirmed".
        for (i, (label, _)) in labeled.iter().enumerate() {
            match statuses.get(i) {
                Some(Some(s)) if s.err.is_some() => {
                    return Err(RpcError::Schema(format!(
                        "{label} lock_note tx reverted: err={:?}",
                        s.err
                    )));
                }
                Some(Some(s)) if s.confirmed_at_commitment == Some(true) => { /* good */ }
                _ => all_confirmed = false,
            }
        }
        if all_confirmed {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(RpcError::Schema(format!(
                "lock_note pair did not confirm within {:?}: status={:?}",
                timeout, statuses
            )));
        }
        tokio::time::sleep(interval).await;
        interval = (interval * 2).min(std::time::Duration::from_secs(1));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_proof() -> Groth16ProofBytes {
        Groth16ProofBytes {
            pi_a: [0x11; 64],
            pi_b: [0x22; 128],
            pi_c: [0x33; 64],
        }
    }

    fn dummy_buyer_inputs() -> LockSideInputs {
        LockSideInputs {
            tree_id: 0,
            note_use_tag: [0xAA; 32],
            order_id: [0xBB; 16],
            expiry_slot: 1_000_000,
            token_mint: [0xCC; 32],
            merkle_root: [0xDD; 32],
            proof: dummy_proof(),
            already_locked: false,
        }
    }

    fn dummy_seller_inputs() -> LockSideInputs {
        LockSideInputs {
            tree_id: 0,
            note_use_tag: [0x55; 32],
            order_id: [0x66; 16],
            expiry_slot: 1_000_000,
            token_mint: [0x77; 32],
            merkle_root: [0xDD; 32],
            proof: dummy_proof(),
            already_locked: false,
        }
    }

    #[test]
    fn lock_side_inputs_into_args_round_trips() {
        let buyer = dummy_buyer_inputs();
        let args: LockNoteArgs = buyer.clone().into();
        assert_eq!(args.note_use_tag, buyer.note_use_tag);
        assert_eq!(args.order_id, buyer.order_id);
        assert_eq!(args.expiry_slot, buyer.expiry_slot);
        assert_eq!(args.token_mint, buyer.token_mint);
        assert_eq!(args.merkle_root, buyer.merkle_root);
    }

    #[test]
    fn buyer_and_seller_inputs_produce_distinct_note_locks() {
        let buyer: LockNoteArgs = dummy_buyer_inputs().into();
        let seller: LockNoteArgs = dummy_seller_inputs().into();
        assert_ne!(buyer.note_use_tag, seller.note_use_tag);
        // The PDA derivation is what makes these distinct on-chain;
        // verifying the input commitments differ is the test layer
        // assertion we can make without a runtime.
    }

    #[test]
    fn private_amount_lock_tx_retains_wire_headroom() {
        let keypair = Keypair::new();
        let encoded = build_lock_tx_b64(
            &keypair,
            Hash::new_from_array([7u8; 32]),
            &dummy_buyer_inputs(),
            1,
        )
        .unwrap()
        .unwrap();
        let wire = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert!(
            wire.len() <= 800,
            "lock tx is {} bytes; expected at least 432 bytes of cap headroom",
            wire.len()
        );
    }
}
