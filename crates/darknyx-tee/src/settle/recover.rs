//! Boot reconciliation of journaled in-flight settlements (audit finding T-06).
//!
//! The journal ([`crate::persistence::journal`]) says what the enclave was doing
//! when it stopped. This module decides what each surviving entry means now, by
//! asking the chain — never by trusting the journal's own stage, which by
//! construction records an *intent* that may or may not have taken effect.
//!
//! # The authority is the consumed-note PDA, not the signature
//!
//! A transaction signature can be unknown for reasons that have nothing to do
//! with whether it landed: the RPC dropped it from its status cache, the node is
//! behind, the send never left the enclave. `tee_forced_settle_batched` creates
//! BOTH commitment-keyed consumed-note PDAs atomically, so their existence is
//! durable, node-independent proof that the match settled. That is the same
//! reasoning the in-process ambiguity path already uses
//! (`worker::reconcile_consumed_pdas`); recovery applies it to a journal entry
//! instead of a live job, so the two agree by construction rather than by
//! coincidence.
//!
//! Exactly one PDA present is never resolved by guessing. It means either an
//! inconsistent RPC view or external consumption of one input, and both demand a
//! human — inferring "probably settled" there is how a redrive double-spends or
//! a stall silently strands collateral.
//!
//! # Redrive is bounded by the lock, not by optimism
//!
//! A settle may only be redriven while the notes' locks and the batch marker are
//! still valid. Past that deadline the on-chain state has moved on: the locks are
//! permissionlessly releasable and any redrive would fail anyway. Recovery
//! therefore reports [`RecoveryAction::ReleaseExpired`] rather than retrying
//! forever, so the collateral goes back to the user instead of being retried
//! against a window that has closed.
//!
//! # What is deliberately NOT recovered
//!
//! Resting orders. They are not restored from disk and not auto-rebooked — a
//! recorded decision, not an omission. An order is a signed client intent with a
//! nonce and a session binding; resurrecting one after an arbitrary gap would
//! re-enter the book on the client's behalf at a price it chose under different
//! conditions. The daemon observes the terminal/restart state and submits a
//! fresh signed order once the note is usable again.

use crate::persistence::journal::{JournalEntry, JournalStage};

/// What the chain says about one match's two input notes.
///
/// Mirrors `worker::ConsumedPdaState`; kept as its own type so the recovery
/// decision table can be exercised without an RPC client.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ConsumedState {
    /// Both consumed-note PDAs exist and are vault-owned — the match settled.
    BothConsumed,
    /// Neither exists — nothing was consumed; a redrive is still safe.
    NeitherConsumed,
    /// Exactly one exists. Never resolved by inference.
    Inconsistent,
}

/// What the enclave should do with a journal entry after checking the chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    /// Settled before the restart. Drop the journal entry; the notes are
    /// consumed and the locks are spent.
    AlreadySettled {
        /// True when the conclusion came from the consumed PDAs rather than a
        /// signature status — worth surfacing, because it is the case where the
        /// enclave never saw its own transaction confirm.
        reconciled_from_consumed_pdas: bool,
    },
    /// Nothing was consumed and the lock window is still open: the settle can be
    /// safely rebuilt and resubmitted from the journaled openings.
    Redrive { deadline_slot: u64 },
    /// Nothing was consumed and the window has closed. The locks are releasable;
    /// the user's collateral must go back rather than be retried.
    ReleaseExpired { expired_at_slot: u64 },
    /// The chain view is self-contradictory. Requires an operator; the enclave
    /// must neither redrive nor declare success.
    Indeterminate { reason: String },
}

/// The chain facts recovery needs, as a trait so the decision table is testable
/// without a live RPC.
pub trait ChainView {
    /// Consumed-note PDA state for a match's two input commitments.
    fn consumed_state(&self, note_a: &[u8; 32], note_b: &[u8; 32]) -> ConsumedState;
    /// Whether a submitted signature is known-confirmed. `None` means "cannot
    /// tell" — which is NOT the same as "did not land", and is why this returning
    /// `None` falls through to the consumed-PDA check rather than concluding
    /// anything.
    fn signature_confirmed(&self, signature: &str) -> Option<bool>;
    /// Current finalized slot, for the lock/marker deadline comparison.
    fn current_slot(&self) -> u64;
}

/// Decide what to do with one journaled entry.
///
/// The order of checks matters. The consumed PDAs are consulted first whenever
/// they are decisive, because they are durable on-chain state; a signature status
/// only ever *adds* confidence to a `BothConsumed` reading or explains a
/// `NeitherConsumed` one. A signature that reads confirmed while neither PDA
/// exists is contradictory and is reported as such rather than believed.
pub fn decide(entry: &JournalEntry, chain: &impl ChainView) -> RecoveryAction {
    let note_a = entry.payload.note_a_commitment;
    let note_b = entry.payload.note_b_commitment;

    match chain.consumed_state(&note_a, &note_b) {
        ConsumedState::BothConsumed => {
            // Whether we ever saw the signature confirm only changes how we
            // describe it, never the conclusion: the PDAs are the proof.
            let saw_confirmation = entry
                .settle_sig
                .as_deref()
                .and_then(|s| chain.signature_confirmed(s))
                .unwrap_or(false);
            RecoveryAction::AlreadySettled {
                reconciled_from_consumed_pdas: !saw_confirmation,
            }
        }

        ConsumedState::NeitherConsumed => {
            // A signature the chain reports CONFIRMED while neither input note
            // is consumed cannot both be true. Rather than pick the convenient
            // half, say so — a redrive under a genuinely-confirmed settle is a
            // double-settle attempt, and declaring success under a genuinely
            // unconsumed one strands the notes.
            if let Some(sig) = entry.settle_sig.as_deref() {
                if chain.signature_confirmed(sig) == Some(true) {
                    return RecoveryAction::Indeterminate {
                        reason: format!(
                            "settle signature {sig} reads confirmed but neither consumed-note \
                             PDA exists; refusing to redrive or to declare settled"
                        ),
                    };
                }
            }
            let now = chain.current_slot();
            if now < entry.lock_expiry_slot {
                RecoveryAction::Redrive {
                    deadline_slot: entry.lock_expiry_slot,
                }
            } else {
                RecoveryAction::ReleaseExpired {
                    expired_at_slot: entry.lock_expiry_slot,
                }
            }
        }

        ConsumedState::Inconsistent => RecoveryAction::Indeterminate {
            reason: format!(
                "exactly one consumed-note PDA exists for batch {} match {} — an inconsistent \
                 RPC view or external consumption of one input; never inferred",
                entry.batch_id, entry.match_idx
            ),
        },
    }
}

/// Summary of a whole recovery pass, for the boot log and for tests.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct RecoverySummary {
    pub already_settled: usize,
    pub redrive: usize,
    pub release_expired: usize,
    pub indeterminate: usize,
}

impl RecoverySummary {
    pub fn total(&self) -> usize {
        self.already_settled + self.redrive + self.release_expired + self.indeterminate
    }

    /// True when anything needs a human before trading should be considered
    /// healthy.
    pub fn needs_operator(&self) -> bool {
        self.indeterminate > 0
    }
}

/// Classify every journaled entry. Returns the per-entry decisions alongside the
/// summary; the caller performs the actions (redrive, release, drop).
pub fn plan(
    entries: &[JournalEntry],
    chain: &impl ChainView,
) -> (Vec<(JournalEntry, RecoveryAction)>, RecoverySummary) {
    let mut summary = RecoverySummary::default();
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let action = decide(e, chain);
        match &action {
            RecoveryAction::AlreadySettled { .. } => summary.already_settled += 1,
            RecoveryAction::Redrive { .. } => summary.redrive += 1,
            RecoveryAction::ReleaseExpired { .. } => summary.release_expired += 1,
            RecoveryAction::Indeterminate { .. } => summary.indeterminate += 1,
        }
        out.push((e.clone(), action));
    }
    (out, summary)
}

/// Whether a `Redrive` decision is actually actionable for this entry.
///
/// A settle can only be rebuilt once the batch has a Merkle root: the root
/// derives the `BatchValidityMarker` PDA that Tx D reads, and it is what the
/// per-match inclusion proof is against. An entry journaled at
/// [`JournalStage::Prepared`] — locks captured, nothing proven yet — has no root,
/// so there is nothing to resubmit and the locks should be released instead of
/// retried. Returning `true` here for such an entry would send recovery into a
/// redrive loop that can never succeed.
pub fn is_redrivable(entry: &JournalEntry) -> bool {
    !matches!(entry.stage, JournalStage::Prepared) && entry.batch_root.is_some()
}

// ── Boot-time reconciliation against a live RPC ─────────────────────────────

/// Chain facts gathered up front, so the decision table stays a pure function.
///
/// Querying first and deciding second is deliberate: it keeps [`decide`] free of
/// I/O and therefore exhaustively testable, and it means every entry in one boot
/// is judged against a single consistent view rather than a view that drifts as
/// the pass runs.
struct GatheredChain {
    consumed: std::collections::HashMap<(u64, u8), ConsumedState>,
    confirmed: std::collections::HashMap<String, bool>,
    slot: u64,
}

impl ChainView for GatheredChain {
    fn consumed_state(&self, _a: &[u8; 32], _b: &[u8; 32]) -> ConsumedState {
        // Unused: `decide` is driven through `keyed` below, which resolves per
        // entry. Kept to satisfy the trait for the gathered view.
        ConsumedState::Inconsistent
    }
    fn signature_confirmed(&self, signature: &str) -> Option<bool> {
        self.confirmed.get(signature).copied()
    }
    fn current_slot(&self) -> u64 {
        self.slot
    }
}

/// A per-entry view that answers `consumed_state` from the gathered map.
struct EntryChain<'a> {
    inner: &'a GatheredChain,
    key: (u64, u8),
}

impl ChainView for EntryChain<'_> {
    fn consumed_state(&self, _a: &[u8; 32], _b: &[u8; 32]) -> ConsumedState {
        self.inner
            .consumed
            .get(&self.key)
            .copied()
            // A missing gather result means the RPC failed for this entry. That
            // is not evidence of anything, so it must not read as "nothing was
            // consumed" — which would authorise a redrive.
            .unwrap_or(ConsumedState::Inconsistent)
    }
    fn signature_confirmed(&self, s: &str) -> Option<bool> {
        self.inner.signature_confirmed(s)
    }
    fn current_slot(&self) -> u64 {
        self.inner.current_slot()
    }
}

/// Query the chain for every journaled entry, then classify them.
pub async fn reconcile_at_boot(
    rpc: &crate::solana_rpc::SolanaRpcClient,
    entries: &[JournalEntry],
) -> (Vec<(JournalEntry, RecoveryAction)>, RecoverySummary) {
    use crate::settle::vault::{consumed_note_pda, vault_program_id};

    // `getLatestBlockhash` carries the context slot, so this needs no extra
    // round trip. A failure yields slot 0, which makes every deadline comparison
    // read as "still inside the window" — the conservative direction: recovery
    // proposes a redrive that the chain will simply reject if the lock has in
    // fact expired, rather than releasing a lock that is still live.
    let slot = rpc
        .get_latest_blockhash()
        .await
        .map(|bh| bh.context_slot)
        .unwrap_or(0);
    let vault = vault_program_id();
    let mut consumed = std::collections::HashMap::new();
    let mut confirmed = std::collections::HashMap::new();

    for e in entries {
        let (a_pda, _) = consumed_note_pda(&e.payload.note_a_commitment);
        let (b_pda, _) = consumed_note_pda(&e.payload.note_b_commitment);
        let a = rpc.get_account_info(&a_pda).await;
        let b = rpc.get_account_info(&b_pda).await;
        let state = match (a, b) {
            (Ok(a), Ok(b)) => {
                let a_ok = a.as_ref().is_some_and(|acc| acc.owner == vault);
                let b_ok = b.as_ref().is_some_and(|acc| acc.owner == vault);
                match (a_ok, b_ok) {
                    (true, true) => ConsumedState::BothConsumed,
                    (false, false) => ConsumedState::NeitherConsumed,
                    _ => ConsumedState::Inconsistent,
                }
            }
            // An RPC error is not a chain fact. Reporting it as Inconsistent
            // routes the entry to an operator instead of letting a transient
            // outage authorise a redrive.
            _ => ConsumedState::Inconsistent,
        };
        consumed.insert((e.batch_id, e.match_idx), state);

        // Signature status is a WEAK signal here and is treated as one. The RPC
        // keeps only the recent ~150 slots without `searchTransactionHistory`,
        // so after any restart worth recovering from the status is usually
        // absent — which is exactly why the consumed PDAs above are the
        // authority and a missing status resolves to `None` rather than `false`.
        if let Some(sig) = e.settle_sig.as_deref() {
            if let Ok(statuses) = rpc.get_signature_statuses(&[sig.to_string()]).await {
                if let Some(Some(st)) = statuses.first() {
                    confirmed.insert(sig.to_string(), st.err.is_none());
                }
            }
        }
    }

    let gathered = GatheredChain {
        consumed,
        confirmed,
        slot,
    };
    let mut summary = RecoverySummary::default();
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let view = EntryChain {
            inner: &gathered,
            key: (e.batch_id, e.match_idx),
        };
        let action = decide(e, &view);
        match &action {
            RecoveryAction::AlreadySettled { .. } => summary.already_settled += 1,
            RecoveryAction::Redrive { .. } => summary.redrive += 1,
            RecoveryAction::ReleaseExpired { .. } => summary.release_expired += 1,
            RecoveryAction::Indeterminate { .. } => summary.indeterminate += 1,
        }
        out.push((e.clone(), action));
    }
    (out, summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settle::lock_note::Groth16ProofBytes;
    use crate::settle::payload::MatchResultPayload;
    use crate::settle::submit_lock::LockSideInputs;

    struct FakeChain {
        consumed: ConsumedState,
        sig_confirmed: Option<bool>,
        slot: u64,
    }

    impl ChainView for FakeChain {
        fn consumed_state(&self, _a: &[u8; 32], _b: &[u8; 32]) -> ConsumedState {
            self.consumed
        }
        fn signature_confirmed(&self, _s: &str) -> Option<bool> {
            self.sig_confirmed
        }
        fn current_slot(&self) -> u64 {
            self.slot
        }
    }

    fn lock_side(note: u8) -> LockSideInputs {
        LockSideInputs {
            tree_id: 0,
            note_commitment: [note; 32],
            order_id: [note; 16],
            expiry_slot: 1_000,
            token_mint: [0x0F; 32],
            merkle_root: [0x7C; 32],
            proof: Groth16ProofBytes {
                pi_a: [0; 64],
                pi_b: [0; 128],
                pi_c: [0; 64],
            },
            already_locked: false,
        }
    }

    fn payload() -> MatchResultPayload {
        MatchResultPayload {
            match_id: [0x11; 16],
            note_a_commitment: [0xA1; 32],
            note_b_commitment: [0xB1; 32],
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
            batch_slot: 7,
            fill_recovery: [0u8; 128],
        }
    }

    fn entry(stage: JournalStage, settle_sig: Option<&str>, expiry: u64) -> JournalEntry {
        JournalEntry {
            batch_id: 1,
            match_idx: 0,
            stage,
            payload: payload(),
            buyer_lock: lock_side(0xA1),
            seller_lock: lock_side(0xB1),
            match_index: 0,
            batch_root: Some([0xAB; 32]),
            lock_expiry_slot: expiry,
            lock_buyer_sig: None,
            lock_seller_sig: None,
            verify_sig: None,
            settle_sig: settle_sig.map(str::to_string),
            updated_at_ms: 0,
        }
    }

    #[test]
    fn both_consumed_is_settled_even_when_the_signature_is_unknown() {
        // The exact crash this is for: the enclave sent Tx D, died before seeing
        // it confirm, and the RPC no longer has the status. The PDAs still say
        // it landed.
        let chain = FakeChain {
            consumed: ConsumedState::BothConsumed,
            sig_confirmed: None,
            slot: 10,
        };
        let action = decide(&entry(JournalStage::Settling, Some("sig"), 1_000), &chain);
        assert_eq!(
            action,
            RecoveryAction::AlreadySettled {
                reconciled_from_consumed_pdas: true
            }
        );
    }

    #[test]
    fn both_consumed_with_a_confirmed_signature_is_not_flagged_as_pda_reconciled() {
        let chain = FakeChain {
            consumed: ConsumedState::BothConsumed,
            sig_confirmed: Some(true),
            slot: 10,
        };
        let action = decide(&entry(JournalStage::Settling, Some("sig"), 1_000), &chain);
        assert_eq!(
            action,
            RecoveryAction::AlreadySettled {
                reconciled_from_consumed_pdas: false
            }
        );
    }

    #[test]
    fn nothing_consumed_inside_the_window_is_redrivable() {
        let chain = FakeChain {
            consumed: ConsumedState::NeitherConsumed,
            sig_confirmed: None,
            slot: 500,
        };
        assert_eq!(
            decide(&entry(JournalStage::Verifying, None, 1_000), &chain),
            RecoveryAction::Redrive {
                deadline_slot: 1_000
            }
        );
    }

    /// Past the lock deadline the collateral must go back to the user, not be
    /// retried against a window that has closed.
    #[test]
    fn nothing_consumed_past_the_deadline_releases_rather_than_retries() {
        let chain = FakeChain {
            consumed: ConsumedState::NeitherConsumed,
            sig_confirmed: None,
            slot: 1_000,
        };
        assert_eq!(
            decide(&entry(JournalStage::Verifying, None, 1_000), &chain),
            RecoveryAction::ReleaseExpired {
                expired_at_slot: 1_000
            },
            "at exactly the expiry slot the lock is already releasable"
        );
    }

    #[test]
    fn one_consumed_pda_is_never_inferred_either_way() {
        let chain = FakeChain {
            consumed: ConsumedState::Inconsistent,
            sig_confirmed: Some(true),
            slot: 10,
        };
        match decide(&entry(JournalStage::Settling, Some("sig"), 1_000), &chain) {
            RecoveryAction::Indeterminate { reason } => {
                assert!(reason.contains("exactly one"), "got: {reason}")
            }
            other => panic!("expected Indeterminate, got {other:?}"),
        }
    }

    /// A confirmed signature with no consumed notes is a contradiction. Believing
    /// either half is unsafe: redriving risks a double-settle, declaring success
    /// strands the notes.
    #[test]
    fn a_confirmed_signature_with_no_consumed_notes_is_indeterminate() {
        let chain = FakeChain {
            consumed: ConsumedState::NeitherConsumed,
            sig_confirmed: Some(true),
            slot: 10,
        };
        match decide(&entry(JournalStage::Settling, Some("sig"), 1_000), &chain) {
            RecoveryAction::Indeterminate { reason } => {
                assert!(reason.contains("confirmed"), "got: {reason}");
            }
            other => panic!("expected Indeterminate, got {other:?}"),
        }
    }

    /// A signature the chain says did NOT confirm is ordinary: redrive it.
    #[test]
    fn a_definitively_unconfirmed_signature_redrives_normally() {
        let chain = FakeChain {
            consumed: ConsumedState::NeitherConsumed,
            sig_confirmed: Some(false),
            slot: 10,
        };
        assert_eq!(
            decide(&entry(JournalStage::Settling, Some("sig"), 1_000), &chain),
            RecoveryAction::Redrive {
                deadline_slot: 1_000
            }
        );
    }

    #[test]
    fn plan_counts_every_class_and_flags_operator_attention() {
        let chain = FakeChain {
            consumed: ConsumedState::Inconsistent,
            sig_confirmed: None,
            slot: 10,
        };
        let entries = vec![
            entry(JournalStage::Settling, None, 1_000),
            entry(JournalStage::Settling, None, 1_000),
        ];
        let (decisions, summary) = plan(&entries, &chain);
        assert_eq!(decisions.len(), 2);
        assert_eq!(summary.indeterminate, 2);
        assert_eq!(summary.total(), 2);
        assert!(
            summary.needs_operator(),
            "an indeterminate entry must not be silently absorbed into a healthy boot"
        );
    }

    #[test]
    fn an_entry_journaled_before_proving_is_not_redrivable() {
        // Prepared: locks captured, no batch root yet. There is nothing to
        // resubmit, so it must be released rather than retried forever.
        let e = entry(JournalStage::Prepared, None, 1_000);
        assert!(!is_redrivable(&e));
    }

    #[test]
    fn an_entry_without_a_batch_root_is_not_redrivable() {
        // Defensive: a later stage that somehow lost its root still cannot be
        // rebuilt, because the root derives the marker PDA Tx D reads.
        let mut e = entry(JournalStage::Settling, None, 1_000);
        e.batch_root = None;
        assert!(!is_redrivable(&e));
    }

    #[test]
    fn a_proven_entry_with_a_root_is_redrivable() {
        assert!(is_redrivable(&entry(JournalStage::Verifying, None, 1_000)));
        assert!(is_redrivable(&entry(JournalStage::Settling, None, 1_000)));
    }
}
