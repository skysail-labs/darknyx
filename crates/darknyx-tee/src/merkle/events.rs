//! Decode on-chain leaf-append events into `(leaf_index, value)` pairs
//! for the Merkle mirror sync (Phase 2b).
//!
//! The vault appends Merkle leaves in three instructions; only two
//! actually create leaves, and they expose the data differently:
//!
//! - **`deposit`** emits `NoteCreated { leaf_index, commitment, … }` —
//!   self-describing: the event carries both the index AND the value.
//! - **`tee_forced_settle_batched`** emits `TradeSettled { …,
//!   note_c_leaf, note_d_leaf, note_e_leaf, note_f_leaf,
//!   note_fee_base_leaf, note_fee_quote_leaf, … }` — the event carries
//!   the leaf INDICES (`u64::MAX` = not inserted) but NOT the values.
//!   The values live in the instruction's `MatchResultPayload`
//!   (`note_c_commitment`, …), which we decode from the ix data and
//!   pair with the event indices by name.
//! - **`withdraw`** appends nothing (it spends a note via its
//!   nullifier; no new leaf), so it's not a source here.
//!
//! Anchor logs an event as a `Program data: <base64>` line where the
//! decoded bytes are `discriminator(8) || borsh(fields)`, and the event
//! discriminator is `sha256("event:<Name>")[..8]`.
//!
//! ## Provenance: `Program data:` is not a vault-private channel
//!
//! `Program data:` is the output of `sol_log_data`, which **any** Solana
//! program can call — Anchor's `emit!` is only a wrapper around it. A
//! transaction's `meta.logMessages` interleaves the logs of every program it
//! invokes, and the sync sources transactions by *address reference*
//! (`getTransactionsForAddress`), which returns transactions that merely name
//! the vault among their account keys — not only those that invoke it.
//!
//! Decoding that combined stream without attribution let anyone forge a leaf:
//! read the public `leaf_count` from `/tree/root`, emit a `NoteCreated` at that
//! index from a program of your own in a transaction naming the vault, and the
//! mirror appends an arbitrary value as a genuine leaf. The mirror is
//! append-only with no rewind, so `/tree/inclusion`, the intake root check, and
//! `/tree/leaves` are all built on a root the chain never had — a permanent
//! venue halt for the price of one transaction.
//!
//! Solana logs *do* carry program scope: `Program <id> invoke [n]` opens a
//! frame and `Program <id> success` / `failed` closes it. [`LogScope`] tracks
//! that stack, and a `Program data:` line is decoded only while the vault is
//! the **innermost** active program. Absent or malformed brackets mean no leaf
//! is accepted — fail closed.
//!
//! This module is pure decoding — the RPC fetch + ordering + applying
//! to the mirror lives in [`super::sync`] (the sync task feeds the
//! `(logs, settle_ix_data)` it pulled from each transaction in here).

use std::sync::LazyLock;

use base64::Engine as _;
use borsh::BorshDeserialize;
use sha2::{Digest, Sha256};

use crate::settle::payload::MatchResultPayload;
use crate::settle::settle_batched::SETTLE_BATCHED_DISCRIMINATOR;

/// `sha256("event:NoteCreated")[..8]`.
pub static NOTE_CREATED_DISCRIMINATOR: LazyLock<[u8; 8]> = LazyLock::new(|| {
    let h = Sha256::digest(b"event:NoteCreated");
    let mut d = [0u8; 8];
    d.copy_from_slice(&h[..8]);
    d
});

/// `sha256("event:TradeSettled")[..8]`.
pub static TRADE_SETTLED_DISCRIMINATOR: LazyLock<[u8; 8]> = LazyLock::new(|| {
    let h = Sha256::digest(b"event:TradeSettled");
    let mut d = [0u8; 8];
    d.copy_from_slice(&h[..8]);
    d
});

/// `sha256("event:NoteMerged")[..8]`.
pub static NOTE_MERGED_DISCRIMINATOR: LazyLock<[u8; 8]> = LazyLock::new(|| {
    let h = Sha256::digest(b"event:NoteMerged");
    let mut d = [0u8; 8];
    d.copy_from_slice(&h[..8]);
    d
});

/// One leaf appended on-chain: which shard it landed in + its index within
/// that shard + the 32-byte value. Post-sharding the index is PER-SHARD, so
/// `tree_id` is required to route the leaf to the right mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendedLeaf {
    pub tree_id: u8,
    pub leaf_index: u64,
    pub value: [u8; 32],
}

/// A leaf-append, wire-shaped for the live `tree` channel of the multiplexed
/// `/v1/stream` socket (`docs/tee-api-openapi.yaml`). The commitment is hex so
/// a browser client can match it against its own note commitments without a
/// byte decode. Public information (every leaf is already on-chain), so the
/// `tree` channel is GLOBAL — not per-account like fills/orders.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TreeAppendEvent {
    /// Discriminates the channel on the multiplexed socket.
    pub channel: &'static str,
    pub tree_id: u8,
    pub leaf_index: u64,
    /// 32-byte leaf commitment, hex-encoded.
    pub commitment: String,
}

impl TreeAppendEvent {
    /// Build the wire event from an applied leaf.
    pub fn from_leaf(leaf: &AppendedLeaf) -> Self {
        Self {
            channel: "tree",
            tree_id: leaf.tree_id,
            leaf_index: leaf.leaf_index,
            commitment: hex::encode(leaf.value),
        }
    }
}

/// Borsh-decode mirror of the vault `NoteCreated` event (field order
/// must match `programs/vault/src/instructions/deposit.rs`).
#[derive(BorshDeserialize)]
struct NoteCreatedEvent {
    tree_id: u8,
    leaf_index: u64,
    commitment: [u8; 32],
    _token_mint: [u8; 32],
    _amount: u64,
    _new_root: [u8; 32],
}

/// Borsh-decode mirror of the vault `TradeSettled` event (field order
/// must match `programs/vault/src/instructions/tee_forced_settle.rs`).
/// We only consume the six leaf-index fields, but the full layout is
/// required for a correct sequential borsh decode.
#[derive(BorshDeserialize)]
struct TradeSettledEvent {
    tree_id: u8,
    _match_id: [u8; 16],
    // Amount-privacy (P3b): the trade amounts / change / fees / clearing price
    // were removed from the on-chain TradeSettled event, so they're gone from
    // this borsh mirror too. The event now carries only leaf indices.
    note_c_leaf: u64,
    note_d_leaf: u64,
    note_e_leaf: u64,
    note_f_leaf: u64,
    note_fee_base_leaf: u64,
    note_fee_quote_leaf: u64,
    _buyer_relock_active: bool,
    _seller_relock_active: bool,
    _new_root: [u8; 32],
}

/// Borsh-decode mirror of the vault `NoteMerged` event (field order
/// must match `programs/vault/src/instructions/merge.rs`). One merge
/// appends exactly one output leaf.
#[derive(BorshDeserialize)]
struct NoteMergedEvent {
    tree_id: u8,
    output_commitment: [u8; 32],
    _token_mint: [u8; 32],
    _k: u8,
    leaf_index: u64,
    _new_root: [u8; 32],
}

/// Sentinel in `TradeSettled` leaf-index fields meaning "no leaf
/// inserted for this slot" (exact-fill change notes, or the
/// non-first settlement in a batch for the fee notes).
const NO_LEAF: u64 = u64::MAX;

/// Decode a `MatchResultPayload` from a `tee_forced_settle_batched`
/// instruction's data. Returns `None` if the data isn't a settle ix
/// (wrong/short discriminator) or the payload bytes don't decode.
///
/// The discriminator is a *shape* check, not an authenticity one — any program
/// can be handed 8 chosen bytes followed by a chosen payload. **The caller must
/// select the instruction by `program_id`** (`super::sync::apply_address_txs`
/// does); otherwise a forged `TradeSettled` event and an attacker instruction
/// supply the two halves of a fabricated leaf between them.
///
/// ix data layout: `disc(8) || tree_id(1) || Borsh(payload, 488) ||
/// match_index(1) || 4×32 siblings` (see
/// `settle_batched::build_settle_batched_ix`). Post-sharding the payload
/// starts at offset 9 (disc + the 1-byte `tree_id`). The width is
/// `MatchResultPayload::WIRE_LEN` (payload v9 removed two nullifiers).
pub fn decode_settle_payload(ix_data: &[u8]) -> Option<MatchResultPayload> {
    const PAYLOAD_START: usize = 8 + 1; // disc + tree_id
    if ix_data.len() < PAYLOAD_START + MatchResultPayload::WIRE_LEN {
        return None;
    }
    if ix_data[..8] != *SETTLE_BATCHED_DISCRIMINATOR {
        return None;
    }
    let payload_bytes = &ix_data[PAYLOAD_START..PAYLOAD_START + MatchResultPayload::WIRE_LEN];
    MatchResultPayload::try_from_slice(payload_bytes).ok()
}

/// What one log line means to the scope tracker.
enum LogLine<'a> {
    /// `Program <id> invoke [n]` — opens a frame for `<id>`.
    Invoke(&'a str),
    /// `Program <id> success` / `Program <id> failed: …` /
    /// `Program failed to complete: …` — closes the innermost frame.
    Exit,
    /// `Program data: <base64>` — an event emitted by whichever program owns
    /// the innermost open frame.
    Data(&'a str),
    /// Anything else: `Program log:`, compute-unit accounting, `Log truncated`,
    /// or a line from outside this vocabulary.
    Other,
}

/// Classify one log line.
///
/// `Program log:` and `Program return:` are checked and discarded **before**
/// the scope-marker patterns on purpose. Their payload is attacker-controlled
/// text — a program can `msg!("Program <vault> invoke [1]")` — and a matcher
/// that reached the `invoke`/`success` patterns first would let that text open
/// a vault frame. (An attacker cannot forge a whole *array element*: a log with
/// an embedded newline is still one entry, and we classify per entry.)
fn classify(line: &str) -> LogLine<'_> {
    if let Some(b64) = line.strip_prefix("Program data: ") {
        return LogLine::Data(b64);
    }
    if line.starts_with("Program log:") || line.starts_with("Program return:") {
        return LogLine::Other;
    }
    let Some(rest) = line.strip_prefix("Program ") else {
        return LogLine::Other;
    };
    // `Program failed to complete: …` aborts the innermost program and, unlike
    // every other exit line, carries no program id.
    if rest.starts_with("failed to complete") {
        return LogLine::Exit;
    }
    match rest.split_once(' ') {
        // `invoke [n]` — the depth marker is redundant with our own stack
        // depth, so it is not parsed.
        Some((id, tail)) if tail.starts_with("invoke [") => LogLine::Invoke(id),
        Some((_, tail)) if tail == "success" || tail.starts_with("failed") => LogLine::Exit,
        _ => LogLine::Other,
    }
}

/// The stack of currently-executing programs, innermost last.
///
/// Solana brackets every invocation, including CPIs at any depth, so replaying
/// the bracket lines reconstructs exactly which program emitted each
/// `Program data:` line.
#[derive(Default)]
struct LogScope<'a> {
    stack: Vec<&'a str>,
}

impl<'a> LogScope<'a> {
    fn enter(&mut self, program_id: &'a str) {
        self.stack.push(program_id);
    }

    fn exit(&mut self) {
        self.stack.pop();
    }

    /// Whether `program_id` owns the innermost open frame — i.e. whether it is
    /// the program that emitted the line being classified.
    ///
    /// An empty stack yields `false`, so logs whose brackets are missing or
    /// truncated contribute no leaves rather than being trusted.
    fn innermost_is(&self, program_id: &str) -> bool {
        self.stack.last() == Some(&program_id)
    }
}

/// Extract every leaf appended by one transaction.
///
/// `vault_program_id` is the base58 vault address; **only events emitted inside
/// a vault frame are decoded** (see the module header — without this, any
/// program can forge a leaf into the mirror). `logs` are the transaction's
/// `meta.logMessages`; `settle_ix_data` is the data of the
/// `tee_forced_settle_batched` instruction in that same transaction (if any),
/// needed to recover settle leaf values — the caller must have already
/// confirmed that instruction belongs to the vault. The caller sorts the
/// combined results across all transactions by `leaf_index` before applying to
/// the mirror.
///
/// A `TradeSettled` event with no decodable settle payload yields no
/// settle leaves (logged by the caller) rather than guessing — a
/// mismatch would corrupt the mirror root.
pub fn extract_appended_leaves(
    vault_program_id: &str,
    logs: &[String],
    settle_ix_data: Option<&[u8]>,
) -> Vec<AppendedLeaf> {
    let settle_payload = settle_ix_data.and_then(decode_settle_payload);
    let mut out = Vec::new();
    let mut scope = LogScope::default();

    for line in logs {
        let b64 = match classify(line) {
            LogLine::Invoke(id) => {
                scope.enter(id);
                continue;
            }
            LogLine::Exit => {
                scope.exit();
                continue;
            }
            LogLine::Other => continue,
            // The provenance check. A byte-identical event emitted by any other
            // program — at top level or nested under the vault via CPI — falls
            // here and is dropped.
            LogLine::Data(b64) if scope.innermost_is(vault_program_id) => b64,
            LogLine::Data(_) => continue,
        };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
            continue;
        };
        if bytes.len() < 8 {
            continue;
        }
        let disc = &bytes[..8];
        let body = &bytes[8..];

        if disc == *NOTE_CREATED_DISCRIMINATOR {
            if let Ok(ev) = NoteCreatedEvent::try_from_slice(body) {
                out.push(AppendedLeaf {
                    tree_id: ev.tree_id,
                    leaf_index: ev.leaf_index,
                    value: ev.commitment,
                });
            }
        } else if disc == *NOTE_MERGED_DISCRIMINATOR {
            // A merge appends one output leaf; without this branch the mirror
            // would silently fall behind on-chain after any consolidation.
            if let Ok(ev) = NoteMergedEvent::try_from_slice(body) {
                out.push(AppendedLeaf {
                    tree_id: ev.tree_id,
                    leaf_index: ev.leaf_index,
                    value: ev.output_commitment,
                });
            }
        } else if disc == *TRADE_SETTLED_DISCRIMINATOR {
            let Ok(ev) = TradeSettledEvent::try_from_slice(body) else {
                continue;
            };
            // Without the payload we can't recover the leaf VALUES, so
            // emit nothing rather than a wrong leaf.
            let Some(p) = settle_payload.as_ref() else {
                continue;
            };
            // Every output of one settle appends to the SAME shard
            // (`ev.tree_id`). Pair each inserted leaf index with its commitment.
            for (idx, value) in [
                (ev.note_c_leaf, p.note_c_commitment),
                (ev.note_d_leaf, p.note_d_commitment),
                (ev.note_e_leaf, p.note_e_commitment),
                (ev.note_f_leaf, p.note_f_commitment),
                (ev.note_fee_base_leaf, p.note_fee_base_commitment),
                (ev.note_fee_quote_leaf, p.note_fee_quote_commitment),
            ] {
                if idx != NO_LEAF {
                    out.push(AppendedLeaf {
                        tree_id: ev.tree_id,
                        leaf_index: idx,
                        value,
                    });
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settle::settle_batched::build_settle_batched_ix;
    use borsh::BorshSerialize;

    /// The vault, and a program that is not the vault. Both are shaped like
    /// real base58 addresses so the scope parser sees what it sees in
    /// production.
    const VAULT: &str = "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";
    const ATTACKER: &str = "AttackerPRoGram11111111111111111111111111111";

    /// Re-encode an event the way Anchor's `emit!` logs it:
    /// `Program data: base64(discriminator(8) || borsh(fields))`.
    fn event_log_line(disc: &[u8; 8], body: &[u8]) -> String {
        let mut bytes = disc.to_vec();
        bytes.extend_from_slice(body);
        format!(
            "Program data: {}",
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        )
    }

    /// Bracket `lines` in `program`'s invocation frame, the way the runtime
    /// does. `depth` is 1 for a top-level instruction, 2+ for a CPI.
    fn scoped(program: &str, depth: u8, lines: &[String]) -> Vec<String> {
        let mut out = vec![format!("Program {program} invoke [{depth}]")];
        out.extend(lines.iter().cloned());
        out.push(format!(
            "Program {program} consumed 4242 of 200000 compute units"
        ));
        out.push(format!("Program {program} success"));
        out
    }

    /// The common case: one top-level vault instruction emitting `lines`.
    fn vault_tx(lines: &[String]) -> Vec<String> {
        scoped(VAULT, 1, lines)
    }

    fn fr_safe(seed: u8) -> [u8; 32] {
        let mut b = [seed; 32];
        b[0] = 0;
        b
    }

    // Mirror of the vault NoteCreated for ENCODING in tests (the decode
    // mirror above intentionally has private/underscored fields).
    #[derive(BorshSerialize)]
    struct NoteCreatedWire {
        tree_id: u8,
        leaf_index: u64,
        commitment: [u8; 32],
        token_mint: [u8; 32],
        amount: u64,
        new_root: [u8; 32],
    }

    #[derive(BorshSerialize)]
    struct NoteMergedWire {
        tree_id: u8,
        output_commitment: [u8; 32],
        token_mint: [u8; 32],
        k: u8,
        leaf_index: u64,
        new_root: [u8; 32],
    }

    #[derive(BorshSerialize)]
    struct TradeSettledWire {
        tree_id: u8,
        match_id: [u8; 16],
        note_c_leaf: u64,
        note_d_leaf: u64,
        note_e_leaf: u64,
        note_f_leaf: u64,
        note_fee_base_leaf: u64,
        note_fee_quote_leaf: u64,
        buyer_relock_active: bool,
        seller_relock_active: bool,
        new_root: [u8; 32],
    }

    fn sample_payload() -> MatchResultPayload {
        MatchResultPayload {
            match_id: [0x11; 16],
            note_a_use_tag: fr_safe(0xA1),
            note_b_use_tag: fr_safe(0xB1),
            note_c_commitment: fr_safe(0xC1),
            note_d_commitment: fr_safe(0xD1),
            note_e_commitment: fr_safe(0xE1),
            note_f_commitment: fr_safe(0xF1),
            order_id_a: [0x01; 16],
            order_id_b: [0x02; 16],
            note_fee_base_commitment: fr_safe(0x1B),
            note_fee_quote_commitment: fr_safe(0x1C),
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

    #[test]
    fn discriminators_pin() {
        // Guard against an accidental rename: these are
        // sha256("event:<Name>")[..8].
        assert_eq!(
            hex::encode(*NOTE_CREATED_DISCRIMINATOR),
            hex::encode({
                let h = Sha256::digest(b"event:NoteCreated");
                let mut d = [0u8; 8];
                d.copy_from_slice(&h[..8]);
                d
            })
        );
        assert_eq!(
            hex::encode(*NOTE_MERGED_DISCRIMINATOR),
            hex::encode({
                let h = Sha256::digest(b"event:NoteMerged");
                let mut d = [0u8; 8];
                d.copy_from_slice(&h[..8]);
                d
            })
        );
    }

    #[test]
    fn decodes_note_created_index_and_value() {
        let commitment = fr_safe(0x42);
        let wire = NoteCreatedWire {
            tree_id: 0,
            leaf_index: 7,
            commitment,
            token_mint: [0x9e; 32],
            amount: 1_000,
            new_root: fr_safe(0x33),
        };
        let line = event_log_line(&NOTE_CREATED_DISCRIMINATOR, &borsh::to_vec(&wire).unwrap());
        let leaves = extract_appended_leaves(VAULT, &vault_tx(&[line]), None);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].leaf_index, 7);
        assert_eq!(leaves[0].value, commitment);
    }

    #[test]
    fn decodes_note_merged_index_and_value() {
        // A merge appends exactly one output leaf; the mirror must apply it on
        // the shard the event names (regression for the mirror-misses-merges bug).
        let output = fr_safe(0x77);
        let wire = NoteMergedWire {
            tree_id: 2,
            output_commitment: output,
            token_mint: [0x9e; 32],
            k: 4,
            leaf_index: 19,
            new_root: fr_safe(0x44),
        };
        let line = event_log_line(&NOTE_MERGED_DISCRIMINATOR, &borsh::to_vec(&wire).unwrap());
        let leaves = extract_appended_leaves(VAULT, &vault_tx(&[line]), None);
        assert_eq!(
            leaves,
            vec![AppendedLeaf {
                tree_id: 2,
                leaf_index: 19,
                value: output,
            }]
        );
    }

    #[test]
    fn decodes_settle_leaves_from_event_plus_payload() {
        let payload = sample_payload();
        // A settle with change notes on both sides + both fee notes,
        // so all six leaves are present (indices 10..=15).
        let wire = TradeSettledWire {
            tree_id: 0,
            match_id: payload.match_id,
            note_c_leaf: 10,
            note_d_leaf: 11,
            note_e_leaf: 12,
            note_f_leaf: 13,
            note_fee_base_leaf: 14,
            note_fee_quote_leaf: 15,
            buyer_relock_active: false,
            seller_relock_active: false,
            new_root: fr_safe(0x55),
        };
        let line = event_log_line(&TRADE_SETTLED_DISCRIMINATOR, &borsh::to_vec(&wire).unwrap());

        // Settle ix data the sync task would have pulled from the tx.
        let ix = build_settle_batched_ix(
            &solana_address::Address::new_from_array([0x42; 32]),
            0,
            &payload,
            0,
            &[[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]],
            &fr_safe(0xAB),
        );

        let leaves = extract_appended_leaves(VAULT, &vault_tx(&[line]), Some(&ix.data));
        assert_eq!(leaves.len(), 6);
        // Index ↔ value pairing by name.
        assert_eq!(
            leaves[0],
            AppendedLeaf {
                tree_id: 0,
                leaf_index: 10,
                value: payload.note_c_commitment
            }
        );
        assert_eq!(
            leaves[1],
            AppendedLeaf {
                tree_id: 0,
                leaf_index: 11,
                value: payload.note_d_commitment
            }
        );
        assert_eq!(
            leaves[2],
            AppendedLeaf {
                tree_id: 0,
                leaf_index: 12,
                value: payload.note_e_commitment
            }
        );
        assert_eq!(
            leaves[3],
            AppendedLeaf {
                tree_id: 0,
                leaf_index: 13,
                value: payload.note_f_commitment
            }
        );
        assert_eq!(
            leaves[4],
            AppendedLeaf {
                tree_id: 0,
                leaf_index: 14,
                value: payload.note_fee_base_commitment
            }
        );
        assert_eq!(
            leaves[5],
            AppendedLeaf {
                tree_id: 0,
                leaf_index: 15,
                value: payload.note_fee_quote_commitment
            }
        );
    }

    #[test]
    fn settle_skips_absent_leaves() {
        let payload = sample_payload();
        // Exact-fill, no change, no fees: only note_c + note_d present.
        let wire = TradeSettledWire {
            tree_id: 0,
            match_id: payload.match_id,
            note_c_leaf: 4,
            note_d_leaf: 5,
            note_e_leaf: NO_LEAF,
            note_f_leaf: NO_LEAF,
            note_fee_base_leaf: NO_LEAF,
            note_fee_quote_leaf: NO_LEAF,
            buyer_relock_active: false,
            seller_relock_active: false,
            new_root: fr_safe(0x55),
        };
        let line = event_log_line(&TRADE_SETTLED_DISCRIMINATOR, &borsh::to_vec(&wire).unwrap());
        let ix = build_settle_batched_ix(
            &solana_address::Address::new_from_array([0x42; 32]),
            0,
            &payload,
            0,
            &[[0x01; 32]; 4],
            &fr_safe(0xAB),
        );
        let leaves = extract_appended_leaves(VAULT, &vault_tx(&[line]), Some(&ix.data));
        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[0].leaf_index, 4);
        assert_eq!(leaves[1].leaf_index, 5);
    }

    #[test]
    fn trade_settled_without_payload_yields_nothing() {
        let payload = sample_payload();
        let wire = TradeSettledWire {
            tree_id: 0,
            match_id: payload.match_id,
            note_c_leaf: 4,
            note_d_leaf: 5,
            note_e_leaf: NO_LEAF,
            note_f_leaf: NO_LEAF,
            note_fee_base_leaf: NO_LEAF,
            note_fee_quote_leaf: NO_LEAF,
            buyer_relock_active: false,
            seller_relock_active: false,
            new_root: fr_safe(0x55),
        };
        let line = event_log_line(&TRADE_SETTLED_DISCRIMINATOR, &borsh::to_vec(&wire).unwrap());
        // No settle ix data → can't recover values → no leaves.
        assert!(extract_appended_leaves(VAULT, &vault_tx(&[line]), None).is_empty());
    }

    #[test]
    fn ignores_non_event_log_lines() {
        let logs = vec![
            "Program log: instruction: Deposit".to_string(),
            "Program 11111111111111111111111111111111 invoke [1]".to_string(),
            "Program data: !!!not-base64!!!".to_string(),
        ];
        assert!(extract_appended_leaves(VAULT, &logs, None).is_empty());
    }

    #[test]
    fn decode_settle_payload_rejects_wrong_discriminator() {
        let mut data = vec![0u8; 8 + MatchResultPayload::WIRE_LEN];
        data[..8].copy_from_slice(b"badbaddd");
        assert!(decode_settle_payload(&data).is_none());
        // Too short.
        assert!(decode_settle_payload(&[0u8; 4]).is_none());
    }

    // ── Provenance ──────────────────────────────────────────────────────
    // `Program data:` is `sol_log_data`, which any program can call, and the
    // sync sources transactions by ADDRESS REFERENCE — so a transaction that
    // merely names the vault among its account keys reaches this decoder.
    // Every test below forges an event that is byte-identical to a genuine one
    // and differs ONLY in which program emitted it.

    /// Build a `NoteCreated` log line for `leaf_index` with `commitment`.
    fn note_created_line(leaf_index: u64, commitment: [u8; 32]) -> String {
        let wire = NoteCreatedWire {
            tree_id: 0,
            leaf_index,
            commitment,
            token_mint: [0x9e; 32],
            amount: 1_000,
            new_root: fr_safe(0x33),
        };
        event_log_line(&NOTE_CREATED_DISCRIMINATOR, &borsh::to_vec(&wire).unwrap())
    }

    #[test]
    fn a_foreign_program_cannot_forge_a_leaf() {
        let genuine = fr_safe(0x42);
        let forged = fr_safe(0x66);
        // One transaction, two top-level instructions: the vault's real deposit
        // and the attacker's own program emitting an identical event.
        let mut logs = vault_tx(&[note_created_line(7, genuine)]);
        logs.extend(scoped(ATTACKER, 1, &[note_created_line(8, forged)]));

        let leaves = extract_appended_leaves(VAULT, &logs, None);
        assert_eq!(
            leaves,
            vec![AppendedLeaf {
                tree_id: 0,
                leaf_index: 7,
                value: genuine,
            }],
            "only the vault-scoped event may become a leaf"
        );
    }

    #[test]
    fn a_forged_event_alone_yields_no_leaf() {
        // The actual attack: no vault instruction at all, the vault merely named
        // in the account keys so the tx lands in its address history.
        let logs = scoped(ATTACKER, 1, &[note_created_line(0, fr_safe(0x66))]);
        assert!(
            extract_appended_leaves(VAULT, &logs, None).is_empty(),
            "a transaction that never invoked the vault appends nothing"
        );
    }

    #[test]
    fn a_cpi_callee_cannot_emit_a_vault_leaf() {
        // The vault is on the stack, but a program it CPI'd into is innermost —
        // that inner frame's events are not the vault's.
        let genuine = fr_safe(0x42);
        let mut inner = scoped(ATTACKER, 2, &[note_created_line(9, fr_safe(0x66))]);
        // ...and the vault emits its own event after the CPI returns.
        inner.push(note_created_line(7, genuine));
        let logs = vault_tx(&inner);

        let leaves = extract_appended_leaves(VAULT, &logs, None);
        assert_eq!(
            leaves,
            vec![AppendedLeaf {
                tree_id: 0,
                leaf_index: 7,
                value: genuine,
            }],
            "the CPI frame must close and hand scope back to the vault"
        );
    }

    #[test]
    fn the_vault_is_still_read_when_it_is_the_cpi_callee() {
        // Mirror of the case above: scope tracking must not be a "depth == 1"
        // shortcut. A vault frame nested under another program is still a vault
        // frame — a future relayer or router would produce exactly this shape.
        let genuine = fr_safe(0x42);
        let inner = scoped(VAULT, 2, &[note_created_line(7, genuine)]);
        let logs = scoped(ATTACKER, 1, &inner);
        assert_eq!(extract_appended_leaves(VAULT, &logs, None).len(), 1);
    }

    #[test]
    fn program_log_text_cannot_forge_a_scope_marker() {
        // `msg!` content is attacker-controlled. If the classifier matched the
        // invoke pattern before discarding `Program log:`, this would open a
        // vault frame from inside the attacker's own instruction.
        let logs = scoped(
            ATTACKER,
            1,
            &[
                format!("Program log: Program {VAULT} invoke [1]"),
                note_created_line(0, fr_safe(0x66)),
                format!("Program log: Program {VAULT} success"),
            ],
        );
        assert!(extract_appended_leaves(VAULT, &logs, None).is_empty());
    }

    #[test]
    fn an_unbracketed_event_is_not_trusted() {
        // Truncated or malformed logs leave no open frame. Fail closed: a
        // missing leaf is a recoverable sync gap, a wrong leaf is permanent.
        let logs = vec![note_created_line(0, fr_safe(0x42))];
        assert!(extract_appended_leaves(VAULT, &logs, None).is_empty());
    }

    #[test]
    fn a_failed_cpi_frame_still_closes() {
        // Exit lines come in three shapes; all must pop, or scope leaks into
        // the vault's remaining lines and swallows a genuine leaf.
        for exit in [
            format!("Program {ATTACKER} failed: custom program error: 0x1"),
            "Program failed to complete: exceeded CUs".to_string(),
            format!("Program {ATTACKER} success"),
        ] {
            let logs = vec![
                format!("Program {VAULT} invoke [1]"),
                format!("Program {ATTACKER} invoke [2]"),
                exit.clone(),
                note_created_line(7, fr_safe(0x42)),
                format!("Program {VAULT} success"),
            ];
            assert_eq!(
                extract_appended_leaves(VAULT, &logs, None).len(),
                1,
                "exit line {exit:?} must close the inner frame"
            );
        }
    }

    #[test]
    fn a_forged_trade_settled_needs_both_halves_and_gets_neither() {
        // The second path: the event supplies indices, the settle instruction
        // supplies values. Even handed a payload (as it would be if the ix
        // filter were missing), an attacker-scoped event yields nothing.
        let payload = sample_payload();
        let wire = TradeSettledWire {
            tree_id: 0,
            match_id: payload.match_id,
            note_c_leaf: 0,
            note_d_leaf: 1,
            note_e_leaf: NO_LEAF,
            note_f_leaf: NO_LEAF,
            note_fee_base_leaf: NO_LEAF,
            note_fee_quote_leaf: NO_LEAF,
            buyer_relock_active: false,
            seller_relock_active: false,
            new_root: fr_safe(0x55),
        };
        let line = event_log_line(&TRADE_SETTLED_DISCRIMINATOR, &borsh::to_vec(&wire).unwrap());
        let ix = build_settle_batched_ix(
            &solana_address::Address::new_from_array([0x42; 32]),
            0,
            &payload,
            0,
            &[[0x01; 32]; 4],
            &fr_safe(0xAB),
        );
        let logs = scoped(ATTACKER, 1, &[line]);
        assert!(extract_appended_leaves(VAULT, &logs, Some(&ix.data)).is_empty());
    }
}
