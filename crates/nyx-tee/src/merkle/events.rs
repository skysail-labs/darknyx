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
/// ix data layout: `disc(8) || tree_id(1) || Borsh(payload, 480) ||
/// match_index(1) || 4×32 siblings` (see
/// `settle_batched::build_settle_batched_ix`). Post-sharding the payload
/// starts at offset 9 (disc + the 1-byte `tree_id`).
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

/// Extract every leaf appended by one transaction.
///
/// `logs` are the transaction's `meta.logMessages`; `settle_ix_data` is
/// the data of the `tee_forced_settle_batched` instruction in that same
/// transaction (if any), needed to recover settle leaf values. The
/// caller sorts the combined results across all transactions by
/// `leaf_index` before applying to the mirror.
///
/// A `TradeSettled` event with no decodable settle payload yields no
/// settle leaves (logged by the caller) rather than guessing — a
/// mismatch would corrupt the mirror root.
pub fn extract_appended_leaves(
    logs: &[String],
    settle_ix_data: Option<&[u8]>,
) -> Vec<AppendedLeaf> {
    let settle_payload = settle_ix_data.and_then(decode_settle_payload);
    let mut out = Vec::new();

    for line in logs {
        let Some(b64) = line.strip_prefix("Program data: ") else {
            continue;
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
            note_a_commitment: fr_safe(0xA1),
            note_b_commitment: fr_safe(0xB1),
            note_c_commitment: fr_safe(0xC1),
            note_d_commitment: fr_safe(0xD1),
            note_e_commitment: fr_safe(0xE1),
            note_f_commitment: fr_safe(0xF1),
            nullifier_a: fr_safe(0xEA),
            nullifier_b: fr_safe(0xEB),
            order_id_a: [0x01; 16],
            order_id_b: [0x02; 16],
            base_amount: 100,
            quote_amount: 5_000,
            buyer_change_amt: 1,
            seller_change_amt: 1,
            buyer_fee_amt: 0,
            seller_fee_amt: 0,
            note_fee_base_commitment: fr_safe(0x1B),
            note_fee_quote_commitment: fr_safe(0x1C),
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
            clearing_price: 50,
            batch_slot: 7,
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
        let leaves = extract_appended_leaves(&[line], None);
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
        let leaves = extract_appended_leaves(&[line], None);
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

        let leaves = extract_appended_leaves(&[line], Some(&ix.data));
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
        let leaves = extract_appended_leaves(&[line], Some(&ix.data));
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
        assert!(extract_appended_leaves(&[line], None).is_empty());
    }

    #[test]
    fn ignores_non_event_log_lines() {
        let logs = vec![
            "Program log: instruction: Deposit".to_string(),
            "Program 11111111111111111111111111111111 invoke [1]".to_string(),
            "Program data: !!!not-base64!!!".to_string(),
        ];
        assert!(extract_appended_leaves(&logs, None).is_empty());
    }

    #[test]
    fn decode_settle_payload_rejects_wrong_discriminator() {
        let mut data = vec![0u8; 8 + MatchResultPayload::WIRE_LEN];
        data[..8].copy_from_slice(b"badbaddd");
        assert!(decode_settle_payload(&data).is_none());
        // Too short.
        assert!(decode_settle_payload(&[0u8; 4]).is_none());
    }
}
