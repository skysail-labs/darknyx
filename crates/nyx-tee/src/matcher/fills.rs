//! Fill memos — the per-fill record the CVM publishes to the client so
//! it can correlate which anchor was consumed, run the settle-memo
//! integrity check (recompute the change-note commitment from the
//! reported `inner_hash` + amount + owner and assert it matches), and
//! store the change note for later withdrawal.
//!
//! Emitted by the matcher tick when it assigns a continuation anchor to
//! a relocking side (Phase 6/7), broadcast over the `GET /ws/fills`
//! channel (Phase 7). The memo is NOT secret (it's the user's own fill
//! info; TLS-encrypted on the wire), and it carries nothing the TEE
//! could forge in a way that fools the client — the integrity check is
//! the client's guard against a misbehaving TEE (design-doc Vuln 4).

use serde::Serialize;

/// A single continuation fill: the change note minted for a relocking
/// side, plus the anchor it consumed.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct FillMemo {
    /// The order that partially filled (16-byte id), hex.
    pub order_id: String,
    /// Index into the order's anchor pool that was consumed for this
    /// fill's change note (0-based).
    pub anchor_index: u32,
    /// Amount of the change note (base units).
    pub change_amount: u64,
    /// 32-byte commitment of the change note, hex.
    pub change_note_commitment: String,
    /// 32-byte SPL mint of the change note, hex.
    pub mint: String,
    /// 32-byte `inner_hash` the change note was built with, hex. The
    /// client checks this equals its own deterministically-derived
    /// `inner_hash[anchor_index]` and that
    /// `Poseidon6(mint, change_amount, owner, inner_hash) ==
    /// change_note_commitment`.
    pub inner_hash: String,
}

impl FillMemo {
    pub fn new(
        order_id: [u8; 16],
        anchor_index: usize,
        change_amount: u64,
        change_note_commitment: [u8; 32],
        mint: [u8; 32],
        inner_hash: [u8; 32],
    ) -> Self {
        Self {
            order_id: hex::encode(order_id),
            anchor_index: anchor_index as u32,
            change_amount,
            change_note_commitment: hex::encode(change_note_commitment),
            mint: hex::encode(mint),
            inner_hash: hex::encode(inner_hash),
        }
    }
}
