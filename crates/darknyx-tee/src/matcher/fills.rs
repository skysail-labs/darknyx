//! Fill memos — the per-fill record the CVM publishes to the client so
//! it can bind a change note to the exact consumed input, derive the
//! VALID_MATCH_BATCH v3 output inner locally, and store the verified note
//! for later withdrawal.
//!
//! Emitted by the matcher tick when it derives a non-zero change output,
//! broadcast over the `/v1/stream` `fills` channel. The memo is NOT secret
//! (it's the user's own fill
//! info; TLS-encrypted on the wire), and it carries nothing the TEE
//! could forge in a way that fools the client — the integrity check is
//! the client's guard against a misbehaving TEE (design-doc Vuln 4).

use serde::{Deserialize, Serialize};

/// A single non-zero change output plus the consumed input that determines it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FillMemo {
    /// The order that received the change note (16-byte id), hex.
    pub order_id: String,
    /// The exact input-note commitment consumed by this match, hex.
    pub consumed_note_commitment: String,
    /// Circuit role byte used by `Poseidon3(24, input_inner, role)`.
    pub output_role: u8,
    /// Amount of the change note (base units).
    pub change_amount: u64,
    /// 32-byte commitment of the change note, hex.
    pub change_note_commitment: String,
    /// 32-byte SPL mint of the change note, hex.
    pub mint: String,
    /// 32-byte `inner_hash` the change note was built with, hex. The client
    /// derives this from the stored consumed-input opening and `output_role`,
    /// then recomputes `change_note_commitment` byte-for-byte.
    pub inner_hash: String,
}

impl FillMemo {
    pub fn new(
        order_id: [u8; 16],
        consumed_note_commitment: [u8; 32],
        output_role: u8,
        change_amount: u64,
        change_note_commitment: [u8; 32],
        mint: [u8; 32],
        inner_hash: [u8; 32],
    ) -> Self {
        Self {
            order_id: hex::encode(order_id),
            consumed_note_commitment: hex::encode(consumed_note_commitment),
            output_role,
            change_amount,
            change_note_commitment: hex::encode(change_note_commitment),
            mint: hex::encode(mint),
            inner_hash: hex::encode(inner_hash),
        }
    }
}
