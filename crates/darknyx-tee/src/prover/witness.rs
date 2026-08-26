//! Per-match witness inputs for the VALID_MATCH_BATCH circuit.
//!
//! Mirror of `MatchSlotWitness` in
//! `packages/sdk/tests/helpers/match-batch-prover.ts`. Field names
//! match the circuit's signal names (snake_case here, camelCase in
//! TS) so cross-environment debugging is straightforward.
//!
//! Type choices:
//!   - `[u8; 32]` for anything that's a Poseidon output (already
//!     Fr-safe by construction) or a note `inner_hash` (the derived
//!     output-note inner_hashes are full Fr elements, not u64 — see
//!     the `*_inner` fields).
//!   - `u64` for amounts / slot indices — they always fit in Fr.
//!   - 32-byte pubkeys live as `[u8; 32]` and are split into
//!     `(lo, hi)` Fr-pair at hashing time via
//!     `darkpool_crypto::pubkey_to_fr_pair`.

/// All inputs the circuit needs for ONE match slot. Counts: 6 note
/// commitments + 2 mints + 8 amount-like fields + 1 slot + 17
/// private witnesses. The TS `proveMatchBatch` builds a record of
/// 30 named arrays from these.
// Deliberately no `Debug`: a witness contains user note openings and the
// protocol fee epoch key. Formatting it into a log or panic report is a secret
// disclosure, even though the proof and public inputs are safe to format.
#[derive(Clone, Default)]
pub struct MatchSlotWitness {
    // ── VALID_CREATE-equivalent public fields ──
    pub note_a_commitment: [u8; 32],
    pub note_b_commitment: [u8; 32],
    pub note_c_commitment: [u8; 32],
    pub note_d_commitment: [u8; 32],
    /// All-zero when there's no buyer change. The TS dummy fills
    /// these as zero32 — same convention here.
    pub note_e_commitment: [u8; 32],
    /// All-zero when there's no seller change.
    pub note_f_commitment: [u8; 32],

    pub quote_mint: [u8; 32],
    pub base_mint: [u8; 32],

    pub base_amount: u64,
    pub quote_amount: u64,
    pub buyer_change_amt: u64,
    pub seller_change_amt: u64,
    pub buyer_fee_amt: u64,
    pub seller_fee_amt: u64,

    // ── VALID_PRICE-equivalent public fields ──
    pub batch_slot: u64,
    /// Private activation bit. Real matches are true; canonical padding is
    /// false and cannot be settled because Tx D recomputes an active leaf.
    pub is_active: bool,

    // ── VALID_CREATE private witnesses ──
    pub a_owner_commit: [u8; 32],
    pub b_owner_commit: [u8; 32],
    pub a_amount: u64,
    pub b_amount: u64,
    // v2: one inner_hash per note (replaces the old nonce+blinding pair).
    // inner_hashes are full BN254 Fr elements (32-byte BE), NOT u64: the
    // output-note inner_hashes are derived in-circuit from these two consumed
    // input inners. The canonical output values below are retained for recovery
    // and parity assertions but are NOT circuit witness signals.
    pub a_inner: [u8; 32],
    pub b_inner: [u8; 32],
    pub c_inner: [u8; 32],
    pub d_inner: [u8; 32],
    /// Only meaningful when `buyer_change_amt != 0`.
    pub e_inner: [u8; 32],
    /// Only meaningful when `seller_change_amt != 0`.
    pub f_inner: [u8; 32],

    // ── VALID_PRICE private witness ──
    pub clearing_price: u64,
    pub price_remainder: u64,

    // ── Per-match protocol fee notes ──
    /// Base-mint fee note commitment (seller fees). `[0;32]` when no fee.
    pub note_fee_base_commitment: [u8; 32],
    /// Quote-mint fee note commitment (buyer fees). `[0;32]` when no fee.
    pub note_fee_quote_commitment: [u8; 32],

    // ── Batch-level fields (same across every slot in a batch) ──
    /// Protocol fee rate (bps), a MatchBatch-level config-digest preimage bound
    /// on-chain to `VaultConfig.fee_rate_bps`. Stored per-slot for convenience;
    /// the prover reads it from `slots[0]` and pushes one circuit input.
    pub fee_rate_bps: u64,
    /// Protocol fee-note owner, bound through the MatchBatch config digest to
    /// `VaultConfig.protocol_owner_commitment`. Read from `slots[0]`.
    pub protocol_owner_commitment: [u8; 32],
    pub fee_epoch_key: [u8; 32],
    pub fee_key_binding: [u8; 32],
    pub fee_key_epoch: u64,
    /// Governed fixed-point denominator in the MatchBatch config preimage.
    pub price_scale: u64,
    /// Canonical derived fee inners retained for recovery/parity. The circuit
    /// derives them itself from note_a/note_b commitments.
    pub fee_base_inner: [u8; 32],
    pub fee_quote_inner: [u8; 32],
}

impl std::fmt::Debug for MatchSlotWitness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MatchSlotWitness")
            .field("contents", &"[REDACTED: contains private witnesses]")
            .finish()
    }
}

/// Build a canonical inactive all-zero slot. Used to pad a batch
/// up to `N` when the matcher produced fewer than `N` real matches.
///
/// Mirrors `dummySlot()` in `match-batch-prover.ts`. The dummy
/// The v3 circuit gates note-opening constraints with `is_active` and requires
/// every leaf-visible commitment in an inactive slot to be zero.
pub fn dummy_slot() -> MatchSlotWitness {
    let zero32 = [0u8; 32];
    // Even an all-padding batch must satisfy the batch-level fee-key binding.
    // The private epoch key is zero in this synthetic fixture, but its public
    // binding is still Poseidon2(DOMAIN_FEE_KEY_BINDING, 0), not zero.
    let fee_key_binding =
        darkpool_crypto::fee_key_binding(&zero32).expect("zero is a canonical fee epoch key");

    MatchSlotWitness {
        note_a_commitment: zero32,
        note_b_commitment: zero32,
        note_c_commitment: zero32,
        note_d_commitment: zero32,
        note_e_commitment: zero32,
        note_f_commitment: zero32,
        quote_mint: zero32,
        base_mint: zero32,
        base_amount: 0,
        quote_amount: 0,
        buyer_change_amt: 0,
        seller_change_amt: 0,
        buyer_fee_amt: 0,
        seller_fee_amt: 0,
        batch_slot: 0,
        is_active: false,
        a_owner_commit: zero32,
        b_owner_commit: zero32,
        a_amount: 0,
        b_amount: 0,
        a_inner: zero32,
        b_inner: zero32,
        c_inner: zero32,
        d_inner: zero32,
        e_inner: zero32,
        f_inner: zero32,
        clearing_price: 0,
        price_remainder: 0,
        note_fee_base_commitment: zero32,
        note_fee_quote_commitment: zero32,
        fee_rate_bps: 0,
        protocol_owner_commitment: zero32,
        fee_epoch_key: zero32,
        fee_key_binding,
        fee_key_epoch: 0,
        price_scale: 1,
        fee_base_inner: zero32,
        fee_quote_inner: zero32,
    }
}

/// Pad `real_slots` up to exactly `n` entries using
/// [`dummy_slot`]. Returns an error if `real_slots.len() > n`
/// (the caller violated the batch capacity); returns the input
/// unchanged when already at capacity.
///
/// Mirrors `padBatch` in the TS helper. Production `n` is 16
/// (the on-chain wired circuit instantiation); 2 and 4 exist as
/// fast unit-test instances.
pub fn pad_batch(
    real_slots: &[MatchSlotWitness],
    n: usize,
) -> Result<Vec<MatchSlotWitness>, PadError> {
    if real_slots.len() > n {
        return Err(PadError::TooMany {
            got: real_slots.len(),
            cap: n,
        });
    }
    let mut out = Vec::with_capacity(n);
    out.extend_from_slice(real_slots);
    let dummy = dummy_slot();
    while out.len() < n {
        let mut d = dummy.clone();
        // C-08: VALID_MATCH_BATCH now binds `batch_slot === slot index`, so each
        // pad slot must carry its position (real slots already carry their
        // scheduler-assigned index). Distinct pad batch_slots mean pad leaves are
        // no longer identical, but only the real match's leaf is checked on-chain.
        d.batch_slot = out.len() as u64;
        out.push(d);
    }
    Ok(out)
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum PadError {
    #[error("batch has {got} slots but capacity is {cap}")]
    TooMany { got: usize, cap: usize },
}

/// Convert `u64` → 32-byte BE Fr encoding. Used in leaf-hash
/// construction so the bytes line up the same way the TS
/// `BigInt(n).toString()` → snarkjs path lays them out.
#[inline]
pub(crate) fn u64_to_be32(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

/// Single-byte tag → 32-byte BE Fr encoding (1 trailing byte, 31
/// leading zeros). Used for the circuit's domain-separation tags.
#[inline]
pub(crate) fn u8_tag_to_be32(tag: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = tag;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_slot_note_commitment_is_deterministic() {
        let a = dummy_slot();
        let b = dummy_slot();
        assert_eq!(a.note_a_commitment, b.note_a_commitment);
        // All commitments in canonical inactive padding are zero.
        assert_eq!(a.note_a_commitment, a.note_b_commitment);
        assert_eq!(a.note_a_commitment, a.note_c_commitment);
        assert_eq!(a.note_a_commitment, a.note_d_commitment);
        // Change notes stay zero.
        assert_eq!(a.note_e_commitment, [0u8; 32]);
        assert_eq!(a.note_f_commitment, [0u8; 32]);
    }

    #[test]
    fn dummy_slot_is_inactive() {
        let d = dummy_slot();
        assert!(!d.is_active);
        assert_eq!(d.note_a_commitment, [0u8; 32]);
    }

    #[test]
    fn debug_output_redacts_private_witnesses_and_fee_key() {
        let mut witness = dummy_slot();
        witness.a_inner = [0x91; 32];
        witness.fee_epoch_key = [0x92; 32];
        let rendered = format!("{witness:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains(&hex::encode(witness.a_inner)));
        assert!(!rendered.contains(&hex::encode(witness.fee_epoch_key)));
    }

    #[test]
    fn pad_batch_fills_with_dummies() {
        let real = vec![MatchSlotWitness {
            base_amount: 42,
            ..MatchSlotWitness::default()
        }];
        let padded = pad_batch(&real, 4).unwrap();
        assert_eq!(padded.len(), 4);
        // The first slot is the real one.
        assert_eq!(padded[0].base_amount, 42);
        // The padding slots are canonical inactive zeros.
        for i in 1..4 {
            assert_eq!(padded[i].note_a_commitment, padded[1].note_a_commitment);
            assert_eq!(padded[i].note_a_commitment, [0u8; 32]);
            assert!(!padded[i].is_active);
            assert_eq!(padded[i].base_amount, 0);
        }
    }

    #[test]
    fn pad_batch_full_is_noop() {
        let dummy = dummy_slot();
        let real = vec![dummy.clone(); 2];
        let padded = pad_batch(&real, 2).unwrap();
        assert_eq!(padded.len(), 2);
    }

    #[test]
    fn pad_batch_too_many_errors() {
        let real = vec![dummy_slot(); 5];
        let err = pad_batch(&real, 4).unwrap_err();
        assert_eq!(err, PadError::TooMany { got: 5, cap: 4 });
    }

    #[test]
    fn u64_to_be32_matches_manual() {
        let v: u64 = 0x1122334455667788;
        let got = u64_to_be32(v);
        let expected = [
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16 leading zeros
            0, 0, 0, 0, 0, 0, 0, 0, // next 8 zeros (high half of Fr layout)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn u8_tag_to_be32_pads_left() {
        let t = u8_tag_to_be32(20);
        let mut want = [0u8; 32];
        want[31] = 20;
        assert_eq!(t, want);
    }

    #[test]
    fn u64_to_be32_zero_is_zero() {
        assert_eq!(u64_to_be32(0), [0u8; 32]);
    }

    #[test]
    fn u64_to_be32_one_is_trailing_one() {
        let one = u64_to_be32(1);
        let mut want = [0u8; 32];
        want[31] = 1;
        assert_eq!(one, want);
    }
}
