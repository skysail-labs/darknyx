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

use darkpool_crypto::poseidon_hash_bytes;

/// All inputs the circuit needs for ONE match slot. Counts: 6 note
/// commitments + 2 mints + 8 amount-like fields + 1 slot + 17
/// private witnesses. The TS `proveMatchBatch` builds a record of
/// 30 named arrays from these.
#[derive(Clone, Debug, Default)]
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

    // ── VALID_CREATE private witnesses ──
    pub a_owner_commit: [u8; 32],
    pub b_owner_commit: [u8; 32],
    pub a_amount: u64,
    pub b_amount: u64,
    // v2: one inner_hash per note (replaces the old nonce+blinding pair).
    // inner_hashes are full BN254 Fr elements (32-byte BE), NOT u64: the
    // trade/change/fee output-note inner_hashes come from
    // `change_note::derive_inner` (a masked SHA-256, up to ~2^252) and the
    // input-note inner_hashes come from the user's anchor/opening — neither
    // fits in a u64. Feeding a truncated value would make the circuit
    // reconstruct a different note commitment, so the proof would fail.
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
}

/// Build a fully-valid all-zero "dummy" slot. Used to pad a batch
/// up to `N` when the matcher produced fewer than `N` real matches.
///
/// Mirrors `dummySlot()` in `match-batch-prover.ts`. The dummy
/// note commitment is `Poseidon6(2, 0, 0, 0, 0, 0)` — the value
/// every v2 Poseidon6 note opening collapses to with all-zero inputs.
/// Two dummy slots in the same batch produce identical leaves; the
/// Merkle root still uniquely commits to the real matches.
pub fn dummy_slot() -> MatchSlotWitness {
    let mut domain = [0u8; 32];
    domain[31] = 2; // BE-encoded Fr(2)
    let zero = [0u8; 32];
    let dummy_note = poseidon_hash_bytes(&[domain, zero, zero, zero, zero, zero])
        .expect("Poseidon6 over (tag=2, five zeros) cannot fail");
    let zero32 = [0u8; 32];

    MatchSlotWitness {
        note_a_commitment: dummy_note,
        note_b_commitment: dummy_note,
        note_c_commitment: dummy_note,
        note_d_commitment: dummy_note,
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
        out.push(dummy.clone());
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
        // All four "input" notes share the same dummy hash.
        assert_eq!(a.note_a_commitment, a.note_b_commitment);
        assert_eq!(a.note_a_commitment, a.note_c_commitment);
        assert_eq!(a.note_a_commitment, a.note_d_commitment);
        // Change notes stay zero.
        assert_eq!(a.note_e_commitment, [0u8; 32]);
        assert_eq!(a.note_f_commitment, [0u8; 32]);
    }

    #[test]
    fn dummy_slot_note_commitment_is_nonzero() {
        // Poseidon(2, 0, 0, 0, 0, 0, 0) is a non-zero field element
        // — if this ever produces all-zero, the dummy padding would
        // accidentally collide with an "unused" sentinel in the
        // on-chain handler. Pin the assertion so a future Poseidon
        // refactor surfaces here.
        let d = dummy_slot();
        assert_ne!(d.note_a_commitment, [0u8; 32]);
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
        // The padding slots are dummy notes — non-zero, identical.
        for i in 1..4 {
            assert_eq!(padded[i].note_a_commitment, padded[1].note_a_commitment);
            assert_ne!(padded[i].note_a_commitment, [0u8; 32]);
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
