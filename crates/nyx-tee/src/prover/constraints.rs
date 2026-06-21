//! Conservation-constraint validators.
//!
//! Rust port of the three sanity checks the TS prover runs before
//! invoking snarkjs:
//!
//! ```ts
//! quote_amount === base_amount * clearing_price
//! a_amount     === quote_amount + buyer_change_amt + buyer_fee_amt
//! b_amount     === base_amount  + seller_change_amt + seller_fee_amt
//! ```
//!
//! The constraints are ALREADY enforced by the circom circuit. Why
//! re-check them off-circuit:
//!
//!   - Witnesses that violate them silently fail at `snarkjs.prove`
//!     with a low-level constraint-system error. Surfacing the
//!     three named violations here gives operators a useful log
//!     instead of "R1CS constraint #N failed".
//!   - Same shape as the TS path — easier debugging when a slot
//!     mismatches across environments.
//!
//! Internally everything is u64 + saturating arithmetic so an
//! overflow surfaces as a constraint violation rather than a panic.

use super::witness::MatchSlotWitness;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ConstraintError {
    /// `quote_amount != base_amount * clearing_price`. Either the
    /// matcher emitted an inconsistent slot or an overflow happened
    /// in `base_amount * clearing_price`.
    #[error(
        "slot {slot_idx}: quote (got {got}) != base ({base}) * price ({price}) (expected {expected})"
    )]
    Quote {
        slot_idx: usize,
        base: u64,
        price: u64,
        got: u64,
        expected: u128,
    },
    /// `a_amount != quote + buyer_change + buyer_fee`.
    #[error(
        "slot {slot_idx}: a_amount ({a}) != quote ({quote}) + buyer_change ({change}) + buyer_fee ({fee}) (expected {expected})"
    )]
    AAmount {
        slot_idx: usize,
        a: u64,
        quote: u64,
        change: u64,
        fee: u64,
        expected: u128,
    },
    /// `b_amount != base + seller_change + seller_fee`.
    #[error(
        "slot {slot_idx}: b_amount ({b}) != base ({base}) + seller_change ({change}) + seller_fee ({fee}) (expected {expected})"
    )]
    BAmount {
        slot_idx: usize,
        b: u64,
        base: u64,
        change: u64,
        fee: u64,
        expected: u128,
    },
}

/// Validate every slot in the batch. Returns `Ok(())` if all three
/// constraints hold for every slot; returns the FIRST violation
/// otherwise (matching the TS `.forEach` short-circuit semantics).
pub fn validate_conservation(slots: &[MatchSlotWitness]) -> Result<(), ConstraintError> {
    for (i, s) in slots.iter().enumerate() {
        // Use u128 for the math so overflow surfaces as a violation
        // rather than wrapping silently.
        let expected_quote = (s.base_amount as u128) * (s.clearing_price as u128);
        if (s.quote_amount as u128) != expected_quote {
            return Err(ConstraintError::Quote {
                slot_idx: i,
                base: s.base_amount,
                price: s.clearing_price,
                got: s.quote_amount,
                expected: expected_quote,
            });
        }
        let expected_a =
            (s.quote_amount as u128) + (s.buyer_change_amt as u128) + (s.buyer_fee_amt as u128);
        if (s.a_amount as u128) != expected_a {
            return Err(ConstraintError::AAmount {
                slot_idx: i,
                a: s.a_amount,
                quote: s.quote_amount,
                change: s.buyer_change_amt,
                fee: s.buyer_fee_amt,
                expected: expected_a,
            });
        }
        let expected_b =
            (s.base_amount as u128) + (s.seller_change_amt as u128) + (s.seller_fee_amt as u128);
        if (s.b_amount as u128) != expected_b {
            return Err(ConstraintError::BAmount {
                slot_idx: i,
                b: s.b_amount,
                base: s.base_amount,
                change: s.seller_change_amt,
                fee: s.seller_fee_amt,
                expected: expected_b,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::witness::{dummy_slot, MatchSlotWitness};

    fn valid_slot() -> MatchSlotWitness {
        // base=10, price=20, quote=200; a=quote+0+0=200, b=base+0+0=10.
        MatchSlotWitness {
            base_amount: 10,
            clearing_price: 20,
            quote_amount: 200,
            a_amount: 200,
            b_amount: 10,
            ..MatchSlotWitness::default()
        }
    }

    #[test]
    fn dummy_slot_satisfies_constraints() {
        // All zeros: 0 == 0*0; 0 == 0+0+0; 0 == 0+0+0.
        let d = dummy_slot();
        validate_conservation(&[d]).unwrap();
    }

    #[test]
    fn valid_real_slot_passes() {
        validate_conservation(&[valid_slot()]).unwrap();
    }

    #[test]
    fn quote_mismatch_fails_with_slot_index() {
        let mut s = valid_slot();
        s.quote_amount = 201;
        let err = validate_conservation(&[dummy_slot(), s]).unwrap_err();
        assert!(matches!(err, ConstraintError::Quote { slot_idx: 1, .. }));
    }

    #[test]
    fn a_amount_mismatch_fails() {
        let mut s = valid_slot();
        s.a_amount = 201;
        let err = validate_conservation(&[s]).unwrap_err();
        assert!(matches!(err, ConstraintError::AAmount { slot_idx: 0, .. }));
    }

    #[test]
    fn b_amount_mismatch_fails() {
        let mut s = valid_slot();
        s.b_amount = 9;
        let err = validate_conservation(&[s]).unwrap_err();
        assert!(matches!(err, ConstraintError::BAmount { slot_idx: 0, .. }));
    }

    #[test]
    fn change_and_fee_make_a_amount_higher() {
        // a = quote + buyer_change + buyer_fee
        let mut s = valid_slot();
        s.buyer_change_amt = 7;
        s.buyer_fee_amt = 3;
        s.a_amount = 210;
        validate_conservation(&[s]).unwrap();
    }

    #[test]
    fn overflow_surfaces_as_quote_violation() {
        // base = u64::MAX, price = 2 → expected_quote = 2 *
        // u64::MAX = doesn't fit in u64. quote_amount can't equal
        // u128 expected, so we get a Quote violation rather than
        // a panic.
        let mut s = valid_slot();
        s.base_amount = u64::MAX;
        s.clearing_price = 2;
        s.quote_amount = 0;
        let err = validate_conservation(&[s]).unwrap_err();
        assert!(matches!(err, ConstraintError::Quote { .. }));
    }

    #[test]
    fn empty_batch_is_trivially_ok() {
        validate_conservation(&[]).unwrap();
    }

    #[test]
    fn first_failure_short_circuits() {
        // Slots: [valid, broken-quote, broken-a]. The Quote
        // violation in slot 1 should fire before the AAmount
        // violation in slot 2 is even checked.
        let mut bad_quote = valid_slot();
        bad_quote.quote_amount = 999;
        let mut bad_a = valid_slot();
        bad_a.a_amount = 999;
        let err = validate_conservation(&[valid_slot(), bad_quote, bad_a]).unwrap_err();
        match err {
            ConstraintError::Quote { slot_idx, .. } => assert_eq!(slot_idx, 1),
            other => panic!("expected Quote violation, got {other:?}"),
        }
    }
}
