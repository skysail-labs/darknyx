//! The crate's error type.
//!
//! [`CryptoError::NotInField`] and [`CryptoError::InvalidByteLength`] are direct
//! input-validation errors: both mean the value was never valid to hash, rather
//! than that hashing failed. Returning them early is what keeps an out-of-field
//! value from reaching `light-poseidon`, where it would surface on-chain as
//! `PoseidonFailed (6030)` instead. See `CLAUDE.md` §7.2.
//!
//! The remaining variants report a failure inside a specific primitive —
//! Poseidon, HKDF, AEAD, seed parsing, amount range, or merge-input shape.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("input not in BN254 scalar field")]
    NotInField,

    #[error("invalid byte length: expected {expected}, got {got}")]
    InvalidByteLength { expected: usize, got: usize },

    #[error("poseidon hash error: {0}")]
    Poseidon(String),

    #[error("HKDF expand error: {0}")]
    Hkdf(String),

    #[error("invalid master seed")]
    InvalidMasterSeed,

    #[error("amount too large to fit in field element")]
    AmountOverflow,

    #[error("AEAD error: {0}")]
    Aead(String),

    #[error("invalid merge commitment slots or active bitmap")]
    InvalidMergeInput,
}
