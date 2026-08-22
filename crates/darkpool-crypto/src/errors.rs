//! The crate's error type.
//!
//! Most variants mark a violated precondition of the BN254 field or a fixed-width
//! encoding — [`CryptoError::NotInField`] and [`CryptoError::InvalidByteLength`]
//! are the two a caller hits most, and both mean the input was never valid to
//! hash rather than that hashing failed. Returning them early is what keeps an
//! out-of-field value from reaching `light-poseidon`, where it would surface
//! on-chain as `PoseidonFailed (6030)` instead. See `CLAUDE.md` §7.2.

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
