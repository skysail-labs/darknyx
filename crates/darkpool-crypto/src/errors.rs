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
