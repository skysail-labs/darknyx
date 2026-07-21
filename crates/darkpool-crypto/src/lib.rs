//! Shared cryptographic primitives for the Darknyx dark pool.
//!
//! This crate is the single source of truth for:
//! - Poseidon hashing over BN254 (note commitments, nullifiers, owner commitments)
//! - Note/UTXO structure + commitment formula
//! - Nullifier derivation
//! - Blinding factor derivation (DarknyxShakeKdfV1)
//! - Four-key hierarchy derivation (HKDF + DarknyxShakeKdfV1)
//! - Hierarchical viewing key tree (MVK -> PairVK -> MonthlyVK)
//!
//! All functions MUST produce byte-identical output in:
//! - the off-chain Rust prover (ark-groth16)
//! - the off-chain Rust vault tests (this crate's tests)
//! - the on-chain vault program (via `sol_poseidon` syscall)
//! - the circom/snarkjs proving pipeline (via circomlib's poseidon.circom)
//!
//! If any cross-env byte mismatch occurs, funds can be permanently locked.

#![allow(clippy::too_many_arguments)]

pub mod deposit;
pub mod errors;
pub mod field;
#[cfg(not(target_os = "solana"))]
pub mod fill_encryption;
#[cfg(not(target_os = "solana"))]
pub mod keys;
pub mod match_config;
pub mod match_output;
pub mod merge;
pub mod note;
pub mod nullifier;
pub mod poseidon;
pub mod price_commitment;
#[cfg(not(target_os = "solana"))]
pub mod user_commitment;
#[cfg(not(target_os = "solana"))]
pub mod viewing_keys;

pub use deposit::{deposit_inner_hash, DOMAIN_DEPOSIT_INNER};
pub use errors::CryptoError;
pub use field::{fr_from_be_bytes, fr_to_be_bytes, pubkey_to_fr_pair, Fr, FR_BYTES};
#[cfg(not(target_os = "solana"))]
pub use fill_encryption::{
    decrypt_fill_amounts, encrypt_fill_amounts, ephemeral_public,
    is_contributory_x25519_public_key, FillAmounts, SIDE_BLOB_LEN,
};
#[cfg(not(target_os = "solana"))]
pub use keys::{
    darknyx_shake_kdf_v1, derive_blinding_factor, derive_master_viewing_key, derive_spending_key,
    derive_trading_key_at_offset, KeyBundle, MasterSeed, MASTER_SEED_BYTES,
};
pub use match_config::{match_config_digest, DOMAIN_MATCH_CONFIG};
pub use match_output::{
    match_fee_inner_hash, match_output_inner_hash, DOMAIN_MATCH_FEE_INNER,
    DOMAIN_MATCH_OUTPUT_INNER,
};
pub use merge::{merge_output_inner_hash, DOMAIN_MERGE_INNER};
pub use note::{commitment_from_fields_v2, NoteCommitment, NOTE_COMMITMENT_BYTES};
pub use nullifier::{nullifier_v2, Nullifier, NULLIFIER_BYTES};
pub use poseidon::{poseidon_hash, poseidon_hash_bytes};
pub use price_commitment::price_commitment;
#[cfg(not(target_os = "solana"))]
pub use user_commitment::{user_commitment_from_keys, UserCommitmentInputs};
#[cfg(not(target_os = "solana"))]
pub use viewing_keys::{
    derive_monthly_viewing_key, derive_scope_aead_key, derive_viewing_key_for_pair,
    scope_aead_decrypt, scope_aead_encrypt,
};
