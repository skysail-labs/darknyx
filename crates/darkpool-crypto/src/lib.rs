//! Shared cryptographic primitives for the Darknyx dark pool.
//!
//! This crate is the single source of truth for Poseidon hashing over BN254, the
//! note commitment and nullifier formulas, note-use tags, deposit/merge/match inner
//! hashes, the four-key hierarchy, and the hierarchical viewing-key tree.
//!
//! # The byte-equality contract
//!
//! Every primitive that has a counterpart elsewhere must produce
//! **byte-identical** output in four places:
//!
//!   - this crate (the off-chain Rust prover and the vault's Rust tests),
//!   - the on-chain vault program, via the `sol_poseidon` syscall,
//!   - the circom/snarkjs proving pipeline, via circomlib's `poseidon.circom`,
//!   - the TypeScript SDK.
//!
//! **A mismatch can permanently lock funds**, because a note whose commitment two
//! environments disagree about cannot be proved spendable by its owner.
//!
//! That guarantee is not aspirational — it is pinned. Each such primitive has a
//! named parity test in `packages/sdk/tests/` that shells out to a matching
//! binary under `examples/` and asserts byte equality against the TypeScript
//! implementation (`CLAUDE.md` §7.1).
//!
//! **[`viewing_keys`] is the exception**: it is Rust-only, has no TypeScript
//! counterpart, and therefore no parity test. Changing a derivation there breaks
//! previously issued keys with nothing to catch it — see that module. **The `examples/` directory exists for that purpose**, which
//! is why `cargo build --examples -p darkpool-crypto` is part of the pre-PR gate:
//! without the binaries every one of those assertions silently skips, and
//! `REQUIRE_PARITY_HELPERS=1` turns that skip into a hard failure.
//!
//! So a change here is a change in two languages. Editing a formula on this side
//! alone fails the parity test; editing the TypeScript side alone fails on devnet
//! as `InvalidProof (6000)` instead.
//!
//! Values reaching Poseidon must also fit in BN254 Fr. Raw 32-byte inputs pass
//! through most of this crate without complaint and are rejected only at
//! `light-poseidon`, surfacing on-chain as `PoseidonFailed (6030)` — see
//! `CLAUDE.md` §7.2 and [`field`].

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
pub mod note_use;
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
    darknyx_shake_kdf_v1, derive_blinding_factor, derive_master_viewing_key, derive_note_secret,
    derive_spending_key, derive_trading_key_at_offset, KeyBundle, MasterSeed, MASTER_SEED_BYTES,
};
pub use match_config::{match_config_digest, DOMAIN_MATCH_CONFIG};
pub use match_output::{
    match_fee_inner_hash, match_output_inner_hash, DOMAIN_MATCH_FEE_INNER,
    DOMAIN_MATCH_OUTPUT_INNER,
};
pub use merge::{merge_output_inner_hash, DOMAIN_MERGE_INNER};
pub use note::{commitment_from_fields_v2, NoteCommitment, NOTE_COMMITMENT_BYTES};
pub use note_use::{note_use_tag, DOMAIN_NOTE_USE};
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
