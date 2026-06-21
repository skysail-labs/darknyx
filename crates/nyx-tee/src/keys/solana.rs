//! Solana keypair helpers.
//!
//! **History**: PR 4g.2 introduced a separate fee-payer derivation
//! from a distinct dstack path (`"nyx/solana-fee-payer/v1"`). PR
//! 4g.3 walked that back when it became clear `lock_note` (and
//! every other settle-pipeline ix) requires `tee_authority` —
//! `vault_config.tee_pubkey` — as a signer. Having two separate
//! Solana addresses both needing devnet SOL doubled the operational
//! burden without any compromise-isolation benefit (both keys live
//! in the same TEE memory).
//!
//! The unified model: **one Ed25519 keypair** derived from
//! `"nyx/ed25519-signer/v1"` (see [`crate::keys::ed25519`]) acts as
//! all three roles:
//!
//!   - the TEE `canonical_payload_hash` signer
//!     (`MatchResultPayload` auth in `tee_forced_settle_batched`)
//!   - the on-chain `tee_authority` Signer in `lock_note` /
//!     `tee_forced_settle_batched` (the registered key check)
//!   - the Solana tx fee-payer (pays per-ix rent + tx fees)
//!
//! Conversion is via [`crate::keys::ed25519::DerivedSigner::solana_keypair`].
//! This module is intentionally near-empty — kept around as the
//! home for future Solana-specific key utilities (e.g. priority-fee
//! sub-accounts in 4g.5, if we end up needing them).
