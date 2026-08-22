//! Solana keypair helpers.
//!
//! **One Ed25519 keypair, derived from `"darknyx/ed25519-signer/v2"` (see
//! [`crate::keys::ed25519`]), fills all three roles:**
//!
//!   - the TEE `canonical_payload_hash` signer, authenticating
//!     `MatchResultPayload` in `tee_forced_settle_batched`;
//!   - the on-chain `tee_authority` signer in `lock_note` and
//!     `tee_forced_settle_batched`, checked against `vault_config.tee_pubkeys`;
//!   - the Solana transaction fee-payer, paying per-instruction rent and tx fees.
//!
//! Deriving a separate fee-payer from its own dstack path is possible but was
//! rejected: every settle-pipeline instruction already requires `tee_authority` as
//! a signer, so a second address would need funding and monitoring in parallel
//! while offering no compromise isolation — both keys would live in the same
//! enclave memory anyway.
//!
//! Conversion is [`crate::keys::ed25519::DerivedSigner::solana_keypair`]. This
//! module is deliberately near-empty; it is the home for Solana-specific key
//! utilities should any be needed.
