//! Ed25519 signer derivation from a dstack-supplied seed.
//!
//! The single load-bearing constant in this module is the path
//! `"nyx/ed25519-signer/v1"`. **Bumping it triggers the full
//! multisig rotation ceremony** documented in
//! `docs/tee-attestation-flow.md` §5. Same seed → same signing
//! key, deterministically, for the lifetime of the compose-hash.

use anyhow::{Context, Result};
use dstack_sdk::dstack_client::DstackClient;
use ed25519_dalek::SigningKey;

/// The canonical derivation path. Mirrored byte-for-byte in
/// `packages/sdk/src/tee/attestation.ts` so client-side verifier
/// scripts know which key to check against
/// `vault_config.tee_pubkey`.
pub const SIGNER_PATH: &str = "nyx/ed25519-signer/v1";

/// Derived Ed25519 signing key + display-ready encodings.
#[allow(dead_code)] // `key` is consumed by the settle pipeline in PR 4c.
pub struct DerivedSigner {
    /// The full Ed25519 keypair. **Private**: never serialise,
    /// never log, never leave this struct's owning scope. The
    /// settle pipeline (PR 4c) will use `key.sign(canonical_hash)`
    /// per `MatchResultPayload`.
    pub key: SigningKey,
    /// Base58 encoding of the public key. Matches the Solana
    /// wire format; this is what `vault_config.tee_pubkey` holds.
    pub pubkey_base58: String,
    /// Hex encoding of the public key. Useful for the
    /// `report_data` binding when calling `get_quote(SHA-256(pubkey))`.
    pub pubkey_hex: String,
}

/// Derive the signer from dstack's KDF.
///
/// Stages:
///   1. Call `dstack.get_key("nyx/ed25519-signer/v1")` — returns
///      hex-encoded 32-byte seed material.
///   2. `decode_key()` to bytes; assert length == 32.
///   3. Construct `SigningKey::from_bytes(&seed)`. The same 32-byte
///      seed is what Python's `solders.Keypair.from_seed(...)` uses
///      (which is what we validated end-to-end against a real
///      Phala Cloud CVM in the Phase-1 smoke test), so the Solana
///      pubkey produced here is byte-identical to that path.
pub async fn derive(client: &DstackClient) -> Result<DerivedSigner> {
    let resp = client
        .get_key(Some(SIGNER_PATH.to_string()), None)
        .await
        .with_context(|| format!("dstack.get_key('{}') failed", SIGNER_PATH))?;

    let seed_bytes = resp
        .decode_key()
        .with_context(|| "dstack.get_key returned undecodable key material")?;
    let seed_array: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .context("dstack.get_key returned non-32-byte material")?;

    let key = SigningKey::from_bytes(&seed_array);
    let pubkey_bytes = key.verifying_key().to_bytes();

    Ok(DerivedSigner {
        key,
        pubkey_base58: bs58::encode(pubkey_bytes).into_string(),
        pubkey_hex: hex::encode(pubkey_bytes),
    })
}
