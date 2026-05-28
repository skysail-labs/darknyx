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
use solana_keypair::Keypair;

/// The canonical derivation path. Mirrored byte-for-byte in
/// `packages/sdk/src/tee/attestation.ts` so client-side verifier
/// scripts know which key to check against
/// `vault_config.tee_pubkey`.
pub const SIGNER_PATH: &str = "nyx/ed25519-signer/v1";

/// Derived Ed25519 signing key + display-ready encodings.
///
/// One keypair, two type views: `key` for `canonical_payload_hash`
/// signing (settle pipeline payload auth); [`Self::solana_keypair`]
/// for Solana tx signing (the same key acts as `tee_authority` AND
/// the tx fee-payer for every settle-pipeline tx — see PR 4g.3 for
/// the walk-back rationale).
pub struct DerivedSigner {
    /// The full Ed25519 keypair. **Private**: never serialise,
    /// never log, never leave this struct's owning scope. Used to
    /// sign `canonical_payload_hash(payload)` for
    /// `tee_forced_settle_batched`.
    pub key: SigningKey,
    /// Base58 encoding of the public key. Matches the Solana
    /// wire format; this is what `vault_config.tee_pubkey` holds
    /// AND the address that needs to hold SOL on whichever cluster
    /// the TEE points at.
    pub pubkey_base58: String,
    /// Hex encoding of the same public key. Useful for the
    /// `report_data` binding when calling `get_quote(SHA-256(pubkey))`.
    pub pubkey_hex: String,
}

impl DerivedSigner {
    /// Construct a fresh Solana `Keypair` from the same 32-byte
    /// Ed25519 seed `self.key` was built from. Cheap (one Ed25519
    /// pubkey-derivation step); the caller takes ownership so it
    /// can be moved into a settle-stage worker without keeping a
    /// reference back to this struct.
    ///
    /// **Property**: the returned `Keypair::pubkey()` equals the
    /// pubkey in `self.pubkey_base58`. This is what makes the
    /// "TEE signer == Solana fee-payer == `vault_config.tee_pubkey`"
    /// unification work — one funded address satisfies every
    /// signer constraint in the settle pipeline.
    pub fn solana_keypair(&self) -> Keypair {
        // `SigningKey::to_bytes()` returns the 32-byte secret seed.
        // `Keypair::new_from_array` constructs the matching Solana
        // keypair byte-for-byte the same way `solders.Keypair.from_seed`
        // does in the Python tooling — so an airdrop to one is an
        // airdrop to both.
        Keypair::new_from_array(self.key.to_bytes())
    }
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
