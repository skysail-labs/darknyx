//! Asymmetric encryption of a fill's `change_amount` — the permanent on-chain
//! recovery backstop (change-amount recovery, Proposal B).
//!
//! Distinct from [`crate::viewing_keys`] (the symmetric compliance hierarchy
//! MVK→PairVK→MonthlyVK). Here the **TEE** encrypts each side's 8-byte
//! `change_amount` TO that side's X25519 viewing-encryption *public* key, so
//! only the holder of the matching secret — derived client-side from the master
//! seed (`deriveViewingEncKeypair` in the SDK) — can recover it. This survives a
//! CVM redeploy (the chain is permanent), curing the fund-stranding gap that the
//! amount-privacy revamp opened.
//!
//! One ephemeral key per **fill**, not per side (multi-recipient ECIES): a single
//! 32-byte ephemeral public goes on-chain, plus one 36-byte ciphertext blob per
//! side. On-chain cost = 32 + 2×36 = **104 bytes**.
//!
//! Scheme (per side):
//! ```text
//!   shared   = X25519(ephemeral_secret, recipient_pub)
//!   aead_key = HKDF-SHA256(ikm = shared,
//!                          info = "nyx-fill-enc-v1" || eph_pub || recipient_pub)[:32]
//!   blob     = nonce(12) ‖ ChaCha20Poly1305(aead_key, nonce).encrypt(amount_le8)
//!            = 12 + 8 + 16 = 36 bytes
//! ```
//!
//! Binding the ephemeral + recipient pubkeys into the HKDF `info` hardens against
//! key-reuse / unknown-key-share. The ciphertext is **self-verifying** at the
//! client (the decrypted amount must recompute the on-chain `note_e/f` commitment),
//! so this layer needs no settle-ix authentication of its own.
//!
//! There is no cross-language *key-derivation* parity contract: the TEE only ever
//! *consumes* the client's public key, it never re-derives it. The *encryption*
//! construction, however, must agree byte-for-byte with the SDK decryptor — pinned
//! by the fixed vector in the tests below (mirrored in
//! `packages/sdk/tests/fill-encryption.test.ts`).

use crate::errors::CryptoError;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// HKDF `info` label domain-separating the per-fill AEAD key.
pub const FILL_ENC_INFO: &[u8] = b"nyx-fill-enc-v1";

/// ChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 12;
/// Plaintext length — the `change_amount` as a little-endian `u64`.
pub const AMOUNT_LEN: usize = 8;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// One side's on-chain ciphertext blob: `nonce ‖ ct ‖ tag`.
pub const SIDE_BLOB_LEN: usize = NONCE_LEN + AMOUNT_LEN + TAG_LEN; // 36

/// X25519 public-key / shared-secret length.
pub const X25519_LEN: usize = 32;

/// Compute the on-chain ephemeral public key for a given ephemeral secret.
///
/// The secret is generated once per fill; this public is shared across both
/// sides' ciphertexts.
pub fn ephemeral_public(ephemeral_secret: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
    let eph = StaticSecret::from(*ephemeral_secret);
    PublicKey::from(&eph).to_bytes()
}

/// Encrypt one side's `change_amount` to `recipient_pub`.
///
/// `ephemeral_secret` is the fill's ephemeral X25519 secret (reused across both
/// sides), `nonce12` a unique 12-byte nonce. Both are caller-supplied randomness
/// (the function is pure + deterministic given its inputs, so it stays testable
/// with fixed vectors). Returns the 36-byte `nonce ‖ ct ‖ tag` blob.
pub fn encrypt_change_amount(
    ephemeral_secret: &[u8; X25519_LEN],
    recipient_pub: &[u8; X25519_LEN],
    amount: u64,
    nonce12: &[u8; NONCE_LEN],
) -> Result<[u8; SIDE_BLOB_LEN], CryptoError> {
    let eph = StaticSecret::from(*ephemeral_secret);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient_pub));

    let aead_key = derive_aead_key(shared.as_bytes(), eph_pub.as_bytes(), recipient_pub)?;
    let cipher = ChaCha20Poly1305::new(&aead_key.into());
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce12), &amount.to_le_bytes()[..])
        .map_err(|e| CryptoError::Aead(format!("fill enc encrypt: {e:?}")))?;
    debug_assert_eq!(ct.len(), AMOUNT_LEN + TAG_LEN);

    let mut blob = [0u8; SIDE_BLOB_LEN];
    blob[..NONCE_LEN].copy_from_slice(nonce12);
    blob[NONCE_LEN..].copy_from_slice(&ct);
    Ok(blob)
}

/// Decrypt one side's blob with the recipient's viewing-encryption secret.
///
/// Returns `None` on any failure (wrong key, tampered ciphertext, malformed
/// plaintext) — the canonical "this key cannot read this blob" signal. The
/// recipient's own public key (bound into the HKDF `info`) is recomputed from
/// the secret, so the caller need not pass it.
pub fn decrypt_change_amount(
    viewing_secret: &[u8; X25519_LEN],
    ephemeral_pub: &[u8; X25519_LEN],
    blob: &[u8; SIDE_BLOB_LEN],
) -> Option<u64> {
    let secret = StaticSecret::from(*viewing_secret);
    let my_pub = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&PublicKey::from(*ephemeral_pub));

    let aead_key = derive_aead_key(shared.as_bytes(), ephemeral_pub, my_pub.as_bytes()).ok()?;
    let cipher = ChaCha20Poly1305::new(&aead_key.into());
    let pt = cipher
        .decrypt(Nonce::from_slice(&blob[..NONCE_LEN]), &blob[NONCE_LEN..])
        .ok()?;
    if pt.len() != AMOUNT_LEN {
        return None;
    }
    let mut amt = [0u8; AMOUNT_LEN];
    amt.copy_from_slice(&pt);
    Some(u64::from_le_bytes(amt))
}

/// HKDF-SHA256 → 32-byte ChaCha20-Poly1305 key, binding both pubkeys into `info`.
fn derive_aead_key(
    shared: &[u8],
    eph_pub: &[u8; X25519_LEN],
    recipient_pub: &[u8; X25519_LEN],
) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut info = Vec::with_capacity(FILL_ENC_INFO.len() + 2 * X25519_LEN);
    info.extend_from_slice(FILL_ENC_INFO);
    info.extend_from_slice(eph_pub);
    info.extend_from_slice(recipient_pub);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|e| CryptoError::Hkdf(format!("fill enc aead key: {e:?}")))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Cross-language fixed vector -------------------------------------
    // Pins the encryption construction against the SDK decryptor
    // (`packages/sdk/tests/fill-encryption.test.ts`). The TS test recomputes
    // EPH_PUB from EPH_SECRET (proving X25519 base-point mult agrees across
    // x25519-dalek and tweetnacl) and decrypts BLOB_HEX back to AMOUNT.
    const RECIPIENT_SECRET: [u8; 32] = [0x02; 32];
    const EPH_SECRET: [u8; 32] = [0x07; 32];
    const NONCE: [u8; 12] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    ];
    const AMOUNT: u64 = 1_234_567_890_123;

    fn recipient_pub() -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(RECIPIENT_SECRET)).to_bytes()
    }

    #[test]
    fn round_trip() {
        let blob = encrypt_change_amount(&EPH_SECRET, &recipient_pub(), AMOUNT, &NONCE).unwrap();
        let eph_pub = ephemeral_public(&EPH_SECRET);
        let got = decrypt_change_amount(&RECIPIENT_SECRET, &eph_pub, &blob).unwrap();
        assert_eq!(got, AMOUNT);
    }

    #[test]
    fn wrong_key_fails() {
        let blob = encrypt_change_amount(&EPH_SECRET, &recipient_pub(), AMOUNT, &NONCE).unwrap();
        let eph_pub = ephemeral_public(&EPH_SECRET);
        let wrong = [0x09u8; 32];
        assert!(decrypt_change_amount(&wrong, &eph_pub, &blob).is_none());
    }

    #[test]
    fn tampered_blob_fails() {
        let mut blob =
            encrypt_change_amount(&EPH_SECRET, &recipient_pub(), AMOUNT, &NONCE).unwrap();
        let eph_pub = ephemeral_public(&EPH_SECRET);
        blob[SIDE_BLOB_LEN - 1] ^= 0x01; // flip a tag byte
        assert!(decrypt_change_amount(&RECIPIENT_SECRET, &eph_pub, &blob).is_none());
    }

    #[test]
    fn one_ephemeral_serves_both_sides() {
        // The multi-recipient property: a single ephemeral secret encrypts to
        // two distinct recipients; each decrypts only its own blob.
        let alice_secret = [0x21u8; 32];
        let bob_secret = [0x22u8; 32];
        let alice_pub = PublicKey::from(&StaticSecret::from(alice_secret)).to_bytes();
        let bob_pub = PublicKey::from(&StaticSecret::from(bob_secret)).to_bytes();

        let eph_pub = ephemeral_public(&EPH_SECRET);
        let n1 = [1u8; 12];
        let n2 = [2u8; 12];
        let blob_a = encrypt_change_amount(&EPH_SECRET, &alice_pub, 111, &n1).unwrap();
        let blob_b = encrypt_change_amount(&EPH_SECRET, &bob_pub, 222, &n2).unwrap();

        assert_eq!(
            decrypt_change_amount(&alice_secret, &eph_pub, &blob_a),
            Some(111)
        );
        assert_eq!(
            decrypt_change_amount(&bob_secret, &eph_pub, &blob_b),
            Some(222)
        );
        // Cross-decrypt must fail (wrong recipient binding).
        assert!(decrypt_change_amount(&alice_secret, &eph_pub, &blob_b).is_none());
        assert!(decrypt_change_amount(&bob_secret, &eph_pub, &blob_a).is_none());
    }

    #[test]
    fn fixed_vector_is_stable() {
        // If this fails after a deliberate scheme change, update the vector here
        // AND in packages/sdk/tests/fill-encryption.test.ts in lockstep.
        let eph_pub = ephemeral_public(&EPH_SECRET);
        let blob = encrypt_change_amount(&EPH_SECRET, &recipient_pub(), AMOUNT, &NONCE).unwrap();
        // Print so the TS vector can be regenerated with `--nocapture`.
        println!("FILL_ENC eph_pub   = {}", hex::encode(eph_pub));
        println!("FILL_ENC recip_pub = {}", hex::encode(recipient_pub()));
        println!("FILL_ENC blob      = {}", hex::encode(blob));
        assert_eq!(hex::encode(eph_pub), EXPECTED_EPH_PUB_HEX);
        assert_eq!(hex::encode(blob), EXPECTED_BLOB_HEX);
    }

    // Filled in after the first `--nocapture` run (see below).
    const EXPECTED_EPH_PUB_HEX: &str =
        "13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d";
    const EXPECTED_BLOB_HEX: &str =
        "101112131415161718191a1bf38cd2533492baadb9e66ce516a13d47fca255f1f877cb1e";
}
