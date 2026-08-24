//! Asymmetric encryption of a fill side's trade + change amounts — the
//! permanent on-chain recovery backstop.
//!
//! This is the live recovery hierarchy; the former symmetric compliance-key
//! hierarchy is retired. The **TEE** encrypts each side's two `u64`
//! output amounts TO that side's X25519 viewing-encryption *public* key, so
//! only the holder of the matching secret — derived client-side from the master
//! seed (`deriveViewingEncKeypair` in the SDK) — can recover it. This survives a
//! CVM redeploy (the chain is permanent), curing the fund-stranding gap that the
//! amount-privacy revamp opened.
//!
//! One ephemeral key per **fill**, not per side (multi-recipient ECIES): a single
//! 32-byte ephemeral public goes on-chain, plus one 44-byte ciphertext blob per
//! side. On-chain cost = 32 + 2×44 = **120 bytes**.
//!
//! Scheme (per side):
//! ```text
//!   shared   = X25519(ephemeral_secret, recipient_pub)
//!   aead_key = HKDF-SHA256(ikm = shared,
//!                          info = "darknyx-fill-enc-v3" || eph_pub || recipient_pub)[:32]
//!   plaintext = trade_amount_le8 ‖ change_amount_le8
//!   blob      = nonce(12) ‖ ChaCha20Poly1305(aead_key, nonce).encrypt(plaintext)
//!             = 12 + 16 + 16 = 44 bytes
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
pub const FILL_ENC_INFO: &[u8] = b"darknyx-fill-enc-v3";

/// ChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 12;
/// Plaintext length — `trade_amount || change_amount`, both little-endian u64.
pub const AMOUNTS_LEN: usize = 16;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// One side's on-chain ciphertext blob: `nonce ‖ ct ‖ tag`.
pub const SIDE_BLOB_LEN: usize = NONCE_LEN + AMOUNTS_LEN + TAG_LEN; // 44

/// X25519 public-key / shared-secret length.
pub const X25519_LEN: usize = 32;

/// The private settlement amounts needed to reconstruct both outputs owned by
/// one side. Buyer semantics are `(trade_base, change_quote)`; seller semantics
/// are `(trade_quote, change_base)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FillAmounts {
    pub trade: u64,
    pub change: u64,
}

/// Return true only when `public_key` contributes to X25519 Diffie-Hellman.
/// RFC 7748 requires protocols to reject the all-zero shared secret; doing the
/// check at order intake prevents low-order points from turning the supposedly
/// owner-only recovery ciphertext into a public, attacker-chosen key stream.
pub fn is_contributory_x25519_public_key(public_key: &[u8; X25519_LEN]) -> bool {
    // Any fixed non-zero scalar is sufficient for the low-order test. X25519
    // clamps it internally; this value is not secret and never reused for data.
    let probe = StaticSecret::from([0x42; X25519_LEN]);
    let shared = probe.diffie_hellman(&PublicKey::from(*public_key));
    shared.as_bytes().iter().any(|byte| *byte != 0)
}

/// Compute the on-chain ephemeral public key for a given ephemeral secret.
///
/// The secret is generated once per fill; this public is shared across both
/// sides' ciphertexts.
pub fn ephemeral_public(ephemeral_secret: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
    let eph = StaticSecret::from(*ephemeral_secret);
    PublicKey::from(&eph).to_bytes()
}

/// Encrypt one side's trade + change amounts to `recipient_pub`.
///
/// `ephemeral_secret` is the fill's ephemeral X25519 secret (reused across both
/// sides), `nonce12` a unique 12-byte nonce. Both are caller-supplied randomness
/// (the function is pure + deterministic given its inputs, so it stays testable
/// with fixed vectors). Returns the 44-byte `nonce ‖ ct ‖ tag` blob.
pub fn encrypt_fill_amounts(
    ephemeral_secret: &[u8; X25519_LEN],
    recipient_pub: &[u8; X25519_LEN],
    amounts: FillAmounts,
    nonce12: &[u8; NONCE_LEN],
) -> Result<[u8; SIDE_BLOB_LEN], CryptoError> {
    if !is_contributory_x25519_public_key(recipient_pub) {
        return Err(CryptoError::Aead(
            "fill enc recipient is a non-contributory X25519 point".to_string(),
        ));
    }
    let eph = StaticSecret::from(*ephemeral_secret);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient_pub));

    let aead_key = derive_aead_key(shared.as_bytes(), eph_pub.as_bytes(), recipient_pub)?;
    let cipher = ChaCha20Poly1305::new(&aead_key.into());
    let mut plaintext = [0u8; AMOUNTS_LEN];
    plaintext[..8].copy_from_slice(&amounts.trade.to_le_bytes());
    plaintext[8..].copy_from_slice(&amounts.change.to_le_bytes());
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce12), &plaintext[..])
        .map_err(|e| CryptoError::Aead(format!("fill enc encrypt: {e:?}")))?;
    debug_assert_eq!(ct.len(), AMOUNTS_LEN + TAG_LEN);

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
pub fn decrypt_fill_amounts(
    viewing_secret: &[u8; X25519_LEN],
    ephemeral_pub: &[u8; X25519_LEN],
    blob: &[u8; SIDE_BLOB_LEN],
) -> Option<FillAmounts> {
    if !is_contributory_x25519_public_key(ephemeral_pub) {
        return None;
    }
    let secret = StaticSecret::from(*viewing_secret);
    let my_pub = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&PublicKey::from(*ephemeral_pub));

    let aead_key = derive_aead_key(shared.as_bytes(), ephemeral_pub, my_pub.as_bytes()).ok()?;
    let cipher = ChaCha20Poly1305::new(&aead_key.into());
    let pt = cipher
        .decrypt(Nonce::from_slice(&blob[..NONCE_LEN]), &blob[NONCE_LEN..])
        .ok()?;
    if pt.len() != AMOUNTS_LEN {
        return None;
    }
    let mut trade = [0u8; 8];
    trade.copy_from_slice(&pt[..8]);
    let mut change = [0u8; 8];
    change.copy_from_slice(&pt[8..]);
    Some(FillAmounts {
        trade: u64::from_le_bytes(trade),
        change: u64::from_le_bytes(change),
    })
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
    const AMOUNTS: FillAmounts = FillAmounts {
        trade: 1_234_567_890_123,
        change: 98_765_432_101,
    };

    fn recipient_pub() -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(RECIPIENT_SECRET)).to_bytes()
    }

    #[test]
    fn round_trip() {
        let blob = encrypt_fill_amounts(&EPH_SECRET, &recipient_pub(), AMOUNTS, &NONCE).unwrap();
        let eph_pub = ephemeral_public(&EPH_SECRET);
        let got = decrypt_fill_amounts(&RECIPIENT_SECRET, &eph_pub, &blob).unwrap();
        assert_eq!(got, AMOUNTS);
    }

    #[test]
    fn wrong_key_fails() {
        let blob = encrypt_fill_amounts(&EPH_SECRET, &recipient_pub(), AMOUNTS, &NONCE).unwrap();
        let eph_pub = ephemeral_public(&EPH_SECRET);
        let wrong = [0x09u8; 32];
        assert!(decrypt_fill_amounts(&wrong, &eph_pub, &blob).is_none());
    }

    #[test]
    fn tampered_blob_fails() {
        let mut blob =
            encrypt_fill_amounts(&EPH_SECRET, &recipient_pub(), AMOUNTS, &NONCE).unwrap();
        let eph_pub = ephemeral_public(&EPH_SECRET);
        blob[SIDE_BLOB_LEN - 1] ^= 0x01; // flip a tag byte
        assert!(decrypt_fill_amounts(&RECIPIENT_SECRET, &eph_pub, &blob).is_none());
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
        let amounts_a = FillAmounts {
            trade: 111,
            change: 11,
        };
        let amounts_b = FillAmounts {
            trade: 222,
            change: 22,
        };
        let blob_a = encrypt_fill_amounts(&EPH_SECRET, &alice_pub, amounts_a, &n1).unwrap();
        let blob_b = encrypt_fill_amounts(&EPH_SECRET, &bob_pub, amounts_b, &n2).unwrap();

        assert_eq!(
            decrypt_fill_amounts(&alice_secret, &eph_pub, &blob_a),
            Some(amounts_a)
        );
        assert_eq!(
            decrypt_fill_amounts(&bob_secret, &eph_pub, &blob_b),
            Some(amounts_b)
        );
        // Cross-decrypt must fail (wrong recipient binding).
        assert!(decrypt_fill_amounts(&alice_secret, &eph_pub, &blob_b).is_none());
        assert!(decrypt_fill_amounts(&bob_secret, &eph_pub, &blob_a).is_none());
    }

    #[test]
    fn fixed_vector_is_stable() {
        // If this fails after a deliberate scheme change, update the vector here
        // AND in packages/sdk/tests/fill-encryption.test.ts in lockstep.
        let eph_pub = ephemeral_public(&EPH_SECRET);
        let blob = encrypt_fill_amounts(&EPH_SECRET, &recipient_pub(), AMOUNTS, &NONCE).unwrap();
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
        "101112131415161718191a1b90b91ce896d093df943c6875cd06f2dd114d124486ffcedc672edf6cfb1b6bc3";

    #[test]
    fn rejects_low_order_x25519_points() {
        // The seven canonical/non-canonical low-order encodings blacklisted by
        // deployed X25519 implementations. Keep this list in byte parity with
        // the SDK KAT.
        let low_order = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ];
        for encoded in low_order {
            let point: [u8; 32] = hex::decode(encoded).unwrap().try_into().unwrap();
            assert!(
                !is_contributory_x25519_public_key(&point),
                "accepted low-order point {encoded}"
            );
        }
        assert!(is_contributory_x25519_public_key(&recipient_pub()));
        let zero = [0u8; 32];
        assert!(encrypt_fill_amounts(&EPH_SECRET, &zero, AMOUNTS, &NONCE).is_err());
        assert!(decrypt_fill_amounts(&RECIPIENT_SECRET, &zero, &[0; SIDE_BLOB_LEN]).is_none());
    }
}
