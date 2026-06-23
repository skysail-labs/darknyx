//! Per-fill change-amount recovery ciphertext (change-amount recovery,
//! Proposal B, B.3 — the TEE-side encryption at settle).
//!
//! The amount-privacy revamp removed plaintext amounts from the settle ix, so a
//! fill's `change_amount` lives only in the live `/ws/fills` memo + the P7 TTL
//! log — both wiped on a CVM redeploy, after which the on-chain change note is
//! visible-but-unspendable. This module builds the permanent on-chain backstop:
//! for each match it encrypts each side's `change_amount` to that side's X25519
//! viewing-encryption public key (supplied at order intake, carried on the
//! [`crate::matcher::openings::OrderOpening`]).
//!
//! One ephemeral key per fill (multi-recipient ECIES): a single ephemeral public
//! plus one 36-byte blob per side. The crypto lives in
//! [`darkpool_crypto::fill_encryption`]; this module only sources the per-fill
//! randomness and decides which sides get a ciphertext.
//!
//! The resulting [`FillCiphertext`] is carried TEE-internally on
//! `MatchSettleInputs`; B.5a writes it into the signed `MatchResultPayload` so
//! it lands on-chain. The all-zero value is the "no recovery ciphertext"
//! sentinel (exact fill on both sides, or no viewing key) that B.5a / the
//! client / the indexer skip.

use darkpool_crypto::fill_encryption::{encrypt_change_amount, ephemeral_public, SIDE_BLOB_LEN};
use rand::rngs::OsRng;
use rand::RngCore;

/// One match's recovery ciphertext: a shared ephemeral X25519 public plus one
/// per-side encrypted `change_amount` blob (`nonce ‖ ct ‖ tag`, 36 bytes). A
/// side with no change or no viewing key carries a zeroed blob; the whole struct
/// is all-zero when neither side has a ciphertext (see [`FillCiphertext::is_empty`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillCiphertext {
    pub ephemeral_pubkey: [u8; 32],
    pub buyer_enc: [u8; SIDE_BLOB_LEN],
    pub seller_enc: [u8; SIDE_BLOB_LEN],
}

impl Default for FillCiphertext {
    fn default() -> Self {
        Self {
            ephemeral_pubkey: [0u8; 32],
            buyer_enc: [0u8; SIDE_BLOB_LEN],
            seller_enc: [0u8; SIDE_BLOB_LEN],
        }
    }
}

impl FillCiphertext {
    /// True iff this carries no recovery ciphertext (the all-zero sentinel). A
    /// real ciphertext always has a non-zero ephemeral pubkey.
    pub fn is_empty(&self) -> bool {
        self.ephemeral_pubkey == [0u8; 32]
    }
}

/// Build the recovery ciphertext for one match. Each side is encrypted only when
/// it BOTH has a change note (`change_amt > 0`) AND supplied a `viewing_pubkey`;
/// otherwise that side's blob is zeroed. Returns the all-zero sentinel iff
/// NEITHER side qualifies (so an exact fill, or a no-viewing-key client, adds
/// nothing on-chain). One freshly-generated ephemeral X25519 key serves both
/// sides (multi-recipient ECIES); nonces are per-side fresh.
pub fn build_fill_ciphertext(
    buyer_viewing: Option<[u8; 32]>,
    seller_viewing: Option<[u8; 32]>,
    buyer_change_amt: u64,
    seller_change_amt: u64,
) -> FillCiphertext {
    let buyer_recipient = buyer_viewing.filter(|_| buyer_change_amt > 0);
    let seller_recipient = seller_viewing.filter(|_| seller_change_amt > 0);
    if buyer_recipient.is_none() && seller_recipient.is_none() {
        return FillCiphertext::default();
    }

    let mut rng = OsRng;
    let mut eph_secret = [0u8; 32];
    rng.fill_bytes(&mut eph_secret);
    let ephemeral_pubkey = ephemeral_public(&eph_secret);

    let buyer_enc = encrypt_side(&mut rng, &eph_secret, buyer_recipient, buyer_change_amt);
    let seller_enc = encrypt_side(&mut rng, &eph_secret, seller_recipient, seller_change_amt);

    FillCiphertext {
        ephemeral_pubkey,
        buyer_enc,
        seller_enc,
    }
}

fn encrypt_side(
    rng: &mut OsRng,
    eph_secret: &[u8; 32],
    recipient: Option<[u8; 32]>,
    amount: u64,
) -> [u8; SIDE_BLOB_LEN] {
    match recipient {
        Some(pk) => {
            let mut nonce = [0u8; 12];
            rng.fill_bytes(&mut nonce);
            // `encrypt_change_amount` can only fail on an internal AEAD error,
            // never for a valid 8-byte plaintext — fall back to the zero
            // sentinel rather than abort the whole settle if it ever does.
            encrypt_change_amount(eph_secret, &pk, amount, &nonce).unwrap_or([0u8; SIDE_BLOB_LEN])
        }
        None => [0u8; SIDE_BLOB_LEN],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use darkpool_crypto::fill_encryption::decrypt_change_amount;

    // A deterministic X25519 keypair from a seed byte. The public key is the
    // X25519 base-mult of the secret — `ephemeral_public` computes exactly that
    // (so we don't need a direct x25519-dalek dep here).
    fn keypair(tag: u8) -> ([u8; 32], [u8; 32]) {
        let secret = [tag; 32];
        (secret, ephemeral_public(&secret))
    }

    #[test]
    fn both_sides_encrypt_and_decrypt() {
        let (buyer_sk, buyer_pk) = keypair(0x11);
        let (seller_sk, seller_pk) = keypair(0x22);
        let ct = build_fill_ciphertext(Some(buyer_pk), Some(seller_pk), 1234, 5678);

        assert!(!ct.is_empty());
        assert_eq!(
            decrypt_change_amount(&buyer_sk, &ct.ephemeral_pubkey, &ct.buyer_enc),
            Some(1234)
        );
        assert_eq!(
            decrypt_change_amount(&seller_sk, &ct.ephemeral_pubkey, &ct.seller_enc),
            Some(5678)
        );
        // Cross-decrypt fails (recipient binding in the HKDF info).
        assert!(decrypt_change_amount(&buyer_sk, &ct.ephemeral_pubkey, &ct.seller_enc).is_none());
    }

    #[test]
    fn one_side_only() {
        let (buyer_sk, buyer_pk) = keypair(0x11);
        // Seller has change but NO viewing key → zeroed seller blob; buyer
        // encrypts. Ephemeral pubkey is still generated.
        let ct = build_fill_ciphertext(Some(buyer_pk), None, 1234, 5678);
        assert!(!ct.is_empty());
        assert_eq!(
            decrypt_change_amount(&buyer_sk, &ct.ephemeral_pubkey, &ct.buyer_enc),
            Some(1234)
        );
        assert_eq!(ct.seller_enc, [0u8; SIDE_BLOB_LEN]);
    }

    #[test]
    fn no_change_means_no_ciphertext() {
        let (_, buyer_pk) = keypair(0x11);
        // Viewing key present but the side took an exact fill (change 0).
        let ct = build_fill_ciphertext(Some(buyer_pk), Some([0x22; 32]), 0, 0);
        assert!(ct.is_empty());
        assert_eq!(ct, FillCiphertext::default());
    }

    #[test]
    fn no_viewing_key_means_no_ciphertext() {
        let ct = build_fill_ciphertext(None, None, 1234, 5678);
        assert!(ct.is_empty());
    }
}
