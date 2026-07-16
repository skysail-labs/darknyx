//! Per-fill durable output recovery ciphertext (the TEE-side encryption at
//! settle).
//!
//! The amount-privacy revamp removed plaintext amounts from the settle ix, so a
//! fill's output amounts otherwise live only in the live `/v1/stream` memo.
//! This module builds the permanent on-chain backstop: for each match it
//! encrypts both of a side's output amounts to that side's X25519
//! viewing-encryption public key (supplied at order intake, carried on the
//! [`crate::matcher::openings::OrderOpening`]).
//! Buyer plaintext is `(trade_base, change_quote)` and seller plaintext is
//! `(trade_quote, change_base)`.
//!
//! One ephemeral key per fill (multi-recipient ECIES): a single ephemeral public
//! plus one 44-byte blob per side. The crypto lives in
//! [`darkpool_crypto::fill_encryption`]; this module only sources the per-fill
//! randomness and decides which sides get a ciphertext.
//!
//! The resulting [`FillCiphertext`] is carried TEE-internally on
//! `MatchSettleInputs`; B.5a writes it into the signed `MatchResultPayload` so
//! it lands on-chain. The all-zero value is the "no recovery ciphertext"
//! sentinel (no viewing key on either side) that the client / indexer skip.

use darkpool_crypto::fill_encryption::{
    encrypt_fill_amounts, ephemeral_public, FillAmounts, SIDE_BLOB_LEN,
};
use darkpool_crypto::CryptoError;
use rand::rngs::OsRng;
use rand::RngCore;

/// One match's recovery ciphertext: a shared ephemeral X25519 public plus one
/// per-side encrypted `(trade, change)` blob (`nonce ‖ ct ‖ tag`, 44 bytes). A
/// side with no viewing key carries a zeroed blob; the whole struct
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

/// Width of the on-chain recovery field. The 120-byte ECIES bundle
/// (`ephemeral_pubkey 32 + 2×44` side blobs) plus an 8-byte version trailer is
/// exactly 128 bytes. A single fixed field keeps the cross-port canonical-hash
/// lockstep to one entry and remains compatible with Anchor's fixed-array
/// serialization.
pub const RECOVERY_LEN: usize = 128;

/// Reject legacy or ambiguously-packed recovery bundles after the clean
/// devnet cutover. The all-zero sentinel intentionally carries no trailer.
pub const RECOVERY_V2_TRAILER: [u8; 8] = *b"NYXREC02";

impl FillCiphertext {
    /// True iff this carries no recovery ciphertext (the all-zero sentinel). A
    /// real ciphertext always has a non-zero ephemeral pubkey.
    pub fn is_empty(&self) -> bool {
        self.ephemeral_pubkey == [0u8; 32]
    }

    /// Pack into the on-chain `MatchResultPayload.fill_recovery` field:
    /// `ephemeral_pubkey(32) ‖ buyer_enc(44) ‖ seller_enc(44) ‖ "NYXREC02"`.
    /// The all-zero sentinel packs to all-zero.
    pub fn to_payload_bytes(&self) -> [u8; RECOVERY_LEN] {
        let mut out = [0u8; RECOVERY_LEN];
        out[0..32].copy_from_slice(&self.ephemeral_pubkey);
        out[32..32 + SIDE_BLOB_LEN].copy_from_slice(&self.buyer_enc);
        out[32 + SIDE_BLOB_LEN..32 + 2 * SIDE_BLOB_LEN].copy_from_slice(&self.seller_enc);
        if !self.is_empty() {
            out[RECOVERY_LEN - RECOVERY_V2_TRAILER.len()..].copy_from_slice(&RECOVERY_V2_TRAILER);
        }
        out
    }

    /// Inverse of [`Self::to_payload_bytes`] — used by the client / indexer to
    /// recover the ephemeral pubkey + each side's ciphertext from the on-chain
    /// field. A non-empty bundle with the wrong version trailer is rejected as
    /// the empty sentinel; callers must never try to interpret legacy v1 bytes
    /// using the v2 plaintext schema.
    pub fn from_payload_bytes(b: &[u8; RECOVERY_LEN]) -> Self {
        if b == &[0u8; RECOVERY_LEN]
            || b[RECOVERY_LEN - RECOVERY_V2_TRAILER.len()..] != RECOVERY_V2_TRAILER
        {
            return Self::default();
        }
        let mut ephemeral_pubkey = [0u8; 32];
        ephemeral_pubkey.copy_from_slice(&b[0..32]);
        let mut buyer_enc = [0u8; SIDE_BLOB_LEN];
        buyer_enc.copy_from_slice(&b[32..32 + SIDE_BLOB_LEN]);
        let mut seller_enc = [0u8; SIDE_BLOB_LEN];
        seller_enc.copy_from_slice(&b[32 + SIDE_BLOB_LEN..32 + 2 * SIDE_BLOB_LEN]);
        Self {
            ephemeral_pubkey,
            buyer_enc,
            seller_enc,
        }
    }
}

/// Build the recovery ciphertext for one match. Each side is encrypted when it
/// supplied a `viewing_pubkey`; otherwise that side's blob is zeroed. Returns
/// the all-zero sentinel iff NEITHER side supplies a viewing key. One
/// freshly-generated ephemeral X25519 key serves both
/// sides (multi-recipient ECIES); nonces are per-side fresh.
pub fn build_fill_ciphertext(
    buyer_viewing: Option<[u8; 32]>,
    seller_viewing: Option<[u8; 32]>,
    buyer_trade_amt: u64,
    buyer_change_amt: u64,
    seller_trade_amt: u64,
    seller_change_amt: u64,
) -> Result<FillCiphertext, CryptoError> {
    let buyer_recipient = buyer_viewing;
    let seller_recipient = seller_viewing;
    if buyer_recipient.is_none() && seller_recipient.is_none() {
        return Ok(FillCiphertext::default());
    }

    let mut rng = OsRng;
    let mut eph_secret = [0u8; 32];
    rng.fill_bytes(&mut eph_secret);
    let ephemeral_pubkey = ephemeral_public(&eph_secret);

    let buyer_enc = encrypt_side(
        &mut rng,
        &eph_secret,
        buyer_recipient,
        FillAmounts {
            trade: buyer_trade_amt,
            change: buyer_change_amt,
        },
    )?;
    let seller_enc = encrypt_side(
        &mut rng,
        &eph_secret,
        seller_recipient,
        FillAmounts {
            trade: seller_trade_amt,
            change: seller_change_amt,
        },
    )?;

    Ok(FillCiphertext {
        ephemeral_pubkey,
        buyer_enc,
        seller_enc,
    })
}

fn encrypt_side(
    rng: &mut OsRng,
    eph_secret: &[u8; 32],
    recipient: Option<[u8; 32]>,
    amounts: FillAmounts,
) -> Result<[u8; SIDE_BLOB_LEN], CryptoError> {
    match recipient {
        Some(pk) => {
            let mut nonce = [0u8; 12];
            rng.fill_bytes(&mut nonce);
            // A canonical wire order already passed the contributory-key check,
            // but fail the assembly rather than mint an unrecoverable output if
            // encryption ever fails internally.
            encrypt_fill_amounts(eph_secret, &pk, amounts, &nonce)
        }
        None => Ok([0u8; SIDE_BLOB_LEN]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use darkpool_crypto::fill_encryption::decrypt_fill_amounts;

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
        let ct =
            build_fill_ciphertext(Some(buyer_pk), Some(seller_pk), 1_000, 234, 5_000, 678).unwrap();

        assert!(!ct.is_empty());
        assert_eq!(
            decrypt_fill_amounts(&buyer_sk, &ct.ephemeral_pubkey, &ct.buyer_enc),
            Some(FillAmounts {
                trade: 1_000,
                change: 234,
            })
        );
        assert_eq!(
            decrypt_fill_amounts(&seller_sk, &ct.ephemeral_pubkey, &ct.seller_enc),
            Some(FillAmounts {
                trade: 5_000,
                change: 678,
            })
        );
        // Cross-decrypt fails (recipient binding in the HKDF info).
        assert!(decrypt_fill_amounts(&buyer_sk, &ct.ephemeral_pubkey, &ct.seller_enc).is_none());
    }

    #[test]
    fn one_side_only() {
        let (buyer_sk, buyer_pk) = keypair(0x11);
        // Seller has change but NO viewing key → zeroed seller blob; buyer
        // encrypts. Ephemeral pubkey is still generated.
        let ct = build_fill_ciphertext(Some(buyer_pk), None, 1_000, 234, 5_000, 678).unwrap();
        assert!(!ct.is_empty());
        assert_eq!(
            decrypt_fill_amounts(&buyer_sk, &ct.ephemeral_pubkey, &ct.buyer_enc),
            Some(FillAmounts {
                trade: 1_000,
                change: 234,
            })
        );
        assert_eq!(ct.seller_enc, [0u8; SIDE_BLOB_LEN]);
    }

    #[test]
    fn exact_fill_still_encrypts_trade_amounts() {
        let (_, buyer_pk) = keypair(0x11);
        let (buyer_sk, _) = keypair(0x11);
        let ct = build_fill_ciphertext(Some(buyer_pk), None, 123, 0, 456, 0).unwrap();
        assert!(!ct.is_empty());
        assert_eq!(
            decrypt_fill_amounts(&buyer_sk, &ct.ephemeral_pubkey, &ct.buyer_enc),
            Some(FillAmounts {
                trade: 123,
                change: 0,
            })
        );
    }

    #[test]
    fn no_viewing_key_means_no_ciphertext() {
        let ct = build_fill_ciphertext(None, None, 1_000, 234, 5_000, 678).unwrap();
        assert!(ct.is_empty());
    }

    #[test]
    fn invalid_viewing_key_fails_assembly_closed() {
        let err = build_fill_ciphertext(Some([0u8; 32]), None, 1_000, 234, 5_000, 678)
            .expect_err("a non-contributory recipient must not mint unrecoverable outputs");
        assert!(err.to_string().contains("non-contributory X25519"));
    }

    #[test]
    fn payload_bytes_round_trip() {
        let (_, buyer_pk) = keypair(0x11);
        let (_, seller_pk) = keypair(0x22);
        let ct =
            build_fill_ciphertext(Some(buyer_pk), Some(seller_pk), 1_000, 234, 5_000, 678).unwrap();
        let bytes = ct.to_payload_bytes();
        assert_eq!(bytes.len(), RECOVERY_LEN);
        assert_eq!(&bytes[120..], &RECOVERY_V2_TRAILER);
        assert_eq!(FillCiphertext::from_payload_bytes(&bytes), ct);
        // The empty sentinel packs to all-zero and round-trips.
        assert_eq!(
            FillCiphertext::default().to_payload_bytes(),
            [0u8; RECOVERY_LEN]
        );
        assert!(FillCiphertext::from_payload_bytes(&[0u8; RECOVERY_LEN]).is_empty());
        let mut legacy = bytes;
        legacy[120..].fill(0);
        assert!(FillCiphertext::from_payload_bytes(&legacy).is_empty());
    }
}
