//! Fixed-size protocol fee recovery record carried by MATCH_BATCH Tx B.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::CryptoError;

pub const FEE_RECOVERY_SLOTS: usize = 16;
pub const FEE_RECOVERY_PLAINTEXT_LEN: usize = FEE_RECOVERY_SLOTS * 16;
pub const FEE_RECOVERY_CIPHERTEXT_LEN: usize = FEE_RECOVERY_PLAINTEXT_LEN + 16;
pub const FEE_RECOVERY_VERSION: u8 = 1;

const KEY_INFO: &[u8] = b"darknyx/fee-recovery-aead/v1";
const NONCE_DOMAIN: &[u8] = b"darknyx/fee-recovery-nonce/v1";

fn key(epoch_key: &[u8; 32], epoch: u64) -> Result<[u8; 32], CryptoError> {
    let mut info = Vec::with_capacity(KEY_INFO.len() + 8);
    info.extend_from_slice(KEY_INFO);
    info.extend_from_slice(&epoch.to_be_bytes());
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, epoch_key)
        .expand(&info, &mut out)
        .map_err(|e| CryptoError::Hkdf(format!("fee recovery key: {e:?}")))?;
    Ok(out)
}

fn nonce(batch_root: &[u8; 32], epoch: u64) -> [u8; 24] {
    let mut h = Sha256::new();
    h.update(NONCE_DOMAIN);
    h.update(batch_root);
    h.update(epoch.to_be_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 24];
    out.copy_from_slice(&digest[..24]);
    out
}

fn aad(
    batch_root: &[u8; 32],
    market: &[u8; 32],
    base_mint: &[u8; 32],
    quote_mint: &[u8; 32],
    epoch: u64,
) -> [u8; 137] {
    let mut out = [0u8; 137];
    out[0] = FEE_RECOVERY_VERSION;
    out[1..33].copy_from_slice(batch_root);
    out[33..65].copy_from_slice(market);
    out[65..97].copy_from_slice(base_mint);
    out[97..129].copy_from_slice(quote_mint);
    out[129..137].copy_from_slice(&epoch.to_be_bytes());
    out
}

pub fn encode_fee_amounts(amounts: &[(u64, u64); FEE_RECOVERY_SLOTS]) -> [u8; 256] {
    let mut out = [0u8; FEE_RECOVERY_PLAINTEXT_LEN];
    for (index, (base, quote)) in amounts.iter().enumerate() {
        let offset = index * 16;
        out[offset..offset + 8].copy_from_slice(&base.to_le_bytes());
        out[offset + 8..offset + 16].copy_from_slice(&quote.to_le_bytes());
    }
    out
}

pub fn decode_fee_amounts(bytes: &[u8; 256]) -> [(u64, u64); FEE_RECOVERY_SLOTS] {
    let mut out = [(0u64, 0u64); FEE_RECOVERY_SLOTS];
    for (index, slot) in out.iter_mut().enumerate() {
        let offset = index * 16;
        slot.0 = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        slot.1 = u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
    }
    out
}

pub fn encrypt_fee_recovery(
    epoch_key: &[u8; 32],
    epoch: u64,
    batch_root: &[u8; 32],
    market: &[u8; 32],
    base_mint: &[u8; 32],
    quote_mint: &[u8; 32],
    amounts: &[(u64, u64); FEE_RECOVERY_SLOTS],
) -> Result<[u8; FEE_RECOVERY_CIPHERTEXT_LEN], CryptoError> {
    let cipher = XChaCha20Poly1305::new((&key(epoch_key, epoch)?).into());
    let plaintext = encode_fee_amounts(amounts);
    let associated = aad(batch_root, market, base_mint, quote_mint, epoch);
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce(batch_root, epoch)),
            Payload {
                msg: &plaintext,
                aad: &associated,
            },
        )
        .map_err(|e| CryptoError::Aead(format!("fee recovery encrypt: {e:?}")))?;
    encrypted
        .try_into()
        .map_err(|v: Vec<u8>| CryptoError::InvalidByteLength {
            expected: FEE_RECOVERY_CIPHERTEXT_LEN,
            got: v.len(),
        })
}

pub fn decrypt_fee_recovery(
    epoch_key: &[u8; 32],
    epoch: u64,
    batch_root: &[u8; 32],
    market: &[u8; 32],
    base_mint: &[u8; 32],
    quote_mint: &[u8; 32],
    ciphertext: &[u8; FEE_RECOVERY_CIPHERTEXT_LEN],
) -> Result<[(u64, u64); FEE_RECOVERY_SLOTS], CryptoError> {
    let cipher = XChaCha20Poly1305::new((&key(epoch_key, epoch)?).into());
    let associated = aad(batch_root, market, base_mint, quote_mint, epoch);
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce(batch_root, epoch)),
            Payload {
                msg: ciphertext,
                aad: &associated,
            },
        )
        .map_err(|e| CryptoError::Aead(format!("fee recovery decrypt: {e:?}")))?;
    let fixed: [u8; FEE_RECOVERY_PLAINTEXT_LEN] =
        plaintext
            .try_into()
            .map_err(|v: Vec<u8>| CryptoError::InvalidByteLength {
                expected: FEE_RECOVERY_PLAINTEXT_LEN,
                got: v.len(),
            })?;
    Ok(decode_fee_amounts(&fixed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_binding_fail_closed() {
        let mut amounts = [(0, 0); 16];
        amounts[0] = (7, 11);
        amounts[15] = (13, 17);
        let encrypted = encrypt_fee_recovery(
            &[1; 32], 4, &[2; 32], &[3; 32], &[4; 32], &[5; 32], &amounts,
        )
        .unwrap();
        assert_eq!(
            decrypt_fee_recovery(&[1; 32], 4, &[2; 32], &[3; 32], &[4; 32], &[5; 32], &encrypted)
                .unwrap(),
            amounts
        );
        assert!(decrypt_fee_recovery(
            &[1; 32], 5, &[2; 32], &[3; 32], &[4; 32], &[5; 32], &encrypted
        )
        .is_err());
        assert!(decrypt_fee_recovery(
            &[8; 32], 4, &[2; 32], &[3; 32], &[4; 32], &[5; 32], &encrypted
        )
        .is_err());
        assert!(decrypt_fee_recovery(
            &[1; 32], 4, &[9; 32], &[3; 32], &[4; 32], &[5; 32], &encrypted
        )
        .is_err());
        assert!(decrypt_fee_recovery(
            &[1; 32], 4, &[2; 32], &[9; 32], &[4; 32], &[5; 32], &encrypted
        )
        .is_err());
        assert!(decrypt_fee_recovery(
            &[1; 32], 4, &[2; 32], &[3; 32], &[9; 32], &[5; 32], &encrypted
        )
        .is_err());
        assert!(decrypt_fee_recovery(
            &[1; 32], 4, &[2; 32], &[3; 32], &[4; 32], &[9; 32], &encrypted
        )
        .is_err());
        let mut tampered = encrypted;
        tampered[17] ^= 1;
        assert!(decrypt_fee_recovery(
            &[1; 32], 4, &[2; 32], &[3; 32], &[4; 32], &[5; 32], &tampered
        )
        .is_err());
    }
}
