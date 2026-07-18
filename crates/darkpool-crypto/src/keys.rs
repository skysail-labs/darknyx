//! Four-key hierarchy derivation.
//!
//! Reference: Sections 4.2, 20.2, 23.2 of darkpool_protocol_spec_v3_changed.md
//!
//! The four keys are:
//!
//! 1. **Root / Vault Key**     — Ed25519 (Solana native). Cold wallet.
//! 2. **Trading Key**          — Ed25519 (Solana native). Hot wallet. Offset-rotatable.
//! 3. **Shielded Spending Key**— BN254 scalar. Cold / HSM.
//! 4. **Master Viewing Key**   — BN254 scalar (derived from DarknyxShakeKdfV1). Compliance.
//!
//! Derivation contracts (must match the on-chain `create_wallet` verifier):
//!
//! ```text
//! spending_key   = reduce_mod_r( HKDF-SHA256(master_seed, b"darkpool_spend_key_v1", 512) )
//! viewing_key    = reduce_mod_r( DarknyxShakeKdfV1(master_seed, b"darkpool_viewing_key_v1", 512) )
//! trading_key(n) = Ed25519::from_seed( HKDF-SHA256(master_seed,
//!                    b"darkpool_trading_key_v1" || offset_u64_le, 32) )
//! root_key       = Ed25519::from_seed( HKDF-SHA256(master_seed,
//!                    b"darkpool_root_key_v1", 32) )
//!                  [used only when user does not bring their own Solana wallet]
//! ```
//!
//! Blinding factor derivation (versioned Darknyx SHAKE KDF):
//!
//! ```text
//! blinding_r(i) = reduce_mod_r( DarknyxShakeKdfV1(master_seed, b"note_blinding_v1" || i_u64_le, 512) )
//! ```
//!
//! All KDF outputs are 512 bits (64 bytes) to make the reduction mod r statistically
//! uniform (bias < 2^-256).

use crate::errors::CryptoError;
use crate::field::{fr_from_uniform_bytes, Fr};
use ed25519_dalek::{SecretKey, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Size of the master seed. 64 bytes = 512 bits gives far more security margin
/// than necessary (128 bits is enough), but matches common wallet-seed entropy.
pub const MASTER_SEED_BYTES: usize = 64;

/// HKDF salt constants for each derived key. Include a `_v1` suffix so we can
/// migrate in the future without breaking existing wallets.
const INFO_SPENDING: &[u8] = b"darkpool_spend_key_v1";
const INFO_VIEWING: &[u8] = b"darkpool_viewing_key_v1";
const INFO_TRADING: &[u8] = b"darkpool_trading_key_v1";
const INFO_ROOT: &[u8] = b"darkpool_root_key_v1";
const INFO_BLINDING: &[u8] = b"note_blinding_v1";

/// The raw master seed (64 bytes, cryptographically random or wallet-derived).
#[derive(Clone)]
pub struct MasterSeed(pub [u8; MASTER_SEED_BYTES]);

impl MasterSeed {
    pub fn new(bytes: [u8; MASTER_SEED_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        let mut b = [0u8; MASTER_SEED_BYTES];
        rng.fill_bytes(&mut b);
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; MASTER_SEED_BYTES] {
        &self.0
    }
}

impl std::fmt::Debug for MasterSeed {
    // Never log the seed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSeed(<redacted>)")
    }
}

// Manual `Zeroize` so we don't pull the full zeroize crate.
trait Zeroize {
    fn zeroize(&mut self);
}
impl Zeroize for [u8; MASTER_SEED_BYTES] {
    fn zeroize(&mut self) {
        for b in self.iter_mut() {
            *b = 0;
        }
    }
}
impl Zeroize for MasterSeed {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for MasterSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Convenience: derive all four keys from a master seed in one call.
pub struct KeyBundle {
    pub spending_key: Fr,
    pub viewing_key: Fr,
    pub trading_key: SigningKey,
    pub root_key: SigningKey,
}

impl KeyBundle {
    pub fn derive(seed: &MasterSeed, trading_offset: u64) -> Result<Self, CryptoError> {
        Ok(Self {
            spending_key: derive_spending_key(seed)?,
            viewing_key: derive_master_viewing_key(seed)?,
            trading_key: derive_trading_key_at_offset(seed, trading_offset)?,
            root_key: derive_root_key(seed)?,
        })
    }
}

/// Derive the BN254-scalar Shielded Spending Key.
pub fn derive_spending_key(seed: &MasterSeed) -> Result<Fr, CryptoError> {
    let bytes = hkdf_expand_64(seed.as_bytes(), INFO_SPENDING)?;
    Ok(fr_from_uniform_bytes(&bytes))
}

/// Derive the BN254-scalar Master Viewing Key via DarknyxShakeKdfV1.
pub fn derive_master_viewing_key(seed: &MasterSeed) -> Result<Fr, CryptoError> {
    let bytes = darknyx_shake_kdf_v1(seed.as_bytes(), INFO_VIEWING, &[], 64);
    Ok(fr_from_uniform_bytes(&bytes))
}

/// Derive an Ed25519 Trading Key at a given rotation offset.
/// offset = 0 for the first trading key; rotate by incrementing.
pub fn derive_trading_key_at_offset(
    seed: &MasterSeed,
    offset: u64,
) -> Result<SigningKey, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, seed.as_bytes());
    let mut info = Vec::with_capacity(INFO_TRADING.len() + 8);
    info.extend_from_slice(INFO_TRADING);
    info.extend_from_slice(&offset.to_le_bytes());
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|e| CryptoError::Hkdf(format!("{e:?}")))?;
    // Ed25519 accepts any 32-byte secret.
    let secret: SecretKey = okm;
    Ok(SigningKey::from_bytes(&secret))
}

/// Derive an Ed25519 Root Key (only used when the user does not bring their
/// own Solana wallet). In institutional flows this is NOT used — the Root Key
/// is a separate cold Solana wallet.
pub fn derive_root_key(seed: &MasterSeed) -> Result<SigningKey, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, seed.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(INFO_ROOT, &mut okm)
        .map_err(|e| CryptoError::Hkdf(format!("{e:?}")))?;
    Ok(SigningKey::from_bytes(&okm))
}

/// Derive the blinding factor for the note at a given insertion counter.
/// Counter = the Merkle tree leaf index at the time of deposit.
pub fn derive_blinding_factor(seed: &MasterSeed, counter: u64) -> Fr {
    let mut info = Vec::with_capacity(INFO_BLINDING.len() + 8);
    info.extend_from_slice(INFO_BLINDING);
    info.extend_from_slice(&counter.to_le_bytes());
    let bytes = darknyx_shake_kdf_v1(seed.as_bytes(), &info, &[], 64);
    fr_from_uniform_bytes(&bytes)
}

// ---------- internal helpers ----------

fn hkdf_expand_64(ikm: &[u8], info: &[u8]) -> Result<[u8; 64], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 64];
    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::Hkdf(format!("{e:?}")))?;
    Ok(okm)
}

/// Darknyx-specific, versioned SHAKE256 KDF retained byte-for-byte for existing
/// notes and keys. This feeds SP 800-185-style encodings into raw SHAKE256; it
/// is deliberately not claimed to be NIST KMAC or cSHAKE.
pub fn darknyx_shake_kdf_v1(
    key: &[u8],
    custom_info: &[u8],
    data: &[u8],
    out_len: usize,
) -> Vec<u8> {
    // bytepad(encode_string("KMAC") || encode_string(custom_info), 136) || bytepad(encode_string(key), 136) || X || right_encode(out_len_bits)
    let mut hasher = Shake256::default();
    // Preserve the historical literal bytes for compatibility. They do not
    // make raw SHAKE256 a standards-conformant KMAC construction.
    let name = b"KMAC";

    let mut header = Vec::new();
    header.extend_from_slice(&encode_string(name));
    header.extend_from_slice(&encode_string(custom_info));
    let padded = bytepad(&header, 136);
    hasher.update(&padded);

    let padded_key = bytepad(&encode_string(key), 136);
    hasher.update(&padded_key);

    hasher.update(data);

    let bits = (out_len * 8) as u64;
    hasher.update(&right_encode(bits));

    let mut out = vec![0u8; out_len];
    let mut reader = hasher.finalize_xof();
    reader.read(&mut out);
    out
}

fn left_encode(x: u64) -> Vec<u8> {
    if x == 0 {
        return vec![1, 0];
    }
    let bytes = x.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap();
    let trimmed = &bytes[first_nonzero..];
    let n = trimmed.len() as u8;
    let mut v = Vec::with_capacity(1 + trimmed.len());
    v.push(n);
    v.extend_from_slice(trimmed);
    v
}

fn right_encode(x: u64) -> Vec<u8> {
    if x == 0 {
        return vec![0, 1];
    }
    let bytes = x.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap();
    let trimmed = &bytes[first_nonzero..];
    let n = trimmed.len() as u8;
    let mut v = Vec::with_capacity(trimmed.len() + 1);
    v.extend_from_slice(trimmed);
    v.push(n);
    v
}

fn encode_string(s: &[u8]) -> Vec<u8> {
    let bits = (s.len() as u64) * 8;
    let mut v = left_encode(bits);
    v.extend_from_slice(s);
    v
}

fn bytepad(x: &[u8], w: usize) -> Vec<u8> {
    let mut v = left_encode(w as u64);
    v.extend_from_slice(x);
    while !v.len().is_multiple_of(w) {
        v.push(0);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;

    fn fixed_seed() -> MasterSeed {
        // Deterministic test seed.
        let mut b = [0u8; MASTER_SEED_BYTES];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = i as u8;
        }
        MasterSeed::new(b)
    }

    #[test]
    fn all_key_derivations_deterministic() {
        let s = fixed_seed();
        let b1 = KeyBundle::derive(&s, 0).unwrap();
        let b2 = KeyBundle::derive(&s, 0).unwrap();
        assert_eq!(b1.spending_key, b2.spending_key);
        assert_eq!(b1.viewing_key, b2.viewing_key);
        assert_eq!(b1.trading_key.to_bytes(), b2.trading_key.to_bytes());
        assert_eq!(b1.root_key.to_bytes(), b2.root_key.to_bytes());
    }

    #[test]
    fn darknyx_shake_kdf_v1_known_answer_is_frozen() {
        let actual = darknyx_shake_kdf_v1(&[0x40; 32], b"darknyx-vk-v2", &[], 64);
        assert_eq!(
            hex::encode(actual),
            "d99fdc876dcd8ca6f4be42b7587b2147a4fd7b4846e1dad32adc3e0e8af63e4d461a0361e83a3acde5e58e878dcbe4fecea8dd60f1fe16b021940aeb1ae810a3"
        );
    }

    #[test]
    fn spending_key_in_bn254_field() {
        let s = fixed_seed();
        let sk = derive_spending_key(&s).unwrap();
        // If derivation produced a reduced Fr, it's definitely in field.
        let bytes = sk.into_bigint();
        let _ = bytes; // just exercising the type
    }

    #[test]
    fn keys_are_independent() {
        let s = fixed_seed();
        let sk = derive_spending_key(&s).unwrap();
        let vk = derive_master_viewing_key(&s).unwrap();
        assert_ne!(sk, vk);
    }

    #[test]
    fn trading_key_offset_rotation() {
        let s = fixed_seed();
        let k0 = derive_trading_key_at_offset(&s, 0).unwrap();
        let k1 = derive_trading_key_at_offset(&s, 1).unwrap();
        assert_ne!(k0.to_bytes(), k1.to_bytes());
    }

    #[test]
    fn blinding_factor_deterministic_from_counter() {
        let s = fixed_seed();
        let r5a = derive_blinding_factor(&s, 5);
        let r5b = derive_blinding_factor(&s, 5);
        assert_eq!(r5a, r5b);
    }

    #[test]
    fn blinding_factors_unique_per_counter() {
        let s = fixed_seed();
        let mut set = std::collections::HashSet::new();
        for i in 0..1000u64 {
            let r = derive_blinding_factor(&s, i);
            assert!(set.insert(r), "collision at counter {i}");
        }
    }
}
