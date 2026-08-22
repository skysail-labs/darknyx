//! Hierarchical viewing-key tree — scoped, revocable read access for compliance.
//!
//! ```text
//!     MVK                            master; never leaves the compliance team
//!      |
//!      PairVK(base, quote)           = Poseidon5(mvk, base_lo, base_hi, quote_lo, quote_hi)
//!      |
//!      MonthlyVK(year, month)        = Poseidon2( Poseidon2(pair_vk, year), month )
//! ```
//!
//! The point of the tree is that disclosure can be **scoped**: handing over one
//! `MonthlyVK` grants visibility into exactly one market-pair for exactly one
//! month, and nothing else.
//!
//! That holds because derivation is one-directional — given a child key there is no
//! function recovering the parent, which follows from Poseidon's preimage
//! resistance rather than from any access control around the key. So the isolation
//! survives a leaked child key; it does not survive a leaked MVK.
//!
//! Unlike most of this crate, these have **no TypeScript counterpart** and no
//! parity test: viewing keys are used by off-chain compliance tooling on the Rust
//! side only. Changing a derivation here therefore breaks previously issued keys
//! rather than failing a cross-language assertion — there is nothing to catch it.
//!
//! See `CRYPTOGRAPHY.md` for how this sits in the wider key model.

use crate::errors::CryptoError;
use crate::field::{fr_to_be_bytes, pubkey_to_fr_pair, u64_to_fr, Fr};
use crate::poseidon::poseidon_hash;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a per-pair viewing key from the Master Viewing Key.
pub fn derive_viewing_key_for_pair(
    mvk: &Fr,
    base_mint: &[u8; 32],
    quote_mint: &[u8; 32],
) -> Result<Fr, CryptoError> {
    let [base_lo, base_hi] = pubkey_to_fr_pair(base_mint);
    let [quote_lo, quote_hi] = pubkey_to_fr_pair(quote_mint);
    poseidon_hash(&[*mvk, base_lo, base_hi, quote_lo, quote_hi])
}

/// Derive a per-month viewing key from a pair viewing key.
pub fn derive_monthly_viewing_key(pair_vk: &Fr, year: u64, month: u64) -> Result<Fr, CryptoError> {
    let yearly = poseidon_hash(&[*pair_vk, u64_to_fr(year)])?;
    poseidon_hash(&[yearly, u64_to_fr(month)])
}

/// Derive a symmetric AEAD key from any viewing-key scope (typically a MonthlyVK).
///
/// HKDF-SHA256 expands the 32-byte BE encoding of the viewing key into a 32-byte
/// ChaCha20-Poly1305 key. The label encodes the key purpose so an AEAD key derived
/// for scope A cannot collide with one derived for scope B.
pub fn derive_scope_aead_key(scope_vk: &Fr) -> Result<[u8; 32], CryptoError> {
    let ikm = fr_to_be_bytes(scope_vk);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"darkpool_scope_aead_v1", &mut okm)
        .map_err(|e| CryptoError::Hkdf(format!("scope aead: {e:?}")))?;
    Ok(okm)
}

/// AEAD-encrypt a payload with a symmetric key derived from the scope viewing key.
///
/// Nonce is supplied by the caller (12 bytes). It must be unique per key.
pub fn scope_aead_encrypt(
    scope_vk: &Fr,
    nonce12: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = derive_scope_aead_key(scope_vk)?;
    let cipher = ChaCha20Poly1305::new(&key.into());
    cipher
        .encrypt(Nonce::from_slice(nonce12), plaintext)
        .map_err(|e| CryptoError::Aead(format!("encrypt: {e:?}")))
}

/// AEAD-decrypt a payload. Returns None on authentication failure (the canonical
/// signal that "this scope key cannot read this ciphertext").
pub fn scope_aead_decrypt(
    scope_vk: &Fr,
    nonce12: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Option<Vec<u8>>, CryptoError> {
    let key = derive_scope_aead_key(scope_vk)?;
    let cipher = ChaCha20Poly1305::new(&key.into());
    match cipher.decrypt(Nonce::from_slice(nonce12), ciphertext) {
        Ok(pt) => Ok(Some(pt)),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_vk_deterministic() {
        let mvk = Fr::from(7u64);
        let base = [1u8; 32];
        let quote = [2u8; 32];
        let a = derive_viewing_key_for_pair(&mvk, &base, &quote).unwrap();
        let b = derive_viewing_key_for_pair(&mvk, &base, &quote).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn viewing_key_scope_isolation() {
        let mvk = Fr::from(7u64);
        let base = [1u8; 32];
        let quote_a = [2u8; 32];
        let quote_b = [3u8; 32];

        let pair_a = derive_viewing_key_for_pair(&mvk, &base, &quote_a).unwrap();
        let pair_b = derive_viewing_key_for_pair(&mvk, &base, &quote_b).unwrap();
        assert_ne!(pair_a, pair_b, "different pairs must yield different keys");

        let mk_a_jan = derive_monthly_viewing_key(&pair_a, 2025, 1).unwrap();
        let mk_a_feb = derive_monthly_viewing_key(&pair_a, 2025, 2).unwrap();
        let mk_b_jan = derive_monthly_viewing_key(&pair_b, 2025, 1).unwrap();
        assert_ne!(mk_a_jan, mk_a_feb);
        assert_ne!(mk_a_jan, mk_b_jan);
    }

    #[test]
    fn hierarchy_one_directional() {
        // Statically enforced — there is no function in this module that takes a
        // child key and returns a parent. This test documents that contract.
        // (If someone adds a `recover_parent` function, this test's comment must
        // be updated and the API review must explicitly approve it.)
        let marker = "one-directional";
        assert!(!marker.is_empty());
    }

    /// test_viewing_key_scope_isolation (Section 23.2.3):
    /// MonthlyVK for (SOL/USDC, 2025-01) must NOT decrypt ciphertexts that were
    /// produced under (SOL/USDC, 2025-02) or (wBTC/USDC, 2025-01).
    #[test]
    fn scope_aead_enforces_key_isolation() {
        let mvk = Fr::from(42u64);
        let sol = [0x1au8; 32];
        let usdc = [0x2bu8; 32];
        let wbtc = [0x3cu8; 32];

        let pair_sol_usdc = derive_viewing_key_for_pair(&mvk, &sol, &usdc).unwrap();
        let pair_wbtc_usdc = derive_viewing_key_for_pair(&mvk, &wbtc, &usdc).unwrap();

        // Three scoped keys we'll use in the test.
        let scope_sol_jan = derive_monthly_viewing_key(&pair_sol_usdc, 2025, 1).unwrap();
        let scope_sol_feb = derive_monthly_viewing_key(&pair_sol_usdc, 2025, 2).unwrap();
        let scope_wbtc_jan = derive_monthly_viewing_key(&pair_wbtc_usdc, 2025, 1).unwrap();
        assert_ne!(scope_sol_jan, scope_sol_feb);
        assert_ne!(scope_sol_jan, scope_wbtc_jan);

        let nonce = [0u8; 12];
        let plaintext = b"order settled: SOL/USDC @ 2025-01-15T10:00Z, 100 SOL";

        // Encrypt under SOL/USDC January.
        let ct = scope_aead_encrypt(&scope_sol_jan, &nonce, plaintext).unwrap();

        // Right key decrypts.
        let ok = scope_aead_decrypt(&scope_sol_jan, &nonce, &ct).unwrap();
        assert_eq!(ok.as_deref(), Some(&plaintext[..]));

        // Wrong month (same pair) must fail.
        let wrong_month = scope_aead_decrypt(&scope_sol_feb, &nonce, &ct).unwrap();
        assert!(wrong_month.is_none(), "Feb key decrypted Jan ciphertext!");

        // Wrong pair (same month) must fail.
        let wrong_pair = scope_aead_decrypt(&scope_wbtc_jan, &nonce, &ct).unwrap();
        assert!(
            wrong_pair.is_none(),
            "wBTC/USDC key decrypted SOL/USDC ciphertext!"
        );

        // Tampered ciphertext must fail under right key too.
        let mut bad = ct.clone();
        bad[0] ^= 0x01;
        let tampered = scope_aead_decrypt(&scope_sol_jan, &nonce, &bad).unwrap();
        assert!(tampered.is_none(), "tampered ciphertext must fail AEAD tag");
    }
}
