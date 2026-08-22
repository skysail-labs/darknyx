//! Canonical governed-config digest for VALID_MATCH_BATCH.
//!
//! The circuit exposes `[batch_root, config_digest]` and keeps the digest preimage
//! private. The vault recomputes the same digest from authoritative `VaultConfig`
//! and `MarketConfig` fields; the TEE supplies it to the prover. Field order and
//! big-endian encoding are consensus-critical.
//!
//! Three implementations must agree — this one, the vault's recomputation in
//! `verify_match_batch`, and the TypeScript mirror — so a change here is a change
//! in all three. Pinned by `match-config-parity.test.ts` via
//! `examples/match-config-digest`. A drift does not fail locally: the proof
//! verifies against a digest the vault does not recompute, and the settle is
//! rejected on-chain.

use crate::errors::CryptoError;
use crate::poseidon::poseidon_hash_bytes;

/// Fresh production domain tag, following `DOMAIN_DEPOSIT_INNER = 27`.
pub const DOMAIN_MATCH_CONFIG: u64 = 28;

/// `Poseidon8(28, fee_rate_bps, protocol_owner, base_lo, base_hi,
/// quote_lo, quote_hi, price_scale)`.
pub fn match_config_digest(
    fee_rate_bps: u64,
    protocol_owner_commitment: &[u8; 32],
    base_mint: &[u8; 32],
    quote_mint: &[u8; 32],
    price_scale: u64,
) -> Result<[u8; 32], CryptoError> {
    let [base_lo, base_hi] = mint_halves_be(base_mint);
    let [quote_lo, quote_hi] = mint_halves_be(quote_mint);
    poseidon_hash_bytes(&[
        u64_to_be32(DOMAIN_MATCH_CONFIG),
        u64_to_be32(fee_rate_bps),
        *protocol_owner_commitment,
        base_lo,
        base_hi,
        quote_lo,
        quote_hi,
        u64_to_be32(price_scale),
    ])
}

fn u64_to_be32(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn mint_halves_be(mint: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut lo = [0u8; 32];
    lo[16..].copy_from_slice(&mint[16..]);
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&mint[..16]);
    [lo, hi]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_binds_every_field() {
        let owner = [7u8; 32];
        let mut base = [0u8; 32];
        base[0] = 1;
        base[31] = 0xb1;
        let mut quote = [0u8; 32];
        quote[0] = 1;
        quote[31] = 0x9e;
        let digest = match_config_digest(30, &owner, &base, &quote, 100_000_000).unwrap();

        assert_eq!(
            hex::encode(digest),
            "053d4a1e1aa0c604c482f58e4afb9327ac4793922fc6be567c2120459be10758"
        );

        assert_ne!(
            digest,
            match_config_digest(31, &owner, &base, &quote, 100_000_000).unwrap()
        );
        let mut other_owner = owner;
        other_owner[31] ^= 1;
        assert_ne!(
            digest,
            match_config_digest(30, &other_owner, &base, &quote, 100_000_000).unwrap()
        );
        let mut other_base = base;
        other_base[31] ^= 1;
        assert_ne!(
            digest,
            match_config_digest(30, &owner, &other_base, &quote, 100_000_000).unwrap()
        );
        let mut other_quote = quote;
        other_quote[31] ^= 1;
        assert_ne!(
            digest,
            match_config_digest(30, &owner, &base, &other_quote, 100_000_000).unwrap()
        );
        assert_ne!(
            digest,
            match_config_digest(30, &owner, &base, &quote, 1).unwrap()
        );
        assert!(match_config_digest(30, &[0xff; 32], &base, &quote, 1).is_err());
    }
}
