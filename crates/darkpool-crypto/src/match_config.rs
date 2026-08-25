//! Canonical governed-config digest for VALID_MATCH_BATCH.
//!
//! The circuit exposes `[batch_root, config_digest]` and keeps the digest preimage
//! private. The vault recomputes the same digest from authoritative `VaultConfig`
//! and `MarketConfig` fields; the TEE supplies it to the prover. Field order and
//! big-endian encoding are consensus-critical.
//!
//! Three implementations must agree — this one, the vault's recomputation in
//! `verify_match_batch`, and the TypeScript mirror — so a change here is a change
//! in all three.
//!
//! Only one of the two drifts is caught before deployment.
//! `match-config-parity.test.ts`, via `examples/match-config-digest`, pins this
//! implementation against the TypeScript one, so Rust↔TS drift fails there.
//! Drift against the **vault's** recomputation is not covered by it: the proof
//! then verifies against a digest the vault does not reproduce, and the failure
//! appears only when a settle is rejected on-chain.

use crate::errors::CryptoError;
use crate::poseidon::poseidon_hash_bytes;

pub const DOMAIN_MATCH_CONFIG_V2: u64 = 37;

/// `Poseidon10(37, fee_rate_bps, protocol_owner, base_lo, base_hi,
/// quote_lo, quote_hi, price_scale, fee_key_binding, fee_key_epoch)`.
pub fn match_config_digest(
    fee_rate_bps: u64,
    protocol_owner_commitment: &[u8; 32],
    base_mint: &[u8; 32],
    quote_mint: &[u8; 32],
    price_scale: u64,
    fee_key_binding: &[u8; 32],
    fee_key_epoch: u64,
) -> Result<[u8; 32], CryptoError> {
    let [base_lo, base_hi] = mint_halves_be(base_mint);
    let [quote_lo, quote_hi] = mint_halves_be(quote_mint);
    poseidon_hash_bytes(&[
        u64_to_be32(DOMAIN_MATCH_CONFIG_V2),
        u64_to_be32(fee_rate_bps),
        *protocol_owner_commitment,
        base_lo,
        base_hi,
        quote_lo,
        quote_hi,
        u64_to_be32(price_scale),
        *fee_key_binding,
        u64_to_be32(fee_key_epoch),
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
        let binding = [3u8; 32];
        let digest =
            match_config_digest(30, &owner, &base, &quote, 100_000_000, &binding, 7).unwrap();

        assert_ne!(
            digest,
            match_config_digest(31, &owner, &base, &quote, 100_000_000, &binding, 7).unwrap()
        );
        let mut other_owner = owner;
        other_owner[31] ^= 1;
        assert_ne!(
            digest,
            match_config_digest(30, &other_owner, &base, &quote, 100_000_000, &binding, 7).unwrap()
        );
        let mut other_base = base;
        other_base[31] ^= 1;
        assert_ne!(
            digest,
            match_config_digest(30, &owner, &other_base, &quote, 100_000_000, &binding, 7).unwrap()
        );
        let mut other_quote = quote;
        other_quote[31] ^= 1;
        assert_ne!(
            digest,
            match_config_digest(30, &owner, &base, &other_quote, 100_000_000, &binding, 7).unwrap()
        );
        assert_ne!(
            digest,
            match_config_digest(30, &owner, &base, &quote, 1, &binding, 7).unwrap()
        );
        let mut other_binding = binding;
        other_binding[31] ^= 1;
        assert_ne!(
            digest,
            match_config_digest(30, &owner, &base, &quote, 100_000_000, &other_binding, 7).unwrap()
        );
        assert_ne!(
            digest,
            match_config_digest(30, &owner, &base, &quote, 100_000_000, &binding, 8).unwrap()
        );
        assert!(match_config_digest(30, &[0xff; 32], &base, &quote, 1, &binding, 7).is_err());
        assert!(match_config_digest(30, &owner, &base, &quote, 1, &[0xff; 32], 7).is_err());
    }
}
