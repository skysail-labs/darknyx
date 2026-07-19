//! Minimal reader for the on-chain `VaultConfig` zero-copy account.
//!
//! The TEE does NOT depend on the `vault` BPF crate (it would drag in
//! `solana-program` + the whole Anchor stack), so — exactly like
//! [`crate::merkle::sync::parse_merkle_tree_root`] does for the
//! `MerkleTree` shard accounts — we read the one field we need by its
//! fixed byte offset and pin that offset with a unit test.
//!
//! The proof binds both `fee_rate_bps` and `protocol_owner_commitment`, while
//! settlement authorization and sharding depend on the active TEE keys and
//! `num_trees`. Reading the authoritative finalized account removes env/chain
//! drift before the process accepts real-market trading. Per-market identity
//! and matching parameters live in the separate `MarketConfig` PDA.
//!
//! Layout (Anchor `#[account(zero_copy)]`, `repr(C)`, after the 8-byte
//! discriminator — mirrors `programs/vault/src/state.rs::VaultConfig`):
//!
//! ```text
//! 0    discriminator            [u8; 8]
//! 8    admin                    Pubkey            (32)
//! 40   tee_pubkeys              [Pubkey; 16]      (512)
//! 552  root_key                 Pubkey            (32)
//! 584  zero_subtree_roots       [[u8; 32]; 20]    (640)
//! 1224 protocol_owner_commitment[u8; 32]          (32)
//! 1256 fee_rate_bps             u16               (2)   ← read
//! 1258 num_tee_keys             u8
//! 1259 num_trees                u8
//! 1260 bump                     u8
//! 1261 _padding                 [u8; 3]
//! 1264 (end)
//! ```

use std::sync::LazyLock;

use sha2::{Digest, Sha256};

/// Anchor discriminator width.
const DISCRIMINATOR: usize = 8;
/// `admin: Pubkey`.
const ADMIN: usize = DISCRIMINATOR + 32;
/// Byte offset of the first `tee_pubkeys` entry.
const TEE_PUBKEYS_OFFSET: usize = ADMIN;
/// `tee_pubkeys: [Pubkey; 16]`.
const TEE_PUBKEYS: usize = ADMIN + 32 * 16;
/// `root_key: Pubkey`.
const ROOT_KEY: usize = TEE_PUBKEYS + 32;
/// `zero_subtree_roots: [[u8; 32]; 20]` (MERKLE_DEPTH = 20).
const ZERO_SUBTREE_ROOTS: usize = ROOT_KEY + 32 * 20;
/// `protocol_owner_commitment: [u8; 32]`.
const PROTOCOL_OWNER_COMMITMENT: usize = ZERO_SUBTREE_ROOTS + 32;
const PROTOCOL_OWNER_COMMITMENT_OFFSET: usize = ZERO_SUBTREE_ROOTS;
/// Byte offset of `fee_rate_bps: u16` (little-endian).
pub const FEE_RATE_BPS_OFFSET: usize = PROTOCOL_OWNER_COMMITMENT;
const NUM_TEE_KEYS_OFFSET: usize = FEE_RATE_BPS_OFFSET + 2;
const NUM_TREES_OFFSET: usize = NUM_TEE_KEYS_OFFSET + 1;
pub const VAULT_CONFIG_ACCOUNT_LEN: usize = 1264;

static VAULT_CONFIG_DISCRIMINATOR: LazyLock<[u8; 8]> = LazyLock::new(|| {
    let hash = Sha256::digest(b"account:VaultConfig");
    let mut discriminator = [0u8; 8];
    discriminator.copy_from_slice(&hash[..8]);
    discriminator
});

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnChainVaultConfig {
    pub tee_pubkeys: [[u8; 32]; 16],
    pub protocol_owner_commitment: [u8; 32],
    pub fee_rate_bps: u16,
    pub num_tee_keys: u8,
    pub num_trees: u8,
}

/// Parse the governance fields the TEE needs from the exact current layout.
pub fn parse_vault_config(data: &[u8]) -> Option<OnChainVaultConfig> {
    if data.len() != VAULT_CONFIG_ACCOUNT_LEN || data[..8] != *VAULT_CONFIG_DISCRIMINATOR {
        return None;
    }
    let mut tee_pubkeys = [[0u8; 32]; 16];
    for (index, key) in tee_pubkeys.iter_mut().enumerate() {
        let start = TEE_PUBKEYS_OFFSET + index * 32;
        key.copy_from_slice(&data[start..start + 32]);
    }
    Some(OnChainVaultConfig {
        tee_pubkeys,
        protocol_owner_commitment: data
            [PROTOCOL_OWNER_COMMITMENT_OFFSET..PROTOCOL_OWNER_COMMITMENT]
            .try_into()
            .ok()?,
        fee_rate_bps: u16::from_le_bytes(
            data[FEE_RATE_BPS_OFFSET..FEE_RATE_BPS_OFFSET + 2]
                .try_into()
                .ok()?,
        ),
        num_tee_keys: data[NUM_TEE_KEYS_OFFSET],
        num_trees: data[NUM_TREES_OFFSET],
    })
}

/// Extract `fee_rate_bps` from raw `VaultConfig` account data.
/// `None` unless the exact current layout and discriminator are present.
pub fn parse_fee_rate_bps(data: &[u8]) -> Option<u16> {
    parse_vault_config(data).map(|config| config.fee_rate_bps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_match_vault_layout() {
        // Pin the offsets against the hand-computed layout above; if the
        // on-chain struct grows a field before these, this and the doc
        // comment must move together. Total account data = 1264 bytes.
        assert_eq!(FEE_RATE_BPS_OFFSET, 1256);
        assert_eq!(PROTOCOL_OWNER_COMMITMENT_OFFSET, 1224);
        assert_eq!(NUM_TEE_KEYS_OFFSET, 1258);
        assert_eq!(NUM_TREES_OFFSET, 1259);
    }

    #[test]
    fn parse_fee_rate_bps_reads_le_u16() {
        let mut data = vec![0u8; 1264];
        data[..8].copy_from_slice(&*VAULT_CONFIG_DISCRIMINATOR);
        data[FEE_RATE_BPS_OFFSET..FEE_RATE_BPS_OFFSET + 2].copy_from_slice(&30u16.to_le_bytes());
        assert_eq!(parse_fee_rate_bps(&data), Some(30));
    }

    #[test]
    fn parses_proof_and_runtime_governance_fields() {
        let mut data = vec![0u8; VAULT_CONFIG_ACCOUNT_LEN];
        data[..8].copy_from_slice(&*VAULT_CONFIG_DISCRIMINATOR);
        data[TEE_PUBKEYS_OFFSET..TEE_PUBKEYS_OFFSET + 32].copy_from_slice(&[0x11; 32]);
        data[TEE_PUBKEYS_OFFSET + 32..TEE_PUBKEYS_OFFSET + 64].copy_from_slice(&[0x22; 32]);
        data[PROTOCOL_OWNER_COMMITMENT_OFFSET..PROTOCOL_OWNER_COMMITMENT]
            .copy_from_slice(&[0x03; 32]);
        data[FEE_RATE_BPS_OFFSET..FEE_RATE_BPS_OFFSET + 2].copy_from_slice(&30u16.to_le_bytes());
        data[NUM_TEE_KEYS_OFFSET] = 2;
        data[NUM_TREES_OFFSET] = 2;

        let parsed = parse_vault_config(&data).unwrap();
        assert_eq!(parsed.tee_pubkeys[0], [0x11; 32]);
        assert_eq!(parsed.tee_pubkeys[1], [0x22; 32]);
        assert_eq!(parsed.protocol_owner_commitment, [0x03; 32]);
        assert_eq!(parsed.fee_rate_bps, 30);
        assert_eq!(parsed.num_tee_keys, 2);
        assert_eq!(parsed.num_trees, 2);
    }

    #[test]
    fn parsers_reject_short_buffer() {
        // A short buffer (missing or stale account layout) is rejected.
        assert!(parse_fee_rate_bps(&[0u8; 8]).is_none());
    }

    #[test]
    fn parser_rejects_wrong_discriminator_and_legacy_long_layout() {
        let mut data = vec![0u8; VAULT_CONFIG_ACCOUNT_LEN];
        assert!(parse_fee_rate_bps(&data).is_none());
        data[..8].copy_from_slice(&*VAULT_CONFIG_DISCRIMINATOR);
        data.push(0);
        assert!(parse_fee_rate_bps(&data).is_none());
    }
}
