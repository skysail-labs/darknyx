//! Minimal reader for the on-chain `VaultConfig` zero-copy account.
//!
//! The TEE does NOT depend on the `vault` BPF crate (it would drag in
//! `solana-program` + the whole Anchor stack), so — exactly like
//! [`crate::merkle::sync::parse_merkle_tree_root`] does for the
//! `MerkleTree` shard accounts — we read the one field we need by its
//! fixed byte offset and pin that offset with a unit test.
//!
//! `fee_rate_bps` is the load-bearing field (the on-chain batched-settle
//! handler enforces a fee FLOOR against it, so the TEE must charge AT LEAST
//! that rate or every settle rejects — reading the authoritative on-chain
//! value removes the `NYX_TEE_FEE_RATE_BPS` env-vs-chain foot-gun). We also
//! parse the three matcher-governance params (`tick_size`, `min_order_size`,
//! `circuit_breaker_bps`) the TEE adopts at boot — same single account, one
//! fetch, `0 = unset` ⇒ keep the env/dev default.
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
//! 1264 tick_size                u64               (8)   ← read
//! 1272 min_order_size           u64               (8)   ← read
//! 1280 circuit_breaker_bps      u64               (8)   ← read
//! 1288 (end)
//! ```

/// Anchor discriminator width.
const DISCRIMINATOR: usize = 8;
/// `admin: Pubkey`.
const ADMIN: usize = DISCRIMINATOR + 32;
/// `tee_pubkeys: [Pubkey; 16]`.
const TEE_PUBKEYS: usize = ADMIN + 32 * 16;
/// `root_key: Pubkey`.
const ROOT_KEY: usize = TEE_PUBKEYS + 32;
/// `zero_subtree_roots: [[u8; 32]; 20]` (MERKLE_DEPTH = 20).
const ZERO_SUBTREE_ROOTS: usize = ROOT_KEY + 32 * 20;
/// `protocol_owner_commitment: [u8; 32]`.
const PROTOCOL_OWNER_COMMITMENT: usize = ZERO_SUBTREE_ROOTS + 32;
/// Byte offset of `fee_rate_bps: u16` (little-endian).
pub const FEE_RATE_BPS_OFFSET: usize = PROTOCOL_OWNER_COMMITMENT;
/// `fee_rate_bps(2) + num_tee_keys(1) + num_trees(1) + bump(1) + _padding(3)`
/// = 8 bytes bring us to the appended `u64` matcher params.
pub const TICK_SIZE_OFFSET: usize = FEE_RATE_BPS_OFFSET + 8;
/// `min_order_size: u64` (little-endian).
pub const MIN_ORDER_SIZE_OFFSET: usize = TICK_SIZE_OFFSET + 8;
/// `circuit_breaker_bps: u64` (little-endian).
pub const CIRCUIT_BREAKER_BPS_OFFSET: usize = MIN_ORDER_SIZE_OFFSET + 8;

/// Extract `fee_rate_bps` from raw `VaultConfig` account data.
/// `None` if the buffer is too short (e.g. the account doesn't exist).
pub fn parse_fee_rate_bps(data: &[u8]) -> Option<u16> {
    if data.len() < FEE_RATE_BPS_OFFSET + 2 {
        return None;
    }
    let mut b = [0u8; 2];
    b.copy_from_slice(&data[FEE_RATE_BPS_OFFSET..FEE_RATE_BPS_OFFSET + 2]);
    Some(u16::from_le_bytes(b))
}

/// Read a little-endian `u64` at `offset`. `None` if the buffer is too short —
/// e.g. an account written under the OLD (pre-matcher-params) layout, which the
/// caller treats as `unset` and falls back to the env/dev default.
fn parse_u64_at(data: &[u8], offset: usize) -> Option<u64> {
    if data.len() < offset + 8 {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[offset..offset + 8]);
    Some(u64::from_le_bytes(b))
}

/// `tick_size: u64` — smallest price increment in base units.
pub fn parse_tick_size(data: &[u8]) -> Option<u64> {
    parse_u64_at(data, TICK_SIZE_OFFSET)
}

/// `min_order_size: u64` — minimum order size in base units.
pub fn parse_min_order_size(data: &[u8]) -> Option<u64> {
    parse_u64_at(data, MIN_ORDER_SIZE_OFFSET)
}

/// `circuit_breaker_bps: u64` — max |clearing − twap| / twap band, in bps.
pub fn parse_circuit_breaker_bps(data: &[u8]) -> Option<u64> {
    parse_u64_at(data, CIRCUIT_BREAKER_BPS_OFFSET)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_match_vault_layout() {
        // Pin the offsets against the hand-computed layout above; if the
        // on-chain struct grows a field before these, this and the doc
        // comment must move together. Total account data = 1288 bytes.
        assert_eq!(FEE_RATE_BPS_OFFSET, 1256);
        assert_eq!(TICK_SIZE_OFFSET, 1264);
        assert_eq!(MIN_ORDER_SIZE_OFFSET, 1272);
        assert_eq!(CIRCUIT_BREAKER_BPS_OFFSET, 1280);
    }

    #[test]
    fn parse_fee_rate_bps_reads_le_u16() {
        let mut data = vec![0u8; 1288];
        data[FEE_RATE_BPS_OFFSET..FEE_RATE_BPS_OFFSET + 2].copy_from_slice(&30u16.to_le_bytes());
        assert_eq!(parse_fee_rate_bps(&data), Some(30));
    }

    #[test]
    fn parse_matcher_params_read_le_u64() {
        let mut data = vec![0u8; 1288];
        data[TICK_SIZE_OFFSET..TICK_SIZE_OFFSET + 8].copy_from_slice(&5u64.to_le_bytes());
        data[MIN_ORDER_SIZE_OFFSET..MIN_ORDER_SIZE_OFFSET + 8]
            .copy_from_slice(&1_000u64.to_le_bytes());
        data[CIRCUIT_BREAKER_BPS_OFFSET..CIRCUIT_BREAKER_BPS_OFFSET + 8]
            .copy_from_slice(&250u64.to_le_bytes());
        assert_eq!(parse_tick_size(&data), Some(5));
        assert_eq!(parse_min_order_size(&data), Some(1_000));
        assert_eq!(parse_circuit_breaker_bps(&data), Some(250));
    }

    #[test]
    fn parsers_reject_short_buffer() {
        // A short buffer (missing account, or the OLD pre-matcher-params
        // layout) yields None for every field ⇒ callers keep env defaults.
        assert!(parse_fee_rate_bps(&[0u8; 8]).is_none());
        assert!(parse_tick_size(&[0u8; 1264]).is_none()); // 1 byte short of the field
        assert!(parse_min_order_size(&[0u8; 8]).is_none());
        assert!(parse_circuit_breaker_bps(&[0u8; 8]).is_none());
    }
}
