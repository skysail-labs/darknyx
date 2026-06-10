//! Per-batch Address Lookup Table (Tx C).
//!
//! Builds the create + extend instructions for an ALT holding the
//! five derivable per-batch PDAs (`note_lock_a/b/e/f` +
//! `batch_validity_marker`). Hoisting these into an ALT is what
//! lets the settle tx (Tx D) reference them by 1-byte index instead
//! of 32-byte pubkey, keeping it under the 1232-byte cap (see
//! CRYPTOGRAPHY.md §9 + CLAUDE.md §5).
//!
//! **`recent_slot` gotcha** (CRYPTOGRAPHY.md §9): the slot fed to
//! `create_lookup_table` MUST come from
//! `getLatestBlockhashAndContext().context.slot`, NOT
//! `getSlot("confirmed")` — the latter can return a leader-skipped
//! slot the runtime rejects as "is not a recent slot". Our
//! `SolanaRpcClient::get_latest_blockhash` already returns
//! `context_slot` from the same call, so callers pass that.

use solana_address::Address;
use solana_address_lookup_table_interface::instruction::{
    create_lookup_table, deactivate_lookup_table, extend_lookup_table,
};
use solana_instruction::Instruction;
use solana_message::AddressLookupTableAccount;
use solana_pubkey::Pubkey;

/// `Address` (solana-message / our builders) ↔ `Pubkey` (the ALT
/// interface crate). Both are 32-byte newtypes; the conversion is
/// a byte round-trip. Centralised here so the boundary is explicit.
fn to_pubkey(a: &Address) -> Pubkey {
    Pubkey::new_from_array(a.to_bytes())
}
fn to_address(p: &Pubkey) -> Address {
    Address::new_from_array(p.to_bytes())
}

/// Max addresses per `extend_lookup_table` tx. One extend ix carries 32 bytes
/// per address inline; with the tx envelope (sig + header + ~4 account keys +
/// blockhash + ix overhead ≈ 250 B) that caps a single extend tx at ~30
/// addresses under Solana's 1232-byte limit. 25 leaves a safety margin — a
/// batch needing more addresses (e.g. N=16 with the lock + consumed + nullifier
/// PDAs) is split across SEQUENTIAL extend txs (order matters: the ALT's index
/// mapping must mirror the in-memory address list).
pub const MAX_EXTEND_ADDRESSES: usize = 25;

/// The create + extend instructions for a per-batch ALT, plus the
/// derived ALT address. The caller submits these as Tx C, waits
/// for confirmation, then references the ALT in the Tx D v0
/// message.
///
/// `authority` is the TEE keypair pubkey (also the fee-payer).
/// `recent_slot` must be the context slot from a recent
/// `getLatestBlockhash` (see the module doc).
pub struct PerBatchAltIxs {
    /// The `create_lookup_table` ix — sent in its own tx (or with the first
    /// extend chunk).
    pub create_ix: Instruction,
    /// One `extend` ix per ≤[`MAX_EXTEND_ADDRESSES`] chunk of `addresses`, in
    /// order. Each MUST go in its OWN tx (a single tx can't hold more than ~30
    /// addresses' worth of extend data) and be confirmed before the next so the
    /// on-chain address order matches the in-memory list.
    pub extend_ixs: Vec<Instruction>,
    /// The derived ALT address — used to construct the
    /// `AddressLookupTableAccount` for Tx D's v0 message.
    pub alt_address: Address,
}

/// Build the per-batch ALT create + (chunked) extend instructions for the
/// given derivable addresses (from
/// [`super::settle_batched::per_batch_alt_addresses`]).
pub fn build_per_batch_alt_ixs(
    authority: &Address,
    recent_slot: u64,
    addresses: &[Address],
) -> PerBatchAltIxs {
    let auth_pk = to_pubkey(authority);
    let (create_ix, alt_pk) = create_lookup_table(auth_pk, auth_pk, recent_slot);
    let alt_address = to_address(&alt_pk);
    PerBatchAltIxs {
        create_ix,
        extend_ixs: build_extend_alt_ix_chunks(authority, &alt_address, addresses),
        alt_address,
    }
}

/// Build a standalone `extend` ix that appends `addresses` to an
/// existing ALT (the rolling-pool reuse path — no `create`). The
/// newly appended addresses are unusable until the slot after this
/// lands, same as a fresh create.
///
/// `addresses` MUST be ≤ [`MAX_EXTEND_ADDRESSES`] (one tx's worth); use
/// [`build_extend_alt_ix_chunks`] for an arbitrary-length set.
pub fn build_extend_alt_ix(
    authority: &Address,
    alt: &Address,
    addresses: &[Address],
) -> Instruction {
    let auth_pk = to_pubkey(authority);
    let new_addresses: Vec<Pubkey> = addresses.iter().map(to_pubkey).collect();
    extend_lookup_table(to_pubkey(alt), auth_pk, Some(auth_pk), new_addresses)
}

/// Chunk `addresses` into ≤[`MAX_EXTEND_ADDRESSES`] groups and build one
/// `extend` ix per chunk — each must be sent in its OWN tx, in order, so the
/// on-chain ALT address ordering matches the in-memory list a Tx D v0 message
/// indexes into. Empty input → no ixs.
pub fn build_extend_alt_ix_chunks(
    authority: &Address,
    alt: &Address,
    addresses: &[Address],
) -> Vec<Instruction> {
    addresses
        .chunks(MAX_EXTEND_ADDRESSES)
        .map(|chunk| build_extend_alt_ix(authority, alt, chunk))
        .collect()
}

/// Build a `deactivate` ix for an ALT being rotated out of the pool.
/// After this lands the ALT enters a ~512-slot cooldown; its rent is
/// reclaimable (via `close`) only once cooled.
pub fn build_deactivate_alt_ix(authority: &Address, alt: &Address) -> Instruction {
    deactivate_lookup_table(to_pubkey(alt), to_pubkey(authority))
}

/// Construct the `AddressLookupTableAccount` Tx D's v0 message
/// compilation needs — the ALT key + its full address list (the
/// addresses must be inline, NOT fetched, so the message can be
/// compiled offline).
pub fn alt_account(alt_address: Address, addresses: Vec<Address>) -> AddressLookupTableAccount {
    AddressLookupTableAccount {
        key: alt_address,
        addresses,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_authority() -> Address {
        bs58::encode([0x11u8; 32]).into_string().parse().unwrap()
    }

    #[test]
    fn pubkey_address_round_trip() {
        let a = dummy_authority();
        assert_eq!(to_address(&to_pubkey(&a)), a);
    }

    #[test]
    fn build_returns_create_plus_one_extend_for_small_set() {
        let auth = dummy_authority();
        let addrs: Vec<Address> = (0u8..5).map(|i| Address::new_from_array([i; 32])).collect();
        let out = build_per_batch_alt_ixs(&auth, 12345, &addrs);
        // 5 addresses ≤ MAX_EXTEND_ADDRESSES → a single extend chunk.
        assert_eq!(out.extend_ixs.len(), 1);
        // The ALT address is deterministic from (authority, slot).
        let out2 = build_per_batch_alt_ixs(&auth, 12345, &addrs);
        assert_eq!(out.alt_address, out2.alt_address);
        // A different recent_slot → different ALT address.
        let out3 = build_per_batch_alt_ixs(&auth, 12346, &addrs);
        assert_ne!(out.alt_address, out3.alt_address);
    }

    #[test]
    fn extend_chunks_split_large_address_sets() {
        let auth = dummy_authority();
        let alt = Address::new_from_array([0x99; 32]);
        // 98 addresses (≈ N=16 with lock+consumed+nullifier PDAs) → ceil(98/25)
        // = 4 extend txs, none over the per-tx address cap.
        let addrs: Vec<Address> = (0u16..98)
            .map(|i| Address::new_from_array([(i % 251) as u8; 32]))
            .collect();
        let chunks = build_extend_alt_ix_chunks(&auth, &alt, &addrs);
        assert_eq!(chunks.len(), 98_usize.div_ceil(MAX_EXTEND_ADDRESSES));
        assert_eq!(chunks.len(), 4);
        // Empty input → no extend ixs.
        assert!(build_extend_alt_ix_chunks(&auth, &alt, &[]).is_empty());
    }

    #[test]
    fn alt_account_carries_addresses_inline() {
        let key = Address::new_from_array([0xAB; 32]);
        let addrs = vec![
            Address::new_from_array([1; 32]),
            Address::new_from_array([2; 32]),
        ];
        let acct = alt_account(key, addrs.clone());
        assert_eq!(acct.key, key);
        assert_eq!(acct.addresses, addrs);
    }
}
