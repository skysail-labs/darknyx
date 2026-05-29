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
    create_lookup_table, extend_lookup_table,
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

/// The create + extend instructions for a per-batch ALT, plus the
/// derived ALT address. The caller submits these as Tx C, waits
/// for confirmation, then references the ALT in the Tx D v0
/// message.
///
/// `authority` is the TEE keypair pubkey (also the fee-payer).
/// `recent_slot` must be the context slot from a recent
/// `getLatestBlockhash` (see the module doc).
pub struct PerBatchAltIxs {
    /// `[create_ix, extend_ix]`, in submit order.
    pub ixs: Vec<Instruction>,
    /// The derived ALT address — used to construct the
    /// `AddressLookupTableAccount` for Tx D's v0 message.
    pub alt_address: Address,
}

/// Build the per-batch ALT create + extend instructions for the
/// given derivable addresses (from
/// [`super::settle_batched::per_batch_alt_addresses`]).
pub fn build_per_batch_alt_ixs(
    authority: &Address,
    recent_slot: u64,
    addresses: &[Address],
) -> PerBatchAltIxs {
    let auth_pk = to_pubkey(authority);
    let (create_ix, alt_pk) = create_lookup_table(auth_pk, auth_pk, recent_slot);

    let new_addresses: Vec<Pubkey> = addresses.iter().map(to_pubkey).collect();
    let extend_ix = extend_lookup_table(alt_pk, auth_pk, Some(auth_pk), new_addresses);

    PerBatchAltIxs {
        ixs: vec![create_ix, extend_ix],
        alt_address: to_address(&alt_pk),
    }
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
    fn build_returns_create_plus_extend() {
        let auth = dummy_authority();
        let addrs: Vec<Address> = (0u8..5).map(|i| Address::new_from_array([i; 32])).collect();
        let out = build_per_batch_alt_ixs(&auth, 12345, &addrs);
        assert_eq!(out.ixs.len(), 2);
        // The ALT address is deterministic from (authority, slot).
        let out2 = build_per_batch_alt_ixs(&auth, 12345, &addrs);
        assert_eq!(out.alt_address, out2.alt_address);
        // A different recent_slot → different ALT address.
        let out3 = build_per_batch_alt_ixs(&auth, 12346, &addrs);
        assert_ne!(out.alt_address, out3.alt_address);
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
