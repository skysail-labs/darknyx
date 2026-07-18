//! Hand-built SPL Token + Associated-Token-Account instructions (Increment B2).
//!
//! `spl-token` itself pulls `solana-program` 1.18, which conflicts with ark 0.5
//! on zeroize (the whole reason the crate uses the modular solana-* stack) — so
//! the two ixs the real-settle flow needs (mint collateral + create the ATA) are
//! encoded by hand. Their layouts are stable parts of the SPL ABI; the encoding
//! is unit-tested and the live path is validated on a CVM run.

use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use super::vault::{token_program_id, SYSTEM_PROGRAM_ID};

fn parse_id(b58: &str) -> Address {
    b58.parse().expect("hardcoded base58 program id is valid")
}

fn ata_program_id() -> Address {
    parse_id(super::vault::ATA_PROGRAM_ID_BASE58)
}

/// SPL Token `MintTo` (instruction tag 7): data = `[7, amount u64 LE]`,
/// accounts = `[mint(w), dest(w), authority(signer)]`.
pub fn build_mint_to_ix(
    mint: &Address,
    dest: &Address,
    authority: &Address,
    amount: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.push(7u8);
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: token_program_id(),
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new(*dest, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

/// ATA program `CreateIdempotent` (instruction tag 1): data = `[1]`, accounts =
/// `[funder(signer,w), ata(w), owner(ro), mint(ro), system(ro), token(ro)]`.
pub fn build_create_ata_idempotent_ix(
    funder: &Address,
    ata: &Address,
    owner: &Address,
    mint: &Address,
) -> Instruction {
    Instruction {
        program_id: ata_program_id(),
        accounts: vec![
            AccountMeta::new(*funder, true),
            AccountMeta::new(*ata, false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(token_program_id(), false),
        ],
        data: vec![1u8],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_to_layout() {
        let a = Address::new_from_array([1u8; 32]);
        let ix = build_mint_to_ix(&a, &a, &a, 0xCAFE);
        assert_eq!(ix.data[0], 7);
        assert_eq!(&ix.data[1..9], &0xCAFEu64.to_le_bytes());
        assert_eq!(ix.accounts.len(), 3);
        assert!(ix.accounts[2].is_signer); // authority signs
    }

    #[test]
    fn create_ata_idempotent_layout() {
        let a = Address::new_from_array([2u8; 32]);
        let ix = build_create_ata_idempotent_ix(&a, &a, &a, &a);
        assert_eq!(ix.data, vec![1u8]);
        assert_eq!(ix.accounts.len(), 6);
        assert!(ix.accounts[0].is_signer); // funder signs
    }
}
