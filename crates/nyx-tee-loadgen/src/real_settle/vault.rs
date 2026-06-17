//! Vault deposit instruction + PDAs + NoteCreated event parsing (Increment B1).
//!
//! Hand-mirrors the SDK's `buildDepositInstruction` (vault-client.ts), the PDA
//! seeds in `crates/nyx-tee/src/settle/vault.rs`, and the NoteCreated event in
//! `utxo/leaf-index.ts`. The ix encoding (discriminator, data layout, account
//! order) is unit-tested here; the live deposit/confirm path is validated on a
//! CVM run (see BENCHMARK.md).

use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use super::RealSettleError;

// ── Program ids ──────────────────────────────────────────────────────────────

/// Devnet vault program id (source of truth: `programs/vault/src/lib.rs`).
pub const VAULT_PROGRAM_ID_BASE58: &str = "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";
/// SPL Token program.
pub const TOKEN_PROGRAM_ID_BASE58: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// Associated-token-account program.
pub const ATA_PROGRAM_ID_BASE58: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// Rent sysvar.
pub const RENT_SYSVAR_BASE58: &str = "SysvarRent111111111111111111111111111111111";
/// System program (all-zeros).
pub const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0u8; 32]);

// ── PDA seeds (mirror programs/vault/src/state.rs::SEED) ─────────────────────

const VAULT_CONFIG_SEED: &[u8] = b"vault_config";
const MERKLE_TREE_SEED: &[u8] = b"merkle_tree";
const VAULT_TOKEN_SEED: &[u8] = b"vault_token";
const OUTSTANDING_MINT_SEED: &[u8] = b"outstanding_mint";

fn parse_id(b58: &str) -> Address {
    b58.parse().expect("hardcoded base58 program id is valid")
}

pub fn vault_program_id() -> Address {
    parse_id(VAULT_PROGRAM_ID_BASE58)
}
pub fn token_program_id() -> Address {
    parse_id(TOKEN_PROGRAM_ID_BASE58)
}

// ── PDAs ─────────────────────────────────────────────────────────────────────

pub fn vault_config_pda() -> Address {
    Address::find_program_address(&[VAULT_CONFIG_SEED], &vault_program_id()).0
}
pub fn merkle_tree_pda(tree_id: u8) -> Address {
    Address::find_program_address(&[MERKLE_TREE_SEED, &[tree_id]], &vault_program_id()).0
}
pub fn vault_token_account_pda(mint: &Address) -> Address {
    Address::find_program_address(&[VAULT_TOKEN_SEED, &mint.to_bytes()], &vault_program_id()).0
}
pub fn outstanding_mint_pda(mint: &Address) -> Address {
    Address::find_program_address(
        &[OUTSTANDING_MINT_SEED, &mint.to_bytes()],
        &vault_program_id(),
    )
    .0
}

/// The associated token account for `owner` + `mint` under the SPL ATA program:
/// `find_program_address([owner, token_program, mint], ata_program)`.
pub fn associated_token_address(owner: &Address, mint: &Address) -> Address {
    Address::find_program_address(
        &[
            &owner.to_bytes(),
            &token_program_id().to_bytes(),
            &mint.to_bytes(),
        ],
        &parse_id(ATA_PROGRAM_ID_BASE58),
    )
    .0
}

// ── Anchor discriminator ─────────────────────────────────────────────────────

/// `sha256("global:<name>")[..8]` — the Anchor ix discriminator.
pub fn anchor_discriminator(name: &str) -> [u8; 8] {
    let digest = Sha256::digest(format!("global:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

// ── Deposit instruction ──────────────────────────────────────────────────────

/// Build the vault `deposit` ix appending a note to shard `tree_id`. Mirrors the
/// SDK's `buildDepositInstruction` byte-for-byte: data = disc(8) ‖ tree_id(1) ‖
/// amount(u64 LE) ‖ owner_commitment(32) ‖ inner_hash(32); 10 accounts in order.
pub fn build_deposit_ix(
    tree_id: u8,
    depositor: &Address,
    token_mint: &Address,
    depositor_token_account: &Address,
    amount: u64,
    owner_commitment: &[u8; 32],
    inner_hash: &[u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 1 + 8 + 32 + 32);
    data.extend_from_slice(&anchor_discriminator("deposit"));
    data.push(tree_id);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(owner_commitment);
    data.extend_from_slice(inner_hash);

    let accounts = vec![
        AccountMeta::new(*depositor, true),
        AccountMeta::new_readonly(vault_config_pda(), false),
        AccountMeta::new(merkle_tree_pda(tree_id), false),
        AccountMeta::new_readonly(*token_mint, false),
        AccountMeta::new(*depositor_token_account, false),
        AccountMeta::new(vault_token_account_pda(token_mint), false),
        AccountMeta::new(outstanding_mint_pda(token_mint), false),
        AccountMeta::new_readonly(token_program_id(), false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        AccountMeta::new_readonly(parse_id(RENT_SYSVAR_BASE58), false),
    ];

    Instruction {
        program_id: vault_program_id(),
        accounts,
        data,
    }
}

// ── NoteCreated event parsing ────────────────────────────────────────────────

const PROGRAM_DATA_PREFIX: &str = "Program data: ";

/// The shard + position a deposit appended its note at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteCreated {
    pub tree_id: u8,
    pub leaf_index: u64,
}

/// Scan a confirmed tx's log lines for the `NoteCreated` Anchor event and return
/// its `(tree_id, leaf_index)`. The event body is `tree_id(u8) ‖ leaf_index(u64
/// LE) ‖ …` after the 8-byte `sha256("event:NoteCreated")[..8]` discriminator.
pub fn note_created_from_logs(logs: &[String]) -> Result<NoteCreated, RealSettleError> {
    let disc = {
        let d = Sha256::digest(b"event:NoteCreated");
        let mut out = [0u8; 8];
        out.copy_from_slice(&d[..8]);
        out
    };
    for line in logs {
        let Some(b64) = line.strip_prefix(PROGRAM_DATA_PREFIX) else {
            continue;
        };
        let Ok(bytes) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
        else {
            continue;
        };
        // disc(8) + tree_id(1) + leaf_index(8)
        if bytes.len() < 8 + 1 + 8 || bytes[..8] != disc {
            continue;
        }
        let tree_id = bytes[8];
        let mut le = [0u8; 8];
        le.copy_from_slice(&bytes[9..17]);
        return Ok(NoteCreated {
            tree_id,
            leaf_index: u64::from_le_bytes(le),
        });
    }
    Err(RealSettleError::Event(
        "no NoteCreated event in tx logs".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn deposit_discriminator_matches_anchor_formula() {
        // sha256("global:deposit")[..8] — independent of the builder.
        let want = {
            let d = Sha256::digest(b"global:deposit");
            let mut o = [0u8; 8];
            o.copy_from_slice(&d[..8]);
            o
        };
        assert_eq!(anchor_discriminator("deposit"), want);
    }

    #[test]
    fn deposit_data_layout_is_81_bytes_in_order() {
        let mint = vault_token_account_pda(&SYSTEM_PROGRAM_ID); // any address
        let ix = build_deposit_ix(3, &mint, &mint, &mint, 0xAABB, &[0x11; 32], &[0x22; 32]);
        assert_eq!(ix.data.len(), 8 + 1 + 8 + 32 + 32);
        assert_eq!(&ix.data[..8], &anchor_discriminator("deposit"));
        assert_eq!(ix.data[8], 3); // tree_id
        assert_eq!(&ix.data[9..17], &0xAABBu64.to_le_bytes());
        assert_eq!(&ix.data[17..49], &[0x11; 32]); // owner_commitment
        assert_eq!(&ix.data[49..81], &[0x22; 32]); // inner_hash
        assert_eq!(ix.accounts.len(), 10);
        assert!(ix.accounts[0].is_signer); // depositor signs
        assert!(ix.accounts[2].is_writable); // merkle_tree[tree_id]
    }

    #[test]
    fn pdas_are_deterministic_and_distinct_per_shard() {
        assert_eq!(merkle_tree_pda(0), merkle_tree_pda(0));
        assert_ne!(merkle_tree_pda(0), merkle_tree_pda(1));
        assert_eq!(vault_config_pda(), vault_config_pda());
    }

    #[test]
    fn note_created_event_round_trips() {
        let disc = {
            let d = Sha256::digest(b"event:NoteCreated");
            let mut o = [0u8; 8];
            o.copy_from_slice(&d[..8]);
            o
        };
        let mut body = Vec::new();
        body.extend_from_slice(&disc);
        body.push(2); // tree_id
        body.extend_from_slice(&17u64.to_le_bytes()); // leaf_index
        body.extend_from_slice(&[0u8; 32]); // (trailing commitment etc.)
        let line = format!(
            "Program data: {}",
            base64::engine::general_purpose::STANDARD.encode(&body)
        );
        let got = note_created_from_logs(&["Program log: Instruction: Deposit".to_string(), line])
            .unwrap();
        assert_eq!(
            got,
            NoteCreated {
                tree_id: 2,
                leaf_index: 17
            }
        );
    }

    #[test]
    fn note_created_absent_is_an_error() {
        assert!(note_created_from_logs(&["Program log: nope".to_string()]).is_err());
    }
}
