//! Phase-5 governance setter: `set_protocol_config`
//!
//! Verifies:
//!   - happy path rewrites `protocol_owner_commitment` + `fee_rate_bps`
//!   - non-admin signer is rejected
//!   - `fee_rate_bps > 10_000` is rejected

mod common;

use std::path::PathBuf;

use borsh::BorshSerialize;
use litesvm::LiteSVM;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

type Pubkey = Address;
const SYSTEM_PROGRAM_ID: Pubkey = solana_system_interface::program::ID;

// Must match `declare_id!` in programs/vault/src/lib.rs. LiteSVM
// verifies the embedded declared id in target/deploy/vault.so against
// the id supplied to add_program_from_file and rejects mismatches.
// Derived from the program crate, NOT hand-copied. A literal here silently
// desynchronises from declare_id!(): the harness then loads the .so at an
// address the binary does not claim, and every settle-path test fails with
// IncorrectProgramId. That is exactly what happened when the v2 experiment
// moved to its own program id.
fn vault_program_id() -> anchor_lang::prelude::Address {
    vault::ID
}

fn program_so_path() -> PathBuf {
    common::vault_program_so()
}

fn vault_config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault_config"], program_id)
}

#[derive(BorshSerialize)]
struct InitializeArgs {
    operations_admin: [u8; 32],
    tee_pubkeys: Vec<[u8; 32]>,
    root_key: [u8; 32],
    num_trees: u8,
}

#[derive(BorshSerialize)]
struct SetProtocolConfigArgs {
    protocol_owner_commitment: [u8; 32],
    fee_rate_bps: u16,
}

fn initialize(svm: &mut LiteSVM, admin: &Keypair, program_id: &Pubkey) -> Pubkey {
    let tee_kp = Keypair::new();
    let root_kp = Keypair::new();
    let (vault_pda, _) = vault_config_pda(program_id);

    let mut data = common::anchor_disc("initialize").to_vec();
    InitializeArgs {
        operations_admin: admin.pubkey().to_bytes(),
        tee_pubkeys: vec![tee_kp.pubkey().to_bytes()],
        root_key: root_kp.pubkey().to_bytes(),
        num_trees: 1,
    }
    .serialize(&mut data)
    .unwrap();

    let ix = Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(vault_pda, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    };
    let tx = Transaction::new(
        &[admin],
        Message::new(&[ix], Some(&admin.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("initialize failed");
    vault_pda
}

fn build_set_protocol_config_ix(
    program_id: &Pubkey,
    admin: &Pubkey,
    vault_pda: &Pubkey,
    commitment: [u8; 32],
    fee_rate_bps: u16,
) -> Instruction {
    let mut data = common::anchor_disc("set_protocol_config").to_vec();
    SetProtocolConfigArgs {
        protocol_owner_commitment: commitment,
        fee_rate_bps,
    }
    .serialize(&mut data)
    .unwrap();

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*admin, true),
            AccountMeta::new(*vault_pda, false),
        ],
        data,
    }
}

#[test]
fn set_protocol_config_happy_path_writes_all_fields() {
    let program_path = program_so_path();
    assert!(
        program_path.exists(),
        "run `cargo build-sbf --manifest-path programs/vault/Cargo.toml` first"
    );

    let mut svm = LiteSVM::new();
    let program_id: Pubkey = vault_program_id();
    svm.add_program_from_file(program_id, &program_path)
        .unwrap();

    let admin = Keypair::new();
    svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
    let vault_pda = initialize(&mut svm, &admin, &program_id);

    let new_commitment = [0xCD; 32];
    let ix =
        build_set_protocol_config_ix(&program_id, &admin.pubkey(), &vault_pda, new_commitment, 42);
    let tx = Transaction::new(
        &[&admin],
        Message::new(&[ix], Some(&admin.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .expect("set_protocol_config failed");

    // Re-read the account raw and check the tail. VaultConfig layout tail is
    // owner(32) + fee(2) + key/tree/bump(3) + explicit padding(3) = 40 bytes.
    let acct = svm.get_account(&vault_pda).expect("vault config");
    let d = &acct.data;
    let len = d.len();
    let tail_commitment = &d[len - 40..len - 8];
    let tail_rate = u16::from_le_bytes(d[len - 8..len - 6].try_into().unwrap());
    assert_eq!(tail_commitment, new_commitment);
    assert_eq!(tail_rate, 42);
}

#[test]
fn set_protocol_config_rejects_non_admin_signer() {
    let program_path = program_so_path();
    if !program_path.exists() {
        return;
    }

    let mut svm = LiteSVM::new();
    let program_id: Pubkey = vault_program_id();
    svm.add_program_from_file(program_id, &program_path)
        .unwrap();

    let admin = Keypair::new();
    let impostor = Keypair::new();
    svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
    svm.airdrop(&impostor.pubkey(), 1_000_000_000).unwrap();
    let vault_pda = initialize(&mut svm, &admin, &program_id);

    let ix =
        build_set_protocol_config_ix(&program_id, &impostor.pubkey(), &vault_pda, [0x99; 32], 10);
    let tx = Transaction::new(
        &[&impostor],
        Message::new(&[ix], Some(&impostor.pubkey())),
        svm.latest_blockhash(),
    );
    let result = svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "non-admin must be rejected, but ix succeeded"
    );
}

#[test]
fn set_protocol_config_rejects_fee_rate_above_max() {
    let program_path = program_so_path();
    if !program_path.exists() {
        return;
    }

    let mut svm = LiteSVM::new();
    let program_id: Pubkey = vault_program_id();
    svm.add_program_from_file(program_id, &program_path)
        .unwrap();

    let admin = Keypair::new();
    svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
    let vault_pda = initialize(&mut svm, &admin, &program_id);

    let ix = build_set_protocol_config_ix(
        &program_id,
        &admin.pubkey(),
        &vault_pda,
        [0xAB; 32],
        10_001, // MAX + 1
    );
    let tx = Transaction::new(
        &[&admin],
        Message::new(&[ix], Some(&admin.pubkey())),
        svm.latest_blockhash(),
    );
    let result = svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "fee_rate_bps > 10000 must be rejected, but ix succeeded"
    );
}
