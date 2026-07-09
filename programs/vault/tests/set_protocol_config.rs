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
const VAULT_PROGRAM_ID_BYTES: &str = "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";

fn program_so_path() -> PathBuf {
    common::repo_root().join("target/deploy/vault.so")
}

fn vault_config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault_config"], program_id)
}

#[derive(BorshSerialize)]
struct InitializeArgs {
    tee_pubkey: [u8; 32],
    root_key: [u8; 32],
    num_trees: u8,
}

#[derive(BorshSerialize)]
struct SetProtocolConfigArgs {
    protocol_owner_commitment: [u8; 32],
    fee_rate_bps: u16,
    tick_size: u64,
    min_order_size: u64,
    circuit_breaker_bps: u64,
}

fn initialize(svm: &mut LiteSVM, admin: &Keypair, program_id: &Pubkey) -> Pubkey {
    let tee_kp = Keypair::new();
    let root_kp = Keypair::new();
    let (vault_pda, _) = vault_config_pda(program_id);

    let mut data = common::anchor_disc("initialize").to_vec();
    InitializeArgs {
        tee_pubkey: tee_kp.pubkey().to_bytes(),
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

#[allow(clippy::too_many_arguments)]
fn build_set_protocol_config_ix(
    program_id: &Pubkey,
    admin: &Pubkey,
    vault_pda: &Pubkey,
    commitment: [u8; 32],
    fee_rate_bps: u16,
    tick_size: u64,
    min_order_size: u64,
    circuit_breaker_bps: u64,
) -> Instruction {
    let mut data = common::anchor_disc("set_protocol_config").to_vec();
    SetProtocolConfigArgs {
        protocol_owner_commitment: commitment,
        fee_rate_bps,
        tick_size,
        min_order_size,
        circuit_breaker_bps,
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
    let program_id: Pubkey = VAULT_PROGRAM_ID_BYTES.parse().unwrap();
    svm.add_program_from_file(program_id, &program_path)
        .unwrap();

    let admin = Keypair::new();
    svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
    let vault_pda = initialize(&mut svm, &admin, &program_id);

    let new_commitment = [0xCD; 32];
    let ix = build_set_protocol_config_ix(
        &program_id,
        &admin.pubkey(),
        &vault_pda,
        new_commitment,
        42,
        5,     // tick_size
        1_000, // min_order_size
        250,   // circuit_breaker_bps
    );
    let tx = Transaction::new(
        &[&admin],
        Message::new(&[ix], Some(&admin.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .expect("set_protocol_config failed");

    // Re-read the account raw and check the tail. VaultConfig layout tail:
    // protocol_owner_commitment([u8;32]) + fee_rate_bps(u16) + num_tee_keys(u8)
    // + num_trees(u8) + bump(u8) + _padding([u8;3]) + tick_size(u64)
    // + min_order_size(u64) + circuit_breaker_bps(u64)
    // = 32 + 2 + 1 + 1 + 1 + 3 + 8 + 8 + 8 = 64 trailing bytes; walk from the
    // end so we don't have to track Anchor's 8-byte disc.
    let acct = svm.get_account(&vault_pda).expect("vault config");
    let d = &acct.data;
    let len = d.len();
    let tail_commitment = &d[len - 64..len - 32];
    let tail_rate = u16::from_le_bytes(d[len - 32..len - 30].try_into().unwrap());
    let tick = u64::from_le_bytes(d[len - 24..len - 16].try_into().unwrap());
    let min_order = u64::from_le_bytes(d[len - 16..len - 8].try_into().unwrap());
    let cb = u64::from_le_bytes(d[len - 8..len].try_into().unwrap());
    assert_eq!(tail_commitment, new_commitment);
    assert_eq!(tail_rate, 42);
    assert_eq!(tick, 5);
    assert_eq!(min_order, 1_000);
    assert_eq!(cb, 250);
}

#[test]
fn set_protocol_config_rejects_non_admin_signer() {
    let program_path = program_so_path();
    if !program_path.exists() {
        return;
    }

    let mut svm = LiteSVM::new();
    let program_id: Pubkey = VAULT_PROGRAM_ID_BYTES.parse().unwrap();
    svm.add_program_from_file(program_id, &program_path)
        .unwrap();

    let admin = Keypair::new();
    let impostor = Keypair::new();
    svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
    svm.airdrop(&impostor.pubkey(), 1_000_000_000).unwrap();
    let vault_pda = initialize(&mut svm, &admin, &program_id);

    let ix = build_set_protocol_config_ix(
        &program_id,
        &impostor.pubkey(),
        &vault_pda,
        [0x99; 32],
        10,
        0,
        0,
        0,
    );
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
    let program_id: Pubkey = VAULT_PROGRAM_ID_BYTES.parse().unwrap();
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
        0,
        0,
        0,
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
