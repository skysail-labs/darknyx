//! Phase-3 governance setter: `set_tee_pubkey`
//!
//! Verifies:
//!   - happy path rotates `vault_config.tee_pubkey`
//!   - non-admin signer is rejected
//!
//! Needed so a freshly-deployed CVM (new dstack-derived signer) can be
//! pointed at without re-initialising the vault.

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
const VAULT_PROGRAM_ID_BYTES: &str = "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";

// VaultConfig layout: 8-byte Anchor disc + admin(32) + tee_pubkey(32) …
// so tee_pubkey occupies bytes [40..72].
const TEE_PUBKEY_OFFSET: usize = 8 + 32;

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
}

/// Initialise, returning `(vault_pda, initial_tee_pubkey)`.
fn initialize(svm: &mut LiteSVM, admin: &Keypair, program_id: &Pubkey) -> (Pubkey, [u8; 32]) {
    let tee_kp = Keypair::new();
    let root_kp = Keypair::new();
    let (vault_pda, _) = vault_config_pda(program_id);

    let mut data = common::anchor_disc("initialize").to_vec();
    InitializeArgs {
        tee_pubkey: tee_kp.pubkey().to_bytes(),
        root_key: root_kp.pubkey().to_bytes(),
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
    (vault_pda, tee_kp.pubkey().to_bytes())
}

fn build_set_tee_pubkey_ix(
    program_id: &Pubkey,
    admin: &Pubkey,
    vault_pda: &Pubkey,
    new_tee_pubkey: [u8; 32],
) -> Instruction {
    let mut data = common::anchor_disc("set_tee_pubkey").to_vec();
    data.extend_from_slice(&new_tee_pubkey); // Pubkey == raw 32 bytes (Borsh)
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*admin, true),
            AccountMeta::new(*vault_pda, false),
        ],
        data,
    }
}

fn load_svm() -> (LiteSVM, Pubkey) {
    let mut svm = LiteSVM::new();
    let program_id: Pubkey = VAULT_PROGRAM_ID_BYTES.parse().unwrap();
    svm.add_program_from_file(program_id, program_so_path())
        .unwrap();
    (svm, program_id)
}

#[test]
fn set_tee_pubkey_happy_path_rotates_the_signer() {
    let program_path = program_so_path();
    assert!(
        program_path.exists(),
        "run `cargo build-sbf --manifest-path programs/vault/Cargo.toml` first"
    );

    let (mut svm, program_id) = load_svm();
    let admin = Keypair::new();
    svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
    let (vault_pda, initial) = initialize(&mut svm, &admin, &program_id);

    let new_signer = Keypair::new().pubkey().to_bytes();
    assert_ne!(initial, new_signer);

    let ix = build_set_tee_pubkey_ix(&program_id, &admin.pubkey(), &vault_pda, new_signer);
    let tx = Transaction::new(
        &[&admin],
        Message::new(&[ix], Some(&admin.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("set_tee_pubkey failed");

    let acct = svm.get_account(&vault_pda).expect("vault config");
    let stored = &acct.data[TEE_PUBKEY_OFFSET..TEE_PUBKEY_OFFSET + 32];
    assert_eq!(stored, new_signer, "tee_pubkey was not rotated");
}

#[test]
fn set_tee_pubkey_rejects_non_admin_signer() {
    let program_path = program_so_path();
    if !program_path.exists() {
        return;
    }

    let (mut svm, program_id) = load_svm();
    let admin = Keypair::new();
    let impostor = Keypair::new();
    svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
    svm.airdrop(&impostor.pubkey(), 1_000_000_000).unwrap();
    let (vault_pda, _) = initialize(&mut svm, &admin, &program_id);

    let ix = build_set_tee_pubkey_ix(
        &program_id,
        &impostor.pubkey(),
        &vault_pda,
        Keypair::new().pubkey().to_bytes(),
    );
    let tx = Transaction::new(
        &[&impostor],
        Message::new(&[ix], Some(&impostor.pubkey())),
        svm.latest_blockhash(),
    );
    assert!(
        svm.send_transaction(tx).is_err(),
        "non-admin must be rejected, but set_tee_pubkey succeeded"
    );
}
