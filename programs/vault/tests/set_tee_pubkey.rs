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
// Derived from the program crate, NOT hand-copied. A literal here silently
// desynchronises from declare_id!(): the harness then loads the .so at an
// address the binary does not claim, and every settle-path test fails with
// IncorrectProgramId. That is exactly what happened when the v2 experiment
// moved to its own program id.
fn vault_program_id() -> anchor_lang::prelude::Address {
    vault::ID
}

// VaultConfig layout: 8-byte Anchor disc + admin(32) + tee_pubkey(32) …
// so tee_pubkey occupies bytes [40..72].
const TEE_PUBKEY_OFFSET: usize = 8 + 32;

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

/// Initialise, returning `(vault_pda, initial_tee_pubkey)`.
fn initialize(svm: &mut LiteSVM, admin: &Keypair, program_id: &Pubkey) -> (Pubkey, [u8; 32]) {
    initialize_with_num_trees(svm, admin, program_id, 1)
}

fn initialize_with_num_trees(
    svm: &mut LiteSVM,
    admin: &Keypair,
    program_id: &Pubkey,
    num_trees: u8,
) -> (Pubkey, [u8; 32]) {
    let tee_pubkeys: Vec<[u8; 32]> = (0..num_trees)
        .map(|_| Keypair::new().pubkey().to_bytes())
        .collect();
    let initial = tee_pubkeys[0];
    let root_kp = Keypair::new();
    let (vault_pda, _) = vault_config_pda(program_id);

    let mut data = common::anchor_disc("initialize").to_vec();
    InitializeArgs {
        operations_admin: admin.pubkey().to_bytes(),
        tee_pubkeys,
        root_key: root_kp.pubkey().to_bytes(),
        num_trees,
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
    (vault_pda, initial)
}

fn build_set_tee_pubkey_ix(
    program_id: &Pubkey,
    admin: &Pubkey,
    vault_pda: &Pubkey,
    new_tee_pubkey: [u8; 32],
) -> Instruction {
    let mut data = common::anchor_disc("set_tee_pubkey").to_vec();
    // The arg is now `keys: Vec<Pubkey>` (the K-key set). Borsh-encode a
    // single-element vec: 4-byte LE length prefix + the 32-byte key.
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&new_tee_pubkey);
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
    let program_id: Pubkey = vault_program_id();
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

#[test]
fn set_tee_pubkey_rejects_count_that_differs_from_num_trees() {
    if !program_so_path().exists() {
        return;
    }
    let (mut svm, program_id) = load_svm();
    let admin = Keypair::new();
    svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
    let (vault_pda, _) = initialize_with_num_trees(&mut svm, &admin, &program_id, 2);

    let one_key = [Keypair::new().pubkey().to_bytes()];
    let ix = build_set_tee_pubkeys_ix(&program_id, &admin.pubkey(), &vault_pda, &one_key);
    let tx = Transaction::new(
        &[&admin],
        Message::new(&[ix], Some(&admin.pubkey())),
        svm.latest_blockhash(),
    );
    assert!(
        svm.send_transaction(tx).is_err(),
        "TEE key count must equal num_trees",
    );
}

/// Build a `set_tee_pubkey` ix over an arbitrary K-key set (Borsh `Vec<Pubkey>`).
fn build_set_tee_pubkeys_ix(
    program_id: &Pubkey,
    admin: &Pubkey,
    vault_pda: &Pubkey,
    keys: &[[u8; 32]],
) -> Instruction {
    let mut data = common::anchor_disc("set_tee_pubkey").to_vec();
    data.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in keys {
        data.extend_from_slice(k);
    }
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*admin, true),
            AccountMeta::new(*vault_pda, false),
        ],
        data,
    }
}

// F-09: the zero (default) key is unusable — it would never authorize a real
// signer — so `set_tee_pubkey` must reject it.
#[test]
fn set_tee_pubkey_rejects_zero_key() {
    if !program_so_path().exists() {
        return;
    }
    let (mut svm, program_id) = load_svm();
    let admin = Keypair::new();
    svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
    let (vault_pda, _) = initialize(&mut svm, &admin, &program_id);

    let ix = build_set_tee_pubkeys_ix(&program_id, &admin.pubkey(), &vault_pda, &[[0u8; 32]]);
    let tx = Transaction::new(
        &[&admin],
        Message::new(&[ix], Some(&admin.pubkey())),
        svm.latest_blockhash(),
    );
    assert!(
        svm.send_transaction(tx).is_err(),
        "the zero tee_pubkey must be rejected",
    );
}

#[test]
fn set_tee_pubkey_rejects_operations_admin_as_signer() {
    if !program_so_path().exists() {
        return;
    }
    let (mut svm, program_id) = load_svm();
    let admin = Keypair::new();
    svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
    let (vault_pda, _) = initialize(&mut svm, &admin, &program_id);

    let ix = build_set_tee_pubkeys_ix(
        &program_id,
        &admin.pubkey(),
        &vault_pda,
        &[admin.pubkey().to_bytes()],
    );
    let tx = Transaction::new(
        &[&admin],
        Message::new(&[ix], Some(&admin.pubkey())),
        svm.latest_blockhash(),
    );
    assert!(svm.send_transaction(tx).is_err());
}

// F-09: a duplicate key silently shrinks the effective authorized set + corrupts
// the shard→key round-robin (keys[j] settles shard j) — reject it.
#[test]
fn set_tee_pubkey_rejects_duplicate_keys() {
    if !program_so_path().exists() {
        return;
    }
    let (mut svm, program_id) = load_svm();
    let admin = Keypair::new();
    svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
    let (vault_pda, _) = initialize_with_num_trees(&mut svm, &admin, &program_id, 2);

    let k = Keypair::new().pubkey().to_bytes();
    let ix = build_set_tee_pubkeys_ix(&program_id, &admin.pubkey(), &vault_pda, &[k, k]);
    let tx = Transaction::new(
        &[&admin],
        Message::new(&[ix], Some(&admin.pubkey())),
        svm.latest_blockhash(),
    );
    assert!(
        svm.send_transaction(tx).is_err(),
        "a duplicate tee_pubkey must be rejected",
    );
}
