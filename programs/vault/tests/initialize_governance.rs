//! N-10/N-11 initialization and split-authority regressions.

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
const VAULT_PROGRAM_ID: &str = "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";

#[derive(BorshSerialize)]
struct InitializeArgs {
    operations_admin: [u8; 32],
    tee_pubkeys: Vec<[u8; 32]>,
    root_key: [u8; 32],
    num_trees: u8,
}

fn program_so_path() -> PathBuf {
    common::vault_program_so()
}

fn setup() -> (LiteSVM, Pubkey, Keypair, Pubkey) {
    let mut svm = LiteSVM::new();
    let program_id: Pubkey = VAULT_PROGRAM_ID.parse().unwrap();
    svm.add_program_from_file(program_id, program_so_path())
        .unwrap();
    let initializer = Keypair::new();
    svm.airdrop(&initializer.pubkey(), 2_000_000_000).unwrap();
    let (vault, _) = Pubkey::find_program_address(&[b"vault_config"], &program_id);
    (svm, program_id, initializer, vault)
}

fn initialize_ix(
    program_id: Pubkey,
    initializer: Pubkey,
    vault: Pubkey,
    args: InitializeArgs,
) -> Instruction {
    let mut data = common::anchor_disc("initialize").to_vec();
    args.serialize(&mut data).unwrap();
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(initializer, true),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

fn send_initialize(
    svm: &mut LiteSVM,
    initializer: &Keypair,
    ix: Instruction,
) -> Result<(), String> {
    let tx = Transaction::new(
        &[initializer],
        Message::new(&[ix], Some(&initializer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

#[test]
fn upgrade_initializer_can_install_a_distinct_operations_admin() {
    let (mut svm, program_id, initializer, vault) = setup();
    let operations_admin = Keypair::new().pubkey();
    assert_ne!(initializer.pubkey(), operations_admin);
    let tee_keys = vec![
        Keypair::new().pubkey().to_bytes(),
        Keypair::new().pubkey().to_bytes(),
    ];
    let ix = initialize_ix(
        program_id,
        initializer.pubkey(),
        vault,
        InitializeArgs {
            operations_admin: operations_admin.to_bytes(),
            tee_pubkeys: tee_keys.clone(),
            root_key: Keypair::new().pubkey().to_bytes(),
            num_trees: 2,
        },
    );
    send_initialize(&mut svm, &initializer, ix).unwrap();

    let data = svm.get_account(&vault).unwrap().data;
    assert_eq!(data.len(), 1264);
    assert_eq!(&data[8..40], operations_admin.as_ref());
    assert_eq!(&data[40..72], &tee_keys[0]);
    assert_eq!(&data[72..104], &tee_keys[1]);
    assert_eq!(data[1258], 2);
    assert_eq!(data[1259], 2);
}

#[test]
fn initialize_rejects_default_root_admin_and_tee_keys() {
    for case in ["admin", "root", "tee"] {
        let (mut svm, program_id, initializer, vault) = setup();
        let mut operations_admin = Keypair::new().pubkey().to_bytes();
        let mut root_key = Keypair::new().pubkey().to_bytes();
        let mut tee_key = Keypair::new().pubkey().to_bytes();
        match case {
            "admin" => operations_admin = [0u8; 32],
            "root" => root_key = [0u8; 32],
            "tee" => tee_key = [0u8; 32],
            _ => unreachable!(),
        }
        let ix = initialize_ix(
            program_id,
            initializer.pubkey(),
            vault,
            InitializeArgs {
                operations_admin,
                tee_pubkeys: vec![tee_key],
                root_key,
                num_trees: 1,
            },
        );
        assert!(
            send_initialize(&mut svm, &initializer, ix).is_err(),
            "default {case} key was accepted"
        );
    }
}

#[test]
fn initialize_rejects_partial_and_duplicate_shard_key_sets() {
    for duplicate in [false, true] {
        let (mut svm, program_id, initializer, vault) = setup();
        let key = Keypair::new().pubkey().to_bytes();
        let keys = if duplicate { vec![key, key] } else { vec![key] };
        let ix = initialize_ix(
            program_id,
            initializer.pubkey(),
            vault,
            InitializeArgs {
                operations_admin: Keypair::new().pubkey().to_bytes(),
                tee_pubkeys: keys,
                root_key: Keypair::new().pubkey().to_bytes(),
                num_trees: 2,
            },
        );
        assert!(send_initialize(&mut svm, &initializer, ix).is_err());
    }
}

#[test]
fn initialize_rejects_an_operations_admin_reused_as_root_key() {
    let (mut svm, program_id, initializer, vault) = setup();
    let shared = Keypair::new().pubkey().to_bytes();
    let ix = initialize_ix(
        program_id,
        initializer.pubkey(),
        vault,
        InitializeArgs {
            operations_admin: shared,
            tee_pubkeys: vec![Keypair::new().pubkey().to_bytes()],
            root_key: shared,
            num_trees: 1,
        },
    );
    assert!(send_initialize(&mut svm, &initializer, ix).is_err());
}

#[test]
fn initialize_rejects_tee_keys_reused_as_governance_authorities() {
    for reuse in ["admin", "root"] {
        let (mut svm, program_id, initializer, vault) = setup();
        let operations_admin = Keypair::new().pubkey().to_bytes();
        let root_key = Keypair::new().pubkey().to_bytes();
        let tee_key = if reuse == "admin" {
            operations_admin
        } else {
            root_key
        };
        let ix = initialize_ix(
            program_id,
            initializer.pubkey(),
            vault,
            InitializeArgs {
                operations_admin,
                tee_pubkeys: vec![tee_key],
                root_key,
                num_trees: 1,
            },
        );
        assert!(send_initialize(&mut svm, &initializer, ix).is_err());
    }
}

#[test]
fn root_rotation_rejects_default_and_accepts_a_real_successor() {
    let (mut svm, program_id, initializer, vault) = setup();
    let root = Keypair::new();
    let operations_admin = Keypair::new().pubkey();
    let tee = Keypair::new().pubkey();
    svm.airdrop(&root.pubkey(), 1_000_000_000).unwrap();
    let ix = initialize_ix(
        program_id,
        initializer.pubkey(),
        vault,
        InitializeArgs {
            operations_admin: operations_admin.to_bytes(),
            tee_pubkeys: vec![tee.to_bytes()],
            root_key: root.pubkey().to_bytes(),
            num_trees: 1,
        },
    );
    send_initialize(&mut svm, &initializer, ix).unwrap();

    let rotate_ix = |new_root_key: [u8; 32]| {
        let mut data = common::anchor_disc("rotate_root_key").to_vec();
        data.extend_from_slice(&new_root_key);
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(root.pubkey(), true),
                AccountMeta::new(vault, false),
            ],
            data,
        }
    };
    for invalid in [
        [0u8; 32],
        root.pubkey().to_bytes(),
        operations_admin.to_bytes(),
        tee.to_bytes(),
    ] {
        let invalid_tx = Transaction::new(
            &[&root],
            Message::new(&[rotate_ix(invalid)], Some(&root.pubkey())),
            svm.latest_blockhash(),
        );
        assert!(svm.send_transaction(invalid_tx).is_err());
    }

    let successor = Keypair::new().pubkey();
    let success_tx = Transaction::new(
        &[&root],
        Message::new(&[rotate_ix(successor.to_bytes())], Some(&root.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(success_tx).unwrap();
    let data = svm.get_account(&vault).unwrap().data;
    assert_eq!(&data[552..584], successor.as_ref());
}
