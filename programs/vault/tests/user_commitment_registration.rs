//! End-to-end (litesvm) test for `create_wallet`.
//!
//! Verifies Section 23.2.3's `test_user_commitment_registration` contract:
//! VALID_WALLET_CREATE proof + create_wallet() registers the correct commitment
//! on L1 and writes an on-chain `WalletEntry` account containing that
//! commitment byte-for-byte.
//!
//! Strategy:
//!   1. Load the compiled program from `target/deploy/vault.so` (must be built
//!      via `cargo build-sbf` first — script lives in `scripts/build-vault.sh`).
//!   2. Derive a MasterSeed, compute the User Commitment.
//!   3. Generate a Groth16 proof for VALID_WALLET_CREATE via snarkjs.
//!   4. Build an Anchor-compatible `create_wallet` instruction by hand
//!      (discriminator + Borsh-encoded args).
//!   5. Submit via litesvm.
//!   6. Read the `WalletEntry` PDA, skip the 8-byte discriminator, verify the
//!      first 32 bytes == commitment.

mod common;

use std::path::PathBuf;

use borsh::BorshSerialize;
use darkpool_crypto::{
    field::{fr_to_be_bytes, pubkey_to_fr_pair},
    keys::{derive_master_viewing_key, derive_spending_key, MasterSeed},
    user_commitment::{user_commitment_from_keys, UserCommitmentInputs},
    Fr,
};
use litesvm::LiteSVM;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

// The split Solana SDK: `Address` is the new name for `Pubkey`. The
// `solana-instruction` crate uses its own `Pubkey` alias that equals `Address`.
type Pubkey = Address;
const SYSTEM_PROGRAM_ID: Pubkey = solana_system_interface::program::ID;

// Must match `declare_id!` in programs/vault/src/lib.rs. LiteSVM
// verifies the embedded declared id in target/deploy/vault.so against
// the id supplied to add_program_from_file and rejects mismatches.
const VAULT_PROGRAM_ID_BYTES: &str = "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";

fn program_so_path() -> PathBuf {
    common::repo_root().join("target/deploy/vault.so")
}

#[derive(BorshSerialize)]
struct CreateWalletArgs {
    commitment: [u8; 32],
    proof: RawGroth16Proof,
}

/// Mirror of `vault::zk::verifier::Groth16Proof` for Borsh encoding. Keep the
/// field layout byte-for-byte identical.
#[derive(BorshSerialize)]
struct RawGroth16Proof {
    pi_a: [u8; 64],
    pi_b: [u8; 128],
    pi_c: [u8; 64],
}

#[derive(BorshSerialize)]
struct InitializeArgs {
    operations_admin: [u8; 32],
    tee_pubkeys: Vec<[u8; 32]>,
    root_key: [u8; 32],
    num_trees: u8,
}

fn vault_config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault_config"], program_id)
}

fn wallet_entry_pda(program_id: &Pubkey, commitment: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"wallet", commitment.as_ref()], program_id)
}

#[test]
fn test_user_commitment_registration() {
    let program_path = program_so_path();
    if !program_path.exists() {
        panic!(
            "program binary missing — run `cargo build-sbf --manifest-path programs/vault/Cargo.toml` first. Expected: {:?}",
            program_path
        );
    }

    // --- Set up LiteSVM + funded admin + program ---
    let mut svm = LiteSVM::new();
    let program_id: Pubkey = VAULT_PROGRAM_ID_BYTES.parse().expect("program id");
    svm.add_program_from_file(program_id, &program_path)
        .expect("load program");

    let admin = Keypair::new();
    svm.airdrop(&admin.pubkey(), 1_000_000_000)
        .expect("airdrop admin");

    let tee_kp = Keypair::new();
    let root_kp = Keypair::new();

    // --- Call `initialize` ---
    let (vault_pda, _bump) = vault_config_pda(&program_id);

    let mut init_data = common::anchor_disc("initialize").to_vec();
    let init_args = InitializeArgs {
        operations_admin: admin.pubkey().to_bytes(),
        tee_pubkeys: vec![tee_kp.pubkey().to_bytes()],
        root_key: root_kp.pubkey().to_bytes(),
        num_trees: 1,
    };
    init_args.serialize(&mut init_data).unwrap();

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(vault_pda, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: init_data,
    };
    let tx = Transaction::new(
        &[&admin],
        Message::new(&[ix], Some(&admin.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("initialize failed");

    // --- Compute User Commitment off-chain ---
    let mut seed_bytes = [0u8; 64];
    for (i, b) in seed_bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7);
    }
    let seed = MasterSeed::new(seed_bytes);
    let spending_key: Fr = derive_spending_key(&seed).unwrap();
    let viewing_key: Fr = derive_master_viewing_key(&seed).unwrap();

    let root_pubkey: [u8; 32] = admin.pubkey().to_bytes();
    let r0 = Fr::from(1u64);
    let r1 = Fr::from(2u64);
    let r2 = Fr::from(3u64);

    let uc = user_commitment_from_keys(&UserCommitmentInputs {
        root_key_pubkey: root_pubkey,
        spending_key,
        viewing_key,
        r0,
        r1,
        r2,
    })
    .unwrap();

    // --- Generate a VALID_WALLET_CREATE proof via snarkjs ---
    let [rk_lo, rk_hi] = pubkey_to_fr_pair(&root_pubkey);
    let input_json = format!(
        "{{\n  \"userCommitment\": \"{uc}\",\n  \"rootKey\": [\"{lo}\", \"{hi}\"],\n  \"spendingKey\": \"{sk}\",\n  \"viewingKey\": \"{vk}\",\n  \"r0\": \"{r0}\",\n  \"r1\": \"{r1}\",\n  \"r2\": \"{r2}\"\n}}",
        uc = common::fr_to_dec(&uc),
        lo = common::fr_to_dec(&rk_lo),
        hi = common::fr_to_dec(&rk_hi),
        sk = common::fr_to_dec(&spending_key),
        vk = common::fr_to_dec(&viewing_key),
        r0 = common::fr_to_dec(&r0),
        r1 = common::fr_to_dec(&r1),
        r2 = common::fr_to_dec(&r2),
    );
    let root = common::repo_root();
    let build = root.join("circuits/build/valid_wallet_create");
    let tmp = std::env::temp_dir().join("nyx_user_commit_registration");
    let (proof, public_inputs) = common::snarkjs_fullprove(&input_json, &build, &tmp);
    assert_eq!(public_inputs.len(), 1);
    let commitment_bytes: [u8; 32] = fr_to_be_bytes(&uc);
    assert_eq!(public_inputs[0], commitment_bytes);

    // --- Submit `create_wallet` ---
    let (wallet_pda, _) = wallet_entry_pda(&program_id, &commitment_bytes);

    let mut cw_data = common::anchor_disc("create_wallet").to_vec();
    let args = CreateWalletArgs {
        commitment: commitment_bytes,
        proof: RawGroth16Proof {
            pi_a: proof.pi_a,
            pi_b: proof.pi_b,
            pi_c: proof.pi_c,
        },
    };
    // Anchor's on-wire format for instruction args is plain Borsh after the
    // 8-byte discriminator. Fixed-size byte arrays are emitted inline (no
    // length prefix), so a single `args.serialize(...)` produces the exact
    // layout that #[program] expects.
    BorshSerialize::serialize(&args, &mut cw_data).unwrap();

    // Accounts: [owner(signer,mut), wallet_entry(init,mut), system_program(ro)].
    // CU-3 / audit F-07: the unused `vault_config` account was dropped from
    // `CreateWallet` — this list mirrors the new on-chain struct.
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(wallet_pda, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: cw_data,
    };
    let tx = Transaction::new(
        &[&admin],
        Message::new(&[ix], Some(&admin.pubkey())),
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);
    if let Err(ref e) = result {
        eprintln!("create_wallet logs:");
        for l in e.meta.logs.iter() {
            eprintln!("  {}", l);
        }
    }
    result.expect("create_wallet failed");

    // --- Verify on-chain WalletEntry has the correct commitment ---
    let acct = svm
        .get_account(&wallet_pda)
        .expect("wallet_entry must exist");
    assert!(
        acct.data.len() >= 8 + 32,
        "wallet entry account too small: {}",
        acct.data.len()
    );
    let stored_commitment: [u8; 32] = acct.data[8..40].try_into().unwrap();
    assert_eq!(
        stored_commitment, commitment_bytes,
        "on-chain WalletEntry.commitment must equal derived User Commitment"
    );
}
