//! VALID_DEPOSIT vertical slice: real proof + SPL custody + Merkle append.

mod common;
mod settle_harness;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use borsh::BorshSerialize;
use darkpool_crypto::field::{fr_from_uniform_bytes, fr_to_be_bytes, pubkey_to_fr_pair};
use darkpool_crypto::note::commitment_from_fields_v2;
use darkpool_crypto::poseidon::poseidon_hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

use settle_harness::{
    compute_budget_ix, create_spl_mint, create_spl_token_account, merkle_tree_pda, spl_token_id,
    tree_leaf_count, vault_config_pda, Harness, Pubkey, SYSTEM_PROGRAM_ID,
};

const DEPOSIT_COMPUTE_LIMIT: u32 = 300_000;
const DEPOSIT_CU_GATE: u64 = 240_000;
const DEPOSIT_TX_SIZE_GATE: usize = 900;

fn vault_token_pda(program_id: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"vault_token", mint.as_ref()], program_id).0
}

fn outstanding_mint_pda(program_id: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"outstanding_mint", mint.as_ref()], program_id).0
}

fn rent_sysvar_id() -> Pubkey {
    "SysvarRent111111111111111111111111111111111"
        .parse()
        .unwrap()
}

#[derive(Clone)]
struct DepositOpening {
    spending_key: Fr,
    r_owner: Fr,
    recovery_nonce: Fr,
    inner_hash: Fr,
    owner_commitment: Fr,
    commitment: [u8; 32],
}

fn opening(mint: &Pubkey, amount: u64) -> DepositOpening {
    let spending_key = fr_from_uniform_bytes(&[0x31; 32]);
    let r_owner = fr_from_uniform_bytes(&[0x42; 32]);
    let recovery_nonce = fr_from_uniform_bytes(&[0x53; 32]);
    let owner_commitment =
        poseidon_hash(&[Fr::from(1u64), spending_key, r_owner]).expect("owner hash");
    let inner_hash = poseidon_hash(&[Fr::from(27u64), owner_commitment, recovery_nonce])
        .expect("deposit inner hash");
    let commitment = commitment_from_fields_v2(
        &mint.to_bytes(),
        amount,
        &fr_to_be_bytes(&owner_commitment),
        &fr_to_be_bytes(&inner_hash),
    )
    .expect("note commitment");
    DepositOpening {
        spending_key,
        r_owner,
        recovery_nonce,
        inner_hash,
        owner_commitment,
        commitment,
    }
}

fn valid_deposit_proof(
    mint: &Pubkey,
    amount: u64,
    opening: &DepositOpening,
) -> vault::zk::Groth16Proof {
    let [mint_lo, mint_hi] = pubkey_to_fr_pair(&mint.to_bytes());
    let input = format!(
        "{{\n  \"noteCommitment\": \"{commitment}\",\n  \"tokenMint\": [\"{mint_lo}\", \"{mint_hi}\"],\n  \"amount\": \"{amount}\",\n  \"recoveryNonce\": \"{nonce}\",\n  \"spendingKey\": \"{spending}\",\n  \"ownerCommitmentBlinding\": \"{r_owner}\"\n}}",
        commitment = common::fr_to_dec(&Fr::from_be_bytes_mod_order(&opening.commitment)),
        mint_lo = common::fr_to_dec(&mint_lo),
        mint_hi = common::fr_to_dec(&mint_hi),
        nonce = common::fr_to_dec(&opening.recovery_nonce),
        spending = common::fr_to_dec(&opening.spending_key),
        r_owner = common::fr_to_dec(&opening.r_owner),
    );
    let build = common::repo_root().join("circuits/build/valid_deposit");
    let tmp = std::env::temp_dir().join("nyx_valid_deposit_litesvm");
    let (proof, public) = common::snarkjs_fullprove(&input, &build, &tmp);
    let [mint_lo_bytes, mint_hi_bytes] = pubkey_pair_be32(&mint.to_bytes());
    let mut amount_bytes = [0u8; 32];
    amount_bytes[24..].copy_from_slice(&amount.to_be_bytes());
    assert_eq!(
        public,
        vec![
            opening.commitment,
            mint_lo_bytes,
            mint_hi_bytes,
            amount_bytes,
            fr_to_be_bytes(&opening.recovery_nonce),
        ],
        "VALID_DEPOSIT public-input ordering drifted",
    );
    vault::zk::Groth16Proof {
        pi_a: proof.pi_a,
        pi_b: proof.pi_b,
        pi_c: proof.pi_c,
    }
}

fn pubkey_pair_be32(pk: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut lo = [0u8; 32];
    lo[16..].copy_from_slice(&pk[16..]);
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&pk[..16]);
    [lo, hi]
}

struct DepositTxArgs<'a> {
    h: &'a Harness,
    depositor: &'a Keypair,
    depositor_token: Pubkey,
    mint: Pubkey,
    amount: u64,
    opening: &'a DepositOpening,
    proof: &'a vault::zk::Groth16Proof,
    wire_commitment: Option<[u8; 32]>,
    wire_recovery_nonce: Option<[u8; 32]>,
}

fn deposit_tx(args: DepositTxArgs<'_>) -> Transaction {
    let (vault_config, _) = vault_config_pda(&args.h.vault_id);
    let (tree, _) = merkle_tree_pda(&args.h.vault_id, 0);
    let mut data = common::anchor_disc("deposit").to_vec();
    data.push(0);
    data.extend_from_slice(&args.amount.to_le_bytes());
    data.extend_from_slice(&args.wire_commitment.unwrap_or(args.opening.commitment));
    data.extend_from_slice(
        &args
            .wire_recovery_nonce
            .unwrap_or_else(|| fr_to_be_bytes(&args.opening.recovery_nonce)),
    );
    args.proof.serialize(&mut data).unwrap();

    let deposit = Instruction {
        program_id: args.h.vault_id,
        accounts: vec![
            AccountMeta::new(args.depositor.pubkey(), true),
            AccountMeta::new_readonly(vault_config, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(args.mint, false),
            AccountMeta::new(args.depositor_token, false),
            AccountMeta::new(vault_token_pda(&args.h.vault_id, &args.mint), false),
            AccountMeta::new(outstanding_mint_pda(&args.h.vault_id, &args.mint), false),
            AccountMeta::new_readonly(spl_token_id(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(rent_sysvar_id(), false),
        ],
        data,
    };
    Transaction::new(
        &[args.depositor],
        Message::new(
            &[compute_budget_ix(DEPOSIT_COMPUTE_LIMIT), deposit],
            Some(&args.depositor.pubkey()),
        ),
        args.h.svm.latest_blockhash(),
    )
}

fn token_amount(h: &Harness, account: &Pubkey) -> u64 {
    let data = h.svm.get_account(account).expect("token account").data;
    u64::from_le_bytes(data[64..72].try_into().unwrap())
}

#[test]
fn valid_deposit_meets_size_and_cu_gates_and_invalid_proof_is_atomic() {
    let mut h = Harness::setup();
    let depositor = Keypair::new();
    h.svm
        .airdrop(&depositor.pubkey(), 10_000_000_000)
        .expect("fund depositor");
    let mint = create_spl_mint(&mut h, 6);
    let amount = 5_015_000u64;
    let depositor_token = create_spl_token_account(&mut h, &mint, &depositor.pubkey(), amount * 2);
    let opening = opening(&mint, amount);
    let proof = valid_deposit_proof(&mint, amount, &opening);
    let tx = deposit_tx(DepositTxArgs {
        h: &h,
        depositor: &depositor,
        depositor_token,
        mint,
        amount,
        opening: &opening,
        proof: &proof,
        wire_commitment: None,
        wire_recovery_nonce: None,
    });
    let tx_size = bincode::serialize(&tx)
        .expect("serialize transaction")
        .len();
    assert!(
        tx_size <= DEPOSIT_TX_SIZE_GATE,
        "proof deposit transaction is {tx_size} bytes; gate is {DEPOSIT_TX_SIZE_GATE}",
    );

    let meta = h.svm.send_transaction(tx).expect("proof deposit succeeds");
    println!(
        "VALID_DEPOSIT_GATE constraints=2501 tx_bytes={tx_size} cu={}",
        meta.compute_units_consumed
    );
    assert!(
        meta.compute_units_consumed <= DEPOSIT_CU_GATE,
        "proof deposit used {} CU; gate is {DEPOSIT_CU_GATE}",
        meta.compute_units_consumed,
    );
    assert_eq!(tree_leaf_count(&h, 0), 1);
    assert_eq!(token_amount(&h, &depositor_token), amount);
    let vault_token = vault_token_pda(&h.vault_id, &mint);
    assert_eq!(token_amount(&h, &vault_token), amount);

    // Reuse the proof but alter the instruction amount. Verification must fail
    // and the transaction must leave custody and the Merkle tree unchanged.
    let invalid = deposit_tx(DepositTxArgs {
        h: &h,
        depositor: &depositor,
        depositor_token,
        mint,
        amount: amount + 1,
        opening: &opening,
        proof: &proof,
        wire_commitment: None,
        wire_recovery_nonce: None,
    });
    assert!(h.svm.send_transaction(invalid).is_err());
    assert_eq!(tree_leaf_count(&h, 0), 1);
    assert_eq!(token_amount(&h, &depositor_token), amount);
    assert_eq!(token_amount(&h, &vault_token), amount);

    let mut altered_commitment = opening.commitment;
    altered_commitment[31] ^= 1;
    let invalid = deposit_tx(DepositTxArgs {
        h: &h,
        depositor: &depositor,
        depositor_token,
        mint,
        amount,
        opening: &opening,
        proof: &proof,
        wire_commitment: Some(altered_commitment),
        wire_recovery_nonce: None,
    });
    assert!(h.svm.send_transaction(invalid).is_err());
    assert_eq!(tree_leaf_count(&h, 0), 1);
    assert_eq!(token_amount(&h, &depositor_token), amount);
    assert_eq!(token_amount(&h, &vault_token), amount);

    let mut altered_nonce = fr_to_be_bytes(&opening.recovery_nonce);
    altered_nonce[31] ^= 1;
    let invalid = deposit_tx(DepositTxArgs {
        h: &h,
        depositor: &depositor,
        depositor_token,
        mint,
        amount,
        opening: &opening,
        proof: &proof,
        wire_commitment: None,
        wire_recovery_nonce: Some(altered_nonce),
    });
    assert!(h.svm.send_transaction(invalid).is_err());
    assert_eq!(tree_leaf_count(&h, 0), 1);
    assert_eq!(token_amount(&h, &depositor_token), amount);
    assert_eq!(token_amount(&h, &vault_token), amount);

    let wrong_mint = create_spl_mint(&mut h, 6);
    let wrong_mint_token =
        create_spl_token_account(&mut h, &wrong_mint, &depositor.pubkey(), amount);
    let invalid = deposit_tx(DepositTxArgs {
        h: &h,
        depositor: &depositor,
        depositor_token: wrong_mint_token,
        mint: wrong_mint,
        amount,
        opening: &opening,
        proof: &proof,
        wire_commitment: None,
        wire_recovery_nonce: None,
    });
    assert!(h.svm.send_transaction(invalid).is_err());
    assert_eq!(tree_leaf_count(&h, 0), 1);
    assert_eq!(token_amount(&h, &wrong_mint_token), amount);

    // Pin the hidden opening construction used by the successful commitment.
    assert_eq!(
        opening.inner_hash,
        poseidon_hash(&[
            Fr::from(27u64),
            opening.owner_commitment,
            opening.recovery_nonce,
        ])
        .unwrap(),
    );
}
