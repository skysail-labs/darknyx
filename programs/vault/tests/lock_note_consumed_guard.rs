//! U-02 — `lock_note` must reject a note-use tag that has already been consumed
//! (settled or withdrawn). The tag-keyed `ConsumedNoteEntry` is the
//! shared consume-once guard; a note whose entry exists but whose Merkle leaf
//! survives could otherwise be re-locked by an authorized TEE holding a stale
//! VALID_INPUT proof (rent waste + stuck state).
//!
//! The guard fires BEFORE Groth16 verification, so this differential test needs
//! no real proof: with an identical dummy proof, a consumed tag is
//! rejected `NoteAlreadyConsumed` while an unconsumed one gets PAST the guard
//! and fails later at `InvalidProof` — proving the guard keys exactly on
//! consumed-ness.

mod common;
mod settle_harness;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use common::{fr_to_dec, repo_root, snarkjs_fullprove, ProofBytes};
use darkpool_crypto::field::{fr_to_be_bytes, pubkey_to_fr_pair};
use darkpool_crypto::poseidon::poseidon_hash;
use settle_harness::*;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use vault::merkle::{append_leaf, compute_zero_subtree_roots, empty_root};
use vault::state::{MerkleTree, MERKLE_DEPTH, ROOT_HISTORY_SIZE};

struct ValidLockFixture {
    note_use_tag: [u8; 32],
    token_mint: [u8; 32],
    merkle_root: [u8; 32],
    proof: ProofBytes,
}

fn prove_valid_lock(h: &mut Harness) -> ValidLockFixture {
    let spending_key = Fr::from(0x1234u64);
    let owner_blinding = Fr::from(0x5678u64);
    let inner_hash = Fr::from(0x9ABCu64);
    let amount = 5_000_000u64;
    let token_mint = h.test_mint.to_bytes();
    let [mint_lo, mint_hi] = pubkey_to_fr_pair(&token_mint);
    let owner_commitment =
        poseidon_hash(&[Fr::from(1u64), spending_key, owner_blinding]).expect("owner commitment");
    let commitment = poseidon_hash(&[
        Fr::from(2u64),
        mint_lo,
        mint_hi,
        Fr::from(amount),
        owner_commitment,
        inner_hash,
    ])
    .expect("note commitment");
    let commitment_bytes = fr_to_be_bytes(&commitment);
    let note_use_tag = darkpool_crypto::note_use_tag(
        &darkpool_crypto::NoteCommitment::from_bytes(commitment_bytes).unwrap(),
        &fr_to_be_bytes(&inner_hash),
    )
    .unwrap()
    .into_bytes();

    let zero_subtree_roots = compute_zero_subtree_roots().unwrap();
    let mut tree = MerkleTree {
        leaf_count: 0u64.into(),
        current_root: empty_root(&zero_subtree_roots).unwrap(),
        roots: [[0u8; 32]; ROOT_HISTORY_SIZE],
        right_path: [[0u8; 32]; MERKLE_DEPTH as usize],
        roots_head: 0,
        tree_id: 0,
        bump: 0,
        _padding: [0u8; 5],
    };
    let merkle_root = append_leaf(&mut tree, &zero_subtree_roots, commitment_bytes).unwrap();
    let (tree_pda, bump) = merkle_tree_pda(&h.vault_id, 0);
    tree.bump = bump;
    let mut tree_account = h.svm.get_account(&tree_pda).expect("merkle tree account");
    tree_account.data[8..].copy_from_slice(bytemuck::bytes_of(&tree));
    h.svm.set_account(tree_pda, tree_account).unwrap();

    let path = zero_subtree_roots
        .iter()
        .map(|value| format!("\"{}\"", fr_to_dec(&Fr::from_be_bytes_mod_order(value))))
        .collect::<Vec<_>>()
        .join(", ");
    let indices = vec!["\"0\""; MERKLE_DEPTH as usize].join(", ");
    let input_json = format!(
        "{{\n\
           \"merkleRoot\": \"{root}\",\n\
           \"noteUseTag\": \"{tag}\",\n\
           \"tokenMint\": [\"{mint_lo}\", \"{mint_hi}\"],\n\
           \"amount\": \"{amount}\",\n\
           \"spendingKey\": \"{spending_key}\",\n\
           \"ownerCommitmentBlinding\": \"{owner_blinding}\",\n\
           \"innerHash\": \"{inner_hash}\",\n\
           \"merklePath\": [{path}],\n\
           \"merkleIndices\": [{indices}]\n\
         }}",
        root = fr_to_dec(&Fr::from_be_bytes_mod_order(&merkle_root)),
        tag = fr_to_dec(&Fr::from_be_bytes_mod_order(&note_use_tag)),
        mint_lo = fr_to_dec(&mint_lo),
        mint_hi = fr_to_dec(&mint_hi),
        spending_key = fr_to_dec(&spending_key),
        owner_blinding = fr_to_dec(&owner_blinding),
        inner_hash = fr_to_dec(&inner_hash),
    );
    let build = repo_root().join("circuits/build/valid_input");
    let tmp = std::env::temp_dir().join(format!("darknyx_lock_note_verify_{}", std::process::id()));
    let (proof, public_inputs) = snarkjs_fullprove(&input_json, &build, &tmp);
    assert_eq!(
        public_inputs,
        vec![
            merkle_root,
            note_use_tag,
            fr_to_be_bytes(&mint_lo),
            fr_to_be_bytes(&mint_hi),
        ]
    );

    ValidLockFixture {
        note_use_tag,
        token_mint,
        merkle_root,
        proof,
    }
}

/// Build a `lock_note` ix for `note_use_tag`, signed by the authorized TEE
/// key, with a syntactically-sized but invalid dummy proof and a recent root
/// (so the handler reaches the U-02 guard / proof verification rather than
/// tripping the auth or root-recency check first).
fn build_lock_note_ix(h: &Harness, note_use_tag: &[u8; 32]) -> Instruction {
    build_lock_note_ix_with(
        h,
        note_use_tag,
        h.test_mint.to_bytes(),
        tree_current_root(h, 0),
        &ProofBytes {
            pi_a: [0u8; 64],
            pi_b: [0u8; 128],
            pi_c: [0u8; 64],
        },
    )
}

fn build_lock_note_ix_with(
    h: &Harness,
    note_use_tag: &[u8; 32],
    token_mint: [u8; 32],
    merkle_root: [u8; 32],
    proof: &ProofBytes,
) -> Instruction {
    let (vault_cfg, _) = vault_config_pda(&h.vault_id);
    let (merkle_tree, _) = merkle_tree_pda(&h.vault_id, 0);
    let (note_lock, _) = note_lock_pda(&h.vault_id, note_use_tag);
    let (consumed_note, _) = consumed_note_pda(&h.vault_id, note_use_tag);

    let mut data = Vec::with_capacity(385);
    data.extend_from_slice(&anchor_disc("lock_note"));
    data.push(0u8); // tree_id
    data.extend_from_slice(note_use_tag);
    data.extend_from_slice(&[0x22u8; 16]); // order_id
                                           // Relative to the CURRENT slot, not a hardcoded 1_000. litesvm 0.13 started
                                           // at slot 0 so the literal happened to satisfy `expiry_slot > clock.slot`;
                                           // 0.15 does not, and the ix then failed InvalidExpirySlot (6011) BEFORE
                                           // reaching the proof check this test is actually about.
    let now_slot = h.svm.get_sysvar::<solana_clock::Clock>().slot;
    data.extend_from_slice(&(now_slot + 1_000).to_le_bytes()); // expiry_slot (> slot, < slot + TTL)
    data.extend_from_slice(&token_mint);
    data.extend_from_slice(&merkle_root);
    data.extend_from_slice(&proof.pi_a);
    data.extend_from_slice(&proof.pi_b);
    data.extend_from_slice(&proof.pi_c);

    Instruction {
        program_id: h.vault_id,
        accounts: vec![
            AccountMeta::new(h.tee.pubkey(), true),
            AccountMeta::new_readonly(vault_cfg, false),
            AccountMeta::new_readonly(merkle_tree, false),
            AccountMeta::new(note_lock, false),
            AccountMeta::new_readonly(consumed_note, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

#[test]
fn valid_lock_uses_lean_layout_and_stays_within_cu_limit() {
    let mut h = Harness::setup();
    let fixture = prove_valid_lock(&mut h);
    let ix = build_lock_note_ix_with(
        &h,
        &fixture.note_use_tag,
        fixture.token_mint,
        fixture.merkle_root,
        &fixture.proof,
    );
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    let meta = h.svm.send_transaction(tx).expect("valid lock must succeed");
    let consumed = meta.compute_units_consumed;
    eprintln!("CU_PROFILE lock_note consumed={consumed}");
    assert!(consumed <= 136_000, "lock_note CU regression: {consumed}");

    let lock_pda = note_lock_pda(&h.vault_id, &fixture.note_use_tag).0;
    let lock = h.svm.get_account(&lock_pda).expect("lock account exists");
    assert_eq!(lock.data.len(), 72, "NoteLock must use the lean layout");
    assert_eq!(
        lock.lamports,
        h.svm.minimum_balance_for_rent_exemption(72),
        "NoteLock must fund exactly the lean account rent"
    );
}

fn send_lock_note(h: &mut Harness, note_use_tag: &[u8; 32]) -> Vec<String> {
    let ix = build_lock_note_ix(h, note_use_tag);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    match h.svm.send_transaction(tx) {
        Ok(_) => panic!("lock_note with a dummy proof must never succeed"),
        Err(e) => e.meta.logs,
    }
}

#[test]
fn lock_note_rejects_already_consumed_tag() {
    let mut h = Harness::setup();
    let consumed = fr_safe(0xC0, 0x01);

    // Simulate a prior settle/withdraw of this note.
    seed_consumed_note(&mut h, &consumed);
    assert!(consumed_note_exists(&h, &consumed));

    let logs = send_lock_note(&mut h, &consumed);
    assert!(
        logs_have_error_code(&logs.join("\n"), E_NOTE_ALREADY_CONSUMED),
        "expected NoteAlreadyConsumed rejection; logs:\n{}",
        logs.join("\n")
    );
}

#[test]
fn lock_note_allows_unconsumed_tag_past_the_guard() {
    let mut h = Harness::setup();
    let fresh = fr_safe(0xC0, 0x02);

    // No ConsumedNoteEntry — the guard must NOT fire; the same dummy proof
    // then fails at Groth16 verification, proving we got past U-02.
    assert!(!consumed_note_exists(&h, &fresh));

    let logs = send_lock_note(&mut h, &fresh);
    assert!(
        !logs_have_error_code(&logs.join("\n"), E_NOTE_ALREADY_CONSUMED),
        "U-02 guard must not fire for an unconsumed note; logs:\n{}",
        logs.join("\n")
    );
    assert!(
        logs_have_error_code(&logs.join("\n"), E_INVALID_PROOF),
        "expected the flow to reach + fail proof verification; logs:\n{}",
        logs.join("\n")
    );
}
