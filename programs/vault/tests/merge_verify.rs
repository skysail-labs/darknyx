//! VALID_MERGE(K) verify roundtrip — the §5 circuit↔VK↔on-chain-verifier check.
//!
//! Mirrors `zk_spend_roundtrip`: builds the Merkle tree in Rust (`append_leaf`),
//! shells out to snarkjs for a real proof, then verifies it with the COMMITTED
//! `vk_valid_merge_k{2,4}.rs` consts via `groth16-solana`. It also asserts the
//! public-signal ORDER matches what `merge.rs` builds. The full merge ix (PDA
//! creation + leaf append) is exercised end-to-end by `devnet-merge` — this test
//! pins the proof/VK chain, which is the part that breaks silently.

mod common;
mod settle_harness;

use ark_bn254::Fr;
use ark_ff::PrimeField;

use common::{fr_to_dec, repo_root, snarkjs_fullprove};
use darkpool_crypto::field::{fr_from_be_bytes, fr_to_be_bytes, pubkey_to_fr_pair, u64_to_fr};
use darkpool_crypto::merge_output_inner_hash;
use darkpool_crypto::poseidon::poseidon_hash;
use vault::merkle::{append_leaf, compute_zero_subtree_roots, empty_root};
use vault::state::{MerkleTree, MERKLE_DEPTH, ROOT_HISTORY_SIZE};
use vault::zk::verifier::{make_vk, Groth16Proof};
use vault::zk::verify_groth16_proof;

use settle_harness::{
    anchor_disc, consumed_note_exists, consumed_note_pda, merkle_tree_pda, note_lock_pda,
    seed_note_lock, tree_current_root, tree_leaf_count, vault_config_pda, Harness, Pubkey,
    SYSTEM_PROGRAM_ID,
};
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

const TREE_DEPTH: usize = 20;

// Fixed test owner.
fn owner_parts() -> (Fr, Fr, Fr) {
    let sk = Fr::from(0x1234_5678u64);
    let r_owner = Fr::from(0xfeedu64);
    let owner = poseidon_hash(&[Fr::from(1u64), sk, r_owner]).unwrap(); // DOMAIN_OWNER
    (sk, r_owner, owner)
}

fn fresh_tree() -> (MerkleTree, [[u8; 32]; MERKLE_DEPTH as usize]) {
    let zeros = compute_zero_subtree_roots().unwrap();
    let tree = MerkleTree {
        leaf_count: 0,
        current_root: empty_root(&zeros).unwrap(),
        roots: [[0u8; 32]; ROOT_HISTORY_SIZE],
        right_path: [[0u8; 32]; MERKLE_DEPTH as usize],
        roots_head: 0,
        tree_id: 0,
        bump: 0,
        _padding: [0u8; 5],
    };
    (tree, zeros)
}

/// Inclusion witness for `target_index` in a small dense tree padded to depth 20.
fn merkle_witness(leaves: &[[u8; 32]], target_index: usize) -> (Vec<[u8; 32]>, Vec<u8>) {
    let zero_subtree = compute_zero_subtree_roots().unwrap();
    let mut siblings = vec![[0u8; 32]; TREE_DEPTH];
    let mut path_indices = vec![0u8; TREE_DEPTH];

    let n = leaves.len();
    let mut small_depth = 0usize;
    while (1usize << small_depth) < n {
        small_depth += 1;
    }
    small_depth = small_depth.max(1);
    let padded = 1usize << small_depth;

    let mut level = leaves.to_vec();
    level.resize(padded, [0u8; 32]);

    let mut idx = target_index;
    for d in 0..small_depth {
        siblings[d] = level[idx ^ 1];
        path_indices[d] = (idx & 1) as u8;
        idx >>= 1;
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(vault::merkle::poseidon2(&pair[0], &pair[1]).unwrap());
        }
        level = next;
    }
    let mut current = level[0];
    for d in small_depth..TREE_DEPTH {
        siblings[d] = zero_subtree[d];
        path_indices[d] = 0;
        current = vault::merkle::poseidon2(&current, &zero_subtree[d]).unwrap();
    }
    let _ = current;
    (siblings, path_indices)
}

/// Build + prove a merge of `num_real` notes in a K-slot circuit.
/// Returns (proof, snarkjs public inputs, the values merge.rs would build).
#[allow(clippy::type_complexity)]
fn prove_merge(
    k: usize,
    num_real: usize,
) -> (
    Groth16Proof,
    Vec<[u8; 32]>,
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    Vec<[u8; 32]>,
) {
    assert!(num_real >= 1 && num_real <= k);
    let (sk, r_owner, owner) = owner_parts();
    let mint_bytes = [0x07u8; 32];
    let [mint_lo, mint_hi] = pubkey_to_fr_pair(&mint_bytes);

    // Real notes: amounts 100, 200, 300, ... and distinct inner hashes.
    let amounts: Vec<u64> = (0..num_real).map(|i| 100u64 * (i as u64 + 1)).collect();
    let inners: Vec<Fr> = (0..num_real)
        .map(|i| Fr::from(0x11u64 + i as u64))
        .collect();

    // Commit each note + append to a fresh on-chain-style tree.
    let (mut tree, zsr) = fresh_tree();
    let mut commitments = vec![];
    let mut root = [0u8; 32];
    for i in 0..num_real {
        let c = poseidon_hash(&[
            Fr::from(2u64),
            mint_lo,
            mint_hi,
            u64_to_fr(amounts[i]),
            owner,
            inners[i],
        ])
        .unwrap();
        let cb = fr_to_be_bytes(&c);
        commitments.push(cb);
        root = append_leaf(&mut tree, &zsr, cb).unwrap();
    }

    // Per-slot witnesses (real) + dummies.
    let sum: u64 = amounts.iter().sum();

    let mut is_active = vec![];
    let mut amount_s = vec![];
    let mut inner_s = vec![];
    // C-01: the K input note commitments are the circuit's PUBLIC OUTPUTS —
    // active slots emit their real commitment (BE32), dummies emit 0. These are
    // what merge.rs consumes as commitment-keyed ConsumedNoteEntry guards.
    let mut input_commitments: Vec<[u8; 32]> = vec![];
    let mut paths: Vec<Vec<String>> = vec![];
    let mut indices: Vec<Vec<String>> = vec![];

    for i in 0..k {
        if i < num_real {
            let (sib, idx) = merkle_witness(&commitments, i);
            is_active.push("1".to_string());
            amount_s.push(amounts[i].to_string());
            inner_s.push(fr_to_dec(&inners[i]));
            input_commitments.push(commitments[i]);
            paths.push(
                sib.iter()
                    .map(|s| fr_to_dec(&Fr::from_be_bytes_mod_order(s)))
                    .collect(),
            );
            indices.push(idx.iter().map(|x| x.to_string()).collect());
        } else {
            is_active.push("0".to_string());
            amount_s.push("0".to_string());
            inner_s.push("0".to_string());
            input_commitments.push([0u8; 32]);
            paths.push(vec!["0".to_string(); TREE_DEPTH]);
            indices.push(vec!["0".to_string(); TREE_DEPTH]);
        }
    }

    let mut merge_slots = [[0u8; 32]; 4];
    merge_slots[..k].copy_from_slice(&input_commitments);
    let active_bitmap = (1u8 << num_real) - 1;
    let output_inner_bytes = merge_output_inner_hash(&merge_slots, active_bitmap).unwrap();
    let output_inner = fr_from_be_bytes(&output_inner_bytes).unwrap();
    let output_commitment = fr_to_be_bytes(
        &poseidon_hash(&[
            Fr::from(2u64),
            mint_lo,
            mint_hi,
            u64_to_fr(sum),
            owner,
            output_inner,
        ])
        .unwrap(),
    );

    let arr = |v: &[String]| {
        v.iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let arr2 = |v: &[Vec<String>]| {
        v.iter()
            .map(|row| format!("[{}]", arr(row)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let input_json = format!(
        "{{\n\
           \"merkleRoot\": \"{mr}\",\n\
           \"tokenMint\": [\"{mlo}\", \"{mhi}\"],\n\
           \"spendingKey\": \"{sk}\",\n\
           \"ownerCommitmentBlinding\": \"{ocb}\",\n\
           \"isActive\": [{act}],\n\
           \"amount\": [{amt}],\n\
           \"innerHash\": [{inr}],\n\
           \"merklePath\": [{paths}],\n\
           \"merkleIndices\": [{idxs}]\n\
         }}",
        mr = fr_to_dec(&Fr::from_be_bytes_mod_order(&root)),
        mlo = fr_to_dec(&mint_lo),
        mhi = fr_to_dec(&mint_hi),
        sk = fr_to_dec(&sk),
        ocb = fr_to_dec(&r_owner),
        act = arr(&is_active),
        amt = arr(&amount_s),
        inr = arr(&inner_s),
        paths = arr2(&paths),
        idxs = arr2(&indices),
    );

    let build = repo_root().join(format!("circuits/build/valid_merge_k{k}"));
    // Unique per call: `cargo test` runs the test fns in this binary in
    // parallel, and two of them (merge_k2_verifies_… + merge_rejects_tampered_…)
    // both prove_merge(2, 2). A shared dir name lets their concurrent snarkjs
    // runs clobber each other's input/proof/public files → flaky failures.
    // pid + a process-local counter is unique across threads AND processes
    // without pulling in a tempfile dep.
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let uniq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = std::env::temp_dir().join(format!(
        "darknyx_merge_verify_k{k}_{num_real}_{}_{uniq}",
        std::process::id()
    ));
    let (pb, public_inputs) = snarkjs_fullprove(&input_json, &build, &tmp);
    let proof = Groth16Proof {
        pi_a: pb.pi_a,
        pi_b: pb.pi_b,
        pi_c: pb.pi_c,
    };

    (
        proof,
        public_inputs,
        output_commitment,
        root,
        fr_to_be_bytes(&mint_lo),
        fr_to_be_bytes(&mint_hi),
        input_commitments,
    )
}

fn install_merge_input_tree(h: &mut Harness, commitments: &[[u8; 32]]) -> [u8; 32] {
    let (mut tree, zsr) = fresh_tree();
    let mut root = tree.current_root;
    for commitment in commitments.iter().filter(|c| **c != [0u8; 32]) {
        root = append_leaf(&mut tree, &zsr, *commitment).unwrap();
    }
    let (tree_pda, bump) = merkle_tree_pda(&h.vault_id, 0);
    tree.bump = bump;
    let mut account = h.svm.get_account(&tree_pda).expect("merkle tree account");
    let body = bytemuck::bytes_of(&tree);
    assert_eq!(account.data.len(), 8 + body.len());
    account.data[8..].copy_from_slice(body);
    h.svm.set_account(tree_pda, account).unwrap();
    root
}

fn build_merge_ix(
    h: &Harness,
    proof: &Groth16Proof,
    input_commitments: &[[u8; 32]],
    output_commitment: [u8; 32],
    merkle_root: [u8; 32],
) -> Instruction {
    let payer = h.trader.pubkey();
    let token_mint = Pubkey::from([0x07u8; 32]);
    let (vault_config, _) = vault_config_pda(&h.vault_id);
    let (merkle_tree, _) = merkle_tree_pda(&h.vault_id, 0);
    let active: Vec<_> = input_commitments
        .iter()
        .filter(|commitment| **commitment != [0u8; 32])
        .collect();

    let mut data = anchor_disc("merge").to_vec();
    data.push(0); // tree_id
    data.extend_from_slice(&(input_commitments.len() as u32).to_le_bytes());
    for commitment in input_commitments {
        data.extend_from_slice(commitment);
    }
    data.extend_from_slice(&output_commitment);
    data.extend_from_slice(token_mint.as_ref());
    data.extend_from_slice(&merkle_root);
    data.push(input_commitments.len() as u8); // k
    data.extend_from_slice(&proof.pi_a);
    data.extend_from_slice(&proof.pi_b);
    data.extend_from_slice(&proof.pi_c);

    let mut accounts = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new_readonly(vault_config, false),
        AccountMeta::new(merkle_tree, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];
    accounts.extend(
        active.iter().map(|commitment| {
            AccountMeta::new(consumed_note_pda(&h.vault_id, commitment).0, false)
        }),
    );
    accounts.extend(active.iter().map(|commitment| {
        AccountMeta::new_readonly(note_lock_pda(&h.vault_id, commitment).0, false)
    }));

    Instruction {
        program_id: h.vault_id,
        accounts,
        data,
    }
}

#[test]
fn merge_k2_verifies_and_public_order_matches() {
    let (proof, public_inputs, out_c, root, mlo, mhi, ics) = prove_merge(2, 2);

    // Public-signal order (must match merge.rs — C-01, outputs first):
    //   [outputCommitment, inputCommitments[0], inputCommitments[1], merkleRoot, mint_lo, mint_hi]
    assert_eq!(public_inputs.len(), 6);
    assert_eq!(public_inputs[0], out_c, "signal 0 must be outputCommitment");
    assert_eq!(
        public_inputs[1], ics[0],
        "signal 1 must be inputCommitments[0]"
    );
    assert_eq!(
        public_inputs[2], ics[1],
        "signal 2 must be inputCommitments[1]"
    );
    assert_eq!(public_inputs[3], root, "signal 3 must be merkleRoot");
    assert_eq!(public_inputs[4], mlo);
    assert_eq!(public_inputs[5], mhi);

    let pi: [[u8; 32]; 6] = public_inputs.try_into().unwrap();
    let vk = make_vk(
        &vault::zk::vk_valid_merge_k2::VALID_MERGE_K2_ALPHA_G1,
        &vault::zk::vk_valid_merge_k2::VALID_MERGE_K2_BETA_G2,
        &vault::zk::vk_valid_merge_k2::VALID_MERGE_K2_GAMMA_G2,
        &vault::zk::vk_valid_merge_k2::VALID_MERGE_K2_DELTA_G2,
        &vault::zk::vk_valid_merge_k2::VALID_MERGE_K2_IC,
    );
    verify_groth16_proof::<6>(&vk, &proof, &pi).expect("K=2 merge proof must verify");
}

#[test]
fn merge_k4_padded_verifies() {
    // 2 real notes + 2 dummy slots.
    let (proof, public_inputs, out_c, root, _mlo, _mhi, ics) = prove_merge(4, 2);
    // Order (C-01): [outputCommitment, inputCommitments[0..3], merkleRoot, mint_lo, mint_hi]
    assert_eq!(public_inputs.len(), 8);
    assert_eq!(public_inputs[0], out_c);
    assert_eq!(public_inputs[1], ics[0]);
    assert_eq!(public_inputs[2], ics[1]);
    // Dummy slots' public input-commitments are zero.
    assert_eq!(ics[2], [0u8; 32]);
    assert_eq!(ics[3], [0u8; 32]);
    assert_eq!(public_inputs[3], [0u8; 32]);
    assert_eq!(public_inputs[4], [0u8; 32]);
    assert_eq!(public_inputs[5], root);

    let pi: [[u8; 32]; 8] = public_inputs.try_into().unwrap();
    let vk = make_vk(
        &vault::zk::vk_valid_merge_k4::VALID_MERGE_K4_ALPHA_G1,
        &vault::zk::vk_valid_merge_k4::VALID_MERGE_K4_BETA_G2,
        &vault::zk::vk_valid_merge_k4::VALID_MERGE_K4_GAMMA_G2,
        &vault::zk::vk_valid_merge_k4::VALID_MERGE_K4_DELTA_G2,
        &vault::zk::vk_valid_merge_k4::VALID_MERGE_K4_IC,
    );
    verify_groth16_proof::<8>(&vk, &proof, &pi).expect("K=4 padded merge proof must verify");
}

#[test]
fn merge_rejects_tampered_proof() {
    let (mut proof, public_inputs, ..) = prove_merge(2, 2);
    let pi: [[u8; 32]; 6] = public_inputs.try_into().unwrap();
    let vk = make_vk(
        &vault::zk::vk_valid_merge_k2::VALID_MERGE_K2_ALPHA_G1,
        &vault::zk::vk_valid_merge_k2::VALID_MERGE_K2_BETA_G2,
        &vault::zk::vk_valid_merge_k2::VALID_MERGE_K2_GAMMA_G2,
        &vault::zk::vk_valid_merge_k2::VALID_MERGE_K2_DELTA_G2,
        &vault::zk::vk_valid_merge_k2::VALID_MERGE_K2_IC,
    );
    proof.pi_c[0] ^= 0x01;
    assert!(
        verify_groth16_proof::<6>(&vk, &proof, &pi).is_err(),
        "a mutated proof must not verify"
    );
}

#[test]
fn merge_rejects_locked_input_before_consuming_any_note() {
    let (proof, _public_inputs, output, root, _mlo, _mhi, commitments) = prove_merge(2, 2);

    let mut locked = Harness::setup();
    assert_eq!(install_merge_input_tree(&mut locked, &commitments), root);
    seed_note_lock(&mut locked, &commitments[0], &[0x44u8; 16], 1_000_000, 0);
    let locked_ix = build_merge_ix(&locked, &proof, &commitments, output, root);
    let locked_tx = Transaction::new(
        &[&locked.trader],
        Message::new(&[locked_ix], Some(&locked.trader.pubkey())),
        locked.svm.latest_blockhash(),
    );
    assert!(
        locked.svm.send_transaction(locked_tx).is_err(),
        "merge must reject when any active input has a NoteLock"
    );
    assert_eq!(tree_leaf_count(&locked, 0), 2);
    assert!(!consumed_note_exists(&locked, &commitments[0]));
    assert!(!consumed_note_exists(&locked, &commitments[1]));

    // The same proof and inputs succeed when both required NoteLock PDAs are
    // absent, proving the negative result above is the lifecycle guard rather
    // than a malformed proof/root/account layout.
    let mut unlocked = Harness::setup();
    assert_eq!(install_merge_input_tree(&mut unlocked, &commitments), root);
    let unlocked_ix = build_merge_ix(&unlocked, &proof, &commitments, output, root);
    let unlocked_tx = Transaction::new(
        &[&unlocked.trader],
        Message::new(&[unlocked_ix], Some(&unlocked.trader.pubkey())),
        unlocked.svm.latest_blockhash(),
    );
    unlocked
        .svm
        .send_transaction(unlocked_tx)
        .expect("merge without locks must succeed");
    assert_eq!(tree_leaf_count(&unlocked, 0), 3);
    assert!(consumed_note_exists(&unlocked, &commitments[0]));
    assert!(consumed_note_exists(&unlocked, &commitments[1]));
}

#[test]
fn merge_rejects_all_dummy_transport_before_tree_append() {
    let mut h = Harness::setup();
    let root = tree_current_root(&h, 0);
    let proof = Groth16Proof {
        pi_a: [0u8; 64],
        pi_b: [0u8; 128],
        pi_c: [0u8; 64],
    };
    let ix = build_merge_ix(&h, &proof, &[[0u8; 32]; 2], [1u8; 32], root);
    let tx = Transaction::new(
        &[&h.trader],
        Message::new(&[ix], Some(&h.trader.pubkey())),
        h.svm.latest_blockhash(),
    );
    assert!(h.svm.send_transaction(tx).is_err());
    assert_eq!(tree_leaf_count(&h, 0), 0);
}
