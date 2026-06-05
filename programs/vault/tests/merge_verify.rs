//! VALID_MERGE(K) verify roundtrip — the §5 circuit↔VK↔on-chain-verifier check.
//!
//! Mirrors `zk_spend_roundtrip`: builds the Merkle tree in Rust (`append_leaf`),
//! shells out to snarkjs for a real proof, then verifies it with the COMMITTED
//! `vk_valid_merge_k{2,4}.rs` consts via `groth16-solana`. It also asserts the
//! public-signal ORDER matches what `merge.rs` builds. The full merge ix (PDA
//! creation + leaf append) is exercised end-to-end by `devnet-merge` — this test
//! pins the proof/VK chain, which is the part that breaks silently.

mod common;

use ark_bn254::Fr;
use ark_ff::PrimeField;

use common::{fr_to_dec, repo_root, snarkjs_fullprove};
use darkpool_crypto::field::{fr_to_be_bytes, pubkey_to_fr_pair, u64_to_fr};
use darkpool_crypto::poseidon::poseidon_hash;
use vault::merkle::{append_leaf, compute_zero_subtree_roots, empty_root};
use vault::state::{VaultConfig, MERKLE_DEPTH, ROOT_HISTORY_SIZE};
use vault::zk::verifier::{make_vk, Groth16Proof};
use vault::zk::verify_groth16_proof;

const TREE_DEPTH: usize = 20;

// Fixed test owner.
fn owner_parts() -> (Fr, Fr, Fr) {
    let sk = Fr::from(0x1234_5678u64);
    let r_owner = Fr::from(0xfeedu64);
    let owner = poseidon_hash(&[Fr::from(1u64), sk, r_owner]).unwrap(); // DOMAIN_OWNER
    (sk, r_owner, owner)
}

fn fresh_config() -> VaultConfig {
    let zeros = compute_zero_subtree_roots().unwrap();
    VaultConfig {
        admin: Default::default(),
        tee_pubkey: Default::default(),
        root_key: Default::default(),
        leaf_count: 0,
        current_root: empty_root(&zeros).unwrap(),
        roots: [[0u8; 32]; ROOT_HISTORY_SIZE],
        roots_head: 0,
        zero_subtree_roots: zeros,
        right_path: [[0u8; 32]; MERKLE_DEPTH as usize],
        bump: 0,
        protocol_owner_commitment: [0u8; 32],
        fee_rate_bps: 0,
        _padding: [0u8; 4],
    }
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
    let mut cfg = fresh_config();
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
        root = append_leaf(&mut cfg, cb).unwrap();
    }

    // Per-slot witnesses (real) + dummies.
    let output_inner = Fr::from(0xabcu64);
    let sum: u64 = amounts.iter().sum();
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

    let mut is_active = vec![];
    let mut amount_s = vec![];
    let mut inner_s = vec![];
    let mut nullifiers = vec![]; // BE32 (what merge.rs passes)
    let mut nullifiers_dec = vec![];
    let mut paths: Vec<Vec<String>> = vec![];
    let mut indices: Vec<Vec<String>> = vec![];

    for i in 0..k {
        if i < num_real {
            let (sib, idx) = merkle_witness(&commitments, i);
            let nf = poseidon_hash(&[Fr::from(3u64), sk, inners[i]]).unwrap();
            is_active.push("1".to_string());
            amount_s.push(amounts[i].to_string());
            inner_s.push(fr_to_dec(&inners[i]));
            nullifiers.push(fr_to_be_bytes(&nf));
            nullifiers_dec.push(fr_to_dec(&nf));
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
            nullifiers.push([0u8; 32]);
            nullifiers_dec.push("0".to_string());
            paths.push(vec!["0".to_string(); TREE_DEPTH]);
            indices.push(vec!["0".to_string(); TREE_DEPTH]);
        }
    }

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
           \"nullifiers\": [{nulls}],\n\
           \"spendingKey\": \"{sk}\",\n\
           \"ownerCommitmentBlinding\": \"{ocb}\",\n\
           \"outputInnerHash\": \"{oih}\",\n\
           \"isActive\": [{act}],\n\
           \"amount\": [{amt}],\n\
           \"innerHash\": [{inr}],\n\
           \"merklePath\": [{paths}],\n\
           \"merkleIndices\": [{idxs}]\n\
         }}",
        mr = fr_to_dec(&Fr::from_be_bytes_mod_order(&root)),
        mlo = fr_to_dec(&mint_lo),
        mhi = fr_to_dec(&mint_hi),
        nulls = arr(&nullifiers_dec),
        sk = fr_to_dec(&sk),
        ocb = fr_to_dec(&r_owner),
        oih = fr_to_dec(&output_inner),
        act = arr(&is_active),
        amt = arr(&amount_s),
        inr = arr(&inner_s),
        paths = arr2(&paths),
        idxs = arr2(&indices),
    );

    let build = repo_root().join(format!("circuits/build/valid_merge_k{k}"));
    let tmp = std::env::temp_dir().join(format!("nyx_merge_verify_k{k}_{num_real}"));
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
        nullifiers,
    )
}

#[test]
fn merge_k2_verifies_and_public_order_matches() {
    let (proof, public_inputs, out_c, root, mlo, mhi, nulls) = prove_merge(2, 2);

    // Public-signal order (must match merge.rs):
    //   [outputCommitment, merkleRoot, mint_lo, mint_hi, nullifiers[0], nullifiers[1]]
    assert_eq!(public_inputs.len(), 6);
    assert_eq!(public_inputs[0], out_c, "signal 0 must be outputCommitment");
    assert_eq!(public_inputs[1], root, "signal 1 must be merkleRoot");
    assert_eq!(public_inputs[2], mlo);
    assert_eq!(public_inputs[3], mhi);
    assert_eq!(public_inputs[4], nulls[0]);
    assert_eq!(public_inputs[5], nulls[1]);

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
    let (proof, public_inputs, out_c, root, _mlo, _mhi, nulls) = prove_merge(4, 2);
    assert_eq!(public_inputs.len(), 8);
    assert_eq!(public_inputs[0], out_c);
    assert_eq!(public_inputs[1], root);
    // Dummy slots' public nullifiers are zero.
    assert_eq!(nulls[2], [0u8; 32]);
    assert_eq!(nulls[3], [0u8; 32]);
    assert_eq!(public_inputs[6], [0u8; 32]);
    assert_eq!(public_inputs[7], [0u8; 32]);

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
