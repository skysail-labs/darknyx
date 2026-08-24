//! Cross-environment VALID_SPEND round-trip.
//!
//! The most important single test in this suite. It exercises:
//!
//!   1. Merkle-tree construction in Rust (via `append_leaf`) producing the same
//!      root the circom `MerkleTreeChecker` verifies.
//!   2. Owner commitment: Poseidon3(DOMAIN_OWNER=1, sk, r_owner)
//!   3. Note commitment: Poseidon6(DOMAIN_NOTE=2, mint_lo, mint_hi, amt, owner, inner_hash)
//!   4. Nullifier:       Poseidon3(DOMAIN_NULL=3,  sk, inner_hash)
//!   5. noteUseTag = Poseidon3(DOMAIN_NOTE_USE=29, commitment, inner_hash) is
//!      the circuit's public output at wire index 0 — the commitment itself is
//!      now a private intermediate and never appears in a public signal.
//!   6. snarkjs Groth16 proof generation.
//!   7. `groth16-solana` verification producing `Ok(())`.
//!
//! A pass means this fixture round-trips and the tampering cases below are
//! rejected — not that VALID_SPEND holds for all inputs.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

use darkpool_crypto::field::{fr_from_uniform_bytes, fr_to_be_bytes, pubkey_to_fr_pair, u64_to_fr};
use darkpool_crypto::poseidon::poseidon_hash;
use vault::merkle::{append_leaf, compute_zero_subtree_roots, empty_root};
use vault::state::{MerkleTree, MERKLE_DEPTH, ROOT_HISTORY_SIZE};
use vault::zk::verifier::{make_vk, Groth16Proof};
use vault::zk::verify_groth16_proof;
use vault::zk::vk_valid_spend::*;

const TREE_DEPTH: usize = 20;

fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn fr_to_dec(fr: &Fr) -> String {
    let bi = fr.into_bigint();
    let bytes = bi.to_bytes_be();
    num_bigint_decstring(&bytes)
}

fn num_bigint_decstring(bytes: &[u8]) -> String {
    let mut n: Vec<u32> = Vec::new();
    for &b in bytes {
        let mut carry = b as u64;
        for limb in n.iter_mut() {
            let v = (*limb as u64) * 256 + carry;
            *limb = (v % 1_000_000_000) as u32;
            carry = v / 1_000_000_000;
        }
        while carry > 0 {
            n.push((carry % 1_000_000_000) as u32);
            carry /= 1_000_000_000;
        }
    }
    if n.is_empty() {
        return "0".into();
    }
    let mut out = String::new();
    for (i, limb) in n.iter().rev().enumerate() {
        if i == 0 {
            out.push_str(&limb.to_string());
        } else {
            out.push_str(&format!("{:09}", limb));
        }
    }
    out
}

fn fresh_tree() -> (MerkleTree, [[u8; 32]; MERKLE_DEPTH as usize]) {
    let zeros = compute_zero_subtree_roots().unwrap();
    let tree = MerkleTree {
        leaf_count: 0.into(),
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

/// Build a Merkle inclusion proof for `leaf_index` in a tree populated with `leaves`.
/// Returns (siblings, path_indices, root).
fn merkle_witness(leaves: &[[u8; 32]], target_index: usize) -> (Vec<[u8; 32]>, Vec<u8>, [u8; 32]) {
    assert!(target_index < leaves.len());

    // Level 0 = leaves, padded with zero-subtree roots.
    let zero_subtree = compute_zero_subtree_roots().unwrap();

    let mut siblings = vec![[0u8; 32]; TREE_DEPTH];
    let mut path_indices = vec![0u8; TREE_DEPTH];

    // Build the tree level-by-level. For our small test tree, we can afford
    // to compute the full `2^depth` vector; but that's 1M nodes at depth 20.
    // Instead, we build only the path-relevant neighbours using the same
    // "right-path + zero-subtree" logic as the on-chain append algorithm.
    //
    // For this test we use a simpler dense computation by building the tree
    // up to a logarithmic depth that covers `leaves.len()`, then padding
    // with zero-subtree roots at deeper levels.

    // Compute the smallest power-of-two >= leaves.len().
    let n = leaves.len();
    let small_depth: usize = {
        let mut d = 0;
        while (1usize << d) < n {
            d += 1;
        }
        d.max(1)
    };
    let padded_len = 1usize << small_depth;

    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    level.resize(padded_len, [0u8; 32]);

    let mut idx = target_index;
    for d in 0..small_depth {
        let sibling_idx = idx ^ 1;
        siblings[d] = level[sibling_idx];
        path_indices[d] = (idx & 1) as u8;
        idx >>= 1;

        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let h = vault::merkle::poseidon2(&pair[0], &pair[1]).unwrap();
            next.push(h);
        }
        level = next;
    }

    let mut current = level[0];
    for d in small_depth..TREE_DEPTH {
        siblings[d] = zero_subtree[d];
        path_indices[d] = 0; // current node is left child (right is empty)
        current = vault::merkle::poseidon2(&current, &zero_subtree[d]).unwrap();
    }

    (siblings, path_indices, current)
}

#[test]
fn valid_spend_roundtrip() {
    let root = repo_root();
    let build = root.join("circuits/build/valid_spend");
    let wasm = build.join("circuit_js/circuit.wasm");
    let zkey = build.join("circuit_final.zkey");
    assert!(wasm.exists(), "missing {wasm:?}");
    assert!(zkey.exists(), "missing {zkey:?}");

    // ----- Build the note -----
    let mint_bytes: [u8; 32] = [
        0x06, 0x74, 0x2c, 0x78, 0xb0, 0x80, 0x8a, 0x9d, 0x8c, 0x33, 0x11, 0xcd, 0x1d, 0x4a, 0x45,
        0x3d, 0xe8, 0xcf, 0xaa, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let [mint_lo, mint_hi] = pubkey_to_fr_pair(&mint_bytes);
    // S-01: the destination token account is a PUBLIC input, so the proof only
    // authorises tokens landing here.
    let dest_bytes: [u8; 32] = [
        0x0d, 0xe5, 0x11, 0x77, 0x2a, 0x4c, 0x93, 0x18, 0x6b, 0x22, 0xf0, 0x81, 0x3e, 0x5a, 0xc7,
        0x64, 0x99, 0x10, 0xab, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let [dest_lo, dest_hi] = pubkey_to_fr_pair(&dest_bytes);
    let amount_u64: u64 = 1_234_567;
    let amount_fr = u64_to_fr(amount_u64);

    let spending_key = fr_from_uniform_bytes(&[0x41u8; 32]);
    let owner_commit_blinding = fr_from_uniform_bytes(&[0x42u8; 32]);
    // owner_commitment = Poseidon3(DOMAIN_OWNER=1, spendingKey, r_owner)
    let owner_commitment =
        poseidon_hash(&[Fr::from(1u64), spending_key, owner_commit_blinding]).unwrap();
    let inner_hash = fr_from_uniform_bytes(&[0x43u8; 32]);

    // note_commitment = Poseidon6(DOMAIN_NOTE=2, mint_lo, mint_hi, amount, owner, inner_hash)
    let note_commitment = poseidon_hash(&[
        Fr::from(2u64),
        mint_lo,
        mint_hi,
        amount_fr,
        owner_commitment,
        inner_hash,
    ])
    .unwrap();
    let note_commitment_bytes = fr_to_be_bytes(&note_commitment);

    // note_use_tag = Poseidon3(DOMAIN_NOTE_USE=29, note_commitment, inner_hash).
    // This, not the commitment, is what `withdraw` keys the consume guard on.
    let note_use_tag = poseidon_hash(&[Fr::from(29u64), note_commitment, inner_hash]).unwrap();

    // ----- Build an on-chain-style Merkle tree with this as the only leaf -----
    let (mut tree, zsr) = fresh_tree();
    let root_bytes = append_leaf(&mut tree, &zsr, note_commitment_bytes).unwrap();

    // Build the matching inclusion witness.
    let (siblings, path_indices, witness_root) = merkle_witness(&[note_commitment_bytes], 0);
    assert_eq!(
        witness_root, root_bytes,
        "merkle_witness root does not match on-chain append root — \
         indicates our Merkle algorithm diverges from expected"
    );

    // nullifier = Poseidon3(DOMAIN_NULL=3, spendingKey, inner_hash)
    let nullifier = poseidon_hash(&[Fr::from(3u64), spending_key, inner_hash]).unwrap();

    // ----- Write snarkjs input.json -----
    // Per-process scratch dir. A FIXED name is safe only while exactly one
    // test ever uses it in one process; it breaks silently the moment a second
    // test is added here, or under a per-test-process runner like
    // `cargo nextest`, where two processes would share the path and clobber each
    // other's proof.json. Matches the pid convention in merge_verify.rs.
    let tmp = std::env::temp_dir().join(format!("darknyx_spend_roundtrip_{}", std::process::id()));
    fs::create_dir_all(&tmp).unwrap();
    let input_path = tmp.join("input.json");
    let proof_path = tmp.join("proof.json");
    let public_path = tmp.join("public.json");

    let siblings_dec: Vec<String> = siblings
        .iter()
        .map(|s| {
            // Convert 32-byte BE to decimal
            let f = Fr::from_be_bytes_mod_order(s);
            fr_to_dec(&f)
        })
        .collect();
    let indices_dec: Vec<String> = path_indices.iter().map(|i| i.to_string()).collect();

    let input_json = format!(
        "{{\n\
           \"merkleRoot\": \"{mr}\",\n\
           \"nullifier\": \"{nl}\",\n\
           \"tokenMint\": [\"{mlo}\", \"{mhi}\"],\n\
           \"amount\": \"{amt}\",\n\
           \"spendingKey\": \"{sk}\",\n\
           \"ownerCommitmentBlinding\": \"{ocb}\",\n\
           \"innerHash\": \"{ih}\",\n\
           \"merklePath\": [{sibs}],\n\
           \"merkleIndices\": [{idxs}],\n\
           \"recipient\": [\"{dlo}\", \"{dhi}\"]\n\
         }}",
        mr = fr_to_dec(&Fr::from_be_bytes_mod_order(&witness_root)),
        nl = fr_to_dec(&nullifier),
        mlo = fr_to_dec(&mint_lo),
        mhi = fr_to_dec(&mint_hi),
        dlo = fr_to_dec(&dest_lo),
        dhi = fr_to_dec(&dest_hi),
        amt = amount_u64,
        sk = fr_to_dec(&spending_key),
        ocb = fr_to_dec(&owner_commit_blinding),
        ih = fr_to_dec(&inner_hash),
        sibs = siblings_dec
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", "),
        idxs = indices_dec
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", "),
    );
    fs::write(&input_path, &input_json).unwrap();

    let snarkjs = root.join("node_modules/.bin/snarkjs");
    let status = Command::new(&snarkjs)
        .arg("groth16")
        .arg("fullprove")
        .arg(&input_path)
        .arg(&wasm)
        .arg(&zkey)
        .arg(&proof_path)
        .arg(&public_path)
        .status()
        .expect("failed to spawn snarkjs");
    assert!(status.success(), "snarkjs fullprove failed for VALID_SPEND");

    // ----- Parse proof and verify via groth16-solana -----
    let proof_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&proof_path).unwrap()).unwrap();

    let pi_a = groth16_g1_bytes(&proof_json["pi_a"]);
    let pi_a_neg = negate_g1(&pi_a);
    let pi_b = groth16_g2_bytes(&proof_json["pi_b"]);
    let pi_c = groth16_g1_bytes(&proof_json["pi_c"]);

    let proof = Groth16Proof {
        pi_a: pi_a_neg,
        pi_b,
        pi_c,
    };

    // Public signal wire order (from circuit.sym — circom places outputs before inputs):
    //   wire 1: noteUseTag      (signal output — appears first)
    //   wire 2: merkleRoot
    //   wire 3: nullifier
    //   wire 4: tokenMint[0]
    //   wire 5: tokenMint[1]
    //   wire 6: amount
    // groth16-solana IC array: IC[0] is the constant term, IC[i] corresponds to wire i.
    // public.json from snarkjs lists them in this same wire-index order.
    let amount_be32 = {
        let mut b = [0u8; 32];
        b[24..32].copy_from_slice(&amount_u64.to_be_bytes());
        b
    };
    // Order mirrors `withdraw.rs` exactly, which in turn mirrors the circom
    // public-signal order (output first, then public inputs in template
    // declaration order).
    let public_inputs: [[u8; 32]; 8] = [
        fr_to_be_bytes(&note_use_tag),
        witness_root,
        fr_to_be_bytes(&nullifier),
        fr_to_be_bytes(&mint_lo),
        fr_to_be_bytes(&mint_hi),
        amount_be32,
        fr_to_be_bytes(&dest_lo),
        fr_to_be_bytes(&dest_hi),
    ];

    let vk = make_vk(
        &VALID_SPEND_ALPHA_G1,
        &VALID_SPEND_BETA_G2,
        &VALID_SPEND_GAMMA_G2,
        &VALID_SPEND_DELTA_G2,
        &VALID_SPEND_IC,
    );
    verify_groth16_proof::<8>(&vk, &proof, &public_inputs)
        .expect("VALID_SPEND proof verification failed");

    // ----- Negative: mutated proof must be rejected (ZK soundness) -----
    let mut tampered = proof.clone();
    tampered.pi_c[0] ^= 0x01;
    let res = verify_groth16_proof::<8>(&vk, &tampered, &public_inputs);
    assert!(res.is_err(), "mutated proof must not verify");

    // ----- Negative: wrong public input (amount, index 5) must be rejected -----
    let mut bad_inputs = public_inputs;
    bad_inputs[5][31] ^= 0x01;
    let res2 = verify_groth16_proof::<8>(&vk, &proof, &bad_inputs);
    assert!(res2.is_err(), "mutated amount must not verify");

    // ----- Negative: stale Merkle root (index 1) must be rejected -----
    let mut stale_inputs = public_inputs;
    stale_inputs[1][0] ^= 0x01;
    let res3 = verify_groth16_proof::<8>(&vk, &proof, &stale_inputs);
    assert!(res3.is_err(), "stale Merkle root must not verify");

    // ----- Negative: wrong note_use_tag (index 0) must be rejected -----
    let mut bad_nc = public_inputs;
    bad_nc[0][0] ^= 0x01;
    let res4 = verify_groth16_proof::<8>(&vk, &proof, &bad_nc);
    assert!(res4.is_err(), "tampered note_use_tag must not verify");

    // ----- S-01: substituted destination must be rejected -----
    //
    // THE finding this circuit revision exists for. Before the recipient was
    // bound, this exact substitution succeeded: an observer copied a valid
    // proof and its five arguments verbatim, swapped in their own token
    // account, and the vault paid them. Both halves are checked because a
    // pubkey spans two field elements, and binding only one would leave 128
    // bits free.
    let mut redirected_lo = public_inputs;
    redirected_lo[6][31] ^= 0x01;
    assert!(
        verify_groth16_proof::<8>(&vk, &proof, &redirected_lo).is_err(),
        "a proof must not verify against a different destination (lo half)"
    );

    let mut redirected_hi = public_inputs;
    redirected_hi[7][31] ^= 0x01;
    assert!(
        verify_groth16_proof::<8>(&vk, &proof, &redirected_hi).is_err(),
        "a proof must not verify against a different destination (hi half)"
    );
}

// ----- snarkjs proof parsing helpers -----

fn dec_to_be32(s: &str) -> [u8; 32] {
    str_to_u256_be(s)
}

fn str_to_u256_be(s: &str) -> [u8; 32] {
    let mut digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
    let mut out = [0u8; 32];
    let mut byte_idx = 32;
    while !digits.is_empty() && byte_idx > 0 {
        let mut rem: u32 = 0;
        let mut new_digits: Vec<u8> = Vec::with_capacity(digits.len());
        for d in &digits {
            let cur = rem * 10 + *d as u32;
            let q = cur / 256;
            rem = cur % 256;
            if !(new_digits.is_empty() && q == 0) {
                new_digits.push(q as u8);
            }
        }
        byte_idx -= 1;
        out[byte_idx] = rem as u8;
        digits = new_digits;
    }
    out
}

fn groth16_g1_bytes(v: &serde_json::Value) -> [u8; 64] {
    let x = dec_to_be32(v[0].as_str().unwrap());
    let y = dec_to_be32(v[1].as_str().unwrap());
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&x);
    out[32..64].copy_from_slice(&y);
    out
}

fn groth16_g2_bytes(v: &serde_json::Value) -> [u8; 128] {
    let x0 = dec_to_be32(v[0][0].as_str().unwrap());
    let x1 = dec_to_be32(v[0][1].as_str().unwrap());
    let y0 = dec_to_be32(v[1][0].as_str().unwrap());
    let y1 = dec_to_be32(v[1][1].as_str().unwrap());
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&x1);
    out[32..64].copy_from_slice(&x0);
    out[64..96].copy_from_slice(&y1);
    out[96..128].copy_from_slice(&y0);
    out
}

fn negate_g1(point: &[u8; 64]) -> [u8; 64] {
    const P_BYTES: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
        0xfd, 0x47,
    ];
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&point[0..32]);
    let mut y = [0u8; 32];
    y.copy_from_slice(&point[32..64]);
    let y_neg = sub_be(&P_BYTES, &y);
    out[32..64].copy_from_slice(&y_neg);
    out
}

fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}
