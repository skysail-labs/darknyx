//! Cross-environment ZK proof round-trip test.
//!
//! Generates a VALID_WALLET_CREATE proof via snarkjs (as the browser/client would)
//! and verifies it using `groth16-solana` — the same verifier the on-chain
//! program runs. If this test passes, the Rust side is byte-compatible with the
//! browser-side prover for this circuit.
//!
//! Prereq: `bash scripts/build-circuits.sh` must have been run so
//! `circuits/build/valid_wallet_create/` contains `.zkey` and WASM artifacts.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use darkpool_crypto::field::fr_from_uniform_bytes;
use darkpool_crypto::poseidon::poseidon_hash;
use vault::zk::verifier::{make_vk, Groth16Proof};
use vault::zk::verify_groth16_proof;
use vault::zk::vk_valid_wallet_create::*;

fn repo_root() -> PathBuf {
    // tests/zk_roundtrip.rs -> programs/vault/tests -> programs/vault -> programs -> repo
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn fr_to_dec(fr: &Fr) -> String {
    let bi = fr.into_bigint();
    // print as decimal string
    let bytes = bi.to_bytes_be();
    let mut s = num_bigint_decstring(&bytes);
    if s.is_empty() {
        s = "0".to_string();
    }
    s
}

// Tiny decimal-string conversion from big-endian bytes to avoid pulling num-bigint.
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

#[test]
fn valid_wallet_create_roundtrip() {
    let root = repo_root();
    let build = root.join("circuits/build/valid_wallet_create");
    let wasm = build.join("circuit_js/circuit.wasm");
    let zkey = build.join("circuit_final.zkey");
    if !wasm.exists() || !zkey.exists() {
        panic!(
            "circuit artifacts missing — run `bash scripts/build-circuits.sh` first. \
             Missing: {:?} or {:?}",
            wasm, zkey
        );
    }

    // Build a fully-in-field witness.
    // rootKey: split 32 bytes into two 128-bit halves (as Fr)
    let root_pk_bytes: [u8; 32] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xde,
        0xad, 0xbe, 0xef, 0xca, 0xfe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c,
    ];
    let [rk_lo, rk_hi] = darkpool_crypto::field::pubkey_to_fr_pair(&root_pk_bytes);

    // Randomly-looking but in-field field elements.
    let spending_key = fr_from_uniform_bytes(&[7u8; 32]);
    let viewing_key = fr_from_uniform_bytes(&[11u8; 32]);
    let r0 = fr_from_uniform_bytes(&[1u8; 32]);
    let r1 = fr_from_uniform_bytes(&[2u8; 32]);
    let r2 = fr_from_uniform_bytes(&[3u8; 32]);

    // Compute user commitment off-chain (must match the circuit exactly).
    // DOMAIN_ROOT=10, DOMAIN_SPEND=11, DOMAIN_VIEW=12, DOMAIN_LEAF=13, DOMAIN_TOP=14
    let root_hash = poseidon_hash(&[Fr::from(10u64), rk_lo, rk_hi, r0]).unwrap();
    let spending_hash = poseidon_hash(&[Fr::from(11u64), spending_key, r1]).unwrap();
    let viewing_hash = poseidon_hash(&[Fr::from(12u64), viewing_key, r2]).unwrap();
    let leaf_root = poseidon_hash(&[Fr::from(13u64), root_hash, spending_hash]).unwrap();
    let user_commitment = poseidon_hash(&[Fr::from(14u64), leaf_root, viewing_hash]).unwrap();

    // Write input.json for snarkjs (all values decimal strings).
    let tmp = std::env::temp_dir().join("nyx_wc_roundtrip");
    fs::create_dir_all(&tmp).unwrap();
    let input_path = tmp.join("input.json");
    let _witness_path = tmp.join("witness.wtns");
    let proof_path = tmp.join("proof.json");
    let public_path = tmp.join("public.json");

    let input_json = format!(
        "{{\n  \"userCommitment\": \"{uc}\",\n  \"rootKey\": [\"{lo}\", \"{hi}\"],\n  \"spendingKey\": \"{sk}\",\n  \"viewingKey\": \"{vk}\",\n  \"r0\": \"{r0}\",\n  \"r1\": \"{r1}\",\n  \"r2\": \"{r2}\"\n}}",
        uc = fr_to_dec(&user_commitment),
        lo = fr_to_dec(&rk_lo),
        hi = fr_to_dec(&rk_hi),
        sk = fr_to_dec(&spending_key),
        vk = fr_to_dec(&viewing_key),
        r0 = fr_to_dec(&r0),
        r1 = fr_to_dec(&r1),
        r2 = fr_to_dec(&r2),
    );
    fs::write(&input_path, input_json).unwrap();

    // Use snarkjs CLI: `snarkjs groth16 fullprove <input> <wasm> <zkey> <proof> <public>`
    let snarkjs = root.join("node_modules/.bin/snarkjs");
    assert!(snarkjs.exists(), "snarkjs not found — run `npm install`");

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
    assert!(status.success(), "snarkjs fullprove failed");

    // Parse proof.json into the groth16-solana byte layout.
    let proof_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&proof_path).unwrap()).unwrap();

    let pi_a = groth16_g1_bytes(&proof_json["pi_a"]);
    let pi_b = groth16_g2_bytes(&proof_json["pi_b"]);
    let pi_c = groth16_g1_bytes(&proof_json["pi_c"]);

    // groth16-solana expects pi_a to be NEGATED before verification.
    // snarkjs emits pi_a in affine form. We must negate the y-coordinate mod p.
    let pi_a_negated = negate_g1(&pi_a);

    let proof = Groth16Proof {
        pi_a: pi_a_negated,
        pi_b,
        pi_c,
    };

    // Public input is just the user commitment, encoded big-endian 32 bytes.
    let public_bytes: [u8; 32] = darkpool_crypto::field::fr_to_be_bytes(&user_commitment);
    let public_inputs: [[u8; 32]; 1] = [public_bytes];

    let vk = make_vk(
        &VALID_WALLET_CREATE_ALPHA_G1,
        &VALID_WALLET_CREATE_BETA_G2,
        &VALID_WALLET_CREATE_GAMMA_G2,
        &VALID_WALLET_CREATE_DELTA_G2,
        &VALID_WALLET_CREATE_IC,
    );

    verify_groth16_proof::<1>(&vk, &proof, &public_inputs).expect("proof verification failed");
}

// ----- Proof parsing helpers -----

fn dec_to_be32(s: &str) -> [u8; 32] {
    str_to_u256_be(s)
}

fn str_to_u256_be(s: &str) -> [u8; 32] {
    // Convert a decimal string to a big-endian 32-byte representation.
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
    // snarkjs format: [[x0, x1], [y0, y1]], c0||c1. groth16-solana expects x1||x0, y1||y0.
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
    // BN254 base field modulus p (big-endian 32 bytes).
    const P_BYTES: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
        0xfd, 0x47,
    ];

    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&point[0..32]);

    // y_neg = p - y
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
