//! Cross-environment VALID_PRICE round-trip.
//!
//! Generates a VALID_PRICE proof via snarkjs and verifies it with groth16-solana.
//! The circuit proves:
//!   quote_amount == base_amount * clearing_price
//!   price_commitment == Poseidon3(DOMAIN_PRICE=5, clearing_price, batch_slot)
//!   all three inputs in [0, 2^64)

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use darkpool_crypto::price_commitment as compute_price_commitment;
use vault::zk::verifier::{make_vk, Groth16Proof};
use vault::zk::verify_groth16_proof;
use vault::zk::vk_valid_price::*;

fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn dec_to_be32(s: &str) -> [u8; 32] {
    let mut digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
    let mut out = [0u8; 32];
    let mut byte_idx = 32usize;
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
    out[..32].copy_from_slice(&x);
    out[32..].copy_from_slice(&y);
    out
}

fn groth16_g2_bytes(v: &serde_json::Value) -> [u8; 128] {
    let x0 = dec_to_be32(v[0][0].as_str().unwrap());
    let x1 = dec_to_be32(v[0][1].as_str().unwrap());
    let y0 = dec_to_be32(v[1][0].as_str().unwrap());
    let y1 = dec_to_be32(v[1][1].as_str().unwrap());
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&x1);
    out[32..64].copy_from_slice(&x0);
    out[64..96].copy_from_slice(&y1);
    out[96..].copy_from_slice(&y0);
    out
}

fn negate_g1(point: &[u8; 64]) -> [u8; 64] {
    const P: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
        0xfd, 0x47,
    ];
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&point[..32]);
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = P[i] as i16 - point[32 + i] as i16 - borrow;
        out[32 + i] = if diff < 0 {
            borrow = 1;
            (diff + 256) as u8
        } else {
            borrow = 0;
            diff as u8
        };
    }
    out
}

#[test]
fn valid_price_roundtrip() {
    let root = repo_root();
    let build = root.join("circuits/build/valid_price");
    let wasm = build.join("circuit_js/circuit.wasm");
    let zkey = build.join("circuit_final.zkey");
    if !wasm.exists() || !zkey.exists() {
        panic!("circuit artifacts missing — run `bash scripts/build-circuits.sh` first");
    }

    let clearing_price: u64 = 50;
    let base_amount: u64 = 100;
    let quote_amount: u64 = 5_000; // 100 * 50
    let batch_slot: u64 = 42;

    let price_commitment_bytes = compute_price_commitment(clearing_price, batch_slot).unwrap();

    let tmp = std::env::temp_dir().join("nyx_price_roundtrip");
    fs::create_dir_all(&tmp).unwrap();
    let input_path = tmp.join("input.json");
    let proof_path = tmp.join("proof.json");
    let public_path = tmp.join("public.json");

    // price_commitment as decimal
    let mut pc_big = 0u128;
    for b in &price_commitment_bytes {
        pc_big = (pc_big << 8) | (*b as u128);
    }
    // Use u256 decimal via a simple approach: convert bytes to decimal string
    let pc_dec = {
        let mut n: Vec<u32> = Vec::new();
        for &b in &price_commitment_bytes {
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
            "0".to_string()
        } else {
            let mut s = String::new();
            for (i, limb) in n.iter().rev().enumerate() {
                if i == 0 {
                    s.push_str(&limb.to_string());
                } else {
                    s.push_str(&format!("{:09}", limb));
                }
            }
            s
        }
    };

    let input_json = format!(
        "{{\n  \"price_commitment\": \"{pc}\",\n  \"batch_slot\": \"{bs}\",\n  \"clearing_price\": \"{cp}\",\n  \"base_amount\": \"{ba}\",\n  \"quote_amount\": \"{qa}\"\n}}",
        pc = pc_dec,
        bs = batch_slot,
        cp = clearing_price,
        ba = base_amount,
        qa = quote_amount,
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
    assert!(status.success(), "snarkjs fullprove failed for VALID_PRICE");

    let proof_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&proof_path).unwrap()).unwrap();

    let pi_a = groth16_g1_bytes(&proof_json["pi_a"]);
    let pi_b = groth16_g2_bytes(&proof_json["pi_b"]);
    let pi_c = groth16_g1_bytes(&proof_json["pi_c"]);
    let proof = Groth16Proof {
        pi_a: negate_g1(&pi_a),
        pi_b,
        pi_c,
    };

    // Wire order (circuit.sym): wire 1 = price_commitment, wire 2 = batch_slot
    let batch_slot_be32 = {
        let mut b = [0u8; 32];
        b[24..32].copy_from_slice(&batch_slot.to_be_bytes());
        b
    };
    let public_inputs: [[u8; 32]; 2] = [price_commitment_bytes, batch_slot_be32];

    let vk = make_vk(
        &VALID_PRICE_ALPHA_G1,
        &VALID_PRICE_BETA_G2,
        &VALID_PRICE_GAMMA_G2,
        &VALID_PRICE_DELTA_G2,
        &VALID_PRICE_IC,
    );
    verify_groth16_proof::<2>(&vk, &proof, &public_inputs)
        .expect("VALID_PRICE proof verification failed");

    // Negative: tampered proof must fail
    let mut tampered = proof.clone();
    tampered.pi_c[0] ^= 0x01;
    assert!(verify_groth16_proof::<2>(&vk, &tampered, &public_inputs).is_err());

    // Negative: wrong batch_slot must fail
    let mut bad = public_inputs;
    bad[1][31] ^= 0x01;
    assert!(verify_groth16_proof::<2>(&vk, &proof, &bad).is_err());
}
