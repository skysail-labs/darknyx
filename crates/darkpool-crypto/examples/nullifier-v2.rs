//! Helper CLI used by the TS parity test to emit a v2 (inner_hash) Nullifier
//! as hex.
//!
//! Formula (matches `circuits/valid_spend/circuit.circom` v2):
//!   nullifier_v2 = Poseidon3( DOMAIN_NULL=3, spending_key_fr, inner_hash_fr )
//!
//! Usage:
//!   nullifier-v2 <spending_key_dec> <inner_hash_hex64>
//!
//! Outputs: 64-char hex string of the 32-byte BE nullifier.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use darkpool_crypto::nullifier::nullifier_v2;

fn dec_to_fr(s: &str) -> Fr {
    let mut digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
    let mut be = Vec::new();
    while !digits.is_empty() {
        let mut rem: u32 = 0;
        let mut new_digits = Vec::with_capacity(digits.len());
        for d in &digits {
            let cur = rem * 10 + *d as u32;
            let q = cur / 256;
            rem = cur % 256;
            if !(new_digits.is_empty() && q == 0) {
                new_digits.push(q as u8);
            }
        }
        be.insert(0, rem as u8);
        digits = new_digits;
    }
    if be.is_empty() {
        be.push(0);
    }
    Fr::from_be_bytes_mod_order(&be)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: nullifier-v2 <spending_key_dec> <inner_hash_hex64>");
        std::process::exit(2);
    }

    let sk = dec_to_fr(&args[1]);
    let inner_bytes = hex::decode(&args[2]).expect("invalid hex for inner_hash");
    assert_eq!(inner_bytes.len(), 32, "inner_hash must be 32 bytes");
    let mut inner = [0u8; 32];
    inner.copy_from_slice(&inner_bytes);

    let n = nullifier_v2(&sk, &inner).expect("nullifier compute failed");
    println!("{}", hex::encode(n));
}
