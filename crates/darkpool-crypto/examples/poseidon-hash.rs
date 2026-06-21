//! CLI helper — emit Poseidon hash of N input field elements (decimal-string).
//! Used by the TS-side parity test to cross-check light-poseidon vs circomlibjs.
//!
//! Usage: poseidon-hash 2 12345 67890

use ark_bn254::Fr;
use ark_ff::PrimeField;
use darkpool_crypto::field::fr_to_be_bytes;
use darkpool_crypto::poseidon::poseidon_hash;

/// Convert a base-10 decimal string to a big-endian u256 byte buffer by
/// repeated divison. Faster to just use u128 for small test inputs; we accept
/// arbitrary size for robustness.
fn dec_to_be(s: &str) -> Vec<u8> {
    let mut digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
    let mut out = Vec::new();
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
        out.insert(0, rem as u8);
        digits = new_digits;
    }
    if out.is_empty() {
        out.push(0);
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: poseidon-hash <arity> <input_0_dec> <input_1_dec> ...");
        std::process::exit(2);
    }
    let n: usize = args[1].parse().expect("arity");
    assert_eq!(args.len(), 2 + n, "expected {n} inputs");

    let inputs: Vec<Fr> = args[2..]
        .iter()
        .map(|s| {
            let be = dec_to_be(s);
            Fr::from_be_bytes_mod_order(&be)
        })
        .collect();

    let h = poseidon_hash(&inputs).expect("hash");
    println!("{}", hex::encode(fr_to_be_bytes(&h)));
}
