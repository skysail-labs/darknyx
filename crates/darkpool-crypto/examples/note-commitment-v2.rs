//! Helper CLI used by the TS parity test to emit a v2 (inner_hash) Note
//! Commitment as hex.
//!
//! Formula (matches `circuits/valid_spend/circuit.circom` v2 + the on-chain
//! hasher): Poseidon6(DOMAIN_NOTE=2, mint_lo, mint_hi, amount, owner, inner_hash).
//!
//! Usage:
//!   note-commitment-v2 <token_mint_hex64> <amount_dec> \
//!                      <owner_commitment_hex64> <inner_hash_hex64>
//!
//! Outputs: 64-char hex string of the 32-byte BE note commitment.

use darkpool_crypto::note::commitment_from_fields_v2;

fn hex32(s: &str, name: &str) -> [u8; 32] {
    let bytes = hex::decode(s).unwrap_or_else(|_| panic!("invalid hex for {name}"));
    assert_eq!(bytes.len(), 32, "{name} must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "usage: note-commitment-v2 <mint_hex64> <amount_dec> <owner_commit_hex64> <inner_hash_hex64>"
        );
        std::process::exit(2);
    }

    let mint = hex32(&args[1], "token_mint");
    let amount: u64 = args[2].parse().expect("amount must be u64 decimal");
    let owner = hex32(&args[3], "owner_commitment");
    let inner = hex32(&args[4], "inner_hash");

    let c = commitment_from_fields_v2(&mint, amount, &owner, &inner)
        .expect("commitment compute failed");
    println!("{}", hex::encode(c));
}
