//! Emit `Poseidon3(27, owner_commitment, recovery_nonce)` for SDK parity.

use darkpool_crypto::deposit_inner_hash;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: deposit-inner-hash <owner_hex> <recovery_nonce_hex>");
        std::process::exit(2);
    }
    let decode = |value: &str, label: &str| -> [u8; 32] {
        let decoded = hex::decode(value).unwrap_or_else(|_| panic!("invalid {label} hex"));
        decoded
            .try_into()
            .unwrap_or_else(|_| panic!("{label} must be 32 bytes"))
    };
    let owner = decode(&args[1], "owner");
    let nonce = decode(&args[2], "recovery nonce");
    let inner = deposit_inner_hash(&owner, &nonce).expect("field-safe deposit inputs");
    println!("{}", hex::encode(inner));
}
