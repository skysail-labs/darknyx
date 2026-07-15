//! Helper CLI used by the TS parity test to emit derived keys as hex.
//! Invoked as:
//!   target/debug/examples/derive-keys spending <seed_hex>
//!   target/debug/examples/derive-keys viewing  <seed_hex>
//!   target/debug/examples/derive-keys trading  <seed_hex> <offset>
//!   target/debug/examples/derive-keys root     <seed_hex>
//!   target/debug/examples/derive-keys blinding <seed_hex> <counter>

use darkpool_crypto::field::fr_to_be_bytes;
use darkpool_crypto::keys::{
    derive_blinding_factor, derive_master_viewing_key, derive_root_key, derive_spending_key,
    derive_trading_key_at_offset, MasterSeed, MASTER_SEED_BYTES,
};

fn parse_seed(h: &str) -> MasterSeed {
    let bytes = hex::decode(h).expect("seed hex parse");
    assert_eq!(bytes.len(), MASTER_SEED_BYTES, "seed must be 64 bytes");
    let mut arr = [0u8; MASTER_SEED_BYTES];
    arr.copy_from_slice(&bytes);
    MasterSeed::new(arr)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: derive-keys <cmd> <seed_hex> [...]");
        std::process::exit(2);
    }
    let cmd = &args[1];
    let seed = parse_seed(&args[2]);

    let out: String = match cmd.as_str() {
        "spending" => hex::encode(fr_to_be_bytes(&derive_spending_key(&seed).unwrap())),
        "viewing" => hex::encode(fr_to_be_bytes(&derive_master_viewing_key(&seed).unwrap())),
        "root" => hex::encode(derive_root_key(&seed).unwrap().to_bytes()),
        "trading" => {
            let off: u64 = args[3].parse().expect("offset u64");
            hex::encode(derive_trading_key_at_offset(&seed, off).unwrap().to_bytes())
        }
        "blinding" => {
            let ctr: u64 = args[3].parse().expect("counter u64");
            hex::encode(fr_to_be_bytes(&derive_blinding_factor(&seed, ctr)))
        }
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(2);
        }
    };
    println!("{out}");
}
