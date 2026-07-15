//! Emit the VALID_MERGE output inner for four commitment slots + one bitmap.
//! Used by the SDK byte-parity regression.

use darkpool_crypto::merge_output_inner_hash;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!("usage: merge-inner-hash <c0_hex> <c1_hex> <c2_hex> <c3_hex> <bitmap>");
        std::process::exit(2);
    }

    let mut commitments = [[0u8; 32]; 4];
    for (slot, value) in commitments.iter_mut().zip(&args[1..5]) {
        let decoded = hex::decode(value).expect("commitment hex");
        assert_eq!(decoded.len(), 32, "commitment must be 32 bytes");
        slot.copy_from_slice(&decoded);
    }
    let bitmap: u8 = args[5].parse().expect("bitmap u8");
    let inner = merge_output_inner_hash(&commitments, bitmap).expect("valid merge inputs");
    println!("{}", hex::encode(inner));
}
