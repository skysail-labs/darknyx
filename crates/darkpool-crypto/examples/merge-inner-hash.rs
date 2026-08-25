//! Emit the VALID_MERGE output inner for four private-inner slots + one bitmap.
//! Used by the SDK byte-parity regression.

use darkpool_crypto::merge_output_inner_hash;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!(
            "usage: merge-inner-hash <inner0_hex> <inner1_hex> <inner2_hex> <inner3_hex> <bitmap>"
        );
        std::process::exit(2);
    }

    let mut inners = [[0u8; 32]; 4];
    for (slot, value) in inners.iter_mut().zip(&args[1..5]) {
        let decoded = hex::decode(value).expect("inner hex");
        assert_eq!(decoded.len(), 32, "inner must be 32 bytes");
        slot.copy_from_slice(&decoded);
    }
    let bitmap: u8 = args[5].parse().expect("bitmap u8");
    let inner = merge_output_inner_hash(&inners, bitmap).expect("valid merge inputs");
    println!("{}", hex::encode(inner));
}
