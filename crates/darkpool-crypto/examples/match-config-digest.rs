//! Emit the canonical VALID_MATCH_BATCH governed-config digest for SDK parity.

use darkpool_crypto::match_config_digest;

fn decode32(value: &str, label: &str) -> [u8; 32] {
    let decoded = hex::decode(value).unwrap_or_else(|_| panic!("invalid {label} hex"));
    decoded
        .try_into()
        .unwrap_or_else(|_| panic!("{label} must be 32 bytes"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!(
            "usage: match-config-digest <fee_bps> <owner_hex> <base_mint_hex> <quote_mint_hex> <price_scale>"
        );
        std::process::exit(2);
    }
    let fee_rate_bps = args[1].parse::<u64>().expect("fee_bps must be u64");
    let owner = decode32(&args[2], "owner");
    let base = decode32(&args[3], "base mint");
    let quote = decode32(&args[4], "quote mint");
    let price_scale = args[5].parse::<u64>().expect("price_scale must be u64");
    let digest = match_config_digest(fee_rate_bps, &owner, &base, &quote, price_scale)
        .expect("field-safe match config");
    println!("{}", hex::encode(digest));
}
