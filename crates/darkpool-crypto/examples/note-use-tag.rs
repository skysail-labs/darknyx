//! Emit `Poseidon3(29, note_commitment, inner_hash)` for SDK parity.

use darkpool_crypto::{note_use_tag, NoteCommitment};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: note-use-tag <note_commitment_hex> <inner_hash_hex>");
        std::process::exit(2);
    }
    let decode = |value: &str, label: &str| -> [u8; 32] {
        let decoded = hex::decode(value).unwrap_or_else(|_| panic!("invalid {label} hex"));
        decoded
            .try_into()
            .unwrap_or_else(|_| panic!("{label} must be 32 bytes"))
    };
    let commitment = NoteCommitment::from_bytes(decode(&args[1], "note commitment"))
        .expect("note commitment must be a canonical field element");
    let inner = decode(&args[2], "inner hash");
    let tag = note_use_tag(&commitment, &inner).expect("field-safe tag inputs");
    println!("{}", hex::encode(tag.into_bytes()));
}
