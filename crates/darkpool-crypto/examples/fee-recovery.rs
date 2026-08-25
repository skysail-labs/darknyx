//! Emit the frozen protocol fee-recovery ciphertext for SDK parity.

use darkpool_crypto::encrypt_fee_recovery;

fn main() {
    let mut amounts = [(0u64, 0u64); 16];
    amounts[0] = (7, 11);
    amounts[15] = (13, 17);
    let ciphertext = encrypt_fee_recovery(
        &[1; 32], 4, &[2; 32], &[3; 32], &[4; 32], &[5; 32], &amounts,
    )
    .expect("fixed fee-recovery inputs are valid");
    println!("{}", hex::encode(ciphertext));
}
