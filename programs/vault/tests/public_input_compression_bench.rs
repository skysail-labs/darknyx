#![cfg(feature = "public-input-bench")]

//! Litesvm CU A/B for Groth16 statement compression. Build the benchmark-only
//! SBF first:
//!
//! `cargo build-sbf --manifest-path programs/vault/Cargo.toml --features devnet-admin,public-input-bench`
//! `cargo test -p vault --features devnet-admin,public-input-bench --test public_input_compression_bench -- --nocapture`

mod settle_harness;

use anchor_lang::prelude::Pubkey;
use settle_harness::Harness;
use sha2::{Digest, Sha256};
use solana_instruction::Instruction;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

const PI8_PROOF: &[u8; 256] = include_bytes!("fixtures/public_input_bench_pi8.bin");
const PI2_PROOF: &[u8; 256] = include_bytes!("fixtures/public_input_bench_pi2.bin");
const PI1_PROOF: &[u8; 256] = include_bytes!("fixtures/public_input_bench_pi1.bin");

fn instruction_discriminator(name: &str) -> [u8; 8] {
    let hash = Sha256::digest(format!("global:{name}").as_bytes());
    hash[..8].try_into().unwrap()
}

fn benchmark_ix(program_id: Pubkey, public_input_count: u8, proof: &[u8; 256]) -> Instruction {
    let mut data = Vec::with_capacity(8 + 1 + 256);
    data.extend_from_slice(&instruction_discriminator("benchmark_public_inputs"));
    data.push(public_input_count);
    data.extend_from_slice(proof);
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

fn run(h: &mut Harness, public_input_count: u8, proof: &[u8; 256]) -> u64 {
    let ix = benchmark_ix(vault::id(), public_input_count, proof);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm
        .send_transaction(tx)
        .expect("benchmark proof must verify")
        .compute_units_consumed
}

#[test]
fn public_input_compression_cu_profile() {
    let mut h = Harness::setup();
    let pi8 = run(&mut h, 8, PI8_PROOF);
    let pi2 = run(&mut h, 2, PI2_PROOF);
    let pi1 = run(&mut h, 1, PI1_PROOF);

    let pi8_to_pi2 = pi8.saturating_sub(pi2);
    let pi2_to_pi1 = pi2.saturating_sub(pi1);
    eprintln!(
        "CU_PROFILE public_input_compression pi8={pi8} pi2={pi2} pi1={pi1} pi8_to_pi2_saved={pi8_to_pi2} pi2_to_pi1_saved={pi2_to_pi1}"
    );

    // Broad regression bands around the current runtime schedule. They catch
    // an accidental pure-BPF hash or a verifier path change without pretending
    // that syscall pricing is immutable across Solana releases.
    assert!(
        (20_000..=40_000).contains(&pi8_to_pi2),
        "8->2 should save material CU after paying for Poseidon8; saved {pi8_to_pi2}"
    );
    assert!(
        (2_000..=8_000).contains(&pi2_to_pi1),
        "2->1 should provide only a modest incremental saving; saved {pi2_to_pi1}"
    );
}
