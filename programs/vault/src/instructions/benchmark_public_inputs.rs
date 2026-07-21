//! Feature-gated CU probe for Groth16 public-input compression.
//!
//! This instruction is compiled only with `public-input-bench`. It verifies
//! three synthetic proofs over the same fixed statement:
//!   - 8 direct public inputs (current MATCH layout),
//!   - root + Poseidon8(governed config),
//!   - Poseidon9(root + governed config).
//!
//! Keeping all three arms behind the same Anchor discriminator makes their CU
//! delta isolate the verifier MSM and Poseidon syscall rather than transaction
//! or account-validation noise. It must never be enabled in a deployed build.

use crate::errors::VaultError;
use crate::zk::{verifier::make_vk, verify_groth16_proof, Groth16Proof};
use anchor_lang::prelude::*;

use crate::zk::{vk_benchmark_pi1::*, vk_benchmark_pi2::*, vk_benchmark_pi8::*};

#[cfg(not(target_os = "solana"))]
use ark_bn254::Fr;
#[cfg(not(target_os = "solana"))]
use light_poseidon::{Poseidon, PoseidonBytesHasher};
#[cfg(target_os = "solana")]
use solana_poseidon::{hashv as solana_poseidon_hashv, Endianness, Parameters};

#[derive(Accounts)]
pub struct BenchmarkPublicInputs {}

const DOMAIN_CONFIG: u64 = 1001;
const DOMAIN_FULL: u64 = 1002;

fn fr_u64(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn poseidon_n(inputs: &[&[u8]]) -> Result<[u8; 32]> {
    #[cfg(target_os = "solana")]
    {
        return solana_poseidon_hashv(Parameters::Bn254X5, Endianness::BigEndian, inputs)
            .map(|hash| hash.to_bytes())
            .map_err(|_| error!(VaultError::InvalidProof));
    }
    #[cfg(not(target_os = "solana"))]
    {
        let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
            .map_err(|_| error!(VaultError::InvalidProof))?;
        hasher
            .hash_bytes_be(inputs)
            .map_err(|_| error!(VaultError::InvalidProof))
    }
}

pub fn benchmark_public_inputs_handler(
    _ctx: Context<BenchmarkPublicInputs>,
    public_input_count: u8,
    proof: Groth16Proof,
) -> Result<()> {
    // Same fixed, Fr-canonical statement as the fixture generator.
    let merkle_root = fr_u64(11);
    let fee_rate_bps = fr_u64(30);
    let protocol_owner = fr_u64(13);
    let base_lo = fr_u64(17);
    let base_hi = fr_u64(19);
    let quote_lo = fr_u64(23);
    let quote_hi = fr_u64(29);
    let price_scale = fr_u64(100_000_000);

    match public_input_count {
        8 => {
            let public_inputs = [
                merkle_root,
                fee_rate_bps,
                protocol_owner,
                base_lo,
                base_hi,
                quote_lo,
                quote_hi,
                price_scale,
            ];
            let vk = make_vk(
                &BENCHMARK_PI8_ALPHA_G1,
                &BENCHMARK_PI8_BETA_G2,
                &BENCHMARK_PI8_GAMMA_G2,
                &BENCHMARK_PI8_DELTA_G2,
                &BENCHMARK_PI8_IC,
            );
            verify_groth16_proof::<8>(&vk, &proof, &public_inputs)
        }
        2 => {
            let domain = fr_u64(DOMAIN_CONFIG);
            let digest = poseidon_n(&[
                &domain,
                &fee_rate_bps,
                &protocol_owner,
                &base_lo,
                &base_hi,
                &quote_lo,
                &quote_hi,
                &price_scale,
            ])?;
            let public_inputs = [merkle_root, digest];
            let vk = make_vk(
                &BENCHMARK_PI2_ALPHA_G1,
                &BENCHMARK_PI2_BETA_G2,
                &BENCHMARK_PI2_GAMMA_G2,
                &BENCHMARK_PI2_DELTA_G2,
                &BENCHMARK_PI2_IC,
            );
            verify_groth16_proof::<2>(&vk, &proof, &public_inputs)
        }
        1 => {
            let domain = fr_u64(DOMAIN_FULL);
            let digest = poseidon_n(&[
                &domain,
                &merkle_root,
                &fee_rate_bps,
                &protocol_owner,
                &base_lo,
                &base_hi,
                &quote_lo,
                &quote_hi,
                &price_scale,
            ])?;
            let public_inputs = [digest];
            let vk = make_vk(
                &BENCHMARK_PI1_ALPHA_G1,
                &BENCHMARK_PI1_BETA_G2,
                &BENCHMARK_PI1_GAMMA_G2,
                &BENCHMARK_PI1_DELTA_G2,
                &BENCHMARK_PI1_IC,
            );
            verify_groth16_proof::<1>(&vk, &proof, &public_inputs)
        }
        _ => err!(VaultError::InvalidProof),
    }
}
