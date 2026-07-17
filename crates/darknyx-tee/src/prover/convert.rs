//! ark-groth16 `Proof<Bn254>` → on-chain `groth16-solana` byte format.
//!
//! Byte-for-byte mirror of the SDK's
//! `packages/sdk/src/zk/groth16-format.ts::formatGroth16ForOnChain`,
//! which is itself the reference for what the on-chain
//! `vault::zk::verifier::Groth16Proof` (256 bytes: pi_a 64 + pi_b
//! 128 + pi_c 64) expects. The on-chain `groth16-solana` verifier
//! does NOT negate pi_a internally, so we negate here.
//!
//! Layout produced (all field elements big-endian 32-byte):
//!
//! ```text
//!   pi_a (64)  = a.x || (-a.y)
//!   pi_b (128) = b.x.c1 || b.x.c0 || b.y.c1 || b.y.c0
//!                (Fq2 coefficient pairs swapped — snarkjs emits
//!                 (c0, c1); groth16-solana wants (c1, c0))
//!   pi_c (64)  = c.x || c.y
//! ```
//!
//! The negation + the Fq2 swap are the two easy-to-get-wrong
//! pieces; the unit tests below pin both against a round-trip
//! decode.

use ark_bn254::{Bn254, Fq};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Proof;

use crate::settle::Groth16ProofBytes;

/// Big-endian 32-byte encoding of a BN254 base-field element.
/// `to_bytes_be` on the 4-limb BigInteger is always exactly 32
/// bytes, so the `copy_from_slice` cannot panic.
fn fq_be32(fq: &Fq) -> [u8; 32] {
    let v = fq.into_bigint().to_bytes_be();
    debug_assert_eq!(v.len(), 32, "BN254 Fq must encode to 32 BE bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// Convert an ark-groth16 proof to the on-chain 256-byte layout.
pub fn proof_to_onchain_bytes(proof: &Proof<Bn254>) -> Groth16ProofBytes {
    // pi_a = a.x || (-a.y). `-proof.a.y` is the field negation
    // (P - y mod P), matching the SDK's `negateG1`.
    let mut pi_a = [0u8; 64];
    pi_a[..32].copy_from_slice(&fq_be32(&proof.a.x));
    pi_a[32..].copy_from_slice(&fq_be32(&(-proof.a.y)));

    // pi_b = b.x.c1 || b.x.c0 || b.y.c1 || b.y.c0.
    let mut pi_b = [0u8; 128];
    pi_b[0..32].copy_from_slice(&fq_be32(&proof.b.x.c1));
    pi_b[32..64].copy_from_slice(&fq_be32(&proof.b.x.c0));
    pi_b[64..96].copy_from_slice(&fq_be32(&proof.b.y.c1));
    pi_b[96..128].copy_from_slice(&fq_be32(&proof.b.y.c0));

    // pi_c = c.x || c.y (no negation).
    let mut pi_c = [0u8; 64];
    pi_c[..32].copy_from_slice(&fq_be32(&proof.c.x));
    pi_c[32..].copy_from_slice(&fq_be32(&proof.c.y));

    Groth16ProofBytes { pi_a, pi_b, pi_c }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq2, G1Affine, G2Affine};
    use ark_ff::{Field, UniformRand};
    use ark_groth16::Proof;

    fn fq_from_be32(b: &[u8]) -> Fq {
        Fq::from_be_bytes_mod_order(b)
    }

    /// Build a deterministic non-identity proof from a seeded RNG.
    /// We only need well-formed curve points to exercise the byte
    /// layout — they need not satisfy any pairing relation.
    fn sample_proof() -> Proof<Bn254> {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xABCD_1234);
        Proof {
            a: G1Affine::rand(&mut rng),
            b: G2Affine::rand(&mut rng),
            c: G1Affine::rand(&mut rng),
        }
    }

    #[test]
    fn output_widths_are_exact() {
        let proof = sample_proof();
        let bytes = proof_to_onchain_bytes(&proof);
        assert_eq!(bytes.pi_a.len(), 64);
        assert_eq!(bytes.pi_b.len(), 128);
        assert_eq!(bytes.pi_c.len(), 64);
    }

    #[test]
    fn pi_a_x_round_trips_and_y_is_negated() {
        let proof = sample_proof();
        let bytes = proof_to_onchain_bytes(&proof);

        // x half decodes back to a.x.
        let x = fq_from_be32(&bytes.pi_a[..32]);
        assert_eq!(x, proof.a.x);

        // y half decodes back to -a.y (the field negation).
        let y_enc = fq_from_be32(&bytes.pi_a[32..]);
        assert_eq!(y_enc, -proof.a.y);
        // And -(-a.y) == a.y, so the encoded value is NOT the raw y
        // unless y == 0 (it isn't for a random point).
        assert_ne!(y_enc, proof.a.y);
    }

    #[test]
    fn pi_b_swaps_fq2_coefficients() {
        let proof = sample_proof();
        let bytes = proof_to_onchain_bytes(&proof);

        // Reconstruct the Fq2 coords from the swapped layout and
        // confirm they equal the original b.x / b.y.
        let x_c1 = fq_from_be32(&bytes.pi_b[0..32]);
        let x_c0 = fq_from_be32(&bytes.pi_b[32..64]);
        let y_c1 = fq_from_be32(&bytes.pi_b[64..96]);
        let y_c0 = fq_from_be32(&bytes.pi_b[96..128]);

        assert_eq!(Fq2::new(x_c0, x_c1), proof.b.x);
        assert_eq!(Fq2::new(y_c0, y_c1), proof.b.y);

        // The swap is observable: c1 slot != c0 slot for a random
        // point (guards against accidentally writing (c0, c1)).
        assert_ne!(x_c1, x_c0);
    }

    #[test]
    fn pi_c_round_trips_without_negation() {
        let proof = sample_proof();
        let bytes = proof_to_onchain_bytes(&proof);
        let x = fq_from_be32(&bytes.pi_c[..32]);
        let y = fq_from_be32(&bytes.pi_c[32..]);
        assert_eq!(x, proof.c.x);
        assert_eq!(y, proof.c.y); // NOT negated, unlike pi_a
    }

    #[test]
    fn fq_be32_is_fixed_width() {
        let one = Fq::ONE;
        let b = fq_be32(&one);
        assert_eq!(b.len(), 32);
        assert_eq!(b[31], 1);
        assert!(b[..31].iter().all(|&x| x == 0));
    }
}
