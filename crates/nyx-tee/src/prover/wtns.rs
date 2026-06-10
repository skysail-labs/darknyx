//! Serialize an ark witness vector into the snarkjs `.wtns` v2 binary format
//! that rapidsnark consumes. ark-circom keeps the witness in memory as a
//! `Vec<Fr>` (signal order); rapidsnark's `groth16_prover_prove` takes the
//! `.wtns` BYTES (no temp file), so this bridges the two.
//!
//! Format (mirrors rapidsnark `binfile_utils` + `wtns_utils`):
//!   "wtns"            4 bytes magic
//!   version           u32 LE  (= 2)
//!   nSections         u32 LE  (= 2)
//!   ── section 1 (header) ──
//!   sectionType=1     u32 LE
//!   sectionSize       u64 LE  (= 4 + n8 + 4)
//!   n8                u32 LE  (= 32)
//!   prime             n8 bytes LE  (BN254 Fr modulus)
//!   nWitness          u32 LE
//!   ── section 2 (data) ──
//!   sectionType=2     u32 LE
//!   sectionSize       u64 LE  (= nWitness * n8)
//!   witness[i]        n8 bytes LE   for each witness element

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

const N8: u32 = 32;

/// Serialize the full witness vector (incl. the leading `1`) to `.wtns` v2 bytes.
pub fn serialize_wtns(witness: &[Fr]) -> Vec<u8> {
    let n = witness.len();
    // The .wtns format stores nWitness as a u32 (line 15). A witness exceeding
    // u32::MAX is physically impossible here (>137 GB at 32 B/element), but make
    // the format bound explicit so the `n as u32` below can never silently wrap.
    debug_assert!(n <= u32::MAX as usize, "witness length {n} exceeds .wtns u32 nWitness bound");
    let mut out = Vec::with_capacity(12 + (4 + 8 + 40) + (4 + 8) + n * 32);

    out.extend_from_slice(b"wtns");
    out.extend_from_slice(&2u32.to_le_bytes()); // version
    out.extend_from_slice(&2u32.to_le_bytes()); // nSections

    // ── section 1: header ──
    out.extend_from_slice(&1u32.to_le_bytes());
    let header_size: u64 = 4 + u64::from(N8) + 4; // n8 + prime + nWitness
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&N8.to_le_bytes());
    out.extend_from_slice(&fr_modulus_le());
    out.extend_from_slice(&(n as u32).to_le_bytes());

    // ── section 2: witness values ──
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&((n as u64) * u64::from(N8)).to_le_bytes());
    for w in witness {
        out.extend_from_slice(&fr_to_le32(w));
    }
    out
}

/// 32-byte little-endian encoding of a BN254 scalar (zero-padded).
fn fr_to_le32(fr: &Fr) -> [u8; 32] {
    let mut v = fr.into_bigint().to_bytes_le();
    v.resize(32, 0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v[..32]);
    out
}

/// BN254 Fr modulus, 32-byte little-endian (the `.wtns` header's `prime`).
fn fr_modulus_le() -> [u8; 32] {
    let mut v = Fr::MODULUS.to_bytes_le();
    v.resize(32, 0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v[..32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, Zero};

    #[test]
    fn header_and_framing_are_well_formed() {
        let w = vec![Fr::one(), Fr::from(7u64), Fr::zero()];
        let b = serialize_wtns(&w);
        assert_eq!(&b[0..4], b"wtns");
        assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 2); // version
        assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()), 2); // nSections
                                                                         // section 1 header
        assert_eq!(u32::from_le_bytes(b[12..16].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(b[16..24].try_into().unwrap()), 40); // 4+32+4
        assert_eq!(u32::from_le_bytes(b[24..28].try_into().unwrap()), 32); // n8
                                                                           // prime then nWitness at offset 28+32 = 60
        assert_eq!(u32::from_le_bytes(b[60..64].try_into().unwrap()), 3); // nWitness
                                                                          // section 2
        assert_eq!(u32::from_le_bytes(b[64..68].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(b[68..76].try_into().unwrap()), 3 * 32);
        // first witness value == 1 (LE)
        assert_eq!(b[76], 1);
        assert!(b[77..108].iter().all(|&x| x == 0));
        assert_eq!(b.len(), 76 + 3 * 32);
    }

    #[test]
    fn prime_is_bn254_fr_modulus() {
        // Low byte of the BN254 Fr modulus is 0x01.
        let m = fr_modulus_le();
        assert_eq!(m[0], 0x01);
        // It must be 32 bytes and non-zero in the high half.
        assert!(m[24..].iter().any(|&x| x != 0));
    }
}
