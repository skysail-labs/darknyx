//! Real ark-circom-backed VALID_MATCH_BATCH prover (PR 4g.4b).
//!
//! Implements the [`super::groth16::Prover`] trait by:
//!   1. Running the 4g.4a deterministic pre-flight (conservation
//!      constraints + leaf/root + public-input vector).
//!   2. Building a Circom witness from the slot inputs via
//!      ark-circom (wasmer-backed witness calc consuming
//!      `circuit.wasm` + `circuit.r1cs`).
//!   3. Cross-checking the circuit's computed public input (the
//!      Merkle root) against our off-circuit `compute_batch_root` —
//!      a mismatch means our leaf/root port drifted from the
//!      circuit, surfaced loudly rather than as a silent on-chain
//!      `InvalidProof`.
//!   4. Generating a Groth16 proof against the cached proving key.
//!   5. Converting the ark proof to the on-chain `groth16-solana`
//!      byte layout via [`super::convert::proof_to_onchain_bytes`].
//!
//! ## What's cached vs rebuilt
//!
//! The multi-MB `ProvingKey` (parsed from `circuit_final.zkey`) is
//! loaded ONCE at construction and cached. The `CircomConfig`
//! (wasm + r1cs parse) is rebuilt per `prove()` call because it
//! holds a wasmer `Store`, which is `!Sync` — caching it would
//! make the `Prover` non-`Sync`, breaking the `Send + Sync` trait
//! bound the settle-stage workers rely on. The per-call wasm parse
//! is ~100-300 ms; proving dominates at ~1-2 s. If profiling later
//! shows the parse matters, a `Mutex<CircomConfig>` or a Store pool
//! is the fix — internal, no trait-surface change.

use std::path::{Path, PathBuf};

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig, CircomReduction};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey};
use num_bigint::{BigInt, Sign};

use super::convert::proof_to_onchain_bytes;
use super::groth16::{ProofWithInputs, Prover, ProverError};
use super::inputs::{build_batch_public_inputs, BatchPublicInputs};
use super::witness::MatchSlotWitness;

/// ark-circom-backed prover for a fixed circuit instantiation N.
pub struct ArkMatchBatchProver {
    /// Cached proving key parsed from `circuit_final.zkey`.
    pk: ProvingKey<Bn254>,
    /// Path to `circuit.wasm` (witness calculator).
    wasm_path: PathBuf,
    /// Path to `circuit.r1cs` (constraint system).
    r1cs_path: PathBuf,
    /// Circuit instantiation size (2, 4, or 16).
    n: usize,
}

impl ArkMatchBatchProver {
    /// Load the proving key + record the wasm/r1cs paths. The
    /// `circuits_dir` is the repo's `circuits/build` (or the
    /// in-image `/circuits/build`); we resolve
    /// `match_batch_n{N}/{circuit_final.zkey, circuit_js/circuit.wasm,
    /// circuit.r1cs}` under it.
    pub fn load(circuits_build_dir: impl AsRef<Path>, n: usize) -> Result<Self, ProverError> {
        let base = circuits_build_dir
            .as_ref()
            .join(format!("match_batch_n{n}"));
        let zkey_path = base.join("circuit_final.zkey");
        let wasm_path = base.join("circuit_js").join("circuit.wasm");
        let r1cs_path = base.join("circuit.r1cs");

        let mut zkey_file = std::fs::File::open(&zkey_path)
            .map_err(|e| ProverError::Io(format!("open zkey {}: {e}", zkey_path.display())))?;
        let (pk, _matrices) = ark_circom::read_zkey(&mut zkey_file)
            .map_err(|e| ProverError::Io(format!("read_zkey {}: {e}", zkey_path.display())))?;

        Ok(Self {
            pk,
            wasm_path,
            r1cs_path,
            n,
        })
    }

    /// Read-only access to the cached proving key's verifying key.
    /// Used by tests (and a future `/info`-style self-check) to
    /// verify a freshly-produced proof against the same VK the
    /// zkey carries.
    pub fn verifying_key(&self) -> &ark_groth16::VerifyingKey<Bn254> {
        &self.pk.vk
    }

    /// Core proving path returning the RAW ark proof + public
    /// inputs. `Prover::prove` wraps this with the on-chain byte
    /// conversion. Exposed (ark-typed) so tests can verify the
    /// proof against the zkey VK via ark-groth16 directly; the
    /// generic `Prover` trait stays ark-free so a rapidsnark swap
    /// doesn't touch call-sites.
    pub fn prove_ark(
        &self,
        slots: &[MatchSlotWitness],
    ) -> Result<(Proof<Bn254>, BatchPublicInputs), ProverError> {
        if slots.len() != self.n {
            return Err(ProverError::BatchSizeMismatch {
                expected: self.n,
                got: slots.len(),
            });
        }

        // 1. Deterministic pre-flight (4g.4a). Surfaces bad batches
        //    as named-constraint violations BEFORE the expensive
        //    witness calc + prove.
        super::constraints::validate_conservation(slots)?;
        let public = build_batch_public_inputs(slots)?;

        // 2-3. Build the ark-circom witness + cross-check the circuit's
        //      Merkle root against our off-circuit one (shared with the
        //      rapidsnark backend, which reuses this witness).
        let t_w = std::time::Instant::now();
        let circom = build_circom_and_check(&self.wasm_path, &self.r1cs_path, slots, &public)?;
        let witness_ms = t_w.elapsed().as_millis();

        // 4. Prove against the cached proving key.
        let t_p = std::time::Instant::now();
        let mut rng = rand::thread_rng();
        let proof = Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(
            circom, &self.pk, &mut rng,
        )
        .map_err(|e| ProverError::Prove(format!("groth16 prove: {e}")))?;
        let prove_step_ms = t_p.elapsed().as_millis();
        tracing::info!(
            backend = "ark",
            witness_ms = witness_ms as u64,
            prove_step_ms = prove_step_ms as u64,
            "prove breakdown (witness-gen vs groth16 prove)"
        );

        Ok((proof, public))
    }
}

impl Prover for ArkMatchBatchProver {
    fn prove(&self, slots: &[MatchSlotWitness]) -> Result<ProofWithInputs, ProverError> {
        let (proof, public) = self.prove_ark(slots)?;
        Ok(ProofWithInputs {
            proof: proof_to_onchain_bytes(&proof),
            public,
        })
    }

    fn n(&self) -> usize {
        self.n
    }
}

/// Build the ark-circom witness for `slots` and cross-check that the circuit's
/// single public input (its internally-computed Merkle root) equals our
/// off-circuit `build_batch_public_inputs` root. Returns the built
/// `CircomCircuit` (whose `.witness` is the full assignment) so BOTH backends
/// share one witness-gen + drift guard:
///   - ark proves `circom` directly with `create_random_proof_with_reduction`,
///   - rapidsnark serializes `circom.witness` to `.wtns` and proves via FFI.
///
/// The wasmer `Store` inside `CircomConfig` is `!Sync`, so this is called fresh
/// per prove (the ~100-300ms witness parse; proving dominates).
pub(crate) fn build_circom_and_check(
    wasm_path: &Path,
    r1cs_path: &Path,
    slots: &[MatchSlotWitness],
    public: &BatchPublicInputs,
) -> Result<CircomCircuit<Fr>, ProverError> {
    let cfg = CircomConfig::<Fr>::new(wasm_path, r1cs_path)
        .map_err(|e| ProverError::WitnessGen(format!("CircomConfig::new: {e}")))?;
    let mut builder = CircomBuilder::new(cfg);
    push_all_inputs(&mut builder, slots, &public.merkle_root);

    let circom = builder
        .build()
        .map_err(|e| ProverError::WitnessGen(format!("witness build: {e}")))?;

    let circuit_public = circom
        .get_public_inputs()
        .ok_or_else(|| ProverError::WitnessGen("circuit produced no public inputs".into()))?;
    if circuit_public.len() != public.public_inputs_be.len() {
        return Err(ProverError::WitnessGen(format!(
            "expected {} public inputs ([merkle_root, fee_rate_bps]), got {}",
            public.public_inputs_be.len(),
            circuit_public.len()
        )));
    }
    let circuit_root = fr_to_be32(&circuit_public[0]);
    if circuit_root != public.merkle_root {
        return Err(ProverError::RootMismatch {
            circuit: hex::encode(circuit_root),
            computed: hex::encode(public.merkle_root),
        });
    }
    // Remaining public inputs (fee_rate_bps, …) must match the off-circuit
    // vector IN ORDER, or the on-chain verifier would reject the proof.
    for (i, cp) in circuit_public.iter().enumerate().skip(1) {
        let got = fr_to_be32(cp);
        if got != public.public_inputs_be[i] {
            return Err(ProverError::WitnessGen(format!(
                "public input[{i}] mismatch: circuit {} != computed {}",
                hex::encode(got),
                hex::encode(public.public_inputs_be[i])
            )));
        }
    }
    Ok(circom)
}

/// Big-endian 32-byte encoding of a BN254 scalar-field element.
fn fr_to_be32(fr: &Fr) -> [u8; 32] {
    let v = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// Push every circuit signal. Array signals are fed one element
/// per slot, IN ORDER — `push_input` accumulates repeated names
/// into the circuit's array signal. Names + ordering mirror the TS
/// `proveMatchBatch` inputs object exactly.
fn push_all_inputs(
    builder: &mut CircomBuilder<Fr>,
    slots: &[MatchSlotWitness],
    merkle_root: &[u8; 32],
) {
    // Public inputs (order matches the circuit `main` list).
    builder.push_input("merkle_root", be32_to_bigint(merkle_root));
    // fee_rate_bps is a single batch-level input (same on every slot).
    builder.push_input("fee_rate_bps", BigInt::from(slots[0].fee_rate_bps));

    macro_rules! push_u64 {
        ($name:literal, $field:ident) => {
            for s in slots {
                builder.push_input($name, BigInt::from(s.$field));
            }
        };
    }
    macro_rules! push_be32 {
        ($name:literal, $field:ident) => {
            for s in slots {
                builder.push_input($name, be32_to_bigint(&s.$field));
            }
        };
    }

    // VALID_CREATE-equivalent public fields.
    push_be32!("note_a_commitment", note_a_commitment);
    push_be32!("note_b_commitment", note_b_commitment);
    push_be32!("note_c_commitment", note_c_commitment);
    push_be32!("note_d_commitment", note_d_commitment);
    push_be32!("note_e_commitment", note_e_commitment);
    push_be32!("note_f_commitment", note_f_commitment);

    // Mint halves. lo = bytes[16..32], hi = bytes[0..16] — matches
    // `darkpool_crypto::pubkey_to_fr_pair` and the TS `pubkeyToFrPair`.
    for s in slots {
        let (lo, hi) = mint_lo_hi(&s.quote_mint);
        builder.push_input("quote_mint_lo", lo);
        builder.push_input("quote_mint_hi", hi);
    }
    for s in slots {
        let (lo, hi) = mint_lo_hi(&s.base_mint);
        builder.push_input("base_mint_lo", lo);
        builder.push_input("base_mint_hi", hi);
    }

    push_u64!("base_amount", base_amount);
    push_u64!("quote_amount", quote_amount);
    push_u64!("buyer_change_amt", buyer_change_amt);
    push_u64!("seller_change_amt", seller_change_amt);
    push_u64!("buyer_fee_amt", buyer_fee_amt);
    push_u64!("seller_fee_amt", seller_fee_amt);
    push_u64!("batch_slot", batch_slot);

    // VALID_CREATE private witnesses.
    push_be32!("a_owner_commit", a_owner_commit);
    push_be32!("b_owner_commit", b_owner_commit);
    push_u64!("a_amount", a_amount);
    push_u64!("b_amount", b_amount);
    // v2: one inner_hash per note (full Fr elements, 32-byte BE) — see
    // MatchSlotWitness. Keys match the circuit's `*_inner` signal names.
    push_be32!("a_inner", a_inner);
    push_be32!("b_inner", b_inner);
    push_be32!("c_inner", c_inner);
    push_be32!("d_inner", d_inner);
    push_be32!("e_inner", e_inner);
    push_be32!("f_inner", f_inner);

    // VALID_PRICE private witness.
    push_u64!("clearing_price", clearing_price);
}

fn be32_to_bigint(b: &[u8; 32]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, b)
}

/// Split a 32-byte BE pubkey into `(lo, hi)` BigInts. `hi` is the
/// top 16 bytes, `lo` the bottom 16 — same split as
/// `pubkey_to_fr_pair`.
fn mint_lo_hi(mint: &[u8; 32]) -> (BigInt, BigInt) {
    let hi = BigInt::from_bytes_be(Sign::Plus, &mint[0..16]);
    let lo = BigInt::from_bytes_be(Sign::Plus, &mint[16..32]);
    (lo, hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_lo_hi_splits_halves() {
        let mut mint = [0u8; 32];
        mint[15] = 0xAB; // last byte of the hi half
        mint[31] = 0xCD; // last byte of the lo half
        let (lo, hi) = mint_lo_hi(&mint);
        assert_eq!(lo, BigInt::from(0xCDu64));
        assert_eq!(hi, BigInt::from(0xABu64));
    }

    #[test]
    fn be32_to_bigint_is_big_endian() {
        let mut b = [0u8; 32];
        b[31] = 1;
        assert_eq!(be32_to_bigint(&b), BigInt::from(1u64));
        let mut b2 = [0u8; 32];
        b2[30] = 1; // 256
        assert_eq!(be32_to_bigint(&b2), BigInt::from(256u64));
    }

    #[test]
    fn fr_to_be32_round_trips_small() {
        use ark_ff::Field;
        let one = Fr::ONE;
        let b = fr_to_be32(&one);
        assert_eq!(b[31], 1);
        assert!(b[..31].iter().all(|&x| x == 0));
    }
}
