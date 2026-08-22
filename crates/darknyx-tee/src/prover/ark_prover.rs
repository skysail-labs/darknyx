//! ark-circom-backed VALID_MATCH_BATCH prover.
//!
//! Implements the [`super::groth16::Prover`] trait by:
//!   1. Running the deterministic pre-flight (conservation
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

use std::path::Path;
use std::sync::Mutex;

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomCircuit, CircomConfig, CircomReduction};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey};
use num_bigint::{BigInt, Sign};

use super::convert::proof_to_onchain_bytes;
use super::groth16::{ProofWithInputs, Prover, ProverError, ProverTimings};
use super::inputs::{build_batch_public_inputs, BatchPublicInputs};
use super::witness::MatchSlotWitness;

/// ark-circom-backed prover for a fixed circuit instantiation N.
pub struct ArkMatchBatchProver {
    /// Cached proving key parsed from `circuit_final.zkey`.
    pk: ProvingKey<Bn254>,
    /// Cached ark-circom witness calculator: the wasm is compiled
    /// (`Module::from_file`) + the r1cs parsed ONCE here, then reused across
    /// every `prove()` (`calculate_witness` re-inits the wasm instance, so the
    /// witness stays byte-identical). `Mutex` because the wasmer `Store` is
    /// `!Sync` and the settle worker proves one batch at a time anyway. Removes
    /// the per-call wasm compile (~350 ms ≈ half of witness-gen) the old path
    /// paid on every prove.
    cfg: Mutex<CircomConfig<Fr>>,
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
        let dir = circuits_build_dir.as_ref();
        let zkey_path = dir
            .join(format!("match_batch_n{n}"))
            .join("circuit_final.zkey");

        let mut zkey_file = std::fs::File::open(&zkey_path)
            .map_err(|e| ProverError::Io(format!("open zkey {}: {e}", zkey_path.display())))?;
        let (pk, _matrices) = ark_circom::read_zkey(&mut zkey_file)
            .map_err(|e| ProverError::Io(format!("read_zkey {}: {e}", zkey_path.display())))?;

        let cfg = load_circom_cfg(dir, n)?;

        Ok(Self { pk, cfg, n })
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
        let (proof, public, _) = self.prove_ark_with_timings(slots)?;
        Ok((proof, public))
    }

    fn prove_ark_with_timings(
        &self,
        slots: &[MatchSlotWitness],
    ) -> Result<(Proof<Bn254>, BatchPublicInputs, ProverTimings), ProverError> {
        if slots.len() != self.n {
            return Err(ProverError::BatchSizeMismatch {
                expected: self.n,
                got: slots.len(),
            });
        }

        // 1. Deterministic pre-flight. Surfaces bad batches
        //    as named-constraint violations BEFORE the expensive
        //    witness calc + prove.
        super::constraints::validate_conservation(slots)?;
        let public = build_batch_public_inputs(slots)?;

        // 2-3. Build the ark-circom witness + cross-check the circuit's
        //      Merkle root against our off-circuit one (shared with the
        //      rapidsnark backend, which reuses this witness).
        let t_w = std::time::Instant::now();
        let circom = build_circom_and_check(&self.cfg, slots, &public)?;
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

        Ok((
            proof,
            public,
            ProverTimings {
                backend: "ark".to_string(),
                witness_backend: "wasmer".to_string(),
                device: None,
                witness_ms: witness_ms as u64,
                prove_step_ms: prove_step_ms as u64,
            },
        ))
    }
}

impl Prover for ArkMatchBatchProver {
    fn prove(&self, slots: &[MatchSlotWitness]) -> Result<ProofWithInputs, ProverError> {
        let (proof, public, timings) = self.prove_ark_with_timings(slots)?;
        Ok(ProofWithInputs {
            proof: proof_to_onchain_bytes(&proof),
            public,
            timings,
        })
    }

    fn n(&self) -> usize {
        self.n
    }
}

/// Compile the witness calculator (wasm) + parse the r1cs ONCE, returning a
/// `Mutex`-wrapped `CircomConfig` to cache on the prover. The wasm compile
/// (`Module::from_file`) is ~half of per-prove witness-gen, so doing it here
/// instead of per `build_circom_and_check` call is the Step-0 win. Shared by
/// both backends' `load` (the witness path is ark-circom either way).
pub(crate) fn load_circom_cfg(
    circuits_build_dir: &Path,
    n: usize,
) -> Result<Mutex<CircomConfig<Fr>>, ProverError> {
    let base = circuits_build_dir.join(format!("match_batch_n{n}"));
    let wasm_path = base.join("circuit_js").join("circuit.wasm");
    let r1cs_path = base.join("circuit.r1cs");
    let t = std::time::Instant::now();
    let cfg = CircomConfig::<Fr>::new(&wasm_path, &r1cs_path)
        .map_err(|e| ProverError::WitnessGen(format!("CircomConfig::new: {e}")))?;
    tracing::info!(
        parse_ms = t.elapsed().as_millis() as u64,
        n,
        "witness-gen cfg compiled + cached (wasm compile + r1cs parse, once at load)"
    );
    Ok(Mutex::new(cfg))
}

/// Build the ark-circom witness for `slots` (using the CACHED `CircomConfig`)
/// and cross-check that the circuit's two public inputs (its
/// internally-computed Merkle root plus governed-config digest) equal our
/// off-circuit values. Returns the built `CircomCircuit` (whose
/// `.witness` is the full assignment) so BOTH backends share one witness-gen +
/// drift guard:
///   - ark proves `circom` directly with `create_random_proof_with_reduction`,
///   - rapidsnark serializes `circom.witness` to `.wtns` and proves via FFI.
///
/// Reuses the cached `WitnessCalculator` + wasmer `Store` under the `Mutex`
/// (`calculate_witness` re-inits the instance each call → byte-identical
/// witness; no per-call wasm recompile). This replaces `CircomBuilder`, which
/// would consume a fresh `CircomConfig`.
pub(crate) fn build_circom_and_check(
    cfg_cell: &Mutex<CircomConfig<Fr>>,
    slots: &[MatchSlotWitness],
    public: &BatchPublicInputs,
) -> Result<CircomCircuit<Fr>, ProverError> {
    let mut inputs: std::collections::HashMap<String, Vec<BigInt>> =
        std::collections::HashMap::new();
    push_all_inputs(&mut inputs, slots, public);

    let t_exec = std::time::Instant::now();
    let circom = {
        let mut guard = cfg_cell
            .lock()
            .map_err(|_| ProverError::WitnessGen("circom cfg mutex poisoned".into()))?;
        // Disjoint mutable borrows of the cached config's fields so the witness
        // calc (wtns) + its Store are reused (no recompile). Mirrors
        // `CircomBuilder::{setup, build}` exactly.
        let CircomConfig {
            r1cs,
            wtns,
            store,
            sanity_check,
        } = &mut *guard;
        let mut circom = CircomCircuit {
            r1cs: r1cs.clone(),
            witness: None,
        };
        circom.r1cs.wire_mapping = None;
        let witness = wtns
            .calculate_witness_element::<Fr, _>(store, inputs, *sanity_check)
            .map_err(|e| ProverError::WitnessGen(format!("witness build: {e}")))?;
        circom.witness = Some(witness);
        circom
    };
    tracing::info!(
        exec_ms = t_exec.elapsed().as_millis() as u64,
        "witness-gen (cached cfg — exec only; wasm compile amortized at load)"
    );

    let circuit_public = circom
        .get_public_inputs()
        .ok_or_else(|| ProverError::WitnessGen("circuit produced no public inputs".into()))?;
    if circuit_public.len() != public.public_inputs_be.len() {
        return Err(ProverError::WitnessGen(format!(
            "expected {} public inputs ([root, config_digest]), got {}",
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
    // The config digest must match the off-circuit
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

/// Serialize the circuit inputs for `slots` to a circom `input.json` string
/// (consumed by the native C++ witness generator). Reuses `push_all_inputs`
/// so the inputs are byte-for-byte the SAME as the wasmer path feeds — the
/// batch-level signals are emitted as bare strings; per-slot signals are
/// length-N arrays of decimal strings. Mirrors the TS
/// `match-batch-prover.ts` inputs object exactly.
// Only the snarkjs-format backends' native witness path uses it.
#[cfg(any(feature = "rapidsnark", feature = "icicle"))]
pub(crate) fn circom_input_json(
    slots: &[MatchSlotWitness],
    public: &BatchPublicInputs,
) -> Result<String, ProverError> {
    let mut inputs: std::collections::HashMap<String, Vec<BigInt>> =
        std::collections::HashMap::new();
    push_all_inputs(&mut inputs, slots, public);

    // Batch-level `signal input` (no `[N]`) at the MatchBatch level → bare
    // scalar strings in input.json. Everything else is a per-slot array signal.
    // Keep IN SYNC with the scalar pushes in `push_all_inputs` and the circuit's
    // MatchBatch signal declarations.
    const SCALAR_INPUTS: &[&str] = &[
        "merkle_root",
        "config_digest",
        "fee_rate_bps",
        "protocol_owner_commitment",
        "base_mint_lo",
        "base_mint_hi",
        "quote_mint_lo",
        "quote_mint_hi",
        "price_scale",
    ];
    let mut obj = serde_json::Map::with_capacity(inputs.len());
    for (name, vals) in inputs {
        let value = if SCALAR_INPUTS.contains(&name.as_str()) {
            // A circuit SCALAR signal → a bare string.
            let v = vals
                .first()
                .ok_or_else(|| ProverError::WitnessGen(format!("empty scalar input {name}")))?;
            serde_json::Value::String(v.to_str_radix(10))
        } else {
            // Array signal → list of decimal strings, one per slot.
            serde_json::Value::Array(
                vals.iter()
                    .map(|b| serde_json::Value::String(b.to_str_radix(10)))
                    .collect(),
            )
        };
        obj.insert(name, value);
    }
    serde_json::to_string(&serde_json::Value::Object(obj))
        .map_err(|e| ProverError::WitnessGen(format!("serialize circom input.json: {e}")))
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
    inputs: &mut std::collections::HashMap<String, Vec<BigInt>>,
    slots: &[MatchSlotWitness],
    public: &BatchPublicInputs,
) {
    macro_rules! push {
        ($name:expr, $val:expr) => {
            inputs.entry($name.to_string()).or_default().push($val);
        };
    }
    // Public inputs (order matches the circuit `main` list).
    push!("merkle_root", be32_to_bigint(&public.merkle_root));
    push!("config_digest", be32_to_bigint(&public.config_digest));
    // Batch-level single (scalar) inputs — identical on every slot; read from
    // slot 0. These are `signal input` (no `[N]`) at the MatchBatch level, so
    // the native-witness JSON path must emit them as bare scalars (see
    // `circom_input_json`'s SCALAR_INPUTS set), not length-1 arrays.
    push!("fee_rate_bps", BigInt::from(slots[0].fee_rate_bps));
    push!(
        "protocol_owner_commitment",
        be32_to_bigint(&slots[0].protocol_owner_commitment)
    );
    let (base_lo, base_hi) = mint_lo_hi(&slots[0].base_mint);
    let (quote_lo, quote_hi) = mint_lo_hi(&slots[0].quote_mint);
    push!("base_mint_lo", base_lo);
    push!("base_mint_hi", base_hi);
    push!("quote_mint_lo", quote_lo);
    push!("quote_mint_hi", quote_hi);
    push!("price_scale", BigInt::from(slots[0].price_scale));

    macro_rules! push_u64 {
        ($name:literal, $field:ident) => {
            for s in slots {
                push!($name, BigInt::from(s.$field));
            }
        };
    }
    macro_rules! push_be32 {
        ($name:literal, $field:ident) => {
            for s in slots {
                push!($name, be32_to_bigint(&s.$field));
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
    push_be32!("note_fee_base_commitment", note_fee_base_commitment);
    push_be32!("note_fee_quote_commitment", note_fee_quote_commitment);

    push_u64!("base_amount", base_amount);
    push_u64!("quote_amount", quote_amount);
    push_u64!("buyer_change_amt", buyer_change_amt);
    push_u64!("seller_change_amt", seller_change_amt);
    push_u64!("buyer_fee_amt", buyer_fee_amt);
    push_u64!("seller_fee_amt", seller_fee_amt);
    push_u64!("batch_slot", batch_slot);
    for s in slots {
        push!("is_active", BigInt::from(u8::from(s.is_active)));
    }

    // VALID_CREATE private witnesses.
    push_be32!("a_owner_commit", a_owner_commit);
    push_be32!("b_owner_commit", b_owner_commit);
    push_u64!("a_amount", a_amount);
    push_u64!("b_amount", b_amount);
    // v2: one inner_hash per note (full Fr elements, 32-byte BE) — see
    // MatchSlotWitness. Keys match the circuit's `*_inner` signal names.
    push_be32!("a_inner", a_inner);
    push_be32!("b_inner", b_inner);
    // VALID_PRICE private witness.
    push_u64!("clearing_price", clearing_price);
    push_u64!("price_remainder", price_remainder);
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
