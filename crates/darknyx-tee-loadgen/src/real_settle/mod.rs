//! Real-settle support (Increment A): native C++ client-circuit witnesses,
//! ark-groth16 proving, and a Poseidon Merkle witness, so the loadgen can drive
//! real on-chain settlement instead of only synthetic intake. Gated behind the
//! `real-settle` cargo feature.
//!
//! There is no reusable Rust VALID_INPUT prover elsewhere in the tree — the TEE
//! proves VALID_MATCH_BATCH; clients prove VALID_INPUT via snarkjs. This mirrors
//! the SDK's `tests/helpers/valid-input-prover.ts` signal layout and produces the
//! same 256-byte on-chain proof without invoking a WASM witness runtime.
//!
//! Increment B (deposit on-chain → witness → POST order → track settle) layers
//! the Solana glue on top of this (the `vault` + `rpc` submodules, behind the
//! `real-settle-chain` feature); see BENCHMARK.md.

#[cfg(feature = "real-settle-chain")]
pub mod flow;
#[cfg(feature = "real-settle-chain")]
pub mod rpc;
#[cfg(feature = "real-settle-chain")]
pub mod run;
#[cfg(feature = "real-settle-chain")]
pub mod spl;
#[cfg(feature = "real-settle-chain")]
pub mod vault;

use std::path::{Path, PathBuf};

use ark_bn254::{Bn254, Fq, Fr};
use ark_circom::CircomReduction;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use num_bigint::{BigInt, Sign};

use darkpool_crypto::note::owner_commitment;
use darkpool_crypto::{
    commitment_from_fields_v2, deposit_inner_hash, fr_to_be_bytes, merge_output_inner_hash,
    note_use_tag, poseidon_hash_bytes, pubkey_to_fr_pair,
};

/// Depth of the vault's incremental Merkle tree (the VALID_INPUT witness is 20
/// levels — see `MerkleWitnessFr20` in the SDK).
pub const TREE_DEPTH: usize = 20;

#[derive(Debug, thiserror::Error)]
pub enum RealSettleError {
    #[error("io: {0}")]
    Io(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("witness/prove: {0}")]
    Prove(String),
    #[error("leaf index {0} out of range (tree has {1} leaves)")]
    LeafOutOfRange(usize, usize),
    /// Increment B: a JSON-RPC call / encoding / on-chain error.
    #[cfg(feature = "real-settle-chain")]
    #[error("rpc: {0}")]
    Rpc(String),
    /// Increment B: a confirmed tx had no parseable NoteCreated event.
    #[cfg(feature = "real-settle-chain")]
    #[error("event: {0}")]
    Event(String),
}

static NATIVE_WITNESS_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn decimal(value: BigInt) -> serde_json::Value {
    serde_json::Value::String(value.to_str_radix(10))
}

fn decimal_be32(value: &[u8; 32]) -> serde_json::Value {
    decimal(be32_to_bigint(value))
}

fn decimal_fr(value: &Fr) -> serde_json::Value {
    decimal(fr_to_bigint(value))
}

fn decimal_u64(value: u64) -> serde_json::Value {
    decimal(BigInt::from(value))
}

fn decimal_array(values: impl IntoIterator<Item = BigInt>) -> serde_json::Value {
    serde_json::Value::Array(values.into_iter().map(decimal).collect())
}

fn required_native_witness(base: &Path) -> Result<PathBuf, RealSettleError> {
    let path = base.join("circuit_cpp").join("native-witness");
    if !path.is_file() {
        return Err(RealSettleError::Prove(format!(
            "native witness generator missing at {}; run scripts/build-native-client-witnesses.sh",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .map_err(|e| {
                RealSettleError::Io(format!("inspect native witness {}: {e}", path.display()))
            })?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err(RealSettleError::Prove(format!(
                "native witness generator is not executable at {}; rerun scripts/build-native-client-witnesses.sh",
                path.display()
            )));
        }
    }
    Ok(path)
}

/// Run a mandatory native Circom witness generator and parse its `.wtns`
/// assignment. The loadgen intentionally has no Wasmer fallback: a paid
/// benchmark must fail before touching devnet if the native artifacts were not
/// prepared by `scripts/build-native-client-witnesses.sh`.
fn native_witness_assignment(
    witness_bin: &Path,
    input_json: &str,
) -> Result<Vec<Fr>, RealSettleError> {
    if !witness_bin.is_file() {
        return Err(RealSettleError::Prove(format!(
            "native witness generator missing at {}; run scripts/build-native-client-witnesses.sh",
            witness_bin.display()
        )));
    }
    let seq = NATIVE_WITNESS_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("darknyx-client-wtns-{}-{seq}", std::process::id()));
    std::fs::create_dir(&dir)
        .map_err(|e| RealSettleError::Io(format!("create native witness temp dir: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| RealSettleError::Io(format!("secure witness temp dir: {e}")))?;
    }
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let input_path = dir.join("input.json");
    let witness_path = dir.join("witness.wtns");
    std::fs::write(&input_path, input_json)
        .map_err(|e| RealSettleError::Io(format!("write native witness input: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&input_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| RealSettleError::Io(format!("secure witness input: {e}")))?;
    }

    let output = std::process::Command::new(witness_bin)
        .arg(&input_path)
        .arg(&witness_path)
        .output()
        .map_err(|e| {
            RealSettleError::Prove(format!(
                "spawn native witness generator {}: {e}",
                witness_bin.display()
            ))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.lines().last().unwrap_or("no generator detail");
        return Err(RealSettleError::Prove(format!(
            "native witness generator failed ({}): {detail}",
            output.status
        )));
    }
    let bytes = std::fs::read(&witness_path)
        .map_err(|e| RealSettleError::Io(format!("read native .wtns: {e}")))?;
    parse_wtns_assignment(&bytes)
}

fn read_u32_le(bytes: &[u8], offset: &mut usize) -> Result<u32, RealSettleError> {
    let end = offset.saturating_add(4);
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| RealSettleError::Prove("native .wtns truncated at u32".to_string()))?;
    *offset = end;
    Ok(u32::from_le_bytes(value.try_into().expect("four bytes")))
}

fn read_u64_le(bytes: &[u8], offset: &mut usize) -> Result<u64, RealSettleError> {
    let end = offset.saturating_add(8);
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| RealSettleError::Prove("native .wtns truncated at u64".to_string()))?;
    *offset = end;
    Ok(u64::from_le_bytes(value.try_into().expect("eight bytes")))
}

fn fr_modulus_le() -> [u8; 32] {
    let mut bytes = Fr::MODULUS.to_bytes_le();
    bytes.resize(32, 0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn parse_wtns_assignment(bytes: &[u8]) -> Result<Vec<Fr>, RealSettleError> {
    if bytes.get(0..4) != Some(&b"wtns"[..]) {
        return Err(RealSettleError::Prove(
            "native witness has invalid .wtns magic".to_string(),
        ));
    }
    let mut offset = 4usize;
    if read_u32_le(bytes, &mut offset)? != 2 || read_u32_le(bytes, &mut offset)? != 2 {
        return Err(RealSettleError::Prove(
            "native witness must be .wtns v2 with two sections".to_string(),
        ));
    }
    if read_u32_le(bytes, &mut offset)? != 1 || read_u64_le(bytes, &mut offset)? != 40 {
        return Err(RealSettleError::Prove(
            "native witness has invalid header section".to_string(),
        ));
    }
    if read_u32_le(bytes, &mut offset)? != 32 {
        return Err(RealSettleError::Prove(
            "native witness field width is not 32 bytes".to_string(),
        ));
    }
    let prime_end = offset + 32;
    if bytes.get(offset..prime_end) != Some(fr_modulus_le().as_slice()) {
        return Err(RealSettleError::Prove(
            "native witness field modulus is not BN254 Fr".to_string(),
        ));
    }
    offset = prime_end;
    let count = read_u32_le(bytes, &mut offset)? as usize;
    if read_u32_le(bytes, &mut offset)? != 2 {
        return Err(RealSettleError::Prove(
            "native witness data section missing".to_string(),
        ));
    }
    let section_bytes = read_u64_le(bytes, &mut offset)?;
    let expected_bytes = (count as u64)
        .checked_mul(32)
        .ok_or_else(|| RealSettleError::Prove("native witness length overflow".to_string()))?;
    if section_bytes != expected_bytes
        || bytes.len().saturating_sub(offset) != expected_bytes as usize
    {
        return Err(RealSettleError::Prove(
            "native witness data length mismatch".to_string(),
        ));
    }
    Ok(bytes[offset..]
        .chunks_exact(32)
        .map(Fr::from_le_bytes_mod_order)
        .collect())
}

fn native_ark_proof(
    pk: &ProvingKey<Bn254>,
    matrices: &ConstraintMatrices<Fr>,
    witness_bin: &Path,
    input_json: &str,
) -> Result<Proof<Bn254>, RealSettleError> {
    let assignment = native_witness_assignment(witness_bin, input_json)?;
    let expected = matrices
        .num_instance_variables
        .checked_add(matrices.num_witness_variables)
        // ark-circom's snarkjs zkey parser counts the implicit constant-one
        // variable in both halves of this sum. A Circom `.wtns` contains it
        // once, so its canonical assignment length is one smaller.
        .and_then(|count| count.checked_sub(1))
        .ok_or_else(|| RealSettleError::Prove("R1CS variable count overflow".to_string()))?;
    if assignment.len() != expected {
        return Err(RealSettleError::Prove(format!(
            "native witness assignment has {} values; R1CS expects {expected}",
            assignment.len()
        )));
    }
    let mut rng = rand::thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        pk,
        r,
        s,
        matrices,
        matrices.num_instance_variables,
        matrices.num_constraints,
        &assignment,
    )
    .map_err(|e| RealSettleError::Prove(format!("native-assignment Groth16 prove: {e}")))
}

// ── Incremental Poseidon Merkle tree (depth 20) ──────────────────────────────

/// A 20-level Merkle witness: 20 sibling commitments + 20 side bits
/// (`0` = sibling on the right / leaf is the left child, `1` = sibling on left).
#[derive(Debug, Clone)]
pub struct MerkleWitness {
    pub path_elements: [[u8; 32]; TREE_DEPTH],
    pub path_indices: [u8; TREE_DEPTH],
    /// The root these siblings traverse to (32 BE bytes).
    pub root: [u8; 32],
}

/// Append-only Poseidon2 Merkle tree mirroring the SDK's `MerkleShadow`:
/// `z_0 = 0`, `z_{i+1} = Poseidon2(z_i, z_i)`; a node is `Poseidon2(left, right)`.
pub struct IncrementalTree {
    leaves: Vec<[u8; 32]>,
    /// Empty-subtree root at each level (`zeros[0]` = leaf zero).
    zeros: [[u8; 32]; TREE_DEPTH + 1],
}

fn poseidon2(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], RealSettleError> {
    poseidon_hash_bytes(&[*left, *right]).map_err(|e| RealSettleError::Crypto(e.to_string()))
}

impl IncrementalTree {
    pub fn new() -> Result<Self, RealSettleError> {
        let mut zeros = [[0u8; 32]; TREE_DEPTH + 1];
        for i in 0..TREE_DEPTH {
            zeros[i + 1] = poseidon2(&zeros[i], &zeros[i])?;
        }
        Ok(Self {
            leaves: Vec::new(),
            zeros,
        })
    }

    /// Append a leaf, returning its index.
    pub fn append(&mut self, leaf: [u8; 32]) -> usize {
        self.leaves.push(leaf);
        self.leaves.len() - 1
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Current root (32 BE bytes).
    pub fn root(&self) -> Result<[u8; 32], RealSettleError> {
        Ok(self.witness_and_root(None)?.1)
    }

    /// The inclusion witness for `index`.
    pub fn witness(&self, index: usize) -> Result<MerkleWitness, RealSettleError> {
        if index >= self.leaves.len() {
            return Err(RealSettleError::LeafOutOfRange(index, self.leaves.len()));
        }
        let (w, root) = self.witness_and_root(Some(index))?;
        let w = w.expect("index was Some");
        Ok(MerkleWitness {
            path_elements: w.0,
            path_indices: w.1,
            root,
        })
    }

    /// Walk the tree bottom-up, collecting the witness for `index` (if given) and
    /// the root. One pass shared between `root()` and `witness()`.
    #[allow(clippy::type_complexity)]
    fn witness_and_root(
        &self,
        index: Option<usize>,
    ) -> Result<(Option<([[u8; 32]; TREE_DEPTH], [u8; TREE_DEPTH])>, [u8; 32]), RealSettleError>
    {
        let mut path_elements = [[0u8; 32]; TREE_DEPTH];
        let mut path_indices = [0u8; TREE_DEPTH];
        let mut level: Vec<[u8; 32]> = self.leaves.clone();
        let mut idx = index.unwrap_or(0);

        for depth in 0..TREE_DEPTH {
            if index.is_some() {
                let sib = idx ^ 1;
                path_elements[depth] = level.get(sib).copied().unwrap_or(self.zeros[depth]);
                path_indices[depth] = (idx & 1) as u8;
            }
            // Build the parent level, padding the odd tail with this level's zero.
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                let l = level[i];
                let r = level.get(i + 1).copied().unwrap_or(self.zeros[depth]);
                next.push(poseidon2(&l, &r)?);
                i += 2;
            }
            level = next;
            idx /= 2;
        }
        let root = level.first().copied().unwrap_or(self.zeros[TREE_DEPTH]);
        Ok((index.map(|_| (path_elements, path_indices)), root))
    }
}

// ── Native client-circuit provers ────────────────────────────────────────────

/// A proof-gated deposit opening and the public values carried by the vault ix.
pub struct ValidDepositProof {
    pub proof_bytes: [u8; 256],
    pub note_commitment: [u8; 32],
    pub inner_hash: [u8; 32],
    pub recovery_nonce: [u8; 32],
}

struct GeneratedDepositProof {
    proof: Proof<Bn254>,
    note_commitment: [u8; 32],
    inner_hash: [u8; 32],
}

/// Native-witness VALID_DEPOSIT prover. The optional real-settle load rig is a
/// client of the deposit circuit just like the TypeScript SDK, so it must prove
/// the hidden owner/inner construction before transferring collateral.
pub struct ValidDepositProver {
    pk: ProvingKey<Bn254>,
    matrices: ConstraintMatrices<Fr>,
    native_witness_bin: PathBuf,
}

impl ValidDepositProver {
    pub fn load(circuits_build_dir: impl AsRef<Path>) -> Result<Self, RealSettleError> {
        let base = circuits_build_dir.as_ref().join("valid_deposit");
        let zkey_path = base.join("circuit_final.zkey");
        let mut zkey_file = std::fs::File::open(&zkey_path)
            .map_err(|e| RealSettleError::Io(format!("open {}: {e}", zkey_path.display())))?;
        let (pk, matrices) = ark_circom::read_zkey(&mut zkey_file)
            .map_err(|e| RealSettleError::Io(format!("read valid_deposit zkey: {e}")))?;
        Ok(Self {
            pk,
            matrices,
            native_witness_bin: required_native_witness(&base)?,
        })
    }

    pub fn prove(
        &self,
        spending_key: &Fr,
        owner_blinding: &Fr,
        token_mint: &[u8; 32],
        amount: u64,
        recovery_nonce: &[u8; 32],
        note_secret: &[u8; 32],
    ) -> Result<ValidDepositProof, RealSettleError> {
        let generated = self.prove_ark(
            spending_key,
            owner_blinding,
            token_mint,
            amount,
            recovery_nonce,
            note_secret,
        )?;
        Ok(ValidDepositProof {
            proof_bytes: proof_to_onchain_bytes(&generated.proof),
            note_commitment: generated.note_commitment,
            inner_hash: generated.inner_hash,
            recovery_nonce: *recovery_nonce,
        })
    }

    fn prove_ark(
        &self,
        spending_key: &Fr,
        owner_blinding: &Fr,
        token_mint: &[u8; 32],
        amount: u64,
        recovery_nonce: &[u8; 32],
        note_secret: &[u8; 32],
    ) -> Result<GeneratedDepositProof, RealSettleError> {
        if amount == 0 {
            return Err(RealSettleError::Prove(
                "VALID_DEPOSIT amount must be positive".to_string(),
            ));
        }
        let owner = owner_commitment(spending_key, owner_blinding)
            .map_err(|e| RealSettleError::Crypto(e.to_string()))?;
        let inner_hash = deposit_inner_hash(&owner, recovery_nonce, note_secret)
            .map_err(|e| RealSettleError::Crypto(e.to_string()))?;
        let note_commitment = commitment_from_fields_v2(token_mint, amount, &owner, &inner_hash)
            .map_err(|e| RealSettleError::Crypto(e.to_string()))?;

        let [mint_lo, mint_hi] = pubkey_to_fr_pair(token_mint);
        let input_json = serde_json::to_string(&serde_json::json!({
            "noteCommitment": decimal_be32(&note_commitment),
            "tokenMint": decimal_array([fr_to_bigint(&mint_lo), fr_to_bigint(&mint_hi)]),
            "amount": decimal_u64(amount),
            "recoveryNonce": decimal_be32(recovery_nonce),
            "noteSecret": decimal_be32(note_secret),
            "spendingKey": decimal_fr(spending_key),
            "ownerCommitmentBlinding": decimal_fr(owner_blinding),
        }))
        .map_err(|e| RealSettleError::Prove(format!("encode deposit native inputs: {e}")))?;
        let proof = native_ark_proof(
            &self.pk,
            &self.matrices,
            &self.native_witness_bin,
            &input_json,
        )?;
        Ok(GeneratedDepositProof {
            proof,
            note_commitment,
            inner_hash,
        })
    }

    pub fn verifying_key(&self) -> &ark_groth16::VerifyingKey<Bn254> {
        &self.pk.vk
    }
}

/// A built VALID_INPUT proof + the private commitment and public use tag it
/// attests.
pub struct ValidInputProof {
    /// 256-byte on-chain layout (`pi_a 64 || pi_b 128 || pi_c 64`), the exact
    /// bytes the order's `valid_input_proof` field carries.
    pub proof_bytes: [u8; 256],
    /// The note commitment (32 BE bytes) that anchors the private Merkle proof.
    pub note_commitment: [u8; 32],
    /// The public handle the proof exposes and `lock_note` keys on.
    pub note_use_tag: [u8; 32],
    /// The Merkle root the proof was built against (the order's `merkle_root`).
    pub merkle_root: [u8; 32],
}

/// Native-witness VALID_INPUT prover. Loads the proving key and constraint
/// matrices once, then proves each native C++ assignment with ark-groth16.
pub struct ValidInputProver {
    pk: ProvingKey<Bn254>,
    matrices: ConstraintMatrices<Fr>,
    native_witness_bin: PathBuf,
}

impl ValidInputProver {
    /// Resolve `valid_input/{circuit_final.zkey,circuit_cpp/native-witness}`
    /// under `circuits/build`.
    pub fn load(circuits_build_dir: impl AsRef<Path>) -> Result<Self, RealSettleError> {
        let base = circuits_build_dir.as_ref().join("valid_input");
        let zkey_path = base.join("circuit_final.zkey");
        let mut zkey_file = std::fs::File::open(&zkey_path)
            .map_err(|e| RealSettleError::Io(format!("open {}: {e}", zkey_path.display())))?;
        let (pk, matrices) = ark_circom::read_zkey(&mut zkey_file)
            .map_err(|e| RealSettleError::Io(format!("read_zkey: {e}")))?;
        Ok(Self {
            pk,
            matrices,
            native_witness_bin: required_native_witness(&base)?,
        })
    }

    /// Prove that the note `(token_mint, amount, owner(spending_key, blinding),
    /// inner_hash)` sits at `witness` under `witness.root`. Returns the 256-byte
    /// on-chain proof + the note commitment.
    pub fn prove(
        &self,
        spending_key: &Fr,
        owner_blinding: &Fr,
        inner_hash: &[u8; 32],
        token_mint: &[u8; 32],
        amount: u64,
        witness: &MerkleWitness,
    ) -> Result<ValidInputProof, RealSettleError> {
        let (proof, note_commitment, note_use_tag) = self.prove_ark(
            spending_key,
            owner_blinding,
            inner_hash,
            token_mint,
            amount,
            witness,
        )?;
        Ok(ValidInputProof {
            proof_bytes: proof_to_onchain_bytes(&proof),
            note_commitment,
            note_use_tag,
            merkle_root: witness.root,
        })
    }

    /// Core path returning the RAW ark proof + commitment + public inputs, so
    /// tests can verify against the zkey VK without a CVM.
    #[allow(clippy::type_complexity)]
    fn prove_ark(
        &self,
        spending_key: &Fr,
        owner_blinding: &Fr,
        inner_hash: &[u8; 32],
        token_mint: &[u8; 32],
        amount: u64,
        witness: &MerkleWitness,
    ) -> Result<(Proof<Bn254>, [u8; 32], [u8; 32]), RealSettleError> {
        let owner = owner_commitment(spending_key, owner_blinding)
            .map_err(|e| RealSettleError::Crypto(e.to_string()))?;
        let note_commitment: [u8; 32] =
            commitment_from_fields_v2(token_mint, amount, &owner, inner_hash)
                .map_err(|e| RealSettleError::Crypto(e.to_string()))?;
        let note_use_tag = note_use_tag(&note_commitment, inner_hash)
            .map_err(|e| RealSettleError::Crypto(e.to_string()))?;

        let [mint_lo, mint_hi] = pubkey_to_fr_pair(token_mint);
        let input_json = serde_json::to_string(&serde_json::json!({
            "merkleRoot": decimal_be32(&witness.root),
            "noteUseTag": decimal_be32(&note_use_tag),
            "tokenMint": decimal_array([fr_to_bigint(&mint_lo), fr_to_bigint(&mint_hi)]),
            "amount": decimal_u64(amount),
            "spendingKey": decimal_fr(spending_key),
            "ownerCommitmentBlinding": decimal_fr(owner_blinding),
            "innerHash": decimal_be32(inner_hash),
            "merklePath": decimal_array(witness.path_elements.iter().map(be32_to_bigint)),
            "merkleIndices": decimal_array(
                witness.path_indices.iter().map(|bit| BigInt::from(*bit))
            ),
        }))
        .map_err(|e| RealSettleError::Prove(format!("encode input native inputs: {e}")))?;
        let proof = native_ark_proof(
            &self.pk,
            &self.matrices,
            &self.native_witness_bin,
            &input_json,
        )?;

        Ok((proof, note_commitment, note_use_tag))
    }

    /// The proving key's verifying key — for a post-prove self-check.
    pub fn verifying_key(&self) -> &ark_groth16::VerifyingKey<Bn254> {
        &self.pk.vk
    }
}

fn be32_to_bigint(b: &[u8; 32]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, b)
}

fn fr_to_bigint(fr: &Fr) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, &fr_to_be_bytes(fr))
}

/// ark proof → on-chain 256-byte `groth16-solana` layout. Byte-for-byte mirror
/// of `darknyx_tee::prover::convert::proof_to_onchain_bytes` (pi_a.y negated; the
/// Fq2 coefficient pairs swapped to (c1, c0)).
fn proof_to_onchain_bytes(proof: &Proof<Bn254>) -> [u8; 256] {
    let mut out = [0u8; 256];
    // pi_a (64) = a.x || (-a.y)
    out[0..32].copy_from_slice(&fq_be32(&proof.a.x));
    out[32..64].copy_from_slice(&fq_be32(&(-proof.a.y)));
    // pi_b (128) = b.x.c1 || b.x.c0 || b.y.c1 || b.y.c0
    out[64..96].copy_from_slice(&fq_be32(&proof.b.x.c1));
    out[96..128].copy_from_slice(&fq_be32(&proof.b.x.c0));
    out[128..160].copy_from_slice(&fq_be32(&proof.b.y.c1));
    out[160..192].copy_from_slice(&fq_be32(&proof.b.y.c0));
    // pi_c (64) = c.x || c.y
    out[192..224].copy_from_slice(&fq_be32(&proof.c.x));
    out[224..256].copy_from_slice(&fq_be32(&proof.c.y));
    out
}

fn fq_be32(fq: &Fq) -> [u8; 32] {
    let v = fq.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

// ── VALID_MERGE prover (K=2/4) ───────────────────────────────────────────────

/// One real input note for a merge: its opening + Merkle witness (all active
/// slots prove membership against the same `witness.root`).
pub struct MergeInput {
    pub amount: u64,
    pub inner_hash: [u8; 32],
    pub witness: MerkleWitness,
}

/// A built VALID_MERGE proof + the merged output note it produces.
pub struct MergeProof {
    pub proof_bytes: [u8; 256],
    /// The merged note's commitment (Σ input amounts, commitment-derived inner).
    pub output_commitment: [u8; 32],
    /// `Poseidon6(26, c0, c1, c2, c3, active_bitmap)` derived by the circuit.
    pub output_inner_hash: [u8; 32],
    /// The merged note's amount (Σ active input amounts).
    pub output_amount: u64,
    /// K public input-note handles in circuit order (zero for padding).
    pub input_use_tags: Vec<[u8; 32]>,
}

/// Native-witness VALID_MERGE prover for a fixed K (2 or 4). Mirrors
/// [`ValidInputProver`] + `tests/helpers/merge-prover.ts` (exact signals).
pub struct MergeProver {
    pk: ProvingKey<Bn254>,
    matrices: ConstraintMatrices<Fr>,
    native_witness_bin: PathBuf,
    k: usize,
}

impl MergeProver {
    /// Resolve
    /// `valid_merge_k{k}/{circuit_final.zkey,circuit_cpp/native-witness}`
    /// under `circuits/build`.
    pub fn load(circuits_build_dir: impl AsRef<Path>, k: usize) -> Result<Self, RealSettleError> {
        let base = circuits_build_dir
            .as_ref()
            .join(format!("valid_merge_k{k}"));
        let mut zkey = std::fs::File::open(base.join("circuit_final.zkey"))
            .map_err(|e| RealSettleError::Io(format!("open merge zkey: {e}")))?;
        let (pk, matrices) = ark_circom::read_zkey(&mut zkey)
            .map_err(|e| RealSettleError::Io(format!("read merge zkey: {e}")))?;
        Ok(Self {
            pk,
            matrices,
            native_witness_bin: required_native_witness(&base)?,
            k,
        })
    }

    pub fn verifying_key(&self) -> &ark_groth16::VerifyingKey<Bn254> {
        &self.pk.vk
    }

    /// Prove a K-slot merge of `inputs` (M ≤ K real notes, same owner + mint, all
    /// under `inputs[0].witness.root`) into one output note carrying their sum.
    /// The output inner is derived from the consumed commitments, exactly as the
    /// circuit does. Returns the 256-byte on-chain proof + the merged note.
    pub fn prove(
        &self,
        spending_key: &Fr,
        owner_blinding: &Fr,
        token_mint: &[u8; 32],
        inputs: &[MergeInput],
    ) -> Result<MergeProof, RealSettleError> {
        let (proof, output_commitment, output_inner_hash, output_amount, input_use_tags) =
            self.prove_ark(spending_key, owner_blinding, token_mint, inputs)?;
        Ok(MergeProof {
            proof_bytes: proof_to_onchain_bytes(&proof),
            output_commitment,
            output_inner_hash,
            output_amount,
            input_use_tags,
        })
    }

    #[allow(clippy::type_complexity)]
    fn prove_ark(
        &self,
        spending_key: &Fr,
        owner_blinding: &Fr,
        token_mint: &[u8; 32],
        inputs: &[MergeInput],
    ) -> Result<(Proof<Bn254>, [u8; 32], [u8; 32], u64, Vec<[u8; 32]>), RealSettleError> {
        if inputs.is_empty() || inputs.len() > self.k {
            return Err(RealSettleError::Prove(format!(
                "merge needs 1..{} real slots; got {}",
                self.k,
                inputs.len()
            )));
        }
        let owner = owner_commitment(spending_key, owner_blinding)
            .map_err(|e| RealSettleError::Crypto(e.to_string()))?;
        let merkle_root = inputs[0].witness.root;
        if inputs.iter().any(|input| input.amount == 0) {
            return Err(RealSettleError::Prove(
                "merge inputs must carry positive amounts".to_string(),
            ));
        }
        let sum = inputs.iter().try_fold(0u64, |acc, input| {
            acc.checked_add(input.amount)
                .ok_or_else(|| RealSettleError::Prove("merged amount exceeds u64".to_string()))
        })?;
        let mut input_commitments = [[0u8; 32]; 4];
        for (slot, input) in input_commitments.iter_mut().zip(inputs) {
            *slot = commitment_from_fields_v2(token_mint, input.amount, &owner, &input.inner_hash)
                .map_err(|e| RealSettleError::Crypto(e.to_string()))?;
        }
        let mut input_use_tags = vec![[0u8; 32]; self.k];
        for (slot, (commitment, input)) in input_use_tags
            .iter_mut()
            .zip(input_commitments.iter().zip(inputs))
        {
            *slot = note_use_tag(commitment, &input.inner_hash)
                .map_err(|e| RealSettleError::Crypto(e.to_string()))?;
        }
        let active_bitmap = (1u8 << inputs.len()) - 1;
        let output_inner_hash = merge_output_inner_hash(&input_commitments, active_bitmap)
            .map_err(|e| RealSettleError::Crypto(e.to_string()))?;
        let output_commitment =
            commitment_from_fields_v2(token_mint, sum, &owner, &output_inner_hash)
                .map_err(|e| RealSettleError::Crypto(e.to_string()))?;

        let [mint_lo, mint_hi] = pubkey_to_fr_pair(token_mint);
        let is_active = (0..self.k).map(|i| BigInt::from(inputs.get(i).is_some() as u8));
        let amounts =
            (0..self.k).map(|i| BigInt::from(inputs.get(i).map(|s| s.amount).unwrap_or(0)));
        let inner_hashes = (0..self.k).map(|i| {
            be32_to_bigint(
                &inputs
                    .get(i)
                    .map(|slot| slot.inner_hash)
                    .unwrap_or([0u8; 32]),
            )
        });
        let merkle_paths = serde_json::Value::Array(
            (0..self.k)
                .map(|i| match inputs.get(i) {
                    Some(slot) => {
                        decimal_array(slot.witness.path_elements.iter().map(be32_to_bigint))
                    }
                    None => decimal_array((0..TREE_DEPTH).map(|_| BigInt::from(0))),
                })
                .collect(),
        );
        let merkle_indices = serde_json::Value::Array(
            (0..self.k)
                .map(|i| match inputs.get(i) {
                    Some(slot) => decimal_array(
                        slot.witness
                            .path_indices
                            .iter()
                            .map(|bit| BigInt::from(*bit)),
                    ),
                    None => decimal_array((0..TREE_DEPTH).map(|_| BigInt::from(0))),
                })
                .collect(),
        );
        let input_json = serde_json::to_string(&serde_json::json!({
            "merkleRoot": decimal_be32(&merkle_root),
            "tokenMint": decimal_array([fr_to_bigint(&mint_lo), fr_to_bigint(&mint_hi)]),
            "spendingKey": decimal_fr(spending_key),
            "ownerCommitmentBlinding": decimal_fr(owner_blinding),
            "isActive": decimal_array(is_active),
            "amount": decimal_array(amounts),
            "innerHash": decimal_array(inner_hashes),
            "merklePath": merkle_paths,
            "merkleIndices": merkle_indices,
        }))
        .map_err(|e| RealSettleError::Prove(format!("encode merge native inputs: {e}")))?;
        let proof = native_ark_proof(
            &self.pk,
            &self.matrices,
            &self.native_witness_bin,
            &input_json,
        )?;
        Ok((
            proof,
            output_commitment,
            output_inner_hash,
            sum,
            input_use_tags,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use darkpool_crypto::fr_from_be_bytes;

    fn artifacts_dir() -> Option<PathBuf> {
        // tests run from the crate dir; the artifacts live at repo-root
        // circuits/build (two levels up).
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circuits/build");
        dir.join("valid_input/circuit_final.zkey")
            .exists()
            .then_some(dir)
    }

    #[test]
    fn empty_tree_root_matches_zero_subtree() {
        let tree = IncrementalTree::new().unwrap();
        // Empty root == z_TREE_DEPTH == poseidon2^20(0).
        assert_eq!(tree.root().unwrap(), tree.zeros[TREE_DEPTH]);
    }

    #[test]
    fn witness_indices_follow_leaf_position() {
        let mut tree = IncrementalTree::new().unwrap();
        for i in 0..3u8 {
            tree.append([i; 32]);
        }
        // leaf 0 is a left child at every level → all side bits 0.
        assert_eq!(tree.witness(0).unwrap().path_indices[0], 0);
        // leaf 1 is a right child at level 0 → bit 1.
        assert_eq!(tree.witness(1).unwrap().path_indices[0], 1);
    }

    #[test]
    fn valid_deposit_proof_verifies_against_zkey_vk() {
        let Some(dir) = artifacts_dir() else {
            eprintln!("skipping: circuits/build artifacts not present");
            return;
        };
        if !dir.join("valid_deposit/circuit_final.zkey").exists() {
            eprintln!("skipping: valid_deposit artifacts not present");
            return;
        }
        let prover = ValidDepositProver::load(&dir).expect("load valid_deposit prover");
        let spending_key = Fr::from(12_345u64);
        let owner_blinding = Fr::from(67_890u64);
        let recovery_nonce = fr_to_be_bytes(&Fr::from(2468u64));
        let note_secret = fr_to_be_bytes(&Fr::from(1357u64));
        let mut token_mint = [0u8; 32];
        token_mint[0] = 1;
        token_mint[31] = 0xb1;
        let amount = 1_000_000u64;

        let generated = prover
            .prove_ark(
                &spending_key,
                &owner_blinding,
                &token_mint,
                amount,
                &recovery_nonce,
                &note_secret,
            )
            .expect("prove");
        let owner = owner_commitment(&spending_key, &owner_blinding).unwrap();
        assert_eq!(
            generated.inner_hash,
            deposit_inner_hash(&owner, &recovery_nonce, &note_secret).unwrap()
        );
        assert_eq!(
            generated.note_commitment,
            commitment_from_fields_v2(&token_mint, amount, &owner, &generated.inner_hash,).unwrap()
        );

        let [mint_lo, mint_hi] = pubkey_to_fr_pair(&token_mint);
        let public_inputs = vec![
            fr_from_be_bytes(&generated.note_commitment).unwrap(),
            mint_lo,
            mint_hi,
            Fr::from(amount),
            fr_from_be_bytes(&recovery_nonce).unwrap(),
        ];
        let pvk = ark_groth16::prepare_verifying_key(prover.verifying_key());
        assert!(Groth16::<Bn254>::verify_proof(&pvk, &generated.proof, &public_inputs).unwrap());
        assert!(proof_to_onchain_bytes(&generated.proof)
            .iter()
            .any(|&b| b != 0));
    }

    #[test]
    fn valid_input_proof_verifies_against_zkey_vk() {
        let Some(dir) = artifacts_dir() else {
            eprintln!("skipping: circuits/build/valid_input artifacts not present");
            return;
        };
        let prover = ValidInputProver::load(&dir).expect("load valid_input prover");

        let spending_key = Fr::from(12_345u64);
        let owner_blinding = Fr::from(67_890u64);
        let inner_hash = fr_to_be_bytes(&Fr::from(99u64)); // Fr-safe by construction
        let mut token_mint = [0u8; 32];
        token_mint[0] = 1;
        token_mint[31] = 0xb1; // placeholder base mint
        let amount = 1_000_000u64;

        // Deposit the note into a fresh tree at leaf 0, build its witness.
        let owner = owner_commitment(&spending_key, &owner_blinding).unwrap();
        let commitment: [u8; 32] =
            commitment_from_fields_v2(&token_mint, amount, &owner, &inner_hash).unwrap();
        let mut tree = IncrementalTree::new().unwrap();
        tree.append(commitment);
        let witness = tree.witness(0).unwrap();

        // Prove (raw ark) and verify against the zkey's own VK — a full,
        // CVM-free check that the witness + signals + circuit all agree.
        let (proof, note_commitment, note_use_tag) = prover
            .prove_ark(
                &spending_key,
                &owner_blinding,
                &inner_hash,
                &token_mint,
                amount,
                &witness,
            )
            .expect("prove");
        assert_eq!(note_commitment, commitment);

        let [mint_lo, mint_hi] = pubkey_to_fr_pair(&token_mint);
        let public_inputs = vec![
            fr_from_be_bytes(&witness.root).unwrap(),
            fr_from_be_bytes(&note_use_tag).unwrap(),
            mint_lo,
            mint_hi,
        ];
        let pvk = ark_groth16::prepare_verifying_key(prover.verifying_key());
        let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)
            .expect("verify_proof runs");
        assert!(ok, "VALID_INPUT proof failed to verify against the zkey VK");

        // The on-chain 256-byte conversion is well-formed (non-trivial).
        let onchain = proof_to_onchain_bytes(&proof);
        assert_eq!(onchain.len(), 256);
        assert!(onchain.iter().any(|&b| b != 0));
    }

    /// Manual regression for the real-settle benchmark's client proving phase.
    ///
    /// Covers the exact fixed benchmark fixture: 160 deposits followed by 160
    /// VALID_INPUT proofs. It is deliberately native-only and must complete
    /// without descriptor growth or a hidden Wasmer fallback.
    #[test]
    #[ignore = "slow 160+160 native-proof preflight; run before a CVM throughput pass"]
    fn native_client_proofs_sustain_full_fixture() {
        let Some(dir) = artifacts_dir() else {
            eprintln!("skipping: circuits/build artifacts not present");
            return;
        };
        if !dir.join("valid_deposit/circuit_final.zkey").exists() {
            eprintln!("skipping: valid_deposit artifacts not present");
            return;
        }

        let deposit_prover = ValidDepositProver::load(&dir).expect("load valid_deposit prover");
        let spending_key = Fr::from(12_345u64);
        let owner_blinding = Fr::from(67_890u64);
        let mut token_mint = [0u8; 32];
        token_mint[0] = 1;
        token_mint[31] = 0xb1;
        let amount = 1_000_000u64;
        let mut final_deposit = None;

        for nonce in 1..=160u64 {
            let recovery_nonce = fr_to_be_bytes(&Fr::from(nonce));
            // Synthetic per-note secret. The real client derives this from the
            // master seed keyed on the public nonce; the harness only needs it
            // to vary with the note.
            let note_secret = fr_to_be_bytes(&Fr::from(nonce + 1_000_000));
            final_deposit = Some(
                deposit_prover
                    .prove(
                        &spending_key,
                        &owner_blinding,
                        &token_mint,
                        amount,
                        &recovery_nonce,
                        &note_secret,
                    )
                    .unwrap_or_else(|e| panic!("deposit proof {nonce} failed: {e}")),
            );
        }

        let deposit = final_deposit.expect("at least one deposit proof");
        let mut tree = IncrementalTree::new().unwrap();
        tree.append(deposit.note_commitment);
        let witness = tree.witness(0).unwrap();
        let input_prover = ValidInputProver::load(&dir).expect("load valid_input prover");
        for index in 1..=160 {
            input_prover
                .prove(
                    &spending_key,
                    &owner_blinding,
                    &deposit.inner_hash,
                    &token_mint,
                    amount,
                    &witness,
                )
                .unwrap_or_else(|e| panic!("input proof {index} failed: {e}"));
        }
    }

    #[test]
    fn valid_merge_proof_verifies_against_zkey_vk() {
        let Some(dir) = artifacts_dir() else {
            eprintln!("skipping: circuits/build artifacts not present");
            return;
        };
        if !dir.join("valid_merge_k2/circuit_final.zkey").exists() {
            eprintln!("skipping: valid_merge_k2 artifacts not present");
            return;
        }
        let prover = MergeProver::load(&dir, 2).expect("load merge prover");

        let sk = Fr::from(123u64);
        let ob = Fr::from(456u64);
        let owner = owner_commitment(&sk, &ob).unwrap();
        let mut mint = [0u8; 32];
        mint[0] = 1;
        mint[31] = 0xb1;
        let ih0 = fr_to_be_bytes(&Fr::from(11u64));
        let ih1 = fr_to_be_bytes(&Fr::from(22u64));
        let (a0, a1) = (3_000u64, 2_000u64);
        let c0 = commitment_from_fields_v2(&mint, a0, &owner, &ih0).unwrap();
        let c1 = commitment_from_fields_v2(&mint, a1, &owner, &ih1).unwrap();

        let mut tree = IncrementalTree::new().unwrap();
        tree.append(c0);
        tree.append(c1);
        let inputs = vec![
            MergeInput {
                amount: a0,
                inner_hash: ih0,
                witness: tree.witness(0).unwrap(),
            },
            MergeInput {
                amount: a1,
                inner_hash: ih1,
                witness: tree.witness(1).unwrap(),
            },
        ];
        let (proof, out_commit, out_ih, sum, input_use_tags) = prover
            .prove_ark(&sk, &ob, &mint, &inputs)
            .expect("merge prove");
        assert_eq!(sum, a0 + a1);
        let expected_inner = merge_output_inner_hash(&[c0, c1, [0u8; 32], [0u8; 32]], 3)
            .expect("derive output inner");
        assert_eq!(out_ih, expected_inner);

        // Public inputs (circuit order): [outputCommitment,
        // inputUseTags[0..k-1], merkleRoot, mint_lo, mint_hi].
        let [mint_lo, mint_hi] = pubkey_to_fr_pair(&mint);
        let public = vec![
            fr_from_be_bytes(&out_commit).unwrap(),
            fr_from_be_bytes(&input_use_tags[0]).unwrap(),
            fr_from_be_bytes(&input_use_tags[1]).unwrap(),
            fr_from_be_bytes(&tree.root().unwrap()).unwrap(),
            mint_lo,
            mint_hi,
        ];
        let pvk = ark_groth16::prepare_verifying_key(prover.verifying_key());
        assert!(
            Groth16::<Bn254>::verify_proof(&pvk, &proof, &public).expect("verify runs"),
            "VALID_MERGE proof failed to verify against the zkey VK"
        );
    }
}
