//! Real-settle support (Increment A): a Rust VALID_INPUT prover + a Poseidon
//! Merkle witness, so the loadgen can drive REAL on-chain settle instead of only
//! synthetic intake. Gated behind the `real-settle` cargo feature.
//!
//! There is no reusable Rust VALID_INPUT prover elsewhere in the tree — the TEE
//! proves VALID_MATCH_BATCH; clients prove VALID_INPUT via snarkjs. This mirrors
//! `crates/darknyx-tee/src/prover/ark_prover.rs` (the proven ark-circom pattern) and
//! the SDK's `tests/helpers/valid-input-prover.ts` (the exact circuit signals)
//! to produce the same 256-byte on-chain proof in-process.
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
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey};
use num_bigint::{BigInt, Sign};

use darkpool_crypto::note::owner_commitment;
use darkpool_crypto::{
    commitment_from_fields_v2, deposit_inner_hash, fr_to_be_bytes, merge_output_inner_hash,
    poseidon_hash_bytes, pubkey_to_fr_pair,
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

// ── VALID_INPUT prover (ark-circom) ──────────────────────────────────────────

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

/// ark-circom VALID_DEPOSIT prover. The optional real-settle load rig is a
/// client of the deposit circuit just like the TypeScript SDK, so it must prove
/// the hidden owner/inner construction before transferring collateral.
pub struct ValidDepositProver {
    pk: ProvingKey<Bn254>,
    wasm_path: PathBuf,
    r1cs_path: PathBuf,
}

impl ValidDepositProver {
    pub fn load(circuits_build_dir: impl AsRef<Path>) -> Result<Self, RealSettleError> {
        let base = circuits_build_dir.as_ref().join("valid_deposit");
        let zkey_path = base.join("circuit_final.zkey");
        let mut zkey_file = std::fs::File::open(&zkey_path)
            .map_err(|e| RealSettleError::Io(format!("open {}: {e}", zkey_path.display())))?;
        let (pk, _matrices) = ark_circom::read_zkey(&mut zkey_file)
            .map_err(|e| RealSettleError::Io(format!("read valid_deposit zkey: {e}")))?;
        Ok(Self {
            pk,
            wasm_path: base.join("circuit_js").join("circuit.wasm"),
            r1cs_path: base.join("circuit.r1cs"),
        })
    }

    pub fn prove(
        &self,
        spending_key: &Fr,
        owner_blinding: &Fr,
        token_mint: &[u8; 32],
        amount: u64,
        recovery_nonce: &[u8; 32],
    ) -> Result<ValidDepositProof, RealSettleError> {
        let generated = self.prove_ark(
            spending_key,
            owner_blinding,
            token_mint,
            amount,
            recovery_nonce,
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
    ) -> Result<GeneratedDepositProof, RealSettleError> {
        if amount == 0 {
            return Err(RealSettleError::Prove(
                "VALID_DEPOSIT amount must be positive".to_string(),
            ));
        }
        let owner = owner_commitment(spending_key, owner_blinding)
            .map_err(|e| RealSettleError::Crypto(e.to_string()))?;
        let inner_hash = deposit_inner_hash(&owner, recovery_nonce)
            .map_err(|e| RealSettleError::Crypto(e.to_string()))?;
        let note_commitment = commitment_from_fields_v2(token_mint, amount, &owner, &inner_hash)
            .map_err(|e| RealSettleError::Crypto(e.to_string()))?;

        let cfg = CircomConfig::<Fr>::new(&self.wasm_path, &self.r1cs_path)
            .map_err(|e| RealSettleError::Prove(format!("deposit CircomConfig::new: {e}")))?;
        let mut builder = CircomBuilder::new(cfg);
        let [mint_lo, mint_hi] = pubkey_to_fr_pair(token_mint);
        builder.push_input("noteCommitment", be32_to_bigint(&note_commitment));
        builder.push_input("tokenMint", fr_to_bigint(&mint_lo));
        builder.push_input("tokenMint", fr_to_bigint(&mint_hi));
        builder.push_input("amount", BigInt::from(amount));
        builder.push_input("recoveryNonce", be32_to_bigint(recovery_nonce));
        builder.push_input("spendingKey", fr_to_bigint(spending_key));
        builder.push_input("ownerCommitmentBlinding", fr_to_bigint(owner_blinding));

        let circom = builder
            .build()
            .map_err(|e| RealSettleError::Prove(format!("deposit witness build: {e}")))?;
        let mut rng = rand::thread_rng();
        let proof = Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(
            circom, &self.pk, &mut rng,
        )
        .map_err(|e| RealSettleError::Prove(format!("deposit groth16 prove: {e}")))?;
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

/// A built VALID_INPUT proof + the note commitment it attests.
pub struct ValidInputProof {
    /// 256-byte on-chain layout (`pi_a 64 || pi_b 128 || pi_c 64`), the exact
    /// bytes the order's `valid_input_proof` field carries.
    pub proof_bytes: [u8; 256],
    /// The note commitment (32 BE bytes) the proof binds.
    pub note_commitment: [u8; 32],
    /// The Merkle root the proof was built against (the order's `merkle_root`).
    pub merkle_root: [u8; 32],
}

/// ark-circom VALID_INPUT prover. Loads the proving key once; rebuilds the
/// `CircomConfig` (wasm + r1cs) per prove (its wasmer `Store` is `!Sync`), same
/// as `ArkMatchBatchProver`.
pub struct ValidInputProver {
    pk: ProvingKey<Bn254>,
    wasm_path: PathBuf,
    r1cs_path: PathBuf,
}

impl ValidInputProver {
    /// Resolve `valid_input/{circuit_final.zkey, circuit_js/circuit.wasm,
    /// circuit.r1cs}` under `circuits/build`.
    pub fn load(circuits_build_dir: impl AsRef<Path>) -> Result<Self, RealSettleError> {
        let base = circuits_build_dir.as_ref().join("valid_input");
        let zkey_path = base.join("circuit_final.zkey");
        let wasm_path = base.join("circuit_js").join("circuit.wasm");
        let r1cs_path = base.join("circuit.r1cs");

        let mut zkey_file = std::fs::File::open(&zkey_path)
            .map_err(|e| RealSettleError::Io(format!("open {}: {e}", zkey_path.display())))?;
        let (pk, _matrices) = ark_circom::read_zkey(&mut zkey_file)
            .map_err(|e| RealSettleError::Io(format!("read_zkey: {e}")))?;
        Ok(Self {
            pk,
            wasm_path,
            r1cs_path,
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
        let (proof, note_commitment) = self.prove_ark(
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
    ) -> Result<(Proof<Bn254>, [u8; 32]), RealSettleError> {
        let owner = owner_commitment(spending_key, owner_blinding)
            .map_err(|e| RealSettleError::Crypto(e.to_string()))?;
        let note_commitment: [u8; 32] =
            commitment_from_fields_v2(token_mint, amount, &owner, inner_hash)
                .map_err(|e| RealSettleError::Crypto(e.to_string()))?;

        let cfg = CircomConfig::<Fr>::new(&self.wasm_path, &self.r1cs_path)
            .map_err(|e| RealSettleError::Prove(format!("CircomConfig::new: {e}")))?;
        let mut builder = CircomBuilder::new(cfg);

        let [mint_lo, mint_hi] = pubkey_to_fr_pair(token_mint);

        // Signal names + order mirror the SDK's proveValidInput inputs object.
        builder.push_input("merkleRoot", be32_to_bigint(&witness.root));
        builder.push_input("noteCommitment", be32_to_bigint(&note_commitment));
        builder.push_input("tokenMint", fr_to_bigint(&mint_lo));
        builder.push_input("tokenMint", fr_to_bigint(&mint_hi));
        builder.push_input("amount", BigInt::from(amount));
        builder.push_input("spendingKey", fr_to_bigint(spending_key));
        builder.push_input("ownerCommitmentBlinding", fr_to_bigint(owner_blinding));
        builder.push_input("innerHash", be32_to_bigint(inner_hash));
        for sib in &witness.path_elements {
            builder.push_input("merklePath", be32_to_bigint(sib));
        }
        for &bit in &witness.path_indices {
            builder.push_input("merkleIndices", BigInt::from(bit));
        }

        let circom = builder
            .build()
            .map_err(|e| RealSettleError::Prove(format!("witness build (bad opening?): {e}")))?;

        let mut rng = rand::thread_rng();
        let proof = Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(
            circom, &self.pk, &mut rng,
        )
        .map_err(|e| RealSettleError::Prove(format!("groth16 prove: {e}")))?;

        Ok((proof, note_commitment))
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

// ── VALID_MERGE prover (ark-circom, K=2/4) ───────────────────────────────────

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
}

/// ark-circom VALID_MERGE prover for a fixed K (2 or 4). Mirrors
/// [`ValidInputProver`] + `tests/helpers/merge-prover.ts` (exact signals).
pub struct MergeProver {
    pk: ProvingKey<Bn254>,
    wasm_path: PathBuf,
    r1cs_path: PathBuf,
    k: usize,
}

impl MergeProver {
    /// Resolve `valid_merge_k{k}/{circuit_final.zkey, circuit_js/circuit.wasm,
    /// circuit.r1cs}` under `circuits/build`.
    pub fn load(circuits_build_dir: impl AsRef<Path>, k: usize) -> Result<Self, RealSettleError> {
        let base = circuits_build_dir
            .as_ref()
            .join(format!("valid_merge_k{k}"));
        let mut zkey = std::fs::File::open(base.join("circuit_final.zkey"))
            .map_err(|e| RealSettleError::Io(format!("open merge zkey: {e}")))?;
        let (pk, _m) = ark_circom::read_zkey(&mut zkey)
            .map_err(|e| RealSettleError::Io(format!("read merge zkey: {e}")))?;
        Ok(Self {
            pk,
            wasm_path: base.join("circuit_js").join("circuit.wasm"),
            r1cs_path: base.join("circuit.r1cs"),
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
        let (proof, output_commitment, output_inner_hash, output_amount) =
            self.prove_ark(spending_key, owner_blinding, token_mint, inputs)?;
        Ok(MergeProof {
            proof_bytes: proof_to_onchain_bytes(&proof),
            output_commitment,
            output_inner_hash,
            output_amount,
        })
    }

    #[allow(clippy::type_complexity)]
    fn prove_ark(
        &self,
        spending_key: &Fr,
        owner_blinding: &Fr,
        token_mint: &[u8; 32],
        inputs: &[MergeInput],
    ) -> Result<(Proof<Bn254>, [u8; 32], [u8; 32], u64), RealSettleError> {
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
        let active_bitmap = (1u8 << inputs.len()) - 1;
        let output_inner_hash = merge_output_inner_hash(&input_commitments, active_bitmap)
            .map_err(|e| RealSettleError::Crypto(e.to_string()))?;
        let output_commitment =
            commitment_from_fields_v2(token_mint, sum, &owner, &output_inner_hash)
                .map_err(|e| RealSettleError::Crypto(e.to_string()))?;

        let cfg = CircomConfig::<Fr>::new(&self.wasm_path, &self.r1cs_path)
            .map_err(|e| RealSettleError::Prove(format!("merge CircomConfig::new: {e}")))?;
        let mut b = CircomBuilder::new(cfg);
        let [mint_lo, mint_hi] = pubkey_to_fr_pair(token_mint);

        b.push_input("merkleRoot", be32_to_bigint(&merkle_root));
        b.push_input("tokenMint", fr_to_bigint(&mint_lo));
        b.push_input("tokenMint", fr_to_bigint(&mint_hi));
        b.push_input("spendingKey", fr_to_bigint(spending_key));
        b.push_input("ownerCommitmentBlinding", fr_to_bigint(owner_blinding));
        // Per-slot private witnesses, padded to k with dummies.
        for i in 0..self.k {
            b.push_input("isActive", BigInt::from(inputs.get(i).is_some() as u8));
        }
        for i in 0..self.k {
            b.push_input(
                "amount",
                BigInt::from(inputs.get(i).map(|s| s.amount).unwrap_or(0)),
            );
        }
        for i in 0..self.k {
            let ih = inputs.get(i).map(|s| s.inner_hash).unwrap_or([0u8; 32]);
            b.push_input("innerHash", be32_to_bigint(&ih));
        }
        // merklePath[k][20] + merkleIndices[k][20], row-major.
        for i in 0..self.k {
            match inputs.get(i) {
                Some(s) => {
                    for sib in &s.witness.path_elements {
                        b.push_input("merklePath", be32_to_bigint(sib));
                    }
                }
                None => {
                    for _ in 0..TREE_DEPTH {
                        b.push_input("merklePath", BigInt::from(0));
                    }
                }
            }
        }
        for i in 0..self.k {
            match inputs.get(i) {
                Some(s) => {
                    for &bit in &s.witness.path_indices {
                        b.push_input("merkleIndices", BigInt::from(bit));
                    }
                }
                None => {
                    for _ in 0..TREE_DEPTH {
                        b.push_input("merkleIndices", BigInt::from(0));
                    }
                }
            }
        }

        let circom = b
            .build()
            .map_err(|e| RealSettleError::Prove(format!("merge witness build: {e}")))?;
        let mut rng = rand::thread_rng();
        let proof = Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(
            circom, &self.pk, &mut rng,
        )
        .map_err(|e| RealSettleError::Prove(format!("merge groth16 prove: {e}")))?;
        Ok((proof, output_commitment, output_inner_hash, sum))
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

    // ark-circom's wasmer-wasix witness calculator needs a Tokio reactor in
    // context (host_fs). In the real loadgen the prover runs inside the async
    // trader tasks, so this mirrors that; the test just provides the runtime.
    #[tokio::test]
    async fn valid_deposit_proof_verifies_against_zkey_vk() {
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
            )
            .expect("prove");
        let owner = owner_commitment(&spending_key, &owner_blinding).unwrap();
        assert_eq!(
            generated.inner_hash,
            deposit_inner_hash(&owner, &recovery_nonce).unwrap()
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

    #[tokio::test]
    async fn valid_input_proof_verifies_against_zkey_vk() {
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
        let (proof, note_commitment) = prover
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
            fr_from_be_bytes(&commitment).unwrap(),
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

    #[tokio::test]
    async fn valid_merge_proof_verifies_against_zkey_vk() {
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
        let (proof, out_commit, out_ih, sum) = prover
            .prove_ark(&sk, &ob, &mint, &inputs)
            .expect("merge prove");
        assert_eq!(sum, a0 + a1);
        let expected_inner = merge_output_inner_hash(&[c0, c1, [0u8; 32], [0u8; 32]], 3)
            .expect("derive output inner");
        assert_eq!(out_ih, expected_inner);

        // Public inputs (circuit order): [outputCommitment,
        // inputCommitments[0..k-1], merkleRoot, mint_lo, mint_hi].
        let [mint_lo, mint_hi] = pubkey_to_fr_pair(&mint);
        let public = vec![
            fr_from_be_bytes(&out_commit).unwrap(),
            fr_from_be_bytes(&c0).unwrap(),
            fr_from_be_bytes(&c1).unwrap(),
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
