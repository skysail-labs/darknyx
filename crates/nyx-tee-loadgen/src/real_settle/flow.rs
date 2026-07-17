//! Real-settle on-chain harness (Increment B2) — the reusable building blocks
//! that turn Increment A's prover + B1's ix into a deposit→prove flow against a
//! live cluster: sign+send a tx, deposit a note and mirror it into the
//! per-shard Merkle shadow, read per-shard `leaf_count`, and prove VALID_INPUT
//! against the shard the note landed in.
//!
//! The deposit ix encoding (B1) and the prover (A) are unit-tested; this glue is
//! validated on a CVM run. The remaining live wiring — pairing bid/ask real
//! traders, POSTing the order, and tracking the settle — drives these blocks
//! from `run.rs` and is exercised end-to-end on a CVM (see BENCHMARK.md).

use base64::Engine;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;

use super::rpc::{parse_leaf_count, RpcClient};
use super::vault::{self, NoteCreated};
use super::{
    IncrementalTree, RealSettleError, ValidDepositProver, ValidInputProof, ValidInputProver,
};

use ark_bn254::Fr;

type R<T> = Result<T, RealSettleError>;

/// Load a Solana-CLI keypair file (a JSON array of 64 bytes).
pub fn load_keypair(path: &str) -> R<Keypair> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| RealSettleError::Io(format!("read {path}: {e}")))?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)
        .map_err(|e| RealSettleError::Io(format!("parse keypair {path}: {e}")))?;
    Keypair::try_from(bytes.as_slice())
        .map_err(|e| RealSettleError::Io(format!("keypair from bytes: {e}")))
}

/// A deposited note: its opening + the shard/position the program appended it at
/// (both needed for the per-shard VALID_INPUT witness).
#[derive(Debug, Clone)]
pub struct DepositedNote {
    pub mint: [u8; 32],
    pub amount: u64,
    pub inner_hash: [u8; 32],
    pub commitment: [u8; 32],
    pub tree_id: u8,
    pub leaf_index: u64,
}

/// Ties the RPC client, the VALID_INPUT prover, and one Merkle shadow per shard
/// together — the on-chain analogue of the SDK's `cvm-harness.ts`.
pub struct RealSettleHarness {
    rpc: RpcClient,
    input_prover: ValidInputProver,
    deposit_prover: ValidDepositProver,
    shadows: Vec<IncrementalTree>,
    num_trees: u8,
}

impl RealSettleHarness {
    /// `circuits_build_dir` resolves the valid_input artifacts; `num_trees` is
    /// the on-chain shard count (e2e-config `numTrees`).
    pub fn new(rpc: RpcClient, circuits_build_dir: &str, num_trees: u8) -> R<Self> {
        let input_prover = ValidInputProver::load(circuits_build_dir)?;
        let deposit_prover = ValidDepositProver::load(circuits_build_dir)?;
        let mut shadows = Vec::with_capacity(num_trees.max(1) as usize);
        for _ in 0..num_trees.max(1) {
            shadows.push(IncrementalTree::new()?);
        }
        Ok(Self {
            rpc,
            input_prover,
            deposit_prover,
            shadows,
            num_trees: num_trees.max(1),
        })
    }

    /// Build, sign, send + confirm a single-ix tx, returning the signature.
    pub async fn sign_send_confirm(&self, payer: &Keypair, ix: Instruction) -> R<String> {
        let bh = self.rpc.latest_blockhash().await?;
        let bh_bytes: [u8; 32] = bs58::decode(&bh)
            .into_vec()
            .map_err(|e| RealSettleError::Rpc(format!("blockhash b58: {e}")))?
            .try_into()
            .map_err(|_| RealSettleError::Rpc("blockhash not 32 bytes".into()))?;
        let blockhash = Hash::new_from_array(bh_bytes);
        let payer_pubkey = payer.pubkey();
        let tx =
            Transaction::new_signed_with_payer(&[ix], Some(&payer_pubkey), &[payer], blockhash);
        let wire = bincode::serialize(&tx)
            .map_err(|e| RealSettleError::Rpc(format!("tx bincode: {e}")))?;
        let sig = self
            .rpc
            .send_transaction(&base64::engine::general_purpose::STANDARD.encode(&wire))
            .await?;
        if !self.rpc.confirm(&sig, 40).await? {
            return Err(RealSettleError::Rpc(format!("tx {sig} did not confirm")));
        }
        Ok(sig)
    }

    /// Total leaf count summed across the K shards (each `MerkleTree.leaf_count`).
    pub async fn leaf_count(&self) -> R<u64> {
        let mut total = 0u64;
        for tree_id in 0..self.num_trees {
            let pda = vault::merkle_tree_pda(tree_id).to_string();
            let data =
                self.rpc.account_data(&pda).await?.ok_or_else(|| {
                    RealSettleError::Rpc(format!("merkle_tree[{tree_id}] missing"))
                })?;
            total += parse_leaf_count(&data)?;
        }
        Ok(total)
    }

    /// Deposit a note into shard `tree_id`: send the deposit tx, recover the real
    /// `(tree_id, leaf_index)` from the NoteCreated event, and mirror the
    /// commitment into that shard's shadow.
    #[allow(clippy::too_many_arguments)]
    pub async fn deposit(
        &mut self,
        payer: &Keypair,
        mint: [u8; 32],
        depositor_token_account: &solana_address::Address,
        amount: u64,
        spending_key: &Fr,
        owner_blinding: &Fr,
        recovery_nonce: &[u8; 32],
        tree_id: u8,
    ) -> R<DepositedNote> {
        let mint_addr = solana_address::Address::new_from_array(mint);
        let deposit = self.deposit_prover.prove(
            spending_key,
            owner_blinding,
            &mint,
            amount,
            recovery_nonce,
        )?;
        let ix = vault::build_deposit_ix(
            tree_id,
            &payer.pubkey(),
            &mint_addr,
            depositor_token_account,
            amount,
            &deposit.note_commitment,
            &deposit.recovery_nonce,
            &deposit.proof_bytes,
        );
        let sig = self.sign_send_confirm(payer, ix).await?;
        let logs = self.rpc.transaction_logs(&sig).await?;
        let NoteCreated {
            tree_id: actual_tree,
            leaf_index,
        } = vault::note_created_from_logs(&logs)?;
        self.shadows[actual_tree as usize].append(deposit.note_commitment);
        Ok(DepositedNote {
            mint,
            amount,
            inner_hash: deposit.inner_hash,
            commitment: deposit.note_commitment,
            tree_id: actual_tree,
            leaf_index,
        })
    }

    /// Prove VALID_INPUT for `note`, witnessing against the shard it landed in.
    pub fn prove(
        &self,
        spending_key: &Fr,
        owner_blinding: &Fr,
        note: &DepositedNote,
    ) -> R<ValidInputProof> {
        let witness = self.shadows[note.tree_id as usize].witness(note.leaf_index as usize)?;
        self.input_prover.prove(
            spending_key,
            owner_blinding,
            &note.inner_hash,
            &note.mint,
            note.amount,
            &witness,
        )
    }

    // ── Merge primitives (for the merge-before-order scenario) ───────────────

    /// The inclusion witness for `leaf` in shard `tree_id` (against the shadow's
    /// current root) — the input witnesses a merge prove needs.
    pub fn shadow_witness(&self, tree_id: u8, leaf: u64) -> R<super::MerkleWitness> {
        self.shadows[tree_id as usize].witness(leaf as usize)
    }

    /// Append a settle/merge OUTPUT commitment to a shard's shadow (sequential
    /// setup keeps the shadow index == the on-chain leaf the program appended).
    /// Returns the leaf index.
    pub fn append_shadow(&mut self, tree_id: u8, commitment: [u8; 32]) -> u64 {
        self.shadows[tree_id as usize].append(commitment) as u64
    }

    /// Recover a confirmed merge tx's output `(tree_id, leaf_index)` from its
    /// NoteMerged event.
    pub async fn note_merged(&self, signature: &str) -> R<(u8, u64)> {
        let logs = self.rpc.transaction_logs(signature).await?;
        let n = vault::note_merged_from_logs(&logs)?;
        Ok((n.tree_id, n.leaf_index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_load_rejects_garbage() {
        // A non-array file is a clean error (not a panic).
        let dir = std::env::temp_dir().join("nyx_loadgen_kp_test.json");
        std::fs::write(&dir, b"not json").unwrap();
        assert!(load_keypair(dir.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(&dir);
    }
}
