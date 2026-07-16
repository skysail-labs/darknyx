//! Nyx dark pool — vault program (Phase 1).
//!
//! Responsibilities:
//!   - SPL token custody via per-mint PDA token accounts.
//!   - UTXO note Merkle tree (Poseidon2 over BN254, depth 20).
//!   - Nullifier set / consumed-notes set / note locks (all PDA-based).
//!   - Groth16 verification of VALID_WALLET_CREATE and VALID_SPEND proofs.
//!   - TEE-forced atomic settlement.
//!
//! Reference: Section 23.1 of darkpool_protocol_spec_v3_changed.md

use anchor_lang::prelude::*;

pub mod errors;
pub mod instructions;
pub mod merkle;
pub mod state;
pub mod zk;

// Anchor's `#[program]` macro looks up `crate::<submod>::__client_accounts_*`
// and similar helper modules. Re-exporting each instruction submodule at crate
// root lets the macro resolve everything correctly even though our source lives
// under `programs/vault/src/instructions/`.
pub use instructions::close_batch_validity_marker;
#[cfg(feature = "devnet-admin")]
pub use instructions::close_vault_config;
pub use instructions::create_wallet;
pub use instructions::deposit;
pub use instructions::initialize;
pub use instructions::initialize_market;
pub use instructions::lock_note;
pub use instructions::merge;
pub use instructions::release_lock;
#[cfg(feature = "devnet-admin")]
pub use instructions::reset_merkle_tree;
pub use instructions::rotate_root_key;
pub use instructions::set_protocol_config;
pub use instructions::set_tee_pubkey;
pub use instructions::tee_forced_settle;
pub use instructions::tee_forced_settle_batched;
pub use instructions::update_market_config;
pub use instructions::verify_match_batch;
pub use instructions::withdraw;

use instructions::*;
use zk::Groth16Proof;

declare_id!("C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx");

#[program]
pub mod vault {
    use super::*;

    /// Initialize the global `VaultConfig` singleton. One-time setup. The K
    /// Merkle-tree shards are created separately via `initialize_tree`.
    pub fn initialize(
        ctx: Context<Initialize>,
        operations_admin: Pubkey,
        tee_pubkeys: Vec<Pubkey>,
        root_key: Pubkey,
        num_trees: u8,
    ) -> Result<()> {
        initialize::initialize_handler(ctx, operations_admin, tee_pubkeys, root_key, num_trees)
    }

    /// Initialize one enabled mint-pair market. Mint decimals are read from the
    /// SPL accounts and scaled-price parameters are governance-bounded.
    pub fn initialize_market(
        ctx: Context<InitializeMarket>,
        price_scale: u64,
        tick_size: u64,
        min_order_size: u64,
        circuit_breaker_bps: u64,
    ) -> Result<()> {
        initialize_market::initialize_market_handler(
            ctx,
            price_scale,
            tick_size,
            min_order_size,
            circuit_breaker_bps,
        )
    }

    /// Initialize one Merkle-tree shard account (`tree_id < num_trees`).
    /// Admin-gated. Run once per shard at devnet-setup.
    pub fn initialize_tree(ctx: Context<InitializeTree>, tree_id: u8) -> Result<()> {
        initialize_tree::initialize_tree_handler(ctx, tree_id)
    }

    /// Rotate the protocol root key. Must be signed by the current
    /// root key (self-signature model — admin cannot override).
    pub fn rotate_root_key(ctx: Context<RotateRootKey>, new_root_key: Pubkey) -> Result<()> {
        rotate_root_key::rotate_root_key_handler(ctx, new_root_key)
    }

    /// Register a User Commitment via VALID_WALLET_CREATE proof.
    pub fn create_wallet(
        ctx: Context<CreateWallet>,
        commitment: [u8; 32],
        proof: Groth16Proof,
    ) -> Result<()> {
        create_wallet::create_wallet_handler(ctx, commitment, proof)
    }

    /// Deposit SPL tokens and insert a proof-bound UTXO note commitment.
    /// The proof keeps owner_commitment + inner_hash private while binding the
    /// public mint, amount, commitment, and recovery nonce.
    pub fn deposit(
        ctx: Context<Deposit>,
        tree_id: u8,
        amount: u64,
        note_commitment: [u8; 32],
        recovery_nonce: [u8; 32],
        proof: Groth16Proof,
    ) -> Result<()> {
        deposit::deposit_handler(ctx, tree_id, amount, note_commitment, recovery_nonce, proof)
    }

    /// Withdraw tokens using a VALID_SPEND proof.
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw(
        ctx: Context<Withdraw>,
        tree_id: u8,
        note_commitment: [u8; 32],
        nullifier: [u8; 32],
        merkle_root: [u8; 32],
        amount: u64,
        proof: Groth16Proof,
    ) -> Result<()> {
        withdraw::withdraw_handler(
            ctx,
            tree_id,
            note_commitment,
            nullifier,
            merkle_root,
            amount,
            proof,
        )
    }

    /// Merge K input notes (K=2 or 4) into ONE output note of their sum, using a
    /// VALID_MERGE proof. In-pool consolidation — no external transfer. The K
    /// non-zero input commitments' consume/lock PDAs are passed as
    /// remaining_accounts.
    #[allow(clippy::too_many_arguments)]
    pub fn merge<'info>(
        ctx: Context<'info, Merge<'info>>,
        tree_id: u8,
        input_commitments: Vec<[u8; 32]>,
        output_commitment: [u8; 32],
        token_mint: Pubkey,
        merkle_root: [u8; 32],
        k: u8,
        proof: Groth16Proof,
    ) -> Result<()> {
        merge::merge_handler(
            ctx,
            tree_id,
            input_commitments,
            output_commitment,
            token_mint,
            merkle_root,
            k,
            proof,
        )
    }

    /// Lock a note to an order (TEE-only; v3 requires a VALID_INPUT proof
    /// generated by the note owner so the TEE cannot phantom-lock or learn the
    /// private, positive-u64 amount from instruction/event data).
    #[allow(clippy::too_many_arguments)]
    pub fn lock_note(
        ctx: Context<LockNote>,
        tree_id: u8,
        note_commitment: [u8; 32],
        order_id: [u8; 16],
        expiry_slot: u64,
        token_mint: Pubkey,
        merkle_root: [u8; 32],
        proof: Groth16Proof,
    ) -> Result<()> {
        lock_note::lock_note_handler(
            ctx,
            tree_id,
            note_commitment,
            order_id,
            expiry_slot,
            token_mint,
            merkle_root,
            proof,
        )
    }

    /// Release an expired note lock.
    pub fn release_lock(ctx: Context<ReleaseLock>, note_commitment: [u8; 32]) -> Result<()> {
        release_lock::release_lock_handler(ctx, note_commitment)
    }

    /// Post-deployment governance setter for the protocol-fee fields of
    /// `VaultConfig`. Admin-only. Safe to call repeatedly (e.g. to rotate
    /// the protocol-owner commitment or change the fee rate).
    pub fn set_protocol_config(
        ctx: Context<SetProtocolConfig>,
        protocol_owner_commitment: [u8; 32],
        fee_rate_bps: u16,
    ) -> Result<()> {
        set_protocol_config::set_protocol_config_handler(
            ctx,
            protocol_owner_commitment,
            fee_rate_bps,
        )
    }

    /// Update or pause an existing market. Its mint identity and snapshotted
    /// decimals remain immutable.
    pub fn update_market_config(
        ctx: Context<UpdateMarketConfig>,
        enabled: bool,
        price_scale: u64,
        tick_size: u64,
        min_order_size: u64,
        circuit_breaker_bps: u64,
    ) -> Result<()> {
        update_market_config::update_market_config_handler(
            ctx,
            enabled,
            price_scale,
            tick_size,
            min_order_size,
            circuit_breaker_bps,
        )
    }

    /// Rotate `vault_config.tee_pubkey` to a new attested TEE signer.
    /// Admin-only. Needed whenever a fresh CVM boots with a new
    /// dstack-derived signer. Devnet-simplified — production rotation
    /// is multisig + attestation-gated (see `set_tee_pubkey.rs`).
    pub fn set_tee_pubkey(ctx: Context<SetTeePubkey>, keys: Vec<Pubkey>) -> Result<()> {
        set_tee_pubkey::set_tee_pubkey_handler(ctx, keys)
    }

    /// v3.5 — verify a single Groth16 attesting VALID_CREATE +
    /// VALID_PRICE for ALL N matches in a batch. Writes a
    /// `BatchValidityMarker` PDA seeded by the proof's root public input
    /// (the Merkle root over per-slot leaves). The N
    /// `tee_forced_settle_batched` txs that follow each carry a
    /// Merkle inclusion proof against this marker. See
    /// `instructions/verify_match_batch.rs`. Subsumes the legacy v3.1
    /// `verify_valid_create` + `verify_valid_price` ix pair, which
    /// were removed in Phase 1c-hard.
    pub fn verify_match_batch(
        ctx: Context<VerifyMatchBatch>,
        merkle_root: [u8; 32],
        expiry_slot: u64,
        proof: Groth16Proof,
    ) -> Result<()> {
        verify_match_batch::verify_match_batch_handler(ctx, merkle_root, expiry_slot, proof)
    }

    /// v3.5 — atomic TEE-forced settlement. Reads the batch's
    /// `BatchValidityMarker` (one per batch, keyed by Merkle root)
    /// and walks a depth-4 Merkle inclusion path to bind this
    /// specific match to it. The legacy v3.1 `tee_forced_settle` ix
    /// + its `ValidCreateMarker` / `ValidPriceMarker` per-match
    /// dependencies were removed in Phase 1c-hard.
    pub fn tee_forced_settle_batched(
        ctx: Context<TeeForcedSettleBatched>,
        tree_id: u8,
        payload: MatchResultPayload,
        match_index: u8,
        merkle_proof: [[u8; 32]; 4],
    ) -> Result<()> {
        tee_forced_settle_batched::tee_forced_settle_batched_handler(
            ctx,
            tree_id,
            payload,
            match_index,
            merkle_proof,
        )
    }

    /// v3.5 — close a `BatchValidityMarker` PDA and refund its rent to
    /// `marker.payer`. Called by the matcher after all N matches in
    /// the batch have settled, or by anyone post-expiry as garbage
    /// collection. See instructions/close_batch_validity_marker.rs.
    pub fn close_batch_validity_marker(
        ctx: Context<CloseBatchValidityMarker>,
        merkle_root: [u8; 32],
    ) -> Result<()> {
        close_batch_validity_marker::close_batch_validity_marker_handler(ctx, merkle_root)
    }

    /// DEV-NET-ONLY: reset a Merkle-tree shard to empty. Admin-gated. See
    /// instructions/reset_merkle_tree.rs for rationale + caveats. Compiled ONLY
    /// under `--features devnet-admin` (audit_1 F-01) — a mainnet build has no
    /// such discriminator.
    #[cfg(feature = "devnet-admin")]
    pub fn reset_merkle_tree(ctx: Context<ResetMerkleTree>, tree_id: u8) -> Result<()> {
        reset_merkle_tree::reset_merkle_tree_handler(ctx, tree_id)
    }

    /// DEV-NET-ONLY: close the `VaultConfig` PDA so it can be re-`initialize`d
    /// under a new layout (e.g. after the tree-sharding split). Admin-gated.
    /// See instructions/close_vault_config.rs. Compiled ONLY under
    /// `--features devnet-admin` (audit_1 F-02) — a mainnet build has no such
    /// discriminator.
    #[cfg(feature = "devnet-admin")]
    pub fn close_vault_config(ctx: Context<CloseVaultConfig>) -> Result<()> {
        close_vault_config::close_vault_config_handler(ctx)
    }
}
