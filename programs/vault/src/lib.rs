//! Darknyx dark pool — vault program.
//!
//! Responsibilities:
//!   - SPL token custody via per-mint PDA token accounts.
//!   - UTXO note Merkle tree (Poseidon2 over BN254, depth 20).
//!   - Nullifier set / consumed-notes set / note locks (all PDA-based).
//!   - Groth16 verification of VALID_WALLET_CREATE and VALID_SPEND proofs.
//!   - TEE-forced atomic settlement.
//!
//! See `CRYPTOGRAPHY.md` for the note model, circuits, and settlement design,
//! and `docs/ARCHITECTURE.md` for the account/PDA table.

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
pub use instructions::close_vault_config;
pub use instructions::create_wallet;
pub use instructions::deposit;
pub use instructions::initialize;
pub use instructions::initialize_market;
pub use instructions::lock_note;
pub use instructions::merge;
pub use instructions::release_lock;
pub use instructions::reset_merkle_tree;
pub use instructions::rotate_root_key;
pub use instructions::set_protocol_config;
pub use instructions::set_tee_pubkey;
pub use instructions::settlement_shared;
pub use instructions::tee_forced_settle_batched;
pub use instructions::update_market_config;
pub use instructions::verify_match_batch;
pub use instructions::withdraw;

use instructions::*;
// The v2 `#[program]` macro resolves `super::__client_accounts_<name>` for every
// instruction, including ones whose fn is `#[cfg]`-gated out (it does not
// propagate the cfg). These two globs hoist the generated modules for the
// devnet-admin instructions to crate root so the FEATURELESS (mainnet) build
// resolves them; the instructions themselves stay gated, so neither gains a
// discriminator.
#[cfg(not(feature = "devnet-admin"))]
use instructions::close_vault_config::*;
#[cfg(not(feature = "devnet-admin"))]
use instructions::reset_merkle_tree::*;
use zk::Groth16Proof;

declare_id!("C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx");

#[program]
pub mod vault {
    use super::*;

    /// Initialize the global `VaultConfig` singleton. One-time setup. The K
    /// Merkle-tree shards are created separately via `initialize_tree`.
    pub fn initialize(
        ctx: &mut Context<Initialize>,
        operations_admin: Address,
        tee_pubkeys: Vec<Address>,
        root_key: Address,
        num_trees: u8,
    ) -> Result<()> {
        initialize::initialize_handler(ctx, operations_admin, tee_pubkeys, root_key, num_trees)
    }

    /// Initialize one enabled mint-pair market. Mint decimals are read from the
    /// SPL accounts and scaled-price parameters are governance-bounded.
    pub fn initialize_market(
        ctx: &mut Context<InitializeMarket>,
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
    pub fn initialize_tree(ctx: &mut Context<InitializeTree>, tree_id: u8) -> Result<()> {
        initialize_tree::initialize_tree_handler(ctx, tree_id)
    }

    /// Rotate the protocol root key. Must be signed by the current
    /// root key (self-signature model — admin cannot override).
    pub fn rotate_root_key(ctx: &mut Context<RotateRootKey>, new_root_key: Address) -> Result<()> {
        rotate_root_key::rotate_root_key_handler(ctx, new_root_key)
    }

    /// Register a User Commitment via VALID_WALLET_CREATE proof.
    pub fn create_wallet(
        ctx: &mut Context<CreateWallet>,
        commitment: [u8; 32],
        proof: Groth16Proof,
    ) -> Result<()> {
        create_wallet::create_wallet_handler(ctx, commitment, proof)
    }

    /// Deposit SPL tokens and insert a proof-bound UTXO note commitment.
    /// The proof keeps owner_commitment + inner_hash private while binding the
    /// public mint, amount, commitment, and recovery nonce.
    pub fn deposit(
        ctx: &mut Context<Deposit>,
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
        ctx: &mut Context<Withdraw>,
        tree_id: u8,
        note_use_tag: [u8; 32],
        nullifier: [u8; 32],
        merkle_root: [u8; 32],
        amount: u64,
        proof: Groth16Proof,
    ) -> Result<()> {
        withdraw::withdraw_handler(
            ctx,
            tree_id,
            note_use_tag,
            nullifier,
            merkle_root,
            amount,
            proof,
        )
    }

    /// Merge K input notes (K=2 or 4) into ONE output note of their sum, using a
    /// VALID_MERGE proof. In-pool consolidation — no external transfer. The K
    /// non-zero input use tags' consume/lock PDAs are passed as
    /// remaining_accounts.
    #[allow(clippy::too_many_arguments)]
    pub fn merge(
        ctx: &mut Context<Merge>,
        tree_id: u8,
        input_use_tags: Vec<[u8; 32]>,
        output_commitment: [u8; 32],
        token_mint: Address,
        merkle_root: [u8; 32],
        k: u8,
        proof: Groth16Proof,
    ) -> Result<()> {
        merge::merge_handler(
            ctx,
            tree_id,
            input_use_tags,
            output_commitment,
            token_mint,
            merkle_root,
            k,
            proof,
        )
    }

    /// Lock a note to an order. TEE-only, and it requires a VALID_INPUT proof
    /// generated by the note owner — so the TEE can neither phantom-lock a note
    /// it does not own nor learn the private amount from instruction or event
    /// data.
    #[allow(clippy::too_many_arguments)]
    pub fn lock_note(
        ctx: &mut Context<LockNote>,
        tree_id: u8,
        note_use_tag: [u8; 32],
        order_id: [u8; 16],
        expiry_slot: u64,
        token_mint: Address,
        merkle_root: [u8; 32],
        proof: Groth16Proof,
    ) -> Result<()> {
        lock_note::lock_note_handler(
            ctx,
            tree_id,
            note_use_tag,
            order_id,
            expiry_slot,
            token_mint,
            merkle_root,
            proof,
        )
    }

    /// Release an expired note lock.
    pub fn release_lock(ctx: &mut Context<ReleaseLock>, note_use_tag: [u8; 32]) -> Result<()> {
        release_lock::release_lock_handler(ctx, note_use_tag)
    }

    /// Post-deployment governance setter for the protocol-fee fields of
    /// `VaultConfig`. Admin-only. Safe to call repeatedly (e.g. to rotate
    /// the protocol-owner commitment or change the fee rate).
    pub fn set_protocol_config(
        ctx: &mut Context<SetProtocolConfig>,
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
        ctx: &mut Context<UpdateMarketConfig>,
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
    pub fn set_tee_pubkey(ctx: &mut Context<SetTeeAddress>, keys: Vec<Address>) -> Result<()> {
        set_tee_pubkey::set_tee_pubkey_handler(ctx, keys)
    }

    /// Verify one Groth16 proof covering ALL N matches in a batch, then write a
    /// `BatchValidityMarker` PDA seeded by the proof's root public input (the
    /// Merkle root over the per-slot leaves). Each of the N
    /// `tee_forced_settle_batched` txs that follow carries a Merkle inclusion
    /// proof against this marker, which is how a single proof authorises many
    /// settles. See `instructions/verify_match_batch.rs`.
    pub fn verify_match_batch(
        ctx: &mut Context<VerifyMatchBatch>,
        merkle_root: [u8; 32],
        proof: Groth16Proof,
    ) -> Result<()> {
        verify_match_batch::verify_match_batch_handler(ctx, merkle_root, proof)
    }

    /// Atomic TEE-forced settlement for one match. Reads the batch's
    /// `BatchValidityMarker` (one per batch, keyed by Merkle root) and walks a
    /// depth-4 Merkle inclusion path to bind this specific match to it. The
    /// marker is read-only here and is closed separately — see
    /// `close_batch_validity_marker`.
    pub fn tee_forced_settle_batched(
        ctx: &mut Context<TeeForcedSettleBatched>,
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

    /// Close a `BatchValidityMarker` PDA and refund its rent to
    /// `marker.payer`. Called by the matcher after all N matches in
    /// the batch have settled, or by anyone post-expiry as garbage
    /// collection. See instructions/close_batch_validity_marker.rs.
    pub fn close_batch_validity_marker(
        ctx: &mut Context<CloseBatchValidityMarker>,
        merkle_root: [u8; 32],
    ) -> Result<()> {
        close_batch_validity_marker::close_batch_validity_marker_handler(ctx, merkle_root)
    }

    /// DEV-NET-ONLY: reset a Merkle-tree shard to empty. Admin-gated. See
    /// instructions/reset_merkle_tree.rs for rationale + caveats. Compiled ONLY
    /// under `--features devnet-admin` (audit_1 F-01) — a mainnet build has no
    /// such discriminator.
    #[cfg(feature = "devnet-admin")]
    pub fn reset_merkle_tree(ctx: &mut Context<ResetMerkleTree>, tree_id: u8) -> Result<()> {
        reset_merkle_tree::reset_merkle_tree_handler(ctx, tree_id)
    }

    /// DEV-NET-ONLY: close the `VaultConfig` PDA so it can be re-`initialize`d
    /// under a new layout (e.g. after the tree-sharding split). Admin-gated.
    /// See instructions/close_vault_config.rs. Compiled ONLY under
    /// `--features devnet-admin` (audit_1 F-02) — a mainnet build has no such
    /// discriminator.
    #[cfg(feature = "devnet-admin")]
    pub fn close_vault_config(ctx: &mut Context<CloseVaultConfig>) -> Result<()> {
        close_vault_config::close_vault_config_handler(ctx)
    }
}
