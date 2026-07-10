use crate::errors::VaultError;
use crate::merkle::compute_zero_subtree_roots;
use crate::state::*;
use anchor_lang::prelude::*;
use core::mem::size_of;

/// Initialize accounts — **mainnet** build (default; no `devnet-admin` feature).
///
/// F-03: the initializer is bound to the program's **upgrade authority**, so a
/// third party cannot front-run `initialize` on a freshly deployed program and
/// install themselves as `admin`. `program.programdata_address()` proves the
/// supplied `program_data` really is *this* program's loader data, and its
/// `upgrade_authority_address` must equal the `admin` signer.
///
/// The dev/test/devnet build (`devnet-admin` feature, below) uses the plain
/// admin signer instead: front-running isn't a threat where we control the
/// deploy, and the litesvm harness loads the program non-upgradeably (there is
/// no ProgramData account to bind against). This mirrors the F-01/F-02 gate —
/// the mainnet artifact carries the guard, the dev artifact stays testable.
#[cfg(not(feature = "devnet-admin"))]
#[derive(Accounts)]
#[instruction(tee_pubkey: Pubkey, root_key: Pubkey, num_trees: u8)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        init,
        payer = admin,
        space = 8 + size_of::<VaultConfig>(),
        seeds = [VaultConfig::SEED],
        bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    /// This program — used only to derive/verify its ProgramData address.
    #[account(
        constraint = program.programdata_address()? == Some(program_data.key())
            @ VaultError::Unauthorized,
    )]
    pub program: Program<'info, crate::program::Vault>,

    /// The upgradeable-loader ProgramData; its upgrade authority MUST be `admin`.
    #[account(
        constraint = program_data.upgrade_authority_address == Some(admin.key())
            @ VaultError::Unauthorized,
    )]
    pub program_data: Account<'info, ProgramData>,

    pub system_program: Program<'info, System>,
}

/// Initialize accounts — dev/test/devnet build (`devnet-admin`). Plain admin
/// signer, no upgrade-authority binding (see the mainnet variant above for why).
#[cfg(feature = "devnet-admin")]
#[derive(Accounts)]
#[instruction(tee_pubkey: Pubkey, root_key: Pubkey, num_trees: u8)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        init,
        payer = admin,
        space = 8 + size_of::<VaultConfig>(),
        seeds = [VaultConfig::SEED],
        bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    pub system_program: Program<'info, System>,
}

/// Initialize the GLOBAL vault config. The per-shard Merkle trees are created
/// separately (`initialize_tree`, one per shard id). `tee_pubkey` seeds the
/// authorized-key set as its first entry; the full K-key set is installed via
/// `set_tee_pubkeys` at the rotation ceremony. `num_trees` is the shard count.
pub fn initialize_handler(
    ctx: Context<Initialize>,
    tee_pubkey: Pubkey,
    root_key: Pubkey,
    num_trees: u8,
) -> Result<()> {
    require!(
        (1..=MAX_TREES).contains(&num_trees),
        VaultError::InvalidTreeCount
    );
    let cfg = &mut ctx.accounts.vault_config.load_init()?;

    cfg.admin = ctx.accounts.admin.key();
    cfg.tee_pubkeys = [Pubkey::default(); MAX_TEE_KEYS];
    cfg.tee_pubkeys[0] = tee_pubkey;
    cfg.num_tee_keys = 1;
    cfg.root_key = root_key;
    cfg.num_trees = num_trees;
    cfg.zero_subtree_roots = compute_zero_subtree_roots()?;
    cfg.bump = ctx.bumps.vault_config;
    cfg.protocol_owner_commitment = [0u8; 32];
    cfg.fee_rate_bps = 0;
    cfg._padding = [0u8; 3];
    // Matcher params unset at init (0 ⇒ TEE keeps its env/dev default);
    // governance sets them later via `set_protocol_config`.
    cfg.tick_size = 0;
    cfg.min_order_size = 0;
    cfg.circuit_breaker_bps = 0;
    let _ = VaultError::ZeroAmount; // keep errors linked in
    Ok(())
}
