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
/// `upgrade_authority_address` must equal the `upgrade_authority` signer. The
/// signer supplies a distinct `operations_admin` argument stored in
/// `VaultConfig`, enabling separate cold upgrade/root and operations quorums.
///
/// The dev/test/devnet build (`devnet-admin` feature, below) uses a plain
/// initializer signer instead: front-running isn't a threat where we control the
/// deploy, and the litesvm harness loads the program non-upgradeably (there is
/// no ProgramData account to bind against). This mirrors the F-01/F-02 gate —
/// the mainnet artifact carries the guard, the dev artifact stays testable.
#[cfg(not(feature = "devnet-admin"))]
#[derive(Accounts)]
#[instruction(operations_admin: Pubkey, tee_pubkeys: Vec<Pubkey>, root_key: Pubkey, num_trees: u8)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub upgrade_authority: Signer<'info>,

    #[account(
        init,
        payer = upgrade_authority,
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

    /// The upgradeable-loader ProgramData; its upgrade authority MUST match the
    /// `upgrade_authority` signer.
    #[account(
        constraint = program_data.upgrade_authority_address == Some(upgrade_authority.key())
            @ VaultError::Unauthorized,
    )]
    pub program_data: Account<'info, ProgramData>,

    pub system_program: Program<'info, System>,
}

/// Initialize accounts — dev/test/devnet build (`devnet-admin`). Plain
/// initializer signer, no upgrade-authority binding (see mainnet above).
#[cfg(feature = "devnet-admin")]
#[derive(Accounts)]
#[instruction(operations_admin: Pubkey, tee_pubkeys: Vec<Pubkey>, root_key: Pubkey, num_trees: u8)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub upgrade_authority: Signer<'info>,

    #[account(
        init,
        payer = upgrade_authority,
        space = 8 + size_of::<VaultConfig>(),
        seeds = [VaultConfig::SEED],
        bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    pub system_program: Program<'info, System>,
}

/// Initialize the GLOBAL vault config. The per-shard Merkle trees are created
/// separately (`initialize_tree`, one per shard id). Initialization installs the
/// full one-key-per-shard TEE set atomically and records a possibly distinct
/// operations admin; no default-key or partial-shard bootstrap is accepted.
pub fn initialize_handler(
    ctx: Context<Initialize>,
    operations_admin: Pubkey,
    tee_pubkeys: Vec<Pubkey>,
    root_key: Pubkey,
    num_trees: u8,
) -> Result<()> {
    require!(
        (1..=MAX_TREES).contains(&num_trees),
        VaultError::InvalidTreeCount
    );
    require!(
        operations_admin != Pubkey::default(),
        VaultError::InvalidAdminKey
    );
    require!(root_key != Pubkey::default(), VaultError::InvalidRootKey);
    require!(operations_admin != root_key, VaultError::InvalidAdminKey);
    #[cfg(not(feature = "devnet-admin"))]
    require!(
        operations_admin != ctx.accounts.upgrade_authority.key(),
        VaultError::InvalidAdminKey
    );
    require!(
        tee_pubkeys.len() == num_trees as usize && tee_pubkeys.len() <= MAX_TEE_KEYS,
        VaultError::InvalidKeyCount
    );
    for (i, key) in tee_pubkeys.iter().enumerate() {
        require!(
            *key != Pubkey::default() && *key != operations_admin && *key != root_key,
            VaultError::InvalidTeeKey
        );
        require!(!tee_pubkeys[..i].contains(key), VaultError::InvalidTeeKey);
    }
    let cfg = &mut ctx.accounts.vault_config.load_init()?;

    cfg.admin = operations_admin;
    cfg.tee_pubkeys = [Pubkey::default(); MAX_TEE_KEYS];
    for (slot, key) in cfg.tee_pubkeys.iter_mut().zip(tee_pubkeys.iter()) {
        *slot = *key;
    }
    cfg.num_tee_keys = tee_pubkeys.len() as u8;
    cfg.root_key = root_key;
    cfg.num_trees = num_trees;
    cfg.zero_subtree_roots = compute_zero_subtree_roots()?;
    cfg.bump = ctx.bumps.vault_config;
    cfg.protocol_owner_commitment = [0u8; 32];
    cfg.fee_rate_bps = 0;
    cfg._padding = [0u8; 3];
    let _ = VaultError::ZeroAmount; // keep errors linked in
    Ok(())
}
