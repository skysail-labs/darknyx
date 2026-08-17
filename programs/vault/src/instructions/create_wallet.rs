use crate::state::*;
use crate::zk::{verifier::make_vk, verify_groth16_proof, vk_valid_wallet_create::*, Groth16Proof};
use anchor_lang::prelude::*;
use core::mem::size_of;

#[derive(Accounts)]
#[instruction(commitment: [u8; 32], proof: Groth16Proof)]
pub struct CreateWallet {
    /// Root Key signer.
    #[account(mut)]
    pub owner: Signer,

    // CU-3 / audit F-07: `vault_config` was here but never read — the handler
    // only verifies the VALID_WALLET_CREATE proof + inits `wallet_entry`. Dropped
    // (saves an account on the ix; SDK + tests mirror this account list).
    #[account(
        init,
        payer = owner,
        space = 8 + size_of::<WalletEntry>(),
        seeds = [WalletEntry::SEED, commitment.as_ref()],
        bump,
    )]
    pub wallet_entry: Account<WalletEntry>,

    pub system_program: Program<System>,
}

pub fn create_wallet_handler(
    ctx: &mut Context<CreateWallet>,
    commitment: [u8; 32],
    proof: Groth16Proof,
) -> Result<()> {
    // VALID_WALLET_CREATE has exactly 1 public input: the commitment itself.
    let public_inputs: [[u8; 32]; 1] = [commitment];

    let vk = make_vk(
        &VALID_WALLET_CREATE_ALPHA_G1,
        &VALID_WALLET_CREATE_BETA_G2,
        &VALID_WALLET_CREATE_GAMMA_G2,
        &VALID_WALLET_CREATE_DELTA_G2,
        &VALID_WALLET_CREATE_IC,
    );

    verify_groth16_proof::<1>(&vk, &proof, &public_inputs)?;

    let w = &mut ctx.accounts.wallet_entry;
    w.commitment = commitment;
    w.owner = ctx.accounts.owner.address();
    w.created_slot = Clock::get()?.slot;
    w.bump = ctx.bumps.wallet_entry;
    w._padding = [0u8; 7];

    emit!(WalletCreated {
        commitment,
        owner: ctx.accounts.owner.address(),
        slot: w.created_slot,
    });

    Ok(())
}

#[event]
pub struct WalletCreated {
    pub commitment: [u8; 32],
    pub owner: Address,
    pub slot: u64,
}
