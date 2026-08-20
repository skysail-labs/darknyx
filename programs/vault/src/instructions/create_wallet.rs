use crate::state::*;
use crate::zk::{verifier::make_vk, verify_groth16_proof, vk_valid_wallet_create::*, Groth16Proof};
use anchor_lang::prelude::*;
use core::mem::size_of;

#[derive(Accounts)]
#[instruction(commitment: [u8; 32])]
pub struct CreateWallet {
    /// Root Key signer.
    #[account(mut)]
    pub owner: Signer,

    // CU-3 / audit F-07: `vault_config` was here but never read — the handler
    // only verifies the VALID_WALLET_CREATE proof + inits `wallet_entry`. Dropped
    // (saves an account on the ix; SDK + tests mirror this account list).
    /// Seeded by (commitment, OWNER) — the owner is what stops squatting.
    ///
    /// VALID_WALLET_CREATE's only public input is the commitment, so the
    /// `(commitment, proof)` pair in a landed transaction is replayable by
    /// anyone. When the address depended on the commitment alone, a front-runner
    /// could resubmit that pair with their own key, win the race, and take
    /// `PDA([SEED, commitment])` permanently — `init` is one-shot and there is
    /// no `close_wallet`. The victim could not route around it either: the
    /// commitment is `Poseidon(root_key, spending_key, viewing_key, r0, r1, r2)`,
    /// a deterministic function of their long-lived identity, so "pick another
    /// commitment" means "rotate your wallet".
    ///
    /// Binding the owner into the seeds removes the collision instead of
    /// policing it. A squatter now takes a DIFFERENT address and blocks nobody,
    /// and the entry means what it always claimed to: *this signer registered
    /// this commitment*.
    ///
    /// Two entries may now exist for one commitment. That is acceptable
    /// precisely because no instruction reads `WalletEntry` for authorization —
    /// verified by grep, and the reason `audit_9` TR-14 rated the original
    /// finding as having no authority impact. **If that ever changes, this is
    /// not sufficient**: a reader of `wallet_entry.owner` needs the owner bound
    /// inside the PROOF (TR-14 fix B), because seeds prove only who paid rent,
    /// not who controls the commitment's keys.
    #[account(
        init,
        payer = owner,
        space = 8 + size_of::<WalletEntry>(),
        seeds = [WalletEntry::SEED, commitment.as_ref(), owner.address().as_ref()],
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
    w.owner = *ctx.accounts.owner.address();
    w.created_slot = (Clock::get()?.slot).into();
    w.bump = ctx.bumps.wallet_entry;
    w._padding = [0u8; 7];

    emit!(WalletCreated {
        commitment,
        owner: *ctx.accounts.owner.address(),
        slot: w.created_slot.get(),
    });

    Ok(())
}

#[event]
pub struct WalletCreated {
    pub commitment: [u8; 32],
    pub owner: Address,
    pub slot: u64,
}
