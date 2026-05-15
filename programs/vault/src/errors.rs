use anchor_lang::prelude::*;

#[error_code]
pub enum VaultError {
    // ---- ZK proof verification ----
    #[msg("Invalid Groth16 proof")]
    InvalidProof,
    #[msg("Public inputs malformed or wrong length")]
    MalformedPublicInputs,
    #[msg("Proof public input does not match expected bound value")]
    PublicInputMismatch,

    // ---- Merkle tree ----
    #[msg("Merkle tree is full")]
    MerkleTreeFull,
    #[msg("Merkle root provided by proof does not match current on-chain root")]
    StaleMerkleRoot,

    // ---- Note state ----
    #[msg("Note is currently locked by an active order")]
    NoteAlreadyLocked,
    #[msg("Note has been consumed by a prior settlement")]
    NoteAlreadyConsumed,
    #[msg("Nullifier has already been spent")]
    NullifierAlreadySpent,

    // ---- Wallet registry ----
    #[msg("User commitment is already registered")]
    WalletAlreadyRegistered,

    // ---- Lock lifecycle ----
    #[msg("Note lock has not yet expired")]
    LockNotExpired,
    #[msg("Note lock not found")]
    LockNotFound,
    #[msg("Lock expiry slot is not in the future")]
    InvalidExpirySlot,

    // ---- TEE signature / settlement ----
    #[msg("TEE signature is invalid")]
    InvalidTeeSignature,
    #[msg("TEE public key not yet registered on-chain")]
    TeeKeyNotRegistered,
    #[msg("Input note commitment not locked for the claimed order")]
    NoteNotLockedForOrder,
    #[msg("Lock token_mint does not match payload quote_mint/base_mint")]
    MintMismatch,
    #[msg("Outstanding live-notes counter for this mint is less than the withdraw amount")]
    InsufficientOutstanding,
    #[msg("Outstanding live-notes counter has diverged from the on-chain SPL balance — vault is over-claimed")]
    SolvencyInvariantViolated,

    // ---- Arithmetic / overflow ----
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
    #[msg("Amount must be non-zero")]
    ZeroAmount,

    // ---- Authorization ----
    #[msg("Caller is not authorized for this instruction")]
    Unauthorized,

    // ---- Phase 5: change-note settlement ----
    #[msg("Conservation law violated: note.amount != trade_leg + change_leg + fee_leg")]
    ConservationViolation,
    #[msg("Change-note commitment inconsistent with change amount (one is zero, the other is not)")]
    ChangeNoteInconsistent,
    #[msg("Re-lock requested but no change-note commitment was provided for that side")]
    RelockRequiresChangeNote,
    #[msg("Protocol owner commitment not initialised; fee accrual paused")]
    ProtocolOwnerUnset,
    #[msg("Fee-note commitment supplied with zero fee (or vice-versa)")]
    FeeNoteInconsistent,
    #[msg("Fee rate exceeds the allowed maximum (10000 bps)")]
    InvalidFeeRate,
}
