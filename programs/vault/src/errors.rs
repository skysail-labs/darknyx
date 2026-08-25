//! The program's error codes.
//!
//! **Declaration order is a wire contract.** Anchor numbers `#[error_code]`
//! variants sequentially from 6000, so `InvalidProof` is 6000, `StaleMerkleRoot`
//! is 6004, and `InvalidBatchBinding` is 6022. Inserting a variant anywhere but
//! the end silently renumbers every code after it, and those numbers are quoted
//! throughout the repo — in comments, in `CLAUDE.md`'s failure-signature table,
//! and in client code that branches on them. **Append; do not insert.**
//!
//! Removing a variant is worse than renumbering, because the code it vacated is
//! then reused by whatever follows.

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

    // Error-code slot 6008 is retained so removing the retired wallet registry
    // cannot renumber every later Anchor error. No instruction emits it.
    #[msg("Retired error-code slot")]
    RetiredWalletRegistry,

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
    #[msg("Outstanding live-notes counter for this mint is less than the withdraw amount")]
    InsufficientOutstanding,
    #[msg("Outstanding live-notes counter has diverged from the on-chain SPL balance — vault is over-claimed")]
    SolvencyInvariantViolated,
    #[msg(
        "VALID_CREATE binding hash claimed by caller does not match the hash recomputed on-chain"
    )]
    InvalidCreateBinding,
    #[msg("VALID_CREATE marker expiry is invalid (must be in the future and within MAX_CREATE_MARKER_TTL_SLOTS)")]
    InvalidMarkerExpiry,
    #[msg("VALID_CREATE marker has expired")]
    MarkerExpired,
    #[msg(
        "VALID_PRICE binding hash claimed by caller does not match the marker PDA derived on-chain"
    )]
    InvalidPriceBinding,
    #[msg("VALID_PRICE marker has expired")]
    PriceMarkerExpired,
    #[msg(
        "Batched-validity Merkle inclusion failed: leaf does not walk up to the marker PDA's seed"
    )]
    InvalidBatchBinding,
    #[msg("BatchValidityMarker has expired")]
    BatchValidityMarkerExpired,
    #[msg("BatchValidityMarker has not yet reached its expiry slot")]
    BatchValidityMarkerNotExpired,

    // ---- Arithmetic / overflow ----
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
    #[msg("Amount must be non-zero")]
    ZeroAmount,

    // ---- Authorization ----
    #[msg("Caller is not authorized for this instruction")]
    Unauthorized,

    // ---- change-note settlement ----
    #[msg("Conservation law violated: note.amount != trade_leg + change_leg + fee_leg")]
    ConservationViolation,
    #[msg(
        "Change-note commitment inconsistent with change amount (one is zero, the other is not)"
    )]
    ChangeNoteInconsistent,
    #[msg("Re-lock requested but no change-note commitment was provided for that side")]
    RelockRequiresChangeNote,
    #[msg("Protocol owner commitment not initialised; fee accrual paused")]
    ProtocolOwnerUnset,
    #[msg("Fee-note commitment supplied with zero fee (or vice-versa)")]
    FeeNoteInconsistent,
    #[msg("Fee rate exceeds the allowed maximum (10000 bps)")]
    InvalidFeeRate,
    #[msg("Collected protocol fee does not match the exact governed fee rate")]
    InsufficientFeeCharge,

    // ---- Note merge ----
    #[msg("Merge K must be 2 or 4 and match the input commitment count")]
    InvalidMergeK,
    #[msg("Merge consumed-note or note-lock account is missing or does not match its derived PDA")]
    MergeAccountMismatch,
    #[msg("num_trees out of range (must be in 1..=MAX_TREES)")]
    InvalidTreeCount,
    #[msg("tee_pubkeys count out of range (must be in 1..=MAX_TEE_KEYS)")]
    InvalidKeyCount,
    #[msg("tee_pubkey is zero, duplicated, or reuses a governance authority")]
    InvalidTeeKey,
    #[msg("Input note lock has expired")]
    NoteLockExpired,
    #[msg("Operations admin is default or not distinct from cold governance")]
    InvalidAdminKey,
    #[msg("Protocol root key is default, unchanged, or reuses another authority")]
    InvalidRootKey,
    #[msg("Market base and quote mints must be distinct")]
    InvalidMarketMints,
    #[msg("Market price scale, tick size, minimum size, and circuit-breaker bounds are invalid")]
    InvalidMarketParameters,
    #[msg("Market is disabled")]
    MarketDisabled,
    #[msg("Merge must contain at least one active positive input")]
    EmptyMerge,
    #[msg("Merge inputs must be pairwise distinct")]
    DuplicateMergeInput,
    #[msg("Account uses a retired or otherwise invalid data layout")]
    InvalidAccountLayout,
    #[msg("Protocol fee-key binding is not initialized")]
    FeeKeyBindingUnset,
    #[msg("Protocol fee-key epoch is zero, stale, or changed without rotation")]
    InvalidFeeKeyEpoch,
}
