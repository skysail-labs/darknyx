use anchor_lang::prelude::*;

/// Fixed Merkle tree depth. 2^20 = 1,048,576 notes. Matches circom circuit.
pub const MERKLE_DEPTH: u8 = 20;

/// Number of historical Merkle roots the vault tracks. A withdrawal's proof
/// may reference any of the last N roots so that a legitimate user isn't
/// DoS'd by a racing deposit.
///
/// 32 roots × ~400 ms/slot ≈ ~13 seconds of root freshness — far too short
/// under load (multiple deposits per slot burn the buffer faster). 64 roots
/// gives ~26 seconds, which comfortably covers proof generation even on slow
/// client hardware. The on-chain cost is 64 × 32 = 2 048 extra bytes in the
/// zero-copy VaultConfig account — negligible.
pub const ROOT_HISTORY_SIZE: usize = 64;

/// Hard ceiling on how far in the future a `NoteLock`'s `expiry_slot` may
/// sit. ~216_000 slots ≈ 24h at 400ms slots. Prevents a malicious TEE from
/// effectively burning a note by locking it for `u64::MAX` slots (the
/// `withdraw` ix refuses while a lock exists, even an expired one, until
/// `release_lock` is called — so the lock window is the censorship window).
pub const MAX_LOCK_TTL_SLOTS: u64 = 216_000;

/// Global vault configuration + append-only Merkle tree header + root history.
#[account(zero_copy)]
pub struct VaultConfig {
    /// Admin authority (usually a multisig). Can rotate `tee_pubkey`.
    pub admin: Pubkey,
    /// Attested TEE Ed25519 signing pubkey. Verified for `tee_forced_settle`.
    pub tee_pubkey: Pubkey,
    /// Permission Group "root key". The only key authorised to configure the
    /// MagicBlock Permission Group that gates order submission. Rotatable only
    /// by a self-signed message (see `rotate_root_key` in permissions program).
    pub root_key: Pubkey,
    /// Number of leaves currently inserted into the Merkle tree. Monotonically
    /// increasing; used as the `note_counter` for blinding factor derivation.
    pub leaf_count: u64,
    /// Current Merkle root.
    pub current_root: [u8; 32],
    /// Ring buffer of the last `ROOT_HISTORY_SIZE` roots, newest first.
    pub roots: [[u8; 32]; ROOT_HISTORY_SIZE],
    /// Precomputed empty-subtree roots at each level (0 = leaf, depth-1 = root's children).
    /// Needed to verify append insertions without holding the entire tree on-chain.
    pub zero_subtree_roots: [[u8; 32]; MERKLE_DEPTH as usize],
    /// Right-path nodes: the rightmost filled node at each level. Lets us
    /// append a new leaf by recomputing only MERKLE_DEPTH hashes. This is
    /// exactly the "incremental Merkle tree" pattern from Tornado/Semaphore.
    pub right_path: [[u8; 32]; MERKLE_DEPTH as usize],
    pub roots_head: u8,
    pub bump: u8,
    /// Phase-5 protocol-owned shielded identity. Every fee note flushed
    /// at batch close carries `owner_commitment = protocol_owner_commitment`
    /// so the protocol treasury's Spending Key can later VALID_SPEND them.
    /// Zero-bytes until initialised — fee accrual paused while unset.
    pub protocol_owner_commitment: [u8; 32],
    /// Protocol fee rate expressed in basis points of notional. e.g.
    /// `30 = 0.30 %`. Applied equally to both sides of every match.
    pub fee_rate_bps: u16,
    /// Explicit trailing padding so the zero-copy Pod layout has no implicit padding.
    pub _padding: [u8; 4],
}

impl VaultConfig {
    pub const SEED: &'static [u8] = b"vault_config";
}

/// PDA marking a registered user commitment (wallet identity).
#[account(zero_copy)]
pub struct WalletEntry {
    pub commitment: [u8; 32],
    pub owner: Pubkey, // the Root Key that signed `create_wallet`
    pub created_slot: u64,
    pub bump: u8,
    pub _padding: [u8; 7],
}

impl WalletEntry {
    pub const SEED: &'static [u8] = b"wallet";
}

/// PDA marking a spent nullifier. Existence of the PDA => nullifier consumed.
#[account(zero_copy)]
pub struct NullifierEntry {
    pub nullifier: [u8; 32],
    pub spent_slot: u64,
    pub bump: u8,
    pub _padding: [u8; 7],
}

impl NullifierEntry {
    pub const SEED: &'static [u8] = b"nullifier";
}

/// PDA marking a note commitment consumed by TEE-forced settlement.
#[account(zero_copy)]
pub struct ConsumedNoteEntry {
    pub note_commitment: [u8; 32],
    pub match_id: [u8; 16],
    pub consumed_slot: u64,
    pub bump: u8,
    pub _padding: [u8; 7],
}

impl ConsumedNoteEntry {
    pub const SEED: &'static [u8] = b"consumed_note";
}

/// PDA locking a note to a specific order. Automatically expires at `expiry_slot`.
///
/// Phase 5 additions:
///   - `amount` is the full value of the locked note (in base units of the
///     asset the note carries). Captured at `lock_note` time so
///     `tee_forced_settle` can enforce the conservation-law equality
///     `note.amount == trade_leg + change_leg` before ever writing state.
///
/// v2 additions (on-chain hardening — see `tee_v2_status_and_migration_brief.md`):
///   - `token_mint` is the SPL mint that the locked note carries. Set by
///     `lock_note` from the public inputs of the VALID_INPUT proof (so it is
///     cryptographically bound to the on-chain Merkle leaf — a malicious TEE
///     cannot lie about the mint). Used by `tee_forced_settle` for per-mint
///     conservation checks.
#[account(zero_copy)]
pub struct NoteLock {
    pub note_commitment: [u8; 32],
    pub token_mint: Pubkey,
    pub order_id: [u8; 16],
    pub expiry_slot: u64,
    pub locked_by: Pubkey, // the TEE key that locked
    pub amount: u64,
    pub bump: u8,
    pub _padding: [u8; 7],
}

impl NoteLock {
    pub const SEED: &'static [u8] = b"note_lock";
}

/// v2 — per-mint live-note accounting (the "outstanding" counter).
///
/// Tracks Σ amount across every live note (deposited but not withdrawn,
/// minus any consumed via TEE-forced settlement). One PDA per SPL mint,
/// initialized lazily on first deposit of that mint.
///
/// Invariant maintained by `deposit` and `withdraw`:
///   `outstanding <= vault_token_account.amount`  (the on-chain SPL balance)
///
/// `tee_forced_settle` does not change `outstanding` — settlement is
/// mint-conservation-preserving (Σ inputs per mint == Σ outputs per mint,
/// enforced by the existing per-side conservation law).
///
/// Catches both directions of fraud cleanly:
///   - Malicious TEE creating output notes with a fake mint: withdraw will
///     hit `InsufficientOutstanding` for that mint before reaching the SPL
///     transfer-out (vs. silently failing the SPL transfer when the vault
///     happens to have funds in that mint from another user's deposit).
///   - Off-by-one accounting bug: the assertion at the end of every
///     deposit/withdraw catches divergence between this counter and the
///     real SPL balance.
#[account]
#[derive(Default)]
pub struct OutstandingMint {
    pub mint: Pubkey,
    pub outstanding: u64,
    pub bump: u8,
}

impl OutstandingMint {
    pub const SEED: &'static [u8] = b"outstanding_mint";
    /// 8 disc + 32 mint + 8 outstanding + 1 bump.
    pub const SPACE: usize = 8 + 32 + 8 + 1;
}

/// v3 — VALID_CREATE proof attestation marker.
///
/// Created by `verify_valid_create` after a successful Groth16 check. The
/// PDA seed is `[b"valid_create", binding_hash]` where `binding_hash` is
/// a SHA-256 over the 14 fields the circuit attested to (6 commitments + 2
/// mints + 6 amounts). `tee_forced_settle` recomputes the same hash from
/// its payload + the input locks' mints and reads this PDA to prove the
/// TEE produced a valid VALID_CREATE before settling.
///
/// `expiry_slot` lets stale markers be reclaimed (markers are intended to
/// be consumed by the very next settle tx — see `MAX_CREATE_MARKER_TTL_SLOTS`).
#[account]
#[derive(Default)]
pub struct ValidCreateMarker {
    /// The 32-byte payer who funded this marker's rent. Refund target on close.
    pub payer: Pubkey,
    /// Slot past which this marker is considered stale and may be released.
    pub expiry_slot: u64,
    pub bump: u8,
}

impl ValidCreateMarker {
    pub const SEED: &'static [u8] = b"valid_create";
    /// 8 disc + 32 payer + 8 expiry + 1 bump.
    pub const SPACE: usize = 8 + 32 + 8 + 1;
}

/// Hard ceiling on how far into the future a `ValidCreateMarker` may sit.
/// The marker is meant to be consumed by the immediately-following settle
/// tx — anything beyond a couple of minutes is almost certainly abandoned
/// state from a TEE that failed to land its settle. Tuned to leave the
/// caller plenty of slop without letting stale markers gum up devnet.
pub const MAX_CREATE_MARKER_TTL_SLOTS: u64 = 300; // ~2 min at 400ms slots.

impl VaultConfig {
    /// Check whether a Merkle root appears in the recent-roots ring buffer.
    pub fn contains_root(&self, root: &[u8; 32]) -> bool {
        if &self.current_root == root {
            return true;
        }
        self.roots.iter().any(|r| r == root)
    }

    /// Push a new root into the ring buffer, replacing the oldest entry.
    pub fn push_root(&mut self, root: [u8; 32]) {
        let idx = self.roots_head as usize;
        self.roots[idx] = self.current_root;
        self.roots_head = ((idx + 1) % ROOT_HISTORY_SIZE) as u8;
        self.current_root = root;
    }
}
