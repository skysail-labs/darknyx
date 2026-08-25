//! Account layouts, PDA seeds, and the protocol's sizing constants.
//!
//! **Every `SEED` literal here is hand-mirrored into
//! `packages/sdk/src/idl/seeds.ts`, and nothing in CI compares the two.** Adding
//! a PDA on this side without adding the seed and a `xxxPda()` helper to the SDK
//! compiles cleanly and fails only at runtime, as `AccountNotFound` or
//! `ConstraintSeeds (2006)` against an address that looks plausible. The
//! integration tests are the only thing that catches it (`CLAUDE.md` §8.3).
//!
//! Which value a seed takes is equally easy to get wrong. `NoteLock` and
//! `ConsumedNoteEntry` are keyed by the **note-use tag**; Merkle leaves and
//! `DepositedNoteEntry` are keyed by the **commitment**. Both are `[u8; 32]`, so
//! swapping them also compiles and also fails only on-chain — see
//! `CRYPTOGRAPHY.md` §2.1.
//!
//! Per-leaf PDAs are the replay-protection backbone: `DepositedNoteEntry`,
//! `ConsumedNoteEntry`, and `NoteLock` all rely on `init`
//! failing when the account already exists. Relaxing one to `init_if_needed`
//! removes the guard rather than making it more convenient (`CLAUDE.md` §8.1).

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
/// sit. The settler stamps the lock with the ORDER's `expiry_slot`, so this is
/// simultaneously the **max order lifetime** and the **live censorship
/// window**: withdraw and merge refuse the note strictly before this boundary,
/// then treat the lock as dead at expiry even if a sweeper has not closed its
/// account yet (F-05 / CS-09).
///
/// 4_500 slots ≈ **30 min at today's 400 ms slots**. Placement→settlement is
/// ≤ ~30 s in practice, so this is ~60× headroom. It's a FIXED slot count, so
/// after Alpenglow halves slot times to ~200 ms it naturally becomes ~15 min of
/// wall-clock — the intended tightening, with no code change. Intake rejects
/// orders whose `expiry_slot` exceeds `current + MAX_LOCK_TTL_SLOTS` up front
/// (`api/orders.rs`), so the cap surfaces as a clean placement error rather than
/// a settle-time `lock_note` failure.
pub const MAX_LOCK_TTL_SLOTS: u64 = 4_500;

/// Max authorized TEE signer keys (= max shard fee-payers). Each settles a
/// shard; round-robined so concurrent settles use DISTINCT fee-payers (no
/// write-conflict on the fee-payer account — the tree-sharding throughput lever).
pub const MAX_TEE_KEYS: usize = 16;

/// Max Merkle-tree shards. Each shard is its own `MerkleTree` account so settles
/// to different shards don't write-conflict and the leader can co-include more
/// of them per block.
pub const MAX_TREES: u8 = 16;

/// Governance ceiling for a market's circuit-breaker band. 10_000 bps is a
/// 100% move from the oracle anchor; larger values no longer provide a useful
/// safety bound and make configuration mistakes harder to detect.
pub const MAX_CIRCUIT_BREAKER_BPS: u64 = 10_000;

/// Global vault configuration. The Merkle-tree STATE lives in the per-tree
/// [`MerkleTree`] accounts (sharded); this account holds only the
/// tree-independent config + the precomputed empty-subtree roots (identical for
/// every shard, so stored once here). Read-only on the settle hot path → no
/// write-contention.
#[account]
pub struct VaultConfig {
    /// Admin authority (usually a multisig). Can rotate the TEE keys.
    pub admin: Address,
    /// Authorized TEE Ed25519 signer pubkeys. Each is simultaneously a settle
    /// fee-payer + `tee_authority` + ed25519 settle-signer (one signer per tx,
    /// no extra signature). The first `num_tee_keys` are live.
    pub tee_pubkeys: [Address; MAX_TEE_KEYS],
    /// Protocol "root key": a long-lived governance authority distinct from
    /// `admin`, rotatable only by a self-signed message (see `rotate_root_key`).
    pub root_key: Address,
    /// Precomputed empty-subtree roots at each level (0 = leaf, depth-1 = root's
    /// children). Tree-independent, so global; the per-tree append reads these.
    pub zero_subtree_roots: [[u8; 32]; MERKLE_DEPTH as usize],
    /// Protocol-owned shielded identity. Every per-match fee note carries
    /// `owner_commitment = protocol_owner_commitment` and is issued atomically
    /// by the Tx D that consumes that match's inputs.
    pub protocol_owner_commitment: [u8; 32],
    /// Poseidon2(35, fee_epoch_key). The secret key is injected into the TEE;
    /// only this binding is public and proof-bound.
    pub fee_key_binding: [u8; 32],
    /// Monotonic governance epoch selecting the fee-recovery key.
    pub fee_key_epoch: PodU64,
    /// Protocol fee rate in basis points of notional (e.g. `30 = 0.30 %`).
    pub fee_rate_bps: PodU16,
    /// Number of live entries in `tee_pubkeys`.
    pub num_tee_keys: u8,
    /// Number of Merkle-tree shards the matcher round-robins across.
    pub num_trees: u8,
    pub bump: u8,
    /// Explicit tail padding so the zero-copy struct has no implicit padding.
    pub _padding: [u8; 3],
}

impl VaultConfig {
    pub const SEED: &'static [u8] = b"vault_config";

    /// Is `key` one of the authorized TEE signer pubkeys?
    pub fn is_authorized_tee(&self, key: &Address) -> bool {
        let n = (self.num_tee_keys as usize).min(MAX_TEE_KEYS);
        self.tee_pubkeys[..n].contains(key)
    }
}

/// One governed trading market. Asset identity and scaled-price parameters
/// live in their own PDA so VALID_MATCH_BATCH can bind every proof slot to one
/// unambiguous mint pair without making `VaultConfig` market-specific.
///
/// PDA seeds: `[b"market_config", base_mint, quote_mint]`.
#[account]
#[derive(Default)]
pub struct MarketConfig {
    pub base_mint: Address,
    pub quote_mint: Address,
    /// Fixed-point denominator in
    /// `quote_amount = floor(base_amount * clearing_price / price_scale)`.
    /// `price_scale` (+ the mint pair) IS proof-bound: `verify_match_batch`
    /// fans it in as a public input, so every active slot is pinned to it.
    pub price_scale: PodU64,
    // ── U-01: TEE/matcher-enforced only, NOT proof-bound ────────────────────
    // The three fields below are governance-set market rules the in-TEE matcher
    // honours, but they are NOT public inputs to VALID_MATCH_BATCH and not
    // bound into the leaf. `verify_match_batch` proof-enforces only market
    // identity (mint pair) + `price_scale` + conservation + the EXACT fee; it
    // does NOT check tick alignment, minimum size, or the circuit-breaker band.
    // A buggy/compromised authorized TEE could therefore clear off-tick, under
    // min size, or outside the breaker band and still produce a verifying
    // proof — the same trust class as uniform-price/oracle-band fairness (a
    // documented TEE-trusted non-goal; see CRYPTOGRAPHY.md). Do not describe
    // these as "on-chain-enforced market rules". Binding them would require a
    // lockstep circuit + VK + assembler change (deliberately not done).
    /// Smallest permitted price increment in scaled price units. TEE-enforced.
    pub tick_size: PodU64,
    /// Minimum order quantity in base-asset atomic units. TEE-enforced.
    pub min_order_size: PodU64,
    /// Max `|clearing_price - oracle_twap| / oracle_twap`, in bps. TEE-enforced.
    pub circuit_breaker_bps: PodU64,
    /// Snapshotted from the SPL mint accounts at initialization.
    pub base_decimals: u8,
    pub quote_decimals: u8,
    /// Governance kill switch. A disabled market must not accept new trading.
    pub enabled: PodBool,
    pub bump: u8,
}

impl MarketConfig {
    pub const SEED: &'static [u8] = b"market_config";
    pub const SPACE: usize = 8 + 32 + 32 + 8 + 8 + 8 + 8 + 1 + 1 + 1 + 1;
}

/// One Merkle-tree shard: an append-only incremental tree + its recent-root
/// ring. PDA seed `[b"merkle_tree", &[tree_id]]`. Sharding the tree across K of
/// these is what lets settles to different shards avoid the single-account
/// write-conflict that serialized them.
#[account]
pub struct MerkleTree {
    /// Leaves inserted into THIS shard. Monotonic; the per-shard insertion index.
    pub leaf_count: PodU64,
    /// Current Merkle root of this shard.
    pub current_root: [u8; 32],
    /// Ring buffer of the last `ROOT_HISTORY_SIZE` roots of this shard.
    pub roots: [[u8; 32]; ROOT_HISTORY_SIZE],
    /// Right-path nodes (the rightmost filled node at each level) for this shard.
    pub right_path: [[u8; 32]; MERKLE_DEPTH as usize],
    pub roots_head: u8,
    pub tree_id: u8,
    pub bump: u8,
    pub _padding: [u8; 5],
}

impl MerkleTree {
    pub const SEED: &'static [u8] = b"merkle_tree";

    /// Check whether a Merkle root appears in this shard's recent-roots ring.
    pub fn contains_root(&self, root: &[u8; 32]) -> bool {
        if &self.current_root == root {
            return true;
        }
        self.roots.iter().any(|r| r == root)
    }

    /// Push a new root into this shard's ring buffer, replacing the oldest entry.
    pub fn push_root(&mut self, root: [u8; 32]) {
        let idx = self.roots_head as usize;
        self.roots[idx] = self.current_root;
        self.roots_head = ((idx + 1) % ROOT_HISTORY_SIZE) as u8;
        self.current_root = root;
    }
}

/// PDA marking a note commitment that has already been DEPOSITED (S-05).
///
/// Existence => that exact commitment is already a leaf, so a second deposit of
/// it must be rejected.
///
/// Without this, two deposits sharing a commitment both moved tokens in and
/// both incremented `outstanding`, but only ONE could ever be withdrawn — the
/// second collides on the consume-once guard. The vault ends up permanently
/// over-collateralised (so no solvency alarm fires) and the user's second
/// deposit is silently unrecoverable.
///
/// That remains reachable through an exact retry or a malformed client even
/// though the ordinary SDK deposit API samples a fresh canonical recovery
/// nonce. The on-chain guard is therefore still load-bearing: client-side
/// uniqueness cannot replace consensus-enforced deposit-once semantics.
///
/// Binding the tree position into the commitment instead would make duplicates
/// impossible for free, but the leaf index is only known at execution time, so
/// any concurrent deposit would invalidate the proof. This account is the
/// version that does not trade liveness for it.
#[account]
pub struct DepositedNoteEntry {}

impl DepositedNoteEntry {
    pub const SEED: &'static [u8] = b"deposited_note";
    pub const SPACE: usize = 8;
}

/// PDA marking a note consumed, keyed by its NOTE-USE TAG.
///
/// The tag, not the commitment: the commitment is a public Merkle leaf, so
/// keying the consume guard on it republished the leaf's identity at every
/// spend and let an observer follow a note from deposit to withdrawal. The tag
/// is `Poseidon3(29, note_commitment, inner_hash)` and is unlinkable to the leaf
/// without the private inner. See crates/darkpool-crypto/src/note_use.rs.
///
/// EVERY consume path must key on the same handle — settle, withdraw and merge.
/// A path left on commitments would let one note be consumed once under each
/// scheme, which is a double-spend; that is why the migration lands atomically.
#[account]
pub struct ConsumedNoteEntry {}

impl ConsumedNoteEntry {
    pub const SEED: &'static [u8] = b"consumed_note";
    pub const SPACE: usize = 8;
}

/// PDA locking a note to a specific order. Automatically expires at `expiry_slot`.
///
/// The lock deliberately stores neither amount nor its note-use-tag PDA seed.
/// VALID_MATCH_BATCH proves conservation over private, range-checked amounts.
/// `token_mint` comes from VALID_INPUT public inputs, so it is bound to the
/// Merkle leaf and can safely bind settlement and continuation re-locks.
#[account]
pub struct NoteLock {
    pub token_mint: Address,
    pub order_id: [u8; 16],
    pub expiry_slot: PodU64,
    pub bump: u8,
    pub _padding: [u8; 7],
}

impl NoteLock {
    pub const SEED: &'static [u8] = b"note_lock";

    /// Exact current account size. A 136-byte lock cannot be decoded as this
    /// layout: the removed seed/tag occupied the bytes now read as `token_mint`.
    /// Every read path therefore checks this size and fails closed until the
    /// required development-state reset removes legacy locks.
    pub const SPACE: usize = 8 + core::mem::size_of::<Self>();

    /// Byte offset of `expiry_slot` in the account DATA (discriminator
    /// included): disc(8) + token_mint(32) + order_id(16).
    ///
    /// `note_lock_is_live` slices the raw account bytes at this offset, so a
    /// field reordering that moved `expiry_slot` would not fail to compile —
    /// it would silently start reading eight bytes of `token_mint` as a slot
    /// number and mis-classify every lock's liveness. The assertion below ties
    /// the constant to the real `#[repr(C)]` layout so that becomes a build
    /// error instead.
    pub const EXPIRY_SLOT_OFFSET: usize = 8 + 32 + 16;
}

/// Compile-time drift guard for [`NoteLock::EXPIRY_SLOT_OFFSET`].
///
/// `#[account]` implies `#[repr(C)]`, so `offset_of!` reports the
/// true in-memory (and therefore on-wire) position of the field. Adding the
/// 8-byte Anchor discriminator gives the offset within the account data.
const _: () = assert!(
    NoteLock::EXPIRY_SLOT_OFFSET == 8 + core::mem::offset_of!(NoteLock, expiry_slot),
    "NoteLock::EXPIRY_SLOT_OFFSET no longer matches the struct layout — \
     note_lock_is_live would read the wrong bytes"
);

/// Whether a `NoteLock` PDA is still EFFECTIVE — i.e. whether it should block
/// a spend of the note it pins (S-03).
///
/// `withdraw` and `merge` used to reject on the mere EXISTENCE of this account,
/// expired or not. `withdraw` even borrowed the data and threw it away
/// (`let _ = data;`) with a comment saying it was "safer to reject any
/// initialized lock and require the user to call `release_lock` first" — but
/// nothing in any shipped component could call `release_lock`, so a note left
/// locked by a failed settle was unspendable, unmergeable and unreleasable
/// through every available interface. `MAX_LOCK_TTL_SLOTS` was documented as a
/// bounded censorship window; in practice it was unbounded.
///
/// Reading the expiry the account already carries makes the window real again.
/// The comparison mirrors `release_lock`'s `clock.slot >= expiry_slot`: a lock
/// is dead AT its expiry, which is the CS-09 boundary settlement is required to
/// land strictly before.
///
/// Fails CLOSED — a program-owned account with the legacy/wrong size or
/// discriminator is treated as live rather than assumed absent.
pub fn note_lock_is_live(info: &AccountView, now_slot: u64) -> Result<bool> {
    if info.owner() != &crate::ID {
        return Ok(false); // no lock at all
    }
    let data = info.try_borrow()?;
    if data.len() != NoteLock::SPACE || &data[..8] != NoteLock::DISCRIMINATOR {
        // Program-owned but not the current lock layout: refuse to treat it as
        // absent. This includes the 136-byte compatibility layout.
        return Ok(true);
    }
    let end = NoteLock::EXPIRY_SLOT_OFFSET + 8;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[NoteLock::EXPIRY_SLOT_OFFSET..end]);
    Ok(now_slot < u64::from_le_bytes(buf))
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
    pub mint: Address,
    pub outstanding: PodU64,
    pub bump: u8,
}

impl OutstandingMint {
    pub const SEED: &'static [u8] = b"outstanding_mint";
    /// 8 disc + 32 mint + 8 outstanding + 1 bump.
    pub const SPACE: usize = 8 + 32 + 8 + 1;
}

// Batch validity is tracked by ONE `BatchValidityMarker` per batch, keyed by
// the batch's Merkle root — not by per-match markers.

/// BATCH validity marker. Written by `verify_match_batch` after
/// it verifies a single Groth16 proof attesting VALID_CREATE +
/// VALID_PRICE for ALL N matches in a batch. The proof's first of two public
/// inputs is a Merkle root over the per-slot leaves; the marker's PDA
/// is seeded by that same root. `tee_forced_settle` then takes a
/// Merkle inclusion proof per match, recomputes the leaf from the
/// settle payload, walks up to the root, and asserts the marker
/// exists at the derived PDA.
///
/// Replaces the per-match `ValidCreateMarker` + `ValidPriceMarker`
/// pair: one verify_match_batch tx covers an entire batch instead of
/// 2 × N marker-creating txs. Same TTL semantics + close-on-consume
/// lifecycle.
#[account]
#[derive(Default)]
pub struct BatchValidityMarker {
    /// Refund target on close.
    pub payer: Address,
    /// Slot past which this marker is stale and may be released.
    pub expiry_slot: PodU64,
    pub bump: u8,
}

impl BatchValidityMarker {
    pub const SEED: &'static [u8] = b"batch_validity";
    /// 8 disc + 32 payer + 8 expiry + 1 bump.
    pub const SPACE: usize = 8 + 32 + 8 + 1;
}

/// Same 300-slot (~2 min) ceiling as the per-match markers. A batch
/// marker is meant to be consumed by the N settle txs that follow it
/// in the same matcher cycle; longer TTL just lets stale state pile
/// up if a settle goes missing.
pub const MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS: u64 = 300;
