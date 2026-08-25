//! Role tags for the six note roles produced by a match.
//!
//! # What lives here now
//!
//! Only the role BYTES. They are consumed by VALID_MATCH_BATCH v3's Poseidon
//! derivations — user outputs are `Poseidon3(24, consumed_input_inner, role)`
//! and fee outputs are `Poseidon4(36, epoch_key, consumed_use_tag, role)` — so
//! the tags themselves are still very much live protocol constants.
//!
//! # What was removed (audit 2026-07-25, S-06)
//!
//! This module used to also export `derive_inner(match_id, role)`, a SHA-256
//! construction (`SHA256("darknyx-change-inner-v2" || match_id_le || role)`,
//! Fr-masked) that was the v2 way of deriving a note's `inner_hash`. CS-03
//! replaced it: outputs now derive from the CONSUMED INPUT rather than from a
//! match identifier, which is what removed caller-selected output randomness.
//!
//! The helper survived that migration with a full cross-language KAT still
//! green, which is precisely the failure shape the 2026-07-14 pass warned
//! about — a parity suite validating a retired construction against itself
//! while the live path used something else. `run_batch` was still calling it to
//! fill `note_e_commitment`/`note_f_commitment` with values the chain would
//! never create; the settle assembler overwrote them, but only when its own
//! Poseidon derivation succeeded, so an error there let the stale SHA value
//! through. It was also exported from the SDK's public index, where a consumer
//! following it would compute a commitment absent from the tree and see their
//! balance silently under-report.
//!
//! Change-note inners are now derived exclusively by
//! `darkpool_crypto::match_output::match_output_inner_hash`.

/// Role tag for the buyer's change note (`note_e`).
pub const CHANGE_ROLE_BUYER: u8 = 0xB1;
/// Role tag for the seller's change note (`note_f`).
pub const CHANGE_ROLE_SELLER: u8 = 0x5E;

// ─── Trade-output + fee note roles ───────────────────────────────────────────

/// Role tag for the buyer's full-fill output note (`note_c`).
pub const TRADE_ROLE_BUYER: u8 = 0xC1;
/// Role tag for the seller's full-fill output note (`note_d`).
pub const TRADE_ROLE_SELLER: u8 = 0xD1;
/// Role tag for a base-asset protocol fee note.
pub const FEE_ROLE_BASE: u8 = 0xFB;
/// Role tag for a quote-asset protocol fee note.
pub const FEE_ROLE_QUOTE: u8 = 0xFC;
