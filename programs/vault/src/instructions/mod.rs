// v2 `#[derive(Accounts)]` binds EVERY `#[instruction(...)]` argument in its
// generated `try_accounts`, but only reads the ones a constraint or seed
// mentions there — so the rest warn as unused even when they are demonstrably
// used. `release_lock`'s `note_use_tag`, for instance, warns while appearing in
// `seeds = [NoteLock::SEED, note_use_tag.as_ref()]` two lines below.
//
// Suppressed at the MODULE, because that is the only placement that reaches the
// derive's generated impl: an `#[allow]` on the struct does not, and renaming to
// `_note_use_tag` would silence it only by making every seed expression claim
// the value is unused, which is the opposite of true.
#[allow(unused_variables)]
pub mod close_batch_validity_marker;
// NOTE (Anchor v2): these two modules are NOT `#[cfg]`-gated, while the
// `#[program]` fns that expose them still are. That is forced by a v2 macro
// defect: `#[program]` emits `pub use __client_accounts_<name>::…` for every
// instruction WITHOUT propagating the instruction's own `#[cfg]`, so gating the
// module breaks the featureless (mainnet) build with an unresolved import.
//
// The audited property (audit_1 F-01/F-02 — a mainnet build ships neither
// devnet backdoor) is preserved and is now ASSERTED rather than assumed: with
// the `#[program]` fn gated out there is no dispatch arm and no discriminator,
// and `mainnet_build_has_no_devnet_admin_discriminators` checks the built .so
// for both discriminators directly. That is a stronger guarantee than the cfg
// alone gave, because it tests the artifact instead of the source.
pub mod close_vault_config;
#[allow(unused_variables)]
pub mod create_wallet;
#[allow(unused_variables)]
pub mod deposit;
#[allow(unused_variables)]
pub mod initialize;
pub mod initialize_market;
#[allow(unused_variables)]
pub mod initialize_tree;
#[allow(unused_variables)]
pub mod lock_note;
#[allow(unused_variables)]
pub mod merge;
#[allow(unused_variables)]
pub mod release_lock;
#[allow(unused_variables)]
pub mod reset_merkle_tree;
pub mod rotate_root_key;
pub mod set_protocol_config;
pub mod set_tee_pubkey;
pub mod tee_forced_settle;
#[allow(unused_variables)]
pub mod tee_forced_settle_batched;
pub mod update_market_config;
#[allow(unused_variables)]
pub mod verify_match_batch;
#[allow(unused_variables)]
pub mod withdraw;

// Re-export every item from each instruction module, including the hidden
// `__client_accounts_*` modules Anchor's `#[derive(Accounts)]` macro generates.
// The program macro resolves them at `crate::<module>::__client_accounts_*`.
pub use close_batch_validity_marker::*;
#[cfg(feature = "devnet-admin")]
pub use close_vault_config::*;
pub use create_wallet::*;
pub use deposit::*;
pub use initialize::*;
pub use initialize_market::*;
pub use initialize_tree::*;
pub use lock_note::*;
pub use merge::*;
pub use release_lock::*;
#[cfg(feature = "devnet-admin")]
pub use reset_merkle_tree::*;
pub use rotate_root_key::*;
pub use set_protocol_config::*;
pub use set_tee_pubkey::*;
pub use tee_forced_settle::*;
pub use tee_forced_settle_batched::*;
pub use update_market_config::*;
pub use verify_match_batch::*;
pub use withdraw::*;
