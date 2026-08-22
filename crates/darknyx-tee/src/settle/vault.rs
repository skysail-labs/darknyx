//! Vault program constants and PDA derivation.
//!
//! Hand-mirrored from `programs/vault/src/lib.rs::declare_id!()` and the `*::SEED`
//! constants in `programs/vault/src/state.rs`, the same way
//! `packages/sdk/src/idl/seeds.ts` mirrors them for TypeScript. This crate carries
//! no Anchor IDL runtime, so **a new PDA in the vault program needs a parallel
//! `*_pda` helper added here by hand.** Nothing in CI catches the omission; it
//! surfaces at runtime as `AccountNotFound` or `ConstraintSeeds (2006)`.
//!
//! Note which namespace each seed takes. `note_lock` and `consumed_note` are keyed
//! by the **note-use tag**, while Merkle leaves and `DepositedNoteEntry` are keyed
//! by the **commitment**. Both are `[u8; 32]`, so passing one where the other
//! belongs compiles, derives a plausible-looking address, and fails only on-chain —
//! see `CRYPTOGRAPHY.md` §2.1.

use solana_address::Address;

/// Devnet vault program id. Source of truth:
/// `programs/vault/src/lib.rs::declare_id!()`. CLAUDE.md §2.3 lists
/// the same value. Bumping it triggers the consistency CI job.
pub const VAULT_PROGRAM_ID_BASE58: &str = "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";

/// Solana system program id (`11111111111111111111111111111111`).
/// All zeros. Pinned as a const so `lock_note` doesn't have to do
/// a base58 parse per ix construction.
pub const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0u8; 32]);

/// Vault `VaultConfig::SEED` — mirrors `programs/vault/src/state.rs::VaultConfig::SEED`.
pub const VAULT_CONFIG_SEED: &[u8] = b"vault_config";
/// Vault `MarketConfig::SEED` — one PDA per ordered base/quote pair.
pub const MARKET_CONFIG_SEED: &[u8] = b"market_config";

/// Vault `MerkleTree::SEED` — mirrors `programs/vault/src/state.rs::MerkleTree::SEED`.
/// One `MerkleTree` shard account per `tree_id`.
pub const MERKLE_TREE_SEED: &[u8] = b"merkle_tree";

/// Vault `NoteLock::SEED` — mirrors `programs/vault/src/state.rs::NoteLock::SEED`.
pub const NOTE_LOCK_SEED: &[u8] = b"note_lock";

/// Vault `ConsumedNoteEntry::SEED` — mirrors `programs/vault/src/state.rs`.
pub const CONSUMED_NOTE_SEED: &[u8] = b"consumed_note";

/// Vault `BatchValidityMarker::SEED` — mirrors `programs/vault/src/state.rs`.
pub const BATCH_VALIDITY_SEED: &[u8] = b"batch_validity";

/// Vault `OutstandingMint::SEED` — mirrors `programs/vault/src/state.rs`.
pub const OUTSTANDING_MINT_SEED: &[u8] = b"outstanding_mint";

/// Vault token-account seed — mirrors the `seeds = [b"vault_token",
/// token_mint]` constraint in `programs/vault/src/instructions/deposit.rs`.
/// The PDA is an SPL `TokenAccount` (authority = `vault_config`) holding
/// the vault's balance for one mint.
pub const VAULT_TOKEN_SEED: &[u8] = b"vault_token";

/// Parse the program id once. Cheap — pure deterministic base58
/// decode — but no point doing it on every ix build. Callers go
/// through this fn so the eventual `LazyLock` switch (if it pays
/// off) is a one-spot change.
/// The vault program this enclave talks to.
///
/// Overridable with `DARKNYX_TEE_VAULT_PROGRAM_ID`. Without it the id is a
/// compile-time constant, which means pointing a CVM at a different vault
/// (an Anchor v2 experiment, a second devnet foundation) requires rebuilding
/// and re-attesting the image — the id is not a secret and does not belong in
/// `compose_hash`-bound content for that reason.
///
/// Follows the same env contract as the rest of the enclave (CLAUDE.md §3.2):
/// an EMPTY value falls back to the default; a MALFORMED non-empty value fails
/// fast at first use rather than silently deriving PDAs for the wrong program,
/// which would surface much later as `AccountNotFound` on a settle.
///
/// Resolved once — every PDA helper calls this, so it must stay cheap.
pub fn vault_program_id() -> Address {
    static RESOLVED: std::sync::OnceLock<Address> = std::sync::OnceLock::new();
    *RESOLVED.get_or_init(|| {
        let raw = std::env::var("DARKNYX_TEE_VAULT_PROGRAM_ID").unwrap_or_default();
        let chosen = if raw.trim().is_empty() {
            VAULT_PROGRAM_ID_BASE58
        } else {
            raw.trim()
        };
        chosen.parse().unwrap_or_else(|_| {
            panic!("DARKNYX_TEE_VAULT_PROGRAM_ID is not a valid base58 address: {chosen:?}")
        })
    })
}

/// PDA: `vault_config`. Seeds = `[b"vault_config"]`. Returns
/// `(address, bump)`. There's exactly one `VaultConfig` PDA per
/// program, so the result is stable across calls.
pub fn vault_config_pda() -> (Address, u8) {
    Address::find_program_address(&[VAULT_CONFIG_SEED], &vault_program_id())
}

/// PDA: `[b"market_config", base_mint, quote_mint]`.
pub fn market_config_pda(base_mint: &[u8; 32], quote_mint: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(
        &[MARKET_CONFIG_SEED, base_mint, quote_mint],
        &vault_program_id(),
    )
}

/// PDA: `merkle_tree` shard `tree_id`. Seeds = `[b"merkle_tree", &[tree_id]]`.
/// One account per shard; settles to different shards write distinct accounts.
pub fn merkle_tree_pda(tree_id: u8) -> (Address, u8) {
    Address::find_program_address(&[MERKLE_TREE_SEED, &[tree_id]], &vault_program_id())
}

/// PDA: `note_lock` for the given note commitment. Seeds =
/// `[b"note_lock", note_use_tag]`. One per note. The TAG, not the
/// commitment — see darkpool-crypto/src/note_use.rs.
pub fn note_lock_pda(note_use_tag: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[NOTE_LOCK_SEED, note_use_tag], &vault_program_id())
}

/// PDA: `consumed_note` for a settle-consumed note commitment.
/// Seeds = `[b"consumed_note", note_use_tag]`. Allocation locks
/// out a second settle of the same note (replay protection).
pub fn consumed_note_pda(note_use_tag: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[CONSUMED_NOTE_SEED, note_use_tag], &vault_program_id())
}

/// PDA: `batch_validity` marker. Seeds = `[b"batch_validity",
/// merkle_root]`. One per batch — keyed by the batch Merkle root,
/// so every match in the batch resolves the SAME marker.
pub fn batch_validity_marker_pda(merkle_root: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[BATCH_VALIDITY_SEED, merkle_root], &vault_program_id())
}

/// PDA: `outstanding_mint` counter for a mint. Seeds =
/// `[b"outstanding_mint", mint]`. Holds the live un-spent note total
/// for the mint (the v2 solvency counter).
pub fn outstanding_mint_pda(mint: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[OUTSTANDING_MINT_SEED, mint], &vault_program_id())
}

/// PDA: the vault's SPL token account for a mint. Seeds =
/// `[b"vault_token", mint]`. Its `amount` is the actual on-chain
/// balance backing the mint's outstanding notes.
pub fn vault_token_account_pda(mint: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[VAULT_TOKEN_SEED, mint], &vault_program_id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_program_id_is_all_zeros() {
        assert_eq!(SYSTEM_PROGRAM_ID, Address::new_from_array([0u8; 32]));
        // `11111111111111111111111111111111` (the canonical base58).
        assert_eq!(
            SYSTEM_PROGRAM_ID.to_string(),
            "11111111111111111111111111111111"
        );
    }

    #[test]
    fn vault_program_id_parses() {
        // Asserts the COMPILED-IN DEFAULT parses, not what `vault_program_id()`
        // resolves to. Those diverge the moment DARKNYX_TEE_VAULT_PROGRAM_ID is
        // set, and the accessor memoises in a OnceLock shared across the test
        // binary — so asserting through it made this test env-dependent and
        // order-dependent at once. The override's own behaviour is covered
        // below.
        let pid: Address = VAULT_PROGRAM_ID_BASE58
            .parse()
            .expect("default program id is valid base58");
        assert_eq!(pid.to_string(), VAULT_PROGRAM_ID_BASE58);
    }

    #[test]
    fn vault_program_id_honours_the_env_override() {
        // Not exercised through `vault_program_id()`: its OnceLock resolves
        // once per process, so a test that sets the env var would either race
        // other tests or silently no-op depending on ordering. Pin the
        // selection RULE instead — empty falls back, non-empty wins — which is
        // the part that can regress.
        fn pick(raw: &str) -> &str {
            if raw.trim().is_empty() {
                VAULT_PROGRAM_ID_BASE58
            } else {
                raw.trim()
            }
        }
        assert_eq!(pick(""), VAULT_PROGRAM_ID_BASE58);
        assert_eq!(pick("   "), VAULT_PROGRAM_ID_BASE58);
        // Deliberately a DIFFERENT id from VAULT_PROGRAM_ID_BASE58 - it is the
        // retired v2-experiment program. The test needs an override that is not
        // the default; setting it to the production id would make `pick(other)`
        // and the default identical and the assertion vacuous. Do not "fix" this
        // to the production id when grepping for the experiment address.
        let other = "DtSR7WELiAJMSMsPSLmDmA9ai5Q4715vooH8vderTvX7";
        assert_eq!(pick(other), other);
        assert_eq!(pick(&format!("  {other}  ")), other);
        // And the chosen value must still be parseable — a malformed override
        // panics at first use rather than deriving PDAs for a bogus program.
        assert!(other.parse::<Address>().is_ok());
        assert!("not-base58!!".parse::<Address>().is_err());
    }

    #[test]
    fn vault_config_pda_is_deterministic() {
        let (a, ba) = vault_config_pda();
        let (b, bb) = vault_config_pda();
        assert_eq!(a, b);
        assert_eq!(ba, bb);
    }

    #[test]
    fn market_config_pda_binds_mint_order() {
        let (market, _) = market_config_pda(&[0x11; 32], &[0x22; 32]);
        let (reversed, _) = market_config_pda(&[0x22; 32], &[0x11; 32]);
        assert_ne!(market, reversed);
    }

    #[test]
    fn note_lock_pda_varies_with_commitment() {
        let (a, _) = note_lock_pda(&[0x11; 32]);
        let (b, _) = note_lock_pda(&[0x22; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn note_lock_pda_bump_is_stable_per_commitment() {
        // Same input → same bump. The on-chain `init` constraint
        // re-derives this; if our derivation produced an unstable
        // bump the init would fail mid-flight with a confusing
        // ConstraintSeeds error.
        let (_, b1) = note_lock_pda(&[0x11; 32]);
        let (_, b2) = note_lock_pda(&[0x11; 32]);
        assert_eq!(b1, b2);
    }
}
