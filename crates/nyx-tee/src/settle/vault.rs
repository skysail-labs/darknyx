//! Vault program — constants + PDA derivation helpers.
//!
//! Mirrors `programs/vault/src/lib.rs::declare_id!()` and the
//! `*::SEED` consts in `programs/vault/src/state.rs`. Hand-mirrored
//! the same way `packages/sdk/src/idl/seeds.ts` is hand-mirrored
//! from Rust — there's no IDL runtime in this crate, so any new
//! PDA in vault must add a parallel `*_pda` helper here.

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

/// Vault `NoteLock::SEED` — mirrors `programs/vault/src/state.rs::NoteLock::SEED`.
pub const NOTE_LOCK_SEED: &[u8] = b"note_lock";

/// Vault `ConsumedNoteEntry::SEED` — mirrors `programs/vault/src/state.rs`.
pub const CONSUMED_NOTE_SEED: &[u8] = b"consumed_note";

/// Vault `NullifierEntry::SEED` — mirrors `programs/vault/src/state.rs`.
pub const NULLIFIER_SEED: &[u8] = b"nullifier";

/// Vault `BatchValidityMarker::SEED` — mirrors `programs/vault/src/state.rs`.
pub const BATCH_VALIDITY_SEED: &[u8] = b"batch_validity";

/// Parse the program id once. Cheap — pure deterministic base58
/// decode — but no point doing it on every ix build. Callers go
/// through this fn so the eventual `LazyLock` switch (if it pays
/// off) is a one-spot change.
pub fn vault_program_id() -> Address {
    VAULT_PROGRAM_ID_BASE58
        .parse()
        .expect("VAULT_PROGRAM_ID_BASE58 is a valid base58 pubkey")
}

/// PDA: `vault_config`. Seeds = `[b"vault_config"]`. Returns
/// `(address, bump)`. There's exactly one `VaultConfig` PDA per
/// program, so the result is stable across calls.
pub fn vault_config_pda() -> (Address, u8) {
    Address::find_program_address(&[VAULT_CONFIG_SEED], &vault_program_id())
}

/// PDA: `note_lock` for the given note commitment. Seeds =
/// `[b"note_lock", note_commitment]`. One per note.
pub fn note_lock_pda(note_commitment: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[NOTE_LOCK_SEED, note_commitment], &vault_program_id())
}

/// PDA: `consumed_note` for a settle-consumed note commitment.
/// Seeds = `[b"consumed_note", note_commitment]`. Allocation locks
/// out a second settle of the same note (replay protection).
pub fn consumed_note_pda(note_commitment: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[CONSUMED_NOTE_SEED, note_commitment], &vault_program_id())
}

/// PDA: `nullifier` entry. Seeds = `[b"nullifier", nullifier]`.
pub fn nullifier_pda(nullifier: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[NULLIFIER_SEED, nullifier], &vault_program_id())
}

/// PDA: `batch_validity` marker. Seeds = `[b"batch_validity",
/// merkle_root]`. One per batch — keyed by the batch Merkle root,
/// so every match in the batch resolves the SAME marker.
pub fn batch_validity_marker_pda(merkle_root: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[BATCH_VALIDITY_SEED, merkle_root], &vault_program_id())
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
        let pid = vault_program_id();
        assert_eq!(pid.to_string(), VAULT_PROGRAM_ID_BASE58);
    }

    #[test]
    fn vault_config_pda_is_deterministic() {
        let (a, ba) = vault_config_pda();
        let (b, bb) = vault_config_pda();
        assert_eq!(a, b);
        assert_eq!(ba, bb);
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
