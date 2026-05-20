//! User Commitment (a.k.a. Wallet Commitment).
//!
//! Bind three of the four keys (root, spending, viewing) into a single 32-byte
//! identity — the user's shielded address. The Trading Key is *intentionally*
//! excluded so it can be rotated independently without burning the identity.
//!
//! Formula (must match `circuits/valid_wallet_create/circuit.circom`):
//!
//! Domain tags are prepended to every Poseidon call to prevent cross-role
//! second-preimage collisions. The tag values are fixed constants committed
//! in the circuit; any change here must be mirrored in the circuit and the
//! TS SDK.
//!
//! ```text
//!   DOMAIN_ROOT=10, DOMAIN_SPEND=11, DOMAIN_VIEW=12, DOMAIN_LEAF=13, DOMAIN_TOP=14
//!
//!   rootHash    = Poseidon4(DOMAIN_ROOT,  root_key_lo, root_key_hi, r0)
//!   spendHash   = Poseidon3(DOMAIN_SPEND, spending_key, r1)
//!   viewHash    = Poseidon3(DOMAIN_VIEW,  viewing_key,  r2)
//!   leafPair    = Poseidon3(DOMAIN_LEAF,  rootHash, spendHash)
//!   commitment  = Poseidon3(DOMAIN_TOP,   leafPair, viewHash)
//! ```
//!
//! Reference: Sections 4.4, 20.2, 23.2 of darkpool_protocol_spec_v3_changed.md

use crate::errors::CryptoError;
use crate::field::{pubkey_to_fr_pair, Fr};
use crate::poseidon::poseidon_hash;

/// Inputs needed to compute (or re-compute) a User Commitment.
///
/// Note the absence of `trading_key` — this is enforced at the type level to
/// guarantee `test_commitment_excludes_trading_key` always holds.
pub struct UserCommitmentInputs {
    /// Ed25519 pubkey of the Root / Vault Key (32 bytes).
    pub root_key_pubkey: [u8; 32],
    /// Shielded Spending Key as a BN254 scalar.
    pub spending_key: Fr,
    /// Master Viewing Key as a BN254 scalar.
    pub viewing_key: Fr,
    /// Per-leaf blinding factors r0, r1, r2.
    pub r0: Fr,
    pub r1: Fr,
    pub r2: Fr,
}

// Domain tag constants — must match circuit.circom DOMAIN_* literals exactly.
const DOMAIN_ROOT: u64 = 10;
const DOMAIN_SPEND: u64 = 11;
const DOMAIN_VIEW: u64 = 12;
const DOMAIN_LEAF: u64 = 13;
const DOMAIN_TOP: u64 = 14;

/// Compute the 32-byte User Commitment (big-endian).
pub fn user_commitment_from_keys(inputs: &UserCommitmentInputs) -> Result<Fr, CryptoError> {
    let [root_lo, root_hi] = pubkey_to_fr_pair(&inputs.root_key_pubkey);

    let root_hash = poseidon_hash(&[Fr::from(DOMAIN_ROOT), root_lo, root_hi, inputs.r0])?;
    let spend_hash = poseidon_hash(&[Fr::from(DOMAIN_SPEND), inputs.spending_key, inputs.r1])?;
    let view_hash = poseidon_hash(&[Fr::from(DOMAIN_VIEW), inputs.viewing_key, inputs.r2])?;
    let leaf_pair = poseidon_hash(&[Fr::from(DOMAIN_LEAF), root_hash, spend_hash])?;
    poseidon_hash(&[Fr::from(DOMAIN_TOP), leaf_pair, view_hash])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{
        derive_master_viewing_key, derive_spending_key, derive_trading_key_at_offset, MasterSeed,
    };
    use ed25519_dalek::SigningKey;

    fn inputs_from_seed(master: &MasterSeed, root_pub: [u8; 32]) -> UserCommitmentInputs {
        UserCommitmentInputs {
            root_key_pubkey: root_pub,
            spending_key: derive_spending_key(master).unwrap(),
            viewing_key: derive_master_viewing_key(master).unwrap(),
            r0: Fr::from(1u64),
            r1: Fr::from(2u64),
            r2: Fr::from(3u64),
        }
    }

    fn fixed_seed() -> MasterSeed {
        let mut b = [0u8; 64];
        for (i, s) in b.iter_mut().enumerate() {
            *s = i as u8;
        }
        MasterSeed::new(b)
    }

    #[test]
    fn user_commitment_deterministic() {
        let seed = fixed_seed();
        let root_pub = [7u8; 32];
        let c1 = user_commitment_from_keys(&inputs_from_seed(&seed, root_pub)).unwrap();
        let c2 = user_commitment_from_keys(&inputs_from_seed(&seed, root_pub)).unwrap();
        assert_eq!(c1, c2);
    }

    /// test_commitment_excludes_trading_key (Section 23.2.3):
    /// Changing the trading key offset must not alter the User Commitment.
    #[test]
    fn commitment_excludes_trading_key() {
        let seed = fixed_seed();
        let root_pub = [9u8; 32];

        let t0: SigningKey = derive_trading_key_at_offset(&seed, 0).unwrap();
        let t1: SigningKey = derive_trading_key_at_offset(&seed, 1).unwrap();
        let t9: SigningKey = derive_trading_key_at_offset(&seed, 999).unwrap();

        assert_ne!(t0.to_bytes(), t1.to_bytes());
        assert_ne!(t0.to_bytes(), t9.to_bytes());

        let c = user_commitment_from_keys(&inputs_from_seed(&seed, root_pub)).unwrap();

        // API-level invariant: `UserCommitmentInputs` does not accept a trading key.
        // Semantic invariant: even if we rotate trading key offsets, the commitment
        // stays the same because it only binds root/spending/viewing.
        for offset in [0u64, 1, 2, 42, 999] {
            let _rotated_trading = derive_trading_key_at_offset(&seed, offset).unwrap();
            let c_again = user_commitment_from_keys(&inputs_from_seed(&seed, root_pub)).unwrap();
            assert_eq!(
                c_again, c,
                "rotating trading offset {offset} must not change commitment"
            );
        }
    }

    #[test]
    fn commitment_changes_with_any_bound_key() {
        let seed = fixed_seed();
        let root_pub = [9u8; 32];
        let base = user_commitment_from_keys(&inputs_from_seed(&seed, root_pub)).unwrap();

        // Mutate root_key_pubkey.
        let mut m1 = inputs_from_seed(&seed, root_pub);
        m1.root_key_pubkey[0] ^= 0xff;
        assert_ne!(user_commitment_from_keys(&m1).unwrap(), base);

        // Mutate spending_key.
        let mut m2 = inputs_from_seed(&seed, root_pub);
        m2.spending_key += Fr::from(1u64);
        assert_ne!(user_commitment_from_keys(&m2).unwrap(), base);

        // Mutate viewing_key.
        let mut m3 = inputs_from_seed(&seed, root_pub);
        m3.viewing_key += Fr::from(1u64);
        assert_ne!(user_commitment_from_keys(&m3).unwrap(), base);

        // Mutate blinding factors.
        let mut m4 = inputs_from_seed(&seed, root_pub);
        m4.r0 = Fr::from(999u64);
        assert_ne!(user_commitment_from_keys(&m4).unwrap(), base);
    }
}
