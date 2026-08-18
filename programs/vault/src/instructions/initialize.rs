use crate::errors::VaultError;
use crate::merkle::compute_zero_subtree_roots;
use crate::state::*;
use anchor_lang::prelude::*;
use core::mem::size_of;

/// Initialize accounts — **mainnet** build (default; no `devnet-admin` feature).
///
/// F-03: the initializer is bound to the program's **upgrade authority**, so a
/// third party cannot front-run `initialize` on a freshly deployed program and
/// install themselves as `admin`. `program.programdata_address()` proves the
/// Upgrade-authority binding for the MAINNET `initialize`.
///
/// Anchor v1 gave this for free: `Account<ProgramData>` plus
/// `program.programdata_address()`. **v2 removed both** — there is no
/// `ProgramData` account type and no `programdata_address()` — so the check is
/// reimplemented here against the raw account.
///
/// `UpgradeableLoaderState::ProgramData` is bincode-encoded:
///
/// ```text
///   [0..4)   u32 LE enum tag, 3 = ProgramData
///   [4..12)  u64 LE deployed slot
///   [12]     Option tag, 0 = None, 1 = Some
///   [13..45) upgrade authority pubkey, present only when the tag is 1
/// ```
///
/// Every step is checked, because a permissive parse here would let anyone
/// initialize a fresh mainnet deploy:
///   1. the account is the canonical ProgramData PDA for THIS program,
///   2. it is owned by the upgradeable loader (not a look-alike someone funded),
///   3. the enum tag really is ProgramData,
///   4. an authority is actually set (`None` = immutable ⇒ nobody may pass),
///   5. that authority equals the signer.
#[cfg(not(feature = "devnet-admin"))]
const PROGRAM_DATA_TAG: u32 = 3;
#[cfg(not(feature = "devnet-admin"))]
const AUTHORITY_OFFSET: usize = 13;
#[cfg(not(feature = "devnet-admin"))]
const PROGRAM_DATA_HEADER_LEN: usize = AUTHORITY_OFFSET + 32;

#[cfg(not(feature = "devnet-admin"))]
fn upgrade_authority_matches(program_data: &UncheckedAccount, signer: &Address) -> bool {
    let (expected_pda, _) = Address::find_program_address(
        &[crate::ID.as_ref()],
        &solana_sdk_ids::bpf_loader_upgradeable::ID,
    );
    let view = program_data.account();
    if view.address() != &expected_pda {
        return false;
    }
    if view.owner() != &solana_sdk_ids::bpf_loader_upgradeable::ID {
        return false;
    }
    let Ok(data) = view.try_borrow() else {
        return false;
    };
    parse_upgrade_authority(&data).is_some_and(|a| &a == signer)
}

/// Split out from the account plumbing so the byte handling is unit-testable —
/// this is a security check implemented by offset arithmetic, which is exactly
/// the kind of code that should not be trusted on inspection alone.
#[cfg(not(feature = "devnet-admin"))]
fn parse_upgrade_authority(data: &[u8]) -> Option<Address> {
    if data.len() < PROGRAM_DATA_HEADER_LEN {
        return None;
    }
    let tag = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if tag != PROGRAM_DATA_TAG {
        return None;
    }
    // 0 = None: the program is immutable, so there is no authority to match and
    // NOBODY should pass this check.
    if data[12] != 1 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[AUTHORITY_OFFSET..PROGRAM_DATA_HEADER_LEN]);
    Some(Address::from(key))
}

/// supplied `program_data` really is *this* program's loader data, and its
/// `upgrade_authority_address` must equal the `upgrade_authority` signer. The
/// signer supplies a distinct `operations_admin` argument stored in
/// `VaultConfig`, enabling separate cold upgrade/root and operations quorums.
///
/// The dev/test/devnet build (`devnet-admin` feature, below) uses a plain
/// initializer signer instead: front-running isn't a threat where we control the
/// deploy, and the litesvm harness loads the program non-upgradeably (there is
/// no ProgramData account to bind against). This mirrors the F-01/F-02 gate —
/// the mainnet artifact carries the guard, the dev artifact stays testable.
#[cfg(not(feature = "devnet-admin"))]
#[derive(Accounts)]
#[instruction(operations_admin: Address, tee_pubkeys: Vec<Address>, root_key: Address, num_trees: u8)]
pub struct Initialize {
    #[account(mut)]
    pub upgrade_authority: Signer,

    #[account(
        init,
        payer = upgrade_authority,
        space = 8 + size_of::<VaultConfig>(),
        seeds = [VaultConfig::SEED],
        bump,
    )]
    pub vault_config: Account<VaultConfig>,

    /// The upgradeable-loader ProgramData for THIS program. Its upgrade
    /// authority must be the `upgrade_authority` signer.
    ///
    /// v2 removed both `Account<ProgramData>` and `programdata_address()`, so
    /// the account is taken raw and `upgrade_authority_matches` does the whole
    /// job — PDA identity, loader ownership, enum tag, and the authority
    /// comparison. The separate `program` account the v1 form needed is gone
    /// with it: the PDA is derived from `crate::ID` directly, so passing a
    /// different program's ProgramData no longer type-checks past step 1.
    ///
    /// CHECK: fully validated by `upgrade_authority_matches` below.
    #[account(
        constraint = upgrade_authority_matches(&program_data, upgrade_authority.address())
            @ VaultError::Unauthorized,
    )]
    pub program_data: UncheckedAccount,

    pub system_program: Program<System>,
}

/// Initialize accounts — dev/test/devnet build (`devnet-admin`). Plain
/// initializer signer, no upgrade-authority binding (see mainnet above).
#[cfg(feature = "devnet-admin")]
#[derive(Accounts)]
pub struct Initialize {
    #[account(mut)]
    pub upgrade_authority: Signer,

    #[account(
        init,
        payer = upgrade_authority,
        space = 8 + size_of::<VaultConfig>(),
        seeds = [VaultConfig::SEED],
        bump,
    )]
    pub vault_config: Account<VaultConfig>,

    pub system_program: Program<System>,
}

/// Initialize the GLOBAL vault config. The per-shard Merkle trees are created
/// separately (`initialize_tree`, one per shard id). Initialization installs the
/// full one-key-per-shard TEE set atomically and records a possibly distinct
/// operations admin; no default-key or partial-shard bootstrap is accepted.
pub fn initialize_handler(
    ctx: &mut Context<Initialize>,
    operations_admin: Address,
    tee_pubkeys: Vec<Address>,
    root_key: Address,
    num_trees: u8,
) -> Result<()> {
    require!(
        (1..=MAX_TREES).contains(&num_trees),
        VaultError::InvalidTreeCount
    );
    require!(
        operations_admin != Address::default(),
        VaultError::InvalidAdminKey
    );
    require!(root_key != Address::default(), VaultError::InvalidRootKey);
    require!(operations_admin != root_key, VaultError::InvalidAdminKey);
    #[cfg(not(feature = "devnet-admin"))]
    require!(
        operations_admin != *ctx.accounts.upgrade_authority.address(),
        VaultError::InvalidAdminKey
    );
    require!(
        tee_pubkeys.len() == num_trees as usize && tee_pubkeys.len() <= MAX_TEE_KEYS,
        VaultError::InvalidKeyCount
    );
    for (i, key) in tee_pubkeys.iter().enumerate() {
        require!(
            *key != Address::default() && *key != operations_admin && *key != root_key,
            VaultError::InvalidTeeKey
        );
        require!(!tee_pubkeys[..i].contains(key), VaultError::InvalidTeeKey);
    }
    let cfg = &mut ctx.accounts.vault_config;

    cfg.admin = operations_admin;
    cfg.tee_pubkeys = [Address::default(); MAX_TEE_KEYS];
    for (slot, key) in cfg.tee_pubkeys.iter_mut().zip(tee_pubkeys.iter()) {
        *slot = *key;
    }
    cfg.num_tee_keys = tee_pubkeys.len() as u8;
    cfg.root_key = root_key;
    cfg.num_trees = num_trees;
    cfg.zero_subtree_roots = compute_zero_subtree_roots()?;
    cfg.bump = ctx.bumps.vault_config;
    cfg.protocol_owner_commitment = [0u8; 32];
    cfg.fee_rate_bps = 0u16.into();
    cfg._padding = [0u8; 3];
    let _ = VaultError::ZeroAmount; // keep errors linked in
    Ok(())
}

#[cfg(all(test, not(feature = "devnet-admin"), not(target_os = "solana")))]
mod upgrade_authority_tests {
    use super::*;

    /// Build a well-formed `UpgradeableLoaderState::ProgramData` header.
    fn program_data_bytes(authority: Option<[u8; 32]>) -> Vec<u8> {
        let mut v = Vec::with_capacity(PROGRAM_DATA_HEADER_LEN);
        v.extend_from_slice(&PROGRAM_DATA_TAG.to_le_bytes());
        v.extend_from_slice(&7u64.to_le_bytes()); // deployed slot, unused here
        match authority {
            Some(k) => {
                v.push(1);
                v.extend_from_slice(&k);
            }
            None => {
                v.push(0);
                v.extend_from_slice(&[0u8; 32]);
            }
        }
        v
    }

    #[test]
    fn accepts_a_well_formed_authority() {
        let key = [0x42u8; 32];
        let parsed = parse_upgrade_authority(&program_data_bytes(Some(key)));
        assert_eq!(parsed, Some(Address::from(key)));
    }

    #[test]
    fn rejects_an_immutable_program() {
        // Option tag 0 = no upgrade authority. v1's `Some(x) == Some(y)`
        // comparison could never match None either, and neither may this: an
        // immutable program has no authority, so NOBODY should pass.
        assert_eq!(parse_upgrade_authority(&program_data_bytes(None)), None);
    }

    #[test]
    fn rejects_a_wrong_enum_tag() {
        // Tag 2 is `Program`, not `ProgramData`. Accepting it would read a
        // different account shape at these offsets and yield a bogus key.
        let mut b = program_data_bytes(Some([0x11; 32]));
        b[0] = 2;
        assert_eq!(parse_upgrade_authority(&b), None);
    }

    #[test]
    fn rejects_short_data() {
        // A truncated account must fail closed rather than index out of bounds
        // or read whatever follows in the buffer.
        let full = program_data_bytes(Some([0x33; 32]));
        for len in 0..full.len() {
            assert_eq!(
                parse_upgrade_authority(&full[..len]),
                None,
                "a {len}-byte account must not parse"
            );
        }
        assert!(parse_upgrade_authority(&full).is_some());
    }

    #[test]
    fn reads_the_authority_from_the_right_offset() {
        // Guards the offset arithmetic itself. Two things matter, and only one
        // of them is obvious.
        //
        // (1) Every assertion compares against `key` - the value we PUT IN -
        //     never against another call to the parser. An earlier version
        //     compared `parse(&mutated)` with `parse(&clean)`, which is stable
        //     under ANY consistent shift of AUTHORITY_OFFSET: both sides move
        //     together, so the test passed while the window was wrong.
        //     Mutation-checked: anchored on `key`, AUTHORITY_OFFSET 13 -> 12
        //     FAILS this test; compared against another parse, it passed.
        //
        // (2) The mutated byte must be one the helper does not already set to
        //     that value. Writing 1 at AUTHORITY_OFFSET - 1 hits the Option tag,
        //     which `program_data_bytes(Some(_))` already sets to 1 - a no-op
        //     mutation. Flip a deployed-slot byte instead (slot occupies 4..12),
        //     which keeps the encoding valid.
        let key = [0x5Au8; 32];
        let expected = Address::from(key);
        assert_eq!(
            parse_upgrade_authority(&program_data_bytes(Some(key))),
            Some(expected),
            "a clean header must parse to exactly the key that was written"
        );
        let mut b = program_data_bytes(Some(key));
        b[AUTHORITY_OFFSET - 2] ^= 0xFF; // a deployed-slot byte, before the key
        assert_eq!(parse_upgrade_authority(&b), Some(expected));
        let mut c = program_data_bytes(Some(key));
        c.push(0xFF); // trailing bytes beyond the header are ignored
        assert_eq!(parse_upgrade_authority(&c), Some(expected));
    }
}
