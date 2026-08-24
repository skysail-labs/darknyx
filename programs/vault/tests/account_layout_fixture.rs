//! A-3 — emit ONE account-layout fixture derived from the real vault structs,
//! so the hand-written offsets in the TEE and the SDK cannot agree with their
//! own literals while disagreeing with the program.
//!
//! ## The gap this closes
//!
//! `VaultConfig`, `MerkleTree`, `MarketConfig`, `NoteLock`, and
//! `BatchValidityMarker` are all parsed by byte offset in at least two places
//! outside this crate:
//!
//! * `crates/darknyx-tee/src/solana_rpc/vault_config.rs`
//! * `crates/darknyx-tee/src/solana_rpc/market_config.rs`
//! * `crates/darknyx-tee/src/merkle/sync.rs`
//! * `crates/darknyx-tee/src/settle/{marker_sweep,lock_sweep}.rs`
//! * `packages/sdk/src/tee/vault-config.ts`
//!
//! Each of those held its own hand-computed constants, and where a test existed
//! it asserted a literal against a literal — the TEE's test read
//! `assert_eq!(FEE_RATE_BPS_OFFSET, 1256)`, which is true of the constant and
//! says nothing about the struct. Insert a field into `VaultConfig` and every
//! one of those files stays internally consistent, stays green, and reads the
//! wrong bytes off a real account. The SDK was worse: `1258`, `1259`, `1264`
//! appeared as bare literals with nothing checking them at all.
//!
//! ## Why a fixture rather than a shared constant
//!
//! The consumers are a different crate (which deliberately does not depend on
//! `vault`) and a different language. A generated fixture is the only artifact
//! all three can compare against. It is committed, so a layout change shows up
//! as a reviewable diff rather than a silent recomputation.
//!
//! ## How the offsets are derived
//!
//! * `#[account(zero_copy)]` implies `#[repr(C)]`, so `offset_of!` reports the
//!   true in-memory — and therefore on-wire — position. Add 8 for the Anchor
//!   discriminator.
//! * `#[account]` is Borsh. Its layout is **not** `repr(C)`, so `offset_of!`
//!   would be meaningless. For those, offsets are accumulated from field sizes
//!   in declaration order and then **verified by probe**: an instance is built
//!   with a sentinel in one field, serialized, and the sentinel must land at the
//!   recorded offset. A field inserted or reordered moves the sentinel and fails.
//!
//! Regenerate with `UPDATE_LAYOUT_FIXTURE=1 cargo test -p vault --test
//! account_layout_fixture`, and commit the diff in the same change as the
//! struct edit.

use std::fs;
use std::path::PathBuf;

// v2: accounts are Pod, so the on-wire bytes are the struct's own repr(C)
// image rather than a borsh encoding. `bytemuck::bytes_of` reads exactly those
// bytes, which is what makes this fixture a LAYOUT check under both models --
// and therefore the thing that proves v1 and v2 agree byte for byte.
use anchor_lang::prelude::{Address as Pubkey, Rent};
use anchor_lang::{AccountDeserialize, Discriminator};
use bytemuck::Pod;
use vault::state::{
    BatchValidityMarker, ConsumedNoteEntry, DepositedNoteEntry, MarketConfig, MerkleTree, NoteLock,
    OutstandingMint, VaultConfig, MERKLE_DEPTH, ROOT_HISTORY_SIZE,
};

const DISC: usize = 8;

fn fixture_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("account-layout.json");
    p
}

/// One `"name": {"offset": N, "size": M}` entry.
fn field(name: &str, offset: usize, size: usize) -> String {
    format!("      \"{name}\": {{ \"offset\": {offset}, \"size\": {size} }}")
}

fn account(name: &str, len: usize, fields: Vec<String>) -> String {
    if fields.is_empty() {
        format!("    \"{name}\": {{\n      \"account_len\": {len}\n    }}")
    } else {
        format!(
            "    \"{name}\": {{\n      \"account_len\": {len},\n{}\n    }}",
            fields.join(",\n")
        )
    }
}

/// Borsh offsets accumulate in declaration order; every field below is
/// fixed-size, so this is exact. Verified by probe in `borsh_probes_confirm_*`.
struct BorshCursor(usize);
impl BorshCursor {
    fn new() -> Self {
        Self(DISC)
    }
    fn take(&mut self, name: &str, size: usize, out: &mut Vec<String>) -> usize {
        let at = self.0;
        out.push(field(name, at, size));
        self.0 += size;
        at
    }
}

fn render() -> String {
    let mut accounts: Vec<String> = Vec::new();

    // ---- VaultConfig (zero_copy / repr(C)) ----
    let mut f = Vec::new();
    macro_rules! zc {
        ($ty:ty, $out:expr, $($fname:ident : $fsize:expr),+ $(,)?) => {
            $( $out.push(field(
                stringify!($fname),
                DISC + core::mem::offset_of!($ty, $fname),
                $fsize,
            )); )+
        };
    }
    zc!(VaultConfig, f,
        admin: 32,
        tee_pubkeys: 32 * 16,
        root_key: 32,
        zero_subtree_roots: 32 * MERKLE_DEPTH as usize,
        protocol_owner_commitment: 32,
        fee_rate_bps: 2,
        num_tee_keys: 1,
        num_trees: 1,
        bump: 1,
    );
    accounts.push(account(
        "VaultConfig",
        DISC + core::mem::size_of::<VaultConfig>(),
        f,
    ));

    // ---- MerkleTree (zero_copy / repr(C)) ----
    let mut f = Vec::new();
    zc!(MerkleTree, f,
        leaf_count: 8,
        current_root: 32,
        roots: 32 * ROOT_HISTORY_SIZE,
        right_path: 32 * MERKLE_DEPTH as usize,
        roots_head: 1,
        tree_id: 1,
        bump: 1,
    );
    accounts.push(account(
        "MerkleTree",
        DISC + core::mem::size_of::<MerkleTree>(),
        f,
    ));

    // ---- NoteLock (zero_copy / repr(C)) ----
    let mut f = Vec::new();
    zc!(NoteLock, f, expiry_slot: 8);
    accounts.push(account(
        "NoteLock",
        DISC + core::mem::size_of::<NoteLock>(),
        f,
    ));

    // ---- MarketConfig (Borsh) ----
    let mut f = Vec::new();
    let mut c = BorshCursor::new();
    c.take("base_mint", 32, &mut f);
    c.take("quote_mint", 32, &mut f);
    c.take("price_scale", 8, &mut f);
    c.take("tick_size", 8, &mut f);
    c.take("min_order_size", 8, &mut f);
    c.take("circuit_breaker_bps", 8, &mut f);
    c.take("base_decimals", 1, &mut f);
    c.take("quote_decimals", 1, &mut f);
    c.take("enabled", 1, &mut f);
    c.take("bump", 1, &mut f);
    accounts.push(account("MarketConfig", borsh_len::<MarketConfig>(), f));

    // ---- BatchValidityMarker (Borsh) ----
    let mut f = Vec::new();
    let mut c = BorshCursor::new();
    c.take("payer", 32, &mut f);
    c.take("expiry_slot", 8, &mut f);
    c.take("bump", 1, &mut f);
    accounts.push(account(
        "BatchValidityMarker",
        borsh_len::<BatchValidityMarker>(),
        f,
    ));

    // ---- The three guard/registry PDAs ----
    //
    // Added when the Anchor v2 port needed layout identity asserted for ALL
    // account structs, not only the five that happened to be here. These are
    // the smallest and least glamorous, which is exactly why they were the ones
    // missing. The two replay markers are now deliberately discriminator-only:
    // their PDA seed carries the identity, and existence carries the bit.
    accounts.push(account(
        "DepositedNoteEntry",
        DepositedNoteEntry::SPACE,
        Vec::new(),
    ));

    accounts.push(account(
        "ConsumedNoteEntry",
        ConsumedNoteEntry::SPACE,
        Vec::new(),
    ));

    let mut f = Vec::new();
    zc!(OutstandingMint, f, mint: 32, outstanding: 8, bump: 1);
    accounts.push(account(
        "OutstandingMint",
        DISC + core::mem::size_of::<OutstandingMint>(),
        f,
    ));

    format!(
        "{{\n  \"_generated_by\": \"programs/vault/tests/account_layout_fixture.rs\
         (UPDATE_LAYOUT_FIXTURE=1 cargo test -p vault --test account_layout_fixture)\",\n  \
         \"_note\": \"Offsets INCLUDE the 8-byte Anchor discriminator. Derived from the \
         structs, never hand-written. Consumers assert against this file.\",\n  \
         \"accounts\": {{\n{}\n  }}\n}}\n",
        accounts.join(",\n")
    )
}

fn ser<T: Pod>(v: &T) -> Vec<u8> {
    bytemuck::bytes_of(v).to_vec()
}

/// Named `borsh_len` historically. Under v2 the body is the Pod size, and the
/// point of the test is that the NUMBER is unchanged from the borsh era.
fn borsh_len<T: Default + Pod>() -> usize {
    DISC + core::mem::size_of::<T>()
}

#[test]
fn space_constants_match_the_pod_sizes() {
    // `init` allocates `SPACE` bytes; the runtime then interprets those bytes as
    // the Pod struct. If the two drift the account is mis-sized — too small and
    // loads fail, too large and rent is silently overpaid forever.
    //
    // These constants were hand-written for the v1 BORSH layout. That they still
    // equal `8 + size_of::<T>()` under v2's repr(C) Pod layout is the check that
    // the migration preserved the on-wire size, independently of the JSON
    // fixture (which only records what the structs currently are).
    assert_eq!(
        MarketConfig::SPACE,
        DISC + core::mem::size_of::<MarketConfig>(),
        "MarketConfig::SPACE drifted from the Pod size"
    );
    assert_eq!(
        OutstandingMint::SPACE,
        DISC + core::mem::size_of::<OutstandingMint>(),
        "OutstandingMint::SPACE drifted from the Pod size"
    );
    assert_eq!(
        BatchValidityMarker::SPACE,
        DISC + core::mem::size_of::<BatchValidityMarker>(),
        "BatchValidityMarker::SPACE drifted from the Pod size"
    );
    assert_eq!(DepositedNoteEntry::SPACE, DISC);
    assert_eq!(ConsumedNoteEntry::SPACE, DISC);
    assert_eq!(
        NoteLock::SPACE,
        DISC + core::mem::size_of::<NoteLock>(),
        "NoteLock::SPACE drifted from the Pod size"
    );
}

#[test]
fn compact_account_rent_is_pinned() {
    let rent = Rent::from_bytes(&6_960u64.to_le_bytes()).expect("canonical rent parameters");
    let balance = |size| {
        rent.try_minimum_balance(size)
            .expect("account size is valid")
    };
    let deposit_marker = balance(DepositedNoteEntry::SPACE);
    let consumed_marker = balance(ConsumedNoteEntry::SPACE);
    let note_lock = balance(NoteLock::SPACE);

    // These numbers use Solana's canonical Rent parameters. Pinning both the
    // absolute lamports and the old-layout deltas makes a future layout or Rent
    // assumption change visible in review instead of silently invalidating the
    // account-cost evidence.
    assert_eq!(deposit_marker, 946_560);
    assert_eq!(consumed_marker, 946_560);
    assert_eq!(note_lock, 1_392_000);

    let old_deposit_marker = balance(56);
    let old_consumed_marker = balance(72);
    let old_note_lock = balance(136);
    assert_eq!(old_deposit_marker - deposit_marker, 334_080);
    assert_eq!(old_consumed_marker - consumed_marker, 445_440);
    assert_eq!(old_note_lock - note_lock, 445_440);

    eprintln!(
        "RENT_PROFILE deposit_marker={} consumed_marker={} note_lock={} savings_deposit={} savings_consumed={} savings_lock={}",
        deposit_marker,
        consumed_marker,
        note_lock,
        old_deposit_marker - deposit_marker,
        old_consumed_marker - consumed_marker,
        old_note_lock - note_lock,
    );
}

#[test]
fn legacy_replay_markers_remain_existence_compatible() {
    // Anchor accepts trailing bytes after the current account body. Pin that
    // behavior explicitly: old development accounts remain recognizable as
    // occupied replay markers during a drain/reset, while every newly-created
    // marker pays rent for the discriminator only. No retired payload field is
    // read or trusted.
    let mut legacy_deposit = vec![0xA5; 56];
    legacy_deposit[..DISC].copy_from_slice(DepositedNoteEntry::DISCRIMINATOR);
    DepositedNoteEntry::try_deserialize(&mut legacy_deposit.as_slice())
        .expect("legacy deposit marker must remain occupied");

    let mut legacy_consumed = vec![0xA5; 72];
    legacy_consumed[..DISC].copy_from_slice(ConsumedNoteEntry::DISCRIMINATOR);
    ConsumedNoteEntry::try_deserialize(&mut legacy_consumed.as_slice())
        .expect("legacy consume marker must remain occupied");
}

#[test]
fn every_account_struct_is_covered() {
    // The fixture once covered only 5 account structs, which is how
    // DepositedNoteEntry / ConsumedNoteEntry /
    // OutstandingMint went unasserted through a layout-changing migration. Pin
    // the count so a new account type cannot be added without a layout entry.
    let rendered = render();
    // The name loop below proves each account is PRESENT; it cannot prove
    // nothing else is. Without this count, a tenth account struct renders into
    // the fixture and this test still passes, which is the exact failure the
    // test exists to prevent.
    assert_eq!(
        rendered.matches("\"account_len\"").count(),
        8,
        "layout fixture account count drifted"
    );
    for name in [
        "VaultConfig",
        "MarketConfig",
        "MerkleTree",
        "DepositedNoteEntry",
        "ConsumedNoteEntry",
        "NoteLock",
        "OutstandingMint",
        "BatchValidityMarker",
    ] {
        assert!(
            rendered.contains(&format!("\"{name}\"")),
            "{name} is missing from the layout fixture"
        );
    }
}

#[test]
fn account_layout_fixture_is_current() {
    let rendered = render();
    let path = fixture_path();

    if std::env::var("UPDATE_LAYOUT_FIXTURE").is_ok() {
        fs::write(&path, &rendered).expect("write fixture");
        eprintln!("regenerated {}", path.display());
        return;
    }

    let committed = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "{} is missing. Regenerate with:\n  \
             UPDATE_LAYOUT_FIXTURE=1 cargo test -p vault --test account_layout_fixture",
            path.display()
        )
    });

    assert_eq!(
        committed.trim(),
        rendered.trim(),
        "\n\nThe vault account layout CHANGED and the committed fixture is stale.\n\
         Every hand-written offset in crates/darknyx-tee and packages/sdk is now \
         reading the wrong bytes, and their own tests will not notice because they \
         check their literals against each other.\n\
         Regenerate and update the consumers in the SAME commit:\n  \
         UPDATE_LAYOUT_FIXTURE=1 cargo test -p vault --test account_layout_fixture\n"
    );
}

/// The Borsh offsets above are accumulated, not `offset_of!`-derived, so prove
/// them against the real serializer: a sentinel written into a field must land
/// at the offset the fixture records. Inserting or reordering a field moves it.
#[test]
fn borsh_probes_confirm_accumulated_offsets() {
    // BatchValidityMarker: `payer` at 8, `expiry_slot` at 40.
    let marker = BatchValidityMarker {
        payer: Pubkey::new_from_array([0xAB; 32]),
        expiry_slot: 0x1122_3344_5566_7788.into(),
        ..Default::default()
    };
    let bytes = ser(&marker);
    assert_eq!(
        &bytes[0..32],
        &[0xAB; 32],
        "BatchValidityMarker.payer must serialize first (fixture offset 8 = disc + 0)"
    );
    assert_eq!(
        &bytes[32..40],
        &0x1122_3344_5566_7788u64.to_le_bytes(),
        "BatchValidityMarker.expiry_slot must follow payer (fixture offset 40)"
    );

    // MarketConfig: base_mint at 8, quote_mint at 40, price_scale at 72.
    let market = MarketConfig {
        base_mint: Pubkey::new_from_array([0x11; 32]),
        quote_mint: Pubkey::new_from_array([0x22; 32]),
        price_scale: 0x0102_0304_0506_0708.into(),
        ..Default::default()
    };
    let bytes = ser(&market);
    assert_eq!(&bytes[0..32], &[0x11; 32], "MarketConfig.base_mint at 8");
    assert_eq!(&bytes[32..64], &[0x22; 32], "MarketConfig.quote_mint at 40");
    assert_eq!(
        &bytes[64..72],
        &0x0102_0304_0506_0708u64.to_le_bytes(),
        "MarketConfig.price_scale at 72"
    );
}
