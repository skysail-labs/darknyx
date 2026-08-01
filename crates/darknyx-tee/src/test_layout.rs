//! A-3 — test-only reader for the vault's generated account-layout fixture.
//!
//! Every byte offset this crate uses to parse a vault account is hand-written,
//! and `crates/darknyx-tee` deliberately does not depend on the `vault` crate,
//! so nothing here can see `offset_of!`. Before this existed, the offsets were
//! pinned by tests that compared a constant to a literal —
//! `assert_eq!(FEE_RATE_BPS_OFFSET, 1256)` is true of the constant and says
//! nothing about the program. Insert a field into `VaultConfig` and every parser
//! in this crate keeps agreeing with itself while reading the wrong bytes.
//!
//! `programs/vault/account-layout.json` is generated FROM the real structs
//! (`offset_of!` for the `zero_copy` accounts, probe-verified Borsh
//! accumulation for the rest). Asserting against it makes a layout change fail
//! here rather than in production.
//!
//! The fixture is committed, so this needs no build step — but it must be
//! regenerated in the same commit as any struct change:
//!   `UPDATE_LAYOUT_FIXTURE=1 cargo test -p vault --test account_layout_fixture`

use std::path::PathBuf;
use std::sync::OnceLock;

fn fixture() -> &'static serde_json::Value {
    static FIXTURE: OnceLock<serde_json::Value> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.push("programs/vault/account-layout.json");
        let raw = std::fs::read_to_string(&p).unwrap_or_else(|e| {
            panic!(
                "cannot read the vault account-layout fixture at {}: {e}\n\
                 Regenerate with: UPDATE_LAYOUT_FIXTURE=1 cargo test -p vault \
                 --test account_layout_fixture",
                p.display()
            )
        });
        serde_json::from_str(&raw).expect("account-layout.json is not valid JSON")
    })
}

fn entry(account: &str) -> &'static serde_json::Value {
    fixture()
        .get("accounts")
        .and_then(|a| a.get(account))
        .unwrap_or_else(|| panic!("account-layout.json has no entry for {account}"))
}

/// Byte offset of `field` within `account`'s data, INCLUDING the 8-byte Anchor
/// discriminator.
pub fn offset(account: &str, field: &str) -> usize {
    entry(account)
        .get(field)
        .and_then(|f| f.get("offset"))
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| panic!("account-layout.json: {account}.{field} has no offset"))
        as usize
}

/// Declared byte size of `field` within `account`.
pub fn size(account: &str, field: &str) -> usize {
    entry(account)
        .get(field)
        .and_then(|f| f.get("size"))
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| panic!("account-layout.json: {account}.{field} has no size"))
        as usize
}

/// Total account data length, including the discriminator.
pub fn account_len(account: &str) -> usize {
    entry(account)
        .get("account_len")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| panic!("account-layout.json: {account} has no account_len")) as usize
}
