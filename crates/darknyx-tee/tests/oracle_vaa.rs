//! Integration test for the oracle's VAA parser + guardian-sig
//! verifier.
//!
//! Fixture: `tests/fixtures/sol_usd_vaa.bin` — a real Hermes
//! `AccumulatorUpdateData` response captured live from
//! `https://hermes.pyth.network/v2/updates/price/latest?ids[]=ef0d8b6f...`
//! on 2026-06-27. Signed against Wormhole mainnet guardian set 7.
//!
//! These tests prove three load-bearing properties:
//!
//!   1. Pyth's `AccumulatorUpdateData` wrapper is stripped
//!      correctly to expose the embedded VAA bytes.
//!   2. The VAA byte layout parses without error against real
//!      production data (no off-by-ones in the header / signature
//!      / body section).
//!   3. The Wormhole guardian-set-7 signatures all verify via
//!      `k256` ecrecover against the hardcoded guardian table.
//!      This is the cryptographic trust anchor — if this passes,
//!      the TEE knows the price came from Pyth and wasn't forged
//!      between Hermes and us.
//!
//! Plus a tampering test that flips a single byte in the VAA
//! body to confirm signature verification actually rejects bad
//! inputs.

use darknyx_tee::oracle::vaa;

/// The raw AccumulatorUpdateData bytes captured from Hermes.
/// Including the file via `include_bytes!` keeps the fixture
/// committed and reproducible — no network access required to
/// run these tests.
const FIXTURE: &[u8] = include_bytes!("fixtures/sol_usd_vaa.bin");

/// Extract just the VAA bytes from the Hermes accumulator
/// wrapper. We hardcode the wrapper format here (rather than
/// going through the private hermes.rs helper) so the test is
/// self-contained — it reads exactly the same bytes the
/// production path would.
fn extract_vaa(accum: &[u8]) -> Vec<u8> {
    // Wrapper: "PNAU" (4) + major (1) + minor (1) +
    //           trailing_header_size (1) + proof_type (1) +
    //           vaa_length (BE u16) + vaa[...]
    assert_eq!(&accum[0..4], b"PNAU");
    let trailing = accum[6] as usize;
    let vaa_len_offset = 8 + trailing;
    let vaa_len = u16::from_be_bytes([accum[vaa_len_offset], accum[vaa_len_offset + 1]]) as usize;
    let vaa_start = vaa_len_offset + 2;
    accum[vaa_start..vaa_start + vaa_len].to_vec()
}

// ─────── Tests ──────────────────────────────────────────────────────────────

#[test]
fn fixture_extracts_a_vaa_starting_with_version_1() {
    let vaa_bytes = extract_vaa(FIXTURE);
    assert!(vaa_bytes.len() > 100, "VAA suspiciously small");
    assert_eq!(vaa_bytes[0], 1, "VAA version byte");
}

#[test]
fn fixture_parses_cleanly() {
    let vaa_bytes = extract_vaa(FIXTURE);
    let parsed = vaa::parse(&vaa_bytes).expect("parse");

    assert_eq!(parsed.guardian_set_index, vaa::MAINNET_GUARDIAN_SET_INDEX);
    // Set 7 has 19 guardians, quorum is 13. Hermes typically
    // includes exactly the quorum count.
    assert!(
        parsed.signature_count as usize >= vaa::QUORUM,
        "signature_count {} below quorum {}",
        parsed.signature_count,
        vaa::QUORUM
    );
    // Pyth's Wormhole emitter chain id is 26 (PythNet).
    assert_eq!(
        parsed.emitter_chain_id, 26,
        "expected Pyth-on-Wormhole emitter chain id"
    );
    // payload starts with PNAU-inner magic "AUWV" then
    // accumulator details. Just check it's non-empty.
    assert!(!parsed.payload.is_empty(), "payload should be non-empty");
}

#[test]
fn fixture_verifies_under_mainnet_guardians() {
    let vaa_bytes = extract_vaa(FIXTURE);
    // The load-bearing test: real Hermes bytes verify against
    // the hardcoded set-7 guardian table.
    vaa::verify(&vaa_bytes).expect("Wormhole guardian signature verification failed");
}

#[test]
fn flipped_body_byte_breaks_signatures() {
    // Tamper one byte in the body (post-signatures) — keccak256
    // of the body changes → all 13+ ecrecoveries recover the
    // wrong address → quorum can't be met → reject.
    let mut vaa_bytes = extract_vaa(FIXTURE);

    // Find the body's start: 5 byte header + signature_count
    // (1 byte) + signatures (66 bytes each).
    let sig_count = vaa_bytes[5] as usize;
    let body_start = 6 + sig_count * 66;
    assert!(body_start < vaa_bytes.len());

    // Flip a payload byte (well after the body header) so we
    // don't accidentally change parsing semantics — purely a
    // signature-breaking tamper.
    vaa_bytes[body_start + 50] ^= 0xff;

    let err = vaa::verify(&vaa_bytes).expect_err("tampered VAA must not verify");
    let msg = err.to_string();
    // Either "SignatureMismatch" (most likely) or "BelowQuorum"
    // (if the corrupted hash happens to make all signatures fail).
    assert!(
        msg.contains("does not match guardian")
            || msg.contains("Below")
            || msg.contains("ecrecover")
            || msg.contains("guardian signature verification"),
        "expected sig-rejection error, got: {msg}"
    );
}

#[test]
fn flipped_guardian_set_index_is_rejected() {
    let mut vaa_bytes = extract_vaa(FIXTURE);
    // bytes 1-4 = guardian_set_index BE u32. Change set 7 → set 99.
    vaa_bytes[1..5].copy_from_slice(&99u32.to_be_bytes());
    let err = vaa::verify(&vaa_bytes).expect_err("wrong-set VAA must not verify");
    // anyhow::Context wraps the inner VaaError::WrongGuardianSet
    // variant; use the {:#} alternate format to see the full
    // error chain instead of just the top-level context.
    let chain = format!("{:#}", err);
    assert!(
        chain.contains("guardian set") && chain.contains("99"),
        "expected guardian-set rejection mentioning set 99, got: {chain}"
    );
}
