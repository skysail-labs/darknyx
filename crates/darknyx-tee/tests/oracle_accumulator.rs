//! Integration test for the Pyth accumulator parser + Keccak160 Merkle
//! inclusion verifier (C-05 / A-2).
//!
//! Fixture: `tests/fixtures/sol_usd_accumulator.bin` — a real Hermes SOL/USD
//! `AccumulatorUpdateData` captured live from
//! `https://hermes.pyth.network/v2/updates/price/latest?ids[]=ef0d8b6f...`.
//! 1311 bytes, guardian set 7, 1 update, proof depth 13. Recorded ground
//! truth (see `docs/oracle-accumulator-notes.md`):
//!   - ema_price = 7471749900, exponent = -8, publish_time = 1783978363
//!   - VAA-embedded Merkle root = 8ef2f2693c8b116bd14f75a3bbb013dbf95e48ee
//!
//! The load-bearing property: the price we would cache is the one Merkle-
//! committed under the guardian-signed root — recomputing the root from
//! (message ‖ proof) reproduces the VAA-embedded root, and the decoded
//! ema_price matches the value Hermes reported in its JSON `parsed[]`.

use darknyx_tee::oracle::{accumulator, vaa};

const FIXTURE: &[u8] = include_bytes!("fixtures/sol_usd_accumulator.bin");

/// SOL/USD feed id.
const SOL_USD_FEED_ID: [u8; 32] =
    hex_literal(b"ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d");

/// Recorded ground-truth values from the captured fixture.
const EXPECTED_EMA_PRICE: i64 = 7471749900;
const EXPECTED_EXPONENT: i32 = -8;
const EXPECTED_PUBLISH_TIME: i64 = 1783978363;

// const-fn hex decoder so the feed id + root are compile-time constants.
const fn hex_literal<const N: usize>(s: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nib(s[i * 2]) << 4) | nib(s[i * 2 + 1]);
        i += 1;
    }
    out
}
const fn nib(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => 10 + b - b'a',
        _ => panic!("bad hex"),
    }
}

/// Parse the fixture, verify guardians, extract the root, and return the
/// single price update alongside the guardian-signed root.
fn parsed_update() -> (accumulator::PriceUpdate<'static>, [u8; 20]) {
    let parsed = accumulator::parse(FIXTURE).expect("parse accumulator");
    // Guardian signatures over the VAA must pass (set-7 fixture).
    let v = vaa::verify(parsed.vaa).expect("guardian verify");
    let root = accumulator::merkle_root_from_vaa_payload(v.payload).expect("root");
    assert_eq!(parsed.updates.len(), 1, "single-feed query → one update");
    (parsed.updates.into_iter().next().unwrap(), root)
}

#[test]
fn root_matches_recorded_ground_truth() {
    let parsed = accumulator::parse(FIXTURE).expect("parse");
    let v = vaa::verify(parsed.vaa).expect("verify");
    let root = accumulator::merkle_root_from_vaa_payload(v.payload).expect("root");
    assert_eq!(
        hex::encode(root),
        "8ef2f2693c8b116bd14f75a3bbb013dbf95e48ee"
    );
}

#[test]
fn message_is_included_under_the_guardian_signed_root() {
    let (update, root) = parsed_update();
    assert!(
        accumulator::verify_inclusion(update.message, &update.proof, &root),
        "price message must prove inclusion under the attested Merkle root"
    );
}

#[test]
fn decoded_price_matches_recorded_and_is_the_included_feed() {
    let (update, root) = parsed_update();
    assert!(accumulator::verify_inclusion(
        update.message,
        &update.proof,
        &root
    ));

    let msg = accumulator::parse_price_feed_message(update.message).expect("decode");
    assert_eq!(msg.feed_id, SOL_USD_FEED_ID, "feed id");
    assert_eq!(msg.ema_price, EXPECTED_EMA_PRICE, "ema_price");
    assert_eq!(msg.exponent, EXPECTED_EXPONENT, "exponent");
    assert_eq!(msg.publish_time, EXPECTED_PUBLISH_TIME, "publish_time");
    assert!(msg.ema_price > 0);
}

#[test]
fn flipped_message_byte_breaks_inclusion() {
    let (update, root) = parsed_update();
    let mut tampered = update.message.to_vec();
    // Flip a byte inside the ema_price field region (offset 69..77).
    tampered[70] ^= 0xff;
    assert!(
        !accumulator::verify_inclusion(&tampered, &update.proof, &root),
        "a tampered price message must NOT verify — this is the whole point"
    );
}

#[test]
fn flipped_proof_node_breaks_inclusion() {
    let (update, root) = parsed_update();
    let mut proof = update.proof.clone();
    assert!(!proof.is_empty(), "fixture has a non-trivial proof");
    proof[0][0] ^= 0xff;
    assert!(
        !accumulator::verify_inclusion(update.message, &proof, &root),
        "a corrupted proof node must NOT verify"
    );
}

#[test]
fn wrong_root_breaks_inclusion() {
    let (update, _root) = parsed_update();
    let fake_root = [0x42u8; 20];
    assert!(
        !accumulator::verify_inclusion(update.message, &update.proof, &fake_root),
        "inclusion under a different root must fail"
    );
}

#[test]
fn truncated_buffer_errors_without_panic() {
    // Every prefix of the fixture must yield a typed error (or, for a valid
    // prefix boundary, parse) — never a panic.
    for cut in 0..FIXTURE.len() {
        let _ = accumulator::parse(&FIXTURE[..cut]);
    }
    // A mid-header cut is specifically a Truncated error.
    assert!(matches!(
        accumulator::parse(&FIXTURE[..5]),
        Err(accumulator::AccumulatorError::Truncated { .. })
    ));
}

#[test]
fn full_fixture_parses_and_verifies_end_to_end() {
    // The exact sequence sync.rs runs, minus the cache write.
    let (update, root) = parsed_update();
    assert!(accumulator::verify_inclusion(
        update.message,
        &update.proof,
        &root
    ));
    let msg = accumulator::parse_price_feed_message(update.message).expect("decode");
    assert_eq!(msg.feed_id, SOL_USD_FEED_ID);
    assert_eq!(msg.ema_price as u64, 7471749900u64);
}
