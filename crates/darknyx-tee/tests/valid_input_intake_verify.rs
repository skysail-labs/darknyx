//! Positive + negative gate for the S-02 intake-side VALID_INPUT check.
//!
//! The unit tests in `src/verify.rs` only prove that garbage is rejected. That
//! is the cheap half: a verifier that rejects *everything* would also pass
//! them, while silently breaking every order placement in production. This
//! test closes that gap by proving a REAL VALID_INPUT proof and asserting the
//! intake path accepts it.
//!
//! It also cross-checks two components that must agree but are written
//! independently: the `MerkleMirror`'s inclusion proof supplies the witness
//! path, and the circuit re-derives the root from it. If the mirror's sibling
//! ordering or index bits ever drift from the circuit's `MerkleTreeChecker`,
//! witness generation fails here rather than on devnet.
//!
//! Requires the built circuit artifacts (`bash scripts/build-circuits.sh`);
//! skips cleanly when they are absent so a fresh checkout is not blocked.

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_groth16::Groth16;
use num_bigint::BigInt;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::path::{Path, PathBuf};

use darknyx_tee::merkle::MerkleMirror;
use darknyx_tee::prover::convert::proof_to_onchain_bytes;
use darknyx_tee::verify::{verify_valid_input, VerifyError};

fn repo_root() -> PathBuf {
    // crates/darknyx-tee -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root resolves")
}

/// Big-endian 32 bytes -> the decimal `BigInt` ark-circom wants for an input.
fn be32_to_bigint(b: &[u8; 32]) -> BigInt {
    BigInt::from_bytes_be(num_bigint::Sign::Plus, b)
}

struct Fixture {
    proof_bytes: darknyx_tee::settle::Groth16ProofBytes,
    merkle_root: [u8; 32],
    note_commitment: [u8; 32],
    token_mint: [u8; 32],
}

/// Build a real note, put it in a mirror-backed tree, and prove VALID_INPUT
/// over it. Returns `None` when the circuit artifacts are not built.
///
/// **Artifact-required mode.** With `REQUIRE_CIRCUIT_ARTIFACTS=1` a missing
/// artifact is a hard failure instead of a skip. CI and any release gate set it.
///
/// Why this matters: two of the three artifacts (`circuit.r1cs` and
/// `circuit_js/`) are gitignored, so a fresh checkout has them absent by
/// default. Without the flag the positive test — the one asserting a REAL
/// VALID_INPUT proof is accepted at intake, which is the whole point of the
/// S-02 remediation — returned early and reported PASSED without proving
/// anything. A test that silently becomes a no-op on the machines most likely
/// to lack artifacts is worse than no test: it reports coverage it does not
/// have. Skipping stays available for a casual local run, but it must be
/// explicit and it must announce itself.
fn prove_fixture() -> Option<Fixture> {
    let build = repo_root().join("circuits/build/valid_input");
    let wasm = build.join("circuit_js/circuit.wasm");
    let r1cs = build.join("circuit.r1cs");
    let zkey = build.join("circuit_final.zkey");
    if !wasm.exists() || !r1cs.exists() || !zkey.exists() {
        let required = std::env::var("REQUIRE_CIRCUIT_ARTIFACTS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let detail = format!(
            "valid_input circuit artifacts missing under {} (wasm={} r1cs={} zkey={}) — run \
             `bash scripts/build-circuits.sh`",
            build.display(),
            wasm.exists(),
            r1cs.exists(),
            zkey.exists(),
        );
        assert!(
            !required,
            "REQUIRE_CIRCUIT_ARTIFACTS=1 but {detail}. This test cannot pass without \
             actually proving; refusing to report success."
        );
        eprintln!("SKIP: {detail}");
        return None;
    }

    // ----- A real note -----
    let spending_key = darkpool_crypto::field::fr_from_uniform_bytes(&[7u8; 32]);
    let r_owner = darkpool_crypto::field::fr_from_uniform_bytes(&[11u8; 32]);
    let inner_hash = darkpool_crypto::field::fr_to_be_bytes(
        &darkpool_crypto::field::fr_from_uniform_bytes(&[13u8; 32]),
    );
    let amount: u64 = 5_000_000;
    // An arbitrary but fixed mint pubkey.
    let mut token_mint = [0u8; 32];
    for (i, b) in token_mint.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }

    let owner_commitment =
        darkpool_crypto::note::owner_commitment(&spending_key, &r_owner).expect("owner commitment");
    let note_commitment = darkpool_crypto::note::commitment_from_fields_v2(
        &token_mint,
        amount,
        &owner_commitment,
        &inner_hash,
    )
    .expect("note commitment");

    // ----- Put it in a tree, with some neighbours so the path is non-trivial -----
    let mut mirror = MerkleMirror::new();
    for i in 0u8..3 {
        let mut filler = [0u8; 32];
        filler[31] = i + 1;
        filler[1] = 0x5A; // keep the top byte zero => Fr-safe
        mirror.append_leaf(filler).expect("filler append");
    }
    mirror.append_leaf(note_commitment).expect("note append");
    for i in 0u8..2 {
        let mut filler = [0u8; 32];
        filler[31] = i + 200;
        filler[1] = 0x5A;
        mirror.append_leaf(filler).expect("trailing append");
    }

    let merkle_root = mirror.root();
    let incl = mirror
        .inclusion_proof(&note_commitment)
        .expect("inclusion proof computes")
        .expect("note is in the mirror");
    assert_eq!(incl.merkle_root, merkle_root);

    // ----- Witness -----
    let cfg = CircomConfig::<Fr>::new(&wasm, &r1cs).expect("CircomConfig");
    let mut builder = CircomBuilder::new(cfg);

    let [mint_lo, mint_hi] = darkpool_crypto::field::pubkey_to_fr_pair(&token_mint);
    builder.push_input("merkleRoot", be32_to_bigint(&merkle_root));
    builder.push_input("noteCommitment", be32_to_bigint(&note_commitment));
    builder.push_input(
        "tokenMint",
        be32_to_bigint(&darkpool_crypto::field::fr_to_be_bytes(&mint_lo)),
    );
    builder.push_input(
        "tokenMint",
        be32_to_bigint(&darkpool_crypto::field::fr_to_be_bytes(&mint_hi)),
    );
    builder.push_input("amount", BigInt::from(amount));
    builder.push_input(
        "spendingKey",
        be32_to_bigint(&darkpool_crypto::field::fr_to_be_bytes(&spending_key)),
    );
    builder.push_input(
        "ownerCommitmentBlinding",
        be32_to_bigint(&darkpool_crypto::field::fr_to_be_bytes(&r_owner)),
    );
    builder.push_input("innerHash", be32_to_bigint(&inner_hash));
    for s in incl.siblings.iter() {
        builder.push_input("merklePath", be32_to_bigint(s));
    }
    for idx in incl.indices.iter() {
        builder.push_input("merkleIndices", BigInt::from(*idx));
    }

    let circom = builder.build().expect(
        "witness generation — a failure here usually means the mirror's \
                 inclusion proof disagrees with the circuit's MerkleTreeChecker",
    );

    // Pin the PUBLIC-SIGNAL ORDER contract. `lock_note` (and therefore
    // `verify_valid_input`) hard-codes `[merkleRoot, noteCommitment, mint_lo,
    // mint_hi]`; circom decides that order from the template's declaration
    // order, not from the `public [...]` list. If a future circuit edit
    // reorders those declarations, the on-chain verifier silently starts
    // checking a permuted statement — this assert catches it here instead.
    let circuit_publics = circom
        .get_public_inputs()
        .expect("circuit has public inputs");
    let expected_publics: Vec<Fr> = vec![
        darkpool_crypto::field::fr_from_be_bytes(&merkle_root).unwrap(),
        darkpool_crypto::field::fr_from_be_bytes(&note_commitment).unwrap(),
        mint_lo,
        mint_hi,
    ];
    assert_eq!(
        circuit_publics, expected_publics,
        "VALID_INPUT public-signal order changed; lock_note.rs and \
         darknyx_tee::verify both assume [merkleRoot, noteCommitment, mint_lo, mint_hi]"
    );

    // ----- Prove -----
    let mut zkey_file = std::fs::File::open(&zkey).expect("open zkey");
    let (pk, _matrices) = ark_circom::read_zkey(&mut zkey_file).expect("read_zkey");
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
    let proof = Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(
        circom, &pk, &mut rng,
    )
    .expect("prove");

    // Sanity gate BEFORE the on-chain-format check: the proof must verify
    // against the zkey's own verifying key. If this fails, the fixture is
    // wrong. If this passes but the groth16-solana check below fails, the
    // committed `vk_valid_input.rs` has drifted from `circuit_final.zkey`
    // — the exact CLAUDE.md §5 foot-gun, and a devnet-breaking condition.
    let pvk = ark_groth16::prepare_verifying_key(&pk.vk);
    assert!(
        Groth16::<Bn254, CircomReduction>::verify_proof(&pvk, &proof, &expected_publics).unwrap(),
        "proof does not verify against the zkey's OWN verifying key — the test \
         fixture is malformed, not the intake verifier"
    );

    Some(Fixture {
        proof_bytes: proof_to_onchain_bytes(&proof),
        merkle_root,
        note_commitment,
        token_mint,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_valid_input_proof_is_accepted_at_intake() {
    let Some(f) = prove_fixture() else { return };

    verify_valid_input(
        &f.proof_bytes,
        &f.merkle_root,
        &f.note_commitment,
        &f.token_mint,
    )
    .expect(
        "a genuine VALID_INPUT proof MUST pass intake — a failure here would reject \
         every legitimate order in production",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proof_is_rejected_when_the_declared_note_does_not_match() {
    let Some(f) = prove_fixture() else { return };

    // Substituting the commitment is exactly the S-02 attack shape: a real
    // proof for one note, presented as authorisation for another.
    let mut other = f.note_commitment;
    other[31] ^= 0x01;
    assert_eq!(
        verify_valid_input(&f.proof_bytes, &f.merkle_root, &other, &f.token_mint),
        Err(VerifyError::Invalid),
        "a proof must not authorise a note it was not generated for"
    );

    // A different root must fail too — this is what stops a proof against a
    // tree state that never existed.
    let mut other_root = f.merkle_root;
    other_root[31] ^= 0x01;
    assert_eq!(
        verify_valid_input(
            &f.proof_bytes,
            &other_root,
            &f.note_commitment,
            &f.token_mint
        ),
        Err(VerifyError::Invalid)
    );

    // And a different mint: the note's mint is bound, so an order claiming the
    // wrong side's collateral cannot reuse the proof.
    let mut other_mint = f.token_mint;
    other_mint[0] ^= 0x01;
    assert_eq!(
        verify_valid_input(
            &f.proof_bytes,
            &f.merkle_root,
            &f.note_commitment,
            &other_mint
        ),
        Err(VerifyError::Invalid)
    );
}
