//! Shared helpers for integration tests.
#![allow(dead_code)]
// Individual integration-test binaries pull in a subset of these helpers
// (e.g. set_protocol_config.rs only needs `repo_root` + `anchor_disc`).
// Cargo compiles each test crate independently and warns about the others;
// the allow keeps `-D warnings` happy without sprinkling per-item allows.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

pub fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

/// Path to the compiled BPF program, verified to match the current vault
/// source. **Every LiteSVM test must load through this**, not by joining
/// `target/deploy/vault.so` itself.
///
/// The failure this prevents is silent and total: `target/deploy/vault.so` is a
/// build artifact that no test dependency tracks, so `cargo test` happily runs
/// the entire suite against a binary compiled from *older* source. Every
/// assertion still passes — against the wrong program. It bit this repo during
/// the 2026-07-27 audit-verification pass, where the suite ran green against an
/// artifact older than ten vault source files.
///
/// The guard is a **content fingerprint**, not an mtime comparison. A timestamp
/// answers "was this written after the source?", which is wrong in both
/// directions: `git checkout` and `touch` move mtimes without changing code, and
/// a rebuild with a *different feature set* leaves a newer artifact that is
/// still the wrong binary (`devnet-admin` on/off changes which instructions
/// exist). `scripts/vault-sbf-fingerprint.sh` is the single definition, re-run
/// here rather than reimplemented, so the build side and the check side cannot
/// drift.
pub fn vault_program_so() -> PathBuf {
    use sha2::{Digest, Sha256};

    let root = repo_root();
    let so = root.join("target/deploy/vault.so");
    assert!(
        so.exists(),
        "{} is missing — run `bash scripts/build-vault-sbf.sh`",
        so.display()
    );

    let manifest = so.with_extension("so.fingerprint");
    let recorded = fs::read_to_string(&manifest).unwrap_or_else(|_| {
        panic!(
            "\n\n{} has no fingerprint manifest at {}.\n\
             The artifact exists but nothing records which source built it, so this \
             suite cannot tell whether it is validating the current program.\n\
             Fix: bash scripts/build-vault-sbf.sh\n",
            so.display(),
            manifest.display()
        )
    });

    let mut features = None;
    let mut recorded_fp = None;
    let mut recorded_binary_sha256 = None;
    for line in recorded.lines() {
        if let Some(v) = line.strip_prefix("features=") {
            features = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("fingerprint=") {
            recorded_fp = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("binary_sha256=") {
            recorded_binary_sha256 = Some(v.trim().to_string());
        }
    }
    let (features, recorded_fp, recorded_binary_sha256) =
        match (features, recorded_fp, recorded_binary_sha256) {
            (Some(f), Some(p), Some(binary)) => (f, p, binary),
            _ => panic!(
                "\n\n{} is malformed (want `features=`, `fingerprint=`, and \
                 `binary_sha256=` lines).\n\
                 Fix: bash scripts/build-vault-sbf.sh\n",
                manifest.display()
            ),
        };

    let current_binary_sha256 = format!("{:x}", Sha256::digest(fs::read(&so).unwrap()));
    assert_eq!(
        recorded_binary_sha256, current_binary_sha256,
        "\n\ntarget/deploy/vault.so does not match its fingerprint manifest. The binary \
         changed after the manifest was written.\n  recorded: {recorded_binary_sha256}\n  \
         current:  {current_binary_sha256}\n\
         Fix: bash scripts/build-vault-sbf.sh\n"
    );

    // The suite exercises `reset_merkle_tree` / `close_vault_config`, which only
    // exist under `devnet-admin` (F-01/F-02 keep them out of a mainnet build).
    // Catch that at load with a clear message rather than as a baffling
    // instruction-not-found failure deep inside a test.
    assert!(
        features.split(',').any(|f| f.trim() == "devnet-admin"),
        "\n\ntarget/deploy/vault.so was built with features '{features}', which omits \
         `devnet-admin`. The LiteSVM suite needs the dev/devnet admin instructions.\n\
         Fix: bash scripts/build-vault-sbf.sh\n"
    );

    // Re-run the single fingerprint definition rather than duplicating it here,
    // so the build side and the check side cannot drift apart.
    let out = Command::new("bash")
        .arg(root.join("scripts/vault-sbf-fingerprint.sh"))
        .arg(&features)
        .current_dir(&root)
        .output()
        .expect("failed to run scripts/vault-sbf-fingerprint.sh");
    assert!(
        out.status.success(),
        "vault-sbf-fingerprint.sh failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let current = String::from_utf8_lossy(&out.stdout).trim().to_string();

    assert_eq!(
        recorded_fp, current,
        "\n\ntarget/deploy/vault.so is STALE — built from different vault source than \
         the tree you are testing.\n  recorded: {recorded_fp}\n  current:  {current}\n\
         Every LiteSVM assertion below would have passed against the wrong binary.\n\
         Fix: bash scripts/build-vault-sbf.sh\n"
    );

    so
}

pub fn fr_to_dec(fr: &Fr) -> String {
    let bi = fr.into_bigint();
    let bytes = bi.to_bytes_be();
    let mut s = num_bigint_decstring(&bytes);
    if s.is_empty() {
        s = "0".to_string();
    }
    s
}

fn num_bigint_decstring(bytes: &[u8]) -> String {
    let mut n: Vec<u32> = Vec::new();
    for &b in bytes {
        let mut carry = b as u64;
        for limb in n.iter_mut() {
            let v = (*limb as u64) * 256 + carry;
            *limb = (v % 1_000_000_000) as u32;
            carry = v / 1_000_000_000;
        }
        while carry > 0 {
            n.push((carry % 1_000_000_000) as u32);
            carry /= 1_000_000_000;
        }
    }
    if n.is_empty() {
        return "0".into();
    }
    let mut out = String::new();
    for (i, limb) in n.iter().rev().enumerate() {
        if i == 0 {
            out.push_str(&limb.to_string());
        } else {
            out.push_str(&format!("{:09}", limb));
        }
    }
    out
}

pub fn dec_to_be32(s: &str) -> [u8; 32] {
    let mut digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
    let mut out = [0u8; 32];
    let mut byte_idx = 32;
    while !digits.is_empty() && byte_idx > 0 {
        let mut rem: u32 = 0;
        let mut new_digits: Vec<u8> = Vec::with_capacity(digits.len());
        for d in &digits {
            let cur = rem * 10 + *d as u32;
            let q = cur / 256;
            rem = cur % 256;
            if !(new_digits.is_empty() && q == 0) {
                new_digits.push(q as u8);
            }
        }
        byte_idx -= 1;
        out[byte_idx] = rem as u8;
        digits = new_digits;
    }
    out
}

pub fn groth16_g1_bytes(v: &serde_json::Value) -> [u8; 64] {
    let x = dec_to_be32(v[0].as_str().unwrap());
    let y = dec_to_be32(v[1].as_str().unwrap());
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&x);
    out[32..64].copy_from_slice(&y);
    out
}

pub fn groth16_g2_bytes(v: &serde_json::Value) -> [u8; 128] {
    let x0 = dec_to_be32(v[0][0].as_str().unwrap());
    let x1 = dec_to_be32(v[0][1].as_str().unwrap());
    let y0 = dec_to_be32(v[1][0].as_str().unwrap());
    let y1 = dec_to_be32(v[1][1].as_str().unwrap());
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&x1);
    out[32..64].copy_from_slice(&x0);
    out[64..96].copy_from_slice(&y1);
    out[96..128].copy_from_slice(&y0);
    out
}

pub fn negate_g1(point: &[u8; 64]) -> [u8; 64] {
    const P_BYTES: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
        0xfd, 0x47,
    ];
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&point[0..32]);
    let mut y = [0u8; 32];
    y.copy_from_slice(&point[32..64]);
    let y_neg = sub_be(&P_BYTES, &y);
    out[32..64].copy_from_slice(&y_neg);
    out
}

fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}

pub struct ProofBytes {
    pub pi_a: [u8; 64],
    pub pi_b: [u8; 128],
    pub pi_c: [u8; 64],
}

/// Build input.json in `tmp`, run snarkjs fullprove, return parsed (proof, public[]).
pub fn snarkjs_fullprove(
    input_json: &str,
    circuit_build_dir: &std::path::Path,
    tmp_dir: &std::path::Path,
) -> (ProofBytes, Vec<[u8; 32]>) {
    fs::create_dir_all(tmp_dir).unwrap();
    let input_path = tmp_dir.join("input.json");
    let proof_path = tmp_dir.join("proof.json");
    let public_path = tmp_dir.join("public.json");
    fs::write(&input_path, input_json).unwrap();

    let wasm = circuit_build_dir.join("circuit_js/circuit.wasm");
    let zkey = circuit_build_dir.join("circuit_final.zkey");
    let root = repo_root();
    let snarkjs = root.join("node_modules/.bin/snarkjs");
    assert!(snarkjs.exists(), "snarkjs missing — run `npm install`");

    let status = Command::new(&snarkjs)
        .arg("groth16")
        .arg("fullprove")
        .arg(&input_path)
        .arg(&wasm)
        .arg(&zkey)
        .arg(&proof_path)
        .arg(&public_path)
        .status()
        .expect("failed to spawn snarkjs");
    assert!(status.success(), "snarkjs fullprove failed");

    let proof_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&proof_path).unwrap()).unwrap();
    let public_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&public_path).unwrap()).unwrap();

    let pi_a = groth16_g1_bytes(&proof_json["pi_a"]);
    let pi_b = groth16_g2_bytes(&proof_json["pi_b"]);
    let pi_c = groth16_g1_bytes(&proof_json["pi_c"]);
    let pi_a_negated = negate_g1(&pi_a);

    let public_inputs: Vec<[u8; 32]> = public_json
        .as_array()
        .unwrap()
        .iter()
        .map(|v| dec_to_be32(v.as_str().unwrap()))
        .collect();

    (
        ProofBytes {
            pi_a: pi_a_negated,
            pi_b,
            pi_c,
        },
        public_inputs,
    )
}

/// Anchor global instruction discriminator = first 8 bytes of sha256("global:<name>").
pub fn anchor_disc(name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"global:");
    h.update(name.as_bytes());
    let out = h.finalize();
    let mut d = [0u8; 8];
    d.copy_from_slice(&out[..8]);
    d
}
