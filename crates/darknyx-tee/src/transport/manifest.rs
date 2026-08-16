//! `TransportAttestationManifestV1` — the canonical wire contract that binds a
//! TLS endpoint identity to a TDX quote (T-03P).
//!
//! # Why this exists
//!
//! `GET /attestation` proves *an* enclave with a given signer set is alive. It
//! does not prove that the TLS connection carrying your orders terminates at
//! that enclave: a party able to terminate TLS can relay a genuine quote while
//! routing traffic elsewhere (the "cuckoo proxy" problem). Closing it means
//! committing the **served certificate's public key** into an attested value.
//!
//! # Why a separate quote, not a change to `/attestation`
//!
//! `report_data` is **per quote**, not a global allocation —
//! `dstack.get_quote(report_data)` accepts up to 64 caller-selected bytes on
//! every call (`dstack/sdk/rust/src/dstack_client.rs`). The existing
//! `nonce ‖ SHA-256(signer set)` layout in `api/attestation.rs` is that
//! endpoint's choice, so this contract coexists with it and **`/attestation`
//! stays byte-for-byte unchanged**. An earlier audit record claimed RA-TLS
//! required a breaking migration; that was wrong and is corrected in
//! `audits/audit_6/tracker.md`.
//!
//! # Layout
//!
//! ```text
//! report_data[0..32]  = caller nonce (exactly 32 bytes)
//! report_data[32..64] = SHA-256(DOMAIN ‖ canonical_bytes())
//! ```
//!
//! `canonical_bytes()` is a fixed-width 164-byte encoding. Every field is
//! fixed-size, so the concatenation is unambiguous — the same property
//! `CRYPTOGRAPHY.md` §9 relies on for the settle payload hash. Variable-length
//! identifiers are folded through SHA-256 into fixed slots rather than being
//! length-prefixed, matching `keys::ed25519::signer_set_hash`.
//!
//! ```text
//! [  0..  2] protocol_version   u16 big-endian
//! [  2..  3] transport_mode     u8
//! [  3..  4] reserved           u8 (MUST be 0)
//! [  4.. 36] sha256(app_id)
//! [ 36.. 68] sha256(instance_id)
//! [ 68..100] boot_session_id
//! [100..132] tls_spki_sha256
//! [132..164] signer_set_sha256
//! ```
//!
//! # Instance linkage
//!
//! `signer_set_sha256` is carried **inside** this manifest deliberately. A
//! client must not verify a transport quote and an `/attestation` quote
//! independently and assume they came from the same enclave — that is exactly
//! the inference a relay exploits. Binding the signer set here means one quote
//! covers "this certificate, this boot, this signer set".
//!
//! # What this does NOT do
//!
//! It does not carry the compose hash. The measured compose stays where it is
//! verifiable — the quote's own event log, replayed against RTMR3
//! (`packages/sdk/src/tee/verify-core.ts`). A manifest field would be a
//! self-report; the event log is not.
//!
//! The TypeScript mirror is `packages/sdk/src/tee/transport-manifest.ts`. Both
//! are pinned by the same fixed vector (`FIXED_VECTOR_DIGEST` here,
//! `FIXED_VECTOR_DIGEST` there) — the four-implementation pattern
//! `canonical_payload_hash` already uses. A drift in either fails both suites.

use sha2::{Digest, Sha256};

/// Domain separation tag. Any change to the field list or its encoding MUST
/// bump the version in this string **and** `PROTOCOL_VERSION`.
pub const DOMAIN: &[u8] = b"darknyx/transport-attestation/v1";

/// Wire version of this manifest. Bump with `DOMAIN`, never alone.
pub const PROTOCOL_VERSION: u16 = 1;

/// Length of `canonical_bytes()`. Asserted in tests so a field addition cannot
/// land without the encoding being revisited.
pub const CANONICAL_LEN: usize = 164;

/// How the client reaches this enclave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportMode {
    /// TLS terminated inside the enclave with a boot-random key, reached
    /// through the dstack gateway's `s`-suffix passthrough route.
    RaTls = 1,
    /// TLS terminated by the dstack gateway. Present so a client can tell the
    /// legacy path apart explicitly rather than by absence; production release
    /// assembly must reject it.
    GatewayTerminated = 2,
}

impl TransportMode {
    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Errors constructing a manifest. Every one is a programming error rather
/// than a client input error, so they are surfaced at construction, not at
/// request time.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("nonce must be exactly 32 bytes, got {0}")]
    NonceLength(usize),
}

/// The bound identity of one TLS endpoint at one boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportManifest {
    pub protocol_version: u16,
    pub transport_mode: TransportMode,
    /// SHA-256 of the dstack `app_id` bytes.
    pub app_id_sha256: [u8; 32],
    /// SHA-256 of the dstack `instance_id` bytes.
    pub instance_id_sha256: [u8; 32],
    /// This process's boot session. Changes on every restart, which is what
    /// makes old-boot evidence rejectable.
    pub boot_session_id: [u8; 32],
    /// SHA-256 over the DER `SubjectPublicKeyInfo` of the served certificate.
    /// This is the field the whole contract exists for.
    pub tls_spki_sha256: [u8; 32],
    /// `keys::ed25519::signer_set_hash` over the full ordered K-shard set.
    pub signer_set_sha256: [u8; 32],
}

impl TransportManifest {
    /// Build a manifest, hashing the variable-length dstack identifiers into
    /// their fixed slots.
    pub fn new(
        transport_mode: TransportMode,
        app_id: &[u8],
        instance_id: &[u8],
        boot_session_id: [u8; 32],
        tls_spki_sha256: [u8; 32],
        signer_set_sha256: [u8; 32],
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            transport_mode,
            app_id_sha256: Sha256::digest(app_id).into(),
            instance_id_sha256: Sha256::digest(instance_id).into(),
            boot_session_id,
            tls_spki_sha256,
            signer_set_sha256,
        }
    }

    /// The fixed-width canonical encoding. See the module docs for the layout.
    pub fn canonical_bytes(&self) -> [u8; CANONICAL_LEN] {
        let mut out = [0u8; CANONICAL_LEN];
        out[0..2].copy_from_slice(&self.protocol_version.to_be_bytes());
        out[2] = self.transport_mode.as_u8();
        out[3] = 0; // reserved
        out[4..36].copy_from_slice(&self.app_id_sha256);
        out[36..68].copy_from_slice(&self.instance_id_sha256);
        out[68..100].copy_from_slice(&self.boot_session_id);
        out[100..132].copy_from_slice(&self.tls_spki_sha256);
        out[132..164].copy_from_slice(&self.signer_set_sha256);
        out
    }

    /// `SHA-256(DOMAIN ‖ canonical_bytes())` — the value that goes into the
    /// right half of `report_data`.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(self.canonical_bytes());
        h.finalize().into()
    }

    /// Assemble the 64-byte `report_data` for `dstack.get_quote`.
    ///
    /// The nonce must be exactly 32 bytes. `/attestation` tolerates a short
    /// nonce by zero-padding; this contract does not, because a client that
    /// sends 4 bytes and believes it has 32 bytes of replay protection is
    /// wrong in a way padding would hide.
    pub fn report_data(&self, nonce: &[u8]) -> Result<[u8; 64], ManifestError> {
        if nonce.len() != 32 {
            return Err(ManifestError::NonceLength(nonce.len()));
        }
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(nonce);
        rd[32..].copy_from_slice(&self.digest());
        Ok(rd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic fixture. The TS mirror builds the identical manifest.
    fn fixture() -> TransportManifest {
        TransportManifest::new(
            TransportMode::RaTls,
            b"darknyx-test-app",
            b"darknyx-test-instance",
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
        )
    }

    /// **The cross-language pin.** `packages/sdk/tests/transport-manifest-parity.test.ts`
    /// asserts this exact hex. Changing the encoding without changing both is
    /// the failure mode `canonical_payload_hash` exists to prevent.
    const FIXED_VECTOR_DIGEST: &str =
        "d04907e53cd58635b7cf589c8eb4c331be1d1ff83ca57339d679e67a474427c1";

    #[test]
    fn canonical_encoding_is_exactly_164_bytes() {
        // Guards the layout: a new field cannot be appended without this
        // failing and forcing the version + domain bump.
        assert_eq!(fixture().canonical_bytes().len(), CANONICAL_LEN);
        assert_eq!(CANONICAL_LEN, 164);
    }

    #[test]
    fn canonical_layout_places_each_field_where_documented() {
        let m = fixture();
        let b = m.canonical_bytes();
        assert_eq!(&b[0..2], &1u16.to_be_bytes());
        assert_eq!(b[2], TransportMode::RaTls as u8);
        assert_eq!(b[3], 0, "reserved byte must be zero");
        assert_eq!(&b[4..36], &m.app_id_sha256);
        assert_eq!(&b[36..68], &m.instance_id_sha256);
        assert_eq!(&b[68..100], &m.boot_session_id);
        assert_eq!(&b[100..132], &m.tls_spki_sha256);
        assert_eq!(&b[132..164], &m.signer_set_sha256);
    }

    #[test]
    fn fixed_vector_matches_the_typescript_mirror() {
        assert_eq!(hex::encode(fixture().digest()), FIXED_VECTOR_DIGEST);
    }

    #[test]
    fn every_field_is_bound_independently() {
        // The test that would have caught a manifest which "looks bound" but
        // leaves a field free for a prover to choose.
        let base = fixture().digest();

        let cases: Vec<(&str, TransportManifest)> = vec![
            (
                "app_id",
                TransportManifest::new(
                    TransportMode::RaTls,
                    b"OTHER-app",
                    b"darknyx-test-instance",
                    [0x11; 32],
                    [0x22; 32],
                    [0x33; 32],
                ),
            ),
            (
                "instance_id",
                TransportManifest::new(
                    TransportMode::RaTls,
                    b"darknyx-test-app",
                    b"OTHER-instance",
                    [0x11; 32],
                    [0x22; 32],
                    [0x33; 32],
                ),
            ),
            (
                "boot_session_id",
                TransportManifest::new(
                    TransportMode::RaTls,
                    b"darknyx-test-app",
                    b"darknyx-test-instance",
                    [0x99; 32],
                    [0x22; 32],
                    [0x33; 32],
                ),
            ),
            (
                "tls_spki_sha256",
                TransportManifest::new(
                    TransportMode::RaTls,
                    b"darknyx-test-app",
                    b"darknyx-test-instance",
                    [0x11; 32],
                    [0x99; 32],
                    [0x33; 32],
                ),
            ),
            (
                "signer_set_sha256",
                TransportManifest::new(
                    TransportMode::RaTls,
                    b"darknyx-test-app",
                    b"darknyx-test-instance",
                    [0x11; 32],
                    [0x22; 32],
                    [0x99; 32],
                ),
            ),
            (
                "transport_mode",
                TransportManifest::new(
                    TransportMode::GatewayTerminated,
                    b"darknyx-test-app",
                    b"darknyx-test-instance",
                    [0x11; 32],
                    [0x22; 32],
                    [0x33; 32],
                ),
            ),
        ];

        for (field, perturbed) in cases {
            assert_ne!(
                perturbed.digest(),
                base,
                "perturbing {field} did not change the digest — it is not bound"
            );
        }
    }

    #[test]
    fn protocol_version_is_bound() {
        let mut m = fixture();
        let base = m.digest();
        m.protocol_version = 2;
        assert_ne!(m.digest(), base, "protocol_version is not bound");
    }

    #[test]
    fn a_different_domain_yields_a_different_digest() {
        // Proves DOMAIN is load-bearing: a quote minted under this contract
        // cannot be replayed as one minted under another.
        let m = fixture();
        let mut h = Sha256::new();
        h.update(b"darknyx/transport-attestation/v2");
        h.update(m.canonical_bytes());
        let other: [u8; 32] = h.finalize().into();
        assert_ne!(other, m.digest());
    }

    #[test]
    fn report_data_places_nonce_left_and_digest_right() {
        let m = fixture();
        let nonce = [0xAB; 32];
        let rd = m.report_data(&nonce).expect("32-byte nonce");
        assert_eq!(&rd[..32], &nonce);
        assert_eq!(&rd[32..], &m.digest());
    }

    #[test]
    fn report_data_rejects_a_nonce_that_is_not_exactly_32_bytes() {
        let m = fixture();
        for len in [0usize, 4, 31, 33, 64] {
            assert_eq!(
                m.report_data(&vec![0u8; len]),
                Err(ManifestError::NonceLength(len)),
                "a {len}-byte nonce was accepted"
            );
        }
    }

    #[test]
    fn signer_set_ordering_changes_the_digest() {
        // signer_set_sha256 comes from keys::ed25519::signer_set_hash, which
        // concatenates in shard order. Reordering must not be absorbed here.
        let a: [u8; 32] = Sha256::digest([b"pk0".as_ref(), b"pk1".as_ref()].concat()).into();
        let b: [u8; 32] = Sha256::digest([b"pk1".as_ref(), b"pk0".as_ref()].concat()).into();
        assert_ne!(a, b, "fixture precondition: the two orderings differ");

        let m = |set: [u8; 32]| {
            TransportManifest::new(
                TransportMode::RaTls,
                b"darknyx-test-app",
                b"darknyx-test-instance",
                [0x11; 32],
                [0x22; 32],
                set,
            )
            .digest()
        };
        assert_ne!(m(a), m(b));
    }
}
