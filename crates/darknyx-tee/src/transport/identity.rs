//! The boot-scoped RA-TLS identity (T-03P).
//!
//! One self-signed certificate per process boot, whose SPKI is bound into the
//! transport-attestation quote (`super::manifest`).
//!
//! # Why the key must be boot-random
//!
//! This is the single most important property in this module, and it exists
//! because of a concrete defect found upstream.
//!
//! dstack's own gateway generates its TLS key once, **persists it in a
//! distributed KV store**, and reloads it on later boots without minting a
//! fresh quote (`dstack/gateway/src/distributed_certbot.rs`,
//! `main_service.rs`). Its certificate quote therefore proves where the key was
//! *generated*, not which process is *serving* it — a different or downgraded
//! build holding that key serves TLS while replaying historical evidence. See
//! `docs/transport-integrity-plan.md` §4.
//!
//! Two things follow, and both are enforced here:
//!
//! 1. **Never persist the key.** It lives in process memory and dies with the
//!    process. There is no file, no volume, no journal entry, no env var.
//! 2. **Never derive it from `dstack.get_key()`.** That KDF is deliberately
//!    *stable* for an application identity, and an `app_id` survives compose
//!    changes — so a later, differently-measured build would derive the same
//!    key. That is the same failure with extra steps.
//!
//! The key comes from the OS CSPRNG (via `rcgen`/`ring`) at every boot. A
//! restart is a new identity, which is what makes old-boot evidence rejectable.
//!
//! # On the certificate's validity window
//!
//! `notAfter` is **not** the security boundary here and should not be read as
//! one. A client on this path does not do WebPKI validation — the certificate
//! is self-signed and carries no chain — it verifies the SPKI against an
//! attested manifest bound to `boot_session_id`. The real lifetime is the
//! process boot.
//!
//! So the window is set generously rather than tightly. A short `notAfter`
//! would add an availability failure mode (a long-running CVM's certificate
//! expiring mid-flight) while adding no security, because an attacker holding
//! the key already fails the attestation check regardless of the date.

use rcgen::{DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};

/// Certificate lifetime in days. See the module note — this bounds nothing
/// security-relevant; the boot session does.
const VALIDITY_DAYS: i64 = 397;

/// Subject/issuer CN. Cosmetic: nothing verifies it, because nothing on this
/// path does name validation.
const SUBJECT_CN: &str = "darknyx-tee ra-tls (boot-scoped)";

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("failed to generate the RA-TLS key pair: {0}")]
    KeyGeneration(String),
    #[error("failed to self-sign the RA-TLS certificate: {0}")]
    Certificate(String),
    #[error("generated certificate does not contain the key's SPKI — refusing to serve it")]
    SpkiNotInCertificate,
}

/// A self-signed certificate and its private key, valid for this process only.
///
/// `Debug` is implemented by hand so the private key can never reach a log line
/// through a stray `{:?}`.
pub struct TransportIdentity {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    spki_der: Vec<u8>,
    spki_sha256: [u8; 32],
}

impl std::fmt::Debug for TransportIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Public fingerprint only. Never the key, never the DER.
        f.debug_struct("TransportIdentity")
            .field("spki_sha256", &hex::encode(self.spki_sha256))
            .field("cert_len", &self.cert_der.len())
            .finish_non_exhaustive()
    }
}

impl TransportIdentity {
    /// Generate a fresh identity from the OS CSPRNG.
    ///
    /// ECDSA P-256 rather than Ed25519: it is universally supported by TLS 1.3
    /// implementations including every rustls crypto provider, whereas Ed25519
    /// server authentication is not uniformly available. Both satisfy the
    /// contract; P-256 avoids a provider-dependent failure.
    pub fn generate() -> Result<Self, IdentityError> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| IdentityError::KeyGeneration(e.to_string()))?;

        // Take the SPKI from the key pair, then prove below that this exact
        // encoding is what the certificate carries. Deriving it in parallel and
        // assuming they agree is the shape of bug this whole workstream keeps
        // finding.
        let spki_der = key_pair.public_key_der();

        let mut params = rcgen::CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, SUBJECT_CN);
        params.distinguished_name = dn;
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        let (y, m, d) = civil_from_days(unix_day_today() + VALIDITY_DAYS);
        params.not_after = rcgen::date_time_ymd(y, m, d);

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| IdentityError::Certificate(e.to_string()))?;

        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        // The invariant the manifest depends on: the hash we attest must be of
        // the SPKI actually inside the certificate we serve. A DER SPKI is a
        // contiguous substring of the TBSCertificate, so this is a real check,
        // not a formality.
        if !contains_subslice(&cert_der, &spki_der) {
            return Err(IdentityError::SpkiNotInCertificate);
        }

        let spki_sha256: [u8; 32] = Sha256::digest(&spki_der).into();

        Ok(Self {
            cert_der,
            key_der,
            spki_der,
            spki_sha256,
        })
    }

    /// DER of the self-signed certificate, for the TLS server config.
    pub fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// DER of the private key, for the TLS server config **only**.
    ///
    /// Deliberately not `Clone`/`Serialize`/`Display`. Callers hand it straight
    /// to rustls and do not retain it.
    pub fn private_key_der(&self) -> &[u8] {
        &self.key_der
    }

    /// DER `SubjectPublicKeyInfo` of the served certificate.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// `SHA-256(spki_der)` — the value bound into the transport manifest.
    pub fn spki_sha256(&self) -> [u8; 32] {
        self.spki_sha256
    }

    /// Lowercase-hex fingerprint. The only form safe to log.
    pub fn fingerprint(&self) -> String {
        hex::encode(self.spki_sha256)
    }
}

impl Drop for TransportIdentity {
    fn drop(&mut self) {
        // Best-effort scrub. `rcgen`/`ring` keep their own copies of the key
        // material that we cannot reach, so this narrows the window rather than
        // closing it — stated plainly rather than claimed as zeroization.
        self.key_der.iter_mut().for_each(|b| *b = 0);
    }
}

/// Whole days since the Unix epoch. rcgen wants a calendar date, and computing
/// it this way keeps the identity path free of a date dependency.
fn unix_day_today() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64 / 86_400)
        .unwrap_or(0)
}

/// Howard Hinnant's `civil_from_days` — days since the Unix epoch to (y, m, d).
/// Self-contained so the identity path needs no date dependency.
fn civil_from_days(z: i64) -> (i32, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    ((y + i64::from(m <= 2)) as i32, m, d)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_usable_certificate_and_key() {
        let id = TransportIdentity::generate().expect("generate");
        assert!(!id.certificate_der().is_empty());
        assert!(!id.private_key_der().is_empty());
        assert_eq!(id.spki_sha256().len(), 32);
    }

    #[test]
    fn the_attested_spki_is_the_one_inside_the_served_certificate() {
        // The invariant the whole contract rests on. If this ever fails, the
        // manifest would be attesting a key the server does not present.
        let id = TransportIdentity::generate().expect("generate");
        assert!(
            contains_subslice(id.certificate_der(), id.spki_der()),
            "the SPKI we hash is not present in the certificate we serve"
        );
        assert_eq!(
            id.spki_sha256(),
            <[u8; 32]>::from(Sha256::digest(id.spki_der())),
            "spki_sha256 is not the digest of spki_der"
        );
    }

    #[test]
    fn every_boot_produces_a_different_identity() {
        // The property that makes old-boot evidence rejectable, and the one
        // dstack's gateway does NOT have (see the module docs).
        let a = TransportIdentity::generate().expect("a");
        let b = TransportIdentity::generate().expect("b");
        assert_ne!(a.spki_sha256(), b.spki_sha256());
        assert_ne!(a.certificate_der(), b.certificate_der());
        assert_ne!(a.private_key_der(), b.private_key_der());
    }

    #[test]
    fn generation_is_not_derived_from_any_stable_input() {
        // Ten identities, ten distinct keys. A deterministic KDF (the
        // dstack.get_key() mistake) would collapse these.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            let id = TransportIdentity::generate().expect("generate");
            assert!(
                seen.insert(id.spki_sha256()),
                "a repeated SPKI means the key is not boot-random"
            );
        }
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let id = TransportIdentity::generate().expect("generate");
        let rendered = format!("{id:?}");
        assert!(rendered.contains("spki_sha256"));
        assert!(
            !rendered.contains(&hex::encode(id.private_key_der())),
            "Debug leaked the private key"
        );
        // Also guard the raw-byte rendering a derived Debug would have emitted.
        assert!(
            !rendered.contains(&format!("{:?}", id.private_key_der())),
            "Debug leaked the private key bytes"
        );
    }

    #[test]
    fn fingerprint_is_the_hex_spki_digest() {
        let id = TransportIdentity::generate().expect("generate");
        assert_eq!(id.fingerprint(), hex::encode(id.spki_sha256()));
        assert_eq!(id.fingerprint().len(), 64);
    }

    #[test]
    fn civil_from_days_matches_known_dates() {
        // Pins the hand-rolled date maths so a wrong notAfter cannot slip in.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(20_454), (2026, 1, 1));
    }

    #[test]
    fn contains_subslice_rejects_the_degenerate_cases() {
        // Guards the SPKI check itself: an always-true helper would make
        // `the_attested_spki_is_...` vacuous.
        assert!(!contains_subslice(b"abc", b""));
        assert!(!contains_subslice(b"abc", b"abcd"));
        assert!(!contains_subslice(b"abc", b"xyz"));
        assert!(contains_subslice(b"abcdef", b"cde"));
    }
}
