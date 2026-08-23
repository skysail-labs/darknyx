//! Transport integrity — RA-TLS.
//!
//! The enclave terminates TLS itself with a boot-random key bound into its
//! attestation quote, so a client can verify it is talking to *this* enclave before
//! sending a credential. The gateway bridges raw TCP rather than terminating TLS.
//!
//!   - [`identity`] — the boot-random key and self-signed certificate.
//!   - [`manifest`] — the canonical manifest binding the served certificate, the
//!     boot session, and the full signer set into one attested value.
//!   - [`server`] — [`build_server_config`], the rustls configuration `main.rs`
//!     installs when `DARKNYX_TEE_TRANSPORT_MODE=ra-tls`.
//!
//! **The served certificate is self-signed by design.** Clients verify it against
//! `GET /transport-attestation` and must not fall back to a CA check;
//! `NODE_TLS_REJECT_UNAUTHORIZED=0` is never the fix, since it accepts any
//! certificate from anyone while still reporting as RA-TLS.
//!
//! The plaintext listener still binds inside the enclave; only its port publication
//! is gone. Rolling back requires setting `gateway-terminated` *and* restoring the
//! `8080:8080` publication together — `scripts/check-ratls-cutover.sh` fails the
//! build if the two move independently, in either direction.
//!
//! Design and evidence record: `docs/transport-integrity-remediation-plan.md`.

pub mod identity;
pub mod manifest;
pub mod server;

pub use identity::{IdentityError, TransportIdentity};
pub use manifest::{
    ManifestError, TransportManifest, TransportMode, CANONICAL_LEN, DOMAIN, PROTOCOL_VERSION,
};
pub use server::{build_server_config, ServerConfigError};
