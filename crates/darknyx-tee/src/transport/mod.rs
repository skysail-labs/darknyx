//! Transport-integrity contracts (T-03P).
//!
//! Layer 1 of the RA-TLS work: the canonical manifest that binds a served TLS
//! certificate, the boot session, and the full signer set into one attested
//! value. The listener that mints and serves it lands in the next layer.
//!
//! Design record: `docs/transport-integrity-remediation-plan.md` §7;
//! evidence: `docs/transport-integrity-plan.md`.

pub mod identity;
pub mod manifest;

pub use identity::{IdentityError, TransportIdentity};
pub use manifest::{
    ManifestError, TransportManifest, TransportMode, CANONICAL_LEN, DOMAIN, PROTOCOL_VERSION,
};
