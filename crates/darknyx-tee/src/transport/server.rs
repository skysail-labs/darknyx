//! rustls server configuration for the in-enclave RA-TLS listener (T-03P).
//!
//! # TLS 1.3 only
//!
//! TLS 1.2 is disabled deliberately. Every client on this path is one we
//! write — the Node SDK, the daemon, the loadgen, and trader-host's upstream —
//! so there is no legacy peer to accommodate, and each protocol version left
//! enabled is downgrade surface for no benefit. This is the one place where
//! "narrow" costs nothing.
//!
//! # No client authentication
//!
//! The server does not request a client certificate. Authentication of the
//! *client* is the existing bearer-token layer's job; what this listener adds
//! is authentication of the *server* to the client, which is the direction
//! T-03 is about. Asking for a client certificate here would imply a mutual
//! guarantee the deployment does not have.
//!
//! # Why the certificate is not a chain
//!
//! It is self-signed and carries no issuer a public root store would accept —
//! on purpose. A client on this path must not fall back to WebPKI validation;
//! it verifies the SPKI against a quote-bound manifest
//! (`super::manifest`). A client that accepts this certificate because a CA
//! vouched for it has verified nothing relevant.

use std::sync::Arc;

use rustls::{pki_types::CertificateDer, pki_types::PrivateKeyDer, ServerConfig};

use super::identity::TransportIdentity;

#[derive(Debug, thiserror::Error)]
pub enum ServerConfigError {
    #[error("rustls rejected the boot-scoped certificate/key: {0}")]
    Rustls(String),
    #[error("failed to install the ring crypto provider")]
    Provider,
}

/// Build a TLS 1.3-only `ServerConfig` presenting this boot's certificate.
///
/// The identity passed here MUST be the same one wired into `ApiState` — the
/// entire contract is that the attested SPKI is the certificate the peer
/// actually sees, so two separately generated identities would produce a quote
/// that verifies against nothing.
pub fn build_server_config(
    identity: &TransportIdentity,
) -> Result<Arc<ServerConfig>, ServerConfigError> {
    // rustls 0.23 requires a process-wide default provider before any config is
    // built. Installing is idempotent-ish: it fails if a *different* provider
    // is already installed, which we treat as fine — someone else already set
    // one up and rustls will use it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert = CertificateDer::from(identity.certificate_der().to_vec());
    let key = PrivateKeyDer::try_from(identity.private_key_der().to_vec())
        .map_err(|e| ServerConfigError::Rustls(e.to_string()))?;

    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| ServerConfigError::Rustls(e.to_string()))?;

    // h2 first, then http/1.1. axum speaks both; offering h2 keeps the
    // WebSocket-adjacent request volume on one connection.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_config_from_a_generated_identity() {
        let id = TransportIdentity::generate().expect("identity");
        let cfg = build_server_config(&id).expect("server config");
        assert!(!cfg.alpn_protocols.is_empty());
    }

    // TLS-version policy and the SPKI-on-the-wire invariant are asserted
    // behaviourally in `tests/transport_tls_handshake.rs`: rustls 0.23 exposes
    // no public accessor for a built config's protocol versions or client-auth
    // policy, and a real handshake is the stronger evidence anyway.

    #[test]
    fn alpn_offers_h2_and_http11_in_that_order() {
        let id = TransportIdentity::generate().expect("identity");
        let cfg = build_server_config(&id).expect("server config");
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn each_boot_serves_a_different_certificate() {
        // Ties the config back to the boot-random property: two identities
        // produce two distinct served certificates.
        let a = TransportIdentity::generate().expect("a");
        let b = TransportIdentity::generate().expect("b");
        assert_ne!(a.certificate_der(), b.certificate_der());
        assert!(build_server_config(&a).is_ok());
        assert!(build_server_config(&b).is_ok());
    }
}
