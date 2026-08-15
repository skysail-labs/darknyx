//! Real TLS handshakes against the RA-TLS server config (T-03P).
//!
//! # Why these are integration tests, not unit tests
//!
//! rustls 0.23 exposes no public accessor for a built `ServerConfig`'s protocol
//! versions or client-auth policy, so the version policy cannot be asserted by
//! inspection. It can be asserted by *behaviour*, which is stronger evidence
//! anyway: a TLS 1.2-only client must fail to connect.
//!
//! # The invariant that matters
//!
//! `a_client_sees_exactly_the_attested_spki_on_the_wire` is the whole point of
//! the RA-TLS work. It proves that the SPKI hash bound into the transport quote
//! is the one a peer actually observes on its socket. Everything else in T-03P
//! is built on that equality holding; if it ever stopped holding, a client
//! would verify a quote against a certificate nobody serves.

use std::sync::Arc;

use darknyx_tee::transport::{build_server_config, TransportIdentity};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Accepts any server certificate without validation.
///
/// This is correct for these tests and correct for a real RA-TLS client too:
/// the certificate is self-signed, so WebPKI validation is meaningless. The
/// real check is comparing the observed SPKI against a quote-bound manifest,
/// which is exactly what the SPKI test below does by hand.
#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn client_config(versions: &[&'static rustls::SupportedProtocolVersion]) -> ClientConfig {
    install_provider();
    ClientConfig::builder_with_protocol_versions(versions)
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth()
}

/// Spawn a one-shot TLS echo server on an ephemeral port.
async fn spawn_server(identity: &TransportIdentity) -> std::net::SocketAddr {
    let cfg = build_server_config(identity).expect("server config");
    let acceptor = TlsAcceptor::from(cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        // Serve a bounded number of connections so a failing test cannot leave
        // a task looping forever.
        for _ in 0..4u8 {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let _ = tls.write_all(b"ok").await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });

    addr
}

#[tokio::test]
async fn a_client_sees_exactly_the_attested_spki_on_the_wire() {
    // THE test. The SPKI hash bound into the transport quote must be the one a
    // peer observes on its own socket. If this equality breaks, every client
    // would be verifying a quote against a certificate nobody serves.
    let identity = TransportIdentity::generate().expect("identity");
    let attested = identity.spki_sha256();
    let addr = spawn_server(&identity).await;

    let connector = TlsConnector::from(Arc::new(client_config(&[&rustls::version::TLS13])));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS 1.3 handshake should succeed");

    let (_, conn) = tls.get_ref();
    let chain = conn
        .peer_certificates()
        .expect("server presented no certificate");
    assert_eq!(chain.len(), 1, "expected a single self-signed certificate");

    // Recompute the SPKI hash from the certificate the CLIENT received, using
    // the same substring relationship the identity module asserts. Finding the
    // attested SPKI inside the observed certificate is the equality under test.
    let observed_cert = chain[0].as_ref();
    let spki = identity.spki_der();
    assert!(
        observed_cert.windows(spki.len()).any(|w| w == spki),
        "the attested SPKI is not present in the certificate the client received"
    );
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(spki)),
        attested,
        "spki_sha256 does not match the SPKI observed on the wire"
    );
}

#[tokio::test]
async fn a_tls12_only_client_cannot_connect() {
    // The downgrade-surface guard. Asserted behaviourally because rustls
    // exposes no accessor for a built config's version list.
    let identity = TransportIdentity::generate().expect("identity");
    let addr = spawn_server(&identity).await;

    let connector = TlsConnector::from(Arc::new(client_config(&[&rustls::version::TLS12])));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let result = connector.connect(server_name, tcp).await;

    assert!(
        result.is_err(),
        "a TLS 1.2-only client completed a handshake — TLS 1.2 is enabled"
    );
}

#[tokio::test]
async fn the_connection_actually_carries_data() {
    // Guards the two tests above from passing against a server that accepts a
    // handshake and then does nothing useful.
    let identity = TransportIdentity::generate().expect("identity");
    let addr = spawn_server(&identity).await;

    let connector = TlsConnector::from(Arc::new(client_config(&[&rustls::version::TLS13])));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("handshake");

    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.expect("read");
    assert_eq!(&buf, b"ok");
}

#[tokio::test]
async fn two_boots_present_different_certificates_to_a_client() {
    // The boot-random property, observed from the client side rather than
    // inferred from the identity struct.
    let a = TransportIdentity::generate().expect("a");
    let b = TransportIdentity::generate().expect("b");
    let addr_a = spawn_server(&a).await;
    let addr_b = spawn_server(&b).await;

    let connector = TlsConnector::from(Arc::new(client_config(&[&rustls::version::TLS13])));
    let server_name = ServerName::try_from("localhost").expect("server name");

    let mut seen = Vec::new();
    for addr in [addr_a, addr_b] {
        let tcp = TcpStream::connect(addr).await.expect("tcp connect");
        let tls = connector
            .connect(server_name.clone(), tcp)
            .await
            .expect("handshake");
        let (_, conn) = tls.get_ref();
        seen.push(conn.peer_certificates().expect("cert")[0].as_ref().to_vec());
    }

    assert_ne!(
        seen[0], seen[1],
        "two independently generated identities served the same certificate"
    );
}
