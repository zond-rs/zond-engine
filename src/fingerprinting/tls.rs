// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # TLS transport
//!
//! The I/O half of TLS fingerprinting: complete a handshake against an open port
//! and capture the certificate chain the peer presents. Interpreting that chain
//! is the analyzer's job (see [`TlsCertAnalyzer`]); this module only gathers
//! bytes.
//!
//! ## Why we complete a real handshake
//!
//! In TLS 1.3 the server's `Certificate` message is *encrypted*, so a cert cannot
//! be scraped by parsing raw handshake records — the handshake must actually
//! complete. We therefore run a real rustls client, but with a verifier that
//! [accepts any certificate](AcceptAnyServerCert): a scanner wants the *presented*
//! chain, not a trust decision, and the ports we probe routinely serve expired,
//! self-signed, or wrong-host certs that a validating client would reject before
//! we ever see them.
//!
//! ## Crypto provider
//!
//! We pin the pure-Rust **ring** provider rather than rustls's default
//! `aws-lc-rs`, which needs cmake/NASM at build time and is a known Windows-build
//! friction point for a cross-platform product.
//!
//! [`TlsCertAnalyzer`]: super::tls_cert::TlsCertAnalyzer

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::response::TlsInfo;

/// How long to wait for a handshake on a port where we *expect* TLS (an
/// implicit-TLS port). Patient: a handshake is the whole point here, worth
/// waiting out a slow server.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// A tighter budget for a *speculative* handshake on a silent, non-standard
/// port. The prior probability of TLS there is low, and a real TLS server on a
/// reachable open port completes well under a second; the extra patience would
/// mostly buy tarpits. Since this is paid on every silent port, it is where
/// latency blast-radius on a many-port host concentrates.
const SPECULATIVE_TLS_TIMEOUT: Duration = Duration::from_millis(1_500);

/// Ports that speak TLS immediately on connect (no `STARTTLS` upgrade), where we
/// go straight to a handshake instead of waiting for a plaintext banner that
/// will never come.
const IMPLICIT_TLS_PORTS: &[u16] = &[
    443,  // https
    465,  // smtps
    636,  // ldaps
    989,  // ftps-data
    990,  // ftps
    993,  // imaps
    995,  // pop3s
    2376, // docker over tls
    5061, // sip-tls
    5671, // amqps
    5986, // winrm https
    6697, // ircs
    8443, // https-alt
    8883, // mqtts
];

/// Whether `port` is a well-known implicit-TLS port.
pub fn is_tls_port(port: u16) -> bool {
    IMPLICIT_TLS_PORTS.contains(&port)
}

/// A certificate verifier that accepts everything.
///
/// Sound **only** because we are fingerprinting, not establishing a trusted
/// channel: we complete the handshake purely to read the presented chain and
/// send no sensitive data over it. Never reuse this config for a real client.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Advertise the common schemes so servers pick one we will "verify".
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// The process-wide connector, built once. The rustls config is immutable and
/// internally reference-counted, so every handshake shares it cheaply.
fn connector() -> &'static TlsConnector {
    static CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();
    CONNECTOR.get_or_init(|| {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    })
}

/// Handshake on a port where TLS is *expected* — an implicit-TLS port. Patient
/// (see [`TLS_HANDSHAKE_TIMEOUT`]).
pub async fn handshake(stream: TcpStream, peer: IpAddr) -> Option<TlsInfo> {
    handshake_within(stream, peer, TLS_HANDSHAKE_TIMEOUT).await
}

/// *Speculative* handshake on a silent, un-probed port that might be TLS on a
/// non-standard port. Tighter budget (see [`SPECULATIVE_TLS_TIMEOUT`]) because
/// the prior is low and this cost is paid on every silent port.
pub async fn speculative_handshake(stream: TcpStream, peer: IpAddr) -> Option<TlsInfo> {
    handshake_within(stream, peer, SPECULATIVE_TLS_TIMEOUT).await
}

/// Completes a TLS handshake over `stream` within `budget` and returns the
/// certificate chain the peer presented, as owned DER.
///
/// `peer` is the address we connected to; it becomes the rustls server name.
/// Because we scan by IP, no SNI is sent and the accept-any verifier makes the
/// name irrelevant to whether the handshake completes — we take whatever
/// certificate the default virtual host serves. Returns `None` on timeout,
/// handshake failure, or if the peer presented no certificate.
async fn handshake_within(stream: TcpStream, peer: IpAddr, budget: Duration) -> Option<TlsInfo> {
    let server_name = ServerName::IpAddress(peer.into());
    let connect = connector().connect(server_name, stream);

    let tls = timeout(budget, connect).await.ok()?.ok()?;

    let (_, conn) = tls.get_ref();
    let certificates: Vec<Vec<u8>> = conn
        .peer_certificates()?
        .iter()
        .map(|der| der.as_ref().to_vec())
        .collect();

    (!certificates.is_empty()).then_some(TlsInfo { certificates })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implicit_tls_ports_are_recognised() {
        assert!(is_tls_port(443));
        assert!(is_tls_port(993));
        assert!(!is_tls_port(80));
        assert!(!is_tls_port(22));
    }

    #[test]
    fn connector_builds_with_ring_provider() {
        // Exercises the accept-any config + ring provider path; a panic here
        // would mean the process cannot perform any TLS fingerprinting.
        let _ = connector();
    }
}
