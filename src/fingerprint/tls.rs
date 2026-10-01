// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # TLS transport
//!
//! The I/O half of TLS fingerprinting: complete a handshake against an open port
//! and capture the certificate chain the peer presents. [`TlsCertAnalyzer`]
//! interprets it.
//!
//! ## A real handshake
//!
//! In TLS 1.3 the server's `Certificate` message is encrypted, so the handshake
//! must complete. The rustls client uses a verifier that
//! [accepts any certificate](AcceptAnyServerCert), since scanned ports routinely
//! serve expired, self-signed or wrong-host certificates.
//!
//! ## Crypto provider
//!
//! The **ring** provider is pinned; rustls's default `aws-lc-rs` needs
//! cmake/NASM at build time, which is a problem on Windows.
//!
//! [`TlsCertAnalyzer`]: super::tls_cert::TlsCertAnalyzer

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::response::TlsInfo;

/// A completed TLS client tunnel over a TCP socket. The transport reads and
/// probes *through* this to fingerprint the protocol carried inside.
pub type TlsTunnel = tokio_rustls::client::TlsStream<TcpStream>;

/// How long to wait for a handshake on an implicit-TLS port, where TLS is
/// expected.
pub(super) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// A tighter budget for a *speculative* handshake on a silent, non-standard
/// port. A real TLS server completes well under a second, and this is paid on
/// every silent port.
pub(super) const SPECULATIVE_TLS_TIMEOUT: Duration = Duration::from_millis(1_500);

/// Ports that speak TLS immediately on connect (no `STARTTLS`), so the handshake
/// starts without waiting for a banner.
const IMPLICIT_TLS_PORTS: &[u16] = &[
    443,  // https
    465,  // smtps
    636,  // ldaps
    989,  // ftps-data
    990,  // ftps
    993,  // imaps
    995,  // pop3s
    2376, // docker over tls
    3269, // ldaps, the Active Directory global catalog
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
/// Sound **only** for fingerprinting: the handshake reads the presented chain
/// and carries no sensitive data. Never reuse this config for a real client.
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
        // Advertise the common schemes so servers pick one.
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

/// Handshake on a port where TLS is *expected*, an implicit-TLS port. Patient
/// (see [`TLS_HANDSHAKE_TIMEOUT`]).
pub async fn handshake(
    stream: TcpStream,
    server: ServerName<'static>,
) -> Option<(TlsTunnel, TlsInfo)> {
    handshake_within(stream, server, TLS_HANDSHAKE_TIMEOUT).await
}

/// *Speculative* handshake on a silent, unprobed port that might be TLS. Tighter
/// budget (see [`SPECULATIVE_TLS_TIMEOUT`]).
pub async fn speculative_handshake(
    stream: TcpStream,
    server: ServerName<'static>,
) -> Option<(TlsTunnel, TlsInfo)> {
    handshake_within(stream, server, SPECULATIVE_TLS_TIMEOUT).await
}

/// Completes a TLS handshake over `stream` within `budget`, which allows for
/// the path (see [`on_path`](super::on_path)), returning the live tunnel and
/// the certificate chain the peer presented (owned DER).
///
/// `server` comes from
/// [`Authority::server_name`](super::authority::Authority::server_name): a name
/// goes on the wire as SNI, an address sends none. A server with several sites
/// picks the certificate by it, and without it returns the default site's or
/// refuses.
///
/// The tunnel is returned so the caller can probe through it. The chain may be
/// empty (anonymous handshake). Returns `None` only on timeout or handshake
/// failure.
async fn handshake_within(
    stream: TcpStream,
    server: ServerName<'static>,
    budget: Duration,
) -> Option<(TlsTunnel, TlsInfo)> {
    let connect = connector().connect(server, stream);

    let given = super::on_path(budget);
    let Ok(done) = timeout(given, connect).await else {
        // Reported like a read that heard nothing.
        super::tell(|tally| tally.ran_out(given));
        return None;
    };
    let tls = done.ok()?;

    let connection = tls.get_ref().1;

    let certificates: Vec<Vec<u8>> = connection
        .peer_certificates()
        .unwrap_or(&[])
        .iter()
        .map(|der| der.as_ref().to_vec())
        .collect();

    // Only available while the connection is live.
    let version = protocol_version_name(connection.protocol_version());
    let cipher_suite = connection
        .negotiated_cipher_suite()
        .and_then(|suite| suite.suite().as_str());
    let alpn = connection
        .alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned());

    Some((
        tls,
        TlsInfo {
            certificates,
            version,
            cipher_suite,
            alpn,
        },
    ))
}

/// How long to wait on the legacy probe.
///
/// Used only after a modern handshake has failed on the port.
pub(super) const LEGACY_PROBE_TIMEOUT: Duration = Duration::from_millis(1_500);

/// A ClientHello offering the versions rustls will not.
///
/// Fixed bytes: TLS 1.0, six RSA and 3DES suites legacy servers implement, null
/// compression, a fixed random, and **no extension block**, which is what an
/// SSLv3-era stack expects.
const LEGACY_CLIENT_HELLO: &[u8] = &[
    // Record: handshake, TLS 1.0, 55 bytes.
    // Handshake: client hello, 51 bytes, offering TLS 1.0.
    // Then a fixed 32-byte random, no session to resume, six cipher suites a
    // legacy server actually implements, and null compression.
    0x16, 0x03, 0x01, 0x00, 0x37, 0x01, 0x00, 0x00, 0x33, 0x03, 0x01, 0x5a, 0x0d, 0x00, 0x00, 0x5a,
    0x0d, 0x00, 0x00, 0x5a, 0x0d, 0x00, 0x00, 0x5a, 0x0d, 0x00, 0x00, 0x5a, 0x0d, 0x00, 0x00, 0x5a,
    0x0d, 0x00, 0x00, 0x5a, 0x0d, 0x00, 0x00, 0x5a, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x2f,
    0x00, 0x35, 0x00, 0x0a, 0x00, 0x05, 0x00, 0x3c, 0x00, 0x3d, 0x01, 0x00,
];

/// What a peer that refused a modern handshake turns out to speak.
///
/// rustls implements only TLS 1.2 and 1.3, so a server offering only 1.0 or 1.1
/// fails [`handshake`]. This sends one ClientHello and reads the version from
/// the answer; no tunnel is returned.
///
/// `None` where the peer said nothing, or nothing that is TLS. An alert means
/// the peer speaks TLS and refused these terms, reported as [`REFUSED`].
pub async fn legacy_version(stream: TcpStream) -> Option<&'static str> {
    timeout(
        super::on_path(LEGACY_PROBE_TIMEOUT),
        legacy_exchange(stream),
    )
    .await
    .unwrap_or_default()
}

/// What a peer speaking TLS says when it will not accept the terms offered.
///
/// It establishes that the port speaks TLS, though not the version.
pub const REFUSED: &str = "TLS (version not established)";

/// Sends [`LEGACY_CLIENT_HELLO`] and reads the version out of the answer.
async fn legacy_exchange(mut stream: TcpStream) -> Option<&'static str> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    stream.write_all(LEGACY_CLIENT_HELLO).await.ok()?;

    // Only the first record's start is needed, up to the version.
    let mut buffer = [0u8; 128];
    let read = stream.read(&mut buffer).await.ok()?;
    server_version(&buffer[..read])
}

/// The version a TLS server named in its first record, or [`REFUSED`] where it
/// answered with an alert.
///
/// Every offset is checked against what arrived.
///
/// ```text
/// 16 03 01 00 4a | 02 00 00 46 | 03 01 | ...
/// └── record ──┘ └─ handshake ┘ └ version
/// ```
fn server_version(record: &[u8]) -> Option<&'static str> {
    // Record header: content type, version, length. The record's version is a
    // conservative one; the negotiated version is in the ServerHello.
    let content_type = *record.first()?;

    // An alert: TLS, terms declined.
    if content_type == 0x15 {
        return Some(REFUSED);
    }
    if content_type != 0x16 {
        return None; // not a TLS record at all
    }

    // Handshake header: type, three-byte length, then the version.
    let body = record.get(5..)?;
    if *body.first()? != 0x02 {
        return None; // a handshake, but not a ServerHello
    }
    let version = body.get(4..6)?;
    version_name(u16::from_be_bytes([version[0], version[1]]))
}

/// The name a version number goes by, for the versions worth naming.
fn version_name(version: u16) -> Option<&'static str> {
    match version {
        0x0300 => Some("SSLv3"),
        0x0301 => Some("TLSv1.0"),
        0x0302 => Some("TLSv1.1"),
        // A 1.2 answer means something other than the version stopped the modern
        // connector.
        0x0303 => Some("TLSv1.2"),
        _ => None,
    }
}

/// The negotiated version under the name the RFCs give it.
///
/// `Debug` would render `TLSv1_3`. Only the two versions [`connector`] offers are
/// named; anything else is `None`.
fn protocol_version_name(version: Option<rustls::ProtocolVersion>) -> Option<&'static str> {
    match version? {
        rustls::ProtocolVersion::TLSv1_3 => Some("TLSv1.3"),
        rustls::ProtocolVersion::TLSv1_2 => Some("TLSv1.2"),
        _ => None,
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

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

    /// A server that speaks only TLS 1.0 is identified, though rustls cannot
    /// handshake with it.
    #[test]
    fn a_legacy_server_hello_names_its_version() {
        // Record header, then a ServerHello naming the version.
        let hello = |version: [u8; 2]| {
            let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x4a, 0x02, 0x00, 0x00, 0x46];
            record.extend_from_slice(&version);
            record.extend_from_slice(&[0u8; 32]); // random
            record
        };

        assert_eq!(server_version(&hello([0x03, 0x00])), Some("SSLv3"));
        assert_eq!(server_version(&hello([0x03, 0x01])), Some("TLSv1.0"));
        assert_eq!(server_version(&hello([0x03, 0x02])), Some("TLSv1.1"));
        assert_eq!(server_version(&hello([0x03, 0x03])), Some("TLSv1.2"));
        assert_eq!(server_version(&hello([0x03, 0x09])), None, "not a version");
    }

    /// An alert is reported as [`REFUSED`].
    #[test]
    fn an_alert_establishes_tls_without_establishing_a_version() {
        // Alert, TLS 1.0, two bytes: fatal, handshake_failure.
        assert_eq!(
            server_version(&[0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28]),
            Some(REFUSED)
        );
    }

    /// A non-TLS or truncated record names nothing.
    #[test]
    fn what_is_not_a_server_hello_names_nothing() {
        assert_eq!(server_version(b"HTTP/1.1 200 OK"), None);
        assert_eq!(server_version(b"SSH-2.0-OpenSSH_9.6p1"), None);
        assert_eq!(server_version(&[]), None);
        // A well-formed record header with nothing behind it.
        assert_eq!(server_version(&[0x16, 0x03, 0x01, 0x00, 0x4a]), None);
        // A handshake that is not a ServerHello.
        assert_eq!(
            server_version(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00]),
            None
        );
        // A ServerHello cut off before its version.
        assert_eq!(
            server_version(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x46]),
            None
        );
    }

    /// The hello's length fields agree with its bytes; a server silently drops
    /// one that does not.
    #[test]
    fn the_client_hello_declares_its_own_length_correctly() {
        let record_length = u16::from_be_bytes([LEGACY_CLIENT_HELLO[3], LEGACY_CLIENT_HELLO[4]]);
        assert_eq!(
            usize::from(record_length),
            LEGACY_CLIENT_HELLO.len() - 5,
            "the record length must count everything after the header"
        );

        let handshake_length = u32::from_be_bytes([
            0,
            LEGACY_CLIENT_HELLO[6],
            LEGACY_CLIENT_HELLO[7],
            LEGACY_CLIENT_HELLO[8],
        ]);
        assert_eq!(
            handshake_length as usize,
            LEGACY_CLIENT_HELLO.len() - 9,
            "the handshake length must count everything after its own header"
        );
        assert_eq!(LEGACY_CLIENT_HELLO[0], 0x16, "a handshake record");
        assert_eq!(LEGACY_CLIENT_HELLO[5], 0x01, "a client hello");
    }

    proptest::proptest! {
        /// The walk terminates on any input.
        #[test]
        fn the_version_walk_never_panics(record in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
            let _ = server_version(&record);
        }
    }

    #[test]
    fn connector_builds_with_ring_provider() {
        // Builds the accept-any config with the ring provider.
        let _ = connector();
    }
}
