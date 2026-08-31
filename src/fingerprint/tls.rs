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
//! and capture the certificate chain the peer presents. Interpreting that chain
//! is the analyzer's job (see [`TlsCertAnalyzer`]); this module only gathers
//! bytes.
//!
//! ## Why we complete a real handshake
//!
//! In TLS 1.3 the server's `Certificate` message is *encrypted*, so a cert
//! cannot be scraped by parsing raw handshake records, the handshake must
//! actually complete. We therefore run a real rustls client, but with a
//! verifier that [accepts any certificate](AcceptAnyServerCert): a scanner
//! wants the *presented* chain, not a trust decision, and the ports we probe
//! routinely serve expired, self-signed, or wrong-host certs that a validating
//! client would reject before we ever see them.
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

/// A completed TLS client tunnel over a TCP socket. The transport reads and
/// probes *through* this to fingerprint the protocol carried inside.
pub type TlsTunnel = tokio_rustls::client::TlsStream<TcpStream>;

/// How long to wait for a handshake on a port where we *expect* TLS (an
/// implicit-TLS port). Patient: a handshake is the whole point here, worth
/// waiting out a slow server.
pub(super) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// A tighter budget for a *speculative* handshake on a silent, non-standard
/// port. The prior probability of TLS there is low, and a real TLS server on a
/// reachable open port completes well under a second; the extra patience would
/// mostly buy tarpits. Since this is paid on every silent port, it is where
/// latency blast-radius on a many-port host concentrates.
pub(super) const SPECULATIVE_TLS_TIMEOUT: Duration = Duration::from_millis(1_500);

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

/// Handshake on a port where TLS is *expected*, an implicit-TLS port. Patient
/// (see [`TLS_HANDSHAKE_TIMEOUT`]).
pub async fn handshake(stream: TcpStream, peer: IpAddr) -> Option<(TlsTunnel, TlsInfo)> {
    handshake_within(stream, peer, TLS_HANDSHAKE_TIMEOUT).await
}

/// *Speculative* handshake on a silent, un-probed port that might be TLS on a
/// non-standard port. Tighter budget (see [`SPECULATIVE_TLS_TIMEOUT`]) because
/// the prior is low and this cost is paid on every silent port.
pub async fn speculative_handshake(
    stream: TcpStream,
    peer: IpAddr,
) -> Option<(TlsTunnel, TlsInfo)> {
    handshake_within(stream, peer, SPECULATIVE_TLS_TIMEOUT).await
}

/// Completes a TLS handshake over `stream` within `budget`, returning the live
/// tunnel and the certificate chain the peer presented (owned DER).
///
/// `peer` is the address we connected to; it becomes the rustls server name, and
/// an address is not a name, so **no SNI goes on the wire**. What comes back is
/// whatever certificate the default virtual host serves, and the accept-any
/// verifier means the name never decides whether the handshake completes. The
/// tunnel is returned so the caller can re-probe *through* it; the certificate
/// may be empty (anonymous handshake) without failing. Returns `None` only on
/// timeout or handshake failure.
///
/// # What that costs, and why it is not fixed here
///
/// On a shared address the certificate recorded is the fallback one and not the
/// operator's, and a growing number of hosts refuse a no-SNI handshake
/// outright, which reads, from a scan, as a port that does not speak TLS.
///
/// This used to say the engine scans by IP, as though that settled it. It does
/// not: [`resolve`](crate::resolve) turns names into addresses before a scan and
/// [`rdns`](crate::scanner::rdns) attaches names to hosts after one. The real
/// obstacle is that neither has produced a name **by the time this runs**. A
/// forward-resolved target does not record the name it came from, and reverse
/// resolution lands in `finish_enrichment`, which the orchestrator runs after
/// service detection has finished.
///
/// So the fix is upstream and is one of two things: record the name a target was
/// resolved from, or order reverse resolution before the service phase. Adding a
/// parameter here first would be a seam nothing could fill.
async fn handshake_within(
    stream: TcpStream,
    peer: IpAddr,
    budget: Duration,
) -> Option<(TlsTunnel, TlsInfo)> {
    let server_name = ServerName::IpAddress(peer.into());
    let connect = connector().connect(server_name, stream);

    let tls = timeout(budget, connect).await.ok()?.ok()?;

    let connection = tls.get_ref().1;

    let certificates: Vec<Vec<u8>> = connection
        .peer_certificates()
        .unwrap_or(&[])
        .iter()
        .map(|der| der.as_ref().to_vec())
        .collect();

    // Read off the live connection: these are gone the moment the tunnel is.
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
/// Reached only after a modern handshake has already failed on this port, so it
/// is paid on a port that has otherwise been given up on. A server old enough to
/// need it is old enough to answer promptly.
pub(super) const LEGACY_PROBE_TIMEOUT: Duration = Duration::from_millis(1_500);

/// A ClientHello offering the versions rustls will not.
///
/// Fixed bytes, because everything in it is a constant: TLS 1.0, six RSA and
/// 3DES suites a legacy server actually implements, null compression, and **no
/// extension block at all**. A hello with no extensions is what an SSLv3-era
/// stack expects, and it is what keeps this free of the negotiation a modern
/// handshake needs. The random is fixed too; nothing here is a security context,
/// only a question.
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
/// rustls implements TLS 1.2 and 1.3 and implements neither 1.0
/// nor 1.1, so a server offering only the older versions fails
/// [`handshake`] and is reported as a port that answered nothing at all. For a
/// security scanner that is the wrong way round: "this host still negotiates TLS
/// 1.0" is among the most actionable single facts a scan can report, and it was
/// the one configuration this engine could not see.
///
/// One ClientHello and the version out of the answer. No tunnel comes back and
/// none is wanted, the finding *is* the version, and nothing is worth carrying
/// over a channel this weak anyway.
///
/// `None` where the peer said nothing, or said something that is not TLS. A
/// server that answers with an alert spoke TLS and refused these terms, which is
/// itself an answer and is reported as [`REFUSED`].
pub async fn legacy_version(stream: TcpStream) -> Option<&'static str> {
    timeout(LEGACY_PROBE_TIMEOUT, legacy_exchange(stream))
        .await
        .unwrap_or_default()
}

/// What a peer speaking TLS says when it will not accept the terms offered.
///
/// Recorded rather than discarded: it establishes the port speaks TLS, which is
/// more than a scan that gave up on it knew, even though it leaves the version
/// unsettled.
pub const REFUSED: &str = "TLS (version not established)";

/// Sends [`LEGACY_CLIENT_HELLO`] and reads the version out of the answer.
async fn legacy_exchange(mut stream: TcpStream) -> Option<&'static str> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    stream.write_all(LEGACY_CLIENT_HELLO).await.ok()?;

    // A ServerHello is small and this reads the first record and no more. The
    // buffer is the largest a record header can promise for the part that
    // matters; nothing beyond the version is read, so nothing beyond it is kept.
    let mut buffer = [0u8; 128];
    let read = stream.read(&mut buffer).await.ok()?;
    server_version(&buffer[..read])
}

/// The version a TLS server named in its first record, or [`REFUSED`] where it
/// answered with an alert.
///
/// Every offset is checked against what actually arrived: these bytes are a
/// remote host's and the walk must terminate on any input rather than merely on
/// a well-formed one.
///
/// ```text
/// 16 03 01 00 4a | 02 00 00 46 | 03 01 | ...
/// └── record ──┘ └─ handshake ┘ └ version
/// ```
fn server_version(record: &[u8]) -> Option<&'static str> {
    // Record header: content type, version, length. The record's own version is
    // not the answer: servers write the negotiated one in the ServerHello and
    // a conservative one here.
    let content_type = *record.first()?;

    // An alert is a peer speaking TLS and declining the terms. It settles that
    // the port speaks TLS and nothing more.
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
        // A server that answers this hello with 1.2 was reachable by the modern
        // connector and something else stopped it. Named honestly rather than
        // filed under a version this probe did not establish.
        0x0303 => Some("TLSv1.2"),
        _ => None,
    }
}

/// The negotiated version under the name the RFCs give it.
///
/// Spelled out rather than taken from `Debug`, which renders `TLSv1_3`, a
/// string no reader of a report expects and no other tool prints. Only the two
/// versions [`connector`] offers are named; anything else is reported as
/// unknown rather than guessed at.
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

    /// A server that speaks only TLS 1.0 is a finding, not a silence.
    ///
    /// rustls implements 1.2 and 1.3 and implements neither 1.0
    /// nor 1.1, so such a server fails the modern handshake. Before this probe
    /// it was reported as a port that answered nothing, which loses the
    /// identification and the finding together, and "this host still negotiates
    /// TLS 1.0" is among the most actionable things a scan can say.
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

    /// An alert is a peer speaking TLS and declining these terms, which settles
    /// that the port speaks TLS and nothing more. Reported as exactly that.
    #[test]
    fn an_alert_establishes_tls_without_establishing_a_version() {
        // Alert, TLS 1.0, two bytes: fatal, handshake_failure.
        assert_eq!(
            server_version(&[0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28]),
            Some(REFUSED)
        );
    }

    /// Anything that is not a TLS record names nothing, and a truncated one is
    /// refused rather than read past.
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

    /// The hello is a fixed record and its own length fields have to agree with
    /// it, or a server drops it without a word and the port reads as silent.
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
        /// These bytes come off a socket a scanner opened to a stranger, so the
        /// walk has to terminate on any input rather than merely on a well-formed
        /// one.
        #[test]
        fn the_version_walk_never_panics(record in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
            let _ = server_version(&record);
        }
    }

    #[test]
    fn connector_builds_with_ring_provider() {
        // Exercises the accept-any config + ring provider path; a panic here
        // would mean the process cannot perform any TLS fingerprinting.
        let _ = connector();
    }
}
