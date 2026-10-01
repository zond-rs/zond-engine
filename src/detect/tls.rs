// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Speaking a detection through TLS
//!
//! A flow's [`SocketProbe`](crate::scanner::detection) and a compute module's
//! [`LiveCapabilities`](super::compute::LiveCapabilities) open a plain
//! `TcpStream`. When the port answered inside TLS, the exchange runs through a
//! handshake from here.
//!
//! ## A synchronous client
//!
//! [`fingerprint::tls`](crate::fingerprint) is async (`tokio-rustls`), and the
//! detection probes run on the blocking pool with `std::net::TcpStream`. This is
//! a small blocking rustls client sharing that module's ring provider and its
//! verifier that [accepts any certificate](AcceptAnyServerCert), since scanned
//! ports routinely serve expired, self-signed or wrong-host certificates.
//!
//! ## The name on the wire
//!
//! The handshake carries the target's name where it had one, as identification
//! does; an address puts no server name on the wire. A server refusing a
//! nameless handshake reads as a silent port. See
//! [`Authority::server_name`](crate::fingerprint::authority::Authority::server_name).

use std::io::{Read, Write};
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

use super::exchange::Bounded;
use crate::fingerprint::Tunnel;

/// A byte stream a detection's exchange runs over: a plain [`Bounded`] socket
/// or a TLS [`StreamOwned`] over one.
pub(crate) trait ReadWrite: Read + Write {
    /// The socket underneath, for how long its reads may wait.
    fn socket(&mut self) -> &mut Bounded;
}

impl ReadWrite for Bounded {
    fn socket(&mut self) -> &mut Bounded {
        self
    }
}

impl ReadWrite for StreamOwned<ClientConnection, Bounded> {
    fn socket(&mut self) -> &mut Bounded {
        self.get_mut()
    }
}

/// Wraps a connected socket in the transport a tunnel names, ready for the same
/// exchange either way.
///
/// A `None` tunnel hands the socket straight back. A [`Tunnel::Tls`] sets up a
/// client naming `server_name`; the handshake runs lazily on the first read or
/// write, within the socket's deadline. Returns [`None`] only if the TLS client
/// cannot be created; a failed handshake looks like a silent port.
pub(crate) fn wrap(
    tcp: Bounded,
    server_name: ServerName<'static>,
    tunnel: Option<Tunnel>,
) -> Option<Box<dyn ReadWrite>> {
    match tunnel {
        None => Some(Box::new(tcp)),
        Some(Tunnel::Tls) => {
            let conn = ClientConnection::new(config().clone(), server_name).ok()?;
            Some(Box::new(StreamOwned::new(conn, tcp)))
        }
    }
}

/// The process-wide client config, built once and shared.
fn config() -> &'static Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("the ring provider supports the default TLS versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
                .with_no_client_auth();
        Arc::new(config)
    })
}

/// A certificate verifier that accepts everything.
///
/// Sound only because a detection needs to reach whatever answers, not a trusted
/// channel. Never reuse it for a client that sends anything sensitive.
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
        // The common schemes, as in the certificate path.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::loopback::from_this_process;

    /// A `None` tunnel returns the plain socket, usable.
    #[test]
    fn no_tunnel_returns_the_plain_socket() {
        use std::net::{TcpListener, TcpStream};
        use std::time::{Duration, Instant};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = std::thread::spawn(move || from_this_process(&listener).next());

        let tcp = Bounded::new(
            TcpStream::connect(addr).unwrap(),
            Instant::now() + Duration::from_secs(5),
        );
        let mut wrapped = wrap(tcp, ServerName::IpAddress(addr.ip().into()), None)
            .expect("a plain socket wraps to itself");
        let mut server = accepted.join().unwrap().expect("an accept");

        wrapped.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping", "the bytes crossed the un-tunnelled stream");
    }

    /// The shared config builds, and two calls return the same `Arc`.
    #[test]
    fn the_client_config_is_built_once_and_shared() {
        let first = config();
        let second = config();
        assert!(
            Arc::ptr_eq(first, second),
            "the config is a shared singleton, not rebuilt per call"
        );
    }
}
