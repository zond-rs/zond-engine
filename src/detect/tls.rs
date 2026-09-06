// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Speaking a detection through TLS
//!
//! A detection reaches its port through one of two blocking seams: a flow's
//! [`SocketProbe`](crate::scanner::detection) or a compute module's
//! [`LiveCapabilities`](super::compute::LiveCapabilities). Both open a plain
//! `TcpStream` and exchange bytes over it. This module is the one thing they were
//! missing: when the port answered inside TLS, the same exchange has to run
//! through a completed handshake, or a probe written for an HTTPS service reaches
//! a port that only ever replies in ciphertext and reads back noise.
//!
//! ## Why a synchronous client of its own
//!
//! [`fingerprint::tls`](crate::fingerprint) already completes a handshake to read
//! a certificate, but it is `async`, built on `tokio-rustls`, and the detection
//! probes run on the blocking pool with `std::net::TcpStream`. Driving an async
//! connector from there would mean handing a blocking socket to a reactor that is
//! not running. So this is a small blocking rustls client instead, sharing that
//! module's two decisions and nothing else: the pure-Rust ring provider (no
//! cmake/NASM at build time), and a verifier that
//! [accepts any certificate](AcceptAnyServerCert), because a scanner wants to
//! reach the service the way any client on the network would, and the ports it
//! probes routinely serve expired, self-signed, or wrong-host certificates a
//! validating client would hang up on before a byte of the protocol inside.
//!
//! ## No name on the wire
//!
//! The server name is the peer's address, so no SNI is sent, the same as the
//! certificate path and for the same reason: no hostname exists by the time a
//! detection runs. A forward-resolved target does not record the name it came
//! from and reverse resolution lands after service detection, so the flow that
//! seeds `{host}` seeds the address it reached, and this hands rustls that same
//! address. A server that refuses a no-SNI handshake reads, from here, as a port
//! that stopped answering, which the probe treats as any other silent port.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

use crate::fingerprint::Tunnel;

/// A byte stream a detection's exchange runs over, whichever transport carries
/// it. A plain [`TcpStream`] and a TLS [`StreamOwned`] both satisfy it, so the
/// read-and-write loop in each probe is written once against `dyn ReadWrite`
/// rather than duplicated per transport.
pub(crate) trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// Wraps a connected socket in the transport a tunnel names, ready for the same
/// exchange either way.
///
/// A `None` tunnel hands the socket straight back: the plain-TCP path is the
/// common one and costs nothing here. A [`Tunnel::Tls`] completes a client
/// handshake against `peer` and returns the live tunnel to probe through; the
/// handshake itself runs lazily on the first read or write, so it is bounded by
/// the read timeout the caller already set on `tcp` rather than by a clock of its
/// own. [`None`] only if the connection cannot be turned into a TLS client at
/// all, which a failure to complete the handshake is not; that surfaces as the
/// first exchange going unanswered, exactly like a silent port.
pub(crate) fn wrap(
    tcp: TcpStream,
    peer: IpAddr,
    tunnel: Option<Tunnel>,
) -> Option<Box<dyn ReadWrite>> {
    match tunnel {
        None => Some(Box::new(tcp)),
        Some(Tunnel::Tls) => {
            let name = ServerName::IpAddress(peer.into());
            let conn = ClientConnection::new(config().clone(), name).ok()?;
            Some(Box::new(StreamOwned::new(conn, tcp)))
        }
    }
}

/// The process-wide client config, built once and shared. The config is immutable
/// and internally reference-counted, so every handshake clones an [`Arc`] rather
/// than rebuilding it.
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
/// Sound only because a detection completes the handshake to speak the protocol
/// inside, not to establish a trusted channel: the point of the probe is to reach
/// whatever answers on the port, and a scanner that refused a bad certificate
/// would decline to look at the misconfigured endpoints it exists to find. Never
/// reuse this for a client that sends anything it would mind an impostor reading.
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
        // Advertise the common schemes so a server picks one this verifier will
        // "accept". Mirrors the certificate path's list.
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

    /// A `None` tunnel is the identity: the plain socket comes back usable, so the
    /// common path pays nothing for the branch. Exercised over a loopback pair
    /// rather than a mock, since the value under test is a real `TcpStream`.
    #[test]
    fn no_tunnel_returns_the_plain_socket() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = std::thread::spawn(move || listener.accept().map(|(sock, _)| sock));

        let tcp = TcpStream::connect(addr).unwrap();
        let mut wrapped = wrap(tcp, addr.ip(), None).expect("a plain socket wraps to itself");
        let mut server = accepted.join().unwrap().unwrap();

        wrapped.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping", "the bytes crossed the un-tunnelled stream");
    }

    /// The shared config builds and is reused: the ring provider supports the
    /// default versions (the `expect` in `config`), and two calls hand back the
    /// same `Arc`.
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
