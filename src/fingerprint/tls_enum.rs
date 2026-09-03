// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a TLS endpoint will accept
//!
//! The I/O half of cipher enumeration: offer an endpoint a version and a set of
//! suites, read which one it picked, narrow the offer, and ask again. What comes
//! out is [`TlsSupport`], which is a different fact from the one
//! [`tls`](super::tls) records. That module completes one handshake and reports
//! what was negotiated; this one reports what *would* be, which is the question a
//! PCI scan, an ASV report or an internal audit is actually asking.
//!
//! ## The algorithm, and why it terminates
//!
//! For each version, offer every suite that version can express. A server that
//! answers names exactly one, which is then removed from the offer and the
//! question put again. Each answer costs one connection and removes one suite,
//! so the walk ends after as many exchanges as the server has suites, and a
//! refusal ends it sooner. Two things could make it run forever and neither
//! does: a server naming a suite it was not offered ends the version, since the
//! offer could not shrink, and [`MAX_OFFERS_PER_VERSION`] bounds the rest.
//!
//! ## A version is credited only when the server names it
//!
//! The rule that keeps this from inventing findings. A server answering a TLS
//! 1.0 offer with a ServerHello saying 1.2 has declined 1.0, whatever else it
//! did, and crediting the offered version would report the most quotable finding
//! a TLS scan produces on the strength of not having read the answer. So an
//! answer naming a different version ends that version's walk and records
//! nothing.
//!
//! ## What it costs, and what bounds it
//!
//! One TCP connection per exchange, and the five versions are walked
//! concurrently because each is independent of the others. A current server
//! accepting a handful of suites under 1.2 and 1.3 and refusing the rest costs a
//! dozen connections; an old one accepting everything costs a few dozen, which
//! is the case this exists to find. [`MAX_OFFERS_PER_VERSION`] caps the
//! pathological end, and
//! [`ZondConfig::host_timeout`](crate::config::ZondConfig::host_timeout) caps
//! the time a whole host may spend here.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::limits::CONNECT_PROBE_TIMEOUT;
use crate::model::tls::{CipherSuite, TlsSupport, TlsVersion, VersionSupport};
use crate::protocols::tls::{self, Offer, RECORD_HEADER_LEN, ServerResponse};
use crate::warn;

/// The most offers put to one endpoint under one version.
///
/// Reached only by a server that accepts two dozen distinct suites under a
/// single version, which is well past any configuration anyone has chosen on
/// purpose. It is here so that a peer answering every offer with a fresh suite,
/// whether through misconfiguration or deliberately, costs a bounded number of
/// connections rather than one per suite in the registry.
pub const MAX_OFFERS_PER_VERSION: usize = 24;

/// How long one offer may take, from the connection to the answer.
///
/// A server that has already been found to speak TLS answers a hello in a round
/// trip. This is generous against that, and it is paid once per offer, so a
/// tarpit costs the version's walk rather than the scan.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);

/// Everything `addr` accepts, version by version.
///
/// Empty where the endpoint accepted nothing under any version. That is a real
/// answer and not a failure: a server may be strictly configured, or may have
/// been asked without the name it insists on. See
/// [`Offer::server_name`](crate::protocols::tls::Offer::server_name) for why the
/// name is usually absent.
pub async fn enumerate_tls(addr: SocketAddr) -> TlsSupport {
    // Fixed at five, so the versions are joined rather than spawned: each walk
    // borrows nothing the others need and none of them outlives this call.
    let (ssl30, tls10, tls11, tls12, tls13) = tokio::join!(
        walk(addr, TlsVersion::Ssl30),
        walk(addr, TlsVersion::Tls10),
        walk(addr, TlsVersion::Tls11),
        walk(addr, TlsVersion::Tls12),
        walk(addr, TlsVersion::Tls13),
    );

    let mut support = TlsSupport::new();
    for found in [ssl30, tls10, tls11, tls12, tls13].into_iter().flatten() {
        support.record(found);
    }
    support
}

/// Narrows the offer under one version until the endpoint stops answering.
///
/// `None` where the version was never accepted, which is the ordinary outcome
/// for four of the five against a current server.
async fn walk(addr: SocketAddr, version: TlsVersion) -> Option<VersionSupport> {
    let mut remaining: Vec<CipherSuite> = CipherSuite::offered_under(version).collect();
    let mut accepted: Vec<CipherSuite> = Vec::new();
    let mut unrecognised: Vec<u16> = Vec::new();

    for _ in 0..MAX_OFFERS_PER_VERSION {
        if remaining.is_empty() {
            break;
        }

        let offer = Offer {
            version,
            suites: &remaining,
            // No name to ask for. The limitation, and the fix, are the ones
            // `fingerprint::tls` documents: the name a target was resolved from
            // is not recorded, so there is none to send by the time this runs.
            server_name: None,
        };

        let Some(ServerResponse::Hello {
            version: named,
            suite,
            ..
        }) = exchange(addr, &offer).await
        else {
            // An alert, a silence, or bytes that are not TLS. All three end the
            // version, and none of them is worth telling apart here: the server
            // declined these terms and the walk has nothing narrower to ask.
            break;
        };

        // A server that named a different version declined this one, whatever
        // else it did. Crediting the offer would report a deprecated version on
        // the strength of not having read the answer.
        if named != Some(version) {
            break;
        }

        match remaining.iter().position(|held| held.code() == suite) {
            Some(at) => accepted.push(remaining.remove(at)),
            None => {
                // Selected something it was never offered. The offer cannot
                // shrink, so asking again would put the same question forever.
                warn!(
                    verbosity = 2,
                    "{addr} selected cipher suite 0x{suite:04X} under {version}, which was not offered"
                );
                unrecognised.push(suite);
                break;
            }
        }
    }

    (!accepted.is_empty() || !unrecognised.is_empty())
        .then(|| VersionSupport::new(version, accepted, unrecognised))
}

/// One offer: connect, send the hello, read the first record back, hang up.
///
/// The connection is dropped as soon as the answer is read. Nothing is
/// completed, so the endpoint sees a client that opened a connection, asked what
/// it would accept, and left.
async fn exchange(addr: SocketAddr, offer: &Offer<'_>) -> Option<ServerResponse> {
    let hello = tls::client_hello(offer);

    timeout(EXCHANGE_TIMEOUT, async {
        let mut stream = timeout(CONNECT_PROBE_TIMEOUT, TcpStream::connect(addr))
            .await
            .ok()?
            .ok()?;
        stream.write_all(&hello).await.ok()?;
        let record = first_record(&mut stream).await?;
        tls::read_response(&record)
    })
    .await
    .ok()?
}

/// Reads until the first TLS record is whole, or the peer stops being one.
///
/// TCP delivers a record in as many pieces as it likes, so a single read is not
/// enough; a ServerHello arriving in two segments would otherwise be parsed as a
/// truncated one and the version reported unsupported. What bounds this is the
/// record's own length field, which
/// [`record_length`](crate::protocols::tls::record_length) refuses past the
/// largest TLS permits, so a stranger cannot decide how much this process
/// buffers.
async fn first_record(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    loop {
        match tls::record_length(&buffer) {
            Some(total) if buffer.len() >= total => return Some(buffer),
            // The header is here and the body is not. Keep reading.
            Some(_) => {}
            // Past five bytes a header that still yields nothing is one
            // announcing a record no peer may send.
            None if buffer.len() >= RECORD_HEADER_LEN => return None,
            None => {}
        }

        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            // The peer hung up mid-record. What arrived is handed on rather than
            // discarded: a complete ServerHello followed by a reset is still an
            // answer, and the parser refuses anything short of one.
            return (!buffer.is_empty()).then_some(buffer);
        }
        buffer.extend_from_slice(&chunk[..read]);
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
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::net::TcpListener;

    use crate::protocols::tls::HELLO_RETRY_RANDOM;

    /// A server that accepts `version` and whichever of `accepts` it is offered,
    /// answering everything else with a fatal handshake_failure.
    ///
    /// Written against the RFC layout rather than against this crate's builder,
    /// for the reason the packet tests give: a simulator that reads a hello the
    /// way the engine wrote it agrees with the engine even when both are wrong.
    struct FakeTlsServer {
        /// Which version this server admits to, by wire number.
        version: u16,
        /// The suites it will select, by wire number.
        accepts: BTreeSet<u16>,
        /// Whether it answers with a HelloRetryRequest rather than a plain
        /// ServerHello.
        retry: bool,
        /// Whether it names its version in `supported_versions`, as a TLS 1.3
        /// server must.
        version_in_extension: bool,
        /// A suite this server names whatever it was offered, for the case the
        /// walk has to survive rather than loop on.
        ignores_the_offer: Option<u16>,
        /// How many connections it has taken.
        seen: Arc<AtomicUsize>,
    }

    impl FakeTlsServer {
        fn new(version: u16, accepts: impl IntoIterator<Item = u16>) -> Self {
            Self {
                version,
                accepts: accepts.into_iter().collect(),
                retry: false,
                version_in_extension: false,
                ignores_the_offer: None,
                seen: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn answering_in_the_extension(mut self) -> Self {
            self.version_in_extension = true;
            self
        }

        fn retrying(mut self) -> Self {
            self.retry = true;
            self
        }

        /// Answers every hello with `suite`, offered or not.
        fn always_naming(mut self, suite: u16) -> Self {
            self.ignores_the_offer = Some(suite);
            self
        }

        /// Serves until dropped, and yields the address to point a scan at.
        async fn spawn(self) -> (SocketAddr, Arc<AtomicUsize>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
            let addr = listener.local_addr().expect("has an address");
            let seen = Arc::clone(&self.seen);

            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    self.seen.fetch_add(1, Ordering::SeqCst);

                    let mut buffer = vec![0u8; 4096];
                    let Ok(read) = stream.read(&mut buffer).await else {
                        continue;
                    };
                    let answer = self.answer(&buffer[..read]);
                    let _ = stream.write_all(&answer).await;
                }
            });

            (addr, seen)
        }

        /// The record this server sends back for `hello`.
        fn answer(&self, hello: &[u8]) -> Vec<u8> {
            if let Some(fixed) = self.ignores_the_offer {
                return self.server_hello(fixed);
            }
            let Some(offered) = offered_suites(hello) else {
                return alert();
            };
            let Some(chosen) = offered.iter().find(|code| self.accepts.contains(code)) else {
                return alert();
            };
            self.server_hello(*chosen)
        }

        fn server_hello(&self, suite: u16) -> Vec<u8> {
            let mut body = vec![2u8, 0, 0, 0];
            let legacy = match self.version_in_extension {
                true => 0x0303u16,
                false => self.version,
            };
            body.extend_from_slice(&legacy.to_be_bytes());
            match self.retry {
                true => body.extend_from_slice(&HELLO_RETRY_RANDOM),
                false => body.extend_from_slice(&[0x5A; 32]),
            }
            body.push(0); // no session id
            body.extend_from_slice(&suite.to_be_bytes());
            body.push(0); // null compression

            if self.version_in_extension {
                let extensions = [
                    0x00,
                    0x2B,
                    0x00,
                    0x02,
                    (self.version >> 8) as u8,
                    self.version as u8,
                ];
                body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
                body.extend_from_slice(&extensions);
            }

            let length = (body.len() - 4) as u32;
            body[1..4].copy_from_slice(&length.to_be_bytes()[1..]);

            let mut record = vec![0x16, 0x03, 0x03];
            record.extend_from_slice(&(body.len() as u16).to_be_bytes());
            record.extend_from_slice(&body);
            record
        }
    }

    /// A fatal handshake_failure, which is what a server sends when it will not
    /// accept any of the terms offered.
    fn alert() -> Vec<u8> {
        vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]
    }

    /// The suites a ClientHello offered, walked by offset off the RFC layout.
    fn offered_suites(hello: &[u8]) -> Option<Vec<u16>> {
        // Record header, handshake header, version, random, then the session id.
        let after_random = 5 + 4 + 2 + 32;
        let session_len = usize::from(*hello.get(after_random)?);
        let rest = hello.get(after_random + 1 + session_len..)?;
        let len = usize::from(u16::from_be_bytes([*rest.first()?, *rest.get(1)?]));
        Some(
            rest.get(2..2 + len)?
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes(*pair))
                .collect(),
        )
    }

    /// The whole of the algorithm against a server with a fixed set: every
    /// accepted suite is found, nothing else is claimed, and the walk stops.
    #[tokio::test]
    async fn every_accepted_suite_is_found_and_nothing_else_is() {
        // A TLS 1.2 server offering one strong suite, one without forward
        // secrecy, and one that is simply broken.
        let accepted = [0xC02F, 0x009C, 0x000A];
        let (addr, _) = FakeTlsServer::new(0x0303, accepted).spawn().await;

        let support = enumerate_tls(addr).await;

        assert!(support.accepts(TlsVersion::Tls12));
        assert_eq!(support.floor(), Some(TlsVersion::Tls12));
        assert_eq!(support.ceiling(), Some(TlsVersion::Tls12));

        let found: BTreeSet<u16> = support.suites().iter().map(|suite| suite.code()).collect();
        assert_eq!(found, accepted.into_iter().collect::<BTreeSet<_>>());
    }

    /// The offer narrows: each answer removes one suite, so the number of
    /// connections is the number accepted plus the one refusal that ends it.
    ///
    /// A walk that failed to narrow would ask the same question forever, which
    /// is the one way this algorithm can go wrong.
    #[tokio::test]
    async fn the_walk_costs_one_connection_per_suite_and_then_stops() {
        let accepted = [0xC02F, 0x009C];
        let (addr, seen) = FakeTlsServer::new(0x0303, accepted).spawn().await;

        let support = enumerate_tls(addr).await;
        assert_eq!(support.suites().len(), 2);

        // Two accepted suites and one refusal under 1.2, and one refusal each
        // for the four versions this server does not admit to.
        assert_eq!(
            seen.load(Ordering::SeqCst),
            3 + 4,
            "the walk narrows and ends rather than repeating itself"
        );
    }

    /// A TLS 1.3 server names its version in the extension and 1.2 in the field.
    /// Crediting the field would report the modern web as TLS 1.2, and refusing
    /// to read the extension would report it as nothing at all.
    #[tokio::test]
    async fn a_tls13_server_is_credited_to_thirteen_and_not_to_twelve() {
        let (addr, _) = FakeTlsServer::new(0x0304, [0x1301, 0x1302])
            .answering_in_the_extension()
            .spawn()
            .await;

        let support = enumerate_tls(addr).await;

        assert!(support.accepts(TlsVersion::Tls13));
        assert!(
            !support.accepts(TlsVersion::Tls12),
            "the legacy field says 1.2 and means nothing"
        );
        assert_eq!(support.suites().len(), 2);
    }

    /// A HelloRetryRequest names the suite exactly as a completed ServerHello
    /// does, and a walk that treated it as a refusal would report a TLS 1.3
    /// server as supporting no suites at all.
    #[tokio::test]
    async fn a_retrying_server_still_yields_its_suites() {
        let (addr, _) = FakeTlsServer::new(0x0304, [0x1303])
            .answering_in_the_extension()
            .retrying()
            .spawn()
            .await;

        let support = enumerate_tls(addr).await;
        assert!(support.accepts(TlsVersion::Tls13));
        assert_eq!(support.suites().len(), 1);
    }

    /// The rule that keeps this from inventing the most quotable finding a TLS
    /// scan produces. A server answering every offer with 1.2 accepts 1.2 and
    /// nothing else, however many older versions it was asked about.
    #[tokio::test]
    async fn a_server_that_answers_with_another_version_is_not_credited_the_one_offered() {
        // Answers 0x0303 whatever it is asked, which is what a server that only
        // speaks 1.2 does when it is sloppy about the version check.
        let (addr, _) = FakeTlsServer::new(0x0303, [0x002F]).spawn().await;

        let support = enumerate_tls(addr).await;

        assert!(support.accepts(TlsVersion::Tls12));
        for version in [TlsVersion::Ssl30, TlsVersion::Tls10, TlsVersion::Tls11] {
            assert!(
                !support.accepts(version),
                "{version} was offered and answered with 1.2, which is a refusal"
            );
        }
        assert!(support.deprecated_versions().next().is_none());
    }

    /// A server that refuses everything is an endpoint nothing was established
    /// about, reported as empty rather than as an error or a guess.
    #[tokio::test]
    async fn a_server_that_refuses_everything_yields_nothing() {
        let (addr, _) = FakeTlsServer::new(0x0303, []).spawn().await;

        let support = enumerate_tls(addr).await;
        assert!(support.is_empty());
        assert_eq!(support.floor(), None);
        assert!(support.weakest().is_none());
    }

    /// Nothing listening is the same answer as a refusal, and neither hangs.
    #[tokio::test]
    async fn a_closed_port_yields_nothing() {
        // Bound and dropped, so the port is closed and connections are refused.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");
        drop(listener);

        let support = enumerate_tls(addr).await;
        assert!(support.is_empty());
    }

    /// A deprecated version is found and named, which is the whole point: this
    /// is the configuration rustls cannot ask about, so before this pass it was
    /// invisible.
    #[tokio::test]
    async fn a_server_still_speaking_tls_10_is_reported_as_such() {
        let (addr, _) = FakeTlsServer::new(0x0301, [0x002F, 0x000A]).spawn().await;

        let support = enumerate_tls(addr).await;

        assert!(support.accepts(TlsVersion::Tls10));
        assert_eq!(support.floor(), Some(TlsVersion::Tls10));
        assert_eq!(
            support.deprecated_versions().collect::<Vec<_>>(),
            vec![TlsVersion::Tls10]
        );

        // And what it says about the suites under it.
        use crate::model::tls::{SuiteFault, SuiteStrength};
        assert_eq!(support.weakest(), Some(SuiteStrength::Insecure));
        assert!(support.faults().contains(&SuiteFault::SmallBlock));
    }

    /// The guard against the one way this algorithm can run forever.
    ///
    /// A server naming a suite it was never offered leaves the offer unchanged,
    /// so asking again would put the identical question until something else
    /// stopped it. The walk ends that version instead, and keeps the number:
    /// a server negotiating something the build cannot grade is worth reporting
    /// rather than dropping, and the version was accepted either way.
    #[tokio::test]
    async fn a_server_naming_a_suite_it_was_not_offered_ends_the_walk() {
        // 0xFF01 is in no registry, so it can never be removed from an offer.
        let (addr, seen) = FakeTlsServer::new(0x0303, [])
            .always_naming(0xFF01)
            .spawn()
            .await;

        let support = enumerate_tls(addr).await;

        assert!(support.accepts(TlsVersion::Tls12));
        assert!(
            support.suites().is_empty(),
            "nothing was graded, because nothing was recognised"
        );
        assert_eq!(
            support.versions()[0].unrecognised(),
            &[0xFF01],
            "the number is kept rather than dropped"
        );
        assert!(
            seen.load(Ordering::SeqCst) <= MAX_OFFERS_PER_VERSION,
            "the walk ended on the first unoffered suite rather than looping"
        );
    }

    /// A peer that answers with something other than TLS settles nothing, and
    /// the walk ends rather than reading the bytes as an answer.
    #[tokio::test]
    async fn a_peer_that_is_not_tls_settles_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut scratch = [0u8; 1024];
                let _ = stream.read(&mut scratch).await;
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            }
        });

        let support = enumerate_tls(addr).await;
        assert!(support.is_empty());
    }

    /// A ServerHello split across two segments is one answer, not a truncated
    /// one. A reader taking a single `read` would report the version
    /// unsupported on a slow or fragmenting path.
    #[tokio::test]
    async fn a_server_hello_arriving_in_pieces_is_still_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");
        let server = FakeTlsServer::new(0x0303, [0xC02F]);

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buffer = vec![0u8; 4096];
                let Ok(read) = stream.read(&mut buffer).await else {
                    continue;
                };
                let answer = server.answer(&buffer[..read]);
                let (head, tail) = answer.split_at(7);
                let _ = stream.write_all(head).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
                let _ = stream.write_all(tail).await;
            }
        });

        let support = enumerate_tls(addr).await;
        assert!(support.accepts(TlsVersion::Tls12));
        assert_eq!(support.suites().len(), 1);
    }
}
