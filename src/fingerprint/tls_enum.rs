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
//! out is [`TlsSupport`]. [`tls`](super::tls) reports what one handshake
//! negotiated; this reports everything the endpoint *would* accept, which is
//! what a PCI scan or an audit asks.
//!
//! ## The algorithm
//!
//! For each version, offer every suite that version can express. The server
//! names one, which is removed from the offer, and the question is put again.
//! The walk ends after as many exchanges as the server has suites, or sooner on
//! a refusal. A server naming a suite it was not offered ends the version, and
//! [`MAX_OFFERS_PER_VERSION`] bounds the rest.
//!
//! ## A version is credited only when the server names it
//!
//! A server answering a TLS 1.0 offer with a ServerHello saying 1.2 has declined
//! 1.0. An answer naming a different version ends that version's walk and
//! records nothing.
//!
//! ## A lost exchange is not a refusal
//!
//! A server declines by an alert, a reply that is not TLS, or a hello naming
//! another version. A failed connection or a missing answer says nothing about
//! the offer, and treating it as a refusal would drop the tail of the server's
//! preference order, where legacy configurations keep RC4, export ciphers and
//! anonymous key exchanges. Rate limiters and embedded stacks drop connections
//! readily, so a lost exchange is retried after a pause, and a version whose
//! walk still cannot continue is listed under [`TlsSupport::unfinished`].
//!
//! Some stacks decline by hanging up; `ask` documents how that is told apart.
//!
//! ## Cost
//!
//! One TCP connection per exchange; the five versions are walked concurrently.
//! A current server accepting a handful of suites costs about a dozen
//! connections.
//!
//! An old server accepting everything costs up to 80 exchanges under TLS 1.2
//! and 56 under each of SSL 3.0, 1.0 and 1.1. That is bounded in time by
//! [`ZondConfig::host_timeout`](crate::config::ZondConfig::host_timeout): the
//! scan checks before every connection, so a host over budget is left within one
//! exchange, keeps what was found, and is reported as left early.
//! [`MAX_OFFERS_PER_VERSION`] equals the registry's size and only guards against
//! a loop defect.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::authority::Authority;
use crate::config::limits::CONNECT_PROBE_TIMEOUT;
use crate::model::tls::{
    CipherSuite, Interruption, TlsSupport, TlsVersion, UnfinishedVersion, VersionSupport,
};
use crate::protocols::tls::{self, Offer, RECORD_HEADER_LEN, ServerResponse};
use crate::system::descriptors;
use crate::transport::dial::{Egress, Shaping, pacing};
use crate::{info, warn};

/// The most offers put to one endpoint under one version.
///
/// Every answer removes one suite and every other outcome ends the version, so
/// a walk cannot ask more than the version's suite count. This is that count
/// for the largest version.
///
/// **Do not lower it.** TLS 1.2 offers 80 suites and a stock OpenSSL `DEFAULT`
/// list accepts far more than 24. A lower ceiling would silently drop the tail
/// of the server's preference order, where RC4, export ciphers and anonymous
/// key exchanges live. At this size it only guards against a loop defect.
pub const MAX_OFFERS_PER_VERSION: usize = CipherSuite::MOST_OFFERED_UNDER_ONE_VERSION;

/// How long one offer may take, from the connection to the answer.
///
/// Generous against the one round trip a TLS server needs. An exchange that
/// outlasts it is lost and retried.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long to wait before putting an offer again whose exchange was lost, one
/// entry to a retry.
///
/// A busy embedded stack drops connections when its accept queue overflows,
/// which five concurrent walks can cause; a quarter second lets it drain. A
/// per-second rate limiter is outlasted by the second pause. A longer window
/// leaves the version unfinished, since the pauses are paid per lost offer.
const RETRY_PAUSES: [Duration; 2] = [Duration::from_millis(250), Duration::from_secs(1)];

/// Everything `addr` accepts, version by version.
///
/// Empty where the endpoint accepted nothing under any version, which can mean
/// strict configuration or a server that requires a name; this sends none, and
/// [`enumerate_tls_named`] does. See
/// [`Offer::server_name`](crate::protocols::tls::Offer::server_name).
///
/// A version whose walk the endpoint cut short by not answering is listed under
/// [`TlsSupport::unfinished`], keeping what it had accepted.
///
/// Connections follow the routing table.
pub async fn enumerate_tls(addr: SocketAddr) -> TlsSupport {
    enumerate_tls_while(addr, None, &Egress::KERNEL, || true).await
}

/// [`enumerate_tls`], asking for `addr` by `name`, the host name its address
/// was reached by.
///
/// Every hello carries the name as SNI, which a server holding its sites by name
/// needs before accepting any offer. The suites found are those of the site the
/// name routes to. A name a hello cannot carry (an address) is left off.
pub async fn enumerate_tls_named(addr: SocketAddr, name: &str) -> TlsSupport {
    let server_name = Authority::new(addr).named(Some(Arc::from(name))).sni();
    enumerate_tls_while(addr, server_name.as_deref(), &Egress::KERNEL, || true).await
}

/// [`enumerate_tls`], asking `may_probe` before every connection and ending
/// each version's walk at the first no.
///
/// A walk ends within one exchange of a `false`. What was learned is kept, and
/// each version cut short is listed as [`Interruption::Stopped`].
///
/// Connections leave by `egress`, and every hello carries `server_name` where
/// there is one.
pub(crate) async fn enumerate_tls_while(
    addr: SocketAddr,
    server_name: Option<&str>,
    egress: &Egress,
    may_probe: impl Fn() -> bool,
) -> TlsSupport {
    let may_probe = &may_probe;
    // Shared by the five walks, so one with nothing accepted yet can still tell
    // a declining server from a silent one. See `ask`.
    let control = OnceLock::new();
    let control = &control;
    // Joined, not spawned, so the walks can borrow from this frame.
    let under = |version| walk(addr, server_name, egress, version, control, may_probe);
    let (ssl30, tls10, tls11, tls12, tls13) = tokio::join!(
        under(TlsVersion::Ssl30),
        under(TlsVersion::Tls10),
        under(TlsVersion::Tls11),
        under(TlsVersion::Tls12),
        under(TlsVersion::Tls13),
    );

    let mut support = TlsSupport::new();
    for (found, unfinished) in [ssl30, tls10, tls11, tls12, tls13] {
        if let Some(found) = found {
            support.record(found);
        }
        if let Some(unfinished) = unfinished {
            support.record_unfinished(unfinished);
        }
    }
    support
}

/// Narrows the offer under one version until the endpoint declines what is
/// left of it, or the walk cannot go on.
///
/// Returns what the version accepted (`None` for nothing), and why the walk
/// ended early, where it did.
async fn walk(
    addr: SocketAddr,
    server_name: Option<&str>,
    egress: &Egress,
    version: TlsVersion,
    control: &OnceLock<Control>,
    may_probe: &impl Fn() -> bool,
) -> (Option<VersionSupport>, Option<UnfinishedVersion>) {
    let mut remaining: Vec<CipherSuite> = CipherSuite::offered_under(version).collect();
    let mut accepted: Vec<CipherSuite> = Vec::new();
    let mut unrecognised: Vec<u16> = Vec::new();
    let mut interruption = None;

    // Counted, so exhausting the ceiling (a defect) can be logged.
    let mut offers = 0;
    while !remaining.is_empty() {
        if offers == MAX_OFFERS_PER_VERSION {
            warn!(
                verbosity = 1,
                "{addr} was still answering under {version} after {MAX_OFFERS_PER_VERSION} offers; \
                 the enumeration is incomplete"
            );
            break;
        }
        offers += 1;

        let offer = Offer {
            version,
            suites: &remaining,
            server_name,
        };

        let asked = ask(
            addr,
            egress,
            &offer,
            control,
            may_probe,
            descriptors::PATIENCE,
        );
        let (named, suite, retry) = match asked.await {
            Answer::Hello {
                version,
                suite,
                retry,
            } => (version, suite, retry),
            // The one way a walk finishes.
            Answer::Declined => break,
            Answer::Interrupted(why) => {
                // A stop is reported by the caller; silence and a full
                // descriptor table are logged here.
                match why {
                    Interruption::Unanswered => warn!(
                        verbosity = 2,
                        "{addr} stopped answering under {version}; its enumeration there is incomplete"
                    ),
                    Interruption::FileLimit => warn!(
                        verbosity = 2,
                        "{addr} not asked under {version}: {}",
                        descriptors::starved(descriptors::PATIENCE)
                    ),
                    _ => {}
                }
                interruption = Some(UnfinishedVersion::new(version, why));
                break;
            }
        };

        // A server that named a different version declined this one.
        if named != Some(version) {
            break;
        }

        // A HelloRetryRequest counts: RFC 8446 §4.1.4 sends one only when the
        // server has found acceptable parameters and wants another key share, so
        // the suite it names is one it accepts. No handshake here completes.
        if retry {
            info!(
                verbosity = 3,
                "{addr} answered under {version} with a HelloRetryRequest naming 0x{suite:04X}"
            );
        }

        match remaining.iter().position(|held| held.code() == suite) {
            Some(at) => {
                let chosen = remaining.remove(at);
                // The first acceptance becomes the control offer.
                let _ = control.set(Control {
                    version,
                    suite: chosen,
                });
                accepted.push(chosen);
            }
            None => {
                // Not offered, so the offer cannot shrink.
                warn!(
                    verbosity = 2,
                    "{addr} selected cipher suite 0x{suite:04X} under {version}, which was not offered"
                );
                unrecognised.push(suite);
                break;
            }
        }
    }

    let found = (!accepted.is_empty() || !unrecognised.is_empty())
        .then(|| VersionSupport::new(version, accepted, unrecognised));
    (found, interruption)
}

/// An offer the endpoint has answered with a ServerHello: a version, and a
/// suite it chose under it.
#[derive(Debug, Clone, Copy)]
struct Control {
    version: TlsVersion,
    suite: CipherSuite,
}

impl Control {
    /// The offer of that suite alone, with `server_name`, which an endpoint still
    /// answering answers with a hello.
    fn offer<'a>(&'a self, server_name: Option<&'a str>) -> Offer<'a> {
        Offer {
            version: self.version,
            suites: std::slice::from_ref(&self.suite),
            server_name,
        }
    }
}

/// What putting one offer came to, once it had been put as often as it needed
/// to be.
enum Answer {
    /// A ServerHello, and what it named.
    Hello {
        version: Option<TlsVersion>,
        suite: u16,
        retry: bool,
    },
    /// The server declined the offer.
    Declined,
    /// No answer could be had, for the reason given.
    Interrupted(Interruption),
}

/// Puts `offer` to the endpoint until it is answered or declined, or until
/// asking again stops being worth it.
///
/// A lost exchange is retried after each of [`RETRY_PAUSES`]. A hang-up is
/// ambiguous: some stacks decline that way, and a rate limiter hangs up on
/// everything for a while. It is retried too, and a second hang-up is settled
/// by the `control`: if the endpoint answers the control, it is declining this
/// offer; if it hangs up on the control too, it is not answering.
///
/// With no control yet (no walk has had a hello), a second hang-up counts as
/// declining, which is how a stack treats a version it has disabled.
///
/// `may_probe` is asked before every connection, including the control's.
///
/// An offer with no socket available within `patience` is not retried.
async fn ask(
    addr: SocketAddr,
    egress: &Egress,
    offer: &Offer<'_>,
    control: &OnceLock<Control>,
    may_probe: &impl Fn() -> bool,
    patience: Duration,
) -> Answer {
    let mut hung_up = false;
    let mut pauses = RETRY_PAUSES.into_iter();

    loop {
        if !may_probe() {
            return Answer::Interrupted(Interruption::Stopped);
        }
        match exchange(addr, egress, offer, patience).await {
            Exchange::Answered(ServerResponse::Hello {
                version,
                suite,
                retry,
            }) => {
                return Answer::Hello {
                    version,
                    suite,
                    retry,
                };
            }
            // An alert, or a record that answers nothing.
            Exchange::Answered(_) | Exchange::Unreadable => return Answer::Declined,
            Exchange::HungUp if hung_up => {
                let Some(control) = control.get() else {
                    return Answer::Declined;
                };
                if !may_probe() {
                    return Answer::Interrupted(Interruption::Stopped);
                }
                match exchange(addr, egress, &control.offer(offer.server_name), patience).await {
                    Exchange::Answered(ServerResponse::Hello { .. }) => return Answer::Declined,
                    Exchange::Starved => return Answer::Interrupted(Interruption::FileLimit),
                    Exchange::Unasked => return Answer::Interrupted(Interruption::Stopped),
                    _ => {}
                }
            }
            Exchange::HungUp => hung_up = true,
            Exchange::Lost => {}
            Exchange::Starved => return Answer::Interrupted(Interruption::FileLimit),
            Exchange::Unasked => return Answer::Interrupted(Interruption::Stopped),
        }

        let Some(pause) = pauses.next() else {
            return Answer::Interrupted(Interruption::Unanswered);
        };
        tokio::time::sleep(pause).await;
    }
}

/// How one exchange ended.
enum Exchange {
    /// A TLS answer: a ServerHello naming the terms chosen, or an alert.
    Answered(ServerResponse),
    /// A whole record that is not a hello or an alert, or not TLS at all. Counts
    /// as declining.
    Unreadable,
    /// The connection closed or reset after the hello went out and before a
    /// whole answer came back.
    HungUp,
    /// No question was put or no answer came: the connection could not be
    /// made, the hello could not be sent, or nothing arrived in time.
    Lost,
    /// No question was put because the process had no socket to put it on,
    /// for as long as the offer would wait for one.
    Starved,
    /// No question was put because the scan stopped, or the host ran out of
    /// its budget, while the offer waited for its slot.
    Unasked,
}

/// One offer: connect, send the hello, read the first record back, hang up.
///
/// The connection is dropped once the answer is read; no handshake completes.
/// It leaves by `egress`.
///
/// A socket the process refuses is requested again for up to `patience`, each
/// attempt on its own clock, so waiting for a descriptor never eats into the
/// endpoint's time. A table still full past `patience` is
/// [`Exchange::Starved`].
async fn exchange(
    addr: SocketAddr,
    egress: &Egress,
    offer: &Offer<'_>,
    patience: Duration,
) -> Exchange {
    let hello = tls::client_hello(offer);

    // The slot, then a share of the descriptor budget, both before the offer's
    // clock starts, so queueing is never read as an endpoint that did not answer.
    let Ok(slot) = egress.slot(addr.ip()).await else {
        return Exchange::Unasked;
    };
    let _descriptor = descriptors::gate()
        .acquire()
        .await
        .expect("the descriptor gate is never closed");

    let (hello, slot_held) = (&hello, &slot);
    // Whether the last connect was refused before anything was sent, which
    // returns the slot.
    let unsent = &AtomicBool::new(false);
    let exchanged = descriptors::patiently(patience, || async move {
        timeout(EXCHANGE_TIMEOUT, async {
            let connected = timeout(
                CONNECT_PROBE_TIMEOUT,
                egress.connect_shaped(slot_held, addr, Shaping::default()),
            )
            .await;
            unsent.store(false, Ordering::Relaxed);
            let mut stream = match connected {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) if descriptors::exhausted(&e) => return Err(e),
                Ok(Err(e)) => {
                    unsent.store(pacing::never_left(&e), Ordering::Relaxed);
                    return Ok(Exchange::Lost);
                }
                Err(_elapsed) => return Ok(Exchange::Lost),
            };
            if stream.write_all(hello).await.is_err() {
                return Ok(Exchange::Lost);
            }
            Ok(match first_record(&mut stream).await {
                Record::Whole(record) => {
                    tls::read_response(&record).map_or(Exchange::Unreadable, Exchange::Answered)
                }
                // A cut record can still hold a whole ServerHello; the parser
                // refuses anything less.
                Record::Cut(partial) => {
                    tls::read_response(&partial).map_or(Exchange::HungUp, Exchange::Answered)
                }
                Record::Oversized => Exchange::Unreadable,
            })
        })
        .await
        .unwrap_or(Ok(Exchange::Lost))
    })
    .await;
    // Only a refusal of a socket comes back as an error, and only once
    // `patience` has passed.
    match exchanged {
        Ok(_) if unsent.load(Ordering::Relaxed) => slot.refund(),
        Ok(_) => drop(slot),
        Err(_) => slot.refund(),
    }
    exchanged.unwrap_or(Exchange::Starved)
}

/// What arrived on a connection, read as far as the first record.
enum Record {
    /// The first record whole, and possibly more behind it.
    Whole(Vec<u8>),
    /// Less than a whole record, possibly nothing, and then the peer closed or
    /// reset the connection.
    Cut(Vec<u8>),
    /// A header announcing a record no peer may send.
    Oversized,
}

/// Reads until the first TLS record is whole, or the peer stops being one.
///
/// A ServerHello may arrive in several TCP segments. Bounded by the record's
/// length field, which [`record_length`](crate::protocols::tls::record_length)
/// refuses past the largest TLS permits.
async fn first_record(stream: &mut TcpStream) -> Record {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    loop {
        match tls::record_length(&buffer) {
            Some(total) if buffer.len() >= total => return Record::Whole(buffer),
            Some(_) => {}
            // A complete header that yields no length announces an oversized
            // record.
            None if buffer.len() >= RECORD_HEADER_LEN => return Record::Oversized,
            None => {}
        }

        match stream.read(&mut chunk).await {
            // Close or reset: hand on what arrived.
            Ok(0) | Err(_) => return Record::Cut(buffer),
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
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
    use crate::model::tls::SuiteFault;
    use crate::testing::loopback::accept_from_this_process;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::net::TcpListener;

    use crate::protocols::tls::HELLO_RETRY_RANDOM;

    /// A server that accepts `version` and whichever of `accepts` it is offered,
    /// answering everything else with a fatal handshake_failure.
    ///
    /// Reads hellos by the RFC layout, independently of this crate's builder.
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
        /// A suite this server names whatever it was offered.
        ignores_the_offer: Option<u16>,
        /// Which connections it closes without a word, by the order it took
        /// them in, counting from one: a dropped exchange, or a rate limiter.
        hangs_up_on: fn(usize) -> bool,
        /// Whether it declines terms by closing the connection rather than by
        /// sending an alert, as some stacks do.
        refuses_by_hanging_up: bool,
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
                hangs_up_on: |_| false,
                refuses_by_hanging_up: false,
                seen: Arc::new(AtomicUsize::new(0)),
            }
        }

        /// Closes the connections `which` picks without reading or answering.
        fn hanging_up_on(mut self, which: fn(usize) -> bool) -> Self {
            self.hangs_up_on = which;
            self
        }

        /// Declines by closing the connection instead of sending an alert.
        fn refusing_by_hanging_up(mut self) -> Self {
            self.refuses_by_hanging_up = true;
            self
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
                    let Ok(mut stream) = accept_from_this_process(&listener).await else {
                        return;
                    };
                    let taken = self.seen.fetch_add(1, Ordering::SeqCst) + 1;
                    if (self.hangs_up_on)(taken) {
                        continue;
                    }

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

        /// The record this server sends back for `hello`, or nothing where it
        /// hangs up instead.
        fn answer(&self, hello: &[u8]) -> Vec<u8> {
            if let Some(fixed) = self.ignores_the_offer {
                return self.server_hello(fixed);
            }
            // A hang-up stack also hangs up on a disabled version; an alerting
            // one answers with its own version.
            if self.refuses_by_hanging_up && hello_version(hello) != Some(self.version) {
                return Vec::new();
            }
            let refusal = match self.refuses_by_hanging_up {
                true => Vec::new(),
                false => alert(),
            };
            let Some(offered) = offered_suites(hello) else {
                return refusal;
            };
            let Some(chosen) = offered.iter().find(|code| self.accepts.contains(code)) else {
                return refusal;
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

    /// A fatal handshake_failure alert.
    fn alert() -> Vec<u8> {
        vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]
    }

    /// The version field of a ClientHello, which reads `0x0303` for TLS 1.3.
    fn hello_version(hello: &[u8]) -> Option<u16> {
        // Past the record header and the handshake header.
        Some(u16::from_be_bytes([*hello.get(9)?, *hello.get(10)?]))
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

    /// Every accepted suite is found, nothing else is claimed, and the walk stops.
    #[tokio::test]
    async fn every_accepted_suite_is_found_and_nothing_else_is() {
        // One strong suite, one without forward secrecy, one broken.
        let accepted = [0xC02F, 0x009C, 0x000A];
        let (addr, _) = FakeTlsServer::new(0x0303, accepted).spawn().await;

        let support = enumerate_tls(addr).await;

        assert!(support.accepts(TlsVersion::Tls12));
        assert_eq!(support.floor(), Some(TlsVersion::Tls12));
        assert_eq!(support.ceiling(), Some(TlsVersion::Tls12));

        let found: BTreeSet<u16> = support.suites().iter().map(|suite| suite.code()).collect();
        assert_eq!(found, accepted.into_iter().collect::<BTreeSet<_>>());
    }

    /// A server holding its sites by name accepts only hellos carrying the name.
    #[tokio::test]
    async fn an_endpoint_holding_its_sites_by_name_is_enumerated_by_the_name() {
        let addr = crate::testing::loopback::https_site("box.example", |_| None).await;

        let named = enumerate_tls_named(addr, "box.example").await;
        assert!(named.accepts(TlsVersion::Tls13), "{named:?}");
        assert!(named.accepts(TlsVersion::Tls12), "{named:?}");
        assert!(named.unfinished().is_empty(), "{named:?}");

        let nameless = enumerate_tls(addr).await;
        assert!(nameless.suites().is_empty(), "{nameless:?}");
    }

    /// Connections equal the suites accepted plus the refusal that ends the walk.
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

    /// A HelloRetryRequest names an accepted suite.
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

    /// A server answering every offer with 1.2 accepts 1.2 and nothing else.
    #[tokio::test]
    async fn a_server_that_answers_with_another_version_is_not_credited_the_one_offered() {
        // Answers 0x0303 whatever it is asked.
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

    /// A server that refuses everything is reported as empty.
    #[tokio::test]
    async fn a_server_that_refuses_everything_yields_nothing() {
        let (addr, _) = FakeTlsServer::new(0x0303, []).spawn().await;

        let support = enumerate_tls(addr).await;
        assert!(support.is_empty());
        assert_eq!(support.floor(), None);
        assert!(support.weakest().is_none());
    }

    /// A refused connection leaves every version unfinished; it is not a
    /// refusal of the hello.
    #[tokio::test]
    async fn a_closed_port_leaves_every_version_unfinished() {
        let addr = crate::testing::loopback::refused_port(std::net::IpAddr::from([127, 0, 0, 1]));

        let support = enumerate_tls(addr).await;
        assert!(support.versions().is_empty(), "nothing was accepted");
        assert_eq!(
            support.unfinished(),
            TlsVersion::ALL
                .iter()
                .map(|&version| UnfinishedVersion::new(version, Interruption::Unanswered))
                .collect::<Vec<_>>()
        );
    }

    /// A deprecated version, which rustls cannot ask about, is found and named.
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

        use crate::model::tls::{SuiteFault, SuiteStrength};
        assert_eq!(support.weakest(), Some(SuiteStrength::Insecure));
        assert!(support.faults().contains(&SuiteFault::SmallBlock));
    }

    /// A server naming a suite it was never offered ends the version, and the
    /// suite number is kept.
    #[tokio::test]
    async fn a_server_naming_a_suite_it_was_not_offered_ends_the_walk() {
        // 0xFF01 is in no registry.
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

    /// A non-TLS answer ends the walk.
    #[tokio::test]
    async fn a_peer_that_is_not_tls_settles_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");
        tokio::spawn(async move {
            while let Ok(mut stream) = accept_from_this_process(&listener).await {
                let mut scratch = [0u8; 1024];
                let _ = stream.read(&mut scratch).await;
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            }
        });

        let support = enumerate_tls(addr).await;
        assert!(support.is_empty());
    }

    /// A ServerHello split across two segments is read whole.
    #[tokio::test]
    async fn a_server_hello_arriving_in_pieces_is_still_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");
        let server = FakeTlsServer::new(0x0303, [0xC02F]);

        tokio::spawn(async move {
            while let Ok(mut stream) = accept_from_this_process(&listener).await {
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

    /// A server accepting every suite its version can express is enumerated
    /// completely.
    #[tokio::test]
    async fn a_server_accepting_everything_is_enumerated_to_the_end() {
        let every: Vec<u16> = CipherSuite::offered_under(TlsVersion::Tls12)
            .map(|suite| suite.code())
            .collect();
        let (addr, _) = FakeTlsServer::new(0x0303, every.clone()).spawn().await;

        let support = enumerate_tls(addr).await;

        assert_eq!(
            support.suites().len(),
            every.len(),
            "every suite the server accepts has to be found, not the first {MAX_OFFERS_PER_VERSION}"
        );
    }

    /// One connection lost part way through a walk is retried and the walk
    /// continues.
    #[tokio::test]
    async fn a_connection_lost_mid_walk_does_not_end_the_walk() {
        let every: Vec<u16> = CipherSuite::offered_under(TlsVersion::Tls12)
            .map(|suite| suite.code())
            .collect();
        // After the first offer of each version, so the TLS 1.2 walk loses one
        // with suites still to find.
        let (addr, _) = FakeTlsServer::new(0x0303, every.clone())
            .hanging_up_on(|taken| taken == 20)
            .spawn()
            .await;

        let support = enumerate_tls(addr).await;

        assert_eq!(
            support.suites().len(),
            every.len(),
            "the offer the lost connection carried is put again, and the walk goes on"
        );
        assert!(support.is_complete());
    }

    /// An endpoint that keeps hanging up, on the control offer too (a rate
    /// limiter with a long window), leaves its walk unfinished.
    #[tokio::test]
    async fn an_endpoint_that_goes_on_hanging_up_leaves_the_walk_unfinished() {
        let every: Vec<u16> = CipherSuite::offered_under(TlsVersion::Tls12)
            .map(|suite| suite.code())
            .collect();
        let (addr, _) = FakeTlsServer::new(0x0303, every.clone())
            .hanging_up_on(|taken| taken >= 20)
            .spawn()
            .await;

        let support = enumerate_tls(addr).await;

        let found = support.suites().len();
        assert!(
            (1..every.len()).contains(&found),
            "what was found before the endpoint went quiet is kept, and it is not \
             everything: {found} of {}",
            every.len()
        );
        assert_eq!(
            support.unfinished(),
            &[UnfinishedVersion::new(
                TlsVersion::Tls12,
                Interruption::Unanswered
            )],
            "the walk it cut short is named, and no other"
        );
    }

    /// An offer with no socket available is reported as the file limit, not the
    /// endpoint's silence, so the remedy (a higher limit) is clear. It is not
    /// retried.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_offer_with_no_socket_to_put_it_on_is_named_for_the_file_limit() {
        use crate::system::descriptors::testing::{
            in_a_process_of_its_own, refuse_every_descriptor,
        };

        if !in_a_process_of_its_own(
            module_path!(),
            "an_offer_with_no_socket_to_put_it_on_is_named_for_the_file_limit",
        ) {
            return;
        }
        // Listening before the table fills; nothing will reach it.
        let (addr, seen) = FakeTlsServer::new(0x0303, [0xC02F]).spawn().await;
        let suites: Vec<CipherSuite> = CipherSuite::offered_under(TlsVersion::Tls12).collect();
        let offer = Offer {
            version: TlsVersion::Tls12,
            suites: &suites,
            server_name: None,
        };
        let held = refuse_every_descriptor();

        let answer = ask(
            addr,
            &Egress::KERNEL,
            &offer,
            &OnceLock::new(),
            &|| true,
            Duration::from_millis(200),
        )
        .await;
        drop(held);

        let cause = match answer {
            Answer::Interrupted(why) => why.name(),
            Answer::Hello { .. } => "a hello",
            Answer::Declined => "declined",
        };
        assert_eq!(cause, Interruption::FileLimit.name());
        assert_eq!(seen.load(Ordering::SeqCst), 0, "the endpoint was reached");
    }

    /// A server that declines by hanging up leaves nothing unfinished.
    #[tokio::test]
    async fn a_server_that_declines_by_hanging_up_leaves_nothing_unfinished() {
        let accepted = [0xC02F, 0x009C];
        let (addr, _) = FakeTlsServer::new(0x0303, accepted)
            .refusing_by_hanging_up()
            .spawn()
            .await;

        let support = enumerate_tls(addr).await;

        let found: BTreeSet<u16> = support.suites().iter().map(|suite| suite.code()).collect();
        assert_eq!(found, accepted.into_iter().collect::<BTreeSet<_>>());
        assert_eq!(support.floor(), Some(TlsVersion::Tls12));
        assert!(
            support.is_complete(),
            "every hang-up here was the server declining: {:?}",
            support.unfinished()
        );
    }

    /// A legacy endpoint's three `High` findings come from suites at the far end
    /// of the registry; a walk stopped early would report only `Low` faults.
    #[tokio::test]
    async fn the_high_severity_faults_survive_a_full_offer_list() {
        let every: Vec<u16> = CipherSuite::offered_under(TlsVersion::Tls12)
            .map(|suite| suite.code())
            .collect();
        let (addr, _) = FakeTlsServer::new(0x0303, every).spawn().await;

        let support = enumerate_tls(addr).await;
        let faults: BTreeSet<SuiteFault> = support.faults().into_iter().collect();

        for expected in [
            SuiteFault::NullCipher,
            SuiteFault::Anonymous,
            SuiteFault::Export,
            SuiteFault::Rc4,
            SuiteFault::Md5Mac,
            SuiteFault::SmallBlock,
        ] {
            assert!(
                faults.contains(&expected),
                "{expected} is carried by a suite this server accepts and has to be reported"
            );
        }
        assert_eq!(
            support.weakest(),
            Some(crate::model::tls::SuiteStrength::Insecure)
        );
    }

    /// The ceiling may never sit below the registry it bounds.
    ///
    /// A suite added to `CipherSuite::ALL` must not leave the walk truncating.
    #[test]
    fn the_offer_ceiling_is_never_below_what_a_version_can_offer() {
        for &version in TlsVersion::ALL {
            let offered = CipherSuite::offered_under(version).count();
            assert!(
                offered <= MAX_OFFERS_PER_VERSION,
                "{version} offers {offered} suites against a ceiling of {MAX_OFFERS_PER_VERSION}, \
                 so a server accepting them all would be cut short"
            );
        }
    }

    /// No finding from an enumeration claims a completed handshake.
    #[tokio::test]
    async fn a_finding_does_not_claim_a_handshake_the_scan_never_completed() {
        let (addr, _) = FakeTlsServer::new(0x0301, [0x002F]).spawn().await;

        let support = enumerate_tls(addr).await;
        let findings = support.findings();
        assert!(
            !findings.is_empty(),
            "a TLS 1.0 endpoint is worth reporting"
        );

        for finding in &findings {
            let excerpt = finding.excerpt().as_str();
            assert!(
                !excerpt.contains("completed"),
                "the excerpt claims a completed negotiation: {excerpt}"
            );
        }
    }

    /// Including for a HelloRetryRequest.
    #[tokio::test]
    async fn a_retrying_server_is_not_reported_as_having_negotiated() {
        let (addr, _) = FakeTlsServer::new(0x0301, [0x000A])
            .retrying()
            .spawn()
            .await;

        let support = enumerate_tls(addr).await;
        assert!(
            support.accepts(TlsVersion::Tls10),
            "a retry still names a suite the server would use"
        );
        for finding in support.findings() {
            assert!(
                !finding.excerpt().as_str().contains("completed"),
                "a HelloRetryRequest is the one answer that certainly completed nothing"
            );
        }
    }

    /// A peer that hangs up part way through its ServerHello: the parser refuses
    /// the partial hello, which would otherwise pass a truncated 1.3 hello as
    /// 1.2.
    #[tokio::test]
    async fn a_peer_that_hangs_up_mid_hello_settles_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");
        let server = FakeTlsServer::new(0x0304, [0x1301]).answering_in_the_extension();

        tokio::spawn(async move {
            while let Ok(mut stream) = accept_from_this_process(&listener).await {
                let mut buffer = vec![0u8; 4096];
                let Ok(read) = stream.read(&mut buffer).await else {
                    continue;
                };
                let answer = server.answer(&buffer[..read]);
                // Everything but the extension block, then a close.
                let cut = 5 + 4 + 2 + 32 + 1 + 2 + 1;
                let _ = stream.write_all(&answer[..cut.min(answer.len())]).await;
                drop(stream);
            }
        });

        let support = enumerate_tls(addr).await;
        assert!(
            support.is_empty(),
            "a hello that never finished arriving is not an accepted version, \
             and certainly not the 1.2 its legacy field claims"
        );
    }
}
