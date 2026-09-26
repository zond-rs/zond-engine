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
//! ## A lost exchange is not a refusal
//!
//! A server declines an offer by saying so: an alert, a reply that is not TLS,
//! or a hello naming another version. A connection that fails, or an answer
//! that never comes, says nothing about the offer, and a walk that read one as
//! a refusal would record the suites found so far as the whole answer. What
//! that loses is the tail of the server's preference order, which is where a
//! legacy configuration keeps RC4, the export ciphers and the anonymous key
//! exchanges, and eighty connections in a row is what a walk asks of a rate
//! limiter or an embedded stack. So a lost exchange is put again after a pause,
//! and a version whose walk still cannot go on is listed under
//! [`TlsSupport::unfinished`] rather than passed off as complete.
//!
//! A connection closed unanswered could be either, since some stacks decline
//! by hanging up; `ask` documents how the two are told apart.
//!
//! ## What it costs, and what bounds it
//!
//! One TCP connection per exchange, and the five versions are walked
//! concurrently because each is independent of the others. A current server
//! accepting a handful of suites under 1.2 and 1.3 and refusing the rest costs a
//! dozen connections.
//!
//! An old one accepting everything costs far more — up to 80 exchanges under
//! TLS 1.2 alone, and 56 under each of SSL 3.0, 1.0 and 1.1 — and that is the
//! case this exists to find, so it is a cost to bound in time rather than to cut
//! short by count. [`ZondConfig::host_timeout`](crate::config::ZondConfig::host_timeout)
//! is what bounds it. A scan asks before every connection whether the host may
//! still be probed, so a host that would take longer than its budget is left
//! within one exchange of it, keeps what was found, and is *named in the report
//! as having been left early*, which a walk stopped by a count is not.
//! [`MAX_OFFERS_PER_VERSION`] is set at the registry's own size and so bounds
//! only a defect in the loop; see its documentation for what any ceiling below
//! the registry would cost.

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::limits::CONNECT_PROBE_TIMEOUT;
use crate::model::tls::{
    CipherSuite, Interruption, TlsSupport, TlsVersion, UnfinishedVersion, VersionSupport,
};
use crate::protocols::tls::{self, Offer, RECORD_HEADER_LEN, ServerResponse};
use crate::system::descriptors;
use crate::transport::dial::{Egress, Shaping};
use crate::{info, warn};

/// The most offers put to one endpoint under one version.
///
/// Derived from the registry rather than chosen, because the walk's own
/// arithmetic already fixes it: every answer removes exactly one suite from the
/// offer and every other outcome ends the version, so a walk cannot put more
/// questions than the version had suites to begin with. This is that number,
/// for the version carrying the most of them.
///
/// **A ceiling below the registry is not a safety net.** One that sounds
/// generous, two dozen say, is reached by ordinary servers rather than
/// pathological ones: TLS 1.2 offers 80 suites and a stock OpenSSL `DEFAULT`
/// list accepts far more than 24 of them. Reaching it ends the walk silently:
/// the report names the suites found before the cut and says nothing about the
/// ones never asked for. Because the walk removes each suite as the *server*
/// selects it, what a cut drops is the tail of the server's own preference
/// order, which is where a legacy configuration keeps RC4, the export ciphers
/// and the anonymous key exchanges — the findings the enumeration exists to
/// produce.
///
/// A ceiling at the registry's own size cannot do that. It bounds the walk
/// against a defect in the loop below and against nothing else, since a peer
/// answering with a suite it was not offered already ends the version.
pub const MAX_OFFERS_PER_VERSION: usize = CipherSuite::MOST_OFFERED_UNDER_ONE_VERSION;

/// How long one offer may take, from the connection to the answer.
///
/// A server that has already been found to speak TLS answers a hello in a round
/// trip. This is generous against that. An exchange that outlasts it is lost
/// and put again, so a tarpit costs the version's walk three of these rather
/// than costing the scan.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long to wait before putting an offer again whose exchange was lost, one
/// entry to a retry.
///
/// A lost exchange has two usual causes, and the pauses are set by them. A busy
/// embedded stack drops connections when its accept queue overflows, which five
/// concurrent walks are enough to do; a quarter of a second is many round trips,
/// and the queue has drained by then. A rate limiter refuses connections past a
/// budget counted per second, and the second pause outlasts one. A limiter
/// holding a longer window outlasts both, and the version is then recorded as
/// unfinished rather than waited out: the pauses are paid per lost offer, and a
/// walk is up to eighty offers.
const RETRY_PAUSES: [Duration; 2] = [Duration::from_millis(250), Duration::from_secs(1)];

/// Everything `addr` accepts, version by version.
///
/// Empty where the endpoint accepted nothing under any version. That is a real
/// answer and not a failure: a server may be strictly configured, or may have
/// been asked without the name it insists on, since an endpoint known only by
/// its address is asked for no name. See
/// [`Offer::server_name`](crate::protocols::tls::Offer::server_name).
///
/// A version whose walk the endpoint cut short, by going on not answering when
/// asked again, is listed under [`TlsSupport::unfinished`], and whatever it had
/// accepted by then is kept.
///
/// Every connection goes where the routing table sends it. A scan forced to a
/// source enumerates through the same walk with its connections pinned there.
pub async fn enumerate_tls(addr: SocketAddr) -> TlsSupport {
    enumerate_tls_while(addr, None, Egress::KERNEL, || true).await
}

/// [`enumerate_tls`], asking `may_probe` before every connection and ending
/// each version's walk at the first no.
///
/// For a caller whose budget the walk has to answer to. One endpoint is up to
/// 80 offers under TLS 1.2 alone, so a budget consulted once before the walk
/// bounds almost nothing; consulted here, a walk ends within one exchange of
/// it. What was learned before the answer turned is kept, since every suite in
/// it was named by the server, and each version it cut short is listed as
/// [`Interruption::Stopped`].
///
/// Every connection leaves by `egress`, and every hello asks for
/// `server_name` where there is one: the name a target reached the address by,
/// without which a server holding its sites by name refuses every offer and
/// the endpoint reads as accepting nothing.
pub(crate) async fn enumerate_tls_while(
    addr: SocketAddr,
    server_name: Option<&str>,
    egress: Egress,
    may_probe: impl Fn() -> bool,
) -> TlsSupport {
    let may_probe = &may_probe;
    // Shared by the five walks, so one with nothing accepted yet can still tell
    // a server declining its offer from one not answering at all. See `ask`.
    let control = OnceLock::new();
    let control = &control;
    // Fixed at five, so the versions are joined rather than spawned: what they
    // share is borrowed from this frame, and none of them outlives this call.
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
/// The first half is what the version accepted, `None` where it accepted
/// nothing, which is the ordinary outcome for four of the five against a
/// current server. The second is the walk's own account of ending before the
/// endpoint had declined anything, where it did.
async fn walk(
    addr: SocketAddr,
    server_name: Option<&str>,
    egress: Egress,
    version: TlsVersion,
    control: &OnceLock<Control>,
    may_probe: &impl Fn() -> bool,
) -> (Option<VersionSupport>, Option<UnfinishedVersion>) {
    let mut remaining: Vec<CipherSuite> = CipherSuite::offered_under(version).collect();
    let mut accepted: Vec<CipherSuite> = Vec::new();
    let mut unrecognised: Vec<u16> = Vec::new();
    let mut interruption = None;

    // Counted rather than bounded by a `for`, so that exhausting the budget is
    // distinguishable from finishing. With the ceiling at the registry's size
    // this can only be reached by a walk that stopped narrowing, which is a
    // defect here rather than anything a server did, so it is said out loud.
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
            // The server declined these terms and the walk has nothing
            // narrower to ask. This is the one way a walk finishes.
            Answer::Declined => break,
            Answer::Interrupted(why) => {
                // A stop is the caller's, which says so itself; a silence is
                // this endpoint's, and a full table this machine's, and
                // nothing else will mention either.
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

        // A server that named a different version declined this one, whatever
        // else it did. Crediting the offer would report a deprecated version on
        // the strength of not having read the answer.
        if named != Some(version) {
            break;
        }

        // A HelloRetryRequest counts, and it is bound above rather than
        // discarded so that saying so is a decision on the record. RFC 8446
        // §4.1.4 sends one only when the server has *already* found an
        // acceptable set of parameters and wants a different key share, so it
        // names a suite it is willing to use exactly as a plain ServerHello
        // does. What it is not is a completed handshake — no handshake here is
        // completed, which is why no finding drawn from this claims one.
        if retry {
            info!(
                verbosity = 3,
                "{addr} answered under {version} with a HelloRetryRequest naming 0x{suite:04X}"
            );
        }

        match remaining.iter().position(|held| held.code() == suite) {
            Some(at) => {
                let chosen = remaining.remove(at);
                // The first acceptance any walk reads is the question every
                // walk can put to find out whether the endpoint is answering.
                let _ = control.set(Control {
                    version,
                    suite: chosen,
                });
                accepted.push(chosen);
            }
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
    /// The offer of that suite alone, asking for `server_name` as the walk's
    /// own offers do, which an endpoint still answering answers with a hello.
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
/// A lost exchange says nothing about the offer, so it is put again after each
/// of [`RETRY_PAUSES`]. A connection closed without an answer is the one outcome
/// that could mean either. Some stacks decline by hanging up, on a version they
/// have disabled or on an offer holding nothing they accept, and a rate limiter
/// hangs up on everything for a while. So a hang-up is put again too, and a
/// second one is settled by the `control`: an endpoint that hangs up on this
/// offer twice and answers the control is declining the offer, and one that
/// hangs up on the control as well is not answering anything.
///
/// Where no walk has had a hello from this endpoint yet there is no control, and
/// a second hang-up is taken as declining. That is what a stack that disabled a
/// version does to every hello asking for it, and with nothing the endpoint is
/// known to answer there is no evidence the other way.
///
/// `may_probe` is asked before every connection, the control's included.
///
/// An offer the process had no socket for within `patience` is not put again:
/// the wait for one was already as long as any offer waits, and a full table
/// is this machine's, so a pause says nothing more about the endpoint.
async fn ask(
    addr: SocketAddr,
    egress: Egress,
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
                    _ => {}
                }
            }
            Exchange::HungUp => hung_up = true,
            Exchange::Lost => {}
            Exchange::Starved => return Answer::Interrupted(Interruption::FileLimit),
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
    /// A whole record that is not an answer: bytes that are not TLS, or TLS
    /// carrying something other than a hello or an alert. The peer is not
    /// taking the question, which settles it as surely as an alert does.
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
}

/// One offer: connect, send the hello, read the first record back, hang up.
///
/// The connection is dropped as soon as the answer is read. Nothing is
/// completed, so the endpoint sees a client that opened a connection, asked what
/// it would accept, and left. It leaves by `egress`.
///
/// A socket the process refuses is asked for again for up to `patience`, and
/// each attempt runs on a clock of its own: a refusal comes back before
/// anything is sent, so the wait for a descriptor never comes out of the time
/// the endpoint has to answer, and a table still full past `patience` is
/// [`Exchange::Starved`] rather than an offer lost on the endpoint's account.
async fn exchange(
    addr: SocketAddr,
    egress: Egress,
    offer: &Offer<'_>,
    patience: Duration,
) -> Exchange {
    let hello = tls::client_hello(offer);

    // The five versions' walks each hold a connection at once, so each offer
    // takes its own share of the process's descriptor budget. Taken before the
    // offer's clock starts, so a queue for a socket is never read as an
    // endpoint that did not answer.
    let _descriptor = descriptors::gate()
        .acquire()
        .await
        .expect("the descriptor gate is never closed");

    let hello = &hello;
    let exchanged = descriptors::patiently(patience, || async move {
        timeout(EXCHANGE_TIMEOUT, async {
            let connected = timeout(
                CONNECT_PROBE_TIMEOUT,
                egress.connect_shaped(addr, Shaping::default()),
            )
            .await;
            let mut stream = match connected {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) if descriptors::exhausted(&e) => return Err(e),
                _ => return Ok(Exchange::Lost),
            };
            if stream.write_all(hello).await.is_err() {
                return Ok(Exchange::Lost);
            }
            Ok(match first_record(&mut stream).await {
                Record::Whole(record) => {
                    tls::read_response(&record).map_or(Exchange::Unreadable, Exchange::Answered)
                }
                // A record cut short can still hold a whole ServerHello, where
                // the server coalesced more messages behind it, and that is an
                // answer. The parser refuses anything short of one.
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
/// TCP delivers a record in as many pieces as it likes, so a single read is not
/// enough; a ServerHello arriving in two segments would otherwise be parsed as a
/// truncated one and the version reported unsupported. What bounds this is the
/// record's own length field, which
/// [`record_length`](crate::protocols::tls::record_length) refuses past the
/// largest TLS permits, so a stranger cannot decide how much this process
/// buffers.
async fn first_record(stream: &mut TcpStream) -> Record {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    loop {
        match tls::record_length(&buffer) {
            Some(total) if buffer.len() >= total => return Record::Whole(buffer),
            // The header is here and the body is not. Keep reading.
            Some(_) => {}
            // Past five bytes a header that still yields nothing is one
            // announcing a record no peer may send.
            None if buffer.len() >= RECORD_HEADER_LEN => return Record::Oversized,
            None => {}
        }

        match stream.read(&mut chunk).await {
            // A close and a reset are one outcome here: either way the peer
            // went before the record was whole, and what arrived is handed on.
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
            // A stack that declines by hanging up does so for a version it has
            // disabled too, where an alerting one answers with its own version
            // and leaves the walk to decline it.
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

    /// A fatal handshake_failure, which is what a server sends when it will not
    /// accept any of the terms offered.
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

    /// A server holding its sites by name refuses a hello naming none of them,
    /// so an endpoint a target reached by name is enumerated asking for that
    /// name, and what it accepts is found; asked for nothing, it accepts
    /// nothing.
    #[tokio::test]
    async fn an_endpoint_holding_its_sites_by_name_is_enumerated_by_the_name() {
        let addr = crate::testing::loopback::https_site("box.example", |_| None).await;

        let named = enumerate_tls_while(addr, Some("box.example"), Egress::KERNEL, || true).await;
        assert!(named.accepts(TlsVersion::Tls13), "{named:?}");
        assert!(named.accepts(TlsVersion::Tls12), "{named:?}");
        assert!(named.unfinished().is_empty(), "{named:?}");

        let nameless = enumerate_tls(addr).await;
        assert!(nameless.suites().is_empty(), "{nameless:?}");
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

    /// Nothing listening settles nothing, and says so rather than reading as
    /// an endpoint that refused every version.
    ///
    /// The port was open when the scan found it, and a connection refused now
    /// is a listener gone or a limiter at work: neither is an answer to the
    /// hello that was never sent.
    #[tokio::test]
    async fn a_closed_port_leaves_every_version_unfinished() {
        // Bound and dropped, so the port is closed and connections are refused.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");
        drop(listener);

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

    /// A deprecated version is found and named, which is the whole point: this
    /// is the configuration rustls cannot ask about, so without this pass it
    /// would be invisible.
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
            while let Ok(mut stream) = accept_from_this_process(&listener).await {
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

    /// **The defect a ceiling below the registry hides.**
    ///
    /// A server accepting every suite its version can express is enumerated
    /// completely. A walk stopped after 24 offers would name 24 of the 80
    /// suites without saying it had stopped — and because the walk removes each
    /// suite as the *server* picks it, the 56 it never asked about would be the
    /// tail of that server's own preference order, which is where RC4, the
    /// export ciphers and the anonymous exchanges live.
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

    /// One connection lost part way through a walk costs that connection and
    /// not the rest of the walk.
    ///
    /// The walk removes each suite as the server picks it, so what a walk
    /// ending at a dropped connection loses is the tail of the server's own
    /// preference order: where a legacy configuration keeps RC4, the export
    /// ciphers and the anonymous exchanges. A rate limiter or a busy embedded
    /// stack drops connections readily, and eighty in a row is what a walk
    /// asks of it.
    #[tokio::test]
    async fn a_connection_lost_mid_walk_does_not_end_the_walk() {
        let every: Vec<u16> = CipherSuite::offered_under(TlsVersion::Tls12)
            .map(|suite| suite.code())
            .collect();
        // Past the first offer of each of the five versions, so the connection
        // lost is one the TLS 1.2 walk made with suites still to find.
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

    /// An endpoint that goes on hanging up leaves its walk unfinished, and says
    /// so, rather than passing what was found as the whole answer.
    ///
    /// A rate limiter holding a window longer than the retries is the case: it
    /// hangs up on the known-good control offer as readily as on the walk's, and
    /// that is what separates it from a server declining the offer.
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

    /// An offer the process had no socket for is named for the file limit, not
    /// for the endpoint.
    ///
    /// Nothing reached the endpoint, so reading the refusal as its silence
    /// would send a reader to a slower scan, which gets past a rate limiter
    /// and not past a full descriptor table; the remedy is a higher limit, and
    /// only a cause naming it says so. Nor is such an offer put again after a
    /// pause: the wait for a socket was already as long as an offer waits.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_offer_with_no_socket_to_put_it_on_is_named_for_the_file_limit() {
        use crate::system::descriptors::testing::{exhaust, in_a_process_of_its_own};

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
        let held = exhaust(64);

        let answer = ask(
            addr,
            Egress::KERNEL,
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

    /// A server that declines by hanging up rather than by alert is declining,
    /// and leaves nothing unfinished.
    ///
    /// Some stacks answer a version they have disabled, or an offer holding
    /// nothing they accept, by closing the connection. Read as a lost exchange,
    /// every walk against one would end unfinished, and the marker would say
    /// nothing about the endpoints it is meant to single out.
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

    /// And what that costs the report, which is the reason it matters.
    ///
    /// The three `High` findings a legacy endpoint exists to produce are drawn
    /// from suites at the far end of the registry. A walk that stops early
    /// reports the endpoint as carrying three `Low` faults and nothing worse.
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
    /// The whole of the defect above in one assertion: a suite added to
    /// `CipherSuite::ALL` must not silently leave the walk truncating.
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

    /// No finding drawn from an enumeration may claim a completed handshake,
    /// because the enumeration never completes one: it offers, reads the
    /// ServerHello, and hangs up.
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

    /// And most sharply for a HelloRetryRequest, whose entire meaning is that
    /// the server has *not* settled and wants the client to ask again.
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

    /// A hello cut short, from the scan's side: a peer that hangs up part way
    /// through its ServerHello hands `first_record` a partial buffer, and the
    /// parser refuses anything short of a whole hello. Read as it stands, a
    /// truncated 1.3 hello would pass for a 1.2 one, and an endpoint speaking
    /// only 1.3 would be reported as accepting nothing at all.
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
