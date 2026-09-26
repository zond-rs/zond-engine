// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Service Fingerprinting
//!
//! Identifies the service, product, and version behind an open port. This is
//! distinct from discovery (which ports are alive); fingerprinting answers
//! *what is running there*.
//!
//! ## Shape
//!
//! ```text
//! open port ─▶ probe I/O (async) ─▶ responses ─▶ analyzers (CPU, off-reactor)
//!                                                     │
//!                                              Vec<Evidence>
//!                                                     ▼
//!                                        Resolver ─▶ ServiceVerdict ─▶ Service
//! ```
//!
//! * [`model`] is the shared vocabulary: [`Evidence`], [`ServiceVerdict`],
//!   [`Confidence`](crate::model::confidence::Confidence).
//! * [`SignatureDb`] is the runtime view of the signature database: a cheap
//!   `port -> name` index plus lazily compiled, cached matchers.
//! * [`Analyzer`]s are the extension point; [`BannerRegexAnalyzer`] is the first.
//!
//! ## Concurrency contract
//!
//! Every analyzer runs in two phases and `analyze` enforces the split: the
//! transport's first-contact I/O and each analyzer's own `collect` probes run on
//! the async reactor; all `analyze` (CPU) work is handed to the blocking pool.
//! Nothing in this module compiles a regex on a reactor thread; see
//! `SignatureDb` for why that matters.

pub mod model;

pub mod os;

mod analyzer;
mod authority;
mod context;
mod db;
mod extract;
mod favicon;
mod framed;
mod http;
mod jarm;
mod matcher;
// Crate-visible so the Tier-1 flow interpreter compiles its `expect`/`bind`
// patterns through the one engine every Tier-0 signature does.
pub(crate) mod pattern;
mod prefilter;
mod response;
mod signature;
mod sip;
mod snmp;
mod ssh;
mod tls;
mod tls_cert;
mod tls_enum;
mod tls_summary;

#[cfg(test)]
mod corpus;
// Kept apart from `pattern` because `build.rs` loads that file with `#[path]`
// and has no `proptest`; see the module docs.
#[cfg(test)]
mod pattern_properties;

pub use analyzer::{Analyzer, BannerRegexAnalyzer, PortContext};
pub use db::{InvalidDefinition, SignatureDb};
pub use favicon::FaviconAnalyzer;
// The icon digest a scan would compute, for the container tier's harvest pass.
#[cfg(any(test, feature = "test-support"))]
pub use favicon::digest_of as favicon_digest;
pub use http::HttpHeadersAnalyzer;
pub use jarm::JarmAnalyzer;
pub use model::{Evidence, ServiceVerdict, SourceId, Tunnel};
pub use response::{Collected, ResponseSet, TlsInfo};
// The schema an `assets/fingerprinting` signature file is written against.
// `build.rs` compiles the shipped signatures out of it and validates them; these
// are exported so a consumer authoring signatures of their own is held to the
// same bounds rather than discovering them when a pattern is silently dropped.
// The register of every field a signature may be written against, and whether
// anything in this engine produces it. Exported because a consumer authoring
// signatures needs to know which fields actually arrive, and because a rule
// reading one that does not is inert in a way nothing else reveals.
pub use context::{CONTEXTS, Context, Reach, context_note, reach_of};
pub use signature::{
    CORPUS_ROOT, DefinitionError, MAX_COMPILED_REGEX_BYTES, MAX_UDP_PROBE_BYTES, MatchRule, Probe,
    RULE_ID_SEPARATOR, RuleIdDefect, ServiceDefinition, ServiceSignature, claim_rule_id,
    corpus_slug, rule_id,
};
// The payload decoder Tier-0 probes use, reused by the Tier-1 interpreter to turn
// a flow's `\x`/`\r\n` escapes into the bytes it sends. Crate-visible, not public.
pub(crate) use signature::unescape;
pub use ssh::SshAnalyzer;
pub use tls_cert::TlsCertAnalyzer;
pub use tls_enum::{EXCHANGE_TIMEOUT, MAX_OFFERS_PER_VERSION, enumerate_tls};
// The same walk answering to a scan's budget; see its documentation.
pub(crate) use tls_enum::enumerate_tls_while;

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::ServiceDetection;
use crate::model::port::{Port, PortState, Protocol, Service};
use crate::system::descriptors;
use crate::transport::dial::PathAllowance;
use crate::transport::dial::{Egress, Shaping};
use authority::Authority;

/// How long to wait for a service to speak first (banner grab).
///
/// This and every wait below that waits on the peer is how long the service
/// may take on a path that costs nothing. A scan that measured the path gives
/// each its allowance on top; see [`on_path`].
const BANNER_READ_TIMEOUT: Duration = Duration::from_millis(500);
/// How long to wait for a reply to an active probe.
const PROBE_READ_TIMEOUT: Duration = Duration::from_millis(1_000);
/// How long to keep reading once a response has started arriving.
///
/// Not a second timeout on the response: the response has already begun, and
/// this is only how long its remainder is worth waiting for. What it has to
/// bridge is the gap between a server writing its headers and writing its body,
/// which is a segment boundary rather than a delay, so sub-millisecond on a
/// segment and one round trip at worst anywhere else.
///
/// It is paid in full by every response that is *already* complete, since a
/// finished server simply goes quiet and there is no way to tell that apart from
/// a slow one without waiting. So it is set as low as the job allows: fifty
/// milliseconds bridges any real gap, and the ports pay it in parallel, so it
/// costs a scan the grace once rather than once per port.
const CONTINUATION_GRACE: Duration = Duration::from_millis(50);
/// What this engine calls itself when it asks an HTTP server a question.
///
/// One place, so the authored probe in `assets/fingerprinting/web/http.toml` and
/// the redirect this code follows on its own introduce the same scanner. A
/// server's logs should show one visitor, not two.
const USER_AGENT: &str = "ZondScanner/1.0";

/// How long to wait for the second connection a speculative TLS handshake needs.
///
/// The first one already completed to this same port, so this either succeeds
/// immediately or the port has stopped accepting, so there is nothing here worth
/// a long wait.
const CONNECT_RETRY_TIMEOUT: Duration = Duration::from_millis(500);
/// Upper bound on how much of a single response we read/keep.
const MAX_RESPONSE_BYTES: usize = 4096;

/// The longest a single identity field lifted from a response may be.
///
/// A product name, a version and a supplementary technology are all short by
/// nature. What a bound stops is a hostile response putting a kilobyte into
/// each: measured without it, one reply yields a 1500-byte `product` and a
/// 1500-byte `extrainfo`, and both travel into the store, the journal, the
/// JSON, the CSV, the HTML and the nmap XML.
///
/// Refused rather than truncated, which is the argument
/// the SNMP reader already makes about `sysDescr`: half a value matched
/// against a corpus of whole ones is a match nobody can reproduce, and a
/// truncated version is a version that is simply wrong. A field this long is a
/// pattern that ran away or a peer being difficult, and neither is worth
/// reporting.
///
/// Every sibling reading here already bounded itself, at 255 bytes for a system
/// description, 40 for a document title and 32 for a last-resort banner label,
/// and each said why. These three had no argument for being unbounded, only no
/// author.
pub const MAX_IDENTITY_BYTES: usize = 256;

/// `value` as an identity field, or `None` where it is empty or past
/// [`MAX_IDENTITY_BYTES`].
///
/// The one place the bound is applied, so the three readings that lift text off
/// a response cannot disagree about it.
pub(crate) fn identity_field(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= MAX_IDENTITY_BYTES).then_some(value)
}

/// How long a response may go on arriving, measured from its first byte.
///
/// [`CONTINUATION_GRACE`] bounds the gap between two reads and nothing bounded
/// how many of them there could be, so a peer writing one byte every forty
/// milliseconds stayed permanently inside the grace and held a task for
/// ninety-seven seconds. Measured, against a loopback server doing exactly
/// that, and it costs an attacker one socket.
///
/// Set where a legitimate response cannot reach it. What this has to cover is a
/// server writing its headers and then its body, which is a segment boundary
/// and at worst a round trip; two seconds is three orders of magnitude past
/// that. What it cuts off is a peer being slow on purpose.
const MAX_CONTINUATION: Duration = Duration::from_secs(2);

/// The ceiling on everything one port's collection may spend on the network.
///
/// A backstop rather than a working budget. Every stage below already has its
/// own bound, and the longest honest walk down the ladder in [`gather`] runs a
/// failed handshake, a failed legacy handshake, a silent port in the clear and
/// then the last-resort probes, which at the thorough level comes to twenty-six
/// seconds, three and a half more for each probe authored for strangers. This
/// sits above that, so it never fires on a port behaving normally;
/// `the_collection_budget_covers_every_path_through_gather` is what holds the
/// two together.
///
/// It is here because the stages are added to over time and their sum is nobody's
/// property. `read_bytes` grew a bound it did not have; the next stage to be
/// added will be bounded by whoever writes it, and this is what makes the total
/// somebody's responsibility rather than an emergent number.
///
/// Set for a path that costs nothing. On a measured one each wait along the
/// walk allows for the path once, so the budget allows for it once per wait
/// the longest walk makes; see [`COLLECTION_WAITS`].
///
/// So it has no ceiling of its own in wall time, and grows to minutes behind
/// a slow path. The honest walk grows with it: behind a round trip of two
/// seconds the longest runs near two minutes, every wait on it bounded and
/// every one allowing for the path, and a ceiling beneath that would cut short
/// the identifications the allowance exists to finish. What the backstop is
/// for is a stage with no bound, which a slow path does not make likelier.
const COLLECTION_BUDGET: Duration = Duration::from_secs(30);

/// The most waits on the peer any walk down the ladder in [`gather`] makes in
/// a row, each a connection or a read that allows for the path, with room for
/// probes still to be authored. The longest walk makes fifteen at the thorough
/// level, two more for each probe authored for strangers;
/// `the_collection_budget_covers_every_path_through_gather` holds the two
/// together.
const COLLECTION_WAITS: u32 = 20;

/// Whether a reply from this port over this protocol is one the engine can read.
///
/// What decides whether a port is worth the exchange a service pass costs. A TCP
/// port always is: any of them may volunteer a banner, and reading one costs a
/// connection. A UDP port is worth a datagram only where something here can turn
/// the answer into text. Otherwise the reply proves the port open, which the
/// scan that found it already knew.
#[must_use]
pub fn reads_replies(port: u16, protocol: Protocol) -> bool {
    extract::reads(port, protocol)
}

/// The service name registered for a port number, if any.
///
/// A pure metadata lookup with **no regex compilation**, safe to call on the
/// scan hot path for every classified port. Returns the same names the fuller
/// fingerprinting path uses, so a quick label and a deep identification agree.
///
/// Registration is per port and not per transport, because a signature file
/// names the numbers a service claims and says nothing about how they are
/// reached. This took a `Protocol` for a while and ignored it, which is worse
/// than not taking one: [`reads_replies`] next door does branch on the
/// transport, so the two signatures read as though both meant it.
pub fn lookup_service_name(port: u16) -> Option<String> {
    SignatureDb::global()
        .service_name(port)
        .map(|s| s.to_string())
}

/// What a service said about the *machine* it runs on, as distinct from what it
/// said about itself.
///
/// Two findings filed in two places: the service belongs to the port, the
/// operating system and the hardware to the host. They travel together because
/// one banner routinely states both, and separating them at the source would
/// mean two passes over the same evidence.
#[derive(Debug, Clone, Default)]
pub struct AboutTheHost {
    /// What the responses implied about the operating system.
    pub os: Vec<crate::model::host::OsEvidence>,
    /// The hardware they described, where they described any. Over five hundred
    /// shipped rules name a box and no system at all.
    pub hardware: Option<crate::model::host::HardwareInfo>,
}

impl AboutTheHost {
    /// Whether nothing was concluded about the machine.
    pub fn is_empty(&self) -> bool {
        self.os.is_empty() && self.hardware.is_none()
    }

    /// Records everything this says about `host`, and reports whether the
    /// operating-system reading changed.
    ///
    /// One call because the two findings arrive together and land in two places,
    /// and a caller doing it in two steps is a caller that will one day do only
    /// the first. Hardware is merged rather than replaced: a record read from an
    /// address block and one a banner described are both about the same box, and
    /// [`HardwareInfo::merge`](crate::model::host::HardwareInfo::merge) knows
    /// which half of each to keep.
    pub fn apply(self, host: &mut crate::model::host::Host) -> bool {
        if let Some(described) = self.hardware {
            match host.hardware().cloned() {
                Some(mut known) => {
                    known.merge(described);
                    host.set_hardware(known);
                }
                None => host.set_hardware(described),
            }
        }
        os::identify(host, self.os)
    }

    /// Reads both from a resolved verdict's whole evidence set.
    ///
    /// Taken from every observation rather than the winning one: a host running
    /// two identifiable services says the same thing about itself twice, and a
    /// signature that lost the ranking for *service* may be the one that named
    /// the machine.
    fn from_evidence(evidence: &[Evidence]) -> Self {
        Self {
            os: evidence.iter().filter_map(|e| e.os.clone()).collect(),
            hardware: evidence
                .iter()
                .filter_map(|e| e.hardware.as_ref())
                .cloned()
                .reduce(|mut best, other| {
                    best.merge(other);
                    best
                }),
        }
    }
}

/// The text a UDP reply from `port` carries, where this engine can read one.
///
/// The other half of [`reads_replies`], which says whether a port qualifies and
/// leaves a caller who dialled one themselves with no way to read the answer.
/// `None` for a port with no decoder, which is most of them: a datagram nothing
/// can read is still proof the port is open, and that is what the scan already
/// took from it.
///
/// Returns owned text because decoding is not always a borrow: a value lifted
/// out of a binary encoding has no text in the datagram to point at, and more
/// than one where a reply answers more than one question: an SNMP agent is asked
/// for its description and its object identifier in a single datagram.
pub fn decode_udp_reply(port: u16, datagram: &[u8]) -> Vec<String> {
    extract::from_datagram(port, datagram)
}

/// What a completed handshake established, as the record a report carries.
///
/// A summary rather than the chain: who the certificate claims to be, who
/// vouched for it, when it stops being valid, and a fingerprint to compare two
/// sightings by. Nothing here is a trust decision: validity is recorded as
/// two instants and left for the reader to compare against whatever time they
/// care about, precisely so that expired, self-signed and wrong-host
/// certificates are reported rather than rejected.
///
/// Always produces a record. A chain this cannot read is a finding rather than a
/// reason to report nothing, and the version and cipher agreed are worth keeping
/// on their own.
///
/// For a caller who performed their own handshake: this crate's connector is not
/// public, and a [`TlsInfo`] built from what any TLS client hands back turns into
/// a report record here.
pub fn tls_security(tls: &TlsInfo) -> crate::model::port::Security {
    tls_summary::security(tls)
}

/// The confidence-0 label every scan path seeds before deeper fingerprinting:
/// the name the port number is registered under, and **nothing at all where it
/// is registered under none**.
///
/// Centralising it keeps the SYN, connect and service-detection paths agreeing
/// on the same starting point.
///
/// A port with no registered name yields `None` rather than a placeholder.
/// A placeholder is a service name as far as every consumer is concerned: it
/// reaches the exported JSON, the CSV a spreadsheet opens, the HTML somebody
/// reads and the nmap XML another tool ingests, and each of them then says the
/// port is running something called `???`. Absence is what the scan actually
/// established, and absence is representable.
///
/// The zero is what marks the rest as guesses; see
/// [`Service::is_inferred`](crate::model::port::Service::is_inferred).
pub fn baseline_service(port: u16) -> Option<Service> {
    lookup_service_name(port).map(|name| Service::new(name, 0))
}

/// A [`Port`] in the given `state` carrying only the [`baseline_service`] label.
///
/// This is the shape every discovery path records before (and if) a full
/// fingerprint refines it: the SYN and filtered/closed paths stop here, while
/// the connect and service-detection paths hand the result to
/// [`fingerprint_tcp_detailed`] to upgrade in place.
pub fn baseline_port(port: u16, protocol: Protocol, state: PortState) -> Port {
    let mut classified = Port::new(port, protocol, state);
    if let Some(service) = baseline_service(port) {
        classified.set_service(service);
    }
    classified
}

/// Actively fingerprints an open TCP `stream` and refines `port`'s service.
///
/// Network I/O, meaning the banner grab and any active probes, runs here on the
/// async reactor with bounded reads and per-stage timeouts. The CPU-bound
/// signature
/// matching is handed to `analyze`, which runs on the blocking pool so a large
/// match set can never stall the scheduler.
///
/// If nothing identifies, a trimmed printable banner is attached as a
/// last-resort label rather than leaving the port unannotated.
pub async fn fingerprint_tcp(stream: TcpStream, port: Port, detection: ServiceDetection) -> Port {
    fingerprint_tcp_detailed(stream, port, detection).await.port
}

/// [`fingerprint_tcp`], also returning what the service said about the *machine*.
///
/// Over half the shipped signature corpus carries operating-system metadata, and
/// a banner naming a distribution, such as `OpenSSH_9.6p1 Debian`, is the most
/// direct statement a host ever makes about itself. It is read here because this
/// is
/// where the text already is; no probe is added to collect it.
///
/// Separate from [`fingerprint_tcp`] rather than replacing it because the two
/// findings belong to different places: the service belongs to the port, and what
/// it implies about the operating system belongs to the host. A caller with no
/// host to file it against should not have to handle it.
///
/// The gathered responses come back too, for a caller that runs a later
/// detection over them rather than redrawing them; they are empty when nothing
/// was read. So does whether the identification was starved of a socket, which
/// is what separates a port that had nothing more to say from one that was
/// never asked; see [`Fingerprinted::starved`].
///
/// Every further connection it makes to the port, for a later question or an
/// active analyzer, goes where the routing table sends it. A scan forced to a
/// source reaches the same engine with its connections pinned there instead.
pub async fn fingerprint_tcp_detailed(
    stream: TcpStream,
    port: Port,
    detection: ServiceDetection,
) -> Fingerprinted {
    fingerprint_tcp_via(
        stream,
        port,
        detection,
        Egress::KERNEL,
        PathAllowance::NONE,
        None,
    )
    .await
}

/// What identifying one port came to: the port as it was named, what its
/// service said about the machine, the responses it drew, and whether the
/// process ran short of sockets while asking.
///
/// A struct with named fields rather than a tuple because the last of those is
/// a different kind of fact from the rest, one about this machine rather than
/// the port, and a caller has to be able to see it by name to act on it.
/// Non-exhaustive, so a further fact the identification learns reaches callers
/// as a field they may read rather than a change to a shape they destructure.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Fingerprinted {
    /// The port, its service refined where anything named it.
    pub port: Port,
    /// What the port's service said about the machine behind it.
    pub about_the_host: AboutTheHost,
    /// The responses gathered, for a later detection to read.
    pub responses: Vec<String>,
    /// Whether a connection or datagram the identification needed was given
    /// up because the process had no socket to give it, for as long as it
    /// waited for one.
    ///
    /// What was learned is kept, and is a floor: the question that socket
    /// would have carried went unasked for a reason that is this machine's
    /// rather than the port's, and raising the process's file limit is its
    /// remedy. Over TCP it is a later question, a redirect followed or an
    /// analyzer's own connection, since the first connection is the caller's.
    /// Over UDP it is a datagram, and as each is sent only after the one
    /// before drew nothing readable, a starved UDP identification learned
    /// nothing at all.
    pub starved: bool,
    /// Whether a wait for the port to say something ran its clock out with
    /// nothing heard: a greeting, a reply or a handshake that did not come.
    ///
    /// With nothing drawn, what separates a port that had nothing to say from
    /// one whose answer was still queued behind another's when the clock ran
    /// out. A port that closed on every question waited for nothing.
    pub(crate) ran_out_waiting: bool,
    /// Whether a reply came only after more than half the wait it was given.
    ///
    /// A service answering that late fits one answer in a wait and not two,
    /// so a question queued behind one of its answers is not answered in time.
    pub(crate) answered_late: bool,
}

/// [`fingerprint_tcp_detailed`], with every further connection to the port
/// leaving by `egress`, which is how `stream` was reached, every wait on the
/// port allowing for `path`, the port asked for by `name` where a target
/// named its address (see [`Authority`]), and with whether one of the
/// connections was refused a socket.
pub(crate) async fn fingerprint_tcp_via(
    stream: TcpStream,
    port: Port,
    detection: ServiceDetection,
    egress: Egress,
    path: PathAllowance,
    name: Option<Arc<str>>,
) -> Fingerprinted {
    // Every connection after `stream` dials through this scope, and every
    // wait on the port is sized in it, which is also where a connection given
    // up for want of a socket, and how the port's replies came, are told; see
    // `DIALLING`.
    let tally = Arc::new(Tally::default());
    let dialling = Dialling {
        egress,
        path,
        tally: Arc::clone(&tally),
    };
    let (port, about_the_host, responses) = DIALLING
        .scope(
            dialling,
            identify_tcp(stream, port, detection, egress, path, name),
        )
        .await;
    Fingerprinted {
        port,
        about_the_host,
        responses,
        starved: tally.starved.load(Ordering::Relaxed),
        ran_out_waiting: tally.ran_out_waiting.load(Ordering::Relaxed),
        answered_late: tally.answered_late.load(Ordering::Relaxed),
    }
}

/// The identification [`fingerprint_tcp_via`] runs inside its dialling scope.
async fn identify_tcp(
    stream: TcpStream,
    mut port: Port,
    detection: ServiceDetection,
    egress: Egress,
    path: PathAllowance,
    name: Option<Arc<str>>,
) -> (Port, AboutTheHost, Vec<String>) {
    // Capture the peer address before `gather` consumes the stream, so active
    // analyzers can open their own connection to the same target. Only at a
    // level that sends: an active analyzer's connection carries a request,
    // an SSH key exchange or a favicon fetch, and one handed no address to
    // dial is left with the passive reading the level promises.
    let addr = stream.peer_addr().ok().filter(|_| detection.sends());
    // Every stage inside `gather` is bounded and their sum is nobody's property;
    // see [`COLLECTION_BUDGET`]. A port that runs out of it is left exactly as
    // the scan recorded it, which is what a port that said nothing gets.
    let Ok((responses, tunnel)) = timeout(
        path.over_each(COLLECTION_BUDGET, COLLECTION_WAITS),
        gather(stream, port.number(), detection, egress, name.clone()),
    )
    .await
    else {
        return (port, AboutTheHost::default(), Vec::new());
    };
    if responses.is_empty() {
        return (port, AboutTheHost::default(), Vec::new());
    }

    // Recorded before the response set is handed off, and independently of what
    // the analyzers conclude. A handshake is a fact about the port; whether any
    // analyzer manages to name the service behind it is a separate question, and
    // a port whose service stays unidentified still has a certificate worth
    // reporting.
    if let Some(tls) = responses.tls.as_ref() {
        port.set_security(tls_summary::security(tls));
    }

    // Analysis runs off the reactor. Keep a last-resort banner label, and the
    // gathered responses a later detection may read, before the response set is
    // handed to the blocking pool.
    let fallback = first_printable(&responses.banners);
    let banners = responses.banners.clone();
    let mut about_the_host = AboutTheHost::default();
    // The analyzers dial through the port's egress. They are handed a context
    // whose shape is public and cannot carry it, so it reaches them as the
    // scope their collection runs in; see `DIALLING`.
    let verdict = analyze(
        port.number(),
        Protocol::Tcp,
        addr,
        responses,
        tunnel,
        detection,
        name,
    )
    .await;
    match verdict {
        Some(verdict) if !verdict.is_empty() => {
            // Taken from the whole retained evidence set rather than from the
            // winning service alone: a host running two identifiable services
            // says the same thing about itself twice, and a signature that lost
            // the ranking for *service* may still be the one that named the
            // operating system.
            about_the_host = AboutTheHost::from_evidence(&verdict.evidence);
            if let Some(service) = verdict.to_service() {
                port.set_service(service);
            }
        }
        _ => {
            if let Some(banner) = fallback {
                port.set_service(Service::new(format!("banner: {banner}"), 0));
            }
        }
    }

    (port, about_the_host, banners)
}

/// Fingerprints an open **UDP** port, returning the upgraded [`Port`] and
/// whatever the reply said about the machine behind it.
///
/// The sibling of [`fingerprint_tcp_detailed`], and the same shape:
/// draw a response, turn it into the text the corpus is written against, and
/// hand it to the same analyzers. Only the drawing differs, because UDP has no
/// connection to open and no banner to wait for.
///
/// # Why this is a second datagram rather than the scan's own
///
/// The UDP port scan already sends this exact payload and already sees this
/// exact reply, which is how the port was known to be open at all, and then
/// discards the body, since what it needed was the fact of an answer. Wiring
/// that reply through would save a datagram and cost the thing that makes the
/// scan fast: the scanner would have to hold every response body for every port
/// it probed, through a paced run, against the chance that a later phase wants
/// one. This is the same trade the TCP side already makes, where the service
/// pass reconnects to a port the scan has already knocked on.
///
/// # What it will not do
///
/// Speak to a port it cannot read. A datagram is only worth sending where
/// something here could turn the answer into text, for which see
/// [`reads_replies`], since unlike a TCP banner grab an unread UDP reply teaches
/// nothing the scan does not already know.
///
/// Claim a port answered when it did not. `None` means silence, and silence
/// over UDP is the ordinary case: no connection is refused and no banner is
/// withheld, so nothing distinguishes a filtered port from one with nothing
/// behind it. A caller that dialled a port on its own account uses this to tell
/// whether it found anything at all.
///
/// Call it silence when it was not. A datagram the process had no socket for
/// was never sent, and the port was never asked; that comes back as the port
/// as it was given, with [`starved`](Fingerprinted::starved) set, since it is
/// this machine's shortfall and a caller reading it as the port's would
/// record a question as answered that was never put.
///
/// The datagram leaves where the routing table sends it; a scan forced to a
/// source sends it from there instead.
pub async fn fingerprint_udp_detailed(
    addr: std::net::SocketAddr,
    port: Port,
) -> Option<Fingerprinted> {
    fingerprint_udp_via(addr, port, Egress::KERNEL).await
}

/// [`fingerprint_udp_detailed`], with the datagram leaving by `egress`.
pub(crate) async fn fingerprint_udp_via(
    addr: std::net::SocketAddr,
    port: Port,
    egress: Egress,
) -> Option<Fingerprinted> {
    fingerprint_udp_on(addr, port, egress, PathAllowance::NONE).await
}

/// [`fingerprint_udp_via`], with each wait for a reply allowing for `path`.
pub(crate) async fn fingerprint_udp_on(
    addr: std::net::SocketAddr,
    port: Port,
    egress: Egress,
    path: PathAllowance,
) -> Option<Fingerprinted> {
    fingerprint_udp_within(addr, port, egress, descriptors::PATIENCE, path).await
}

/// [`fingerprint_udp_on`], waiting out a full descriptor table for
/// `patience` before a datagram is given up as starved.
async fn fingerprint_udp_within(
    addr: std::net::SocketAddr,
    mut port: Port,
    egress: Egress,
    patience: Duration,
    path: PathAllowance,
) -> Option<Fingerprinted> {
    let texts = match probe_udp(addr, egress, patience, path).await {
        Datagram::Reply(texts) => texts,
        Datagram::Silent => return None,
        Datagram::Starved => {
            return Some(Fingerprinted {
                port,
                about_the_host: AboutTheHost::default(),
                responses: Vec::new(),
                starved: true,
                ran_out_waiting: false,
                answered_late: false,
            });
        }
    };
    let responses = ResponseSet::from_banners(texts);
    let banners = responses.banners.clone();

    // No tunnel: nothing here carries UDP over TLS, and no peer address is
    // handed to the analyzers either, since an active analyzer dials TCP and
    // this port's address is not one it could speak to. With no address, the
    // detection level cannot change what runs, so the default stands in for a
    // parameter this function would otherwise have to take and never use.
    let verdict = analyze(
        addr.port(),
        Protocol::Udp,
        None,
        responses,
        None,
        ServiceDetection::default(),
        None,
    )
    .await
    .filter(|verdict| !verdict.is_empty())?;

    let about_the_host = AboutTheHost::from_evidence(&verdict.evidence);
    if let Some(service) = verdict.to_service() {
        port.set_service(service);
    }

    Some(Fingerprinted {
        port,
        about_the_host,
        responses: banners,
        starved: false,
        ran_out_waiting: false,
        answered_late: false,
    })
}

/// What asking a UDP port came to.
enum Datagram<T> {
    /// It answered, with this.
    Reply(T),
    /// It was asked and said nothing, or nothing readable.
    Silent,
    /// The process had no socket to ask it with, for as long as it waited
    /// for one, so it was never asked.
    Starved,
}

/// Sends this port's registered probes and reads back whatever text a reply
/// carries, or `None` if none carried any.
///
/// Bound to an ephemeral port of the same family as the target, and
/// connected, so the kernel drops anything from another address before it
/// reaches here: a scanner reading unsolicited datagrams off an unconnected
/// socket would attribute one host's answer to another's port.
///
/// # Why this asks more than once where the port scan asks once
///
/// [`payload::for_port`](crate::scanner::payload::for_port) takes the first
/// probe a port registers and stops, which is right for what it is doing: any
/// reply at all settles the port's state, so a second datagram would buy
/// nothing.
///
/// Identification is a different question, and one probe does not always ask
/// it. NTP is the case this exists for. A client request draws a packet of
/// timestamps, which proves the port open and says nothing else; the daemon's
/// own account of itself comes back only to a mode 6 control message, and the
/// corpus registers both. Taking the first here sent the client request,
/// discarded the timestamps, and left seventy-five rules unreached that had
/// just been given a decoder.
///
/// So each registered probe is tried in turn and the first that yields text
/// wins. A port registering one probe, which is nearly all of them, costs
/// exactly what it did before.
///
/// A probe the process had no socket for ends the walk as starved rather than
/// passing on to the next: the table that refused one socket is the table the
/// next would ask, and the port has not been asked anything yet.
async fn probe_udp(
    addr: std::net::SocketAddr,
    egress: Egress,
    patience: Duration,
    path: PathAllowance,
) -> Datagram<Vec<String>> {
    for payload in SignatureDb::global().udp_probe_payloads(addr.port()) {
        match exchange_datagram(addr, payload, egress, patience, path).await {
            Datagram::Reply(reply) => {
                let texts = extract::from_datagram(addr.port(), &reply);
                if !texts.is_empty() {
                    return Datagram::Reply(texts);
                }
            }
            Datagram::Silent => {}
            Datagram::Starved => return Datagram::Starved,
        }
    }
    Datagram::Silent
}

/// Sends `payload` to `addr` and reads back whatever text the reply carries.
///
/// The same exchange `probe_udp` performs, with the question supplied rather
/// than taken from the corpus. A corpus probe is one payload per port, which is
/// all a port number can decide; a question about a *particular host* cannot come
/// from there. An mDNS device-info record is the case this exists for: it is
/// published under the host's own name, so the query naming it is different for
/// every target.
///
/// The reply is decoded by the same port-keyed decoder either way, so a caller's
/// question and this engine's reading of the answer cannot drift apart.
///
/// Empty when nothing answered or nothing could be read from what did.
pub async fn probe_udp_with(addr: std::net::SocketAddr, payload: &[u8]) -> Vec<String> {
    probe_udp_with_via(addr, payload, Egress::KERNEL).await
}

/// [`probe_udp_with`], with the datagram leaving by `egress`.
pub(crate) async fn probe_udp_with_via(
    addr: std::net::SocketAddr,
    payload: &[u8],
    egress: Egress,
) -> Vec<String> {
    match probe_udp_raw_via(addr, payload, egress).await {
        Some(reply) => extract::from_datagram(addr.port(), &reply),
        None => Vec::new(),
    }
}

/// The same exchange, handing back the datagram rather than what this engine
/// reads out of it.
///
/// For a caller whose question is answered in a form the port's decoder is not
/// for. An mDNS responder is asked two different things on one port: what it
/// calls itself, which is a name in a PTR record, and what hardware it is, which
/// is the text this engine decodes there. Only the second is a banner.
///
/// [`None`] when nothing answered.
pub async fn probe_udp_raw(addr: std::net::SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    probe_udp_raw_via(addr, payload, Egress::KERNEL).await
}

/// [`probe_udp_raw`], with the datagram leaving by `egress`.
pub(crate) async fn probe_udp_raw_via(
    addr: std::net::SocketAddr,
    payload: &[u8],
    egress: Egress,
) -> Option<Vec<u8>> {
    match exchange_datagram(
        addr,
        payload,
        egress,
        descriptors::PATIENCE,
        PathAllowance::NONE,
    )
    .await
    {
        Datagram::Reply(reply) => Some(reply),
        Datagram::Silent | Datagram::Starved => None,
    }
}

/// Sends `payload` to `addr` from a socket of its own and reads the one
/// datagram that comes back, telling a port that said nothing from a process
/// that had no socket to ask it with, after waiting `patience` for one. The
/// wait for the reply allows for `path`.
async fn exchange_datagram(
    addr: std::net::SocketAddr,
    payload: &[u8],
    egress: Egress,
    patience: Duration,
    path: PathAllowance,
) -> Datagram<Vec<u8>> {
    let socket = match egress.udp(addr.ip(), patience).await {
        Ok(socket) => socket,
        Err(e) if descriptors::exhausted(&e) => return Datagram::Starved,
        Err(_) => return Datagram::Silent,
    };
    if socket.connect(addr).await.is_err() || socket.send(payload).await.is_err() {
        return Datagram::Silent;
    }

    let mut buffer = vec![0u8; MAX_RESPONSE_BYTES];
    match timeout(path.over(PROBE_READ_TIMEOUT), socket.recv(&mut buffer)).await {
        Ok(Ok(read)) => {
            buffer.truncate(read);
            Datagram::Reply(buffer)
        }
        _ => Datagram::Silent,
    }
}

/// Collects everything the transport can learn from the port over the network,
/// and how it was carried.
///
/// A ladder of questions rather than a choice between them. The port number sets
/// the *order* the rungs are tried in and never the set: a port numbered for TLS
/// is offered a handshake first and anything else is spoken to in the clear
/// first, and a rung that draws nothing falls through to the next.
///
/// Order is what a port number is good for and membership is what it is not. A
/// number is a convention, and a service can be moved off or onto any of them,
/// so a rung that ended the collection would make the convention the answer.
///
/// Whenever a handshake succeeds the collection re-runs *inside* the tunnel, so
/// the protocol carried by TLS is fingerprinted too, and the returned [`Tunnel`]
/// records that it was.
///
/// Every connection after the first leaves by `egress`, as the first did.
async fn gather(
    mut stream: TcpStream,
    port: u16,
    detection: ServiceDetection,
    egress: Egress,
    name: Option<Arc<str>>,
) -> (ResponseSet, Option<Tunnel>) {
    // Identify nothing. Reached only from the unprivileged path, where the
    // connection is how the port's state was established and so exists whether
    // or not anything is to be learned from it; the privileged path stops a
    // level earlier, in `service::detect`, and never opens one at all.
    if !detection.connects() {
        return (ResponseSet::default(), None);
    }

    // Listen only. Everything below this line puts bytes on the wire, the
    // ClientHello of a handshake as much as the probes, so the level that
    // promises to send nothing has to stop here rather than further in.
    if !detection.sends() {
        let banner = read_response(&mut stream, BANNER_READ_TIMEOUT).await;
        return (
            ResponseSet::from_banners(banner.into_iter().collect()),
            None,
        );
    }

    // Without the peer's address there is nowhere to reconnect to and no server
    // name for a handshake, so the socket in hand is asked in the clear and that
    // is the whole of it.
    let Ok(socket) = stream.peer_addr() else {
        return (plaintext(stream, port, None, egress).await, None);
    };
    let peer = Authority::new(socket).named(name);

    // The first rung inherits the connection the caller opened. Every rung after
    // it dials its own, because a handshake consumes the stream it was given and
    // a probe leaves its request on the one it wrote to.
    let mut opened = Some(stream);
    for rung in Rung::ladder(port) {
        let stream = match opened.take() {
            Some(stream) => stream,
            None => match redial(socket, egress).await {
                Some(fresh) => fresh,
                None => return (ResponseSet::default(), None),
            },
        };

        let (responses, tunnel) = rung.ask(stream, port, &peer, detection, egress).await;
        if responses.is_empty() {
            continue;
        }
        if matches!(rung, Rung::Plaintext)
            && !tls::is_tls_port(port)
            && refused_in_the_clear(&responses)
        {
            return asked_through_tls(responses, port, &peer, egress).await;
        }
        return (responses, tunnel);
    }

    (ResponseSet::default(), None)
}

/// Whether what a port answered in the clear is an HTTP server refusing the
/// request, which is how a web server listening for TLS answers one that
/// arrived without it.
///
/// nginx, Apache, Go and Caddy all answer a plaintext request on a TLS port
/// with a plaintext `400` rather than a TLS alert, and each says why in its
/// own words. The status is what is read, not the words: a well-formed `GET`
/// is refused as a bad request by little else, and asking such a port for a
/// handshake as well costs one connection.
fn refused_in_the_clear(responses: &ResponseSet) -> bool {
    responses.banners.first().is_some_and(|reply| {
        reply.starts_with("HTTP/") && reply.split_whitespace().nth(1) == Some("400")
    })
}

/// What a port that refused a request in the clear says through TLS, with
/// `clear`, what it said in the clear, where it says nothing.
///
/// Reached on a port whose number does not say TLS, since one that does has
/// been asked for a handshake before it was asked anything in the clear. A
/// handshake that completes is the answer, the protocol inside it
/// identified as on any TLS port. One refused on the terms a modern client
/// offers is put the legacy question, and a port answering that in TLS is
/// one that speaks HTTP through TLS and would not complete a handshake with
/// this scanner: a server keeping its certificates by name refuses a client
/// naming no site it holds. Its refusal in the clear is then the port's own
/// account of what it serves, filed as served through TLS, since that is what
/// the refusal said and the handshake bore out. A port answering neither in
/// TLS keeps its answer in the clear.
async fn asked_through_tls(
    clear: ResponseSet,
    port: u16,
    peer: &Authority,
    egress: Egress,
) -> (ResponseSet, Option<Tunnel>) {
    let Some(stream) = redial(peer.socket(), egress).await else {
        return (clear, None);
    };
    let handshake = tls::speculative_handshake(stream, peer.server_name()).await;
    let (through, tunnel) = tunneled(handshake, port, peer).await;
    if !through.is_empty() {
        return (through, tunnel);
    }

    let Some(stream) = redial(peer.socket(), egress).await else {
        return (clear, None);
    };
    match legacy_tls(stream).await.tls {
        Some(tls) => (clear.with_tls(tls), Some(Tunnel::Tls)),
        None => (clear, None),
    }
}

/// A second connection to a port already reached once.
///
/// The first one succeeded, so this either succeeds immediately or the port has
/// stopped accepting; see [`CONNECT_RETRY_TIMEOUT`], which allows for the path.
/// It leaves by `egress`, the way the first one did.
///
/// No share of the process's descriptor budget of its own: the pass that
/// fingerprints the port holds one for the whole identification, whose
/// connections follow one another. A table full for other reasons is waited
/// out before that timeout starts, not within it; see [`dial_again`].
async fn redial(socket: SocketAddr, egress: Egress) -> Option<TcpStream> {
    dial_again(socket, egress, Some(on_path(CONNECT_RETRY_TIMEOUT)))
        .await
        .ok()
}

/// A further connection to the port being identified, leaving by `egress`
/// and given `limit` to connect where one is set.
///
/// Every connection an identification makes after its first comes through
/// here, so that one given up for want of a socket is never read as a port
/// that said nothing. A socket the process refuses is asked for again for up
/// to [`PATIENCE`](descriptors::PATIENCE), each attempt on a clock of its own.
/// Should the table stay full past that, or the caller's own clock run out
/// while this still waits on it, the identification is marked starved on the
/// way out, which is what its caller files: whatever the connection was to
/// ask went unasked, and raising the limit is the remedy.
async fn dial_again(
    addr: SocketAddr,
    egress: Egress,
    limit: Option<Duration>,
) -> std::io::Result<TcpStream> {
    let refused = Refused::default();
    let refused = &refused;
    descriptors::patiently(descriptors::PATIENCE, || async move {
        let attempt = match limit {
            Some(limit) => timeout(limit, egress.connect_shaped(addr, Shaping::default()))
                .await
                .unwrap_or_else(|_elapsed| Err(std::io::ErrorKind::TimedOut.into())),
            None => egress.connect_shaped(addr, Shaping::default()).await,
        };
        refused.saw(&attempt);
        attempt
    })
    .await
}

/// Whether the connection [`dial_again`] is making was last refused a socket,
/// which it reports to the identification's scope if it ends that way, by
/// giving up or by being dropped while it waits.
#[derive(Default)]
struct Refused(AtomicBool);

impl Refused {
    /// Notes how one attempt went.
    fn saw(&self, attempt: &std::io::Result<TcpStream>) {
        let refused = attempt.as_ref().is_err_and(descriptors::exhausted);
        self.0.store(refused, Ordering::Relaxed);
    }
}

impl Drop for Refused {
    fn drop(&mut self) {
        if self.0.load(Ordering::Relaxed) {
            tell(|tally| tally.starved.store(true, Ordering::Relaxed));
        }
    }
}

/// One question a port can be asked, and the unit [`gather`] falls through.
///
/// Each rung is asked on a connection of its own and reports what it drew.
/// Nothing at all is the signal to try the next, so a rung that cannot answer
/// costs the collection a fall-through rather than the identification.
#[derive(Clone, Copy)]
enum Rung {
    /// Handshake and collect through the tunnel, patiently, on a port where TLS
    /// is what the number says to expect.
    Tls,
    /// The same on a port where it is a guess, under the tighter budget a guess
    /// is worth. See [`tls::SPECULATIVE_TLS_TIMEOUT`].
    SpeculativeTls,
    /// A ClientHello offering the versions rustls will not, for a server too old
    /// for the one above.
    LegacyTls,
    /// Listen and probe in the clear: the port's own probes where something
    /// claims it, and the generic question where nothing does.
    Plaintext,
    /// The questions other services registered, put to a port that has answered
    /// none of its own.
    ///
    /// For a service that speaks only when spoken to and is not on the port its
    /// probe is registered against, this is the only rung that can reach it.
    LastResort,
}

impl Rung {
    /// The rungs for `port`, in the order they are worth asking in.
    ///
    /// The whole of the port number's influence on collection. A number
    /// registered for implicit TLS earns the handshake first, which spares an
    /// ordinary HTTPS port a banner timeout it could only lose. It does not earn
    /// the handshake alone.
    ///
    /// `LegacyTls` sits above `Plaintext` because a 1.0-only server answers a
    /// plaintext probe with an alert record: bytes, which the clear-text rung
    /// would report as a banner, ending the ladder one rung above the question
    /// that names the version.
    fn ladder(port: u16) -> &'static [Rung] {
        if tls::is_tls_port(port) {
            &[
                Rung::Tls,
                Rung::LegacyTls,
                Rung::Plaintext,
                Rung::LastResort,
            ]
        } else {
            &[Rung::Plaintext, Rung::SpeculativeTls, Rung::LastResort]
        }
    }

    /// Asks this rung's question over `stream`, which it consumes.
    ///
    /// [`LastResort`](Self::LastResort) is the one rung that may dial again on
    /// its own account, because it asks several unrelated protocols and each
    /// leaves the socket unusable for the next.
    async fn ask(
        self,
        stream: TcpStream,
        port: u16,
        peer: &Authority,
        detection: ServiceDetection,
        egress: Egress,
    ) -> (ResponseSet, Option<Tunnel>) {
        match self {
            Rung::Tls => {
                let handshake = tls::handshake(stream, peer.server_name()).await;
                tunneled(handshake, port, peer).await
            }
            Rung::SpeculativeTls => {
                let handshake = tls::speculative_handshake(stream, peer.server_name()).await;
                tunneled(handshake, port, peer).await
            }
            Rung::LegacyTls => (legacy_tls(stream).await, None),
            Rung::Plaintext => (plaintext(stream, port, Some(peer), egress).await, None),
            Rung::LastResort => (
                last_resort(stream, peer, port, detection, egress).await,
                None,
            ),
        }
    }
}

/// Puts other services' questions to a port that has answered none of its own.
///
/// One connection per probe and one probe per connection, because the protocols
/// are unrelated and most of them end the conversation on a question they do not
/// recognise: PostgreSQL reads `PING` as a four-byte length and gives up, and
/// Redis closes on the second line of an HTTP request rather than answering it.
/// Reusing a socket across two of them would ask the second question of a peer
/// that had already hung up.
///
/// Every probe is asked and the replies accumulate, unlike the rungs above,
/// where one exchange goes to every analyzer and anything that came back is
/// worth handing on. Here each probe is a *different protocol's* question, and a
/// refusal of one says only that the port does not speak that protocol. A
/// service that answers an unknown command with an error rather than a closed
/// socket would otherwise end the rung on the probe before its own.
///
/// Which probes are asked is [`ServiceDetection::probe_intensity`].
async fn last_resort(
    first: TcpStream,
    peer: &Authority,
    port: u16,
    detection: ServiceDetection,
    egress: Egress,
) -> ResponseSet {
    let probes =
        SignatureDb::global().universal_tcp_probe_payloads(port, detection.probe_intensity());

    let mut replies = Vec::new();
    let mut opened = Some(first);
    for payload in probes {
        let Some(mut stream) = (match opened.take() {
            Some(stream) => Some(stream),
            None => redial(peer.socket(), egress).await,
        }) else {
            break;
        };

        if stream.write_all(&peer.addressed(payload)).await.is_err() {
            continue;
        }
        if let Some(reply) = read_document(&mut stream, PROBE_READ_TIMEOUT).await {
            replies.push(reply);
        }
    }

    ResponseSet::from_banners(replies)
}

/// Everything a port will say in the clear.
///
/// Two shapes, chosen by whether anything in the signature database claims the
/// number. A claimed port is listened to and then asked what that service asks,
/// in that order, since a service that greets on connect should be heard before
/// it is interrupted. An unclaimed port is asked generically; see
/// [`ask_generically`].
///
/// A reply that is a TLS record is reported as nothing rather than as a banner,
/// on either shape. The port spoke, but not in this rung's language, and the
/// ladder has a rung that can read it.
async fn plaintext(
    mut stream: TcpStream,
    port: u16,
    peer: Option<&Authority>,
    egress: Egress,
) -> ResponseSet {
    let db = SignatureDb::global();
    let probes = db.tcp_probe_payloads(port);
    if !probes.is_empty() {
        let listen = !db.asked_first(port);
        let banners = collect_responses(&mut stream, port, probes, peer, listen).await;
        // Read back off the decoded text, which is sound only because every
        // byte `looks_like_tls` constrains is under 0x80 and survives
        // `from_utf8_lossy` unchanged.
        if banners
            .first()
            .is_some_and(|first| looks_like_tls(first.as_bytes()))
        {
            return ResponseSet::default();
        }
        return ResponseSet::from_banners(banners);
    }

    match ask_generically(stream, peer, egress).await {
        GenericReply::Spoke(banners) => ResponseSet::from_banners(banners),
        GenericReply::Tls | GenericReply::Silent => ResponseSet::default(),
    }
}

/// What a generic probe drew out of a port nothing in the database claims.
enum GenericReply {
    /// It answered in something we can read. Whatever it said is here.
    Spoke(Vec<String>),
    /// It answered in TLS, most likely an alert, since what went out was not a
    /// ClientHello. The port speaks, just not to that question.
    Tls,
    /// Nothing came back at all.
    Silent,
}

/// Asks an unclaimed port the one question worth asking of any open port, and
/// reads whatever comes back.
///
/// The request goes out before anything is read, which inverts the order the
/// claimed-port path uses, and the inversion is safe for a reason worth writing
/// down: a service that greets on connect has already sent its greeting by the
/// time anything is written, and TCP delivers it whether or not it was asked for
/// first. So writing first cannot lose a banner, and it saves the timeout that
/// waiting for a banner nobody is going to send would cost.
///
/// That saving is the whole point. Waiting half a second for a greeting, sending
/// nothing, concluding the port is silent, and then spending up to another
/// second and a half guessing that the silence is TLS costs two seconds per
/// unidentified port. Measured against one ordinary home server, that was seven
/// of its eleven open ports, to learn nothing about any of them. An HTTP request
/// answers in a round trip and names most of them.
///
/// The stream is closed once its reply is read, before a redirect is followed
/// over a connection of its own, so the identification holds one socket at a
/// time, which is the one share of the descriptor budget its pass took.
async fn ask_generically(
    mut stream: TcpStream,
    peer: Option<&Authority>,
    egress: Egress,
) -> GenericReply {
    for payload in SignatureDb::global().generic_tcp_probe_payloads() {
        let payload = match peer {
            Some(peer) => peer.addressed(payload),
            None => Cow::Borrowed(&payload[..]),
        };
        if stream.write_all(&payload).await.is_err() {
            break;
        }
    }

    let read = read_bytes(&mut stream, PROBE_READ_TIMEOUT, CONTINUATION_GRACE).await;
    drop(stream);
    let Some(bytes) = read else {
        return GenericReply::Silent;
    };
    if looks_like_tls(&bytes) {
        return GenericReply::Tls;
    }

    let first = String::from_utf8_lossy(&bytes).into_owned();

    // A redirect is not an answer but a forwarding address, and for a great
    // many self-hosted applications it is the only thing the root serves. See
    // `redirect_path`.
    let followed = match (peer, redirect_path(&first, peer)) {
        (Some(peer), Some(path)) => follow_redirect(peer, &path, egress).await,
        _ => None,
    };

    GenericReply::Spoke(std::iter::once(first).chain(followed).collect())
}

/// Where a response says to look instead, when that is somewhere on the same
/// host and reachable by the same means.
///
/// The root of a self-hosted application is very often a redirect and nothing
/// else. Jellyfin's is a 302 to `/web/index.html` and Sonarr's is one to its
/// login page, so the page that names either is one hop away and a scanner that
/// stops at the first response sees only the framework underneath, which for
/// both of those and a dozen others is `Kestrel`.
///
/// Refused unless the destination is the port already being identified. A
/// redirect naming somewhere else is an instruction to go and talk to a third
/// party, which is not something a scan of *this* address should do on its own
/// account: it would put traffic on somebody uninvolved and attribute what came
/// back to a host that never served it. Which URLs lead back is
/// [`Authority::path_of`]'s to say, so the check and the `Host` the redirect is
/// then asked with name the port the same way.
fn redirect_path(response: &str, peer: Option<&Authority>) -> Option<String> {
    let (status, headers) = response.split_once("\r\n").or(response.split_once('\n'))?;
    // `HTTP/1.1 302 Found`: the code is the second field.
    let code: u16 = status.split_whitespace().nth(1)?.parse().ok()?;
    if !(300..400).contains(&code) {
        return None;
    }

    let location = headers
        .lines()
        .take_while(|line| !line.trim_end_matches('\r').is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("location")
                .then(|| value.trim())
        })?;

    // A control character is refused rather than carried. `lines()` has already
    // made a CRLF impossible, but a lone carriage return survives in the middle
    // of a value and some servers still treat one as a line terminator, so this
    // would be a remote value spliced into a request line. The blast radius is
    // the peer's own socket, which is why this is hygiene rather than a hole,
    // though the class is worth removing.
    if location.is_empty() || location.chars().any(char::is_control) {
        return None;
    }

    match location {
        // An absolute URL, which is what a great many servers send: Grafana,
        // Portainer and Prometheus all answer `GET /` with a `Location` naming
        // themselves in full. Declining every one of them left three of five
        // self-hosted applications unidentified on a test segment, because the
        // page that names them is the one behind the redirect.
        //
        // So the host is compared rather than the shape. `peer` is the port
        // being identified, and only a URL naming it is followed; anything else
        // is somebody else's, and a scan of one address has no business putting
        // traffic on an uninvolved host.
        url if url.contains("://") || url.starts_with("//") => peer?.path_of(url),
        // Same host by construction: a path is relative to where it was served.
        path if path.starts_with('/') => Some(path.to_string()),
        // A relative reference, which RFC 7231 §7.1.2 permits and RFC 2616 did
        // not. Jellyfin answers `GET /` with `Location: web/`, and reading that
        // as "somewhere else" left the page it points at unread. Every caller
        // here issues its request at the root, so a reference resolves against
        // `/`; a caller requesting a deeper path would have to resolve it
        // against that instead.
        relative => Some(format!("/{relative}")),
    }
}

/// Fetches `path` from `peer` over a fresh connection and returns whatever
/// came back.
///
/// A new connection rather than the one in hand: the response carrying the
/// redirect may well have closed it, and a follow-up written into a socket the
/// peer has already gone away from is a write that succeeds and a read that
/// never returns. One round trip, and only on a response that asked for it,
/// leaving by `egress` as the connection that drew the redirect did.
async fn follow_redirect(peer: &Authority, path: &str, egress: Egress) -> Option<String> {
    let mut stream = dial_again(peer.socket(), egress, Some(on_path(CONNECT_RETRY_TIMEOUT)))
        .await
        .ok()?;

    // `Host` names the port actually being identified, which is what a virtual
    // host would route on and is in any case more truthful than a placeholder.
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\n\
         Accept: */*\r\nConnection: close\r\n\r\n",
        peer.header()
    );
    stream.write_all(request.as_bytes()).await.ok()?;

    read_document(&mut stream, PROBE_READ_TIMEOUT).await
}

/// Whether `bytes` open a TLS record.
///
/// A content type in the range TLS defines, then a major version of 3 and a
/// minor version no higher than TLS 1.3 uses on the wire. What this catches in
/// practice is the alert a TLS server sends when it is handed a plaintext
/// request: our `G` of `GET` is not a record type it knows, so it says so and
/// closes. Read as text that alert is a handful of unprintable bytes, and taking
/// it for a banner would leave a TLS service reported as an unidentifiable one.
fn looks_like_tls(bytes: &[u8]) -> bool {
    matches!(bytes, [0x14..=0x17, 0x03, 0x00..=0x04, ..])
}

/// What a port numbered for TLS turns out to speak, where a modern handshake
/// would not complete.
///
/// rustls implements TLS 1.2 and 1.3 and implements neither 1.0 nor 1.1, so a
/// legacy-only server fails the rung above this one and would otherwise go down
/// as a port that answered nothing.
///
/// The result carries no certificate and no tunnel. A legacy handshake sends its
/// certificate in the clear and reading it would be possible, and it is
/// not done here: the finding is the version, and a second binary
/// parser over remote bytes wants an argument of its own before it exists.
async fn legacy_tls(stream: TcpStream) -> ResponseSet {
    match tls::legacy_version(stream).await {
        Some(version) => {
            ResponseSet::default().with_tls(TlsInfo::new(Vec::new()).with_version(version))
        }
        None => ResponseSet::default(),
    }
}

/// Given the outcome of a handshake, re-probes through the tunnel (if it
/// completed) and packages the decrypted responses with the captured
/// certificate. A failed handshake yields nothing.
async fn tunneled(
    handshake: Option<(tls::TlsTunnel, TlsInfo)>,
    port: u16,
    peer: &Authority,
) -> (ResponseSet, Option<Tunnel>) {
    let Some((mut tunnel, info)) = handshake else {
        return (ResponseSet::default(), None);
    };
    // Inside the tunnel the port's own probes apply if it has any, and the
    // generic question if it does not, since the protocol under TLS is as
    // unidentified as it would have been in the clear. A caller who asked to
    // send nothing never reaches here: `gather` returns before the handshake.
    //
    // The generic question goes out without listening first, as it does in
    // the clear; see `ask_generically` for why that loses no greeting.
    let db = SignatureDb::global();
    let (probes, listen) = match db.tcp_probe_payloads(port) {
        [] => (db.generic_tcp_probe_payloads(), false),
        own => (own, !db.asked_first(port)),
    };
    let peer = peer.through_tls();
    let banners = collect_responses(&mut tunnel, port, probes, Some(&peer), listen).await;
    let responses = ResponseSet {
        banners,
        tls: Some(info),
    };
    (responses, Some(Tunnel::Tls))
}

/// Grabs a first-speak banner where `listen` says one may come, then sends
/// `probes` over `stream`, returning every non-empty response. Generic over the
/// transport, so it runs identically on a raw socket or inside a TLS tunnel.
///
/// Not listening costs no greeting a port sends: one sent on connect is
/// already on its way when the first probe is written, and is read as the
/// first reply. What listening buys is not interrupting a service before it
/// has spoken, and on a port that never speaks first it is a wait that always
/// runs out; see [`SignatureDb::asked_first`].
///
/// The probes are passed in rather than looked up, because the caller is what
/// knows which set applies: a port's own where it has them, and the generic set
/// where it does not. Each is addressed to `peer` where there is one; see
/// [`Authority::addressed`].
async fn collect_responses<S>(
    stream: &mut S,
    port: u16,
    probes: &[Vec<u8>],
    peer: Option<&Authority>,
    listen: bool,
) -> Vec<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut banners = Vec::new();

    // Many services announce themselves on connect.
    if listen && let Some(banner) = read_response(stream, BANNER_READ_TIMEOUT).await {
        banners.push(banner);
    }

    for payload in probes {
        let payload = match peer {
            Some(peer) => peer.addressed(payload),
            None => Cow::Borrowed(&payload[..]),
        };
        if stream.write_all(&payload).await.is_err() {
            break;
        }
        let Some(bytes) = read_bytes(stream, PROBE_READ_TIMEOUT, CONTINUATION_GRACE).await else {
            continue;
        };
        // A reply this engine can read as structure is offered as the fields it
        // holds, before the lossy text of the whole. See `extract::from_stream`.
        banners.extend(extract::from_stream(port, &bytes));
        banners.push(String::from_utf8_lossy(&bytes).into_owned());
    }

    banners
}

/// How the port being fingerprinted is dialled after its first connection,
/// and how long it is waited on.
struct Dialling {
    /// The egress the port was reached by, which every further connection
    /// leaves by.
    egress: Egress,
    /// What the path to the port adds to every wait on it; see [`on_path`].
    path: PathAllowance,
    /// What the identification's connections and reads came to, beyond what
    /// they drew.
    tally: Arc<Tally>,
}

/// What an identification's connections and reads came to beyond what they
/// drew, told from wherever in its scope they happened; see [`Fingerprinted`].
#[derive(Debug, Default)]
struct Tally {
    /// A connection was given up for want of a socket; see [`dial_again`].
    starved: AtomicBool,
    /// A wait for the port to say something ran its clock out with nothing
    /// heard.
    ran_out_waiting: AtomicBool,
    /// A reply came only after more than half the wait it was given.
    answered_late: AtomicBool,
}

/// Tells the identification whose scope this runs in something its
/// connections or reads came to. Nothing is told outside one, which is an
/// analyzer or a read driven directly rather than through a scan.
fn tell(what: impl FnOnce(&Tally)) {
    let _ = DIALLING.try_with(|dialling| what(&dialling.tally));
}

/// `wait`, which a path that costs nothing needs, on the path to the port
/// being identified.
///
/// Every wait on the port, for a connection, a greeting, a reply or a
/// handshake, is set for how long the service may take to answer. A path that
/// costs a round trip adds it to each of them, and a wait that does not allow
/// for it gives up on an answer still on its way: behind a path of two
/// seconds, every greeting and every reply. The allowance is what the scan
/// measured of the path, sized as the port scans size their own probes'; see
/// [`PathAllowance`]. Outside an identification's scope the wait is as set.
fn on_path(wait: Duration) -> Duration {
    DIALLING
        .try_with(|dialling| dialling.path.over(wait))
        .unwrap_or(wait)
}

tokio::task_local! {
    /// How the port being fingerprinted is dialled, by its later questions
    /// and by its analyzers.
    ///
    /// A scope rather than an argument because an analyzer is handed a
    /// [`PortContext`], which is public, non-exhaustive, and built by struct
    /// literal throughout the crate; what an analyzer dials through, and how
    /// it reports a connection the process could not make, is the engine's
    /// business and not a field a caller outside it could fill. Set around
    /// the whole identification, whose collection runs inline on the task
    /// that set it: the one task it spawns is the CPU phase, which dials
    /// nothing, so no connection is made from where the scope cannot reach.
    static DIALLING: Dialling;
}

/// Connects to `addr` for an analyzer, the way the port it is examining was
/// reached.
///
/// Outside a fingerprint's collection, which is an analyzer driven directly
/// through [`analyze_with`], the routing table decides, as it does for any
/// public entry point here, and a connection refused a socket has no scan to
/// report to.
pub(crate) async fn analyzer_connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let egress = DIALLING
        .try_with(|dialling| dialling.egress)
        .unwrap_or(Egress::KERNEL);
    dial_again(addr, egress, None).await
}

/// The analyzer registry. New evidence sources (HTTP, JARM, SNMP, nerva binary
/// handlers, ...) are added here, the only place the set is enumerated. The
/// instances are stateless zero-sized values, so a `'static` slice of shared
/// references is free and lets both phases (and the blocking task) reference the
/// same set.
static ANALYZERS: &[&dyn Analyzer] = &[
    &BannerRegexAnalyzer,
    &FaviconAnalyzer,
    &HttpHeadersAnalyzer,
    &JarmAnalyzer,
    &SshAnalyzer,
    &TlsCertAnalyzer,
];

/// The analyzers this engine runs, in the order they are consulted.
///
/// Exposed so a caller can run the built-in set beside one of their own:
///
/// ```no_run
/// # use zond_engine::fingerprint::{Analyzer, analyzers};
/// # fn example(mine: &'static dyn Analyzer) {
/// let mut set: Vec<&'static dyn Analyzer> = analyzers().to_vec();
/// set.push(mine);
/// # }
/// ```
///
/// The order is not a ranking. Evidence is ranked by
/// [`ServiceVerdict::resolve`], which sorts by confidence and breaks ties
/// stably, so this decides only what a full tie falls back on.
#[must_use]
pub fn analyzers() -> &'static [&'static dyn Analyzer] {
    ANALYZERS
}

/// Runs the registered analyzers over `responses` and resolves their evidence
/// into a verdict, honouring the two-phase contract: each interested analyzer's
/// [`collect`](Analyzer::collect) runs here on the reactor (I/O), then all the
/// [`analyze`](Analyzer::analyze) work is handed to the blocking pool (CPU).
/// `tunnel` marks how the shared responses were carried, so evidence drawn from
/// decrypted data is labelled accordingly. Returns `None` if analysis produced
/// nothing (or the blocking task failed to join).
async fn analyze(
    port: u16,
    protocol: Protocol,
    addr: Option<std::net::SocketAddr>,
    responses: ResponseSet,
    tunnel: Option<Tunnel>,
    detection: ServiceDetection,
    name: Option<Arc<str>>,
) -> Option<ServiceVerdict> {
    // Read before the context is built, so an active analyzer's `collect` can
    // gate on it: `collect` is handed no responses and runs before any evidence
    // is resolved.
    let speaks_http = responses
        .banners
        .iter()
        .any(|banner| banner.starts_with("HTTP/"));

    let ctx = PortContext::new(port, protocol)
        .with_addr(addr)
        .with_tunnel(tunnel)
        .with_speaks_http(speaks_http)
        .with_detection(detection)
        .with_host_name(name.map(|name| name.to_string()));
    analyze_with(ctx, responses, analyzers()).await
}

/// Runs `analyzers` over `responses` and resolves their evidence into a verdict,
/// honouring the two-phase contract.
///
/// Each interested analyzer's [`collect`](Analyzer::collect) runs here on the
/// reactor (I/O), then all the [`analyze`](Analyzer::analyze) work is handed to
/// the blocking pool (CPU). Returns `None` if analysis produced nothing, or if
/// the blocking task failed to join.
///
/// This is where a caller's own analyzer goes. Gather responses by whatever
/// means, with [`fingerprint_tcp_detailed`] handing back the ones it read, then
/// pass [`analyzers()`] alongside it:
///
/// ```no_run
/// # use zond_engine::fingerprint::{Analyzer, PortContext, ResponseSet, analyze_with, analyzers};
/// # use zond_engine::model::port::Protocol;
/// # async fn example(mine: &'static dyn Analyzer) {
/// let mut set: Vec<&'static dyn Analyzer> = analyzers().to_vec();
/// set.push(mine);
/// // Leaked once at start-up, which is what a `'static` set means in practice.
/// let set: &'static [&'static dyn Analyzer] = Box::leak(set.into_boxed_slice());
///
/// let ctx = PortContext::new(8080, Protocol::Tcp);
/// let responses = ResponseSet::from_banners(vec!["HTTP/1.1 200 OK".to_string()]);
/// let verdict = analyze_with(ctx, responses, set).await;
/// # }
/// ```
///
/// The slice is `'static` because the CPU phase runs on the blocking pool and
/// has to own what it reads. That costs nothing in practice: an analyzer is a
/// stateless value, so a `static` of them is the natural way to hold a set, and
/// it is how the built-in registry is held.
pub async fn analyze_with(
    ctx: PortContext,
    responses: ResponseSet,
    analyzers: &'static [&'static dyn Analyzer],
) -> Option<ServiceVerdict> {
    // Phase 1, I/O on the reactor: let each interested analyzer run its own
    // probes. Passive analyzers return an empty `Collected`, their inputs being
    // in the shared `responses`.
    //
    // `interested` is asked once and the answer kept, rather than asked again in
    // the CPU phase: it is documented as a cheap gate, and a gate answering
    // differently between the two phases would silently pair one analyzer's
    // frames with another's reading.
    let mut collected = Vec::with_capacity(analyzers.len());
    for analyzer in analyzers {
        let interested = analyzer.interested(&ctx);
        collected.push((
            interested,
            match interested {
                true => analyzer.collect(&ctx, &responses).await,
                false => Collected::default(),
            },
        ));
    }

    // Phase 2, CPU off the reactor: parse the shared responses plus each
    // analyzer's own frames into evidence, then resolve. A large match set can
    // never stall the scheduler from here.
    tokio::task::spawn_blocking(move || {
        let mut evidence = Vec::new();
        for (analyzer, (interested, collected)) in analyzers.iter().zip(&collected) {
            if *interested {
                evidence.extend(analyzer.analyze(&ctx, &responses, collected));
            }
        }

        (!evidence.is_empty()).then(|| ServiceVerdict::resolve(evidence))
    })
    .await
    .ok()
    .flatten()
}

/// Reads one bounded chunk from `stream`, giving up after `wait`. Returns `None`
/// on timeout, error, or a clean empty read.
async fn read_response<S>(stream: &mut S, wait: Duration) -> Option<String>
where
    S: AsyncRead + Unpin,
{
    read_bytes(stream, wait, Duration::ZERO)
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// [`read_response`], but reading on until the port goes quiet.
///
/// For a reply that may be a *document* rather than a line. One `read` returns
/// one segment, and an HTTP server that writes its headers and its body
/// separately hands over the headers alone, so the `Server` header arrives and
/// the `<title>` that names the application does not, on the ports where the
/// title is the only thing that would have named it.
///
/// Deliberately not what a banner grab uses. A greeting is one short write and
/// waiting on for a second one costs [`CONTINUATION_GRACE`] on every port that
/// greets, which is the fastest path there is and the last one worth taxing.
async fn read_document<S>(stream: &mut S, wait: Duration) -> Option<String>
where
    S: AsyncRead + Unpin,
{
    read_bytes(stream, wait, CONTINUATION_GRACE)
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Reads up to [`MAX_RESPONSE_BYTES`] of whatever the port sends, waiting `wait`
/// for the first byte, allowing for the path (see [`on_path`]), and `grace` for
/// each read after it.
///
/// It tells the identification it reads for when the first byte came late in
/// its wait or not at all; see [`Fingerprinted::answered_late`] and
/// [`Fingerprinted::ran_out_waiting`].
///
/// A `grace` of zero reads exactly once, which is what a banner grab wants; a
/// non-zero one reads on until the port goes quiet, which is what a document
/// wants. See [`read_response`] and [`read_document`].
///
/// Bytes rather than text, because the caller sometimes has to tell a banner
/// from a TLS alert and `from_utf8_lossy` destroys the difference.
///
/// # Three bounds, each owning one thing
///
/// `wait` is how long the port has to say anything at all. `grace` is how long a
/// gap between two reads may be. [`MAX_CONTINUATION`] is how long the whole
/// remainder may take once the first byte has arrived, and it is the one that
/// makes the others safe: a peer that stays inside `grace` indefinitely is
/// inside every per-read bound and past any sensible total, which is how one
/// port held this function for ninety-seven seconds.
async fn read_bytes<S>(stream: &mut S, wait: Duration, grace: Duration) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let wait = on_path(wait);
    let asked = tokio::time::Instant::now();
    let mut collected: Vec<u8> = Vec::new();
    let mut buffer = [0u8; MAX_RESPONSE_BYTES];
    let mut budget = wait;
    // Set on the first byte rather than on entry, so a port that took its time
    // greeting is not then charged for it twice.
    let mut deadline = None;

    while collected.len() < MAX_RESPONSE_BYTES {
        let first = collected.is_empty();
        match timeout(budget, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                if first && asked.elapsed() > wait / 2 {
                    tell(|tally| tally.answered_late.store(true, Ordering::Relaxed));
                }
                let room = MAX_RESPONSE_BYTES - collected.len();
                collected.extend_from_slice(&buffer[..n.min(room)]);
                if grace.is_zero() {
                    break;
                }
                let deadline =
                    *deadline.get_or_insert_with(|| tokio::time::Instant::now() + MAX_CONTINUATION);
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                budget = grace.min(remaining);
            }
            // Nothing at all within the wait, which the identification is
            // told, since a port that said nothing in time may yet have been
            // about to.
            Err(_elapsed) if first => {
                tell(|tally| tally.ran_out_waiting.store(true, Ordering::Relaxed));
                break;
            }
            // A clean close, an error, or the port going quiet: whatever has
            // arrived is all there is.
            _ => break,
        }
    }

    (!collected.is_empty()).then_some(collected)
}

/// The first 32 printable characters across `responses`, for a last-resort
/// banner label. `None` if there is nothing printable.
fn first_printable(responses: &[String]) -> Option<String> {
    let printable: String = responses
        .iter()
        .flat_map(|response| response.chars())
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(32)
        .collect();

    (!printable.is_empty()).then_some(printable)
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

    /// One SNMP reply is one witness to what a host runs.
    ///
    /// A rule that names the box files its maker with the host's hardware, and
    /// identification then read the same maker back as the hardware vendor and
    /// counted it a second time. This MikroTik switch's description reached 86 on
    /// one datagram, past the 85 at which the active OS probe is skipped as having
    /// nothing left to settle. The host here is one reached through a gateway, so
    /// no hardware address stands behind the vendor at all.
    #[test]
    fn a_service_describing_its_hardware_is_one_witness_and_not_two() {
        let evidence = SignatureDb::global()
            .identify(161, Protocol::Udp, "CSS326-24G-2S+ SwOS v2.13")
            .expect("the corpus knows SwOS");
        assert!(
            evidence.os.is_some() && evidence.hardware.is_some(),
            "test premise: the rule names both the system and the box"
        );

        let mut host = crate::model::host::Host::new("192.0.2.1".parse().expect("literal"));
        AboutTheHost::from_evidence(&[evidence]).apply(&mut host);

        let os = host
            .os()
            .expect("an SNMP description is a verdict on its own");
        assert!(
            !os.is_highly_confident(),
            "one reply settled the host at {}",
            os.accuracy()
        );
    }

    /// A port number nothing is registered under yields no service at all.
    ///
    /// The alternative is a placeholder, and a placeholder is a service name as
    /// far as every consumer is concerned. The exported JSON, the CSV, the HTML
    /// page and the nmap XML another tool ingests would each say the port is
    /// running something called `???`.
    #[test]
    fn an_unregistered_port_is_seeded_with_nothing() {
        // 1 is `tcpmux` and registered; a high ephemeral port is not.
        assert!(baseline_service(22).is_some());

        let unregistered = (40_000..=65_535)
            .find(|port| lookup_service_name(*port).is_none())
            .expect("some port in the ephemeral range is unregistered");

        assert!(
            baseline_service(unregistered).is_none(),
            "port {unregistered} invented a service name"
        );
        assert!(
            baseline_port(unregistered, Protocol::Tcp, PortState::Closed)
                .service()
                .is_none()
        );
    }

    /// An SCTP port carries the name of whatever claims its number, which for
    /// the ports a scan of a mobile core asks about is the whole of what this
    /// engine can say about them.
    ///
    /// Nothing here fingerprints an SCTP service: naming one needs a completed
    /// association, and the scan opens none. A port reported with no label at
    /// all is the alternative, and `2905/sctp open` tells a reader less than
    /// their own notes would.
    #[test]
    fn an_sctp_port_is_named_by_the_service_that_claims_its_number() {
        let port = baseline_port(2905, Protocol::Sctp, PortState::Open);
        let service = port.service().expect("m3ua claims 2905");

        assert_eq!(service.name(), "m3ua");
        assert!(
            service.is_inferred(),
            "nothing asked the port what it was running"
        );
    }

    /// And what is seeded is marked as the guess it is.
    #[test]
    fn a_seeded_label_is_never_mistaken_for_an_identification() {
        let seeded = baseline_service(22).expect("ssh is registered");
        assert_eq!(seeded.name(), "ssh");
        assert!(
            seeded.is_inferred(),
            "nothing asked port 22 what it was running"
        );
    }
    /// The root of a self-hosted application is very often a redirect and
    /// nothing else, and the page one hop away is the only thing that names it.
    #[test]
    fn a_same_host_redirect_names_where_to_look_next() {
        let jellyfin = "HTTP/1.1 302 Found\r\n\
             Location: /web/index.html\r\n\
             Server: Kestrel\r\n\r\n";
        assert_eq!(
            redirect_path(jellyfin, Some(&peer())).as_deref(),
            Some("/web/index.html")
        );
    }

    /// The port a redirect test pretends to be identifying.
    fn peer() -> Authority {
        Authority::new("127.0.0.1:8096".parse().expect("a literal address"))
    }

    /// RFC 7231 §7.1.2 permits a relative reference, which RFC 2616 did not, and
    /// real servers send one: Jellyfin answers `GET /` with `Location: web/`.
    /// Reading that as somewhere else left the page it points at unread, and the
    /// application unidentified on a host that was serving its own name one hop
    /// away.
    #[test]
    fn a_relative_location_resolves_against_the_root_it_was_served_from() {
        let jellyfin = "HTTP/1.1 302 Found\r\nLocation: web/\r\nServer: Kestrel\r\n\r\n";
        assert_eq!(
            redirect_path(jellyfin, Some(&peer())).as_deref(),
            Some("/web/")
        );
    }

    /// Grafana, Portainer and Prometheus all answer `GET /` with a `Location`
    /// naming themselves in full. Declining every absolute URL left the page
    /// that identifies them unread on all three.
    #[test]
    fn an_absolute_location_naming_the_scanned_host_is_followed() {
        let grafana = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:8096/login\r\n\r\n";
        assert_eq!(
            redirect_path(grafana, Some(&peer())).as_deref(),
            Some("/login")
        );

        // No path is the root, not an empty request line.
        let bare = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:8096\r\n\r\n";
        assert_eq!(redirect_path(bare, Some(&peer())).as_deref(), Some("/"));
    }

    /// A different port is a different service, over a connection this path has
    /// not made. Same address, and still declined.
    #[test]
    fn an_absolute_location_on_another_port_is_declined() {
        let elsewhere = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9999/x\r\n\r\n";
        assert_eq!(redirect_path(elsewhere, Some(&peer())), None);
    }

    /// A scheme this path cannot speak needs a handshake there is no socket for.
    #[test]
    fn an_upgrade_to_https_is_declined_rather_than_guessed() {
        let upgrade = "HTTP/1.1 301 Moved\r\nLocation: https://127.0.0.1:8096/\r\n\r\n";
        assert_eq!(redirect_path(upgrade, Some(&peer())), None);
    }

    /// With no address to compare against, an absolute URL cannot be shown to be
    /// the host in hand, so it is not followed.
    #[test]
    fn an_absolute_location_is_declined_when_there_is_no_peer_to_check() {
        let named = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:8096/login\r\n\r\n";
        assert_eq!(redirect_path(named, None), None);
    }

    /// A scheme-relative reference names a host, so it is somewhere else however
    /// much it looks like a path.
    #[test]
    fn a_scheme_relative_location_is_declined_like_any_other_host() {
        let elsewhere = "HTTP/1.1 302 Found\r\nLocation: //cdn.example/web/\r\n\r\n";
        assert_eq!(redirect_path(elsewhere, Some(&peer())), None);

        // The same spelling, naming the host in hand, is followed.
        let here = "HTTP/1.1 302 Found\r\nLocation: //127.0.0.1:8096/web/\r\n\r\n";
        assert_eq!(redirect_path(here, Some(&peer())).as_deref(), Some("/web/"));
    }

    /// A redirect somewhere else is an instruction to go and talk to a third
    /// party. A scan of one address has no business putting traffic on an
    /// uninvolved host, and attributing what came back to the host being scanned
    /// would be wrong even if it did.
    #[test]
    fn a_redirect_off_the_host_is_declined() {
        for location in [
            "https://example.com/login",
            "http://somewhere.else/",
            // A scheme change needs a handshake this path has no socket for.
            "https://127.0.0.1/web/",
            // A lone carriage return is not a CRLF and survives `lines()`, and
            // some servers read one as a line terminator. Nothing remote is
            // spliced into a request this engine writes.
            "/web/\rX-Injected: 1",
            "/web/\u{0}index.html",
        ] {
            let response = format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\n\r\n");
            assert_eq!(
                redirect_path(&response, Some(&peer())),
                None,
                "`{location}` is not somewhere this scan may follow"
            );
        }
    }

    /// Only a redirect is followed. A page that answered is the answer.
    #[test]
    fn a_response_that_is_not_a_redirect_names_nowhere_to_go() {
        assert_eq!(
            redirect_path(
                "HTTP/1.1 200 OK\r\nLocation: /ignored\r\n\r\n",
                Some(&peer())
            ),
            None,
            "a 200 is an answer, whatever else it carries"
        );
        assert_eq!(
            redirect_path("HTTP/1.1 302 Found\r\nServer: nginx\r\n\r\n", Some(&peer())),
            None,
            "and a redirect naming nowhere leads nowhere"
        );
        assert_eq!(
            redirect_path("SSH-2.0-OpenSSH_9.2p1\r\n", Some(&peer())),
            None
        );
        assert_eq!(redirect_path("", Some(&peer())), None);
    }

    /// An IPv6 address is written in brackets wherever a port may follow it,
    /// so a server naming itself by its IPv6 address names it bracketed, and a
    /// scan of that address follows the redirect as it would an IPv4 one.
    #[test]
    fn an_ipv6_redirect_naming_the_scanned_host_is_followed() {
        let peer: SocketAddr = "[2001:db8::1]:8096".parse().expect("a literal address");
        let grafana = "HTTP/1.1 302 Found\r\nLocation: http://[2001:db8::1]:8096/login\r\n\r\n";
        assert_eq!(
            redirect_path(grafana, Some(&Authority::new(peer))).as_deref(),
            Some("/login")
        );

        let elsewhere = "HTTP/1.1 302 Found\r\nLocation: http://[2001:db8::2]:8096/login\r\n\r\n";
        assert_eq!(redirect_path(elsewhere, Some(&Authority::new(peer))), None);
    }

    /// The `Host` a redirect is followed with names an IPv6 address in
    /// brackets. Unbracketed, its last group reads as a port, and a server
    /// either refuses the request or routes it to a site that is not there.
    #[tokio::test]
    async fn a_redirect_on_ipv6_is_asked_for_by_a_bracketed_host() {
        let Ok(listener) = tokio::net::TcpListener::bind("[::1]:0").await else {
            eprintln!("SKIP: no IPv6 loopback on this machine");
            return;
        };
        let addr = listener.local_addr().expect("a local address");
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("the first connection");
            let mut buffer = [0u8; 1024];
            let _ = first.read(&mut buffer).await;
            let _ = first
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n")
                .await;
            drop(first);
            let (mut second, _) = listener.accept().await.expect("the redirect followed");
            let read = second.read(&mut buffer).await.unwrap_or(0);
            let _ = second
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
            String::from_utf8_lossy(&buffer[..read]).into_owned()
        });

        let stream = TcpStream::connect(addr).await.expect("connects");
        let _ = plaintext(stream, 51987, Some(&Authority::new(addr)), Egress::KERNEL).await;
        let request = server.await.expect("the listener finishes");

        let host = format!("\r\nHost: [::1]:{}\r\n", addr.port());
        assert!(
            request.contains(&host),
            "the redirect was asked for without `{}`: {request:?}",
            host.trim()
        );
    }

    /// A TLS record is not a banner, and reading one as text loses exactly the
    /// bytes that say so. What a TLS server sends a plaintext request is an
    /// alert, and taking it for a greeting leaves the port unidentifiable.
    #[test]
    fn a_tls_alert_is_recognised_as_tls_rather_than_as_a_banner() {
        // Alert, TLS 1.2, two bytes: fatal, unexpected_message.
        assert!(looks_like_tls(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x0A]));
        // A ServerHello, for a peer that answered the handshake it expected.
        assert!(looks_like_tls(&[0x16, 0x03, 0x01, 0x00, 0x2A]));

        assert!(!looks_like_tls(b"HTTP/1.1 200 OK"));
        assert!(!looks_like_tls(b"SSH-2.0-OpenSSH_9.2p1"));
        assert!(!looks_like_tls(&[0x15]), "too short to be a record");
        assert!(!looks_like_tls(&[]));
    }

    use super::*;

    #[tokio::test]
    async fn analyze_runs_both_phases_and_resolves() {
        // Drives the real orchestration, the collect phase (a no-op for the two
        // passive analyzers) followed by the off-reactor analyze phase, over a
        // recorded SSH banner, and asserts it resolves through to a verdict.
        let responses = ResponseSet::from_banners(vec!["SSH-2.0-OpenSSH_9.6p1 Debian".to_string()]);
        let verdict = analyze(
            22,
            Protocol::Tcp,
            None,
            responses,
            None,
            ServiceDetection::default(),
            None,
        )
        .await
        .expect("names a service");

        assert_eq!(verdict.service.as_deref(), Some("ssh"));
        assert_eq!(verdict.product.as_deref(), Some("OpenSSH"));
        assert_eq!(verdict.version.as_deref(), Some("9.6p1"));
    }

    #[tokio::test]
    async fn analyze_identifies_a_long_tail_http_server_end_to_end() {
        // The structured HTTP analyzer must carry a `Server:` value through to
        // product and version via the full pipeline.
        //
        // Two observations read this header and both are `Strong`: splitting it
        // on the slash yields `gunicorn` and nothing else, and the corpus rule
        // for the same value yields `Gunicorn`, the vendor, and the CPE. The
        // curated reading takes the slot, which is the only reason a version
        // here can reach a vulnerability catalogue at all.
        let responses = ResponseSet::from_banners(vec![
            "HTTP/1.1 200 OK\r\nServer: gunicorn/21.2.0\r\nContent-Type: text/html\r\n\r\n"
                .to_string(),
        ]);
        let verdict = analyze(
            8000,
            Protocol::Tcp,
            None,
            responses,
            None,
            ServiceDetection::default(),
            None,
        )
        .await
        .expect("names a service");

        assert_eq!(verdict.service.as_deref(), Some("http"));
        assert_eq!(verdict.product.as_deref(), Some("Gunicorn"));
        assert_eq!(verdict.version.as_deref(), Some("21.2.0"));
        assert_eq!(
            verdict.cpe.as_deref(),
            Some("cpe:/a:gunicorn:gunicorn:21.2.0"),
            "the reading that won the slot is the one the correlator can use"
        );
    }

    #[tokio::test]
    async fn analyze_composes_curated_product_vendor_with_powered_by_extrainfo() {
        // End-to-end composition across analyzers: the curated Apache signature
        // (banner analyzer) supplies the rich product + vendor, the structured
        // HTTP analyzer supplies the X-Powered-By extrainfo, and the framework
        // never usurps the product slot. All three land on one Service.
        let responses = ResponseSet::from_banners(vec![
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\nX-Powered-By: PHP/8.2.1\r\n\r\n"
                .to_string(),
        ]);
        let service = analyze(
            80,
            Protocol::Tcp,
            None,
            responses,
            None,
            ServiceDetection::default(),
            None,
        )
        .await
        .expect("names a service")
        .to_service()
        .expect("projects onto a service");

        assert_eq!(service.name(), "http");
        assert_eq!(service.product(), Some("Apache HTTP Server"));
        assert_eq!(service.vendor(), Some("Apache Software Foundation"));
        assert_eq!(service.version(), Some("2.4.58"));
        assert_eq!(service.extrainfo(), Some("PHP/8.2.1"));
    }

    #[tokio::test]
    async fn analyze_resolves_a_versionless_server_to_its_name_not_generic_http() {
        // A versionless `Server` is Probable, the same as the HTTP analyzer's
        // baseline. If the baseline names a product, the stable sort keeps it
        // first and the real server ("cloudflare") is buried under a generic
        // "http". This must resolve to the server name.
        let responses = ResponseSet::from_banners(vec![
            "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n\r\n".to_string(),
        ]);
        let verdict = analyze(
            8000,
            Protocol::Tcp,
            None,
            responses,
            None,
            ServiceDetection::default(),
            None,
        )
        .await
        .expect("names a service");

        assert_eq!(verdict.service.as_deref(), Some("http"));
        assert_eq!(verdict.product.as_deref(), Some("cloudflare"));
    }

    /// A hostile response cannot put a kilobyte into a report.
    ///
    /// Measured before [`MAX_IDENTITY_BYTES`] existed: one reply produced a
    /// 1500-byte `product` and a 1500-byte `extrainfo`, and both travelled into
    /// the store and every export. Every sibling reading in this module already
    /// bounded itself and said why; these had no argument for being unbounded,
    /// only no author.
    #[tokio::test]
    async fn a_hostile_response_cannot_fill_a_report_field() {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a socket");
        let addr = listener.local_addr().expect("its address");
        let server = tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let long = "A".repeat(1_500);
            let response =
                format!("HTTP/1.1 200 OK\r\nServer: {long}\r\nX-Powered-By: {long}\r\n\r\n");
            let _ = sock.write_all(response.as_bytes()).await;
            let mut buffer = [0u8; MAX_RESPONSE_BYTES];
            let _ = sock.read(&mut buffer).await;
        });

        let stream = TcpStream::connect(addr).await.expect("connects");
        let port = baseline_port(80, Protocol::Tcp, PortState::Open);
        let identified = fingerprint_tcp(stream, port, ServiceDetection::Probe).await;
        server.abort();

        let service = identified.service().expect("the port is still named");
        for (field, value) in [
            ("product", service.product()),
            ("version", service.version()),
            ("extrainfo", service.extrainfo()),
        ] {
            if let Some(value) = value {
                assert!(
                    value.len() <= MAX_IDENTITY_BYTES,
                    "{field} is {} bytes, past the bound",
                    value.len()
                );
            }
        }
        assert_eq!(
            service.product(),
            None,
            "a fifteen-hundred-byte token is refused rather than truncated"
        );
    }

    /// And an ordinary value is untouched by the bound.
    #[test]
    fn an_ordinary_identity_field_passes_through() {
        assert_eq!(identity_field("nginx/1.24.0"), Some("nginx/1.24.0"));
        assert_eq!(identity_field("  PHP/8.2.1  "), Some("PHP/8.2.1"));
        assert_eq!(identity_field(""), None);
        assert_eq!(identity_field("   "), None);
        assert_eq!(
            identity_field(&"A".repeat(MAX_IDENTITY_BYTES)).map(str::len),
            Some(MAX_IDENTITY_BYTES)
        );
        assert_eq!(identity_field(&"A".repeat(MAX_IDENTITY_BYTES + 1)), None);
    }

    /// A legacy-only TLS server is reported, not lost.
    ///
    /// rustls implements TLS 1.2 and 1.3 and implements neither 1.0
    /// nor 1.1, so a server offering only the older versions fails the modern
    /// handshake. Without the legacy probe it would be reported as a port that
    /// answered nothing at all, which loses the identification and the finding
    /// together.
    ///
    /// The mock answers a ClientHello with a TLS 1.0 ServerHello and nothing
    /// else, which is enough: the finding is the version.
    #[tokio::test]
    async fn a_server_that_speaks_only_tls_ten_is_still_recorded() {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a socket");
        let addr = listener.local_addr().expect("its address");
        let server = tokio::spawn(async move {
            // Twice: the modern handshake dials first and is answered with an
            // alert, then the legacy probe dials on its own connection.
            for round in 0..2 {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buffer = [0u8; 1024];
                let _ = sock.read(&mut buffer).await;
                let reply: &[u8] = match round {
                    // Fatal alert: protocol_version. What a 1.0-only server
                    // answers a hello offering 1.2 and 1.3.
                    0 => &[0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46],
                    // A ServerHello naming TLS 1.0.
                    _ => &[
                        0x16, 0x03, 0x01, 0x00, 0x2a, 0x02, 0x00, 0x00, 0x26, 0x03, 0x01,
                    ],
                };
                let _ = sock.write_all(reply).await;
            }
        });

        // The port number decides the path, and the socket decides the peer, so
        // an implicit-TLS number over a loopback socket exercises the real
        // branch without binding a privileged port.
        let stream = TcpStream::connect(addr).await.expect("connects");
        let port = baseline_port(443, Protocol::Tcp, PortState::Open);
        let (responses, tunnel) =
            gather(stream, 443, ServiceDetection::Probe, Egress::KERNEL, None).await;
        server.abort();
        let _ = port;

        assert!(
            tunnel.is_none(),
            "nothing was tunnelled and nothing claims to be"
        );
        let tls = responses
            .tls
            .as_ref()
            .expect("the port speaks TLS, which is the finding");
        assert_eq!(tls.version, Some("TLSv1.0"));

        // And it reaches the record a report carries.
        assert_eq!(tls_security(tls).tls_version(), Some("TLSv1.0"));
    }

    /// A port that trickles cannot hold a scan.
    ///
    /// One byte every forty milliseconds sits permanently inside
    /// [`CONTINUATION_GRACE`], so without [`MAX_CONTINUATION`] this read would
    /// run until the four-kilobyte cap was reached: measured at ninety-seven
    /// seconds for one socket, with nothing above it to cut the exchange short.
    ///
    /// The assertion is on the clock rather than on the bytes because the clock
    /// is the property. A generous ceiling keeps this from failing on a loaded
    /// machine while still being an order of magnitude below those ninety-seven
    /// seconds.
    #[tokio::test]
    async fn a_trickling_port_cannot_hold_the_reader() {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a socket");
        let addr = listener.local_addr().expect("its address");
        let server = tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            // Just inside the grace, for longer than any budget here allows.
            for _ in 0..2_000 {
                if sock.write_all(b"A").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
        });

        let mut stream = TcpStream::connect(addr).await.expect("connects");
        let started = std::time::Instant::now();
        let read = read_document(&mut stream, PROBE_READ_TIMEOUT).await;
        let held = started.elapsed();
        server.abort();

        assert!(read.is_some(), "what did arrive is still returned");
        assert!(
            held < PROBE_READ_TIMEOUT + MAX_CONTINUATION + Duration::from_secs(2),
            "one trickling port held the reader for {held:?}"
        );
    }

    /// And the whole collection has a ceiling of its own, above every path
    /// through [`gather`], so a stage added later cannot reintroduce the class.
    ///
    /// The paths are written out rather than summed, because their sum is not a
    /// walk anything takes and a budget sized against it would be loose by half.
    /// Whoever adds a rung adds it here, and finds out immediately whether the
    /// budget still covers it.
    ///
    /// A rung has two costs and which one it pays decides whether the ladder
    /// goes on. `spoke` is a rung that drew bytes, so it pays a continuation on
    /// every read and it is the last rung walked. `silent` is a rung that drew
    /// nothing, so it pays only the wait and hands on to the next. Charging both
    /// to every rung would be arithmetic no port can produce.
    ///
    /// The exception is a plaintext rung answered with a TLS record: bytes, so a
    /// continuation, and still nothing this rung can report. That is what
    /// `alert_then_tls` is.
    ///
    /// Each path is counted twice over: what it takes on a path that costs
    /// nothing, and how many of its waits allow for a path that does. A
    /// continuation is not one of them, since it starts once the answer has
    /// already arrived. The budget covers every path on every path only when
    /// it covers the first and allows for at least as many of the second.
    #[test]
    fn the_collection_budget_covers_every_path_through_gather() {
        /// A walk: how long it takes on a path that costs nothing, and how
        /// many of its waits allow for the path.
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
        struct Walk(Duration, u32);
        impl std::ops::Add for Walk {
            type Output = Walk;
            fn add(self, other: Walk) -> Walk {
                Walk(self.0 + other.0, self.1 + other.1)
            }
        }
        impl std::ops::Mul<u32> for Walk {
            type Output = Walk;
            fn mul(self, times: u32) -> Walk {
                Walk(self.0 * times, self.1 * times)
            }
        }
        let wait = |duration: Duration| Walk(duration, 1);
        let continuation = Walk(MAX_CONTINUATION, 0);

        // The longest read a port's own probes can draw: at most two are
        // registered for any port in the shipped corpus, each its own wait plus
        // its continuation.
        let probes = SignatureDb::global()
            .indexed_ports()
            .map(|port| SignatureDb::global().tcp_probe_payloads(port).len())
            .max()
            .unwrap_or(0)
            .max(1) as u32;
        let spoke = |count: u32| {
            wait(BANNER_READ_TIMEOUT) + (wait(PROBE_READ_TIMEOUT) + continuation) * count
        };
        let silent = |count: u32| wait(BANNER_READ_TIMEOUT) + wait(PROBE_READ_TIMEOUT) * count;
        let read_once = wait(PROBE_READ_TIMEOUT) + continuation;
        let rung = wait(CONNECT_RETRY_TIMEOUT);
        let handshake = wait(tls::TLS_HANDSHAKE_TIMEOUT);
        let legacy = wait(tls::LEGACY_PROBE_TIMEOUT);
        let speculative = wait(tls::SPECULATIVE_TLS_TIMEOUT);

        // Numbered for TLS: [Tls, LegacyTls, Plaintext].
        let tls_all_three = handshake + rung + legacy + rung + spoke(probes);
        let tls_then_silence = handshake + rung + legacy + rung + silent(probes);

        // Numbered for anything else: [Plaintext, SpeculativeTls]. Inside the
        // tunnel a claimed port asks its own probes again and an unclaimed one
        // asks the single generic question.
        let claimed_then_tls = silent(probes) + rung + speculative + spoke(probes);
        let alert_then_tls = read_once + rung + speculative + spoke(1);
        let unclaimed_then_redirect = read_once + rung + read_once;
        // A web server refusing the request in the clear, then asked for a
        // handshake, and for the legacy one where that is refused.
        let refused_then_tls = spoke(probes) + rung + speculative + spoke(probes);
        let refused_then_legacy = spoke(probes) + rung + speculative + rung + legacy;

        // And the last rung, which is a connection and a read per probe, for
        // every probe, since a reply to one of them does not end it.
        let universal = SignatureDb::global()
            .universal_tcp_probe_payloads(0, ServiceDetection::Thorough.probe_intensity())
            .len()
            .max(1) as u32;
        let last_resort = (rung + read_once) * universal;

        let paths = [
            tls_all_three + last_resort,
            tls_then_silence + last_resort,
            claimed_then_tls,
            alert_then_tls,
            unclaimed_then_redirect,
            refused_then_tls,
            refused_then_legacy,
            silent(probes) + rung + speculative + last_resort,
        ];
        let longest = paths.iter().map(|walk| walk.0).max().expect("eight paths");
        let most_waits = paths.iter().map(|walk| walk.1).max().expect("eight paths");

        assert!(
            longest < COLLECTION_BUDGET,
            "the budget ({COLLECTION_BUDGET:?}) is below the longest honest path \
             ({longest:?}), so it would cut real scans short"
        );
        assert!(
            most_waits <= COLLECTION_WAITS,
            "the budget allows for the path {COLLECTION_WAITS} times and a walk \
             waits on it {most_waits} times, so it would cut scans on a slow \
             path short"
        );
    }

    /// A level that sends nothing sends nothing through an analyzer either.
    ///
    /// The SSH analyzer's key exchange is a second connection carrying this
    /// engine's identification and a KEXINIT, and it is started from a banner
    /// alone. Listening is what a caller asks for on equipment that must not be
    /// sent anything, and what a scan does on a printer's raw-print port, so the
    /// port that greeted is asked nothing further. The port number is SSH's
    /// while the socket is an ephemeral loopback one, as in the legacy TLS test
    /// above: the number decides which analyzer is interested, the socket who
    /// is dialled.
    #[tokio::test]
    async fn a_port_only_listened_to_is_not_dialled_again_by_an_analyzer() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let addr = listener.local_addr().expect("a local address");
        let connections = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(AtomicUsize::new(0));
        let (seen, bytes) = (Arc::clone(&connections), Arc::clone(&received));
        let server = tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                seen.fetch_add(1, Ordering::SeqCst);
                let bytes = Arc::clone(&bytes);
                tokio::spawn(async move {
                    let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n").await;
                    let mut buffer = [0u8; 1024];
                    while let Ok(n) = sock.read(&mut buffer).await {
                        if n == 0 {
                            break;
                        }
                        bytes.fetch_add(n, Ordering::SeqCst);
                    }
                });
            }
        });

        let stream = TcpStream::connect(addr).await.expect("connects");
        let port = baseline_port(22, Protocol::Tcp, PortState::Open);
        let port = fingerprint_tcp_via(
            stream,
            port,
            ServiceDetection::Banner,
            Egress::KERNEL,
            PathAllowance::NONE,
            None,
        )
        .await
        .port;
        server.abort();

        assert_eq!(
            port.service().map(Service::name),
            Some("ssh"),
            "the greeting alone names the service"
        );
        assert_eq!(
            connections.load(Ordering::SeqCst),
            1,
            "the port was dialled again"
        );
        assert_eq!(
            received.load(Ordering::SeqCst),
            0,
            "the port was sent a payload"
        );
    }

    /// What the clear-text rung sends a silent port numbered `number`, read
    /// off a loopback listener that records every byte and answers nothing.
    /// The number decides what is asked, the socket who is asked, as in the
    /// tests above. Asked with no peer to address it to, so what arrives is
    /// the probes as authored, whatever port the listener was given.
    async fn asked_in_the_clear(number: u16) -> Vec<u8> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let addr = listener.local_addr().expect("a local address");
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("one connection");
            let mut received = Vec::new();
            let _ = sock.read_to_end(&mut received).await;
            received
        });

        let stream = TcpStream::connect(addr).await.expect("connects");
        plaintext(stream, number, None, Egress::KERNEL).await;
        server.await.expect("the listener finishes")
    }

    /// A raw-print port a scan was told to probe is asked what a port nothing
    /// claims is asked.
    ///
    /// What spares a printer is the scan's listen-only list, which keeps these
    /// ports from ever reaching a rung that sends. A port taken off that list
    /// is one the operator chose to probe, and the corpus claiming it for a
    /// probe that sends nothing would quietly undo that choice: the rung would
    /// wait on a port that never greets and never put the question that names
    /// what is there.
    #[tokio::test]
    async fn a_raw_print_port_probed_on_purpose_is_asked_what_an_unclaimed_port_is() {
        let unclaimed = 51987;
        assert!(
            SignatureDb::global()
                .tcp_probe_payloads(unclaimed)
                .is_empty(),
            "test assumes port {unclaimed} is unclaimed"
        );
        let expected: Vec<u8> = SignatureDb::global().generic_tcp_probe_payloads().concat();
        assert!(
            !expected.is_empty(),
            "the corpus asks unclaimed ports nothing"
        );

        let (print, other) = tokio::join!(
            asked_in_the_clear(crate::config::RAW_PRINT_PORTS[0]),
            asked_in_the_clear(unclaimed)
        );

        assert_eq!(other, expected);
        assert_eq!(
            String::from_utf8_lossy(&print),
            String::from_utf8_lossy(&expected),
            "the raw-print port was asked something else"
        );
    }

    /// A connection an identification gives up for want of a socket marks
    /// the identification starved, and one that fails for any other reason
    /// does not.
    ///
    /// An analyzer's connection is made inside a clock of the analyzer's own,
    /// the SSH key exchange's or a favicon fetch's, which a full table runs
    /// out while the connection still waits for a descriptor. Unmarked, the
    /// port reads as one with nothing more to say where the question that
    /// would have said it was never put. A port that refuses the connection
    /// has answered, and is no shortfall of this machine's.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_connection_given_up_for_want_of_a_socket_marks_the_identification_starved() {
        use crate::system::descriptors::testing::{exhaust, in_a_process_of_its_own};

        if !in_a_process_of_its_own(
            module_path!(),
            "a_connection_given_up_for_want_of_a_socket_marks_the_identification_starved",
        ) {
            return;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let open = listener.local_addr().expect("a local address");
        let closed = {
            let gone = std::net::TcpListener::bind("127.0.0.1:0").expect("binds loopback");
            gone.local_addr().expect("a local address")
        };

        // Dialled the way an analyzer dials, inside the identification's
        // scope and inside a clock of its own.
        let dial = |addr: SocketAddr| async move {
            let tally = Arc::new(Tally::default());
            let dialling = Dialling {
                egress: Egress::KERNEL,
                path: PathAllowance::NONE,
                tally: Arc::clone(&tally),
            };
            let _ = DIALLING
                .scope(
                    dialling,
                    timeout(Duration::from_millis(300), analyzer_connect(addr)),
                )
                .await;
            tally.starved.load(Ordering::Relaxed)
        };

        let held = exhaust(64);
        let refused_a_socket = dial(open).await;
        drop(held);
        let refused_by_the_port = dial(closed).await;
        drop(listener);

        assert!(
            refused_a_socket,
            "a connection the process had no socket for was read as the port's silence"
        );
        assert!(
            !refused_by_the_port,
            "a port that refused the connection was blamed on the file limit"
        );
    }

    /// A UDP identification the process had no socket for says so, rather
    /// than coming back as the silence an unanswered datagram is.
    ///
    /// Over UDP silence is the ordinary answer, so a datagram never sent reads
    /// exactly like one the port ignored unless it is marked: the scan would
    /// file the port as heard out when it was never asked. A port asked and
    /// silent is still silence.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_udp_identification_refused_a_socket_is_starved_and_not_silent() {
        use crate::system::descriptors::testing::{exhaust, in_a_process_of_its_own};

        if !in_a_process_of_its_own(
            module_path!(),
            "a_udp_identification_refused_a_socket_is_starved_and_not_silent",
        ) {
            return;
        }
        // A port the corpus asks something of over UDP, with nothing on
        // loopback listening there, so the one asked is refused or unanswered.
        let snmp: SocketAddr = "127.0.0.1:161".parse().expect("an address");
        assert!(
            !SignatureDb::global().udp_probe_payloads(161).is_empty(),
            "test assumes the corpus asks port 161 something over UDP"
        );
        let port = || baseline_port(161, Protocol::Udp, PortState::Open);
        let patience = Duration::from_millis(50);

        let held = exhaust(64);
        let unasked =
            fingerprint_udp_within(snmp, port(), Egress::KERNEL, patience, PathAllowance::NONE)
                .await;
        drop(held);
        let asked =
            fingerprint_udp_within(snmp, port(), Egress::KERNEL, patience, PathAllowance::NONE)
                .await;

        let unasked = unasked.expect("a datagram never sent was read as the port's silence");
        assert!(unasked.starved);
        assert!(unasked.responses.is_empty());
        assert!(
            asked.is_none(),
            "a port asked and silent was not read as silence: {asked:?}"
        );
    }

    /// A redirect is followed once the connection that drew it is closed, so
    /// an identification holds the one socket its pass took a share of the
    /// descriptor budget for, and never two.
    #[tokio::test]
    async fn a_redirect_is_followed_after_the_connection_that_drew_it_is_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let addr = listener.local_addr().expect("a local address");
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("the first connection");
            let mut buffer = [0u8; 1024];
            let _ = first.read(&mut buffer).await;
            // Held open, as a server keeping the connection alive does.
            let _ = first
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n")
                .await;
            let (mut second, _) = listener.accept().await.expect("the redirect followed");
            // By now the first has to have been let go.
            let first_open = !matches!(
                tokio::time::timeout(Duration::from_millis(500), first.read(&mut buffer)).await,
                Ok(Ok(0))
            );
            let _ = second.read(&mut buffer).await;
            let _ = second
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
            first_open
        });

        let stream = TcpStream::connect(addr).await.expect("connects");
        let banners = plaintext(stream, 51987, Some(&Authority::new(addr)), Egress::KERNEL)
            .await
            .banners;
        let first_open = server.await.expect("the listener finishes");

        assert_eq!(
            banners.len(),
            2,
            "the redirect was not followed: {banners:?}"
        );
        assert!(
            !first_open,
            "the redirect was followed while the connection that drew it was held"
        );
    }

    /// A Zabbix agent moved off its registered port is put its framed question
    /// at the thorough level, and only there.
    ///
    /// An agent answers nothing but a request in the protocol's own frame and
    /// closes on anything else, an HTTP request included, so on a port its
    /// number does not name only the questions other services registered can
    /// reach it. Those go to a stranger by the rarity authored on each: the
    /// thorough level is the one that promises them all, and the default level
    /// asks only what a silent port most often turns out to be.
    #[tokio::test]
    async fn a_zabbix_agent_on_a_port_of_its_own_is_named_at_the_thorough_level_alone() {
        let moved = 18801;
        assert!(
            SignatureDb::global().tcp_probe_payloads(moved).is_empty(),
            "test assumes port {moved} is unclaimed"
        );

        let mut named = Vec::new();
        for level in [ServiceDetection::Thorough, ServiceDetection::Probe] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("binds loopback");
            let addr = listener.local_addr().expect("a local address");
            let framed = Arc::new(AtomicBool::new(false));
            let heard = Arc::clone(&framed);
            let agent = tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    let mut buffer = [0u8; 1024];
                    let read = sock.read(&mut buffer).await.unwrap_or(0);
                    if buffer[..read].starts_with(b"ZBXD\x01") {
                        heard.store(true, Ordering::SeqCst);
                        // `1` for the ping, behind the header, the protocol
                        // flag and an eight-byte little-endian length.
                        let _ = sock.write_all(b"ZBXD\x01\x01\0\0\0\0\0\0\0\x31").await;
                    }
                }
            });

            let stream = TcpStream::connect(addr).await.expect("connects");
            let port = baseline_port(moved, Protocol::Tcp, PortState::Open);
            let found = fingerprint_tcp_detailed(stream, port, level).await;
            agent.abort();
            named.push((
                found
                    .port
                    .service()
                    .map(|service| service.name().to_owned()),
                framed.load(Ordering::SeqCst),
            ));
        }

        assert_eq!(
            named[0],
            (Some("zabbix".to_owned()), true),
            "a thorough identification did not name the agent (service, asked)"
        );
        assert_eq!(
            named[1],
            (None, false),
            "the default level put a rare question to a stranger (service, asked)"
        );
    }

    #[tokio::test]
    async fn analyze_returns_none_when_no_evidence() {
        // No banners and no TLS: both phases run, no analyzer produces evidence,
        // so the orchestration resolves to nothing rather than an empty verdict.
        assert!(
            analyze(
                1,
                Protocol::Tcp,
                None,
                ResponseSet::default(),
                None,
                ServiceDetection::default(),
                None,
            )
            .await
            .is_none()
        );
    }

    /// What a loopback server was asked, request by request, in the order
    /// they arrived: decrypted where they came through TLS.
    type Heard = Arc<std::sync::Mutex<Vec<String>>>;

    /// A loopback HTTPS server keeping a certificate for `name` alone, as a
    /// server holding its sites by name keeps one per site, so a handshake
    /// naming nothing, or something else, is refused. A request in the clear is
    /// answered the way Go's server answers one, with a plaintext `400`.
    async fn https_by_name(name: &str) -> (SocketAddr, Heard) {
        use rustls::server::ResolvesServerCertUsingSni;
        use rustls::sign::CertifiedKey;

        let cert = rcgen::generate_simple_self_signed(vec![name.to_string()])
            .expect("a self-signed certificate");
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );
        let signing = rustls::crypto::ring::sign::any_supported_type(&key).expect("a signing key");
        let mut by_name = ResolvesServerCertUsingSni::new();
        by_name
            .add(
                name,
                CertifiedKey::new(vec![cert.cert.der().clone()], signing),
            )
            .expect("the name takes the certificate");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(by_name));
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let addr = listener.local_addr().expect("a local address");
        let heard: Heard = Arc::default();
        let record = Arc::clone(&heard);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (acceptor, record) = (acceptor.clone(), Arc::clone(&record));
                tokio::spawn(async move {
                    let mut first = [0u8; 1];
                    if stream.peek(&mut first).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let mut buffer = [0u8; 2048];
                    if first[0] != 0x16 {
                        let mut stream = stream;
                        let read = stream.read(&mut buffer).await.unwrap_or(0);
                        record.lock().expect("not poisoned").push(format!(
                            "clear: {}",
                            String::from_utf8_lossy(&buffer[..read])
                        ));
                        let _ = stream
                            .write_all(
                                b"HTTP/1.0 400 Bad Request\r\n\r\n\
                                  Client sent an HTTP request to an HTTPS server.\n",
                            )
                            .await;
                        return;
                    }
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let read = tls.read(&mut buffer).await.unwrap_or(0);
                    record
                        .lock()
                        .expect("not poisoned")
                        .push(String::from_utf8_lossy(&buffer[..read]).into_owned());
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nServer: Caddy\r\n\
                              Content-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (addr, heard)
    }

    /// A server keeping its certificates by name completes a handshake only
    /// for a client naming a site it holds, so a port on an address a target
    /// reached by name is asked for by that name, in the handshake and in the
    /// request inside it. Asked for by nothing, the port reads as one that does
    /// not speak TLS at all.
    #[tokio::test]
    async fn a_tls_port_on_a_named_address_is_asked_for_by_its_name() {
        let (addr, heard) = https_by_name("box.example").await;

        let stream = TcpStream::connect(addr).await.expect("connects");
        let port = baseline_port(443, Protocol::Tcp, PortState::Open);
        let found = fingerprint_tcp_via(
            stream,
            port,
            ServiceDetection::Probe,
            Egress::KERNEL,
            PathAllowance::NONE,
            Some(Arc::from("box.example")),
        )
        .await;

        assert!(
            found.port.security().is_some(),
            "the handshake did not complete: {:?}",
            heard.lock().expect("not poisoned")
        );
        let service = found.port.service().expect("a service was named");
        assert_eq!(service.name(), "ssl/http");
        let asked = heard.lock().expect("not poisoned").clone();
        let host = format!("\r\nHost: box.example:{}\r\n", addr.port());
        assert!(
            asked.iter().any(|request| request.contains(&host)),
            "nothing inside the tunnel asked for `{}`: {asked:?}",
            host.trim()
        );
    }

    /// A stream that notes, in order, whether each operation on it was a read
    /// or a write, over the client half of an in-memory pipe.
    struct Noting {
        inner: tokio::io::DuplexStream,
        seen: Vec<&'static str>,
    }

    impl AsyncRead for Noting {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.seen.last() != Some(&"read") {
                self.seen.push("read");
            }
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Noting {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.seen.last() != Some(&"write") {
                self.seen.push("write");
            }
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// What the clear-text rung does first on a port numbered `number`
    /// claimed by something that registered probes.
    async fn first_move_on(number: u16) -> &'static str {
        let (client, mut server) = tokio::io::duplex(8192);
        let answering = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            while server.read(&mut buffer).await.unwrap_or(0) > 0 {
                let _ = server
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });
        let mut noting = Noting {
            inner: client,
            seen: Vec::new(),
        };
        let db = SignatureDb::global();
        let probes = db.tcp_probe_payloads(number);
        assert!(!probes.is_empty(), "port {number} registers probes");
        let _ = collect_responses(&mut noting, number, probes, None, !db.asked_first(number)).await;
        answering.abort();
        noting.seen.first().copied().unwrap_or("nothing")
    }

    /// An HTTP server never speaks first, so a web port is asked at once
    /// rather than listened to for a greeting that never comes, which cost
    /// every web port a scan identified the whole of a banner wait. A port
    /// where something that greets may be listening is listened to first.
    #[tokio::test]
    async fn a_web_port_is_asked_before_it_is_listened_to() {
        assert_eq!(
            first_move_on(8080).await,
            "write",
            "8080 waited for a greeting"
        );
        assert_eq!(
            first_move_on(9200).await,
            "write",
            "9200 waited for a greeting"
        );
        assert!(
            !SignatureDb::global().asked_first(21),
            "a port a greeting service claims is listened to first"
        );
    }

    /// Identifies an HTTPS server, the one `https_by_name` stands up, on a
    /// port whose number does not say TLS, asked for by `name`.
    async fn https_off_the_list(name: Option<&str>) -> Fingerprinted {
        let (addr, _heard) = https_by_name("box.example").await;
        let number = 9443;
        assert!(
            !tls::is_tls_port(number),
            "test assumes {number} is not numbered for TLS"
        );
        let stream = TcpStream::connect(addr).await.expect("connects");
        fingerprint_tcp_via(
            stream,
            baseline_port(number, Protocol::Tcp, PortState::Open),
            ServiceDetection::Probe,
            Egress::KERNEL,
            PathAllowance::NONE,
            name.map(Arc::from),
        )
        .await
    }

    /// A web server listening for TLS answers a request in the clear with a
    /// plaintext `400`, which is an answer and so ended the identification
    /// there: HTTPS on a port its number does not name was reported as plain
    /// `http`, with no certificate and none of the names it carries. The
    /// refusal is what sends the port a handshake.
    #[tokio::test]
    async fn https_on_a_port_numbered_for_nothing_is_reached_through_its_handshake() {
        let found = https_off_the_list(Some("box.example")).await;

        let service = found.port.service().expect("a service was named");
        assert_eq!(service.name(), "ssl/http");
        assert_eq!(service.product(), Some("Caddy"));
        let security = found.port.security().expect("the handshake is recorded");
        assert!(
            security.certificate().is_some(),
            "the certificate was not read: {security:?}"
        );
    }

    /// A server keeping its certificates by name refuses a handshake naming no
    /// site it holds, which is every handshake where the target named an
    /// address. It still answers in TLS, so the port is filed as the web
    /// server over TLS its refusal in the clear said it was, not as a plain
    /// `http` port the next pass would send requests to in the clear.
    #[tokio::test]
    async fn https_refusing_a_nameless_handshake_is_still_filed_as_https() {
        let found = https_off_the_list(None).await;

        let service = found.port.service().expect("a service was named");
        assert_eq!(service.name(), "ssl/http");
        assert!(
            found.port.security().is_some(),
            "the port's TLS went unrecorded"
        );
    }
}
