// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Service fingerprinting
//!
//! Identifies the service, product and version behind an open port.
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
//! * [`Analyzer`]s are the extension point; [`BannerRegexAnalyzer`] is one.
//!
//! ## Concurrency
//!
//! First-contact I/O and each analyzer's `collect` run on the async reactor;
//! all `analyze` (CPU) work runs on the blocking pool. No regex is compiled on
//! a reactor thread.

pub mod model;

pub mod os;

mod analyzer;
pub(crate) mod authority;
mod context;
mod db;
mod extract;
mod favicon;
mod framed;
mod http;
mod jarm;
mod ldap;
mod matcher;
// Crate-visible so the Tier-1 flow interpreter compiles its patterns with the
// same engine.
pub(crate) mod pattern;
mod prefilter;
mod response;
mod signature;
mod sip;
mod smb;
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
// The register of every field a signature may be written against, and whether
// anything in this engine produces it, for callers authoring signatures.
pub use context::{CONTEXTS, Context, Reach, context_note, reach_of};
pub use signature::{
    CORPUS_ROOT, DefinitionError, MAX_COMPILED_REGEX_BYTES, MAX_UDP_PROBE_BYTES, MatchRule, Probe,
    RULE_ID_SEPARATOR, RuleIdDefect, ServiceDefinition, ServiceSignature, claim_rule_id,
    corpus_slug, rule_id,
};
// Also used by the Tier-1 interpreter to decode a flow's escapes.
pub(crate) use signature::unescape;
pub use ssh::SshAnalyzer;
pub use tls_cert::TlsCertAnalyzer;
pub use tls_enum::{EXCHANGE_TIMEOUT, MAX_OFFERS_PER_VERSION, enumerate_tls, enumerate_tls_named};
// The same walk, bounded by a scan's budget.
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
use crate::transport::dial::{Egress, Shaping, pacing};
use authority::Authority;

/// How long to wait for a service to speak first (banner grab).
///
/// This and every peer wait below excludes path delay; a scan that measured the
/// path adds it (see [`on_path`]).
const BANNER_READ_TIMEOUT: Duration = Duration::from_millis(500);
/// How long to wait for a reply to an active probe.
const PROBE_READ_TIMEOUT: Duration = Duration::from_millis(1_000);
/// How long to keep reading once a response has started arriving.
///
/// Bridges the gap between a server writing its headers and its body, at worst
/// a round trip. Every complete response pays it in full, since a finished
/// server just goes quiet, so it is kept low; ports pay it in parallel.
const CONTINUATION_GRACE: Duration = Duration::from_millis(50);
/// What this engine calls itself when it asks an HTTP server a question.
///
/// Matches the authored probe in `assets/fingerprinting/web/http.toml`, so a
/// server's logs show one visitor.
const USER_AGENT: &str = "ZondScanner/1.0";

/// How long to wait for the second connection a speculative TLS handshake needs.
///
/// The first connection to this port already succeeded, so this one either
/// succeeds at once or the port has stopped accepting.
const CONNECT_RETRY_TIMEOUT: Duration = Duration::from_millis(500);
/// Upper bound on how much of a single response is read and kept.
const MAX_RESPONSE_BYTES: usize = 4096;

/// The longest a single identity field lifted from a response may be.
///
/// Product, version and supplementary detail are short by nature; without a
/// bound a hostile reply can put a kilobyte into each, and it travels into the
/// store, the journal and every report format.
///
/// A longer value is refused rather than truncated, as the SNMP reader does for
/// `sysDescr`: a truncated version is simply wrong.
pub const MAX_IDENTITY_BYTES: usize = 256;

/// `value` as an identity field, or `None` where it is empty or past
/// [`MAX_IDENTITY_BYTES`].
///
/// The one place the bound is applied.
pub(crate) fn identity_field(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= MAX_IDENTITY_BYTES).then_some(value)
}

/// How long a response may go on arriving, measured from its first byte.
///
/// [`CONTINUATION_GRACE`] bounds the gap between reads but not their number; a
/// peer writing one byte every forty milliseconds would otherwise hold a task
/// indefinitely. Two seconds is far beyond any legitimate response.
const MAX_CONTINUATION: Duration = Duration::from_secs(2);

/// The ceiling on everything one port's collection may spend on the network.
///
/// A backstop: every stage has its own bound. The longest legitimate walk down
/// [`gather`]'s ladder is 35.5 seconds: a port several services share and none
/// names, where the generic question is refused with a `400`, each service is
/// asked on its own connection with a redirect followed, then a handshake and
/// the same again through the tunnel. At the thorough level, a failed handshake,
/// a failed legacy handshake, the clear and the last-resort probes come to 30,
/// plus 3.5 per probe authored for strangers.
/// `the_collection_budget_covers_every_path_through_gather` keeps this above
/// both.
///
/// On a measured path the budget adds the path delay once per wait the longest
/// walk makes ([`COLLECTION_WAITS`]), so behind a slow path it grows to
/// minutes along with the walk itself.
const COLLECTION_BUDGET: Duration = Duration::from_secs(40);

/// The most sequential peer waits (connections or reads) any walk down
/// [`gather`]'s ladder makes, with headroom. The longest makes nineteen;
/// eighteen at the thorough level, plus two per probe authored for strangers.
/// Checked by `the_collection_budget_covers_every_path_through_gather`.
const COLLECTION_WAITS: u32 = 20;

/// Whether a reply from this port over this protocol is one the engine can read.
///
/// Any TCP port qualifies, since it may volunteer a banner. A UDP port qualifies
/// only where a decoder can turn the answer into text.
#[must_use]
pub fn reads_replies(port: u16, protocol: Protocol) -> bool {
    extract::reads(port, protocol)
}

/// The service name registered for a port number, if any.
///
/// A metadata lookup with **no regex compilation**, cheap enough for every
/// classified port. Returns the same names full fingerprinting uses.
///
/// Registration is per port, not per transport: signature files name port
/// numbers only.
pub fn lookup_service_name(port: u16) -> Option<String> {
    SignatureDb::global()
        .service_name(port)
        .map(|s| s.to_string())
}

/// What a service said about the *machine* it runs on, as distinct from what it
/// said about itself.
///
/// The service belongs to the port; the operating system, hardware and names
/// belong to the host. One banner often states both.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct AboutTheHost {
    /// What the responses implied about the operating system.
    pub os: Vec<crate::model::host::OsEvidence>,
    /// The hardware they described, where they described any. Over five hundred
    /// shipped rules name a box and no system at all.
    pub hardware: Option<crate::model::host::HardwareInfo>,
    /// The names the machine gave for itself, in the order they were read.
    pub names: Vec<crate::model::host::HostName>,
}

impl AboutTheHost {
    /// Whether nothing was concluded about the machine.
    pub fn is_empty(&self) -> bool {
        self.os.is_empty() && self.hardware.is_none() && self.names.is_empty()
    }

    /// Records everything this says about `host`, and reports whether the
    /// operating-system reading changed.
    ///
    /// Hardware is merged, not replaced: an address-block record and a banner
    /// describe the same box, and
    /// [`HardwareInfo::merge`](crate::model::host::HardwareInfo::merge) picks the
    /// right half of each.
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
        for name in self.names {
            host.record_name(name);
        }
        os::identify(host, self.os)
    }

    /// What a verdict says about the machine: everything, where it named the
    /// service, and the names alone where it did not.
    ///
    /// Names are read from a reply's structure by an analyzer, so they hold even
    /// when no rule named the service. Operating system and hardware are a rule's
    /// conclusions about the software it identified.
    fn of_verdict(verdict: Option<&ServiceVerdict>) -> Self {
        match verdict {
            Some(verdict) if !verdict.is_empty() => Self::from_evidence(&verdict.evidence),
            Some(verdict) => Self {
                names: names_in(&verdict.evidence),
                ..Self::default()
            },
            None => Self::default(),
        }
    }

    /// Reads both from a resolved verdict's whole evidence set.
    ///
    /// From every observation, since a signature that lost the service ranking
    /// may be the one that named the machine.
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
            names: names_in(evidence),
        }
    }
}

/// Every name an observation in `evidence` gave for the machine, in order.
fn names_in(evidence: &[Evidence]) -> Vec<crate::model::host::HostName> {
    evidence
        .iter()
        .flat_map(|e| e.names.iter().cloned())
        .collect()
}

/// The text a UDP reply from `port` carries, where this engine can read one.
///
/// For a caller who dialled the port themselves; [`reads_replies`] says whether
/// a port qualifies. Empty for a port with no decoder, which is most of them.
///
/// More than one text where a reply answers more than one question, as an SNMP
/// agent's description and object identifier do.
pub fn decode_udp_reply(port: u16, datagram: &[u8]) -> Vec<String> {
    extract::from_datagram(port, datagram)
}

/// What a completed handshake established, as the record a report carries.
///
/// A summary: who the certificate claims to be, who issued it, its validity
/// window, and a fingerprint. No trust decision is made; expired, self-signed
/// and wrong-host certificates are reported.
///
/// Always produces a record, even for an unreadable chain.
///
/// For a caller who performed their own handshake: build a [`TlsInfo`] from
/// what the TLS client returns.
pub fn tls_security(tls: &TlsInfo) -> crate::model::port::Security {
    tls_summary::security(tls)
}

/// The confidence-0 label every scan path seeds before deeper fingerprinting:
/// the name the port number is registered under, and **nothing at all where it
/// is registered under none**.
///
/// Shared by the SYN, connect and service-detection paths.
///
/// A port with no registered name yields `None`; any placeholder would reach
/// every report format as a service name.
///
/// The zero confidence marks it as a guess; see
/// [`Service::is_inferred`](crate::model::port::Service::is_inferred).
pub fn baseline_service(port: u16) -> Option<Service> {
    lookup_service_name(port).map(|name| Service::new(name, 0))
}

/// Waits for the shipped signature corpus to be built, building it on the
/// blocking pool where nothing has started to, for a scan to call before its
/// first probe leaves.
///
/// The build takes tens of milliseconds. Done lazily on a runtime worker by the
/// first probe filing a verdict, it would delay the readiness of every
/// connection in flight (about 40 ms in a debug build), and each would be
/// timed as a 40 ms path. Built here, before anything is timed, it delays no
/// probe.
///
/// A scan starts the build as it opens, with [`start_loading_corpus`].
pub(crate) async fn load_corpus() {
    // A panic is the embedded corpus failing to decode, which the next caller
    // meets the same way. A build already under way is waited for here too.
    let _ = tokio::task::spawn_blocking(|| {
        SignatureDb::global();
    })
    .await;
}

/// Starts building the shipped signature corpus on the blocking pool, where
/// nothing has yet, and returns at once, for a scan to call as it opens.
///
/// The passes before the port scan never use the corpus, so the build runs
/// beside them and [`load_corpus`] has less to wait for.
pub(crate) fn start_loading_corpus() {
    drop(tokio::task::spawn_blocking(|| {
        SignatureDb::global();
    }));
}

/// A [`Port`] in the given `state` carrying only the [`baseline_service`] label.
///
/// What every discovery path records first. The SYN path and ports that did not
/// open stop here; the connect and service-detection paths refine it with
/// [`fingerprint_tcp_detailed`].
pub fn baseline_port(port: u16, protocol: Protocol, state: PortState) -> Port {
    let mut classified = Port::new(port, protocol, state);
    if let Some(service) = baseline_service(port) {
        classified.set_service(service);
    }
    classified
}

/// Actively fingerprints an open TCP `stream` and refines `port`'s service.
///
/// Network I/O (banner grab, active probes) runs on the reactor with bounded
/// reads and per-stage timeouts; signature matching runs on the blocking pool.
///
/// If nothing identifies, a trimmed printable banner is kept: as detail beside
/// the port number's registered name, or as the label where the number names
/// nothing.
pub async fn fingerprint_tcp(stream: TcpStream, port: Port, detection: ServiceDetection) -> Port {
    fingerprint_tcp_detailed(stream, port, detection).await.port
}

/// [`fingerprint_tcp`], also returning what the service said about the *machine*.
///
/// Over half the signature corpus carries operating-system metadata, and a
/// banner such as `OpenSSH_9.6p1 Debian` states the distribution directly. No
/// extra probe is sent for it.
///
/// Also returns the gathered responses (empty when nothing was read), for a
/// later detection, and whether the identification was starved of a socket;
/// see [`Fingerprinted::starved`].
///
/// Further connections to the port follow the routing table.
pub async fn fingerprint_tcp_detailed(
    stream: TcpStream,
    port: Port,
    detection: ServiceDetection,
) -> Fingerprinted {
    fingerprint_tcp_via(
        stream,
        port,
        detection,
        &Egress::KERNEL,
        PathAllowance::NONE,
        None,
    )
    .await
}

/// What identifying one port came to: the port as it was named, what its
/// service said about the machine, the responses it drew, and whether the
/// process ran short of sockets while asking.
///
/// Non-exhaustive, so further facts can be added as fields.
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
    /// What was learned is kept, as a lower bound. The cause is this machine's,
    /// and the remedy is a higher file limit. Over TCP it affects a later
    /// question (a redirect, an analyzer's connection). Over UDP a starved
    /// identification learned nothing, since each datagram follows a silent one.
    pub starved: bool,
    /// Whether a wait for the port to say something ran its clock out with
    /// nothing heard: a greeting, a reply or a handshake that did not come.
    ///
    /// With nothing drawn, this separates a port with nothing to say from one
    /// whose answer was queued behind another's. A port that closed on every
    /// question waited for nothing.
    pub(crate) ran_out_waiting: bool,
    /// Whether a reply came only after more than half the wait it was given,
    /// counting the service's time and not the path's.
    ///
    /// Such a service fits only one answer in a wait, so a question queued behind
    /// another is not answered in time.
    pub(crate) answered_late: bool,
    /// How long the waits that ran out were given, together.
    ///
    /// A host serving questions one at a time still serves the ones nobody waits
    /// for; this is how long those can occupy it.
    pub(crate) waited_in_vain: Duration,
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
    egress: &Egress,
    path: PathAllowance,
    name: Option<Arc<str>>,
) -> Fingerprinted {
    // Every later connection dials through this scope, every wait is sized in
    // it, and socket starvation and reply timing are reported to it; see
    // `DIALLING`.
    let tally = Arc::new(Tally::default());
    let dialling = Dialling {
        egress: egress.clone(),
        path,
        tally: Arc::clone(&tally),
    };
    // Ceilings pause while a connection waits for its pacing slot; see
    // `dial::pacing`.
    let (port, about_the_host, responses) = pacing::holding(
        egress,
        DIALLING.scope(
            dialling,
            identify_tcp(stream, port, detection, egress, path, name),
        ),
    )
    .await;
    Fingerprinted {
        port,
        about_the_host,
        responses,
        starved: tally.starved.load(Ordering::Relaxed),
        ran_out_waiting: tally.ran_out_waiting.load(Ordering::Relaxed),
        answered_late: tally.answered_late.load(Ordering::Relaxed),
        waited_in_vain: *tally
            .waited_in_vain
            .lock()
            .unwrap_or_else(|held| held.into_inner()),
    }
}

/// The identification [`fingerprint_tcp_via`] runs inside its dialling scope.
async fn identify_tcp(
    stream: TcpStream,
    mut port: Port,
    detection: ServiceDetection,
    egress: &Egress,
    path: PathAllowance,
    name: Option<Arc<str>>,
) -> (Port, AboutTheHost, Vec<String>) {
    // The peer address for active analyzers, before `gather` consumes the
    // stream. Only at a level that sends; without it they stay passive.
    let addr = stream.peer_addr().ok().filter(|_| detection.sends());
    // See `COLLECTION_BUDGET`. A port that runs out is left as the scan recorded
    // it.
    let Ok((responses, tunnel)) =
        pacing::timeout(path.over_each(COLLECTION_BUDGET, COLLECTION_WAITS), || {
            gather(stream, port.number(), detection, egress, name.clone())
        })
        .await
    else {
        return (port, AboutTheHost::default(), Vec::new());
    };
    if responses.is_empty() {
        return (port, AboutTheHost::default(), Vec::new());
    }

    // Recorded whatever the analyzers conclude: an unidentified service still
    // has a certificate worth reporting.
    if let Some(tls) = responses.tls.as_ref() {
        port.set_security(tls_summary::security(tls));
    }

    // Keep a fallback label and the responses before handing the set to the
    // blocking pool.
    let fallback = first_printable(&responses.banners);
    let banners = responses.banners.clone();
    let stated = responses.names.clone();
    // The egress reaches the analyzers as their scope, since the public context
    // cannot carry it; see `DIALLING`.
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
    let mut about_the_host = AboutTheHost::of_verdict(verdict.as_ref());
    match verdict {
        Some(verdict) if !verdict.is_empty() => {
            if let Some(service) = verdict.to_service() {
                port.set_service(service);
            }
        }
        // Unrecognised: a port whose number has a registered name keeps it (as a
        // guess) with the banner as detail; otherwise the banner is the label.
        // This matches what a SYN scan records, so the result does not depend on
        // the scan type.
        _ => {
            if let Some(banner) = fallback {
                let fallen_back = match port.service() {
                    Some(named) if named.extrainfo().is_none() => {
                        Some(named.clone().with_extrainfo(banner))
                    }
                    Some(_) => None,
                    None => Some(Service::new(format!("banner: {banner}"), 0)),
                };
                if let Some(service) = fallen_back {
                    port.set_service(service);
                }
            }
        }
    }
    // Names hold whether or not any rule named the service.
    about_the_host.names.extend(stated);

    (port, about_the_host, banners)
}

/// Fingerprints an open **UDP** port, returning the upgraded [`Port`] and
/// whatever the reply said about the machine behind it.
///
/// The UDP counterpart of [`fingerprint_tcp_detailed`]: draw a response, turn
/// it into corpus text, and hand it to the same analyzers.
///
/// It sends a second datagram, since the port scan discards reply bodies
/// rather than hold them for every port.
///
/// Only ports [`reads_replies`] accepts are asked. `None` means silence, the
/// ordinary case over UDP. A datagram the process had no socket for was never
/// sent; that returns the port unchanged with
/// [`starved`](Fingerprinted::starved) set.
///
/// The datagram follows the routing table.
pub async fn fingerprint_udp_detailed(
    addr: std::net::SocketAddr,
    port: Port,
) -> Option<Fingerprinted> {
    fingerprint_udp_via(addr, port, &Egress::KERNEL).await
}

/// [`fingerprint_udp_detailed`], with the datagram leaving by `egress`.
pub(crate) async fn fingerprint_udp_via(
    addr: std::net::SocketAddr,
    port: Port,
    egress: &Egress,
) -> Option<Fingerprinted> {
    fingerprint_udp_on(addr, port, egress, PathAllowance::NONE).await
}

/// [`fingerprint_udp_via`], with each wait for a reply allowing for `path`.
pub(crate) async fn fingerprint_udp_on(
    addr: std::net::SocketAddr,
    port: Port,
    egress: &Egress,
    path: PathAllowance,
) -> Option<Fingerprinted> {
    fingerprint_udp_within(addr, port, egress, descriptors::PATIENCE, path).await
}

/// [`fingerprint_udp_on`], waiting out a full descriptor table for
/// `patience` before a datagram is given up as starved.
async fn fingerprint_udp_within(
    addr: std::net::SocketAddr,
    mut port: Port,
    egress: &Egress,
    patience: Duration,
    path: PathAllowance,
) -> Option<Fingerprinted> {
    let responses = match probe_udp(addr, egress, patience, path).await {
        Datagram::Reply(responses) => responses,
        Datagram::Silent | Datagram::Unasked => return None,
        Datagram::Starved => {
            return Some(Fingerprinted {
                port,
                about_the_host: AboutTheHost::default(),
                responses: Vec::new(),
                starved: true,
                ran_out_waiting: false,
                answered_late: false,
                waited_in_vain: Duration::ZERO,
            });
        }
    };
    let banners = responses.banners.clone();
    let stated = responses.names.clone();

    // No tunnel and no peer address (active analyzers dial TCP), so the
    // detection level changes nothing and the default is used.
    let verdict = analyze(
        addr.port(),
        Protocol::Udp,
        None,
        responses,
        None,
        ServiceDetection::default(),
        None,
    )
    .await;

    // Names hold whether or not any rule named the service.
    let mut about_the_host = AboutTheHost::of_verdict(verdict.as_ref());
    about_the_host.names.extend(stated);
    let service = verdict.and_then(|verdict| verdict.to_service());
    if service.is_none() && about_the_host.names.is_empty() {
        return None;
    }
    if let Some(service) = service {
        port.set_service(service);
    }

    Some(Fingerprinted {
        port,
        about_the_host,
        responses: banners,
        starved: false,
        ran_out_waiting: false,
        answered_late: false,
        waited_in_vain: Duration::ZERO,
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
    /// The scan stopped, or the host ran out of its budget, while the
    /// exchange waited for its slot, so it was never asked.
    Unasked,
}

/// Sends this port's registered probes and reads back whatever text a reply
/// carries, or `None` if none carried any.
///
/// The socket is connected, so the kernel drops datagrams from other addresses.
///
/// Unlike [`payload::for_port`](crate::scanner::payload::for_port), which needs
/// only the first probe, each registered probe is tried in turn until one
/// yields text or a name. NTP needs this: the client request draws only
/// timestamps, and the daemon describes itself only to a mode 6 message.
///
/// A probe with no socket available ends the walk as starved.
async fn probe_udp(
    addr: std::net::SocketAddr,
    egress: &Egress,
    patience: Duration,
    path: PathAllowance,
) -> Datagram<ResponseSet> {
    for payload in SignatureDb::global().udp_probe_payloads(addr.port()) {
        match exchange_datagram(addr, payload, egress, patience, path).await {
            Datagram::Reply(reply) => {
                let read = ResponseSet {
                    banners: extract::from_datagram(addr.port(), &reply),
                    names: extract::names_from_datagram(addr.port(), &reply),
                    ..ResponseSet::default()
                };
                if !read.banners.is_empty() || !read.names.is_empty() {
                    return Datagram::Reply(read);
                }
            }
            Datagram::Silent => {}
            // The next probe would meet the same condition.
            Datagram::Starved => return Datagram::Starved,
            Datagram::Unasked => return Datagram::Unasked,
        }
    }
    Datagram::Silent
}

/// Sends `payload` to `addr` and reads back whatever text the reply carries.
///
/// Like `probe_udp`, with a caller-supplied payload for questions specific to
/// one host, such as an mDNS device-info query, which names the host. The reply
/// goes through the same port-keyed decoder.
///
/// Empty when nothing answered or nothing could be read from what did.
pub async fn probe_udp_with(addr: std::net::SocketAddr, payload: &[u8]) -> Vec<String> {
    probe_udp_with_via(addr, payload, &Egress::KERNEL).await
}

/// [`probe_udp_with`], with the datagram leaving by `egress`.
pub(crate) async fn probe_udp_with_via(
    addr: std::net::SocketAddr,
    payload: &[u8],
    egress: &Egress,
) -> Vec<String> {
    match probe_udp_raw_via(addr, payload, egress).await {
        Some(reply) => extract::from_datagram(addr.port(), &reply),
        None => Vec::new(),
    }
}

/// The same exchange, handing back the datagram rather than what this engine
/// reads out of it.
///
/// For answers the port's decoder does not handle, such as an mDNS PTR record
/// naming the responder.
///
/// [`None`] when nothing answered.
pub async fn probe_udp_raw(addr: std::net::SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    probe_udp_raw_via(addr, payload, &Egress::KERNEL).await
}

/// [`probe_udp_raw`], with the datagram leaving by `egress`.
pub(crate) async fn probe_udp_raw_via(
    addr: std::net::SocketAddr,
    payload: &[u8],
    egress: &Egress,
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
        Datagram::Silent | Datagram::Starved | Datagram::Unasked => None,
    }
}

/// Sends `payload` to `addr` from a socket of its own and reads the one
/// datagram that comes back, telling a port that said nothing from a process
/// that had no socket to ask it with, after waiting `patience` for one. The
/// wait for the reply allows for `path`.
///
/// The datagram waits for its pacing slot before asking for a socket; the reply
/// wait starts once it has left. One stopped before its turn is
/// [`Datagram::Unasked`].
async fn exchange_datagram(
    addr: std::net::SocketAddr,
    payload: &[u8],
    egress: &Egress,
    patience: Duration,
    path: PathAllowance,
) -> Datagram<Vec<u8>> {
    let Ok(slot) = egress.slot(addr.ip()).await else {
        return Datagram::Unasked;
    };
    let socket = match egress.udp(&slot, addr.ip(), patience).await {
        Ok(socket) => socket,
        Err(e) if descriptors::exhausted(&e) => {
            slot.refund();
            return Datagram::Starved;
        }
        Err(_) => {
            slot.refund();
            return Datagram::Silent;
        }
    };
    let sent = match socket.connect(addr).await {
        Ok(()) => socket.send(payload).await.map(drop),
        Err(e) => Err(e),
    };
    slot.settle(&sent);
    if sent.is_err() {
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
/// A ladder of questions. The port number sets only the *order* of the rungs: a
/// port numbered for TLS is offered a handshake first, anything else is spoken
/// to in the clear first, and a rung that draws nothing falls through to the
/// next. Services move between port numbers, so the number never removes a
/// rung.
///
/// When a handshake succeeds, collection re-runs inside the tunnel, and the
/// returned [`Tunnel`] records it.
///
/// Every connection after the first leaves by `egress`, as the first did.
async fn gather(
    mut stream: TcpStream,
    port: u16,
    detection: ServiceDetection,
    egress: &Egress,
    name: Option<Arc<str>>,
) -> (ResponseSet, Option<Tunnel>) {
    // Identify nothing. Only the unprivileged path reaches this, since its
    // connection established the port's state; the privileged path stops in
    // `service::detect`.
    if !detection.connects() {
        return (ResponseSet::default(), None);
    }

    // Listen only. Everything below sends bytes, a ClientHello included.
    if !detection.sends() {
        let banner = read_response(&mut stream, BANNER_READ_TIMEOUT).await;
        return (
            ResponseSet::from_banners(banner.into_iter().collect()),
            None,
        );
    }

    // Without the peer's address, only the socket in hand can be asked, in the
    // clear.
    let Ok(socket) = stream.peer_addr() else {
        return (plaintext(stream, port, None, egress).await, None);
    };
    let peer = Authority::new(socket).named(name);

    // The first rung uses the caller's connection; later rungs dial their own.
    let mut opened = Some(stream);
    // Both handshakes refused in TLS, on a port numbered for it, held while the
    // port is asked in the clear; see `refused_every_handshake`.
    let mut refused: Option<ResponseSet> = None;
    for rung in Rung::ladder(port) {
        let stream = match opened.take() {
            Some(stream) => stream,
            None => match redial(socket, egress).await {
                Some(fresh) => fresh,
                None => return (refused.unwrap_or_default(), None),
            },
        };

        let (responses, tunnel) = rung.ask(stream, port, &peer, detection, egress).await;
        if let Some(held) = refused.take() {
            return match held.tls {
                Some(tls) if refused_in_the_clear(&responses) => {
                    (responses.with_tls(tls), Some(Tunnel::Tls))
                }
                tls => (ResponseSet { tls, ..held }, None),
            };
        }
        if responses.is_empty() {
            continue;
        }
        if matches!(rung, Rung::LegacyTls) && refused_every_handshake(&responses) {
            refused = Some(responses);
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

    (refused.unwrap_or_default(), None)
}

/// Whether what the legacy handshake drew is a refusal in TLS and nothing
/// else, on a port whose modern handshake had already failed.
///
/// A server keeping certificates by name refuses a client naming no site, as
/// happens when the target was an address. The port speaks TLS, so it is asked
/// in the clear once: a web server answers with a plaintext `400`, and the port
/// is filed as that web server through TLS (as in `asked_through_tls`).
/// Anything else leaves it filed as speaking TLS.
fn refused_every_handshake(responses: &ResponseSet) -> bool {
    responses.banners.is_empty()
        && responses
            .tls
            .as_ref()
            .is_some_and(|tls| tls.version == Some(tls::REFUSED))
}

/// Whether what a port answered in the clear is an HTTP server refusing the
/// request, which is how a web server listening for TLS answers one that
/// arrived without it.
///
/// nginx, Apache, Go and Caddy answer a plaintext request on a TLS port with a
/// plaintext `400`, each worded differently, so only the status is read. Little
/// else refuses a well-formed `GET` as a bad request.
fn refused_in_the_clear(responses: &ResponseSet) -> bool {
    responses.banners.first().is_some_and(|reply| {
        reply.starts_with("HTTP/") && reply.split_whitespace().nth(1) == Some("400")
    })
}

/// What a port that refused a request in the clear says through TLS, with
/// `clear`, what it said in the clear, where it says nothing.
///
/// For a port whose number does not say TLS. A completed handshake is the
/// answer, identified as on any TLS port. If the modern handshake is refused,
/// the legacy one is tried; a TLS answer there means the server keeps
/// certificates by name, and its plaintext refusal is filed as served through
/// TLS. A port answering neither keeps its answer in the clear.
async fn asked_through_tls(
    clear: ResponseSet,
    port: u16,
    peer: &Authority,
    egress: &Egress,
) -> (ResponseSet, Option<Tunnel>) {
    let Some(stream) = redial(peer.socket(), egress).await else {
        return (clear, None);
    };
    let handshake = tls::speculative_handshake(stream, peer.server_name()).await;
    let (through, tunnel) = tunneled(handshake, port, peer, egress).await;
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
/// Bounded by [`CONNECT_RETRY_TIMEOUT`] plus the path; leaves by `egress`.
///
/// Takes no descriptor share of its own: the pass holds one for the whole
/// identification, whose connections are sequential. A full table is waited
/// out before the timeout starts; see [`dial_again`].
async fn redial(socket: SocketAddr, egress: &Egress) -> Option<TcpStream> {
    dial_again(socket, egress, Some(on_path(CONNECT_RETRY_TIMEOUT)))
        .await
        .ok()
}

/// A further connection to the port being identified, leaving by `egress`
/// and given `limit` to connect where one is set.
///
/// Every connection after the first comes through here, so socket starvation is
/// never read as a silent port. A refused socket is requested again for up to
/// [`patience`](descriptors::patience), each attempt on its own clock. If the
/// table stays full, or the caller's clock runs out meanwhile, the
/// identification is marked starved.
///
/// The connection first waits for its pacing slot, outside `limit` and the
/// patience; the identification's clocks pause meanwhile (see
/// [`fingerprint_tcp_via`]). If the scan stops or the host's budget runs out
/// first, it returns an error.
async fn dial_again(
    addr: SocketAddr,
    egress: &Egress,
    limit: Option<Duration>,
) -> std::io::Result<TcpStream> {
    // The slot first, outside `limit` and the patience.
    let slot = egress.slot(addr.ip()).await?;
    let refused = Refused::default();
    let (refused, slot_held) = (&refused, &slot);
    let connected = descriptors::patiently(descriptors::patience(), || async move {
        let connecting = egress.connect_shaped(slot_held, addr, Shaping::default());
        let attempt = match limit {
            Some(limit) => timeout(limit, connecting)
                .await
                .unwrap_or_else(|_elapsed| Err(std::io::ErrorKind::TimedOut.into())),
            None => connecting.await,
        };
        refused.saw(&attempt);
        attempt
    })
    .await;
    slot.settle(&connected);
    connected
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
/// Each rung is asked on its own connection; drawing nothing falls through to
/// the next.
#[derive(Clone, Copy)]
enum Rung {
    /// Handshake and collect through the tunnel, patiently, on a port where TLS
    /// is what the number says to expect.
    Tls,
    /// The same on a port where TLS is a guess, with a tighter budget. See
    /// [`tls::SPECULATIVE_TLS_TIMEOUT`].
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
    /// The only rung that reaches a silent service moved off its registered port.
    LastResort,
}

impl Rung {
    /// The rungs for `port`, in the order they are worth asking in.
    ///
    /// The port number's only influence on collection. An implicit-TLS number
    /// puts the handshake first, sparing an HTTPS port a banner timeout.
    ///
    /// `LegacyTls` sits above `Plaintext` because a 1.0-only server answers a
    /// plaintext probe with an alert record, which the clear-text rung would
    /// report as a banner.
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
    /// [`LastResort`](Self::LastResort) may dial again, since each of its
    /// unrelated protocols leaves the socket unusable for the next.
    async fn ask(
        self,
        stream: TcpStream,
        port: u16,
        peer: &Authority,
        detection: ServiceDetection,
        egress: &Egress,
    ) -> (ResponseSet, Option<Tunnel>) {
        match self {
            Rung::Tls => {
                let handshake = tls::handshake(stream, peer.server_name()).await;
                tunneled(handshake, port, peer, egress).await
            }
            Rung::SpeculativeTls => {
                let handshake = tls::speculative_handshake(stream, peer.server_name()).await;
                tunneled(handshake, port, peer, egress).await
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
/// One probe per connection: most protocols hang up on a question they do not
/// recognise (PostgreSQL reads `PING` as a four-byte length; Redis closes on the
/// second line of an HTTP request).
///
/// Every probe is asked and the replies accumulate, since an error reply to one
/// protocol's question only says the port does not speak it.
///
/// [`ServiceDetection::probe_intensity`] selects the probes, and the path
/// limits how many; see [`guesses_worth_the_path`].
async fn last_resort(
    first: TcpStream,
    peer: &Authority,
    port: u16,
    detection: ServiceDetection,
    egress: &Egress,
) -> ResponseSet {
    let mut probes =
        SignatureDb::global().universal_tcp_probe_payloads(port, detection.probe_intensity());
    probes.truncate(guesses_worth_the_path(probes.len(), detection));

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

/// How many of `guesses` other services' questions a port that has answered
/// none of its own is asked, likeliest first, at `detection`.
///
/// All of them on a path under a third of a second. On a slower path the
/// default level asks only the likeliest, since each guess is a connection and
/// a read that both add the path delay (near nine seconds a guess across a
/// two-second path). The thorough level asks every guess regardless.
fn guesses_worth_the_path(guesses: usize, detection: ServiceDetection) -> usize {
    let slow = on_path(PROBE_READ_TIMEOUT) > PROBE_READ_TIMEOUT * 2;
    match detection {
        ServiceDetection::Thorough => guesses,
        _ if slow => guesses.min(1),
        _ => guesses,
    }
}

/// Everything a port will say in the clear.
///
/// A claimed port is listened to and then asked its service's questions, so a
/// greeting is heard first. An unclaimed port is asked generically; see
/// [`ask_generically`].
///
/// A port several services claim is asked each one's questions on a separate
/// connection, the likeliest first on the connection already open; see
/// [`SignatureDb::tcp_probe_conversations`]. Each connection is closed before
/// the next is dialled. Without the peer's address everything goes down the
/// one connection.
///
/// A port services only share is asked the generic question first: 3000 or
/// 5000 most often holds a development web server.
///
/// A reply that is a TLS record counts as nothing here; a TLS rung reads it.
async fn plaintext(
    mut stream: TcpStream,
    port: u16,
    peer: Option<&Authority>,
    egress: &Egress,
) -> ResponseSet {
    let db = SignatureDb::global();
    let mut conversations = db.tcp_probe_conversations(port).peekable();
    let named = db.service_name(port).is_some();

    // The port's own service on the connection already open, or, where no
    // service names the port, the generic question, which follows its own
    // redirect.
    let (mut responses, mut held) = match conversations.next_if(|_| named) {
        Some(first) => {
            let listen = !db.asked_first(port);
            let responses = collect_responses(&mut stream, port, first, peer, listen).await;
            // Sound on decoded text: every byte `looks_like_tls` checks is under
            // 0x80 and comes first, so `extract::reply_text` keeps it in place.
            if responses
                .banners
                .first()
                .is_some_and(|first| looks_like_tls(first.as_bytes()))
            {
                return ResponseSet::default();
            }
            (responses, Some(stream))
        }
        None => match ask_generically(stream, peer, egress).await {
            GenericReply::Spoke(banners) => (ResponseSet::from_banners(banners), None),
            GenericReply::Silent => (ResponseSet::default(), None),
            GenericReply::Tls => return ResponseSet::default(),
        },
    };

    // Every other service's questions, each on a connection of its own.
    let mut theirs = ResponseSet::default();
    for probes in conversations {
        if let Some(peer) = peer {
            drop(held.take());
            held = redial(peer.socket(), egress).await;
        }
        let Some(stream) = held.as_mut() else {
            break;
        };
        theirs.extend(ask_in_turn(stream, port, probes, peer).await);
    }
    drop(held);

    // Follow a redirect in the services' replies once the last connection is
    // closed. The generic question already followed its own.
    if named {
        responses.extend(theirs);
        let banners = std::mem::take(&mut responses.banners);
        responses.banners = with_redirect_followed(banners, peer, egress).await;
    } else {
        theirs.banners = with_redirect_followed(theirs.banners, peer, egress).await;
        responses.extend(theirs);
    }
    responses
}

/// What a generic probe drew out of a port nothing in the database claims.
enum GenericReply {
    /// It answered readably.
    Spoke(Vec<String>),
    /// It answered in TLS, most likely an alert.
    Tls,
    /// Nothing came back at all.
    Silent,
}

/// Asks an unclaimed port the one question worth asking of any open port, and
/// reads whatever comes back.
///
/// The request is written before anything is read. A greeting sent on connect
/// still arrives first, so no banner is lost, and the banner timeout is saved:
/// listening, then guessing TLS, cost two seconds per unidentified port (seven
/// of eleven open ports on one home server). An HTTP request answers in a round
/// trip and names most of them.
///
/// The stream is closed before a redirect is followed on a new connection, so
/// one socket is held at a time.
async fn ask_generically(
    mut stream: TcpStream,
    peer: Option<&Authority>,
    egress: &Egress,
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

    let first = extract::reply_text(&bytes);

    // Many self-hosted applications serve only a redirect at the root. See
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
/// A self-hosted application's root is often only a redirect: Jellyfin's is a
/// 302 to `/web/index.html`, Sonarr's to its login page. The first response
/// shows only the framework (`Kestrel`).
///
/// Only a redirect back to the port being identified is followed, so no traffic
/// goes to a third party. [`Authority::path_of`] decides which URLs lead back.
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

    // Refuse control characters: a lone CR survives `lines()`, and some servers
    // treat it as a line terminator, which would splice a remote value into the
    // request line.
    if location.is_empty() || location.chars().any(char::is_control) {
        return None;
    }

    match location {
        // An absolute URL (Grafana, Portainer and Prometheus send one), followed
        // only if it names `peer`.
        url if url.contains("://") || url.starts_with("//") => peer?.path_of(url),
        // Same host by construction: a path is relative to where it was served.
        path if path.starts_with('/') => Some(path.to_string()),
        // A relative reference (RFC 7231 §7.1.2), such as Jellyfin's `web/`.
        // Every caller requests the root, so it resolves against `/`.
        relative => Some(format!("/{relative}")),
    }
}

/// Fetches `path` from `peer` over a fresh connection and returns whatever
/// came back.
///
/// A new connection, since the redirect's response may have closed the first.
/// Leaves by `egress`, through TLS where the port speaks it, naming the same
/// site.
async fn follow_redirect(peer: &Authority, path: &str, egress: &Egress) -> Option<String> {
    let stream = dial_again(peer.socket(), egress, Some(on_path(CONNECT_RETRY_TIMEOUT)))
        .await
        .ok()?;
    match peer.is_tls() {
        true => {
            let (mut tunnel, _) = tls::handshake(stream, peer.server_name()).await?;
            ask_for(&mut tunnel, peer, path).await
        }
        false => {
            let mut stream = stream;
            ask_for(&mut stream, peer, path).await
        }
    }
}

/// Asks `stream` for `path` on `peer` and reads the document that comes back.
async fn ask_for<S>(stream: &mut S, peer: &Authority, path: &str) -> Option<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // `Host` names the port being identified.
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\n\
         Accept: */*\r\nConnection: close\r\n\r\n",
        peer.header()
    );
    stream.write_all(request.as_bytes()).await.ok()?;

    read_document(stream, PROBE_READ_TIMEOUT).await
}

/// `banners` with the page the first HTTP reply among them redirects to
/// added, where the redirect leads back to `peer`; see [`redirect_path`].
///
/// Used on claimed, unclaimed and TLS ports alike. Close the connection that
/// drew the redirect first, so one socket is held at a time.
async fn with_redirect_followed(
    mut banners: Vec<String>,
    peer: Option<&Authority>,
    egress: &Egress,
) -> Vec<String> {
    let Some(peer) = peer else {
        return banners;
    };
    let path = banners
        .iter()
        .find(|reply| reply.starts_with("HTTP/"))
        .and_then(|reply| redirect_path(reply, Some(peer)));
    if let Some(path) = path
        && let Some(page) = follow_redirect(peer, &path, egress).await
    {
        banners.push(page);
    }
    banners
}

/// Whether `bytes` open a TLS record.
///
/// A content type in the range TLS defines, then a major version of 3 and a
/// minor version no higher than TLS 1.3 uses on the wire. In practice this
/// catches the alert a TLS server sends for a plaintext `GET`.
fn looks_like_tls(bytes: &[u8]) -> bool {
    matches!(bytes, [0x14..=0x17, 0x03, 0x00..=0x04, ..])
}

/// What a port numbered for TLS turns out to speak, where a modern handshake
/// would not complete.
///
/// rustls implements only TLS 1.2 and 1.3, so a legacy-only server fails the
/// modern rung.
///
/// The result carries no certificate and no tunnel, only the version.
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
    egress: &Egress,
) -> (ResponseSet, Option<Tunnel>) {
    let Some((mut tunnel, info)) = handshake else {
        return (ResponseSet::default(), None);
    };
    // Inside the tunnel: the port's own probes, or the generic question without
    // listening first, as in the clear (see `ask_generically`).
    let db = SignatureDb::global();
    let peer = peer.through_tls();
    let mut conversations = db.tcp_probe_conversations(port);
    let mut drawn = match conversations.next() {
        Some(own) => {
            let listen = !db.asked_first(port);
            collect_responses(&mut tunnel, port, own, Some(&peer), listen).await
        }
        None => {
            let generic = db.generic_tcp_probe_payloads();
            collect_responses(&mut tunnel, port, generic, Some(&peer), false).await
        }
    };

    // Every other service's questions, each through its own handshake, as each
    // gets its own connection in the clear; see `Conversations`.
    let mut held = Some(tunnel);
    for probes in conversations {
        drop(held.take());
        held = retunneled(&peer, egress).await;
        let Some(tunnel) = held.as_mut() else {
            break;
        };
        drawn.extend(ask_in_turn(tunnel, port, probes, Some(&peer)).await);
    }
    drop(held);
    drawn.banners = with_redirect_followed(drawn.banners, Some(&peer), egress).await;
    (drawn.with_tls(info), Some(Tunnel::Tls))
}

/// A fresh tunnel to a port whose handshake has already completed once, or
/// `None` where it can no longer be dialled or no longer completes one.
async fn retunneled(peer: &Authority, egress: &Egress) -> Option<tls::TlsTunnel> {
    let stream = redial(peer.socket(), egress).await?;
    let (tunnel, _) = tls::handshake(stream, peer.server_name()).await?;
    Some(tunnel)
}

/// Grabs a first-speak banner where `listen` says one may come, then sends
/// `probes` over `stream`, returning every non-empty response. Generic over the
/// transport, so it runs identically on a raw socket or inside a TLS tunnel.
///
/// Skipping the listen loses no greeting, which arrives as the first reply;
/// listening only avoids interrupting a service before it speaks. See
/// [`SignatureDb::asked_first`].
///
/// The caller chooses the probes (the port's own, or the generic set). Each is
/// addressed to `peer` where there is one; see [`Authority::addressed`].
async fn collect_responses<S>(
    stream: &mut S,
    port: u16,
    probes: &[Vec<u8>],
    peer: Option<&Authority>,
    listen: bool,
) -> ResponseSet
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut drawn = ResponseSet::default();

    if listen && let Some(banner) = read_response(stream, BANNER_READ_TIMEOUT).await {
        drawn.banners.push(banner);
    }

    drawn.extend(ask_in_turn(stream, port, probes, peer).await);
    drawn
}

/// Sends `probes` over `stream` one after another, each addressed to `peer`
/// where there is one, and returns what each drew: the fields of a reply this
/// engine reads as structure, then its text, and apart from both the names it
/// gave for the machine.
///
/// Nothing is listened for first; a greeting arrives ahead of the reply (see
/// [`ask_generically`]).
async fn ask_in_turn<S>(
    stream: &mut S,
    port: u16,
    probes: &[Vec<u8>],
    peer: Option<&Authority>,
) -> ResponseSet
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut drawn = ResponseSet::default();
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
        // Structured fields before the whole text; see `extract::from_stream`.
        drawn.banners.extend(extract::from_stream(port, &bytes));
        drawn.banners.push(extract::reply_text(&bytes));
        drawn.names.extend(extract::names_from_stream(port, &bytes));
    }

    drawn
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
    /// A reply came only after more than half the wait it was given, net of
    /// the path; see [`Fingerprinted::answered_late`].
    answered_late: AtomicBool,
    /// How long the waits that ran out were given, together.
    waited_in_vain: std::sync::Mutex<Duration>,
}

impl Tally {
    /// Notes a wait for the port to say something that ran out after `wait`.
    fn ran_out(&self, wait: Duration) {
        self.ran_out_waiting.store(true, Ordering::Relaxed);
        *self
            .waited_in_vain
            .lock()
            .unwrap_or_else(|held| held.into_inner()) += wait;
    }
}

/// Reports to the identification whose scope this runs in. Outside a scope (an
/// analyzer driven directly) nothing is reported.
fn tell(what: impl FnOnce(&Tally)) {
    let _ = DIALLING.try_with(|dialling| what(&dialling.tally));
}

/// `wait`, which a path that costs nothing needs, on the path to the port
/// being identified.
///
/// Every wait on the port is set for the service's own time; the path's
/// measured round trip is added here (see [`PathAllowance`]). Outside an
/// identification's scope the wait is unchanged.
fn on_path(wait: Duration) -> Duration {
    DIALLING
        .try_with(|dialling| dialling.path.over(wait))
        .unwrap_or(wait)
}

/// How much of `elapsed`, the time a reply from the port being identified
/// took, was the service's rather than the path's; see
/// [`PathAllowance::service_time`]. All of it outside an identification's
/// scope.
fn service_time(elapsed: Duration) -> Duration {
    DIALLING
        .try_with(|dialling| dialling.path.service_time(elapsed))
        .unwrap_or(elapsed)
}

/// [`on_path`] for a budget spanning `waits` waits on the port one after
/// another, each allowing for the path once.
fn on_path_each(budget: Duration, waits: u32) -> Duration {
    DIALLING
        .try_with(|dialling| dialling.path.over_each(budget, waits))
        .unwrap_or(budget)
}

tokio::task_local! {
    /// How the port being fingerprinted is dialled, by its later questions
    /// and by its analyzers.
    ///
    /// A task-local because analyzers get only the public [`PortContext`], which
    /// cannot carry it. Collection runs inline on the task that sets it; the
    /// one spawned task is the CPU phase, which dials nothing.
    static DIALLING: Dialling;
}

/// Connects to `addr` for an analyzer, the way the port it is examining was
/// reached.
///
/// Outside a fingerprint's collection (an analyzer driven through
/// [`analyze_with`]) the routing table decides.
pub(crate) async fn analyzer_connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let egress = DIALLING
        .try_with(|dialling| dialling.egress.clone())
        .unwrap_or(Egress::KERNEL);
    dial_again(addr, &egress, None).await
}

/// The analyzer registry, the only place the set is enumerated. The analyzers
/// are stateless zero-sized values, so both phases share a `'static` slice.
static ANALYZERS: &[&dyn Analyzer] = &[
    &BannerRegexAnalyzer,
    &FaviconAnalyzer,
    &HttpHeadersAnalyzer,
    &JarmAnalyzer,
    &ldap::LdapAnalyzer,
    &smb::SmbAnalyzer,
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
/// Evidence is ranked by [`ServiceVerdict::resolve`]; this order only settles a
/// full tie.
#[must_use]
pub fn analyzers() -> &'static [&'static dyn Analyzer] {
    ANALYZERS
}

/// Runs the registered analyzers over `responses` and resolves their evidence
/// into a verdict, honouring the two-phase contract: each interested analyzer's
/// [`collect`](Analyzer::collect) runs here on the reactor (I/O), then all the
/// [`analyze`](Analyzer::analyze) work is handed to the blocking pool (CPU).
/// `tunnel` labels evidence drawn from decrypted data. Returns `None` if
/// analysis produced nothing or the blocking task failed to join.
async fn analyze(
    port: u16,
    protocol: Protocol,
    addr: Option<std::net::SocketAddr>,
    responses: ResponseSet,
    tunnel: Option<Tunnel>,
    detection: ServiceDetection,
    name: Option<Arc<str>>,
) -> Option<ServiceVerdict> {
    // In the context so an analyzer can gate on it before seeing responses.
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
/// The slice is `'static` because the CPU phase runs on the blocking pool.
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

    // Phase 2, CPU off the reactor: evidence from the shared responses and each
    // analyzer's frames, then resolve.
    off_the_reactor(move || {
        let mut evidence = Vec::new();
        for (analyzer, (interested, collected)) in analyzers.iter().zip(&collected) {
            if *interested {
                evidence.extend(analyzer.analyze(&ctx, &responses, collected));
            }
        }

        (!evidence.is_empty()).then(|| ServiceVerdict::resolve(evidence))
    })
    .await
    .flatten()
}

/// How many threads the CPU phase of [`analyze_with`] runs on.
///
/// One long-lived thread, for memory. A compiled regex keeps a search cache
/// for the first thread to use it and for each of up to eight groups of other
/// threads, for its whole life, which for the built-in signatures is the
/// process's. Over 5,000 identifications of ten banners, tokio's blocking pool
/// took the process from 57 MB to 200 MB; one thread, from 53 MB to 60.
///
/// Throughput barely suffers: matching is tens of microseconds per banner, and
/// compilation happens once, on every core ([`SignatureDb::warm`]). The same
/// 5,000 took 185 ms on one thread against 140 on the pool.
const ANALYSIS_THREADS: usize = 1;

/// The identification threads, see [`ANALYSIS_THREADS`], started on first
/// use, or `None` where they could not be.
fn analysis_pool() -> Option<&'static rayon::ThreadPool> {
    static POOL: std::sync::OnceLock<Option<rayon::ThreadPool>> = std::sync::OnceLock::new();

    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(ANALYSIS_THREADS)
            .thread_name(|index| format!("zond-identify-{index}"))
            .build()
            .ok()
    })
    .as_ref()
}

/// Runs `work` on the identification threads, see [`ANALYSIS_THREADS`], and
/// hands back what it returns, or `None` if it panicked.
///
/// Falls back to tokio's blocking pool if the threads cannot be started, so
/// identification never fails for want of them; it only costs more memory.
async fn off_the_reactor<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let Some(pool) = analysis_pool() else {
        return tokio::task::spawn_blocking(work).await.ok();
    };

    let (sender, receiver) = tokio::sync::oneshot::channel();
    pool.spawn(move || {
        // A panic on a rayon thread would abort the process.
        let done = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
        let _ = sender.send(done.ok());
    });
    receiver.await.ok().flatten()
}

/// Runs `match_work`, a match against the signature corpus, on the
/// identification threads, blocking the caller until it is done, and hands
/// back what it returns.
///
/// For a caller matching the corpus directly, so each signature keeps one search
/// cache; see [`ANALYSIS_THREADS`].
///
/// Runs in place when already on those threads, or when they could not be
/// started. A panic in `match_work` reaches the caller.
pub(crate) fn on_the_matching_thread<T: Send>(match_work: impl FnOnce() -> T + Send) -> T {
    match analysis_pool() {
        Some(pool) => pool.install(match_work),
        None => match_work(),
    }
}

/// Reads one bounded chunk from `stream`, giving up after `wait`. Returns `None`
/// on timeout, error, or a clean empty read.
async fn read_response<S>(stream: &mut S, wait: Duration) -> Option<String>
where
    S: AsyncRead + Unpin,
{
    read_bytes(stream, wait, Duration::ZERO)
        .await
        .map(|bytes| extract::reply_text(&bytes))
}

/// [`read_response`], but reading on until the port goes quiet.
///
/// For a reply that may be a document: an HTTP server writing headers and body
/// separately would otherwise lose the `<title>`.
///
/// Not for banner grabs, which would pay [`CONTINUATION_GRACE`] on every
/// greeting.
async fn read_document<S>(stream: &mut S, wait: Duration) -> Option<String>
where
    S: AsyncRead + Unpin,
{
    read_bytes(stream, wait, CONTINUATION_GRACE)
        .await
        .map(|bytes| extract::reply_text(&bytes))
}

/// Reads up to [`MAX_RESPONSE_BYTES`] of whatever the port sends, waiting `wait`
/// for the first byte, allowing for the path (see [`on_path`]), and `grace` for
/// each read after it.
///
/// Reports a late or missing first byte to the identification; see
/// [`Fingerprinted::answered_late`] and [`Fingerprinted::ran_out_waiting`].
///
/// A `grace` of zero reads once (a banner); non-zero reads until the port goes
/// quiet (a document). See [`read_response`] and [`read_document`].
///
/// Returns bytes so a caller can tell a banner from a TLS alert.
///
/// # Bounds
///
/// `wait` bounds the first byte, `grace` each gap between reads, and
/// [`MAX_CONTINUATION`] the whole remainder after the first byte, so a peer
/// trickling inside `grace` cannot hold the read indefinitely.
async fn read_bytes<S>(stream: &mut S, wait: Duration, grace: Duration) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    // Lateness is judged on service time, net of the path.
    let late = wait / 2;
    let wait = on_path(wait);
    let asked = tokio::time::Instant::now();
    let mut collected: Vec<u8> = Vec::new();
    let mut buffer = [0u8; MAX_RESPONSE_BYTES];
    let mut budget = wait;
    // Set on the first byte, so a slow greeting is not charged twice.
    let mut deadline = None;

    while collected.len() < MAX_RESPONSE_BYTES {
        let first = collected.is_empty();
        match timeout(budget, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                if first && service_time(asked.elapsed()) > late {
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
            // Nothing within the wait; reported to the identification.
            Err(_elapsed) if first => {
                tell(|tally| tally.ran_out(wait));
                break;
            }
            // A close, an error, or the port going quiet.
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
    use crate::testing::loopback::accept_from_this_process;

    /// One SNMP reply is one witness to what a host runs.
    ///
    /// The maker a rule files with the hardware must not be counted again as the
    /// hardware vendor; counted twice, this MikroTik switch's description would
    /// pass the 85 at which the active OS probe is skipped. The host is behind a
    /// gateway, so no hardware address backs the vendor.
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
    /// Nothing fingerprints SCTP services, since the scan completes no
    /// association.
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

    /// The seeded label is marked as a guess.
    #[test]
    fn a_seeded_label_is_never_mistaken_for_an_identification() {
        let seeded = baseline_service(22).expect("ssh is registered");
        assert_eq!(seeded.name(), "ssh");
        assert!(
            seeded.is_inferred(),
            "nothing asked port 22 what it was running"
        );
    }
    /// A redirect at the root is followed.
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

    /// A relative reference (RFC 7231 §7.1.2): Jellyfin answers `GET /` with
    /// `Location: web/`.
    #[test]
    fn a_relative_location_resolves_against_the_root_it_was_served_from() {
        let jellyfin = "HTTP/1.1 302 Found\r\nLocation: web/\r\nServer: Kestrel\r\n\r\n";
        assert_eq!(
            redirect_path(jellyfin, Some(&peer())).as_deref(),
            Some("/web/")
        );
    }

    /// Grafana, Portainer and Prometheus answer `GET /` with an absolute
    /// `Location` naming themselves.
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

    /// Same address, different port: declined.
    #[test]
    fn an_absolute_location_on_another_port_is_declined() {
        let elsewhere = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9999/x\r\n\r\n";
        assert_eq!(redirect_path(elsewhere, Some(&peer())), None);
    }

    /// A different scheme is declined.
    #[test]
    fn an_upgrade_to_https_is_declined_rather_than_guessed() {
        let upgrade = "HTTP/1.1 301 Moved\r\nLocation: https://127.0.0.1:8096/\r\n\r\n";
        assert_eq!(redirect_path(upgrade, Some(&peer())), None);
    }

    /// With no address to compare against, an absolute URL is not followed.
    #[test]
    fn an_absolute_location_is_declined_when_there_is_no_peer_to_check() {
        let named = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:8096/login\r\n\r\n";
        assert_eq!(redirect_path(named, None), None);
    }

    /// A scheme-relative reference names a host.
    #[test]
    fn a_scheme_relative_location_is_declined_like_any_other_host() {
        let elsewhere = "HTTP/1.1 302 Found\r\nLocation: //cdn.example/web/\r\n\r\n";
        assert_eq!(redirect_path(elsewhere, Some(&peer())), None);

        // The same spelling, naming the host in hand, is followed.
        let here = "HTTP/1.1 302 Found\r\nLocation: //127.0.0.1:8096/web/\r\n\r\n";
        assert_eq!(redirect_path(here, Some(&peer())).as_deref(), Some("/web/"));
    }

    /// A redirect to a third party is not followed.
    #[test]
    fn a_redirect_off_the_host_is_declined() {
        for location in [
            "https://example.com/login",
            "http://somewhere.else/",
            // A scheme change.
            "https://127.0.0.1/web/",
            // A lone CR survives `lines()`; some servers treat it as a line end.
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

    /// Only a redirect is followed.
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

    /// A bracketed IPv6 redirect target is followed like an IPv4 one.
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

    /// The `Host` for an IPv6 address is bracketed; otherwise its last group
    /// reads as a port.
    #[tokio::test]
    async fn a_redirect_on_ipv6_is_asked_for_by_a_bracketed_host() {
        let Ok(listener) = tokio::net::TcpListener::bind("[::1]:0").await else {
            eprintln!("SKIP: no IPv6 loopback on this machine");
            return;
        };
        let addr = listener.local_addr().expect("a local address");
        let server = tokio::spawn(async move {
            let mut first = accept_from_this_process(&listener)
                .await
                .expect("the first connection");
            let mut buffer = [0u8; 1024];
            let _ = first.read(&mut buffer).await;
            let _ = first
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n")
                .await;
            drop(first);
            let mut second = accept_from_this_process(&listener)
                .await
                .expect("the redirect followed");
            let read = second.read(&mut buffer).await.unwrap_or(0);
            let _ = second
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
            String::from_utf8_lossy(&buffer[..read]).into_owned()
        });

        let stream = TcpStream::connect(addr).await.expect("connects");
        let _ = plaintext(stream, 51987, Some(&Authority::new(addr)), &Egress::KERNEL).await;
        let request = server.await.expect("the listener finishes");

        let host = format!("\r\nHost: [::1]:{}\r\n", addr.port());
        assert!(
            request.contains(&host),
            "the redirect was asked for without `{}`: {request:?}",
            host.trim()
        );
    }

    /// A TLS record is not a banner.
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

    /// Records the thread its CPU phase ran on, and panics on port 0.
    struct ThreadWitness;

    static WITNESSED: std::sync::Mutex<Vec<std::thread::ThreadId>> =
        std::sync::Mutex::new(Vec::new());

    #[async_trait::async_trait]
    impl Analyzer for ThreadWitness {
        fn id(&self) -> SourceId {
            SourceId::BannerRegex
        }

        fn interested(&self, _ctx: &PortContext) -> bool {
            true
        }

        fn analyze(&self, ctx: &PortContext, _: &ResponseSet, _: &Collected) -> Vec<Evidence> {
            assert!(ctx.port != 0, "the witness was asked about port 0");
            // Long enough that concurrent analyses overlap.
            std::thread::sleep(Duration::from_millis(20));
            WITNESSED
                .lock()
                .expect("the witness list")
                .push(std::thread::current().id());
            vec![
                Evidence::new(
                    SourceId::BannerRegex,
                    crate::model::confidence::Confidence::Weak,
                )
                .with_service("witnessed"),
            ]
        }
    }

    static WITNESS: [&dyn Analyzer; 1] = [&ThreadWitness];

    /// **Every identification's CPU phase runs on the one thread kept for it,
    /// however many run at once, and a panic there loses one verdict and not
    /// the process.**
    ///
    /// See [`ANALYSIS_THREADS`].
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn identification_runs_on_one_kept_thread_and_survives_a_panic() {
        let runs: Vec<_> = (1..=12u16)
            .map(|port| {
                tokio::spawn(analyze_with(
                    PortContext::new(port, Protocol::Tcp),
                    ResponseSet::default(),
                    &WITNESS,
                ))
            })
            .collect();
        for run in runs {
            assert!(run.await.expect("joins").is_some(), "every run is named");
        }

        let threads: std::collections::BTreeSet<String> = WITNESSED
            .lock()
            .expect("the witness list")
            .iter()
            .map(|id| format!("{id:?}"))
            .collect();
        assert_eq!(threads.len(), 1, "identification ran on {threads:?}");

        let panicked = analyze_with(
            PortContext::new(0, Protocol::Tcp),
            ResponseSet::default(),
            &WITNESS,
        )
        .await;
        assert!(panicked.is_none(), "a panicking analyzer names nothing");
        let after = analyze_with(
            PortContext::new(1, Protocol::Tcp),
            ResponseSet::default(),
            &WITNESS,
        )
        .await;
        assert!(after.is_some(), "and identification carries on after it");
    }

    /// Direct corpus matching from any thread runs on the identification thread.
    #[test]
    fn a_direct_match_against_the_corpus_runs_on_the_identification_thread() {
        let threads: std::collections::BTreeSet<Option<String>> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    on_the_matching_thread(|| std::thread::current().name().map(str::to_owned))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().expect("joins"))
            .collect();
        assert_eq!(
            threads,
            [Some("zond-identify-0".to_string())].into(),
            "matched on {threads:?}"
        );
    }

    #[tokio::test]
    async fn analyze_runs_both_phases_and_resolves() {
        // The real orchestration over a recorded SSH banner resolves to a
        // verdict.
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
        // A `Server:` value reaches product and version through the pipeline.
        // Both readings are `Strong`; the corpus rule's (with vendor and CPE)
        // takes the slot.
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
        // The Apache signature supplies product and vendor, the HTTP analyzer
        // the X-Powered-By extrainfo; all land on one Service.
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
        // A versionless `Server` ties with the baseline at Probable; the server
        // name must still win.
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
    /// See [`MAX_IDENTITY_BYTES`].
    #[tokio::test]
    async fn a_hostile_response_cannot_fill_a_report_field() {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a socket");
        let addr = listener.local_addr().expect("its address");
        let server = tokio::spawn(async move {
            let Ok(mut sock) = accept_from_this_process(&listener).await else {
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

    /// An ordinary value is untouched by the bound.
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
    /// The mock answers a ClientHello with a TLS 1.0 ServerHello and nothing
    /// else.
    #[tokio::test]
    async fn a_server_that_speaks_only_tls_ten_is_still_recorded() {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a socket");
        let addr = listener.local_addr().expect("its address");
        let server = tokio::spawn(async move {
            // Twice: the modern handshake dials first and is answered with an
            // alert, then the legacy probe dials on its own connection.
            for round in 0..2 {
                let Ok(mut sock) = accept_from_this_process(&listener).await else {
                    return;
                };
                let mut buffer = [0u8; 1024];
                let _ = sock.read(&mut buffer).await;
                let reply: &[u8] = match round {
                    // Fatal alert: protocol_version.
                    0 => &[0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46],
                    // A ServerHello naming TLS 1.0.
                    _ => &[
                        0x16, 0x03, 0x01, 0x00, 0x2a, 0x02, 0x00, 0x00, 0x26, 0x03, 0x01,
                    ],
                };
                let _ = sock.write_all(reply).await;
            }
        });

        // The port number picks the path and the socket the peer, so no
        // privileged port is bound.
        let stream = TcpStream::connect(addr).await.expect("connects");
        let port = baseline_port(443, Protocol::Tcp, PortState::Open);
        let (responses, tunnel) =
            gather(stream, 443, ServiceDetection::Probe, &Egress::KERNEL, None).await;
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

        // It reaches the report record.
        assert_eq!(tls_security(tls).tls_version(), Some("TLSv1.0"));
    }

    /// A port that trickles cannot hold a scan.
    ///
    /// One byte every forty milliseconds stays inside [`CONTINUATION_GRACE`];
    /// [`MAX_CONTINUATION`] stops it. The ceiling asserted is generous for
    /// loaded machines.
    #[tokio::test]
    async fn a_trickling_port_cannot_hold_the_reader() {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a socket");
        let addr = listener.local_addr().expect("its address");
        let server = tokio::spawn(async move {
            let Ok(mut sock) = accept_from_this_process(&listener).await else {
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

    /// [`COLLECTION_BUDGET`] covers every path through [`gather`]. Each path is
    /// written out, since their sum is no real walk. Add new rungs here.
    ///
    /// `spoke` is a rung that drew bytes: it pays a continuation per read and
    /// ends the walk. `silent` drew nothing: it pays only the wait. A plaintext
    /// rung answered with a TLS record pays a continuation and still falls
    /// through (`alert_then_tls`).
    ///
    /// Each path counts its time with no path delay and its number of waits
    /// that add the path; a continuation is not one, since the answer has
    /// arrived.
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

        // A port's own probes: at most two per port in the shipped corpus, each a
        // wait plus a continuation.
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

        // In the clear, one more dial per extra service.
        let services = SignatureDb::global()
            .indexed_ports()
            .map(|port| SignatureDb::global().tcp_probe_conversations(port).count())
            .max()
            .unwrap_or(0)
            .max(1) as u32;
        let redials = rung * (services - 1);
        let handshake = wait(tls::TLS_HANDSHAKE_TIMEOUT);
        // Through TLS, one more dial and handshake per extra service.
        let retunnels = (rung + handshake) * (services - 1);
        let legacy = wait(tls::LEGACY_PROBE_TIMEOUT);
        let speculative = wait(tls::SPECULATIVE_TLS_TIMEOUT);

        // A redirect is followed on its own connection (and handshake, over TLS).
        let followed = rung + read_once;
        let followed_tls = rung + handshake + read_once;

        // Numbered for TLS: [Tls, LegacyTls, Plaintext].
        let tls_then_redirect = handshake + spoke(probes) + retunnels + followed_tls;
        let tls_all_three = handshake + rung + legacy + rung + spoke(probes) + redials + followed;
        let tls_then_silence = handshake + rung + legacy + rung + silent(probes) + redials;

        // Numbered for anything else: [Plaintext, SpeculativeTls].
        let claimed_then_tls = silent(probes)
            + redials
            + rung
            + speculative
            + spoke(probes)
            + retunnels
            + followed_tls;
        let alert_then_tls = read_once + rung + speculative + spoke(1) + followed_tls;
        let unclaimed_then_redirect = read_once + rung + read_once;
        // A plaintext `400`, then a handshake, then the legacy one.
        let refused_then_tls =
            spoke(probes) + redials + rung + speculative + spoke(probes) + retunnels + followed_tls;
        let refused_then_legacy = spoke(probes) + redials + rung + speculative + rung + legacy;

        // A shared port: the generic question (refused with a 400), each
        // service on its own connection, a redirect followed, then the
        // handshakes.
        let asked = |count: u32| (wait(PROBE_READ_TIMEOUT) + continuation) * count;
        let unasked = |count: u32| wait(PROBE_READ_TIMEOUT) * count;
        let shared_spoke = unclaimed_then_redirect + rung * services + asked(probes) + followed;
        let shared_silent = unasked(1) + rung * services + unasked(probes);

        // The last rung: a connection and a read per probe, for every probe.
        let universal = SignatureDb::global()
            .universal_tcp_probe_payloads(0, ServiceDetection::Thorough.probe_intensity())
            .len()
            .max(1) as u32;
        let last_resort = (rung + read_once) * universal;

        let paths = [
            tls_then_redirect,
            tls_all_three + last_resort,
            tls_then_silence + last_resort,
            claimed_then_tls,
            alert_then_tls,
            unclaimed_then_redirect,
            refused_then_tls,
            refused_then_legacy,
            silent(probes) + redials + rung + speculative + last_resort,
            shared_spoke,
            shared_spoke + rung + speculative + spoke(probes) + retunnels + followed_tls,
            shared_spoke + rung + speculative + rung + legacy,
            shared_silent + rung + speculative + spoke(probes) + retunnels + followed_tls,
            shared_silent + rung + speculative + last_resort,
        ];
        let longest = paths.iter().map(|walk| walk.0).max().expect("a path");
        let most_waits = paths.iter().map(|walk| walk.1).max().expect("a path");

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
    /// The SSH analyzer would otherwise open a second connection from a banner
    /// alone. The number is SSH's and the socket an ephemeral loopback one.
    #[tokio::test]
    async fn a_port_only_listened_to_is_not_dialled_again_by_an_analyzer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let addr = listener.local_addr().expect("a local address");
        // Reported on close, so nothing in flight is missed.
        let (closed, mut sent) = tokio::sync::mpsc::unbounded_channel::<usize>();
        let server = tokio::spawn(async move {
            while let Ok(mut sock) = accept_from_this_process(&listener).await {
                let closed = closed.clone();
                tokio::spawn(async move {
                    let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n").await;
                    let mut buffer = [0u8; 1024];
                    let mut received = 0;
                    while let Ok(n) = sock.read(&mut buffer).await {
                        if n == 0 {
                            break;
                        }
                        received += n;
                    }
                    let _ = closed.send(received);
                });
            }
        });

        let stream = TcpStream::connect(addr).await.expect("connects");
        let port = baseline_port(22, Protocol::Tcp, PortState::Open);
        let port = fingerprint_tcp_via(
            stream,
            port,
            ServiceDetection::Banner,
            &Egress::KERNEL,
            PathAllowance::NONE,
            None,
        )
        .await
        .port;
        // The channel ends once every connection has reported.
        server.abort();
        let mut per_connection = Vec::new();
        let every_close = async {
            while let Some(received) = sent.recv().await {
                per_connection.push(received);
            }
        };
        timeout(Duration::from_secs(60), every_close)
            .await
            .expect("every connection to the port closes");

        assert_eq!(
            port.service().map(Service::name),
            Some("ssh"),
            "the greeting alone names the service"
        );
        assert_eq!(per_connection.len(), 1, "the port was dialled again");
        assert_eq!(
            per_connection.iter().sum::<usize>(),
            0,
            "the port was sent a payload"
        );
    }

    /// What the clear-text rung sends a silent port numbered `number`, read
    /// off a loopback listener that records every byte and answers nothing.
    /// No peer to address, so the probes arrive as authored.
    async fn asked_in_the_clear(number: u16) -> Vec<u8> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let addr = listener.local_addr().expect("a local address");
        let server = tokio::spawn(async move {
            let mut sock = accept_from_this_process(&listener)
                .await
                .expect("one connection");
            let mut received = Vec::new();
            let _ = sock.read_to_end(&mut received).await;
            received
        });

        let stream = TcpStream::connect(addr).await.expect("connects");
        plaintext(stream, number, None, &Egress::KERNEL).await;
        server.await.expect("the listener finishes")
    }

    /// A raw-print port a scan was told to probe is asked what a port nothing
    /// claims is asked.
    ///
    /// The scan's listen-only list protects printers; a port taken off it was
    /// chosen to be probed, so it gets the generic question.
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

    /// How many other services' questions a silent port is asked across
    /// `round_trip` at `detection`, counted as connections.
    async fn guesses_put(round_trip: Option<Duration>, detection: ServiceDetection) -> usize {
        use crate::testing::loopback::accept_from_this_process;
        use std::sync::atomic::AtomicUsize;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let addr = listener.local_addr().expect("a local address");
        let taken = Arc::new(AtomicUsize::new(0));
        let counting = Arc::clone(&taken);
        let server = tokio::spawn(async move {
            while let Ok(sock) = accept_from_this_process(&listener).await {
                counting.fetch_add(1, Ordering::Relaxed);
                drop(sock);
            }
        });

        let first = TcpStream::connect(addr).await.expect("connects");
        let dialling = Dialling {
            egress: Egress::KERNEL,
            path: PathAllowance::of_round_trips(round_trip),
            tally: Arc::new(Tally::default()),
        };
        let peer = Authority::new(addr);
        DIALLING
            .scope(
                dialling,
                last_resort(first, &peer, 2222, detection, &Egress::KERNEL),
            )
            .await;
        server.abort();
        taken.load(Ordering::Relaxed)
    }

    /// A port silent to its own questions, across a path slower than a
    /// question's own wait, is put only the likeliest of other services'
    /// questions at the default level, and every one of them where the path
    /// is ordinary or the caller asked for the thorough level.
    ///
    /// Across a two-second path each guess costs nearly nine seconds.
    #[tokio::test]
    async fn a_silent_port_across_a_slow_path_is_put_only_the_likeliest_guess() {
        let slow = Some(Duration::from_millis(1_900));
        let all = guesses_put(None, ServiceDetection::Probe).await;
        assert!(all >= 2, "the premise needs guesses to leave out: {all}");

        assert_eq!(guesses_put(slow, ServiceDetection::Probe).await, 1);
        assert_eq!(
            guesses_put(Some(Duration::from_millis(40)), ServiceDetection::Probe).await,
            all
        );
        assert!(guesses_put(slow, ServiceDetection::Thorough).await >= all);
    }

    /// An answer nothing recognised leaves the port the name its number gives
    /// it, whether the identification is recorded as it stands or folded into
    /// a port already recorded under that name.
    ///
    /// The banner is kept as detail either way.
    #[tokio::test]
    async fn an_unrecognised_answer_reads_the_same_however_the_port_was_found() {
        use crate::testing::loopback::accept_from_this_process;

        let greeting = "WIDGET/4.2 ready";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let addr = listener.local_addr().expect("a local address");
        let server = tokio::spawn(async move {
            while let Ok(mut sock) = accept_from_this_process(&listener).await {
                tokio::spawn(async move {
                    let _ = sock.write_all(format!("{greeting}\r\n").as_bytes()).await;
                    let mut buffer = [0u8; 1024];
                    while sock.read(&mut buffer).await.is_ok_and(|read| read > 0) {}
                });
            }
        });

        let stream = TcpStream::connect(addr).await.expect("connects");
        let seeded = baseline_port(6379, Protocol::Tcp, PortState::Open);
        let found = fingerprint_tcp(stream, seeded.clone(), ServiceDetection::Probe).await;
        server.abort();

        let mut folded = seeded;
        folded.merge(found.clone());
        let read = |port: &Port| {
            port.service().map(|service| {
                (
                    service.name().to_owned(),
                    service.extrainfo().map(str::to_owned),
                )
            })
        };
        assert_eq!(
            read(&found),
            Some(("redis".to_owned(), Some(greeting.to_owned()))),
            "recorded as identified"
        );
        assert_eq!(read(&folded), read(&found), "folded into the recorded port");
    }

    /// **The realm a KDC names reaches its host as a name, masked where a
    /// report masks, and never the port's description.** Over sockets end to
    /// end: the corpus probe over TCP, the KDC's `KRB-ERROR` naming a realm of
    /// its own behind the four-byte length, and the host record a report is
    /// written from.
    #[tokio::test]
    async fn a_kdc_s_realm_reaches_its_host_masked_and_not_its_description() {
        use crate::export::schema::HostDto;
        use crate::export::{ExportOptions, Redaction};
        use crate::model::host::Host;
        use crate::testing::loopback::accept_from_this_process;

        // KDC_ERR_WRONG_REALM naming the realm (RFC 4120 §5.9.1), behind the
        // TCP length prefix (§7.2.2).
        let realm = b"CORP.EXAMPLE";
        let mut fields = vec![0xA6, 0x03, 0x02, 0x01, 68];
        fields.extend_from_slice(&[0xA9, realm.len() as u8 + 2, 0x1B, realm.len() as u8]);
        fields.extend_from_slice(realm);
        let mut sequence = vec![0x30, fields.len() as u8];
        sequence.extend_from_slice(&fields);
        let mut error = vec![0x7E, sequence.len() as u8];
        error.extend_from_slice(&sequence);
        let mut reply = (error.len() as u32).to_be_bytes().to_vec();
        reply.extend_from_slice(&error);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let addr = listener.local_addr().expect("a local address");
        let server = tokio::spawn(async move {
            while let Ok(mut sock) = accept_from_this_process(&listener).await {
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    if sock.read(&mut buffer).await.is_ok_and(|read| read > 0) {
                        let _ = sock.write_all(&reply).await;
                    }
                    while sock.read(&mut buffer).await.is_ok_and(|read| read > 0) {}
                });
            }
        });

        let stream = TcpStream::connect(addr).await.expect("connects");
        let port = baseline_port(88, Protocol::Tcp, PortState::Open);
        let found = fingerprint_tcp_detailed(stream, port, ServiceDetection::Probe).await;
        server.abort();

        let service = found.port.service().expect("the port is named");
        assert_eq!(service.product(), Some("Kerberos KDC"));
        assert!(
            !format!("{service:?}").contains("CORP"),
            "the realm reached the service: {service:?}"
        );

        let mut host = Host::new(addr.ip());
        found.about_the_host.apply(&mut host);
        let render = |options: ExportOptions| {
            serde_json::to_value(HostDto::new(&host, &options)).expect("a host renders")
        };
        assert_eq!(
            render(ExportOptions::new())["names"],
            serde_json::json!([{"source": "kerberos", "kind": "domain", "name": "CORP.EXAMPLE"}])
        );
        let masked = render(ExportOptions::new().with_redaction(Redaction::Standard)).to_string();
        assert!(
            !masked.contains("CORP") && masked.contains(r#""source":"kerberos""#),
            "the realm survived redaction: {masked}"
        );
    }

    /// A port two services share has each asked on a connection of its own,
    /// so one's question cannot close the conversation before the other's.
    ///
    /// 3000 is shared by Aerospike and Grafana. A web server there answers
    /// Aerospike's binary request with `400` and closes, as Node and Go do. The
    /// peer here behaves that way; the test reads what each connection heard
    /// first.
    #[tokio::test]
    async fn a_shared_port_asks_each_service_on_a_connection_of_its_own() {
        use crate::testing::loopback::accept_from_this_process;
        use std::sync::{Arc, Mutex};

        let shared = 3000;
        let db = SignatureDb::global();
        assert!(
            db.service_name(shared).is_none() && db.tcp_probe_conversations(shared).count() >= 2,
            "test assumes {shared} is shared by several services and named by none"
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let addr = listener.local_addr().expect("a local address");
        let heard: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let log = Arc::clone(&heard);
        let server = tokio::spawn(async move {
            while let Ok(mut sock) = accept_from_this_process(&listener).await {
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    let read = sock.read(&mut buffer).await.unwrap_or(0);
                    let request = buffer[..read].to_vec();
                    let reply: &[u8] = if request.starts_with(b"GET /login ") {
                        b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n<title>Grafana</title>"
                    } else if request.starts_with(b"GET ") {
                        b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"
                    } else {
                        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
                    };
                    log.lock().unwrap().push(request);
                    let _ = sock.write_all(reply).await;
                });
            }
        });

        let stream = TcpStream::connect(addr).await.expect("connects");
        let port = baseline_port(shared, Protocol::Tcp, PortState::Open);
        let found = fingerprint_tcp_detailed(stream, port, ServiceDetection::Probe).await;
        server.abort();

        let firsts = heard.lock().unwrap().clone();
        // By first line, since requests are addressed; see
        // `Authority::addressed`.
        let first_line = |bytes: &[u8]| -> Vec<u8> {
            let end = bytes
                .windows(2)
                .position(|pair| pair == b"\r\n")
                .unwrap_or(bytes.len());
            bytes[..end].to_vec()
        };
        for probes in db.tcp_probe_conversations(shared) {
            assert!(
                firsts
                    .iter()
                    .any(|first| first_line(first) == first_line(&probes[0])),
                "a service's question was never the first thing on a connection: \
                 {:?} not in {firsts:?}",
                String::from_utf8_lossy(&probes[0])
            );
        }
        assert_eq!(
            found.port.service().map(Service::name),
            Some("grafana"),
            "the port was named by another service's refusal"
        );
    }

    /// A connection an identification gives up for want of a socket marks
    /// the identification starved, and one that fails for any other reason
    /// does not.
    ///
    /// An analyzer's own clock can run out while its connection waits for a
    /// descriptor. A refused connection is the port's answer, not starvation.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_connection_given_up_for_want_of_a_socket_marks_the_identification_starved() {
        use crate::system::descriptors::testing::{
            in_a_process_of_its_own, refuse_every_descriptor,
        };

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
        let closed = crate::testing::loopback::refused_port(std::net::IpAddr::from([127, 0, 0, 1]));

        // As an analyzer dials: in the scope, under its own clock.
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

        let held = refuse_every_descriptor();
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
    /// A port asked and silent is still silence.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_udp_identification_refused_a_socket_is_starved_and_not_silent() {
        use crate::system::descriptors::testing::{
            in_a_process_of_its_own, refuse_every_descriptor,
        };

        if !in_a_process_of_its_own(
            module_path!(),
            "a_udp_identification_refused_a_socket_is_starved_and_not_silent",
        ) {
            return;
        }
        // A UDP port the corpus probes, held by a socket that answers nothing,
        // so no service on the machine can answer for it. Above 1024, which
        // any user may bind.
        let corpus = SignatureDb::global();
        let silent = (1024..=u16::MAX)
            .filter(|&port| !corpus.udp_probe_payloads(port).is_empty())
            .find_map(|port| std::net::UdpSocket::bind(("127.0.0.1", port)).ok())
            .expect("a free UDP port the corpus asks something");
        let addr = silent.local_addr().expect("a local address");
        let port = || baseline_port(addr.port(), Protocol::Udp, PortState::Open);
        let patience = Duration::from_millis(50);

        let held = refuse_every_descriptor();
        let unasked =
            fingerprint_udp_within(addr, port(), &Egress::KERNEL, patience, PathAllowance::NONE)
                .await;
        drop(held);
        let asked =
            fingerprint_udp_within(addr, port(), &Egress::KERNEL, patience, PathAllowance::NONE)
                .await;

        let unasked = unasked.expect("a datagram never sent was read as the port's silence");
        assert!(unasked.starved);
        assert!(unasked.responses.is_empty());
        assert!(
            asked.is_none(),
            "a port asked and silent was not read as silence: {asked:?}"
        );
    }

    /// A redirect is followed only after the first connection is closed.
    #[tokio::test]
    async fn a_redirect_is_followed_after_the_connection_that_drew_it_is_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let addr = listener.local_addr().expect("a local address");
        let server = tokio::spawn(async move {
            let mut first = accept_from_this_process(&listener)
                .await
                .expect("the first connection");
            let mut buffer = [0u8; 1024];
            let _ = first.read(&mut buffer).await;
            // Held open, as with keep-alive.
            let _ = first
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n")
                .await;
            let mut second = accept_from_this_process(&listener)
                .await
                .expect("the redirect followed");
            // The first must be closed by now.
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
        let banners = plaintext(stream, 51987, Some(&Authority::new(addr)), &Egress::KERNEL)
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
    /// An agent answers only its own framed request, so off its port only the
    /// last-resort rung reaches it, gated by the rarity authored on the probe.
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
                while let Ok(mut sock) = accept_from_this_process(&listener).await {
                    let mut buffer = [0u8; 1024];
                    let read = sock.read(&mut buffer).await.unwrap_or(0);
                    if buffer[..read].starts_with(b"ZBXD\x01") {
                        heard.store(true, Ordering::SeqCst);
                        // Header, protocol flag, eight-byte LE length, `1`.
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
        // No banners and no TLS resolve to no verdict.
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

    /// A loopback HTTPS server with a certificate for `name` only, refusing other
    /// handshakes. A request in the clear gets a plaintext `400`, as from Go.
    /// Its root redirects to `/web/`.
    async fn https_by_name(name: &str) -> (SocketAddr, Heard) {
        let acceptor = crate::testing::loopback::tls_by_name(name);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let addr = listener.local_addr().expect("a local address");
        let heard: Heard = Arc::default();
        let record = Arc::clone(&heard);
        tokio::spawn(async move {
            while let Ok(stream) = accept_from_this_process(&listener).await {
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
                    let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
                    let reply: &[u8] = match request.starts_with("GET / ") {
                        true => {
                            b"HTTP/1.1 302 Found\r\nServer: Caddy\r\nLocation: /web/\r\n\
                              Content-Length: 0\r\nConnection: close\r\n\r\n"
                        }
                        false => {
                            b"HTTP/1.1 200 OK\r\nServer: Caddy\r\n\
                              Content-Length: 0\r\nConnection: close\r\n\r\n"
                        }
                    };
                    record.lock().expect("not poisoned").push(request);
                    let _ = tls.write_all(reply).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (addr, heard)
    }

    /// The target's name goes in the handshake and the request inside it.
    #[tokio::test]
    async fn a_tls_port_on_a_named_address_is_asked_for_by_its_name() {
        let (addr, heard) = https_by_name("box.example").await;

        let stream = TcpStream::connect(addr).await.expect("connects");
        let port = baseline_port(443, Protocol::Tcp, PortState::Open);
        let found = fingerprint_tcp_via(
            stream,
            port,
            ServiceDetection::Probe,
            &Egress::KERNEL,
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

    /// Each service sharing a TLS port gets its own handshake. 8443 is shared
    /// with the Kubernetes API.
    #[tokio::test]
    async fn each_service_sharing_a_tls_port_is_asked_through_a_handshake_of_its_own() {
        let (addr, heard) = https_by_name("box.example").await;

        let stream = TcpStream::connect(addr).await.expect("connects");
        let port = baseline_port(8443, Protocol::Tcp, PortState::Open);
        let found = fingerprint_tcp_via(
            stream,
            port,
            ServiceDetection::Probe,
            &Egress::KERNEL,
            PathAllowance::NONE,
            Some(Arc::from("box.example")),
        )
        .await;

        assert!(found.port.security().is_some(), "the handshake completed");
        let asked = heard.lock().expect("not poisoned").clone();
        for question in ["GET / ", "GET /api "] {
            assert!(
                asked.iter().any(|request| request.starts_with(question)),
                "`{}` went unasked: {asked:?}",
                question.trim()
            );
        }
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

    /// A web port is asked at once; a port where something may greet is
    /// listened to first.
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
            &Egress::KERNEL,
            PathAllowance::NONE,
            name.map(Arc::from),
        )
        .await
    }

    /// A plaintext `400` sends the port a handshake.
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

    /// Refused handshakes for an address target still file the port as a web
    /// server over TLS.
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

    /// The same server on the port numbered for HTTPS, asked for by no name,
    /// is filed as a web server over TLS too.
    ///
    /// It refuses both handshakes in TLS; its plaintext `400` says what it
    /// serves.
    #[tokio::test]
    async fn https_on_its_own_port_refusing_a_nameless_handshake_is_filed_as_https() {
        let (addr, _heard) = https_by_name("box.example").await;
        let stream = TcpStream::connect(addr).await.expect("connects");
        let found = fingerprint_tcp_via(
            stream,
            baseline_port(443, Protocol::Tcp, PortState::Open),
            ServiceDetection::Probe,
            &Egress::KERNEL,
            PathAllowance::NONE,
            None,
        )
        .await;

        let service = found.port.service().expect("a service was named");
        assert_eq!(service.name(), "ssl/http");
        assert!(!service.is_inferred(), "the name is still the number's");
    }

    /// A redirect back to the port is followed through TLS and in the clear, on
    /// claimed and unclaimed ports.
    #[tokio::test]
    async fn a_redirect_is_followed_on_a_claimed_port_and_through_tls() {
        let (addr, heard) = https_by_name("box.example").await;
        let stream = TcpStream::connect(addr).await.expect("connects");
        let found = fingerprint_tcp_via(
            stream,
            baseline_port(443, Protocol::Tcp, PortState::Open),
            ServiceDetection::Probe,
            &Egress::KERNEL,
            PathAllowance::NONE,
            Some(Arc::from("box.example")),
        )
        .await;
        let asked = heard.lock().expect("not poisoned").clone();
        assert!(
            asked
                .iter()
                .any(|request| request.starts_with("GET /web/ ")),
            "the redirect through TLS was not followed: {asked:?}"
        );
        assert_eq!(found.responses.len(), 2, "{:?}", found.responses);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let clear = listener.local_addr().expect("a local address");
        let server = tokio::spawn(async move {
            let mut asked = Vec::new();
            for reply in [
                &b"HTTP/1.1 302 Found\r\nLocation: /web/\r\nContent-Length: 0\r\n\r\n"[..],
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            ] {
                let Ok(mut sock) = accept_from_this_process(&listener).await else {
                    break;
                };
                let mut buffer = [0u8; 1024];
                let read = sock.read(&mut buffer).await.unwrap_or(0);
                asked.push(String::from_utf8_lossy(&buffer[..read]).into_owned());
                let _ = sock.write_all(reply).await;
            }
            asked
        });
        let number = 8080;
        assert!(!SignatureDb::global().tcp_probe_payloads(number).is_empty());
        let stream = TcpStream::connect(clear).await.expect("connects");
        let banners = plaintext(
            stream,
            number,
            Some(&Authority::new(clear)),
            &Egress::KERNEL,
        )
        .await
        .banners;
        let asked = server.await.expect("the listener finishes");
        assert!(
            asked
                .iter()
                .any(|request| request.starts_with("GET /web/ ")),
            "the redirect in the clear was not followed: {asked:?}"
        );
        assert_eq!(banners.len(), 2, "{banners:?}");
    }

    /// A port that answered through TLS is asked for its icon through TLS.
    #[tokio::test]
    async fn an_https_port_is_asked_for_its_icon_through_tls() {
        let (addr, heard) = https_by_name("box.example").await;
        let stream = TcpStream::connect(addr).await.expect("connects");
        let _ = fingerprint_tcp_via(
            stream,
            baseline_port(443, Protocol::Tcp, PortState::Open),
            ServiceDetection::Probe,
            &Egress::KERNEL,
            PathAllowance::NONE,
            Some(Arc::from("box.example")),
        )
        .await;

        let asked = heard.lock().expect("not poisoned").clone();
        assert!(
            !asked.iter().any(|request| request.starts_with("clear:")),
            "an HTTPS port was asked in the clear: {asked:?}"
        );
        assert!(
            asked
                .iter()
                .any(|request| request.starts_with("GET /favicon.ico ")),
            "the icon was not asked for through TLS: {asked:?}"
        );
    }
}
