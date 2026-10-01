// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Service detection phase
//!
//! The second phase of a port scan: given ports whose state is already known,
//! identify what is running behind the open ones.
//!
//! ## Why it is a separate phase
//!
//! The unprivileged [`connect`](crate::scanner::strategy::connect) scanner holds
//! a live `TcpStream` when it finds a port open, so it fingerprints inline. The
//! privileged [`TcpPortScanner`](crate::scanner::strategy::ports::TcpPortScanner)
//! classifies each port from a raw SYN exchange and never completes a handshake.
//! This phase opens a real connection to each open TCP port and runs the same
//! engine, so a privileged scan reports the same service detail as the connect
//! path. Port discovery uses raw-packet speed; identification needs a
//! conversation.
//!
//! ## On a slow or a crowded path
//!
//! Every wait on a port allows for the host's round trip as measured during
//! discovery, as the port scans' own probes do. A host's ports are identified
//! side by side, and a host serving them from one worker answers in turn, so a
//! port that drew nothing while its host was busy with another is asked again
//! with the host to itself. The unprivileged port scan shares both.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpStream;

use crate::model::host::{Host, NetworkRole};
use crate::model::ip::scoped::ScopedIp;
use crate::warn;

use crate::config::ServiceDetection;
use crate::config::limits::{CONNECT_CONCURRENCY, CONNECT_PROBE_TIMEOUT};
use crate::detect::contention::HostContention;
use crate::fingerprint::Fingerprinted;
use crate::model::port::{Port, PortState, Protocol};
use crate::report::{Pass, ScannerKind};
use crate::scanner::pool::ProbePool;
use crate::scanner::session::{ScanContext, Stage};
use crate::system::descriptors;
use crate::transport::dial::Egress;
use crate::transport::dial::PathAllowance;

/// Fingerprints every open port currently in the store worth an exchange,
/// upgrading each port's service in place.
///
/// Runs once, after a discovery phase that established port state but not
/// service identity (the SYN path). Re-identifying a port the connect scanner
/// already fingerprinted is harmless.
///
/// `over` is the transport whose ports to take, so a composite with TCP and UDP
/// members fingerprints each port once, from the member that found it.
pub async fn detect(ctx: &ScanContext, detection: ServiceDetection, over: Protocol) {
    identify(ctx, detection, over, Which::Every).await;
}

/// Identifies the open ports over `over` that an earlier sitting identified and
/// this one has not, for a strategy that identifies inline and has no second
/// pass.
///
/// The earlier sitting's responses ended with it, and the port comes back
/// settled, so no probe of this sitting reaches it; see
/// [`Responses`](crate::scanner::session::Responses). Hosts an earlier sitting
/// finished are not asked.
pub(crate) async fn detect_inherited(
    ctx: &ScanContext,
    detection: ServiceDetection,
    over: Protocol,
) {
    identify(ctx, detection, over, Which::Inherited).await;
}

/// Which of a transport's open ports a pass identifies.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Which {
    /// Every one a host owed its passes holds.
    Every,
    /// Only those whose responses ended with an earlier sitting.
    Inherited,
}

/// [`detect`], over the ports `which` names.
async fn identify(ctx: &ScanContext, detection: ServiceDetection, over: Protocol, which: Which) {
    // Nothing to do at a level that opens no connection.
    if !detection.connects() {
        return;
    }

    // Snapshot the targets up front so no DashMap guard is held across an await.
    let tarpits = Tarpits::default();
    let targets = fingerprintable_ports(ctx, over, detection, which, &tarpits);
    // A stopped scan opens nothing further; the report names the pass.
    if targets.is_empty() || ctx.stopping_before(Pass::Services) {
        tarpits.report(ctx, ScannerKind::Service);
        return;
    }

    ctx.enter_stage(Stage::Services, Some(targets.len() as u64));

    let mut asked = 0;
    let mut quiet = QuietPorts::default();
    let mut in_part = QuietPorts::default();
    let crowds = Crowds::default();

    let mut pool = ProbePool::new(
        CONNECT_CONCURRENCY,
        ctx.clone(),
        ScannerKind::Service,
        |attempt: Attempt, _audit| {
            ctx.stage_advanced();

            match attempt {
                Attempt::Identified(found) => {
                    let Identified {
                        ip,
                        port,
                        about_the_host,
                        banners,
                        identified_in_part,
                    } = *found;
                    if identified_in_part {
                        in_part.record(&ip, port.number(), Unreached::Starved);
                    }
                    ctx.record_responses(ip.clone(), port.number(), port.protocol(), banners);
                    write_back(ctx, ip, port, about_the_host);
                }
                Attempt::Unreachable { ip, number, reason } => {
                    quiet.record(&ip, number, reason);
                }
                Attempt::Quiet => {}
            }
        },
    );

    for target in targets {
        if ctx.stopping_before(Pass::Services) {
            break;
        }
        let address = target.address.addr();
        // A host whose budget ran out is not asked; its ports keep their state
        // without a service name.
        if ctx.host_expired(address) {
            continue;
        }
        // Decided here, from what the host's ports so far have answered.
        let crowd = crowds.of(address, ctx.target_name(address));
        let identifies = ctx.read_host(address, |host| {
            tarpits.identifies(host, Some(&crowd), target.number, target.protocol)
        });
        if identifies == Some(false) {
            ctx.stage_advanced();
            continue;
        }
        asked += 1;
        let egress = ctx.egress_toward(address);
        let detection = ctx.service_detection_on(detection, target.number, target.protocol);
        let identifying = fingerprint_one(target, detection, egress, crowd);
        // Ends with the scan, not at its own ceiling (up to half a minute on a
        // port that says nothing). One cut short keeps the port phase's record.
        let handle = ctx.handle.clone();
        pool.admit(async move {
            handle
                .or_stopped(identifying)
                .await
                .unwrap_or(Attempt::Quiet)
        })
        .await;
    }

    pool.drain().await;
    drop(pool);
    // Names the pass if a stop ended identifications in flight.
    ctx.stopping_before(Pass::Services);
    close_pass(ctx, &crowds, &quiet, in_part, asked).await;
    tarpits.report(ctx, ScannerKind::Service);
}

/// Ends a pass whose first identifications are done: asks again the ports its
/// crowds owe a second asking, then reports the ports that said nothing, were
/// out of reach, or were identified only in part because of the file limit.
///
/// Separate from [`detect`] so a test can fill the descriptor table first and
/// count second askings without racing the first identification's sockets.
async fn close_pass(
    ctx: &ScanContext,
    crowds: &Crowds,
    quiet: &QuietPorts,
    mut in_part: QuietPorts,
    asked: usize,
) {
    for (ip, port) in crowds.ask_again(ctx, ScannerKind::Service).await {
        in_part.record(&ip, port, Unreached::Starved);
    }
    crowds.report_silence();

    quiet.report(ctx, asked);
    in_part.report_in_part(ctx);
}

/// How many silent ports it takes before silence is worth a word about the path.
///
/// A few silent open ports are ordinary, since many services wait to be spoken
/// to first. Every open port silent, past this many, points at the path.
const QUIET_PORTS_WORTH_A_WORD: usize = 10;

/// Open ports that answered the port scan and then gave nothing back on a
/// connection, gathered across the phase.
///
/// Reported as one line, since a path that answers every SYN yields one per
/// port probed. Same approach as [`SendFaults`](crate::scanner::strategy::raw).
#[derive(Debug, Default)]
struct QuietPorts {
    /// How many ports it happened to.
    count: usize,
    /// The first one, so the summary names somewhere to start looking.
    first: Option<String>,
    /// Why that one gave nothing back; usually the same for all when something
    /// on the path answers for the services.
    reason: Option<Unreached>,
}

impl QuietPorts {
    /// Files one port that could not be fingerprinted.
    fn record(&mut self, ip: &ScopedIp, number: u16, reason: Unreached) {
        self.count += 1;
        if self.first.is_none() {
            self.first = Some(ip.endpoint(number));
            self.reason = Some(reason);
        }
    }

    /// The one entry the ports amount to in the report, named from the first
    /// of them.
    fn summary(first: &str, reason: &Unreached, count: usize) -> String {
        format!(
            "{} could not be fingerprinted: {}",
            Self::named(first, count),
            reason.said()
        )
    }

    /// The one console line they amount to: which ports, then why in a word or
    /// two. The report's entry says the rest.
    fn line(first: &str, reason: &Unreached, count: usize) -> String {
        format!(
            "{} not fingerprinted ({})",
            Self::named_briefly(first, count),
            reason.terse()
        )
    }

    /// [`named`](Self::named), in the fewer words a console line has.
    fn named_briefly(first: &str, count: usize) -> String {
        match count - 1 {
            0 => first.to_string(),
            rest => format!("{first} and {rest} more"),
        }
    }

    /// `count` ports, named from the first of them.
    fn named(first: &str, count: usize) -> String {
        match count - 1 {
            0 => first.to_string(),
            1 => format!("{first} and 1 other port"),
            rest => format!("{first} and {rest} other ports"),
        }
    }

    /// Says once that these ports were identified only in part, because a later
    /// connection was refused a socket. Filed as cut short and warned in one line
    /// naming the limit, which the caller can raise.
    fn report_in_part(&self, ctx: &ScanContext) {
        let (Some(first), Some(reason)) = (&self.first, &self.reason) else {
            return;
        };
        warn!(
            "{} identified in part ({})",
            Self::named_briefly(first, self.count),
            reason.terse()
        );
        ctx.file_cut_short(
            ScannerKind::Service,
            format!(
                "{} identified in part: {}",
                Self::named(first, self.count),
                reason.said()
            ),
        );
    }

    /// Says it once, against `asked` open ports the phase set out to identify.
    fn report(&self, ctx: &ScanContext, asked: usize) {
        let (Some(first), Some(reason)) = (&self.first, &self.reason) else {
            return;
        };

        // One cut-short entry for all of them: the ports were open and the scan
        // did not learn what was behind them, but nothing broke.
        warn!("{}", Self::line(first, reason, self.count));
        ctx.file_cut_short(
            ScannerKind::Service,
            Self::summary(first, reason, self.count),
        );

        // Every open port taking a SYN and then saying nothing points at the
        // path.
        if self.count == asked && asked >= QUIET_PORTS_WORTH_A_WORD {
            warn!("all {asked} open ports silent on connect (likely a middlebox)");
        }
    }
}

/// Every open `(address, port, protocol)` in the store worth fingerprinting,
/// snapshotted so the DashMap is not borrowed across the exchanges that follow.
///
/// The address comes from the host, which carries the interface a link-local
/// address needs; see [`Host::scoped_ip`](crate::model::host::Host::scoped_ip).
///
/// # Which UDP ports qualify
///
/// Only those whose reply this engine can read ([`reads_replies`]), and only at
/// a level that sends, since a UDP port has no greeting to listen for. Any TCP
/// port qualifies, since any may volunteer a banner.
///
/// # Which ports of a tarpit qualify
///
/// Only its likeliest; see [`Tarpits`]. Only open-port counts are known here; a
/// tarpit revealed by its silence is cut off as its ports are taken, in
/// [`asking_order`].
///
/// [`reads_replies`]: crate::fingerprint::reads_replies
fn fingerprintable_ports(
    ctx: &ScanContext,
    over: Protocol,
    detection: ServiceDetection,
    which: Which,
    tarpits: &Tarpits,
) -> Vec<Target> {
    if over == Protocol::Udp && !detection.sends() {
        return Vec::new();
    }

    let mut targets = Vec::new();
    for host in ctx.store.iter() {
        if !ctx.owes_passes(host.value()) {
            continue;
        }
        let address = host.value().scoped_ip();
        let path = PathAllowance::of_round_trips(host.value().telemetry().round_trips());
        let first = targets.len();
        for port in host.value().ports() {
            if port.protocol() == over
                && port.state() == PortState::Open
                && crate::fingerprint::reads_replies(port.number(), port.protocol())
                && (which == Which::Every
                    || ctx.responses_lost(&address, port.number(), port.protocol()))
                && tarpits.identifies(host.value(), None, port.number(), port.protocol())
            {
                targets.push(Target {
                    address: address.clone(),
                    number: port.number(),
                    protocol: port.protocol(),
                    path,
                });
            }
        }
        asking_order(&mut targets[first..], over);
    }
    targets
}

/// Puts one host's ports over `protocol` in the order their identifications are
/// asked: its likeliest first, most likely first, then the rest spread across
/// the port range.
///
/// The ports asked before [`SILENT_PORTS_OF_A_TARPIT`] have said nothing are
/// the sample a host is judged by. In ascending order, a block of a hundred and
/// fifty silent services low in the range would condemn the host before a
/// service above it was asked.
///
/// The likeliest come first because they are asked whatever the host is, and
/// each that answers on a real host holds off the tarpit verdict.
///
/// The rest are spread by halving: the lowest port in each half of the range
/// first, then the lowest in each quarter not yet taken, and so on to single
/// ports. A block of adjacent ports is sampled one at a time, and a lone port
/// is asked early. The order is deterministic.
fn asking_order(host: &mut [Target], protocol: Protocol) {
    let likeliest = likeliest(protocol);
    let rank = |number: u16| likeliest.iter().position(|&likely| likely == number);
    let mut rest: Vec<u16> = host
        .iter()
        .map(|target| target.number)
        .filter(|&number| rank(number).is_none())
        .collect();
    rest.sort_unstable();
    host.sort_by_cached_key(|target| match rank(target.number) {
        Some(rank) => (0, rank),
        None => {
            let place = rest.binary_search(&target.number).unwrap_or_default();
            (
                1 + halvings_to_part_of_its_own(&rest, place),
                usize::from(target.number),
            )
        }
    });
}

/// How many times the port range must be halved before the part holding
/// `sorted[place]` holds no lower port of `sorted`: zero for the lowest, sixteen
/// for a port whose neighbour below differs only in the last bit.
fn halvings_to_part_of_its_own(sorted: &[u16], place: usize) -> usize {
    match place.checked_sub(1).map(|below| sorted[below]) {
        None => 0,
        Some(below) => (below ^ sorted[place]).leading_zeros() as usize + 1,
    }
}

/// The ports over `protocol` a host that answers on every port still has
/// identified, most likely first; see [`TARPIT_PORTS_IDENTIFIED`].
fn likeliest(protocol: Protocol) -> &'static [u16] {
    use crate::model::port::catalog::{top_tcp, top_udp};

    match protocol {
        Protocol::Tcp => top_tcp(TARPIT_PORTS_IDENTIFIED),
        Protocol::Udp => top_udp(TARPIT_PORTS_IDENTIFIED),
        Protocol::Sctp => &[],
    }
}

/// How many open ports of one host that answers on every port are
/// identified, at most, per transport: the likeliest ones, by the catalog's
/// ranking.
///
/// A host past [`TARPIT_OPEN_PORTS`] answers everything, and identifying every
/// port it accepts would take hours of waited-out conversations. A firewall
/// answering every SYN for a server still passes the server's own ports
/// through, and those are likely on the most common ports. The first tier of
/// the catalog ranking (ports open on a meaningful share of some kind of host)
/// sets the line; see [`TCP_TIER_BOUNDS`].
///
/// [`TARPIT_OPEN_PORTS`]: crate::model::host::TARPIT_OPEN_PORTS
/// [`TCP_TIER_BOUNDS`]: crate::model::port::catalog::TCP_TIER_BOUNDS
pub(crate) const TARPIT_PORTS_IDENTIFIED: usize = crate::model::port::catalog::TCP_TIER_BOUNDS[0];

/// How many of a host's ports must take a connection and say nothing to every
/// question, and more than said anything, before the host is treated as one
/// that answers on every port.
///
/// [`NetworkRole::Tarpit`] is only marked after [`TARPIT_OPEN_PORTS`], by which
/// time an inline-identifying scan has waited out a thousand conversations. A
/// host running real services answers on most of them, so silence gives a
/// tarpit away sooner. Counted only where the identification asked something,
/// since a service that waits to be spoken to is silent to a listener.
///
/// [`NetworkRole::Tarpit`]: crate::model::host::NetworkRole::Tarpit
/// [`TARPIT_OPEN_PORTS`]: crate::model::host::TARPIT_OPEN_PORTS
pub(crate) const SILENT_PORTS_OF_A_TARPIT: usize = TARPIT_PORTS_IDENTIFIED;

/// The open ports a pass leaves unidentified on hosts that answer on every
/// port, counted per host, for one line each once the pass has decided.
///
/// Such a host carries [`NetworkRole::Tarpit`] or has given itself away by its
/// silence ([`SILENT_PORTS_OF_A_TARPIT`]). Its likeliest ports
/// ([`TARPIT_PORTS_IDENTIFIED`]) are still identified; the rest keep the port
/// scan's record. Filed as a shortfall, and reported once per host.
///
/// [`NetworkRole::Tarpit`]: crate::model::host::NetworkRole::Tarpit
#[derive(Debug, Default)]
pub(crate) struct Tarpits {
    /// Per host, the ports passed over.
    ///
    /// Counted once the pass has settled them, and only those found open: an
    /// inline-identifying scan decides before it knows whether a port is open.
    passed_over: Mutex<std::collections::BTreeMap<ScopedIp, PassedOver>>,
}

/// What a [`Tarpits`] passed over on one host, and the most ports it had
/// heard nothing on when it did.
#[derive(Debug, Default)]
struct PassedOver {
    ports: BTreeSet<(u16, Protocol)>,
    silent: usize,
}

impl Tarpits {
    /// Whether `number` over `protocol` on `host` is to be identified: every port
    /// is, except one beyond the likeliest on a host marked a tarpit or given
    /// away by its silence in `crowd`.
    pub(crate) fn identifies(
        &self,
        host: &Host,
        crowd: Option<&Crowd>,
        number: u16,
        protocol: Protocol,
    ) -> bool {
        let silent = crowd.and_then(Crowd::answers_nothing);
        if !host.network_roles().contains(&NetworkRole::Tarpit) && silent.is_none() {
            return true;
        }
        if likeliest(protocol).contains(&number) {
            return true;
        }
        let mut passed_over = self
            .passed_over
            .lock()
            .unwrap_or_else(|held| held.into_inner());
        let host = passed_over.entry(host.scoped_ip()).or_default();
        host.ports.insert((number, protocol));
        host.silent = host.silent.max(silent.unwrap_or(0));
        false
    }

    /// Reports, per host, how many open ports were left unidentified, at the
    /// console and in the report as a shortfall of `kind`.
    pub(crate) fn report(&self, ctx: &ScanContext, kind: ScannerKind) {
        let passed_over = std::mem::take(
            &mut *self
                .passed_over
                .lock()
                .unwrap_or_else(|held| held.into_inner()),
        );
        for (host, passed) in passed_over {
            let counted = ctx.read_host(host.clone(), |recorded| {
                let left = recorded
                    .ports()
                    .filter(|port| port.state() == PortState::Open)
                    .filter(|port| passed.ports.contains(&(port.number(), port.protocol())))
                    .count();
                let why = match recorded.network_roles().contains(&NetworkRole::Tarpit) {
                    true => Why::Open(recorded.open_port_count()),
                    false => Why::Silent(passed.silent),
                };
                (left, why)
            });
            let Some((count, why)) = counted.filter(|(count, _)| *count > 0) else {
                continue;
            };
            warn!("{}", Self::line(&host, count, why));
            ctx.file_cut_short(kind, Self::summary(&host, count, why));
        }
    }

    /// The console line for `count` ports of `host`.
    fn line(host: &ScopedIp, count: usize, why: Why) -> String {
        let why = match why {
            Why::Open(_) => "tarpit".to_owned(),
            Why::Silent(silent) => format!("said nothing on {silent}"),
        };
        format!("{host}: {count} open ports not fingerprinted ({why})")
    }

    /// The report's entry for `count` ports of `host`.
    fn summary(host: &ScopedIp, count: usize, why: Why) -> String {
        let why = match why {
            Why::Open(open) => format!("a host open on {open} ports answers everything"),
            Why::Silent(silent) => {
                format!("{silent} of its ports took a connection and said nothing when asked")
            }
        };
        format!(
            "{host}: {count} open ports were not fingerprinted: {why}, and once it \
             was known for that only its likeliest were asked what they run"
        )
    }
}

/// What gave a host passed over by [`Tarpits`] away.
#[derive(Debug, Clone, Copy)]
enum Why {
    /// It is marked a tarpit, open on this many ports.
    Open(usize),
    /// It had said nothing on this many ports when the pass began passing
    /// its ports over.
    Silent(usize),
}

/// One open port to identify, and the path to it.
struct Target {
    /// The host's address, carrying the interface a link-local one was seen
    /// on.
    address: ScopedIp,
    /// The port number.
    number: u16,
    /// The transport it was found open over.
    protocol: Protocol,
    /// What the measured path to the host adds to every wait on the port.
    path: PathAllowance,
}

/// What one port's fingerprint attempt produced. An open port that refused a
/// connection ([`Unreachable`](Self::Unreachable)) is a shortfall the report
/// shows; a silent UDP port ([`Quiet`](Self::Quiet)) is not.
enum Attempt {
    /// The port answered. Boxed: much larger than the other two variants.
    Identified(Box<Identified>),
    /// The connection could not be made; the port keeps its discovery-phase name
    /// and the scan covered less than it was asked to.
    Unreachable {
        /// The address the connection was aimed at.
        ip: ScopedIp,
        /// The port number, named alongside the address in the reason.
        number: u16,
        /// Why it failed.
        reason: Unreached,
    },
    /// Nothing was learned and nothing went wrong.
    Quiet,
}

/// Why an open port could not be asked what it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Unreached {
    /// Nothing answered the connection within this long, which is the connect
    /// budget with the path's allowance on top.
    Silent(Duration),
    /// The process had no socket to connect with, for as long as it waited
    /// for one.
    Starved,
    /// The connection failed some other way.
    Failed {
        /// The kind of failure, which is what a console line names.
        kind: std::io::ErrorKind,
        /// The failure in the operating system's words.
        said: String,
    },
}

impl Unreached {
    /// Why a connection given `within` to connect failed with `error`.
    fn of(error: std::io::Error, within: Duration) -> Self {
        if descriptors::exhausted(&error) {
            Self::Starved
        } else if error.kind() == std::io::ErrorKind::TimedOut {
            Self::Silent(within)
        } else {
            Self::Failed {
                kind: error.kind(),
                said: error.to_string(),
            }
        }
    }

    /// The reason in the report's words.
    fn said(&self) -> String {
        match self {
            Self::Silent(within) => format!("no answer within {:?}", tenths(*within)),
            Self::Starved => descriptors::starved(descriptors::PATIENCE),
            Self::Failed { said, .. } => said.clone(),
        }
    }

    /// The reason in the few words a console line has room for.
    fn terse(&self) -> String {
        match self {
            Self::Silent(within) => format!("no answer in {:?}", tenths(*within)),
            Self::Starved => descriptors::starved_briefly(),
            Self::Failed { kind, .. } => kind.to_string(),
        }
    }
}

/// `duration` to the nearest tenth of a second.
fn tenths(duration: Duration) -> Duration {
    Duration::from_millis(((duration.as_millis() + 50) / 100 * 100) as u64)
}

/// What a port that answered said, for [`Attempt::Identified`].
struct Identified {
    /// The store key to write back under.
    ip: ScopedIp,
    /// The port as the fingerprint engine refined it.
    port: Port,
    /// What the service said about the machine behind it.
    about_the_host: crate::fingerprint::AboutTheHost,
    /// The responses it drew, kept for the detection phase to read.
    banners: Vec<String>,
    /// Whether a later connection was refused a socket, so the result is a
    /// floor.
    identified_in_part: bool,
}

/// Connects to one open port and fingerprints it.
///
/// A link-local address with no recorded interface has no socket address and is
/// skipped with a log line.
///
/// Every connection leaves by `egress`, and every wait allows for the target's
/// path. A TCP port is identified in its host's `crowd`.
async fn fingerprint_one(
    target: Target,
    detection: ServiceDetection,
    egress: Egress,
    crowd: Arc<Crowd>,
) -> Attempt {
    let Target {
        address: target,
        number: port_number,
        protocol,
        path,
    } = target;
    let Some(addr) = target.to_socket_addr(port_number) else {
        warn!(
            verbosity = 2,
            "cannot fingerprint {}: no interface recorded for a link-local address",
            target.endpoint(port_number)
        );
        return Attempt::Quiet;
    };

    // Seed the same baseline the connect scanner uses, then let the engine
    // refine it over the live exchange.
    let port = crate::fingerprint::baseline_port(port_number, protocol, PortState::Open);

    // A TCP port waits for its pacing slot first, holding no socket share and
    // spending no connect budget. A stop or an expired host while waiting
    // leaves the port as recorded. UDP datagrams each wait as they are sent.
    let slot = match protocol {
        Protocol::Tcp => match egress.slot(addr.ip()).await {
            Ok(slot) => Some(slot),
            Err(_withheld) => return Attempt::Quiet,
        },
        _ => None,
    };

    // One socket share for the whole identification, whose connections are
    // sequential; see `descriptors`.
    let _descriptor = descriptors::gate()
        .acquire()
        .await
        .expect("the descriptor gate is never closed");

    let (port, about_the_host, banners, identified_in_part) = match (protocol, slot) {
        (Protocol::Tcp, Some(slot)) => {
            let within = path.over(CONNECT_PROBE_TIMEOUT);
            let stream = match egress.connect_timed(slot, addr, within).await {
                Ok(stream) => stream,
                Err(e) => {
                    return Attempt::Unreachable {
                        ip: target,
                        number: port_number,
                        reason: Unreached::of(e, within),
                    };
                }
            };
            let identified = crowd
                .identify(target.clone(), stream, port, detection, &egress, path)
                .await;
            (
                identified.port,
                identified.about_the_host,
                identified.responses,
                identified.starved,
            )
        }
        // A silent UDP port is not a failure. One with no socket to ask is
        // filed as starved.
        (Protocol::Udp, _) => {
            match crate::fingerprint::fingerprint_udp_on(addr, port, &egress, path).await {
                Some(identified) if identified.starved => {
                    return Attempt::Unreachable {
                        ip: target,
                        number: port_number,
                        reason: Unreached::Starved,
                    };
                }
                Some(identified) => (
                    identified.port,
                    identified.about_the_host,
                    identified.responses,
                    false,
                ),
                None => return Attempt::Quiet,
            }
        }
        // No SCTP client stack: an open SCTP port keeps its scan name.
        (Protocol::Sctp, _) | (Protocol::Tcp, None) => return Attempt::Quiet,
    };

    // The scoped key, so a link-local address does not fork the host's record.
    Attempt::Identified(Box::new(Identified {
        ip: target,
        port,
        about_the_host,
        banners,
        identified_in_part,
    }))
}

/// Every host a pass identifies ports of, each as the [`Crowd`] its
/// identifications make.
#[derive(Debug, Default)]
pub(crate) struct Crowds {
    hosts: Mutex<HashMap<IpAddr, Arc<Crowd>>>,
}

impl Crowds {
    /// The crowd of `host`'s identifications in this pass, asking by `name`
    /// where a target reached the host by one.
    pub(crate) fn of(&self, host: IpAddr, name: Option<Arc<str>>) -> Arc<Crowd> {
        let mut hosts = self.hosts.lock().unwrap_or_else(|held| held.into_inner());
        Arc::clone(hosts.entry(host).or_insert_with(|| {
            Arc::new(Crowd {
                name,
                ..Crowd::default()
            })
        }))
    }

    /// Asks again, each with its host to itself, every port a [`Crowd`] owes
    /// a second asking, and files what each draws, for a pass `kind` whose
    /// identifications have all finished.
    ///
    /// A host's ports are asked one after another, hosts side by side, each
    /// connection taking one socket share. A stopped scan asks nothing more, and
    /// the ports keep what their first identification drew.
    ///
    /// Returns each port whose second asking the file limit cut short, for the
    /// pass to count as identified in part. A port already counted for its first
    /// asking is not returned again.
    pub(crate) async fn ask_again(
        &self,
        ctx: &ScanContext,
        kind: ScannerKind,
    ) -> Vec<(ScopedIp, u16)> {
        let crowds: Vec<Arc<Crowd>> = {
            let hosts = self.hosts.lock().unwrap_or_else(|held| held.into_inner());
            hosts.values().cloned().collect()
        };
        let mut in_part = Vec::new();
        let mut pool = ProbePool::new(
            CONNECT_CONCURRENCY,
            ctx.clone(),
            kind,
            |asked: AskedAlone, _audit| {
                for (key, found) in asked.named {
                    let (number, protocol) = (found.port.number(), found.port.protocol());
                    ctx.record_responses(key.clone(), number, protocol, found.responses);
                    write_back(ctx, key, found.port, found.about_the_host);
                }
                in_part.extend(asked.in_part);
            },
        );
        for crowd in crowds {
            let owed = crowd.owed();
            if owed.is_empty() {
                continue;
            }
            if ctx.handle.should_stop() {
                break;
            }
            pool.admit(crowd.ask_alone(owed, ctx.clone())).await;
        }
        pool.drain().await;
        drop(pool);
        in_part
    }
}

impl Crowds {
    /// Says once which ports took the connection and answered nothing they
    /// were asked, for a pass whose identifications, second askings
    /// included, have all finished.
    ///
    /// Such a port keeps the name its number gives it, marked as inferred; this
    /// says so at verbosity 1, as one line however many ports it covers.
    pub(crate) fn report_silence(&self) {
        let silent: Vec<(ScopedIp, u16)> = {
            let hosts = self.hosts.lock().unwrap_or_else(|held| held.into_inner());
            hosts
                .values()
                .flat_map(|crowd| {
                    std::mem::take(
                        &mut *crowd.silent.lock().unwrap_or_else(|held| held.into_inner()),
                    )
                })
                .collect()
        };
        if let Some(line) = silence_line(&silent) {
            crate::info!(verbosity = 1, "{line}");
        }
    }
}

/// The console line for `silent`, named from the first of them, or none
/// where there are none.
fn silence_line(silent: &[(ScopedIp, u16)]) -> Option<String> {
    let (ip, number) = silent
        .iter()
        .min_by_key(|(ip, number)| (ip.addr(), *number))?;
    let ports = match silent.len() - 1 {
        0 => ip.endpoint(*number),
        rest => format!("{} and {rest} more", ip.endpoint(*number)),
    };
    Some(format!("{ports} said nothing when asked (unidentified)"))
}

/// The identifications of one host's ports in one pass, which the host
/// answers side by side or in turn as it is built to.
///
/// A pass identifies a host's ports at once. A host serving several ports from
/// a single worker answers them in turn, so a port queued behind a slow answer
/// can run out of wait and be reported silent though a live service is there.
///
/// So a port that drew nothing while another of its host's ports was being
/// identified is asked again with the host to itself, if the host answered one
/// of the pass's questions late. A prompt host has no queue to wait out, and a
/// host that answered nothing (a middlebox taking every connection, say) would
/// only be asked everything twice.
///
/// Second askings wait until every first identification has finished (see
/// [`Crowds::ask_again`]); meanwhile the port is handed back with what it drew,
/// holding no pool place or socket share. They also wait until the host has
/// worked through the questions still queued from the pass; see [`Backlog`].
///
/// Ports are asked again one after another, and only while second askings draw
/// something at least as often as nothing, so a host with hundreds of
/// genuinely silent ports costs at most one walk more than its answers repay;
/// see [`Crowd::ask_alone`].
///
/// Company is counted per host, as the detection stage counts it; see
/// [`HostContention`].
#[derive(Debug, Default)]
pub(crate) struct Crowd {
    /// The host's identifications in flight and begun.
    contention: HostContention,
    /// Whether the host answered one of the pass's questions only after more
    /// than half the wait it was given; see [`Fingerprinted::answered_late`].
    answered_late: AtomicBool,
    /// The ports owed a second asking, in the order their first ended.
    owed: Mutex<Vec<Owed>>,
    /// The questions the host was left with that nobody waits for.
    backlog: Mutex<Backlog>,
    /// The name a target reached the host by, used when asking its web ports;
    /// see [`ZondConfig::target_names`](crate::config::ZondConfig::target_names).
    name: Option<Arc<str>>,
    /// The ports that took the connection and answered nothing before their
    /// wait ran out; see [`Crowds::report_silence`].
    silent: Mutex<Vec<(ScopedIp, u16)>>,
    /// How many of the host's first identifications drew something.
    answered: AtomicUsize,
    /// How many asked a question and waited out silence on every one; see
    /// [`SILENT_PORTS_OF_A_TARPIT`].
    unanswered: AtomicUsize,
}

/// A port a [`Crowd`] owes a second asking, and what that asking needs.
#[derive(Debug)]
struct Owed {
    /// What the port's findings are filed under.
    key: ScopedIp,
    /// Where it was reached.
    addr: std::net::SocketAddr,
    /// The port as the scan recorded it, before its identification.
    port: Port,
    detection: ServiceDetection,
    egress: Egress,
    path: PathAllowance,
    /// Whether the file limit cut the first identification short, so the port
    /// is already counted as identified in part.
    in_part: bool,
}

/// What a [`Crowd`]'s second askings came to.
#[derive(Debug, Default)]
struct AskedAlone {
    /// Each port that drew something, with what it drew, under the key it is
    /// filed under.
    named: Vec<(ScopedIp, Fingerprinted)>,
    /// Each port whose second asking the file limit cut short and that was not
    /// already counted; see [`Crowds::ask_again`].
    in_part: Vec<(ScopedIp, u16)>,
}

impl Crowd {
    /// Identifies the port `stream` reached, as
    /// [`fingerprint_tcp_via`](crate::fingerprint::fingerprint_tcp_via) does,
    /// and owes it a second asking where its silence may have been the host's
    /// queue. Findings are filed under `key`.
    pub(crate) async fn identify(
        &self,
        key: ScopedIp,
        stream: TcpStream,
        port: Port,
        detection: ServiceDetection,
        egress: &Egress,
        path: PathAllowance,
    ) -> Fingerprinted {
        let addr = stream.peer_addr().ok();
        let visit = self.contention.enter();
        let found = crate::fingerprint::fingerprint_tcp_via(
            stream,
            port.clone(),
            detection,
            egress,
            path,
            self.name.clone(),
        )
        .await;
        let alone = visit.leave();
        self.heard(&found);
        if !found.responses.is_empty() {
            self.answered.fetch_add(1, Ordering::Relaxed);
        } else if found.ran_out_waiting && !found.starved && detection.sends() {
            self.unanswered.fetch_add(1, Ordering::Relaxed);
        }
        if found.responses.is_empty() && found.ran_out_waiting && !found.starved {
            self.silent
                .lock()
                .unwrap_or_else(|held| held.into_inner())
                .push((key.clone(), port.number()));
        }
        self.backlog
            .lock()
            .unwrap_or_else(|held| held.into_inner())
            .left(found.waited_in_vain);
        if let (Some(addr), false, true, true) = (
            addr,
            alone,
            found.responses.is_empty(),
            found.ran_out_waiting,
        ) {
            self.owed
                .lock()
                .unwrap_or_else(|held| held.into_inner())
                .push(Owed {
                    key,
                    addr,
                    port,
                    detection,
                    egress: egress.clone(),
                    path,
                    in_part: found.starved,
                });
        }
        found
    }

    /// How many of the host's ports have said nothing when asked, where that is
    /// enough (and more than answered) to treat the host as a tarpit; `None`
    /// otherwise. See [`SILENT_PORTS_OF_A_TARPIT`].
    pub(crate) fn answers_nothing(&self) -> Option<usize> {
        let unanswered = self.unanswered.load(Ordering::Relaxed);
        (unanswered >= SILENT_PORTS_OF_A_TARPIT
            && unanswered > self.answered.load(Ordering::Relaxed))
        .then_some(unanswered)
    }

    /// The ports this crowd owes a second asking, taken, or none where the
    /// host never answered late.
    fn owed(&self) -> Vec<Owed> {
        let owed = std::mem::take(&mut *self.owed.lock().unwrap_or_else(|held| held.into_inner()));
        match self.answered_late.load(Ordering::Relaxed) {
            true => owed,
            false => Vec::new(),
        }
    }

    /// Asks each of `owed` again in turn, with the host to itself, and returns
    /// what drew anything and which the file limit cut short. A port that draws
    /// nothing again keeps its first identification.
    ///
    /// Each dials afresh once the host's [`Backlog`] is waited out. Asking ends
    /// once the host has drawn nothing more often than something (see
    /// [`Crowd`]); a port with no local socket counts neither way. It also ends
    /// on a scan stop, raced against every wait, or when the host's budget runs
    /// out.
    async fn ask_alone(self: Arc<Self>, owed: Vec<Owed>, ctx: ScanContext) -> AskedAlone {
        let mut asked = AskedAlone::default();
        let mut silent = 0usize;
        let through = self
            .backlog
            .lock()
            .unwrap_or_else(|held| held.into_inner())
            .through();
        if let Some(through) = through
            && ctx
                .handle
                .or_stopped(tokio::time::sleep_until(through))
                .await
                .is_none()
        {
            return asked;
        }
        for Owed {
            key,
            addr,
            port,
            detection,
            egress,
            path,
            in_part,
        } in owed
        {
            if silent > asked.named.len() || ctx.handle.should_stop() || ctx.host_expired(addr.ip())
            {
                break;
            }
            // The pacing slot first; a stop or an expired host while waiting
            // asks nothing more.
            let Ok(slot) = egress.slot(addr.ip()).await else {
                break;
            };
            // One socket share for the identification's sequential
            // connections; see `descriptors`.
            let _descriptor = descriptors::gate()
                .acquire()
                .await
                .expect("the descriptor gate is never closed");
            let number = port.number();
            let name = self.name.clone();
            let egress = &egress;
            let identified = async {
                let stream = egress
                    .connect_timed(slot, addr, path.over(CONNECT_PROBE_TIMEOUT))
                    .await?;
                Ok::<_, std::io::Error>(
                    crate::fingerprint::fingerprint_tcp_via(
                        stream, port, detection, egress, path, name,
                    )
                    .await,
                )
            };
            let Some(identified) = ctx.handle.or_stopped(identified).await else {
                break;
            };
            // No local socket is not the host's silence.
            let again = match identified {
                Ok(again) => again,
                Err(e) if descriptors::exhausted(&e) => {
                    if !in_part {
                        asked.in_part.push((key, number));
                    }
                    continue;
                }
                Err(_) => {
                    silent += 1;
                    continue;
                }
            };
            self.heard(&again);
            if again.starved && !in_part {
                asked.in_part.push((key.clone(), number));
            }
            if !again.responses.is_empty() {
                self.silent
                    .lock()
                    .unwrap_or_else(|held| held.into_inner())
                    .retain(|(silent, port)| !(*silent == key && *port == number));
                asked.named.push((key, again));
            } else if !again.starved {
                silent += 1;
            }
        }
        asked
    }

    /// Notes how the host answered one of its identifications.
    fn heard(&self, found: &Fingerprinted) {
        if found.answered_late {
            self.answered_late.store(true, Ordering::Relaxed);
        }
    }
}

/// What a host serving one question at a time may still be working through
/// after the pass's identifications of it are over: the questions whose wait
/// ran out. Each holds the host no longer than its wait (a host that takes
/// longer cannot be identified anyway), so the host is free at the latest when
/// the last identification left plus those waits.
///
/// A second asking waits out that bound, capped at [`BACKLOG_WAIT_LIMIT`],
/// since a host that answers late but in parallel was left nothing.
#[derive(Debug, Default)]
struct Backlog {
    /// The waits that ran out, together.
    waited_in_vain: Duration,
    /// When the last identification of the host left.
    last_left: Option<tokio::time::Instant>,
}

impl Backlog {
    /// Notes an identification leaving, whose waits that ran out were given
    /// `waited_in_vain` together.
    fn left(&mut self, waited_in_vain: Duration) {
        self.waited_in_vain += waited_in_vain;
        self.last_left = Some(tokio::time::Instant::now());
    }

    /// When a question put to the host is the next it serves, at the latest,
    /// or `None` where the host was left nothing.
    fn through(&self) -> Option<tokio::time::Instant> {
        let last_left = self.last_left?;
        if self.waited_in_vain.is_zero() {
            return None;
        }
        let wait = self.waited_in_vain.min(BACKLOG_WAIT_LIMIT);
        Some(last_left + wait)
    }
}

/// The longest a second asking waits for its host to work through what the
/// pass left it; see [`Backlog`].
///
/// Ten seconds covers abandoned questions on a few ports at about a second each
/// for a single-worker host, and is short beside the identifications that
/// follow.
const BACKLOG_WAIT_LIMIT: Duration = Duration::from_secs(10);

/// Folds a freshly fingerprinted port back into its host and announces the
/// update. [`Port::merge`] is confidence-driven, so the fingerprint overwrites
/// the discovery phase's name-only baseline.
///
/// `about_the_host` is what the service said about the machine (its operating
/// system, say), filed on the host.
fn write_back(
    ctx: &ScanContext,
    key: ScopedIp,
    port: Port,
    about_the_host: crate::fingerprint::AboutTheHost,
) {
    ctx.update_host(key, |host| {
        host.add_port(port);

        if about_the_host.is_empty() {
            return;
        }

        // Combined with the host's other evidence: a banner agreeing with the
        // wire is worth more than either.
        about_the_host.apply(host);
    });
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
    use crate::scanner::session::ScanSession;
    use crate::testing::loopback::{SilentPort, accept_from_this_process, from_this_process};
    use std::net::IpAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A port that takes the connection and answers nothing is reported once at
    /// the console, and a port that answered is not. Otherwise a silent listener
    /// on 2222 reads like an SSH server.
    #[tokio::test]
    async fn a_port_that_answers_nothing_is_said_to_have_answered_nothing() {
        use crate::testing::loopback::{SilentPort, accept_from_this_process};

        let silent = SilentPort::open();
        let greeting = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let speaks = greeting.local_addr().expect("a local address");
        tokio::spawn(async move {
            while let Ok(mut sock) = accept_from_this_process(&greeting).await {
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await;
            }
        });

        let crowds = Crowds::default();
        for addr in [silent.addr(), speaks] {
            let key: ScopedIp = addr.ip().into();
            let stream = TcpStream::connect(addr).await.expect("connects");
            let port =
                crate::fingerprint::baseline_port(addr.port(), Protocol::Tcp, PortState::Open);
            crowds
                .of(addr.ip(), None)
                .identify(
                    key,
                    stream,
                    port,
                    ServiceDetection::Banner,
                    &Egress::KERNEL,
                    PathAllowance::NONE,
                )
                .await;
        }

        let silent_ports: Vec<(ScopedIp, u16)> = crowds
            .of(silent.addr().ip(), None)
            .silent
            .lock()
            .expect("not poisoned")
            .clone();
        let key: ScopedIp = silent.addr().ip().into();
        assert_eq!(silent_ports, vec![(key.clone(), silent.addr().port())]);
        assert_eq!(
            silence_line(&silent_ports).as_deref(),
            Some(
                format!(
                    "{} said nothing when asked (unidentified)",
                    key.endpoint(silent.addr().port())
                )
                .as_str()
            )
        );
        assert_eq!(
            silence_line(&[(key.clone(), 2222), (key.clone(), 22)]).as_deref(),
            Some(
                format!(
                    "{} and 1 more said nothing when asked (unidentified)",
                    key.endpoint(22)
                )
                .as_str()
            )
        );
    }

    /// Many quiet ports collapse into one report entry and one console line.
    #[test]
    fn many_quiet_ports_collapse_into_one_line() {
        let mut quiet = QuietPorts::default();
        let ip: ScopedIp = "192.0.2.1".parse::<IpAddr>().expect("an address").into();
        for port in 0..83u16 {
            quiet.record(
                &ip,
                1000 + port,
                Unreached::Silent(Duration::from_millis(1_500)),
            );
        }

        let first = quiet.first.as_deref().expect("a first port");
        let reason = quiet.reason.as_ref().expect("a reason");
        assert_eq!(
            QuietPorts::summary(first, reason, quiet.count),
            "192.0.2.1:1000 and 82 other ports could not be fingerprinted: no answer within 1.5s"
        );
        assert_eq!(
            QuietPorts::line(first, reason, quiet.count),
            "192.0.2.1:1000 and 82 more not fingerprinted (no answer in 1.5s)"
        );
    }

    /// Ports identified in part because of the file limit share one cut-short
    /// entry naming the first, the count and the limit.
    #[test]
    fn ports_identified_in_part_are_one_failure_naming_the_limit() {
        let (session, ctx) = ScanSession::new();
        let mut in_part = QuietPorts::default();
        let ip: ScopedIp = "192.0.2.1".parse::<IpAddr>().expect("an address").into();
        for port in [443u16, 8443, 9443] {
            in_part.record(&ip, port, Unreached::Starved);
        }

        in_part.report_in_part(&ctx);

        let failures = ctx.take_failures();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(
            failures[0].reason().starts_with(
                "192.0.2.1:443 and 2 other ports identified in part: file descriptor limit"
            ),
            "{}",
            failures[0].reason()
        );
        assert!(failures[0].is_cut_short(), "a limit, not a fault");
        drop(session);
    }

    /// One port is named alone, without "and 0 other ports".
    #[test]
    fn one_quiet_port_is_named_alone() {
        let refused = Unreached::of(
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused"),
            CONNECT_PROBE_TIMEOUT,
        );
        assert_eq!(
            QuietPorts::summary("192.0.2.1:22", &refused, 1),
            "192.0.2.1:22 could not be fingerprinted: connection refused"
        );
        assert_eq!(
            QuietPorts::summary("192.0.2.1:22", &refused, 2),
            "192.0.2.1:22 and 1 other port could not be fingerprinted: connection refused"
        );
        assert_eq!(
            QuietPorts::line("192.0.2.1:22", &refused, 1),
            "192.0.2.1:22 not fingerprinted (connection refused)"
        );
    }

    /// An IPv6 endpoint keeps its brackets, so the port is not read as another
    /// group of the address.
    #[test]
    fn an_ipv6_endpoint_stays_bracketed() {
        let mut quiet = QuietPorts::default();
        let ip: ScopedIp = "2001:db8::1".parse::<IpAddr>().expect("an address").into();
        quiet.record(&ip, 443, Unreached::Silent(CONNECT_PROBE_TIMEOUT));

        assert_eq!(quiet.first.as_deref(), Some("[2001:db8::1]:443"));
    }

    #[tokio::test]
    async fn detect_fingerprints_an_open_tcp_port_end_to_end() {
        // A loopback service that greets with an SSH banner.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok(mut sock) = accept_from_this_process(&listener).await {
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n").await;
            }
        });

        // As the SYN scanner leaves it: open, with only the baseline name.
        let (session, ctx) = ScanSession::new();
        let ip = addr.ip();
        let mut host = Host::new(ip);
        host.add_port(Port::new(addr.port(), Protocol::Tcp, PortState::Open));
        session.hosts().insert(ip, host);

        detect(&ctx, ServiceDetection::default(), Protocol::Tcp).await;

        let host = session.hosts().get(ip).unwrap();
        let port = host
            .ports()
            .find(|p| p.number() == addr.port())
            .expect("port present");
        let service = port.service().expect("service identified");
        assert_eq!(service.name(), "ssh");
        assert_eq!(service.product(), Some("OpenSSH"));
        assert_eq!(service.version(), Some("9.6p1"));
    }

    /// Detection turned off opens no connection.
    #[tokio::test]
    async fn detection_turned_off_connects_to_nothing() {
        let (session, ctx) = ScanSession::new();
        let silent = SilentPort::open();
        let addr = silent.addr();
        ctx.update_host(addr.ip(), |host| {
            host.add_port(Port::new(addr.port(), Protocol::Tcp, PortState::Open));
        });

        detect(&ctx, ServiceDetection::Off, Protocol::Tcp).await;

        assert_eq!(
            crate::transport::dial::dialled::to(addr),
            0,
            "a level that connects to nothing connected to the port"
        );
        drop(session);
    }

    /// A scan stopped with open ports still to identify opens nothing further
    /// and names the pass it left.
    #[tokio::test]
    async fn a_stop_before_identification_names_the_pass_it_left() {
        let (session, ctx) = ScanSession::new();
        let unreachable: IpAddr = "192.0.2.1".parse().expect("a documentation address");
        ctx.update_host(unreachable, |host| {
            host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        });
        ctx.handle.abort();

        detect(&ctx, ServiceDetection::default(), Protocol::Tcp).await;

        assert_eq!(ctx.take_passes_cut(), [crate::report::Pass::Services]);
        drop(session);
    }

    #[tokio::test]
    async fn detect_is_a_no_op_with_no_open_ports() {
        let (session, ctx) = ScanSession::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let mut host = Host::new(ip);
        // A closed port must not be probed.
        host.add_port(Port::new(9, Protocol::Tcp, PortState::Closed));
        session.hosts().insert(ip, host);

        detect(&ctx, ServiceDetection::default(), Protocol::Tcp).await;

        let host = session.hosts().get(ip).unwrap();
        let port = host.ports().find(|p| p.number() == 9).unwrap();
        assert!(port.service().is_none());
    }

    /// A listen-only port is sent nothing even at the most thorough level, while
    /// the same port off the list is asked. A printer prints what arrives.
    #[tokio::test]
    async fn a_listen_only_port_is_sent_nothing_where_any_other_is_asked() {
        let mut received = Vec::new();
        for listen_only in [true, false] {
            let silent = SilentPort::open();
            let addr = silent.addr();
            let ports = match listen_only {
                true => BTreeSet::from([addr.port()]),
                false => BTreeSet::new(),
            };
            let (session, ctx) = ScanSession::builder().listening_only_to(ports).build();
            let ip = addr.ip();
            let mut host = Host::new(ip);
            host.add_port(Port::new(addr.port(), Protocol::Tcp, PortState::Open));
            session.hosts().insert(ip, host);

            detect(&ctx, ServiceDetection::Thorough, Protocol::Tcp).await;
            received.push(silent.heard());
        }

        assert_eq!(received[0], 0, "a listen-only port was sent a payload");
        assert!(
            received[1] > 0,
            "the same port off the list was asked nothing, so the first half \
             proves nothing"
        );
    }

    /// A level that only listens takes no UDP port, while the default does. Read
    /// off the targets, since a datagram to a port the test does not own leaves
    /// no trace.
    #[test]
    fn a_level_that_only_listens_takes_no_udp_port() {
        let (session, ctx) = ScanSession::new();
        let ip: IpAddr = "192.0.2.1".parse().expect("a documentation address");
        ctx.update_host(ip, |host| {
            host.add_port(Port::new(161, Protocol::Udp, PortState::Open));
        });
        assert!(
            crate::fingerprint::reads_replies(161, Protocol::Udp),
            "SNMP is a UDP port the pass would otherwise ask"
        );

        let taken = |level| {
            fingerprintable_ports(
                &ctx,
                Protocol::Udp,
                level,
                Which::Every,
                &Tarpits::default(),
            )
            .len()
        };
        assert_eq!(
            taken(ServiceDetection::Banner),
            0,
            "a listening level sent a datagram"
        );
        assert_eq!(
            taken(ServiceDetection::Probe),
            1,
            "the default took no UDP port either, so the first half proves nothing"
        );
        drop(session);
    }

    /// A tarpit has only its likeliest ports taken, an ordinary host every open
    /// port, and the tarpit's remainder is one report entry.
    #[test]
    fn a_tarpit_has_only_its_likeliest_ports_taken() {
        use crate::model::port::catalog::top_tcp;

        let (session, ctx) = ScanSession::new();
        let tarpit: IpAddr = "192.0.2.1".parse().expect("a documentation address");
        let ordinary: IpAddr = "192.0.2.2".parse().expect("a documentation address");
        let range = 1..=1_200u16;
        ctx.update_host(tarpit, |host| {
            for number in range.clone() {
                host.add_port(Port::new(number, Protocol::Tcp, PortState::Open));
            }
        });
        ctx.update_host(ordinary, |host| {
            for number in [22, 51_000] {
                host.add_port(Port::new(number, Protocol::Tcp, PortState::Open));
            }
        });

        let tarpits = Tarpits::default();
        let targets = fingerprintable_ports(
            &ctx,
            Protocol::Tcp,
            ServiceDetection::Probe,
            Which::Every,
            &tarpits,
        );
        let taken = |address: IpAddr| {
            let mut numbers: Vec<u16> = targets
                .iter()
                .filter(|target| target.address.addr() == address)
                .map(|target| target.number)
                .collect();
            numbers.sort_unstable();
            numbers
        };

        let mut likeliest: Vec<u16> = top_tcp(TARPIT_PORTS_IDENTIFIED)
            .iter()
            .copied()
            .filter(|number| range.contains(number))
            .collect();
        likeliest.sort_unstable();
        assert!(
            !likeliest.is_empty(),
            "the range holds some of the likeliest"
        );
        assert_eq!(taken(tarpit), likeliest, "the tarpit's ports taken");
        assert_eq!(
            taken(ordinary),
            [22, 51_000],
            "the ordinary host's ports taken"
        );

        tarpits.report(&ctx, ScannerKind::Service);
        let failures = ctx.take_failures();
        let left = range.len() - likeliest.len();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(
            failures[0].reason().starts_with(&format!(
                "192.0.2.1: {left} open ports were not fingerprinted"
            )),
            "{}",
            failures[0].reason()
        );
        drop(session);
    }

    /// A service high in a host's range is asked before a block of silent ports
    /// low in it can mark the host a tarpit. Identifications are settled one at
    /// a time, so silence counts as fast as it can.
    #[test]
    fn a_service_above_a_block_of_silent_ports_is_asked_before_the_block_gives_the_host_away() {
        let (session, ctx) = ScanSession::new();
        let address: IpAddr = "192.0.2.1".parse().expect("a documentation address");
        let silent = 1..=150u16;
        let talkative = 50_000;
        ctx.update_host(address, |host| {
            for number in silent.clone().chain([talkative]) {
                host.add_port(Port::new(number, Protocol::Tcp, PortState::Open));
            }
        });

        let tarpits = Tarpits::default();
        let targets = fingerprintable_ports(
            &ctx,
            Protocol::Tcp,
            ServiceDetection::Probe,
            Which::Every,
            &tarpits,
        );
        let crowd = Crowd::default();
        let mut asked = Vec::new();
        for target in &targets {
            let identifies = ctx
                .read_host(address, |host| {
                    tarpits.identifies(host, Some(&crowd), target.number, target.protocol)
                })
                .expect("recorded");
            if !identifies {
                continue;
            }
            asked.push(target.number);
            let heard = match target.number == talkative {
                true => &crowd.answered,
                false => &crowd.unanswered,
            };
            heard.fetch_add(1, Ordering::Relaxed);
        }

        assert!(asked.contains(&talkative), "asked only {asked:?}");
        assert!(
            asked.len() < targets.len(),
            "the host's silence still gave it away"
        );
        drop(session);
    }

    /// A host silent on [`SILENT_PORTS_OF_A_TARPIT`] ports, more than it
    /// answered, has only its likeliest identified from then on, and the report
    /// counts what was left. A host that answers as often is identified whole.
    #[test]
    fn a_host_silent_on_its_ports_is_identified_as_a_tarpit_is() {
        use crate::model::port::catalog::top_tcp;

        let (session, ctx) = ScanSession::new();
        let silent: IpAddr = "192.0.2.1".parse().expect("a documentation address");
        let talkative: IpAddr = "192.0.2.2".parse().expect("a documentation address");
        let unlikely = 51_000;
        let likeliest = top_tcp(TARPIT_PORTS_IDENTIFIED)[0];
        assert!(!top_tcp(TARPIT_PORTS_IDENTIFIED).contains(&unlikely));
        for ip in [silent, talkative] {
            ctx.update_host(ip, |host| {
                for number in [likeliest, unlikely] {
                    host.add_port(Port::new(number, Protocol::Tcp, PortState::Open));
                }
            });
        }
        let crowd = |answered, unanswered| Crowd {
            answered: AtomicUsize::new(answered),
            unanswered: AtomicUsize::new(unanswered),
            ..Crowd::default()
        };
        let quiet = crowd(3, SILENT_PORTS_OF_A_TARPIT);
        let busy = crowd(SILENT_PORTS_OF_A_TARPIT, SILENT_PORTS_OF_A_TARPIT);
        let short = crowd(0, SILENT_PORTS_OF_A_TARPIT - 1);

        let tarpits = Tarpits::default();
        let identifies = |ip, crowd: &Crowd, number| {
            ctx.read_host(ip, |host| {
                tarpits.identifies(host, Some(crowd), number, Protocol::Tcp)
            })
            .expect("recorded")
        };
        assert!(!identifies(silent, &quiet, unlikely), "the silent host's");
        assert!(identifies(silent, &quiet, likeliest), "its likeliest");
        assert!(identifies(talkative, &busy, unlikely), "answered as often");
        assert!(identifies(talkative, &short, unlikely), "too few to tell");

        tarpits.report(&ctx, ScannerKind::Service);
        let failures = ctx.take_failures();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(
            failures[0].reason(),
            format!(
                "192.0.2.1: 1 open ports were not fingerprinted: \
                 {SILENT_PORTS_OF_A_TARPIT} of its ports took a connection and said \
                 nothing when asked, and once it was known for that only its \
                 likeliest were asked what they run"
            )
        );
        drop(session);
    }

    /// A steady slow path gets waits a little longer than the path, not the
    /// three round trips a single sample earns; a silent port is waited on
    /// several times in a row.
    #[test]
    fn a_steady_slow_path_is_allowed_for_as_its_round_trips_show() {
        let (session, ctx) = ScanSession::new();
        let host: IpAddr = "192.0.2.1".parse().expect("a documentation address");
        let path = Duration::from_millis(1_900);
        ctx.update_host(host, |record| {
            for _ in 0..10 {
                record.add_rtt(path);
            }
            record.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        });

        let targets = fingerprintable_ports(
            &ctx,
            Protocol::Tcp,
            ServiceDetection::Probe,
            Which::Every,
            &Tarpits::default(),
        );
        let allowed = targets[0].path.over(Duration::ZERO);
        assert!(allowed > path, "the path itself: {allowed:?}");
        assert!(allowed < path * 2, "one sample's three: {allowed:?}");
        drop(session);
    }

    /// An open port that refuses a connection is recorded in the report.
    #[tokio::test]
    async fn a_port_that_refuses_a_connection_is_written_into_the_report() {
        // Nothing answers, but the stack refuses promptly.
        let addr = crate::testing::loopback::refused_port(std::net::IpAddr::from([127, 0, 0, 1]));

        let (session, ctx) = ScanSession::new();
        let ip = addr.ip();
        let mut host = Host::new(ip);
        host.add_port(Port::new(addr.port(), Protocol::Tcp, PortState::Open));
        session.hosts().insert(ip, host);

        detect(&ctx, ServiceDetection::default(), Protocol::Tcp).await;

        let failures = ctx.take_failures();
        assert_eq!(failures.len(), 1, "one unreachable port, one line about it");
        assert!(
            failures[0].reason().contains(&addr.port().to_string()),
            "the failure names the port it is about: {}",
            failures[0].reason()
        );
    }

    /// A loopback service that answers any request after `delay`, standing in
    /// for one behind a slow path.
    async fn behind_a_slow_path(delay: Duration) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok(mut sock) = accept_from_this_process(&listener).await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    if !matches!(sock.read(&mut buffer).await, Ok(n) if n > 0) {
                        return;
                    }
                    tokio::time::sleep(delay).await;
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\
                              Content-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });
        addr
    }

    /// An open port behind a path slower than a reply's own wait is identified,
    /// since every wait allows for the measured round trip.
    #[tokio::test]
    async fn an_open_port_behind_a_slow_path_is_identified_within_the_round_trip_measured() {
        let path = Duration::from_millis(600);
        let addr = behind_a_slow_path(Duration::from_millis(1_300)).await;

        let (session, ctx) = ScanSession::new();
        let ip = addr.ip();
        let mut host = Host::new(ip);
        host.add_rtt(path);
        host.add_port(Port::new(addr.port(), Protocol::Tcp, PortState::Open));
        session.hosts().insert(ip, host);

        detect(&ctx, ServiceDetection::default(), Protocol::Tcp).await;

        let host = session.hosts().get(ip).unwrap();
        let port = host
            .ports()
            .find(|p| p.number() == addr.port())
            .expect("port present");
        assert_eq!(
            port.service().map(|service| service.name()),
            Some("http"),
            "a service answering behind a path of {path:?} went unheard"
        );
    }

    /// A connect timeout is reported with the wait actually given, path
    /// allowance included.
    #[test]
    fn a_connect_behind_a_measured_path_names_the_wait_it_was_given() {
        let within =
            PathAllowance::of_round_trip(Duration::from_millis(1_900)).over(CONNECT_PROBE_TIMEOUT);
        let silent = Unreached::of(std::io::ErrorKind::TimedOut.into(), within);
        assert_eq!(silent.said(), "no answer within 4.5s");
        assert_eq!(
            QuietPorts::line("192.0.2.10:22", &silent, 1),
            "192.0.2.10:22 not fingerprinted (no answer in 4.5s)"
        );
    }

    /// The requests a [`one_worker`] host served, by port and first line.
    type Served = Arc<std::sync::Mutex<Vec<(u16, String)>>>;

    /// A loopback host serving `ports` ports from one worker thread, which takes
    /// all their requests in turn and spends `service` on each HTTP one, like a
    /// small embedded web server. Anything else is closed unanswered. Returns
    /// the ports and the requests served.
    fn one_worker(ports: usize, service: Duration) -> (Vec<u16>, Served) {
        use std::io::{Read, Write};

        let (queue, work) = std::sync::mpsc::channel();
        let mut numbers = Vec::new();
        for _ in 0..ports {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let number = listener.local_addr().unwrap().port();
            numbers.push(number);
            let queue = queue.clone();
            std::thread::spawn(move || {
                for sock in from_this_process(&listener) {
                    if queue.send((number, sock)).is_err() {
                        break;
                    }
                }
            });
        }
        let served = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = Arc::clone(&served);
        std::thread::spawn(move || {
            for (number, mut sock) in work {
                let mut buffer = [0u8; 1024];
                let _ = sock.set_read_timeout(Some(Duration::from_millis(100)));
                let Ok(n) = sock.read(&mut buffer) else {
                    continue;
                };
                let request = String::from_utf8_lossy(&buffer[..n]).into_owned();
                if !request.starts_with("GET ") {
                    continue;
                }
                std::thread::sleep(service);
                let _ = sock.write_all(
                    b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\
                      Content-Length: 0\r\nConnection: close\r\n\r\n",
                );
                let line = request.lines().next().unwrap_or_default().to_owned();
                log.lock().unwrap().push((number, line));
            }
        });
        (numbers, served)
    }

    /// `ports` of loopback, open in the store as a port scan leaves them, and
    /// the session holding them.
    fn open_on_loopback(ports: &[u16]) -> (ScanSession, ScanContext) {
        let (session, ctx) = ScanSession::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let mut host = Host::new(ip);
        for &number in ports {
            host.add_port(Port::new(number, Protocol::Tcp, PortState::Open));
        }
        session.hosts().insert(ip, host);
        (session, ctx)
    }

    /// Two ports one worker serves in turn are both identified: the one queued
    /// behind the other's answer is asked again with the host to itself.
    #[tokio::test]
    async fn ports_one_worker_answers_in_turn_are_each_identified() {
        let (ports, served) = one_worker(2, Duration::from_millis(750));
        let (session, ctx) = open_on_loopback(&ports);

        detect(&ctx, ServiceDetection::default(), Protocol::Tcp).await;

        let host = session
            .hosts()
            .get("127.0.0.1".parse::<IpAddr>().unwrap())
            .unwrap();
        let named: Vec<Option<String>> = ports
            .iter()
            .map(|&number| {
                host.ports()
                    .find(|p| p.number() == number)
                    .and_then(|p| p.service().map(|service| service.name().to_owned()))
            })
            .collect();
        assert_eq!(
            named,
            vec![Some("http".to_owned()), Some("http".to_owned())],
            "a port queued behind its neighbour went unnamed; served: {:?}",
            served.lock().unwrap()
        );
    }

    /// A silent port beside a prompt one is asked once; a prompt host has no
    /// queue to wait out.
    #[tokio::test]
    async fn a_silent_port_beside_a_prompt_one_is_asked_once() {
        let (prompt, _) = one_worker(1, Duration::ZERO);
        let silent = SilentPort::open();
        let (session, ctx) = open_on_loopback(&[prompt[0], silent.addr().port()]);

        detect(&ctx, ServiceDetection::default(), Protocol::Tcp).await;

        // One identification sends what one alone sends; two would double it.
        let once = silent.heard();
        let generic: usize = crate::fingerprint::SignatureDb::global()
            .generic_tcp_probe_payloads()
            .iter()
            .map(Vec::len)
            .sum();
        let (alone_session, alone_ctx) = open_on_loopback(&[silent.addr().port()]);
        detect(&alone_ctx, ServiceDetection::default(), Protocol::Tcp).await;
        let alone = silent.heard() - once;
        assert!(generic > 0 && alone >= generic);
        assert_eq!(
            once, alone,
            "the silent port was sent {once} bytes beside a prompt port and \
             {alone} alone, so it was identified more than once"
        );
        drop((session, alone_session));
    }

    /// What one identification of `silent` in `crowd` sends it.
    async fn identified_in(crowd: &Crowd, silent: &SilentPort) -> usize {
        let before = silent.heard();
        let addr = silent.addr();
        let stream = TcpStream::connect(addr).await.unwrap();
        let port = crate::fingerprint::baseline_port(addr.port(), Protocol::Tcp, PortState::Open);
        let found = crowd
            .identify(
                addr.ip().into(),
                stream,
                port,
                ServiceDetection::default(),
                &Egress::KERNEL,
                PathAllowance::NONE,
            )
            .await;
        assert!(found.responses.is_empty(), "the port says nothing");
        silent.heard() - before
    }

    /// A port owed a second asking is handed back after its first walk and asked
    /// again only once the pass is done, so it holds no pool place or
    /// descriptor meanwhile.
    #[tokio::test]
    async fn a_port_owed_a_second_asking_is_handed_back_before_it_is_asked_again() {
        let silent = SilentPort::open();

        let crowd = Crowd::default();
        crowd.answered_late.store(true, Ordering::Relaxed);
        // Another of the host's ports, still being identified.
        let company = crowd.contention.enter();
        let in_company = identified_in(&crowd, &silent).await;
        drop(company);

        let alone = identified_in(&Crowd::default(), &silent).await;
        assert!(alone > 0);
        assert_eq!(
            in_company, alone,
            "the port was sent {in_company} bytes before it was handed back \
             and {alone} identified once, so it was asked again inside"
        );
    }

    /// The owed port is asked again in full once the pass is done.
    #[tokio::test]
    async fn a_port_owed_a_second_asking_is_asked_again_once_the_pass_is_done() {
        let silent = SilentPort::open();
        let (_session, ctx) = ScanSession::new();
        let crowds = Crowds::default();
        let crowd = crowds.of(silent.addr().ip(), None);
        crowd.answered_late.store(true, Ordering::Relaxed);

        let company = crowd.contention.enter();
        let first = identified_in(&crowd, &silent).await;
        drop(company);
        crowds.ask_again(&ctx, ScannerKind::Service).await;

        assert!(first > 0);
        assert_eq!(silent.heard(), first * 2, "asked once again");
    }

    /// A second asking the file limit cuts short is counted and filed as
    /// identified in part, as a first one is.
    ///
    /// The owed port is set up directly, every descriptor is refused while the
    /// pass closes, and the port refuses connections, so a connection let
    /// through would end the asking at once. The full-table patience is set
    /// short.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_second_asking_the_file_limit_cuts_short_is_counted_identified_in_part() {
        use crate::system::descriptors::testing::{
            in_a_process_of_its_own, refuse_every_descriptor, wait_out_a_full_table_for,
        };

        if !in_a_process_of_its_own(
            module_path!(),
            "a_second_asking_the_file_limit_cuts_short_is_counted_identified_in_part",
        ) {
            return;
        }
        wait_out_a_full_table_for(Duration::from_millis(100));
        let refusing =
            crate::testing::loopback::refused_port(std::net::IpAddr::from([127, 0, 0, 1]));
        let (_session, ctx) = ScanSession::new();
        let crowds = Crowds::default();
        let crowd = crowds.of(refusing.ip(), None);
        crowd.answered_late.store(true, Ordering::Relaxed);
        crowd.owed.lock().unwrap().push(Owed {
            key: refusing.ip().into(),
            addr: refusing,
            port: crate::fingerprint::baseline_port(
                refusing.port(),
                Protocol::Tcp,
                PortState::Open,
            ),
            detection: ServiceDetection::default(),
            egress: Egress::KERNEL,
            path: PathAllowance::NONE,
            in_part: false,
        });

        let held = refuse_every_descriptor();
        close_pass(
            &ctx,
            &crowds,
            &QuietPorts::default(),
            QuietPorts::default(),
            1,
        )
        .await;
        drop(held);

        let failures = ctx.take_failures();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(
            failures[0].reason().starts_with(&format!(
                "{} identified in part",
                ScopedIp::from(refusing.ip()).endpoint(refusing.port())
            )),
            "a second asking refused a socket was not counted: {}",
            failures[0].reason()
        );
    }

    /// A second asking that connects and is then refused a socket for a later
    /// question is counted identified in part, not as a port with nothing to
    /// say.
    ///
    /// The port is a listener nothing accepts from, so the first connection
    /// completes unanswered; then the process's limit is dropped below every
    /// descriptor it holds. Filling the table instead would free a socket when
    /// the first connection closed.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_second_asking_whose_later_questions_find_no_socket_is_counted_identified_in_part() {
        use crate::system::descriptors::testing::{
            in_a_process_of_its_own, refuse_every_descriptor, wait_out_a_full_table_for,
        };
        use std::os::fd::AsRawFd;

        if !in_a_process_of_its_own(
            module_path!(),
            "a_second_asking_whose_later_questions_find_no_socket_is_counted_identified_in_part",
        ) {
            return;
        }
        wait_out_a_full_table_for(Duration::from_millis(100));
        let unanswering = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let addr = unanswering.local_addr().expect("a local address");
        let (_session, ctx) = ScanSession::new();
        let crowds = Crowds::default();
        let crowd = crowds.of(addr.ip(), None);
        crowd.answered_late.store(true, Ordering::Relaxed);
        crowd.owed.lock().unwrap().push(Owed {
            key: addr.ip().into(),
            addr,
            port: crate::fingerprint::baseline_port(addr.port(), Protocol::Tcp, PortState::Open),
            detection: ServiceDetection::default(),
            egress: Egress::KERNEL,
            path: PathAllowance::NONE,
            in_part: false,
        });

        // Waits, holding no descriptor, for the asking's first connection.
        let listening = unanswering.as_raw_fd();
        let refusing = std::thread::spawn(move || {
            let mut waiting = libc::pollfd {
                fd: listening,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one live `pollfd`, and the count says one.
            let ready = unsafe { libc::poll(&raw mut waiting, 1, 30_000) };
            (ready == 1).then(refuse_every_descriptor)
        });
        close_pass(
            &ctx,
            &crowds,
            &QuietPorts::default(),
            QuietPorts::default(),
            1,
        )
        .await;
        let refused = refusing.join().expect("the watch on the listener");
        drop(refused);

        unanswering
            .set_nonblocking(true)
            .expect("a non-blocking listener");
        assert!(
            unanswering.accept().is_ok(),
            "the asking never connected, so its first question was what was refused"
        );
        let failures = ctx.take_failures();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(
            failures[0].reason().starts_with(&format!(
                "{} identified in part",
                ScopedIp::from(addr.ip()).endpoint(addr.port())
            )),
            "an asking whose later questions were refused a socket was not counted: {}",
            failures[0].reason()
        );
    }

    /// A second asking waits out the host's [`Backlog`] before it connects.
    #[tokio::test]
    async fn a_second_asking_waits_out_what_the_pass_left_its_host() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted_tx, mut accepted) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            while let Ok(mut sock) = accept_from_this_process(&listener).await {
                let _ = accepted_tx.send(tokio::time::Instant::now());
                // Says nothing, and holds the connection to its close.
                tokio::spawn(async move {
                    let mut sink = [0u8; 256];
                    while matches!(sock.read(&mut sink).await, Ok(n) if n > 0) {}
                });
            }
        });

        let (_session, ctx) = ScanSession::new();
        let crowds = Crowds::default();
        let crowd = crowds.of(addr.ip(), None);
        crowd.answered_late.store(true, Ordering::Relaxed);
        let company = crowd.contention.enter();
        let found = crowd
            .identify(
                addr.ip().into(),
                TcpStream::connect(addr).await.unwrap(),
                crate::fingerprint::baseline_port(addr.port(), Protocol::Tcp, PortState::Open),
                ServiceDetection::Banner,
                &Egress::KERNEL,
                PathAllowance::NONE,
            )
            .await;
        let left = tokio::time::Instant::now();
        drop(company);
        assert!(!found.waited_in_vain.is_zero(), "the banner wait ran out");

        crowds.ask_again(&ctx, ScannerKind::Service).await;
        server.abort();

        let first = accepted.recv().await.expect("the first asking");
        let second = accepted.recv().await.expect("the second asking");
        assert!(first < left);
        let margin = Duration::from_millis(100);
        assert!(
            second + margin >= left + found.waited_in_vain,
            "asked again {:?} after the first left, with {:?} of its waits run out",
            second.saturating_duration_since(left),
            found.waited_in_vain
        );
    }

    /// Identifies each of `silent` at once in `crowd`, each in the others'
    /// company, and hands back how many connections each took from this
    /// process; see [`SilentPort::connections_told`].
    async fn identified_together(crowd: &Crowd, silent: &[SilentPort; 3]) -> [usize; 3] {
        let one = |port: &SilentPort| {
            let addr = port.addr();
            async move {
                let stream = TcpStream::connect(addr).await.unwrap();
                let baseline =
                    crate::fingerprint::baseline_port(addr.port(), Protocol::Tcp, PortState::Open);
                crowd
                    .identify(
                        addr.ip().into(),
                        stream,
                        baseline,
                        ServiceDetection::default(),
                        &Egress::KERNEL,
                        PathAllowance::NONE,
                    )
                    .await
            }
        };
        let found = tokio::join!(one(&silent[0]), one(&silent[1]), one(&silent[2]));
        assert!(
            [found.0, found.1, found.2]
                .iter()
                .all(|found| found.responses.is_empty() && found.ran_out_waiting),
            "every port says nothing"
        );
        silent.each_ref().map(SilentPort::connections_told)
    }

    /// A host whose ports stay silent when asked again alone is asked again
    /// once, not once per port; otherwise hundreds of silent ports could hold
    /// the pass for most of an hour.
    ///
    /// Counted by connections each port can attribute to this process, since
    /// other loopback scans on the machine reach these ports too.
    #[tokio::test]
    async fn a_host_silent_when_asked_again_alone_is_not_asked_again_port_by_port() {
        let silent = [SilentPort::open(), SilentPort::open(), SilentPort::open()];
        let (_session, ctx) = ScanSession::new();
        let crowds = Crowds::default();
        let crowd = crowds.of("127.0.0.1".parse().unwrap(), None);
        crowd.answered_late.store(true, Ordering::Relaxed);

        let first = identified_together(&crowd, &silent).await;
        crowds.ask_again(&ctx, ScannerKind::Service).await;

        assert!(first.iter().all(|&taken| taken > 0));
        let again: Vec<usize> = silent
            .iter()
            .zip(first)
            .map(|(port, first)| port.connections_told() - first)
            .collect();
        let asked_again = again.iter().filter(|&&taken| taken > 0).count();
        assert_eq!(
            asked_again, 1,
            "the host stayed silent alone and was still asked again on \
             {asked_again} ports: {again:?} connections more"
        );
    }

    /// A stop ends a second asking in flight, not after its full walk.
    #[tokio::test]
    async fn a_stop_cuts_short_a_second_asking_in_flight() {
        let silent = SilentPort::open();
        let (_session, ctx) = ScanSession::new();
        let crowds = Crowds::default();
        let crowd = crowds.of(silent.addr().ip(), None);
        crowd.answered_late.store(true, Ordering::Relaxed);

        let company = crowd.contention.enter();
        let first = identified_in(&crowd, &silent).await;
        drop(company);
        // Stop a second into the second asking: a walk on a silent port takes
        // several seconds of its own timers.
        let through = crowd
            .backlog
            .lock()
            .unwrap()
            .through()
            .unwrap_or_else(tokio::time::Instant::now);
        let stop = async {
            tokio::time::sleep_until(through + Duration::from_secs(1)).await;
            ctx.handle.abort();
        };
        tokio::join!(crowds.ask_again(&ctx, ScannerKind::Service), stop);

        let again = silent.heard() - first;
        assert!(
            again < first,
            "the second asking sent {again} bytes after the stop, as many as \
             a whole walk sends ({first})"
        );
    }
}
