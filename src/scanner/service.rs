// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Service detection phase
//!
//! The second phase of a port scan: given ports whose *state* discovery already
//! classified, identify *what is running* behind the open ones.
//!
//! ## Why it is a separate phase
//!
//! The unprivileged [`connect`](crate::scanner::strategy::connect) scanner already holds a live
//! `TcpStream` the moment it finds a port open, so it fingerprints inline. The
//! privileged [`TcpPortScanner`](crate::scanner::strategy::ports::TcpPortScanner) never completes a
//! handshake, since it classifies each port from a single raw SYN/SYN-ACK/RST
//! exchange, and so it has no connection to fingerprint through. Fingerprinting
//! does not need raw sockets, it needs a real TCP connection. This phase opens one
//! to each open TCP port and runs the same engine, so a fast privileged scan
//! reports the same service detail as the connect fallback instead of a bare
//! port-to-name guess.
//!
//! Discovery and identification are kept separate on purpose. Finding which ports
//! are open is cheap and benefits from raw-packet speed, while identifying what
//! runs on them needs a real conversation with the service. Splitting the two lets
//! each use the transport that suits it.
//!
//! ## On a slow or a crowded path
//!
//! Two things the scan knows by now decide how its conversations are waited
//! on. The path to each host was measured finding it, and every wait on one of
//! its ports allows for that path as the port scans' own probes do. And a
//! host's ports are identified side by side, which a host serving them from
//! one worker answers in turn: a port whose identification drew nothing while
//! its host was answering another port late is asked again with the host to
//! itself. Both are shared with the unprivileged port scan, which identifies
//! each port over the connection that finds it open.

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
/// Intended to run once, after a discovery phase that established port *state* but
/// not service identity, which is the SYN path. Ports that already carry a
/// fingerprint from the connect scanner would be re-identified harmlessly, but the
/// caller only runs this where it is actually needed.
///
/// `over` is which transport's ports to take. A scanner asks for the one it
/// found, so a composite running a TCP and a UDP member fingerprints each port
/// once, from the member that discovered it. Passing the whole store to both
/// would identify every TCP port twice, once per member, which is what kept the
/// UDP scanner from running this phase at all.
pub async fn detect(ctx: &ScanContext, detection: ServiceDetection, over: Protocol) {
    identify(ctx, detection, over, Which::Every).await;
}

/// Identifies the open ports over `over` that an earlier sitting of the job
/// identified and this one has not, for a strategy that identifies what it
/// finds over the connection that finds it and so has no second pass of its
/// own.
///
/// What that sitting drew was the detections' to read and ended with it; the
/// port comes back settled, so no probe of this sitting reaches it. See
/// [`Responses`](crate::scanner::session::Responses) on a port a sitting
/// inherits. A port this sitting found or asked again has been identified
/// already, and nothing is asked of a host an earlier sitting finished with.
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
    // A level that opens no connection has nothing for this phase to do. Checked
    // before the store is walked, so the phase costs nothing at all rather than
    // costing a snapshot it will not use.
    if !detection.connects() {
        return;
    }

    // Snapshot the targets up front so no DashMap guard is held across an await.
    let tarpits = Tarpits::default();
    let targets = fingerprintable_ports(ctx, over, detection, which, &tarpits);
    // A stopped scan opens nothing further, and the report names the pass it
    // left with ports in front of it.
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
        // A host whose budget ran out during the port scan is not asked what
        // its open ports are running. The ports keep whatever the port phase
        // recorded, which is a state without a service name, and the phase has
        // already named the address as one it left early.
        if ctx.host_expired(address) {
            continue;
        }
        // Asked here rather than when the list was drawn, because what
        // decides it is what the host's ports taken so far have answered.
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
        // Ended with the scan rather than at its own ceiling, which on a port
        // that accepts and says nothing is the better part of half a minute.
        // One cut short keeps what the port phase recorded.
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
    // A stop that came while ports were being identified ended the ones in
    // flight, which keep what the port phase recorded and nothing more.
    ctx.stopping_before(Pass::Services);
    close_pass(ctx, &crowds, &quiet, in_part, asked).await;
    tarpits.report(ctx, ScannerKind::Service);
}

/// Ends a pass whose first identifications are done: asks again the ports
/// its crowds owe a second asking, and says what the pass could not learn,
/// the ports that said nothing, those that were quiet or out of reach, and
/// those the file limit left identified in part, a second asking it cut
/// short counted as a first one is.
///
/// Apart from [`detect`] so the counting of a second asking is tested where
/// the pass does it, against a table filled before anything else is opened:
/// a test that ran the pass's first identification before filling it would
/// race the descriptors that identification's far end lets go of.
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
/// A handful of open ports that volunteer nothing is ordinary: plenty of
/// services wait to be spoken to first, and a firewall in front of one answers
/// the same way. A host where every open port behaves that way is not ordinary,
/// and the number is set where the first reading stops being plausible.
const QUIET_PORTS_WORTH_A_WORD: usize = 10;

/// Open ports that answered the port scan and then gave nothing back on a
/// connection, gathered across the phase.
///
/// One report line each is one line per port. A scan whose path answers every
/// SYN produces one of these for every port probed, and the eighty-three lines
/// that follow bury the run they describe. The same shape and the same
/// reasoning as [`SendFaults`](crate::scanner::strategy::raw), which collapses
/// its own repeats for the same reason.
#[derive(Debug, Default)]
struct QuietPorts {
    /// How many ports it happened to.
    count: usize,
    /// The first one, so the summary names somewhere to start looking.
    first: Option<String>,
    /// Why that one gave nothing back. The same reason for all of them wherever
    /// something on the path is answering instead of a service.
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

    /// Says once that these ports were identified only in part, a later
    /// connection of theirs refused a socket.
    ///
    /// Filed, since what those ports were asked is a floor, the questions
    /// that went unasked went unasked for this machine's file limit, and a
    /// report that did not say so would read as ports that had nothing more
    /// to say. Filed as cut short, and warned in one short line naming the
    /// limit, because nothing broke: the remedy is to raise the limit.
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

        // Still a shortfall, and still the report's to carry: these ports were
        // open and the scan did not learn what was behind them. One failure
        // rather than one per port, because a count of eighty-three strategies
        // that did not run describes a scan that broke, and this one did not.
        // Nor did this pass: its connections went unanswered or were turned
        // away, so the console says which ports and why, and not that a
        // scanner failed.
        warn!("{}", Self::line(first, reason, self.count));
        ctx.file_cut_short(
            ScannerKind::Service,
            Self::summary(first, reason, self.count),
        );

        // A port answered for is a port that takes a SYN and then has nothing to
        // say. Every one of them behaving that way is the path, not the host.
        if self.count == asked && asked >= QUIET_PORTS_WORTH_A_WORD {
            warn!("all {asked} open ports silent on connect (likely a middlebox)");
        }
    }
}

/// Every open `(address, port, protocol)` in the store worth fingerprinting,
/// snapshotted so the DashMap is not borrowed across the exchanges that follow.
///
/// The address is taken from the host rather than from the store key, because
/// the key is only the address and a link-local one cannot be connected to
/// without the interface it was seen on. The host carries that; see
/// [`Host::scoped_ip`](crate::model::host::Host::scoped_ip).
///
/// # Which UDP ports qualify
///
/// Only those whose reply this engine can read: [`reads_replies`]. A TCP port
/// always qualifies, because any of them may volunteer a banner and reading one
/// costs a connection that was going to be made anyway. A UDP port is different:
/// there is no banner to wait for, so a datagram nothing here could decode
/// teaches nothing the scan has not already recorded, and sending one would be
/// traffic spent to learn a fact already in hand.
///
/// And only at a level that sends. A UDP port has no greeting to listen for,
/// so the one thing identifying it can do is send it a datagram, which is what
/// a caller who asked only to listen has ruled out.
///
/// # Which ports of a tarpit qualify
///
/// Only its likeliest: a host that answers on every port is asked what runs
/// where a real service behind it would be, and no further. See [`Tarpits`],
/// which counts the rest. Only the host's open ports are known here; one
/// found out by its silence is passed over as its ports are taken.
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
    }
    targets
}

/// How many open ports of one host that answers on every port are
/// identified, at most, per transport: the likeliest ones, by the catalog's
/// ranking.
///
/// A host past [`TARPIT_OPEN_PORTS`] is answering everything rather than
/// answering questions, and identifying every port it accepts costs a
/// conversation each, most of them waited out to the end: across the whole
/// port range, hours. What is worth asking of it is what a real service
/// behind it would be on. A firewall that answers every SYN on a server's
/// behalf still passes the server's own ports through, and those are on the
/// ports a service is likeliest to be on. The first tier of the ranking is the
/// ports that answer on a meaningful share of hosts of some kind, so that is
/// where the line is drawn; see [`TCP_TIER_BOUNDS`].
///
/// [`TARPIT_OPEN_PORTS`]: crate::model::host::TARPIT_OPEN_PORTS
/// [`TCP_TIER_BOUNDS`]: crate::model::port::catalog::TCP_TIER_BOUNDS
pub(crate) const TARPIT_PORTS_IDENTIFIED: usize = crate::model::port::catalog::TCP_TIER_BOUNDS[0];

/// How many of a host's ports have to take a connection and say nothing to
/// every question put to them, and more of them than said anything, before
/// the host is identified as one that answers on every port is.
///
/// A host marked [`NetworkRole::Tarpit`] is known for one only once it has
/// answered on [`TARPIT_OPEN_PORTS`], and a scan that identifies each port
/// over the connection that finds it open has waited out every
/// identification up to then: a thousand conversations, each the better part
/// of its whole wait. Its silence gives it away sooner. A host running a few
/// hundred real services answers on most of them, and one that has said
/// nothing on as many ports as a tarpit's likeliest, and on more than it
/// answered, has nothing more to tell than a tarpit does. Counted only where
/// the identification asked something, since a service that waits to be
/// spoken to is silent to one that only listens.
///
/// [`NetworkRole::Tarpit`]: crate::model::host::NetworkRole::Tarpit
/// [`TARPIT_OPEN_PORTS`]: crate::model::host::TARPIT_OPEN_PORTS
pub(crate) const SILENT_PORTS_OF_A_TARPIT: usize = TARPIT_PORTS_IDENTIFIED;

/// The open ports a pass leaves unidentified on hosts that answer on every
/// port, counted per host, for one line each once the pass has decided.
///
/// Such a host carries [`NetworkRole::Tarpit`], which says its ports are not
/// to be acted on, or has given itself away sooner by saying nothing on its
/// ports; see [`SILENT_PORTS_OF_A_TARPIT`]. Its likeliest ports are still
/// identified, as [`TARPIT_PORTS_IDENTIFIED`] says, and the rest keep what the
/// port scan recorded: open, and the name their number gives them. That is
/// the scan covering less than it was asked to, so it is filed where a
/// shortfall is, and said at the console once per host rather than once per
/// port.
///
/// [`NetworkRole::Tarpit`]: crate::model::host::NetworkRole::Tarpit
#[derive(Debug, Default)]
pub(crate) struct Tarpits {
    /// Per host, the ports passed over.
    ///
    /// Counted once the pass has settled them rather than as each is passed
    /// over, and only those found open: a scan that identifies each port over
    /// the connection that finds it open decides before it knows, and a port
    /// that turned out closed was never one to identify.
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
    /// Whether `number` over `protocol` on `host` is to be identified, which
    /// every port is except one beyond its likeliest of a host that answers
    /// on every port: marked for it, or found out by what `crowd`, its
    /// identifications in this pass, has heard.
    pub(crate) fn identifies(
        &self,
        host: &Host,
        crowd: Option<&Crowd>,
        number: u16,
        protocol: Protocol,
    ) -> bool {
        use crate::model::port::catalog::{top_tcp, top_udp};

        let silent = crowd.and_then(Crowd::answers_nothing);
        if !host.network_roles().contains(&NetworkRole::Tarpit) && silent.is_none() {
            return true;
        }
        let likeliest = match protocol {
            Protocol::Tcp => top_tcp(TARPIT_PORTS_IDENTIFIED),
            Protocol::Udp => top_udp(TARPIT_PORTS_IDENTIFIED),
            Protocol::Sctp => &[],
        };
        if likeliest.contains(&number) {
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

    /// Says, for each host with open ports left unidentified, how many, once
    /// at the console and once in the report, as a shortfall of the pass
    /// `kind`.
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
    /// What the path to the host, as the scan measured it finding the host
    /// and its ports, adds to every wait on the port.
    path: PathAllowance,
}

/// What one port's fingerprint attempt produced. [`Unreachable`](Self::Unreachable)
/// is kept apart from [`Quiet`](Self::Quiet) because an open port that refused a
/// connection is a shortfall the report must show, while a silent UDP port is
/// not.
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

    /// The reason in the report's words, which a reader weighing the
    /// shortfall reads whole.
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

/// `duration` to the nearest tenth of a second, which is as finely as a
/// connect budget with a measured path on top is worth naming.
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
    /// Whether a later connection of the identification's was refused a
    /// socket, so that what it names is a floor.
    identified_in_part: bool,
}

/// Connects to one open port and fingerprints it.
///
/// A link-local address with no interface recorded against it yields no socket
/// address at all, and is skipped with a word about why. Attempting the
/// connection anyway would fail with an error describing the network, which is a
/// claim about the neighbour rather than about what this host knows.
///
/// Every connection it makes to the port leaves by `egress`, and every wait on
/// the port allows for the path the target carries. A TCP port is identified
/// in its host's `crowd`.
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

    // One socket's share of the process's budget, held for the whole of the
    // port's identification. Its connections are made one after another, so
    // one share covers them; see `descriptors`.
    let _descriptor = descriptors::gate()
        .acquire()
        .await
        .expect("the descriptor gate is never closed");

    let (port, about_the_host, banners, identified_in_part) = match protocol {
        Protocol::Tcp => {
            let within = path.over(CONNECT_PROBE_TIMEOUT);
            let stream = match egress.connect_timed(addr, within).await {
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
                .identify(target.clone(), stream, port, detection, egress, path)
                .await;
            (
                identified.port,
                identified.about_the_host,
                identified.responses,
                identified.starved,
            )
        }
        // Silence is not a failure here: a UDP port that says nothing has told
        // the scan what it had to. A port the process had no socket to ask
        // was told nothing, and is filed the way a connection refused a
        // socket is.
        Protocol::Udp => {
            match crate::fingerprint::fingerprint_udp_on(addr, port, egress, path).await {
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
        // Nothing here speaks SCTP as a client, so an open SCTP port keeps the
        // name the scan gave it rather than being dialled for a banner.
        Protocol::Sctp => return Attempt::Quiet,
    };

    // The key, not the address: this is what the finding is written back
    // under, and a link-local written back bare would fork the host's record.
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
    /// The crowd `host`'s identifications make in this pass, which ask its
    /// ports for by `name` where a target reached the host by one.
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
    /// A host's ports one after another, and hosts side by side, as many at
    /// once as the pass identifies ports. Each takes one socket's share of the
    /// process's budget for its connection. A scan told to stop, or that has
    /// outlived its budget, asks nothing more and cuts short the asking in
    /// flight, and the ports keep what their first identification drew.
    ///
    /// Returns each port whose second asking the file limit cut short, which
    /// the pass counts as identified in part as it counts a first asking cut
    /// short: what the port is filed with is a floor, the questions that went
    /// unasked went unasked for this machine's limit. A port already counted
    /// for its first asking is not returned again.
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
    /// Such a port keeps the name its number gives it, marked as inferred,
    /// and without this nothing at the console says that the name is the
    /// number's and not an answer's. A decision behind the result, so it is
    /// said at the first verbosity, as one line however many ports it covers.
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
/// A pass identifies a host's ports at once, and most hosts answer them at
/// once. One that serves several ports from a single worker answers them in
/// turn instead, each question after every one queued ahead of it across all
/// of its ports, and a port whose question queued behind an answer that took
/// most of its wait runs out of wait itself: its identification draws nothing,
/// and a live service is reported as a port with nothing to say. That wait is
/// the pass's doing, not the port's.
///
/// So a port whose identification drew nothing, after waiting in vain, while
/// another of its host's ports was being identified, is asked again with the
/// host to itself, provided the host answered one of the pass's questions
/// late. The two conditions keep the second asking where it can change the
/// answer. A host that answers promptly has no queue a question could have
/// waited out, and a port on it that said nothing in company says nothing
/// alone; and a host that answered nothing at all, as when something on the
/// path takes every connection and says nothing, would be asked everything
/// twice for nothing. Asked alone, a single-worker host answers each port as
/// it would were it the only one.
///
/// The second asking waits until the pass has finished every first one; see
/// [`Crowds::ask_again`]. By then the host has nothing else of the pass's
/// to answer, and its lateness has been heard from every port. The port is
/// handed back to its pass meanwhile, with what its first identification
/// drew, so the wait holds no place in the pass and no socket's share of the
/// process's budget: a pass identifying ports of many such hosts would
/// otherwise have its places held by ports waiting on their neighbours.
///
/// Nor does it go before the host could have worked through what the pass
/// left it. A host serving in turn serves every question it was put, the ones
/// whose wait ran out included, and a second asking put while it still holds
/// them waits behind them as the first did, and runs out of its wait the same
/// way; see [`Backlog`].
///
/// A second asking tests whether the silence was the queue's, and the host's
/// answers settle it. Its ports are asked one after another, each a whole
/// identification, so one late answer on a host with hundreds of ports that
/// wait to be spoken to would otherwise owe every one of them a second walk
/// in a row: a pass running for as many minutes as the host has silent ports,
/// one connection open at a time, which reads as a scan that hung. So a host
/// goes on being asked again only while its second askings have drawn
/// something at least as often as nothing. One that answers alone what it
/// would not in company is asked on, and one that stays silent alone has
/// refuted the queue. The host's silence costs at most one walk more than
/// its answers repay; see [`Crowd::ask_alone`].
///
/// Whether an identification had company is counted as the detection stage
/// counts it, per host; see [`HostContention`].
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
    /// The name a target reached the host by, which its web ports are asked
    /// for by; see
    /// [`ZondConfig::target_names`](crate::config::ZondConfig::target_names).
    name: Option<Arc<str>>,
    /// The ports that took the connection and answered nothing they were
    /// asked, each waited on until its clock ran out; see
    /// [`Crowds::report_silence`].
    silent: Mutex<Vec<(ScopedIp, u16)>>,
    /// How many of the host's first identifications drew something.
    answered: AtomicUsize,
    /// How many of them asked a question and heard nothing to any, each
    /// waited out; see [`SILENT_PORTS_OF_A_TARPIT`].
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
    /// Whether the first identification was cut short by the file limit, and
    /// the port so counted as identified in part already.
    in_part: bool,
}

/// What a [`Crowd`]'s second askings came to.
#[derive(Debug, Default)]
struct AskedAlone {
    /// Each port that drew something, with what it drew, under the key it is
    /// filed under.
    named: Vec<(ScopedIp, Fingerprinted)>,
    /// Each port the file limit cut the second asking of short, not counted
    /// for its first; see [`Crowds::ask_again`].
    in_part: Vec<(ScopedIp, u16)>,
}

impl Crowd {
    /// Identifies the port `stream` reached, as
    /// [`fingerprint_tcp_via`](crate::fingerprint::fingerprint_tcp_via) does,
    /// and owes it a second asking where the identification's silence may
    /// have been its host's queue. Its findings are filed under `key`.
    pub(crate) async fn identify(
        &self,
        key: ScopedIp,
        stream: TcpStream,
        port: Port,
        detection: ServiceDetection,
        egress: Egress,
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
                    egress,
                    path,
                    in_part: found.starved,
                });
        }
        found
    }

    /// How many of the host's ports have said nothing to what their
    /// identification asked, where that is enough, and more than answered,
    /// for the host to be identified as one that answers on every port;
    /// `None` where it is not. See [`SILENT_PORTS_OF_A_TARPIT`].
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

    /// Asks each of `owed` again in turn, with the host to itself, and hands
    /// back what drew anything, under the key each is filed under, and which
    /// the file limit cut short. A port that no longer takes the connection,
    /// or draws nothing again, keeps what its first identification drew.
    ///
    /// Each dials the port afresh, given the connect budget and the path's
    /// allowance, once the host's [`Backlog`] is waited out. The asking ends
    /// once the host has drawn nothing more often than it drew something, as
    /// the [`Crowd`] explains; a port this machine had no socket for is no
    /// silence of the host's and is not counted either way. It ends sooner
    /// where the scan stops or outlives its budget, which is raced against the
    /// backlog's wait and the identification in flight as every other wait on
    /// a port is, and where the host outlives its own, which is asked before
    /// each port.
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
            // One socket's share, for the connections the identification
            // makes one after another; see `descriptors`.
            let _descriptor = descriptors::gate()
                .acquire()
                .await
                .expect("the descriptor gate is never closed");
            let number = port.number();
            let name = self.name.clone();
            let identified = async {
                let stream = egress
                    .connect_timed(addr, path.over(CONNECT_PROBE_TIMEOUT))
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
            // A connection or a question this machine had no socket for is
            // no silence of the host's, and neither refutes its queue.
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

/// What a host serving its questions one at a time may still have to do,
/// once a pass's identifications of it are over, before a question put now is
/// the next it serves.
///
/// What the host is left with at the end is only what nobody waits for any
/// longer: every question that was answered has been served. Each of those
/// holds the host for no longer than the wait it was given, where the host
/// answers a question within its wait at all, and a host that does not
/// cannot be named by any asking. So the host is through them by the time
/// the pass's last identification of it left, and those waits once over, and
/// sooner where it had begun on them while the pass still ran.
///
/// That upper bound is what a second asking waits out, held to
/// [`BACKLOG_WAIT_LIMIT`]: a host that answers late but side by side was left
/// nothing, and a wait on its behalf is time the scan spends for no question.
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
/// Ten seconds is a pass's abandoned questions on a few ports, at the second
/// or so each that a single worker the second asking is for spends on them,
/// and short beside the identifications it waits to complete.
const BACKLOG_WAIT_LIMIT: Duration = Duration::from_secs(10);

/// Folds a freshly fingerprinted port back into its host and announces the
/// update. [`Port::merge`] is confidence-driven, so the fingerprint overwrites
/// the discovery phase's name-only baseline.
///
/// `about_the_host` is what the service said about the *machine*, which is a
/// different finding filed in a different place: the service belongs to the port,
/// the operating system to the host.
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

        // Folded together with what the host's hardware and name say, and with
        // whatever a stack reading already concluded: the point of the evidence
        // bus is that a banner agreeing with the wire is worth more than either.
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

    /// A port that takes the connection and answers nothing it is asked is
    /// said once at the console, and a port that answered is not.
    ///
    /// Such a port keeps the name its number gives it, and with nothing said
    /// the report reads as though the name had been established: a listener
    /// holding 2222 open in silence read `open ssh` like an SSH server.
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
                    Egress::KERNEL,
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

    /// Eighty-three ports reported one by one would be eighty-three report
    /// lines, and the count of strategies that did not run would go up by
    /// eighty-three with them. At the console they are one short line, the
    /// ports and then why, and the report's entry says the rest.
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

    /// Ports whose identification lost a later connection to a full table are
    /// one entry between them, naming the first, the count and the limit,
    /// so what they were identified by reads as a floor rather than as all
    /// they had to say. The entry is marked cut short, since nothing broke
    /// and the remedy is to raise the limit.
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

    /// One of them reads as itself rather than as "and 0 other ports".
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
        // A loopback "service" that greets on connect with an SSH banner, standing
        // in for what a SYN-discovered open port would say once we connect.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok(mut sock) = accept_from_this_process(&listener).await {
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n").await;
            }
        });

        // Seed the store as the SYN scanner would: the port is Open, but its
        // service is only the port→name baseline (confidence 0), not identified.
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
        // The banner was fingerprinted, not left as a bare port→name guess.
        assert_eq!(service.name(), "ssh");
        assert_eq!(service.product(), Some("OpenSSH"));
        assert_eq!(service.version(), Some("9.6p1"));
    }

    /// The level that promises to open no connection has to be checked before
    /// anything else this phase does, or the promise is only as good as whatever
    /// happens to come next.
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
            silent.connections(),
            0,
            "a level that connects to nothing connected to the port"
        );
        drop(session);
    }

    /// A scan stopped with open ports still to identify opens nothing further
    /// and names the pass it left, so a report whose ports carry no service
    /// is not read as ports that had none to name.
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

        detect(&ctx, ServiceDetection::default(), Protocol::Tcp).await; // must return promptly without connecting anywhere

        let host = session.hosts().get(ip).unwrap();
        let port = host.ports().find(|p| p.number() == 9).unwrap();
        // Untouched: no service was attached by the phase.
        assert!(port.service().is_none());
    }

    /// The pass after a raw scan listens on a listen-only port and sends it
    /// nothing, at the most thorough level there is, where the same port off
    /// the list is asked everything.
    ///
    /// The raw path's half of the rule. A printer prints what arrives there,
    /// and this pass is the one a privileged scan reaches it through.
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

    /// A level that only listens sends a UDP port nothing, where the default
    /// asks the same port its question.
    ///
    /// UDP has no greeting, so identifying a UDP port is a datagram and
    /// nothing else. A caller who asked only to listen, on a network where
    /// what the scan sends may knock something over, has ruled that out, and
    /// an SNMP request is exactly the unexpected packet such a network is
    /// being protected from. Read off the targets the pass takes, because the
    /// datagram it would have sent leaves no trace a test could hear without
    /// owning the port it is addressed to.
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

    /// A host that answers on every port has only its likeliest ports taken
    /// for identification, where an ordinary host has every open port taken,
    /// and the ports it leaves are one entry for the host.
    ///
    /// Each port taken is a conversation, and a host accepting every
    /// connection and saying nothing makes each one wait to its end: across
    /// the port range, hours of identification for a host whose ports mean
    /// nothing. Its likeliest ports are what a real service behind it would
    /// be on, so those are still asked.
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

    /// **A host that has said nothing on as many ports as a tarpit's
    /// likeliest, and on more than it answered, has only its likeliest
    /// identified from then on, and the report counts what was left.**
    ///
    /// Known for a tarpit only at a thousand open ports, a host whose ports
    /// are identified as they are found open has had a thousand
    /// conversations waited out by then. One running a few hundred real
    /// services answers on most of them and is identified whole.
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

    /// **A port on a slow path that has answered steadily is identified with
    /// waits a little longer than the path, not three times it.**
    ///
    /// Every wait of an identification allows for the path, and a port that
    /// says nothing is waited on several times in a row: allowing three round
    /// trips each, as one sample earns, a silent port two seconds away cost
    /// the better part of a minute on a path the port scan had measured to
    /// the millisecond.
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

    /// An open port that refuses a connection is a shortfall the port itself
    /// cannot show, so the phase records it as a failure.
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

    /// A loopback service that answers any request only after `delay`,
    /// standing in for one behind a path that costs that much: the reply is
    /// sent promptly and spends the rest on the way.
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

    /// An open port behind a path slower than a reply's own wait is
    /// identified, every wait on it allowing for the round trip the scan
    /// measured finding the host.
    ///
    /// A reply's wait is set for how long a service takes to answer, and a
    /// path adds its round trip to every answer. Waited on as though the path
    /// cost nothing, a service that answered at once behind a slow path is
    /// reported as a port with nothing to say, though the port scan before
    /// this pass had timed the path and found the port by it.
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

    /// A port that could not be connected to within the path's allowance is
    /// reported with that allowance, which is the wait it was actually given.
    #[test]
    fn a_connect_behind_a_measured_path_names_the_wait_it_was_given() {
        let within =
            PathAllowance::of_round_trip(Duration::from_millis(1_900)).over(CONNECT_PROBE_TIMEOUT);
        let silent = Unreached::of(std::io::ErrorKind::TimedOut.into(), within);
        assert_eq!(silent.said(), "no answer within 7.2s");
        assert_eq!(
            QuietPorts::line("192.0.2.10:22", &silent, 1),
            "192.0.2.10:22 not fingerprinted (no answer in 7.2s)"
        );
    }

    /// The requests a [`one_worker`] host served, by port and first line.
    type Served = Arc<std::sync::Mutex<Vec<(u16, String)>>>;

    /// A loopback host serving `ports` ports from one worker, which takes the
    /// requests of all of them in turn and spends `service` on each HTTP one,
    /// the way a small embedded web server does. Anything but an HTTP request
    /// is closed unanswered. Returns the ports and the requests served, by
    /// port and first line.
    ///
    /// The worker is a thread of its own rather than a task on the runtime
    /// the pass runs on, so how long it takes over a request is its own and
    /// not the pass's.
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

    /// Two ports one worker serves in turn are both identified, the one whose
    /// question queued behind the other's answer asked again with the host to
    /// itself.
    ///
    /// Asked at once, the second port's request waits out the first one's
    /// answer before its own begins, and a service taking most of a reply's
    /// wait over each answers the second too late for it. That wait was the
    /// pass's queue and not the port's silence, and a live service reported
    /// as nothing is what it cost.
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

    /// A port that says nothing beside one that answers promptly is asked
    /// once: a host that answers in good time has no queue to wait out, and
    /// asking the silent port again alone would cost its whole walk a second
    /// time for the same silence.
    #[tokio::test]
    async fn a_silent_port_beside_a_prompt_one_is_asked_once() {
        let (prompt, _) = one_worker(1, Duration::ZERO);
        let silent = SilentPort::open();
        let (session, ctx) = open_on_loopback(&[prompt[0], silent.addr().port()]);

        detect(&ctx, ServiceDetection::default(), Protocol::Tcp).await;

        // What the port is sent over one identification is what it is sent
        // identified alone, and two would send it twice that.
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
                Egress::KERNEL,
                PathAllowance::NONE,
            )
            .await;
        assert!(found.responses.is_empty(), "the port says nothing");
        silent.heard() - before
    }

    /// A port whose identification drew nothing in company, on a host that
    /// answers late, is handed back once its own walk is done, and asked
    /// again only when the pass's other identifications are: waiting for them
    /// inside its identification, it held its place in the pass and its
    /// descriptor through all of theirs, holding up every port queued behind
    /// it on a wide scan for a socket it did not have open.
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

    /// And the port is asked again once the pass is done with its host, the
    /// whole of its identification a second time, with the host to itself.
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

    /// A second asking the file limit cuts short is counted as identified in
    /// part, as a first asking cut short is, and the pass files it: the port
    /// keeps what its first identification drew, and the questions the second
    /// would have put went unasked for this machine's limit, not for anything
    /// the port said.
    ///
    /// The port is owed its second asking as its first identification leaves
    /// it owed, with no connection made first, and the table is filled before
    /// anything is opened. A first identification run here would leave its
    /// far end closing sockets on another thread after the fill, and a socket
    /// freed that way lets the second asking connect, which reads as a port
    /// that said nothing rather than one the limit cut short. Nor is the
    /// host's backlog waited out, which is not what is tested here. The port
    /// refuses connections, so a table with room for one ends the asking at
    /// once rather than walking an identification. What it does wait is the
    /// patience every connection gives a full table, which is the path the
    /// limit takes.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_second_asking_the_file_limit_cuts_short_is_counted_identified_in_part() {
        use crate::system::descriptors::testing::{exhaust, in_a_process_of_its_own};

        if !in_a_process_of_its_own(
            module_path!(),
            "a_second_asking_the_file_limit_cuts_short_is_counted_identified_in_part",
        ) {
            return;
        }
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

        let held = exhaust(64);
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

    /// A second asking waits out what the pass left its host before it
    /// connects: a host serving in turn still serves every question whose
    /// wait ran out, and a question put behind them waits as the first did,
    /// and runs out the same way.
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
                Egress::KERNEL,
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
    /// company, and hands back how many connections each took.
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
                        Egress::KERNEL,
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
        silent.each_ref().map(SilentPort::connections)
    }

    /// A host whose ports stay silent when asked again alone is asked again
    /// once, not once per port.
    ///
    /// One late answer owes every port that said nothing in its company a
    /// second asking, and the askings run one after another, each a whole
    /// walk. A host with hundreds of ports that wait to be spoken to, one of
    /// its services slow to greet, would hold the pass for as many walks in a
    /// row, one connection open at a time, which is a scan that looks hung
    /// for the better part of an hour. The first silence alone refutes the
    /// queue the second asking is for.
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
            .map(|(port, first)| port.connections() - first)
            .collect();
        let asked_again = again.iter().filter(|&&taken| taken > 0).count();
        assert_eq!(
            asked_again, 1,
            "the host stayed silent alone and was still asked again on \
             {asked_again} ports: {again:?} connections more"
        );
    }

    /// A scan stopped while a port is being asked again ends that asking
    /// there, rather than once its walk has waited out every greeting and
    /// probe on a port that says nothing.
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
        // Stopped a second into the second asking, once the host's backlog
        // is waited out: a walk on a silent port waits out a greeting and
        // then each of its probes' replies, several seconds of its own timers
        // however fast the machine, so a second in is part way through it.
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
