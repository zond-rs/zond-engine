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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpStream;

use crate::model::ip::scoped::ScopedIp;
use crate::warn;

use crate::config::ServiceDetection;
use crate::config::limits::{CONNECT_CONCURRENCY, CONNECT_PROBE_TIMEOUT};
use crate::detect::contention::HostContention;
use crate::fingerprint::Fingerprinted;
use crate::model::port::{Port, PortState, Protocol};
use crate::report::ScannerKind;
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
    // A level that opens no connection has nothing for this phase to do. Checked
    // before the store is walked, so the phase costs nothing at all rather than
    // costing a snapshot it will not use.
    if !detection.connects() {
        return;
    }

    // Snapshot the targets up front so no DashMap guard is held across an await.
    let targets = fingerprintable_ports(ctx, over);
    if targets.is_empty() {
        return;
    }

    ctx.enter_stage(Stage::Services, Some(targets.len() as u64));

    let asked = targets.len();
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
        if ctx.handle.should_stop() {
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
        let egress = ctx.egress_toward(address);
        let detection = ctx.service_detection_on(detection, target.number, target.protocol);
        pool.admit(fingerprint_one(
            target,
            detection,
            egress,
            crowds.of(address),
        ))
        .await;
    }

    pool.drain().await;
    drop(pool);
    crowds.ask_again(ctx, ScannerKind::Service).await;

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
        let ports = match count - 1 {
            0 => first.to_string(),
            rest => format!("{first} and {rest} more"),
        };
        format!("{ports} not fingerprinted ({})", reason.terse())
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
    /// A failure for the reason every connection refused a socket is one:
    /// what those ports were asked is a floor, the questions that went
    /// unasked went unasked for this machine's file limit, and a report that
    /// did not say so would read as ports that had nothing more to say.
    fn report_in_part(&self, ctx: &ScanContext) {
        let (Some(first), Some(reason)) = (&self.first, &self.reason) else {
            return;
        };
        ctx.record_failure(
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
/// [`reads_replies`]: crate::fingerprint::reads_replies
fn fingerprintable_ports(ctx: &ScanContext, over: Protocol) -> Vec<Target> {
    let mut targets = Vec::new();
    for host in ctx.store.iter() {
        let address = host.value().scoped_ip();
        let path = PathAllowance::of_median(host.value().median_rtt());
        for port in host.value().ports() {
            if port.protocol() == over
                && port.state() == PortState::Open
                && crate::fingerprint::reads_replies(port.number(), port.protocol())
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
            Self::Starved => "file limit reached".to_string(),
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
    /// The crowd `host`'s identifications make in this pass.
    pub(crate) fn of(&self, host: IpAddr) -> Arc<Crowd> {
        let mut hosts = self.hosts.lock().unwrap_or_else(|held| held.into_inner());
        Arc::clone(hosts.entry(host).or_default())
    }

    /// Asks again, each with its host to itself, every port a [`Crowd`] owes
    /// a second asking, and files what each draws, for a pass `kind` whose
    /// identifications have all finished.
    ///
    /// A host's ports one after another, and hosts side by side, as many at
    /// once as the pass identifies ports. Each takes one socket's share of the
    /// process's budget for its connection. A scan told to stop asks nothing
    /// more, and the ports keep what their first identification drew.
    pub(crate) async fn ask_again(&self, ctx: &ScanContext, kind: ScannerKind) {
        let crowds: Vec<Arc<Crowd>> = {
            let hosts = self.hosts.lock().unwrap_or_else(|held| held.into_inner());
            hosts.values().cloned().collect()
        };
        let mut pool = ProbePool::new(
            CONNECT_CONCURRENCY,
            ctx.clone(),
            kind,
            |named: Vec<(ScopedIp, Fingerprinted)>, _audit| {
                for (key, found) in named {
                    let (number, protocol) = (found.port.number(), found.port.protocol());
                    ctx.record_responses(key.clone(), number, protocol, found.responses);
                    write_back(ctx, key, found.port, found.about_the_host);
                }
            },
        );
        for crowd in crowds {
            let owed = crowd.owed();
            if owed.is_empty() {
                continue;
            }
            pool.admit(crowd.ask_alone(owed, ctx.handle.clone())).await;
        }
        pool.drain().await;
    }
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
        let found =
            crate::fingerprint::fingerprint_tcp_via(stream, port.clone(), detection, egress, path)
                .await;
        let alone = visit.leave();
        self.heard(&found);
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
                });
        }
        found
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
    /// back what drew anything, under the key each is filed under. A port
    /// that no longer takes the connection, or draws nothing again, keeps what
    /// its first identification drew.
    ///
    /// Each dials the port afresh, given the connect budget and the path's
    /// allowance.
    async fn ask_alone(
        self: Arc<Self>,
        owed: Vec<Owed>,
        handle: crate::scanner::handle::ScanHandle,
    ) -> Vec<(ScopedIp, Fingerprinted)> {
        let mut named = Vec::new();
        for Owed {
            key,
            addr,
            port,
            detection,
            egress,
            path,
        } in owed
        {
            if handle.should_stop() {
                break;
            }
            // One socket's share, for the connections the identification
            // makes one after another; see `descriptors`.
            let _descriptor = descriptors::gate()
                .acquire()
                .await
                .expect("the descriptor gate is never closed");
            let Ok(stream) = egress
                .connect_timed(addr, path.over(CONNECT_PROBE_TIMEOUT))
                .await
            else {
                continue;
            };
            let again =
                crate::fingerprint::fingerprint_tcp_via(stream, port, detection, egress, path)
                    .await;
            self.heard(&again);
            if !again.responses.is_empty() {
                named.push((key, again));
            }
        }
        named
    }

    /// Notes how the host answered one of its identifications.
    fn heard(&self, found: &Fingerprinted) {
        if found.answered_late {
            self.answered_late.store(true, Ordering::Relaxed);
        }
    }
}

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
    use crate::model::host::Host;

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
    /// one failure between them, naming the first, the count and the limit,
    /// so what they were identified by reads as a floor rather than as all
    /// they had to say.
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

    use crate::scanner::session::ScanSession;
    use std::collections::BTreeSet;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn detect_fingerprints_an_open_tcp_port_end_to_end() {
        // A loopback "service" that greets on connect with an SSH banner, standing
        // in for what a SYN-discovered open port would say once we connect.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
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

        // An open port on an address nothing is listening at. Reaching the
        // network here would take the connect timeout; returning promptly is the
        // observable form of "no connection was attempted".
        let unreachable: IpAddr = "192.0.2.1".parse().expect("a documentation address");
        ctx.update_host(unreachable, |host| {
            host.add_port(Port::new(80, Protocol::Tcp, PortState::Open));
        });

        let started = std::time::Instant::now();
        detect(&ctx, ServiceDetection::Off, Protocol::Tcp).await;

        assert!(
            started.elapsed() < CONNECT_PROBE_TIMEOUT,
            "a level that connects to nothing cannot have waited on a connection"
        );
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

    /// A silent loopback listener that counts every byte any connection sends
    /// it, standing in for a printer's raw-print port.
    async fn counting_listener() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&received);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let count = Arc::clone(&count);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    while let Ok(n) = sock.read(&mut buffer).await {
                        if n == 0 {
                            break;
                        }
                        count.fetch_add(n, Ordering::SeqCst);
                    }
                });
            }
        });
        (addr, received)
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
            let (addr, count) = counting_listener().await;
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
            received.push(count.load(Ordering::SeqCst));
        }

        assert_eq!(received[0], 0, "a listen-only port was sent a payload");
        assert!(
            received[1] > 0,
            "the same port off the list was asked nothing, so the first half \
             proves nothing"
        );
    }

    /// An open port that refuses a connection is a shortfall the port itself
    /// cannot show, so the phase records it as a failure.
    #[tokio::test]
    async fn a_port_that_refuses_a_connection_is_written_into_the_report() {
        // Bound and dropped: nothing answers, but the stack refuses promptly.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

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
            while let Ok((mut sock, _)) = listener.accept().await {
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
                for sock in listener.incoming().flatten() {
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
        let (silent, asked) = counting_listener().await;
        let (session, ctx) = open_on_loopback(&[prompt[0], silent.port()]);

        detect(&ctx, ServiceDetection::default(), Protocol::Tcp).await;

        // What the port is sent over one identification is what it is sent
        // identified alone, and two would send it twice that.
        let once = asked.load(Ordering::SeqCst);
        let generic: usize = crate::fingerprint::SignatureDb::global()
            .generic_tcp_probe_payloads()
            .iter()
            .map(Vec::len)
            .sum();
        let (alone_session, alone_ctx) = open_on_loopback(&[silent.port()]);
        detect(&alone_ctx, ServiceDetection::default(), Protocol::Tcp).await;
        let alone = asked.load(Ordering::SeqCst) - once;
        assert!(generic > 0 && alone >= generic);
        assert_eq!(
            once, alone,
            "the silent port was sent {once} bytes beside a prompt port and \
             {alone} alone, so it was identified more than once"
        );
        drop((session, alone_session));
    }

    /// What one identification of the silent port at `addr` sends it, in
    /// `crowd`, and the bytes the port had been sent when it returned.
    async fn identified_in(
        crowd: &Crowd,
        addr: std::net::SocketAddr,
        asked: &AtomicUsize,
    ) -> usize {
        let before = asked.load(Ordering::SeqCst);
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
        // Read, not answered: what the port was sent may still be arriving.
        tokio::time::sleep(Duration::from_millis(200)).await;
        asked.load(Ordering::SeqCst) - before
    }

    /// A port whose identification drew nothing in company, on a host that
    /// answers late, is handed back once its own walk is done, and asked
    /// again only when the pass's other identifications are: waiting for them
    /// inside its identification, it held its place in the pass and its
    /// descriptor through all of theirs, holding up every port queued behind
    /// it on a wide scan for a socket it did not have open.
    #[tokio::test]
    async fn a_port_owed_a_second_asking_is_handed_back_before_it_is_asked_again() {
        let (silent, asked) = counting_listener().await;

        let crowd = Crowd::default();
        crowd.answered_late.store(true, Ordering::Relaxed);
        // Another of the host's ports, still being identified.
        let company = crowd.contention.enter();
        let in_company = identified_in(&crowd, silent, &asked).await;
        drop(company);

        let alone = identified_in(&Crowd::default(), silent, &asked).await;
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
        let (silent, asked) = counting_listener().await;
        let (_session, ctx) = ScanSession::new();
        let crowds = Crowds::default();
        let crowd = crowds.of(silent.ip());
        crowd.answered_late.store(true, Ordering::Relaxed);

        let company = crowd.contention.enter();
        let first = identified_in(&crowd, silent, &asked).await;
        drop(company);
        crowds.ask_again(&ctx, ScannerKind::Service).await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(first > 0);
        assert_eq!(asked.load(Ordering::SeqCst), first * 2, "asked once again");
    }
}
