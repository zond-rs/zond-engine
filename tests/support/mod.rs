// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared helpers for the integration tests.
//!
//! Most of this file serves the portable Tier 1 tests described below. The
//! fixtures at the bottom serve Tier 2 instead, standing up the simulated host
//! that [`fake_net`] and [`fake_lan`] probe from.
//!
//! These tests drive the *public* scanning API - [`scanner::scan`] and
//! [`scanner::discover`] - end to end against real protocol servers on
//! loopback, so they run identically on macOS and Linux with no root and no
//! network setup. Loopback only ever answers open or closed, so lost probes,
//! firewalls, and injected latency belong to the simulated network in
//! [`fake_net`] instead (see `tests/README.md`).
//!
//! A note on privilege: when the process is root, `scan`/`discover` take their
//! raw-socket ARP/SYN paths, whose behaviour against loopback is
//! environment-specific. The assertions here that depend on the TCP-connect
//! fallback call [`is_privileged`] and skip rather than flake; the
//! privilege-independent ones (lifecycle, empty inputs) always run.

// Each integration-test binary includes this module but uses only part of it,
// so unused helpers are expected per-crate.
#![allow(dead_code)]

pub mod fake_lan;
pub mod fake_net;

// The crate's own fixture, loaded by path because a tier sees nothing the
// crate compiles for its tests alone: the loopback services every tier and
// the crate's unit tests stand up hear only the process they run in.
#[path = "../../src/testing/loopback.rs"]
pub mod loopback;

// The crate's own too, for a test that reaches past its share of the process
// it runs in.
#[path = "../../src/testing/own_process.rs"]
pub mod own_process;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use zond_engine::model::mac::MacAddr;

use zond_engine::config::ZondConfig;
use zond_engine::detect::Detections;
use zond_engine::model::host::{Host, HostStatus};
use zond_engine::model::ip::set::IpSet;
use zond_engine::model::port::{PortSet, PortState, Protocol};
use zond_engine::model::target::{PlannedTarget, Target, TargetMap, TargetSet};
use zond_engine::report::ScanReport;
use zond_engine::scanner::session::{HostStore, ScanEvent, ScanSession};
use zond_engine::scanner::strategy::PortScanner;
use zond_engine::scanner::{self, ScanTask};
use zond_engine::system::interface::{Addressing, Link, LinkAddress, LinkKind, SourceResolver};

use loopback::{accept_from_this_process, recv_from_this_process};

/// The loopback address every portable test targets.
pub const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A config with DNS disabled, so a result reflects only what was actually
/// observed on the wire — no reverse-lookup side effects.
pub fn test_config() -> ZondConfig {
    let mut cfg = ZondConfig::default();
    cfg.no_dns = true;
    cfg
}

/// True when a scan of a loopback target would take a raw path rather than the
/// portable TCP-connect fallback.
///
/// Loopback is the case it decides, and the one the portable tests target.
/// Loopback carries no Ethernet, so the only raw route to it is a raw socket,
/// and whether one opens is what this asks. It does not decide for a target
/// beyond loopback, which the raw path can reach by self-built frames without
/// a raw socket: a macOS user in the `access_bpf` group may inject frames and
/// may not open one, so this is false there while a scan of a LAN address
/// goes raw.
///
/// The connect-fallback assertions are only deterministic unprivileged, so they
/// use this to skip cleanly instead of flaking under a privileged test run.
///
/// Asks the engine's own question rather than restating it. A uid check answers
/// differently on a binary carrying `cap_net_raw`, and a suite that skipped the
/// wrong assertions there would be testing the fallback against a run that never
/// took it.
pub fn is_privileged() -> bool {
    zond_engine::system::privilege::can_send_raw()
}

/// An address nothing answers for that a probe cannot leave the machine to
/// reach, or `None` where this machine has no such address.
///
/// `127.0.0.2` is routed to loopback everywhere. macOS and the BSDs hold
/// `127.0.0.1` alone, so there a probe to it is delivered to loopback and
/// dropped, which is silence produced without a network. Linux holds the whole
/// of `127.0.0.0/8` and answers it as it answers `127.0.0.1`, so there is no
/// such address to borrow, and Tier 3 builds one instead. Whether this machine
/// holds it is asked by binding to it, which sends nothing.
///
/// A documentation address such as `192.0.2.1` is silent too, and is the wrong
/// choice: it belongs to nobody on the internet, but a probe to it still leaves
/// through the default route onto whatever network the machine running the
/// suite is on.
pub fn silent_loopback() -> Option<IpAddr> {
    let address = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    std::net::UdpSocket::bind((address, 0))
        .is_err()
        .then_some(address)
}

/// A running loopback server bound to an ephemeral port. The port stays open for
/// as long as this handle is alive; drop it (or let the test's runtime end) to
/// release it.
pub struct Server {
    pub port: u16,
    _task: JoinHandle<()>,
}

/// Serves a *speak-first* banner: on every connection, writes `banner` and then
/// closes. This mirrors real SSH/SMTP/FTP servers that greet on connect, which
/// is what lets the fingerprinting engine identify them on any port from the
/// banner grab alone (no port-specific probe required).
pub async fn spawn_banner_server(banner: &'static [u8]) -> Server {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind loopback banner server");
    let port = listener.local_addr().expect("server local addr").port();

    let task = tokio::spawn(async move {
        while let Ok(mut sock) = accept_from_this_process(&listener).await {
            let _ = sock.write_all(banner).await;
            let _ = sock.flush().await;
            // Drop closes the connection; the banner has already been sent.
        }
    });

    Server { port, _task: task }
}

/// A loopback port that refuses every connection for the remainder of the
/// test; see [`loopback::refused_ports`].
pub fn closed_loopback_port() -> u16 {
    closed_loopback_ports(1)[0]
}

/// `count` loopback ports, each refusing every connection for the remainder
/// of the test; see [`loopback::refused_ports`].
pub fn closed_loopback_ports(count: usize) -> Vec<u16> {
    loopback::refused_ports(Ipv4Addr::LOCALHOST.into(), count)
}

/// Serves a simple UDP response. On the first datagram this process sends it,
/// it writes `reply` back to the sender and exits, so the port reads as open to
/// a scan and as closed afterwards. A datagram from any other process is read
/// and dropped rather than spending the answer.
pub async fn spawn_udp_server(reply: &'static [u8]) -> Server {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind loopback udp server");
    let port = socket.local_addr().expect("server local addr").port();

    let task = tokio::spawn(async move {
        let mut buf = vec![0; 1024];
        if let Ok((_len, src)) = recv_from_this_process(&socket, &mut buf).await {
            let _ = socket.send_to(reply, src).await;
        }
    });

    Server { port, _task: task }
}

/// Serves `reply` to every datagram, on a caller's chosen loopback port.
///
/// [`spawn_udp_server`] takes whatever port is free, which is right for
/// asserting a port state and wrong for asserting an identification: the corpus
/// keys a UDP probe on the destination port, so a service on an arbitrary number
/// is sent nothing and answers nothing. A test about what the engine makes of a
/// reply has to bind the number the probe is registered for.
///
/// [`None`] when that number is already in use, which the caller should skip on
/// rather than fail: the port belongs to the machine, not to the test.
///
/// Answers every datagram rather than one, because a scan asks twice, once to
/// establish the port is open and once for the service pass, and a responder
/// that exited after the first would make the second read as silence. Answers
/// only this process's, as [`spawn_udp_server`] does.
pub async fn spawn_udp_server_on(port: u16, reply: &'static [u8]) -> Option<Server> {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .ok()?;
    let port = socket.local_addr().expect("server local addr").port();

    let task = tokio::spawn(async move {
        let mut buf = vec![0; 2048];
        while let Ok((_len, src)) = recv_from_this_process(&socket, &mut buf).await {
            let _ = socket.send_to(reply, src).await;
        }
    });

    Some(Server { port, _task: task })
}

/// A loopback UDP port nothing listens on, held by this process for as long
/// as the value lives, so a datagram sent there draws the system's
/// port-unreachable and no other socket can take the port meanwhile.
///
/// Held by a socket connected to a second one, which it also holds: a
/// connected datagram socket takes only what its peer sends, so the system
/// finds no socket for a datagram from anywhere else and answers it as a
/// closed port, and a port a socket is bound to is never handed to one asking
/// for any port. A port found by binding one and letting it go can be handed
/// to another test's service between the letting go and the probe.
pub struct ClosedUdpPort {
    /// Its number.
    pub port: u16,
    _held: [std::net::UdpSocket; 2],
}

/// Takes a [`ClosedUdpPort`] on the IPv4 loopback.
pub fn closed_udp_loopback_port() -> ClosedUdpPort {
    let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("binds loopback");
    let held = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("binds loopback");
    held.connect(peer.local_addr().expect("a local address"))
        .expect("connects on loopback");
    let port = held.local_addr().expect("a local address").port();
    ClosedUdpPort {
        port,
        _held: [held, peer],
    }
}

/// A single-IP [`TargetMap`] over the given comma/range port spec (e.g. `"80"`
/// or `"22,80,443"`), as [`scanner::scan`] expects.
pub fn target_map(ip: IpAddr, ports: &str) -> TargetMap {
    let mut map = TargetMap::new();
    let mut ips = IpSet::new();
    ips.insert(ip);
    let port_set = PortSet::try_from(ports).expect("valid port spec");
    map.add_unit(TargetSet::new(ips, port_set));
    map
}

/// A single-IP [`IpSet`], as [`scanner::discover`] expects.
pub fn ip_set(ip: IpAddr) -> IpSet {
    let mut set = IpSet::new();
    set.insert(ip);
    set
}

/// The outcome of driving a scan to completion: the final host store, every
/// event emitted along the way, and the report the engine produced.
pub struct Outcome {
    pub store: HostStore,
    pub events: Vec<ScanEvent>,
    pub report: ScanReport,
}

impl Outcome {
    /// Everything the scan recorded, under the same name the live
    /// [`ScanSession`] gives it.
    pub fn hosts(&self) -> &HostStore {
        &self.store
    }

    /// The recorded host at `ip`, if the scan found one.
    pub fn host(&self, ip: IpAddr) -> Option<Host> {
        self.store.get(ip)
    }

    /// The state recorded for `ip:port`, if any port entry exists.
    pub fn port_state(&self, ip: IpAddr, port: u16) -> Option<PortState> {
        self.store
            .get(ip)
            .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
    }

    /// Whether a `HostUpdated` event was emitted for `ip`.
    pub fn saw_host_update(&self, ip: IpAddr) -> bool {
        self.events
            .iter()
            .any(|e| matches!(e, ScanEvent::HostUpdated(got) if got.addr() == ip))
    }
}

/// Runs a port scan to completion and collects its store and events. Runs the
/// shipped corpus; [`run_scan_with`] takes a caller's own.
pub async fn run_scan(map: TargetMap, cfg: &ZondConfig) -> Outcome {
    run_scan_with(map, cfg, Detections::embedded()).await
}

/// [`run_scan`] with a specific detection corpus, for the tests that add their own.
pub async fn run_scan_with(map: TargetMap, cfg: &ZondConfig, detections: Detections) -> Outcome {
    let (session, task) = scanner::scan(map, cfg, detections)
        .await
        .expect("scan starts");
    drive(session, task).await
}

/// Runs host discovery to completion and collects its store and events.
pub async fn run_discover(targets: IpSet, cfg: &ZondConfig) -> Outcome {
    let (session, task) = scanner::discover(targets, cfg)
        .await
        .expect("discover starts");
    drive(session, task).await
}

/// Awaits the task, then snapshots the store and drains the event channel.
/// Because the task has finished, every event has already been sent, so a
/// non-blocking drain captures whatever the channel still holds.
///
/// The channel is bounded and drops its oldest events, so this only collects
/// everything for a scan that stayed inside `ScanEvents::CAPACITY`. Every scan
/// in this suite is far smaller than that, and a gap is failed rather than
/// absorbed: an `Outcome` that quietly held half the events would answer
/// `Outcome::saw_host_update` with a `false` about the harness rather than
/// about the scan.
async fn drive(mut session: ScanSession, task: ScanTask) -> Outcome {
    let report = task.join().await.expect("scan task runs to completion");

    let store = session.hosts().clone();
    let mut events = Vec::new();
    while let Some(event) = session.events().try_recv() {
        assert!(
            !matches!(event, ScanEvent::EventsDropped { .. }),
            "this scan outran the event buffer; a test that needs every event \
             has to read the stream while the scan runs"
        );
        events.push(event);
    }

    Outcome {
        store,
        events,
        report,
    }
}

// ── Tier 2 fixtures ────────────────────────────────────────────────────────
//
// The simulated tiers need a host to probe *from*: a MAC and a set of addresses
// the scanners resolve their probe sources against. Nothing here touches the
// machine running the test, so these values are free to be whatever is most
// convenient, as long as every simulated target is on-link with one of them.

/// The MAC the simulated scanner host presents on the wire.
pub const SCANNER_MAC: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);

/// The simulated scanner host's own addresses.
pub const SCANNER_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
pub const SCANNER_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50);
/// The link-local address, which is what local discovery probes from and what
/// an ICMPv6 neighbour must address its reply to.
pub const SCANNER_LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x50);

/// The port a simulated raw port scan probes from, where a test does not care
/// which. The simulated network answers whatever port a probe came from, so
/// any would do; a fixed one keeps two runs of a test comparable.
pub const SCANNER_PORT: u16 = 54_321;

/// The target every simulated scan is pointed at, on-link with the addresses
/// above so a source always resolves.
pub const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
pub const TARGET_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x200));

/// The interface the simulated scanner host probes from.
///
/// It carries a link-local *and* a global IPv6 address because a real one does,
/// and because the two paths want different ones: local discovery sends from the
/// link-local, while the routed scanners resolve a source by longest matching
/// prefix and so need a subnet the v6 targets actually sit in.
pub fn scanner_interface() -> Link {
    // Non-zero index: a scope id of zero is what "no interface" means to the
    // kernel, so a fixture using it could not tell a recorded zone from a
    // missing one.
    Link::new("sim0", 7)
        .with_kind(LinkKind::Wired)
        .with_link_up(true)
        .with_physical(true)
        .with_addressing(Addressing::Broadcast)
        .with_mac(SCANNER_MAC)
        .with_addresses(vec![
            LinkAddress::new(IpAddr::V4(SCANNER_V4), 24),
            LinkAddress::new(IpAddr::V6(SCANNER_LINK_LOCAL), 64),
            LinkAddress::new(IpAddr::V6(SCANNER_V6), 64),
        ])
}

/// A link-local address as the store keys it, on the simulated segment.
///
/// `fe80::AA` names a different machine on every segment, so the store keys a
/// link-local host by the address *and* the interface it was read on — a bare
/// one names no host and finds none. A sweep over
/// [`scanner_interface`] records its neighbours on `sim0`, so this is how a test
/// asks for one back.
///
/// Every other address is its own whole key and needs nothing from this.
pub fn on_segment(ip: IpAddr) -> zond_engine::model::ip::scoped::ScopedIp {
    zond_engine::model::ip::scoped::ScopedIp::scoped(ip, scanner_interface().zone())
}

/// A source resolver over [`scanner_interface`], as the routed scanners expect.
pub fn scanner_resolver() -> SourceResolver {
    SourceResolver::from_links(&[scanner_interface()])
}

/// Feeds `targets` to `scanner` and drives it to completion.
///
/// The channel is closed before the scan is awaited, which is the signal a
/// [`PortScanner`] uses to know no more targets are coming. Without that it
/// would wait out its full deadline on every test.
pub async fn run_port_scanner<S: PortScanner + ?Sized>(scanner: &mut S, targets: Vec<Target>) {
    let (tx, rx) = tokio::sync::mpsc::channel(targets.len().max(1));
    // Numbered as the dispatcher would, so a strategy sees what it sees in a
    // real scan.
    for (position, target) in targets.into_iter().enumerate() {
        tx.send(PlannedTarget::new(position as u64, target))
            .await
            .expect("queue target");
    }
    drop(tx);

    scanner.scan(rx).await.expect("scanner runs to completion");
}

/// A TCP target, as a port scanner expects one.
pub fn tcp(ip: IpAddr, port: u16) -> Target {
    Target::new(ip, port, Protocol::Tcp)
}

/// A UDP target, as a port scanner expects one.
pub fn udp(ip: IpAddr, port: u16) -> Target {
    Target::new(ip, port, Protocol::Udp)
}

/// An SCTP target, as a port scanner expects one.
pub fn sctp(ip: IpAddr, port: u16) -> Target {
    Target::new(ip, port, Protocol::Sctp)
}

/// The state recorded for `ip:port` in a session's store.
///
/// The Tier 1 counterpart on [`Outcome`] reads a finished scan's snapshot; this
/// reads the live store a simulated scanner wrote into directly, since Tier 2
/// drives a single scanner rather than the whole `scan` pipeline.
pub fn port_state(session: &ScanSession, ip: IpAddr, port: u16) -> Option<PortState> {
    session
        .hosts()
        .get(ip)
        .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
}

/// The liveness verdict recorded for `ip`, or `None` if no host was recorded at
/// all. The two are worth distinguishing: a host present with
/// [`HostStatus::Unknown`] was probed and stayed silent, which is a different
/// outcome from never having been probed.
pub fn host_status(session: &ScanSession, ip: IpAddr) -> Option<HostStatus> {
    session.hosts().get(ip).map(|host| host.status())
}

/// Every protocol name recorded as evidence for `ip`'s status, sorted so a test
/// can assert on them without depending on set iteration order.
pub fn status_protocols(
    session: &ScanSession,
    ip: impl Into<zond_engine::model::ip::scoped::ScopedIp>,
) -> Vec<String> {
    let Some(host) = session.hosts().get(ip) else {
        return Vec::new();
    };
    let mut names: Vec<String> = host
        .reasons()
        .iter()
        .map(|reason| format!("{:?}", reason.protocol))
        .collect();
    names.sort();
    names
}
