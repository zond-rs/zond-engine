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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use zond_engine::core::config::ZondConfig;
use zond_engine::core::models::host::{Host, HostStatus};
use zond_engine::core::models::ip::set::IpSet;
use zond_engine::core::models::port::{PortSet, PortState, Protocol};
use zond_engine::core::models::target::{Target, TargetMap, TargetSet};
use zond_engine::core::report::ScanReport;
use zond_engine::core::session::{HostStore, ScanEvent, ScanSession};
use zond_engine::scanner::{self, PortScanner, ScanTask};
use zond_engine::system::interface::SourceResolver;

/// The loopback address every portable test targets.
pub const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A config with DNS disabled, so a result reflects only what was actually
/// observed on the wire — no reverse-lookup side effects.
pub fn test_config() -> ZondConfig {
    ZondConfig {
        no_dns: true,
        ..Default::default()
    }
}

/// True when the process is running as root and would therefore take the raw
/// ARP/SYN scan paths rather than the portable TCP-connect fallback.
///
/// The connect-fallback assertions are only deterministic unprivileged, so they
/// use this to skip cleanly instead of flaking under a privileged test run.
pub fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        // geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
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
        while let Ok((mut sock, _)) = listener.accept().await {
            let _ = sock.write_all(banner).await;
            let _ = sock.flush().await;
            // Drop closes the connection; the banner has already been sent.
        }
    });

    Server { port, _task: task }
}

/// Reserves and immediately frees a loopback port, yielding a number that is
/// closed (connection-refused) for the remainder of the test.
pub async fn closed_loopback_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind to reserve a port");
    let port = listener.local_addr().expect("reserved addr").port();
    drop(listener);
    port
}

/// Serves a simple UDP response. On the first packet received, it writes `reply`
/// back to the sender and exits. This ensures a valid UDP response is generated
/// for the scanner to classify the port as Open.
pub async fn spawn_udp_server(reply: &'static [u8]) -> Server {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind loopback udp server");
    let port = socket.local_addr().expect("server local addr").port();

    let task = tokio::spawn(async move {
        let mut buf = vec![0; 1024];
        // Just wait for one packet and reply
        if let Ok((_len, src)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(reply, src).await;
        }
    });

    Server { port, _task: task }
}

/// Reserves and immediately frees a UDP loopback port, yielding a number that is
/// guaranteed to generate an ICMP Port Unreachable.
pub async fn closed_udp_loopback_port() -> u16 {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind to reserve a udp port");
    let port = socket.local_addr().expect("reserved addr").port();
    drop(socket);
    port
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
        self.store.get(&ip)
    }

    /// The state recorded for `ip:port`, if any port entry exists.
    pub fn port_state(&self, ip: IpAddr, port: u16) -> Option<PortState> {
        self.store
            .get(&ip)
            .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
    }

    /// Whether a `HostUpdated` event was emitted for `ip`.
    pub fn saw_host_update(&self, ip: IpAddr) -> bool {
        self.events
            .iter()
            .any(|e| matches!(e, ScanEvent::HostUpdated(got) if *got == ip))
    }
}

/// Runs a port scan to completion and collects its store and events.
pub async fn run_scan(map: TargetMap, cfg: &ZondConfig) -> Outcome {
    let (session, task) = scanner::scan(map, cfg).await.expect("scan starts");
    drive(session, task).await
}

/// Runs host discovery to completion and collects its store and events.
pub async fn run_discover(targets: IpSet, cfg: &ZondConfig) -> Outcome {
    let (session, task) = scanner::discover(targets, cfg)
        .await
        .expect("discover starts");
    drive(session, task).await
}

/// Awaits the task, then snapshots the store and drains the (unbounded) event
/// channel. Because the task has finished, every event has already been sent, so
/// a non-blocking drain captures all of them.
async fn drive(mut session: ScanSession, task: ScanTask) -> Outcome {
    let report = task.join().await.expect("scan task runs to completion");

    let store = session.hosts().clone();
    let mut events = Vec::new();
    while let Some(event) = session.events().try_recv() {
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
pub const SCANNER_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);

/// The simulated scanner host's own addresses.
pub const SCANNER_V4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
pub const SCANNER_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50);
/// The link-local address, which is what local discovery probes from and what
/// an ICMPv6 neighbour must address its reply to.
pub const SCANNER_LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x50);

/// The target every simulated scan is pointed at, on-link with the addresses
/// above so a source always resolves.
pub const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
pub const TARGET_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x200));

/// The interface the simulated scanner host probes from.
///
/// It carries a link-local *and* a global IPv6 address because a real one does,
/// and because the two paths want different ones: local discovery sends from the
/// link-local, while the routed scanners resolve a source by longest matching
/// prefix and so need a subnet the v6 targets actually sit in.
pub fn scanner_interface() -> NetworkInterface {
    let ips = vec![
        IpNetwork::V4(Ipv4Network::new(SCANNER_V4, 24).expect("valid v4 prefix")),
        IpNetwork::V6(Ipv6Network::new(SCANNER_LINK_LOCAL, 64).expect("valid v6 prefix")),
        IpNetwork::V6(Ipv6Network::new(SCANNER_V6, 64).expect("valid v6 prefix")),
    ];

    NetworkInterface {
        name: "sim0".to_string(),
        description: String::new(),
        // Non-zero: a scope id of zero is what "no interface" means to the
        // kernel, so a fixture using it could not tell a recorded zone from a
        // missing one.
        index: 7,
        mac: Some(SCANNER_MAC),
        ips,
        flags: 0,
    }
}

/// A source resolver over [`scanner_interface`], as the routed scanners expect.
pub fn scanner_resolver() -> SourceResolver {
    SourceResolver::from_interfaces(&[scanner_interface()])
}

/// Feeds `targets` to `scanner` and drives it to completion.
///
/// The channel is closed before the scan is awaited, which is the signal a
/// [`PortScanner`] uses to know no more targets are coming. Without that it
/// would wait out its full deadline on every test.
pub async fn run_port_scanner<S: PortScanner + ?Sized>(scanner: &mut S, targets: Vec<Target>) {
    let (tx, rx) = tokio::sync::mpsc::channel(targets.len().max(1));
    for target in targets {
        tx.send(target).await.expect("queue target");
    }
    drop(tx);

    scanner.scan(rx).await.expect("scanner runs to completion");
}

/// A TCP target, as a port scanner expects one.
pub fn tcp(ip: IpAddr, port: u16) -> Target {
    Target {
        ip,
        port,
        protocol: Protocol::Tcp,
    }
}

/// A UDP target, as a port scanner expects one.
pub fn udp(ip: IpAddr, port: u16) -> Target {
    Target {
        ip,
        port,
        protocol: Protocol::Udp,
    }
}

/// The state recorded for `ip:port` in a session's store.
///
/// The Tier 1 counterpart on [`Outcome`] reads a finished scan's snapshot; this
/// reads the live store a simulated scanner wrote into directly, since Tier 2
/// drives a single scanner rather than the whole `scan` pipeline.
pub fn port_state(session: &ScanSession, ip: IpAddr, port: u16) -> Option<PortState> {
    session
        .hosts()
        .get(&ip)
        .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
}

/// The liveness verdict recorded for `ip`, or `None` if no host was recorded at
/// all. The two are worth distinguishing: a host present with
/// [`HostStatus::Unknown`] was probed and stayed silent, which is a different
/// outcome from never having been probed.
pub fn host_status(session: &ScanSession, ip: IpAddr) -> Option<HostStatus> {
    session.hosts().get(&ip).map(|host| host.status())
}

/// Every protocol name recorded as evidence for `ip`'s status, sorted so a test
/// can assert on them without depending on set iteration order.
pub fn status_protocols(session: &ScanSession, ip: IpAddr) -> Vec<String> {
    let Some(host) = session.hosts().get(&ip) else {
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
