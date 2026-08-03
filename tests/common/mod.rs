// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Shared helpers for the portable (Tier 1) integration tests.
//!
//! These tests drive the *public* scanning API — [`scanner::scan`] and
//! [`scanner::discover`] — end to end against real protocol servers on
//! loopback, so they run identically on macOS and Linux with no root and no
//! network setup. Anything that needs raw sockets, firewalls, or injected
//! latency is covered by in-crate unit tests instead (see `tests/README.md`).
//!
//! A note on privilege: when the process is root, `scan`/`discover` take their
//! raw-socket ARP/SYN paths, whose behaviour against loopback is
//! environment-specific. The assertions here that depend on the TCP-connect
//! fallback call [`is_privileged`] and skip rather than flake; the
//! privilege-independent ones (lifecycle, empty inputs) always run.

// Each integration-test binary includes this module but uses only part of it,
// so unused helpers are expected per-crate.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use dashmap::DashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use zond_engine::core::config::ZondConfig;
use zond_engine::core::models::host::Host;
use zond_engine::core::models::ip::set::IpSet;
use zond_engine::core::models::port::{PortSet, PortState};
use zond_engine::core::models::target::{TargetMap, TargetSet};
use zond_engine::core::session::{ScanEvent, ScanSession};
use zond_engine::scanner::{self, ScanTask};

/// The loopback address every portable test targets.
pub const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A quiet, non-interactive config with DNS disabled, so a result reflects only
/// what was actually observed on the wire — no reverse-lookup side effects.
pub fn test_config() -> ZondConfig {
    ZondConfig {
        no_banner: true,
        no_dns: true,
        disable_input: true,
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

/// The outcome of driving a scan to completion: the final host store plus every
/// event emitted along the way.
pub struct Outcome {
    pub store: Arc<DashMap<IpAddr, Host>>,
    pub events: Vec<ScanEvent>,
}

impl Outcome {
    /// The recorded host at `ip`, if the scan found one.
    pub fn host(&self, ip: IpAddr) -> Option<Host> {
        self.store.get(&ip).map(|h| h.clone())
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
    task.join().await.expect("scan task runs to completion");

    let store = session.store.clone();
    let mut events = Vec::new();
    while let Ok(event) = session.events.try_recv() {
        events.push(event);
    }

    Outcome { store, events }
}
