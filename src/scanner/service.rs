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

use crate::model::ip::scoped::ScopedIp;
use crate::warn;
use tokio::time::timeout;

use crate::config::ServiceDetection;
use crate::config::limits::{CONNECT_CONCURRENCY, CONNECT_PROBE_TIMEOUT};
use crate::model::port::{Port, PortState, Protocol};
use crate::report::ScannerKind;
use crate::scanner::pool::ProbePool;
use crate::scanner::session::{ScanContext, Stage};
use crate::system::dial::Egress;

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
                    } = *found;
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

    for (target, port, protocol) in targets {
        if ctx.handle.should_stop() {
            break;
        }
        // A host whose budget ran out during the port scan is not asked what
        // its open ports are running. The ports keep whatever the port phase
        // recorded, which is a state without a service name, and the phase has
        // already named the address as one it left early.
        if ctx.host_expired(target.addr()) {
            continue;
        }
        let egress = ctx.egress_toward(target.addr());
        let detection = ctx.service_detection_on(detection, port, protocol);
        pool.admit(fingerprint_one(target, port, protocol, detection, egress))
            .await;
    }

    pool.drain().await;
    drop(pool);

    quiet.report(ctx, asked);
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
    reason: Option<String>,
}

impl QuietPorts {
    /// Files one port that could not be fingerprinted.
    fn record(&mut self, ip: &ScopedIp, number: u16, reason: String) {
        self.count += 1;
        if self.first.is_none() {
            self.first = Some(ip.endpoint(number));
            self.reason = Some(reason);
        }
    }

    /// The one line the ports amount to, named from the first of them.
    fn summary(first: &str, reason: &str, count: usize) -> String {
        match count - 1 {
            0 => format!("{first} could not be fingerprinted: {reason}"),
            1 => format!("{first} and 1 other port could not be fingerprinted: {reason}"),
            rest => format!("{first} and {rest} other ports could not be fingerprinted: {reason}"),
        }
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
        ctx.record_failure(
            ScannerKind::Service,
            Self::summary(first, reason, self.count),
        );

        // A port answered for is a port that takes a SYN and then has nothing to
        // say. Every one of them behaving that way is the path, not the host.
        if self.count == asked && asked >= QUIET_PORTS_WORTH_A_WORD {
            warn!(
                "all {asked} open ports went silent on connect; likely a middlebox, not the host"
            );
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
fn fingerprintable_ports(ctx: &ScanContext, over: Protocol) -> Vec<(ScopedIp, u16, Protocol)> {
    let mut targets = Vec::new();
    for host in ctx.store.iter() {
        let address = host.value().scoped_ip();
        for port in host.value().ports() {
            if port.protocol() == over
                && port.state() == PortState::Open
                && crate::fingerprint::reads_replies(port.number(), port.protocol())
            {
                targets.push((address.clone(), port.number(), port.protocol()));
            }
        }
    }
    targets
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
        /// Why it failed, in the operating system's words.
        reason: String,
    },
    /// Nothing was learned and nothing went wrong.
    Quiet,
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
}

/// Connects to one open port and fingerprints it.
///
/// A link-local address with no interface recorded against it yields no socket
/// address at all, and is skipped with a word about why. Attempting the
/// connection anyway would fail with an error describing the network, which is a
/// claim about the neighbour rather than about what this host knows.
///
/// Every connection it makes to the port leaves by `egress`.
async fn fingerprint_one(
    target: ScopedIp,
    port_number: u16,
    protocol: Protocol,
    detection: ServiceDetection,
    egress: Egress,
) -> Attempt {
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

    let (port, about_the_host, banners) = match protocol {
        Protocol::Tcp => {
            let stream = match timeout(CONNECT_PROBE_TIMEOUT, egress.connect(addr)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    return Attempt::Unreachable {
                        ip: target,
                        number: port_number,
                        reason: e.to_string(),
                    };
                }
                Err(_) => {
                    return Attempt::Unreachable {
                        ip: target,
                        number: port_number,
                        reason: format!("no answer within {CONNECT_PROBE_TIMEOUT:?}"),
                    };
                }
            };
            crate::fingerprint::fingerprint_tcp_via(stream, port, detection, egress).await
        }
        // Silence is not a failure here: a UDP port that says nothing has told
        // the scan what it had to.
        Protocol::Udp => match crate::fingerprint::fingerprint_udp_via(addr, port, egress).await {
            Some(fingerprinted) => fingerprinted,
            None => return Attempt::Quiet,
        },
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
    }))
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
    /// eighty-three with them.
    #[test]
    fn many_quiet_ports_collapse_into_one_line() {
        let mut quiet = QuietPorts::default();
        let ip: ScopedIp = "192.0.2.1".parse::<IpAddr>().expect("an address").into();
        for port in 0..83u16 {
            quiet.record(&ip, 1000 + port, "no answer within 1.5s".to_string());
        }

        let summary = QuietPorts::summary(
            quiet.first.as_deref().expect("a first port"),
            quiet.reason.as_deref().expect("a reason"),
            quiet.count,
        );
        assert_eq!(
            summary,
            "192.0.2.1:1000 and 82 other ports could not be fingerprinted: no answer within 1.5s"
        );
    }

    /// One of them reads as itself rather than as "and 0 other ports".
    #[test]
    fn one_quiet_port_is_named_alone() {
        assert_eq!(
            QuietPorts::summary("192.0.2.1:22", "connection refused", 1),
            "192.0.2.1:22 could not be fingerprinted: connection refused"
        );
        assert_eq!(
            QuietPorts::summary("192.0.2.1:22", "connection refused", 2),
            "192.0.2.1:22 and 1 other port could not be fingerprinted: connection refused"
        );
    }

    /// An IPv6 endpoint keeps its brackets, so the port is not read as another
    /// group of the address.
    #[test]
    fn an_ipv6_endpoint_stays_bracketed() {
        let mut quiet = QuietPorts::default();
        let ip: ScopedIp = "2001:db8::1".parse::<IpAddr>().expect("an address").into();
        quiet.record(&ip, 443, "no answer within 1.5s".to_string());

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
}
