// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a port scan makes of an address its sender says cannot be reached.
//!
//! A dead neighbour, or a name whose AAAA this host has no route to, is an
//! absent host and not a broken scanner. The sender says so in the class of
//! its refusal, and these tests hold the port scanners to reading it: every
//! port on the address takes one verdict, the address is reported as not
//! reached, and nothing is filed as a strategy that failed.
//!
//! The seam is the sender rather than the network. `fake_net` never fails a
//! send, because a scanner must not be able to tell a lost probe from an
//! ignored one; the refusal here is the opposite case, a probe that never
//! reached a network to be lost on, and the scanner has to say so. The two
//! shapes below are the two a real sender produces. A frame sender asks the
//! neighbour once and refuses every probe from the first. A raw socket hands
//! the kernel the same question, accepts the first few probes while it waits
//! for the answer, and refuses the rest once it has given up on it, so that
//! whether a port's probe was accepted depends on when it went out.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::support::fake_net::{FakeNet, Layer4, Policy};
use crate::support::*;
use zond_engine::ZondConfig;
use zond_engine::journal::settle::Outcome;
use zond_engine::model::exclusion::Exclusions;
use zond_engine::model::ip::set::IpSet;
use zond_engine::model::port::PortState;
use zond_engine::model::target::Target;
use zond_engine::model::technique::TcpScanTechnique;
use zond_engine::report::{ScanKind, ScanReport, TargetScope};
use zond_engine::scanner::recorder::PhaseRecorder;
use zond_engine::scanner::session::{ScanContext, ScanSession};
use zond_engine::scanner::strategy::ports::{TcpPortScanner, UdpPortScanner};
use zond_engine::system::privilege::Privilege;
use zond_engine::transport::probe::{Emission, ProbeSender, ProbeTransport, SendError};

/// An on-link address nothing answers for, beside [`TARGET`], which does.
const DEAD: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 201));

/// The ports asked of the dead address: enough that a verdict decided per port
/// by timing would come out mixed.
const PORTS: std::ops::RangeInclusive<u16> = 1..=20;

/// The live port beside them, so the scan is not a scan of nothing.
const LIVE: u16 = 80;

/// A sender that refuses every probe to [`DEAD`] once it has accepted the first
/// `accepted` of them, and hands every other probe to the network behind it.
///
/// The accepted ones are what a kernel does while it waits on an address
/// resolution it will give up on: it takes the write and discards the packet
/// later, so nothing reaches the fake network for them and they are never
/// answered.
struct DeadNeighbour {
    inner: Box<dyn ProbeSender>,
    accepted: usize,
    sent: AtomicUsize,
}

impl ProbeSender for DeadNeighbour {
    fn send(
        &self,
        segment: &[u8],
        src: IpAddr,
        dst: IpAddr,
        zone: Option<u32>,
        emission: Emission,
    ) -> Result<(), SendError> {
        if dst != DEAD {
            return self.inner.send(segment, src, dst, zone, emission);
        }
        if self.sent.fetch_add(1, Ordering::SeqCst) < self.accepted {
            return Ok(());
        }
        Err(SendError::Unroutable(format!(
            "failed to send to {dst}: No route to host (os error 65)"
        )))
    }
}

/// `net`'s transport with [`DeadNeighbour`] in front of its sender.
fn behind_a_dead_neighbour(net: &FakeNet, accepted: usize) -> ProbeTransport {
    let ProbeTransport { tx, rx, .. } = net.transport();
    ProbeTransport::from_parts(
        Box::new(DeadNeighbour {
            inner: tx,
            accepted,
            sent: AtomicUsize::new(0),
        }),
        rx,
    )
}

/// Closes a port-scan phase over what the scan wrote into `ctx`, which is where
/// the addresses a scan did not reach are reported.
fn phase(ctx: &ScanContext) -> ScanReport {
    let mut ips = IpSet::new();
    ips.insert(TARGET);
    ips.insert(DEAD);
    let scope = TargetScope::from_ip_set(&mut ips, &Exclusions::none());
    PhaseRecorder::start(
        ScanKind::PortScan,
        Privilege::Raw,
        scope,
        &ZondConfig::default(),
    )
    .finish(ctx)
}

/// The targets both scans are handed: every port of [`PORTS`] on the dead
/// address, and [`LIVE`] on the live one.
fn targets(target: fn(IpAddr, u16) -> Target) -> Vec<Target> {
    PORTS
        .map(|port| target(DEAD, port))
        .chain(std::iter::once(target(TARGET, LIVE)))
        .collect()
}

/// A SYN scan over a sender that accepts the first `accepted` probes to the
/// dead address and refuses the rest.
async fn syn_scan(accepted: usize) -> (ScanSession, ScanContext) {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET, LIVE, Policy::open());
    let (session, ctx) = ScanSession::new();
    let observer = ctx.clone();
    let targets = targets(tcp);
    let mut scanner = TcpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        TcpScanTechnique::Syn,
        behind_a_dead_neighbour(&net, accepted),
        targets.len(),
    );
    run_port_scanner(&mut scanner, targets).await;
    (session, observer)
}

/// Asserts the three halves of reading an absent host rightly, over whatever
/// scan produced `session` and `ctx`.
fn assert_read_as_absent(session: &ScanSession, ctx: &ScanContext, live: PortState) {
    let states: Vec<Option<PortState>> =
        PORTS.map(|port| port_state(session, DEAD, port)).collect();
    assert!(
        states
            .iter()
            .all(|state| *state == Some(PortState::Unasked)),
        "every port on an address nothing answers for takes the one verdict \
         that says it was not asked: {states:?}"
    );
    assert_eq!(
        port_state(session, TARGET, LIVE),
        Some(live),
        "the live host beside it is scanned as ever"
    );

    let settlements = ctx.settlements();
    assert_eq!(
        settlements.count(Outcome::Unroutable),
        PORTS.len() as u64,
        "each port is owed to a resume as unreachable rather than as lost work"
    );

    let failures = ctx.failures_snapshot();
    assert!(
        failures.is_empty(),
        "an absent host is not a scanner that failed: {failures:?}"
    );

    let report = phase(ctx);
    assert_eq!(
        report.phases()[0].unroutable(),
        [DEAD],
        "the address is reported as not reached"
    );
}

/// A frame sender asks the neighbour once and refuses every probe to it from
/// the first, so no probe to the address is ever accepted.
#[tokio::test]
async fn a_neighbour_refused_from_the_first_probe_reads_as_one_absent_host() {
    let (session, ctx) = syn_scan(0).await;
    assert_read_as_absent(&session, &ctx, PortState::Open);
}

/// A raw socket accepts the first probes while the kernel resolves the
/// neighbour and refuses the rest once it has given up. The accepted probes are
/// never answered, so read port by port they would come back as silence while
/// the refused ones came back unasked: the verdict would record when a probe
/// left rather than anything about the port.
#[tokio::test]
async fn probes_accepted_before_the_neighbour_was_given_up_on_take_the_same_verdict() {
    let (session, ctx) = syn_scan(7).await;
    assert_read_as_absent(&session, &ctx, PortState::Open);
}

/// The UDP scanner reads its sender through the same core, and its silence
/// verdict is the one a refused probe is most easily mistaken for.
#[tokio::test]
async fn a_udp_scan_reads_an_absent_host_the_same_way() {
    let net = FakeNet::new(Layer4::Udp).host(TARGET, LIVE, Policy::closed());
    let (session, ctx) = ScanSession::new();
    let observer = ctx.clone();
    let targets = targets(udp);
    let mut scanner = UdpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        behind_a_dead_neighbour(&net, 3),
        targets.len(),
        40_000,
    );
    run_port_scanner(&mut scanner, targets).await;

    assert_read_as_absent(&session, &observer, PortState::Closed);
}

/// A sender refusing a retry for a reason on this host is a fault worth
/// reporting, but the port it was retrying was asked: its verdict comes from
/// the attempts that did leave, and the report must not claim it went unasked.
#[tokio::test]
async fn a_refused_retry_is_not_reported_as_an_unasked_port() {
    /// Accepts the first probe to each port and refuses every one after it.
    struct RefusesRetries {
        inner: Box<dyn ProbeSender>,
        asked: std::sync::Mutex<std::collections::HashSet<Vec<u8>>>,
    }

    impl ProbeSender for RefusesRetries {
        fn send(
            &self,
            segment: &[u8],
            src: IpAddr,
            dst: IpAddr,
            zone: Option<u32>,
            emission: Emission,
        ) -> Result<(), SendError> {
            // The destination port, which is what a retry repeats.
            let port = segment[2..4].to_vec();
            if self.asked.lock().unwrap().insert(port) {
                return self.inner.send(segment, src, dst, zone, emission);
            }
            Err(SendError::Refused(
                "No buffer space available (os error 55)".to_string(),
            ))
        }
    }

    let net = FakeNet::new(Layer4::Tcp);
    let ProbeTransport { tx, rx, .. } = net.transport();
    let transport = ProbeTransport::from_parts(
        Box::new(RefusesRetries {
            inner: tx,
            asked: Default::default(),
        }),
        rx,
    );

    let (session, ctx) = ScanSession::new();
    let observer = ctx.clone();
    let targets: Vec<_> = (1..=4).map(|port| tcp(TARGET, port)).collect();
    let mut scanner = TcpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        TcpScanTechnique::Syn,
        transport,
        targets.len(),
    );
    run_port_scanner(&mut scanner, targets).await;

    for port in 1..=4 {
        assert_eq!(
            port_state(&session, TARGET, port),
            Some(PortState::Filtered),
            "asked once and unanswered is silence, not unasked"
        );
    }

    let failures = observer.failures_snapshot();
    assert_eq!(
        failures.len(),
        1,
        "the refusals are this host's: {failures:?}"
    );
    let reason = failures[0].reason();
    assert!(
        !reason.contains("recorded unasked"),
        "no port was recorded unasked, and the report must not say one was: {reason}"
    );
    assert!(
        reason.contains("No buffer space available"),
        "the sender's own words survive: {reason}"
    );
}
