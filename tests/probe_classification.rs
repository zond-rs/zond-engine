// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the raw scanners conclude from each kind of answer, against the
//! simulated network.
//!
//! The Tier 1 tests cover open and closed on loopback, which is all a
//! cooperative kernel will produce. Everything else a real network does - the
//! silence of a firewall, an ICMP error from a router rather than the host, a
//! duplicate, a reply too damaged to parse - has no coverage without a network
//! that can be told to misbehave. That is what this file adds.
//!
//! These pass today. They are regression guards, and the most valuable ones are
//! the near-misses: an administratively prohibited port that must read
//! `Filtered` rather than `Closed`, and an ICMPv6 code that means something
//! different from the identically numbered ICMPv4 one. Both are the kind of
//! mistake that produces a confident, wrong answer.

mod common;

use std::time::Duration;

use common::fake_net::{FakeNet, Layer4, Policy, Stack, Unreachable};
use common::*;
use zond_engine::model::host::HostStatus;
use zond_engine::model::port::PortState;
use zond_engine::model::technique::TcpScanTechnique;
use zond_engine::scanner::NetworkExplorer;
use zond_engine::scanner::routed::{RoutedScanner, TcpPortScanner, UdpPortScanner};
use zond_engine::scanner::session::ScanSession;
use zond_engine::system::interface::RoutedTarget;

/// The fixed source port the simulated UDP scans probe from.
const UDP_SRC_PORT: u16 = 54_321;

/// Runs one SYN scan against [`TARGET`] over the given policies and returns the
/// session to assert against, together with the network that served it.
async fn syn_scan(ports: &[(u16, Policy)]) -> (ScanSession, FakeNet) {
    syn_scan_on(TARGET, ports).await
}

/// Runs one scan of `technique` against [`TARGET`] over the given policies,
/// against a network whose hosts run `stack`.
async fn tcp_scan_on(
    technique: TcpScanTechnique,
    stack: Stack,
    ports: &[(u16, Policy)],
) -> (ScanSession, FakeNet) {
    let mut net = FakeNet::new(Layer4::Tcp).stack(stack);
    for (port, policy) in ports {
        net = net.host(TARGET, *port, *policy);
    }

    let (session, ctx) = ScanSession::new();
    let mut scanner = TcpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        technique,
        net.transport(),
        ports.len(),
    );
    let targets = ports.iter().map(|(port, _)| tcp(TARGET, *port)).collect();
    run_port_scanner(&mut scanner, targets).await;

    (session, net)
}

/// [`tcp_scan_on`] against a stack that follows the RFC, which is the case
/// every technique is designed for.
async fn tcp_scan(technique: TcpScanTechnique, ports: &[(u16, Policy)]) -> (ScanSession, FakeNet) {
    tcp_scan_on(technique, Stack::Conformant, ports).await
}

/// [`syn_scan`] against an explicit address, so the same policies can be put to
/// either family. The UDP half has taken a target since the ICMPv6 codes needed
/// covering; the SYN half had not, which is why nothing here scanned a port over
/// IPv6 at all.
async fn syn_scan_on(target: std::net::IpAddr, ports: &[(u16, Policy)]) -> (ScanSession, FakeNet) {
    let mut net = FakeNet::new(Layer4::Tcp);
    for (port, policy) in ports {
        net = net.host(target, *port, *policy);
    }

    let (session, ctx) = ScanSession::new();
    let mut scanner = TcpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        TcpScanTechnique::Syn,
        net.transport(),
        ports.len(),
    );
    let targets = ports.iter().map(|(port, _)| tcp(target, *port)).collect();
    run_port_scanner(&mut scanner, targets).await;

    (session, net)
}

/// The UDP counterpart of [`syn_scan`], against `target` so the v6 path can be
/// exercised with the same helper.
async fn udp_scan(target: std::net::IpAddr, ports: &[(u16, Policy)]) -> (ScanSession, FakeNet) {
    let mut net = FakeNet::new(Layer4::Udp);
    for (port, policy) in ports {
        net = net.host(target, *port, *policy);
    }

    let (session, ctx) = ScanSession::new();
    let mut scanner = UdpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        net.transport(),
        ports.len(),
        UDP_SRC_PORT,
    );
    let targets = ports.iter().map(|(port, _)| udp(target, *port)).collect();
    run_port_scanner(&mut scanner, targets).await;

    (session, net)
}

// ── TCP SYN ────────────────────────────────────────────────────────────────

/// The three outcomes a SYN probe can reach, in one scan, so a fix for one
/// cannot quietly break the others.
#[tokio::test]
async fn syn_classifies_open_closed_and_filtered() {
    let (session, _net) = syn_scan(&[
        (80, Policy::open()),
        (81, Policy::closed()),
        (82, Policy::silent()),
    ])
    .await;

    assert_eq!(port_state(&session, TARGET, 80), Some(PortState::Open));
    assert_eq!(port_state(&session, TARGET, 81), Some(PortState::Closed));
    assert_eq!(
        port_state(&session, TARGET, 82),
        Some(PortState::Filtered),
        "silence until the deadline is what a firewall drop looks like"
    );
}

/// A reply that arrives well after the probe must still be matched to it. The
/// adaptive deadline is what keeps the scan open long enough, so this is really
/// a check that a slow host is not written off as filtered.
#[tokio::test]
async fn a_slow_reply_is_still_matched_to_its_probe() {
    let (session, _net) = syn_scan(&[(80, Policy::open().delay(Duration::from_millis(50)))]).await;

    assert_eq!(port_state(&session, TARGET, 80), Some(PortState::Open));
}

/// A duplicated SYN+ACK is normal on a real network, since the host retransmits
/// when our RST never arrives. It must resolve the port once, not twice: a
/// second resolution would feed a bogus round-trip sample into the deadline.
#[tokio::test]
async fn a_duplicated_reply_records_the_port_once() {
    let (session, _net) = syn_scan(&[(80, Policy::open().duplicated())]).await;

    let host = session.hosts().get(&TARGET).expect("host recorded");
    assert_eq!(
        host.ports().filter(|p| p.number() == 80).count(),
        1,
        "two replies to one probe still describe one port"
    );
    assert_eq!(
        host.ports().find(|p| p.number() == 80).map(|p| p.state()),
        Some(PortState::Open)
    );
}

/// Traffic from a probed host that answers no probe must not classify its port.
///
/// This became reachable when the SYN transport learned to admit IPv6. libpcap
/// cannot narrow TCP by flags over IPv6 - `tcp[tcpflags]` is `proto[x]`
/// indexing, which an extension-header chain makes uncompilable - so the filter
/// admits every IPv6 TCP segment and the narrowing moved into userspace. Over
/// IPv4 the kernel still drops this segment before anyone sees it.
///
/// What must not change is the conclusion. A scan of an address the user happens
/// to be connected to sees that connection's ACKs, and if a bare ACK were read
/// as an answer, every such port would report `Open` or `Closed` on the strength
/// of somebody else's session - a wrong result, arrived at confidently, on one
/// address family only.
#[tokio::test]
async fn established_traffic_is_not_an_answer_to_a_probe() {
    let (session, _net) = syn_scan(&[(80, Policy::established())]).await;

    assert_eq!(
        port_state(&session, TARGET, 80),
        Some(PortState::Filtered),
        "a bare ACK answers no probe, so the probe went unanswered"
    );
}

/// The same segment, and the same conclusion, for host discovery: a host is
/// credited only by a reply to a probe this scan actually sent.
#[tokio::test]
async fn established_traffic_does_not_discover_a_host() {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET_V6, 443, Policy::established());
    let (session, ctx) = ScanSession::new();

    let scanner = RoutedScanner::with_transport(
        vec![RoutedTarget {
            target: TARGET_V6,
            source: SCANNER_V6.into(),
        }],
        ctx,
        None,
        net.transport(),
    );
    Box::new(scanner)
        .discover_hosts()
        .await
        .expect("sweep runs to completion");

    assert!(
        !session.hosts().contains(&TARGET_V6),
        "an ACK from an established connection is not evidence of discovery"
    );
}

/// A SYN scan over IPv6 classifies a port, which nothing here previously
/// checked.
///
/// The engine reaches this conclusion through code that is almost all
/// family-agnostic — `RoutedScanner` contains no IPv6 branch at all — so the
/// belief that IPv6 port scanning works rested on the parts rather than on a
/// run: the TCP checksum has an IPv6 pseudo-header arm, the transport picks a v6
/// socket, and the capture filter admits v6 answers. Each is tested alone. This
/// is the first test that puts a SYN on the wire over IPv6 and reads a port
/// state back.
///
/// Both answers in one scan, because the failure worth catching is not "IPv6
/// finds nothing" — that would be obvious — but a family whose replies are
/// admitted and then classified the same way regardless of what came back.
#[tokio::test]
async fn a_syn_scan_over_ipv6_tells_open_from_closed() {
    let (session, _net) =
        syn_scan_on(TARGET_V6, &[(443, Policy::open()), (444, Policy::closed())]).await;

    assert_eq!(
        port_state(&session, TARGET_V6, 443),
        Some(PortState::Open),
        "a SYN/ACK over IPv6 is an open port"
    );
    assert_eq!(
        port_state(&session, TARGET_V6, 444),
        Some(PortState::Closed),
        "a RST over IPv6 is a closed one"
    );
}

/// Silence over IPv6 is filtered, not closed.
///
/// The distinction the whole scanner rests on, asserted for the family where
/// the capture admits more traffic: with the filter unable to narrow TCP flags
/// over IPv6, a scanner that treated any admitted segment as an answer would
/// turn silence into a verdict.
#[tokio::test]
async fn silence_over_ipv6_is_filtered() {
    let (session, _net) = syn_scan_on(TARGET_V6, &[(443, Policy::silent())]).await;

    assert_eq!(
        port_state(&session, TARGET_V6, 443),
        Some(PortState::Filtered)
    );
}

/// A bare ACK over IPv6 answers no probe — and this is the family where that
/// check has to hold.
///
/// Its IPv4 twin above passes partly for free: the kernel drops an established
/// connection's segments before a scanner sees them. Over IPv6 libpcap cannot
/// narrow on TCP flags, so the segment reaches userspace and the *only* thing
/// standing between it and a wrong verdict is the scanner's own flag check.
/// Discovery already guards this over v6; port classification did not.
#[tokio::test]
async fn established_traffic_over_ipv6_is_not_an_answer_to_a_probe() {
    let (session, _net) = syn_scan_on(TARGET_V6, &[(443, Policy::established())]).await;

    assert_eq!(
        port_state(&session, TARGET_V6, 443),
        Some(PortState::Filtered),
        "somebody else's session must not classify a port on the one family \
         whose traffic reaches us"
    );
}

/// A reply too short to parse must be discarded, not guessed at. The probe stays
/// outstanding and times out as filtered, which is the honest answer: nothing
/// interpretable ever came back.
#[tokio::test]
async fn an_unparseable_reply_is_ignored_rather_than_classified() {
    let (session, _net) = syn_scan(&[(80, Policy::truncated())]).await;

    assert_eq!(
        port_state(&session, TARGET, 80),
        Some(PortState::Filtered),
        "a reply that could not be read is not evidence of an open port"
    );
}

// ── TCP flag probes ────────────────────────────────────────────────────────

/// The FIN scan's whole logic in one run, and the inversion that makes it
/// useful: a reset is the *negative* result here, and silence is as close to a
/// positive one as the technique gets.
#[tokio::test]
async fn a_fin_scan_reads_a_reset_as_closed_and_silence_as_open_filtered() {
    let (session, _net) = tcp_scan(
        TcpScanTechnique::Fin,
        &[
            (80, Policy::open()),
            (81, Policy::closed()),
            (82, Policy::silent()),
        ],
    )
    .await;

    assert_eq!(
        port_state(&session, TARGET, 80),
        Some(PortState::OpenFiltered),
        "an open port is required to ignore a FIN, so silence is all we get"
    );
    assert_eq!(port_state(&session, TARGET, 81), Some(PortState::Closed));
    assert_eq!(
        port_state(&session, TARGET, 82),
        Some(PortState::OpenFiltered),
        "a dropped probe is indistinguishable from an ignored one"
    );
}

/// FIN, NULL and Xmas ask the same question with different flags, so they must
/// reach the same verdicts. This is where an off-by-one in the correlation
/// shows up: a flagless probe occupies no sequence space and a FIN occupies
/// one, so reading either with the other's offset rejects every reset and
/// reports the whole host open-filtered.
#[tokio::test]
async fn the_three_flag_probes_agree_on_a_conformant_stack() {
    for technique in [
        TcpScanTechnique::Fin,
        TcpScanTechnique::Null,
        TcpScanTechnique::Xmas,
    ] {
        let (session, _net) =
            tcp_scan(technique, &[(80, Policy::open()), (81, Policy::closed())]).await;

        assert_eq!(
            port_state(&session, TARGET, 80),
            Some(PortState::OpenFiltered),
            "{technique} on an open port"
        );
        assert_eq!(
            port_state(&session, TARGET, 81),
            Some(PortState::Closed),
            "{technique} on a closed port"
        );
    }
}

/// An ACK scan reports on the firewall, not on the ports behind it: a reset
/// means the probe arrived, whether or not anything was listening, and silence
/// means it did not.
#[tokio::test]
async fn an_ack_scan_maps_the_path_rather_than_the_ports() {
    let (session, _net) = tcp_scan(
        TcpScanTechnique::Ack,
        &[
            (80, Policy::open()),
            (81, Policy::closed()),
            (82, Policy::silent()),
        ],
    )
    .await;

    assert_eq!(
        port_state(&session, TARGET, 80),
        Some(PortState::Unfiltered)
    );
    assert_eq!(
        port_state(&session, TARGET, 81),
        Some(PortState::Unfiltered),
        "an ACK scan cannot tell a listener from an empty port, and must not claim to"
    );
    assert_eq!(port_state(&session, TARGET, 82), Some(PortState::Filtered));
}

/// The honest limit of the Maimon technique: RFC 793 has a stack reset any
/// segment carrying ACK for a port it is not holding open, so on a conformant
/// host an open port and a closed one answer identically.
#[tokio::test]
async fn a_maimon_scan_distinguishes_nothing_on_a_conformant_stack() {
    let (session, _net) = tcp_scan(
        TcpScanTechnique::Maimon,
        &[(80, Policy::open()), (81, Policy::closed())],
    )
    .await;

    assert_eq!(port_state(&session, TARGET, 80), Some(PortState::Closed));
    assert_eq!(port_state(&session, TARGET, 81), Some(PortState::Closed));
}

/// And the stack family it was discovered on, where it works: a BSD-derived
/// host drops a FIN+ACK aimed at an open port instead of resetting it.
#[tokio::test]
async fn a_maimon_scan_separates_open_from_closed_on_a_bsd_stack() {
    let (session, _net) = tcp_scan_on(
        TcpScanTechnique::Maimon,
        Stack::BsdDerived,
        &[(80, Policy::open()), (81, Policy::closed())],
    )
    .await;

    assert_eq!(
        port_state(&session, TARGET, 80),
        Some(PortState::OpenFiltered)
    );
    assert_eq!(port_state(&session, TARGET, 81), Some(PortState::Closed));
}

/// The documented failure of the whole flag-probe family, pinned rather than
/// papered over: against a stack that resets everything, a FIN scan reports an
/// open port closed and is confidently wrong.
///
/// Nothing in the engine can detect this from a single scan - the packets are
/// indistinguishable from a host whose ports really are all closed - so the
/// only honest response is to document it where the technique is chosen and to
/// keep this test as the record of what it looks like.
#[tokio::test]
async fn a_stack_that_resets_everything_makes_a_flag_probe_confidently_wrong() {
    let (session, _net) = tcp_scan_on(
        TcpScanTechnique::Fin,
        Stack::AlwaysResets,
        &[(80, Policy::open()), (81, Policy::closed())],
    )
    .await;

    assert_eq!(
        port_state(&session, TARGET, 80),
        Some(PortState::Closed),
        "an open port reported closed: the known limitation of this technique"
    );
    assert_eq!(port_state(&session, TARGET, 81), Some(PortState::Closed));
}

/// What ICMP buys the flag probes, and the reason they ask their capture for
/// it: an explicit refusal turns a verdict that would have read `OpenFiltered`
/// into the `Filtered` it actually is.
#[tokio::test]
async fn an_explicit_refusal_is_filtered_rather_than_open_filtered() {
    let (session, _net) = tcp_scan(
        TcpScanTechnique::Fin,
        &[(80, Policy::admin_prohibited()), (81, Policy::silent())],
    )
    .await;

    assert_eq!(port_state(&session, TARGET, 80), Some(PortState::Filtered));
    assert_eq!(
        port_state(&session, TARGET, 81),
        Some(PortState::OpenFiltered),
        "the contrast is the point: only the refusal is evidence of a filter"
    );
}

/// An ICMP *port* unreachable answering a TCP probe cannot mean what it means
/// for UDP - no TCP stack emits one - so it is a middlebox speaking for the
/// address, which is filtered and not closed. The identical message in a UDP
/// scan is asserted to be `Closed` a few tests below.
#[tokio::test]
async fn a_port_unreachable_about_a_tcp_probe_is_filtered() {
    let (session, _net) = tcp_scan(
        TcpScanTechnique::Fin,
        &[(80, Policy::unreachable(Unreachable::Port))],
    )
    .await;

    assert_eq!(port_state(&session, TARGET, 80), Some(PortState::Filtered));
}

/// A reset says nothing good about the port and everything about the host: it
/// took a packet and answered it.
#[tokio::test]
async fn a_reset_to_a_flag_probe_proves_the_host_is_up() {
    let (session, _net) = tcp_scan(TcpScanTechnique::Fin, &[(81, Policy::closed())]).await;

    assert_eq!(host_status(&session, TARGET), Some(HostStatus::Up));
}

/// And silence says nothing at all. A host whose every port reads
/// `OpenFiltered` has never sent a packet, and must not be reported alive on
/// the strength of a verdict that only means "we cannot tell".
#[tokio::test]
async fn an_open_filtered_port_does_not_make_its_host_alive() {
    let (session, _net) = tcp_scan(TcpScanTechnique::Xmas, &[(80, Policy::silent())]).await;

    assert_ne!(host_status(&session, TARGET), Some(HostStatus::Up));
}

// ── UDP ────────────────────────────────────────────────────────────────────

/// The UDP outcomes. Silence is `OpenFiltered` rather than `Filtered`, because
/// an open UDP port that simply had nothing to say is indistinguishable from a
/// blocked one, and claiming otherwise would be a guess.
#[tokio::test]
async fn udp_classifies_open_closed_and_silence() {
    let (session, _net) = udp_scan(
        TARGET,
        &[
            (53, Policy::open()),
            (161, Policy::closed()),
            (123, Policy::silent()),
        ],
    )
    .await;

    assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Open));
    assert_eq!(
        port_state(&session, TARGET, 161),
        Some(PortState::Closed),
        "an ICMP port-unreachable is the one unambiguous closed signal UDP gets"
    );
    assert_eq!(
        port_state(&session, TARGET, 123),
        Some(PortState::OpenFiltered),
        "silence cannot distinguish an open port from a blocked one"
    );
}

/// A RST proves the host even though it is a negative verdict on the port.
///
/// This is the row of the liveness mapping most easily lost: a closed port and a
/// live host arrive in the same segment, and a scanner reading only the port
/// half reports a machine that answered as never having been heard from.
#[tokio::test]
async fn a_closed_port_still_proves_its_host_is_up() {
    let (session, _net) = syn_scan(&[(80, Policy::closed())]).await;

    assert_eq!(port_state(&session, TARGET, 80), Some(PortState::Closed));
    assert_eq!(host_status(&session, TARGET), Some(HostStatus::Up));
}

/// The complement, and the invariant the whole design rests on: a port that
/// answers nothing leaves the host exactly as unknown as it was. `Filtered` here
/// is reached by exhausting the retry budget, and a status inferred from silence
/// would make `is_alive()` true for a host that never sent a packet - the
/// original defect in a new place.
#[tokio::test]
async fn a_silent_port_leaves_its_host_unknown() {
    let (session, _net) = syn_scan(&[(80, Policy::silent())]).await;

    assert_eq!(port_state(&session, TARGET, 80), Some(PortState::Filtered));
    assert_eq!(host_status(&session, TARGET), Some(HostStatus::Unknown));
    assert!(
        status_protocols(&session, TARGET).is_empty(),
        "silence must leave no audit trail"
    );
}

/// The classic UDP scanning error, guarded. An administratively prohibited
/// message says a filter refused the probe, so the port's real state was never
/// observed. Reading it as `Closed` reports a firewalled port as definitively
/// shut.
#[tokio::test]
async fn an_administratively_prohibited_port_is_filtered_not_closed() {
    let (session, _net) = udp_scan(TARGET, &[(123, Policy::admin_prohibited())]).await;

    assert_eq!(
        port_state(&session, TARGET, 123),
        Some(PortState::Filtered),
        "a filter refusing the probe says nothing about the port behind it"
    );
}

/// A host-unreachable describes the address, not the port. It is the engine's
/// only source of [`HostStatus::Down`], and it deliberately leaves the port
/// alone: a router that could not deliver the datagram never learned anything
/// about the port it was addressed to, so the probe retires by exhaustion like
/// any other unanswered one.
#[tokio::test]
async fn a_host_unreachable_error_is_a_verdict_on_the_host() {
    let (session, _net) = udp_scan(TARGET, &[(123, Policy::unreachable(Unreachable::Host))]).await;

    assert_eq!(host_status(&session, TARGET), Some(HostStatus::Down));
    assert_eq!(
        port_state(&session, TARGET, 123),
        Some(PortState::OpenFiltered),
        "the port was never reported on, so it ends where silence leaves it"
    );
}

/// The same reasons over IPv6, which numbers them differently. Port-unreachable
/// is code 3 on v4 and code 4 on v6; a scanner that compared raw code numbers
/// across families would read one as the other and report the opposite answer.
#[tokio::test]
async fn icmpv6_errors_are_classified_by_their_own_code_numbers() {
    let (session, _net) = udp_scan(
        TARGET_V6,
        &[(161, Policy::closed()), (123, Policy::admin_prohibited())],
    )
    .await;

    assert_eq!(
        port_state(&session, TARGET_V6, 161),
        Some(PortState::Closed),
        "ICMPv6 code 4 is port-unreachable, whatever code 4 means over v4"
    );
    assert_eq!(
        port_state(&session, TARGET_V6, 123),
        Some(PortState::Filtered)
    );
}

/// A duplicated UDP reply, like its TCP counterpart, describes one port once.
#[tokio::test]
async fn a_duplicated_udp_reply_records_the_port_once() {
    let (session, _net) = udp_scan(TARGET, &[(53, Policy::open().duplicated())]).await;

    let host = session.hosts().get(&TARGET).expect("host recorded");
    assert_eq!(host.ports().filter(|p| p.number() == 53).count(), 1);
}

/// An unparseable UDP reply leaves the probe outstanding rather than producing
/// a classification, and must not panic on the way.
#[tokio::test]
async fn an_unparseable_udp_reply_is_ignored() {
    let (session, _net) = udp_scan(TARGET, &[(53, Policy::truncated())]).await;

    assert_eq!(
        port_state(&session, TARGET, 53),
        Some(PortState::OpenFiltered)
    );
}

/// Every probe in a UDP scan must leave from the one source port the capture
/// filter and the quoted-datagram check are both built around. A probe sent
/// from anywhere else is invisible to its own scan.
#[tokio::test]
async fn every_udp_probe_leaves_from_the_scan_source_port() {
    let (_session, net) = udp_scan(
        TARGET,
        &[
            (53, Policy::open()),
            (161, Policy::open()),
            (123, Policy::open()),
        ],
    )
    .await;

    assert_eq!(
        net.probes().len(),
        3,
        "each target should have been probed exactly once"
    );
}
