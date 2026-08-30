// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What an [`EvasionProfile`] actually puts on the wire, read off the wire.
//!
//! Every knob on a profile exists to change a packet, and until this file
//! nothing outside the crate checked that any of them arrived. The unit tests
//! beside `evasion.rs` cover the profile's own arithmetic: that `with_padding`
//! reaches `segment_shaping`, that a framing technique forces the link layer.
//! They stop at the value. This runs a real scanner over [`FakeNet`] and reads
//! the segment it emitted.
//!
//! ## What this cannot cover, and why
//!
//! The seam sits above IP. A scanner hands the transport a finished Layer 4
//! segment, so the packet the hop limit, the spoofed hardware address and the
//! fragment size would have gone into is never built here, and nothing can be
//! asserted about it. What `ProbeSender::send` does carry alongside the
//! segment is the source address and an `Emission`, which is the scanner's
//! instruction for that header, so those three knobs are testable one step
//! short of the wire: the tests below say the scanner asked for them on every
//! probe, and say nothing about the packet a real sender would have produced.
//! Whether fragments come out the right size, whether a spoofed address
//! survives a switch, whether a low hop limit draws the error it is meant to,
//! all belong to Tier 3.
//!
//! Two things are out of reach entirely:
//!
//! - [`EvasionProfile::flags`] reaches a TCP scan through a private field that
//!   only [`TcpPortScanner::new`] sets, and that constructor opens its own
//!   transport. `with_transport` hard-codes it off, so no test outside the
//!   crate can send an arbitrary flag byte. The unit tests in
//!   `scanner::strategy::routed::port_scan` reach it by setting the field
//!   directly.
//! - The idle scan reads a zombie's IP-ID counter, which lives in the IP header
//!   the capture strips before a segment reaches here. `IdlePortScanner` has no
//!   `with_transport` either.
//!
//! ## How a profile gets into a scanner
//!
//! No `with_transport` constructor takes an [`EvasionProfile`]. What
//! `TcpPortScanner::new` does with one is set four fields on the shared
//! [`RawProbeScan`](zond_engine::scanner::strategy::routed::RawProbeScan) core,
//! and those fields are public, so [`shaped`] does the same thing to a scanner
//! built over a simulated transport. The step this does not cover is
//! `new` itself reading `tuning.evasion`, which needs a real socket.

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::ops::Range;

use common::fake_net::{FakeNet, Layer4, Policy, Probe};
use common::*;
use pnet_packet::Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use zond_engine::evasion::EvasionProfile;
use zond_engine::model::mac::MacAddr;
use zond_engine::model::port::PortState;
use zond_engine::model::technique::TcpScanTechnique;
use zond_engine::protocols::ip::HOP_LIMIT_ROUTED;
use zond_engine::scanner::session::ScanSession;
use zond_engine::scanner::strategy::routed::{RawPortScan, TcpPortScanner, UdpPortScanner};
use zond_engine::transport::probe::SendMode;

/// The source port both protocols probe from where a test is not asserting on
/// the source port itself. Pinned rather than left to the scanner's own random
/// choice so two runs can be compared byte for byte.
const PINNED_SRC_PORT: u16 = 54_321;

/// The source port the override tests ask for. A stateless filter that permits
/// returning DNS permits anything leaving from 53, which is the whole reason
/// the knob exists.
const DNS_PORT: u16 = 53;

/// How many bytes of padding the padding tests ask for.
const PADDING: u16 = 16;

/// Applies `profile` to a scanner built over a simulated transport, setting the
/// same four fields `TcpPortScanner::new` sets from `tuning.evasion`.
///
/// `flags` is the fifth and cannot be reached from here; see the module note.
fn shaped<S: RawPortScan>(scanner: &mut S, profile: &EvasionProfile) {
    let core = scanner.core_mut();
    core.src_port = profile.source_port_or(core.src_port);
    core.emission = profile.emission();
    core.shaping = profile.segment_shaping();
    core.decoys = profile.decoys.clone();
}

/// Runs a SYN scan of [`TARGET`] over the given ports under `profile`, with the
/// source port pinned unless the profile chooses one.
async fn syn_scan(profile: &EvasionProfile, ports: &[(u16, Policy)]) -> (ScanSession, FakeNet) {
    let mut net = FakeNet::new(Layer4::Tcp);
    for (port, policy) in ports {
        net = net.host(TARGET, *port, *policy);
    }

    let (session, ctx) = ScanSession::new();
    let mut scanner = TcpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        TcpScanTechnique::Syn,
        net.transport(),
        ports.len(),
    );
    scanner.core_mut().src_port = PINNED_SRC_PORT;
    shaped(&mut scanner, profile);

    let targets = ports.iter().map(|(port, _)| tcp(TARGET, *port)).collect();
    run_port_scanner(&mut scanner, targets).await;

    (session, net)
}

/// The UDP counterpart. The source port is a constructor argument here, because
/// a synthesized ICMP error has to be built around a port the test knows.
async fn udp_scan(profile: &EvasionProfile, ports: &[(u16, Policy)]) -> (ScanSession, FakeNet) {
    let mut net = FakeNet::new(Layer4::Udp);
    for (port, policy) in ports {
        net = net.host(TARGET, *port, *policy);
    }

    let (session, ctx) = ScanSession::new();
    let mut scanner = UdpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        net.transport(),
        ports.len(),
        profile.source_port_or(PINNED_SRC_PORT),
    );
    shaped(&mut scanner, profile);

    let targets = ports.iter().map(|(port, _)| udp(TARGET, *port)).collect();
    run_port_scanner(&mut scanner, targets).await;

    (session, net)
}

/// The one probe a single-port scan sent, or a failure naming how many there
/// were instead.
fn only_probe(net: &FakeNet) -> Probe {
    let probes = net.probes();
    assert_eq!(
        probes.len(),
        1,
        "expected exactly one probe, got {probes:?}"
    );
    probes.into_iter().next().expect("one probe")
}

// ── Source port ────────────────────────────────────────────────────────────

/// Both halves of the source-port override in one run: the probes leave from
/// the chosen port, and the answers addressed back to it are still recognized.
///
/// The second half is what makes the first worth having. A scan that pins its
/// source port and then cannot correlate what comes back to it has not evaded
/// anything, it has gone deaf, and the port would read `Filtered` while every
/// probe on the wire looked exactly right.
#[tokio::test]
async fn a_tcp_scan_sends_from_the_chosen_source_port_and_still_matches_the_reply() {
    let profile = EvasionProfile::default().with_source_port(DNS_PORT);
    let (session, net) = syn_scan(&profile, &[(80, Policy::open())]).await;

    assert_eq!(only_probe(&net).source_port, DNS_PORT);
    assert_eq!(
        port_state(&session, TARGET, 80),
        Some(PortState::Open),
        "the SYN+ACK came back to the chosen port and had to be read there"
    );
}

/// The same for UDP, where the port is held for the whole scan rather than
/// drawn afresh per probe, and where the reply is a datagram from the probed
/// port rather than an acknowledgement.
#[tokio::test]
async fn a_udp_scan_sends_from_the_chosen_source_port_and_still_matches_the_reply() {
    let profile = EvasionProfile::default().with_source_port(DNS_PORT);
    let (session, net) = udp_scan(&profile, &[(161, Policy::open())]).await;

    assert_eq!(only_probe(&net).source_port, DNS_PORT);
    assert_eq!(port_state(&session, TARGET, 161), Some(PortState::Open));
}

/// One port for the whole scan, not one per probe.
///
/// The TCP scanner draws a fresh high port per probe when nothing pins it, so
/// this is the difference the override makes rather than a restatement of the
/// test above: every probe in a multi-port scan leaves from the same place.
#[tokio::test]
async fn every_probe_in_a_scan_leaves_from_the_one_chosen_source_port() {
    let profile = EvasionProfile::default().with_source_port(DNS_PORT);
    let (_session, net) = syn_scan(
        &profile,
        &[
            (80, Policy::open()),
            (81, Policy::closed()),
            (82, Policy::open()),
        ],
    )
    .await;

    let probes = net.probes();
    assert_eq!(probes.len(), 3, "one probe per port, got {probes:?}");
    assert!(
        probes.iter().all(|probe| probe.source_port == DNS_PORT),
        "every probe should have left from {DNS_PORT}, got {:?}",
        probes.iter().map(|p| p.source_port).collect::<Vec<_>>()
    );
}

// ── Padding ────────────────────────────────────────────────────────────────

/// A padded UDP probe is longer by exactly what was asked for, carries the
/// original request unchanged in front of the padding, and is still a datagram:
/// the length field counts the extra bytes and the checksum covers them.
///
/// The length field is the half that matters. Padding appended without it is a
/// datagram every receiver truncates, so the probe would reach the port asking
/// a shorter question than the one it was built to ask.
#[tokio::test]
async fn padding_lengthens_a_udp_probe_and_leaves_the_datagram_well_formed() {
    let (_session, plain) = udp_scan(&EvasionProfile::default(), &[(53, Policy::open())]).await;
    let profile = EvasionProfile::default().with_padding(PADDING);
    let (session, padded) = udp_scan(&profile, &[(53, Policy::open())]).await;

    let plain = only_probe(&plain).bytes;
    let padded = only_probe(&padded).bytes;

    assert_eq!(
        padded.len(),
        plain.len() + usize::from(PADDING),
        "the datagram should have grown by exactly the padding"
    );

    let plain = UdpPacket::new(&plain).expect("an ordinary probe is a datagram");
    let datagram = UdpPacket::new(&padded).expect("a padded probe is still a datagram");
    let request = plain.payload().len();
    assert_eq!(
        &datagram.payload()[..request],
        plain.payload(),
        "the padding rides behind the request, which is unchanged"
    );

    assert_eq!(
        usize::from(datagram.get_length()),
        padded.len(),
        "the length field has to count the padding or a receiver truncates it"
    );
    assert_eq!(
        pnet_packet::udp::ipv4_checksum(&datagram, &SCANNER_V4, &target_v4()),
        datagram.get_checksum(),
        "the checksum has to cover the padding"
    );

    assert_eq!(
        port_state(&session, TARGET, 53),
        Some(PortState::Open),
        "a padded probe still draws an answer the scan can read"
    );
}

/// Padding on a TCP probe rides as segment payload, which is what makes it
/// unusual: a SYN carrying data is a shape most traffic never takes, and that
/// is the point of appending it.
#[tokio::test]
async fn padding_rides_as_payload_on_a_tcp_probe() {
    let profile = EvasionProfile::default().with_padding(PADDING);
    let (session, net) = syn_scan(&profile, &[(80, Policy::open())]).await;

    let bytes = only_probe(&net).bytes;
    let segment = TcpPacket::new(&bytes).expect("a padded probe is still a segment");
    let header_len = usize::from(segment.get_data_offset()) * 4;

    assert_eq!(
        bytes.len() - header_len,
        usize::from(PADDING),
        "the padding is payload, so the header offset must not have moved"
    );
    assert_eq!(
        pnet_packet::tcp::ipv4_checksum(&segment, &SCANNER_V4, &target_v4()),
        segment.get_checksum(),
        "an ordinary probe's checksum covers whatever it carries"
    );
    assert_eq!(port_state(&session, TARGET, 80), Some(PortState::Open));
}

// ── A deliberately wrong checksum ──────────────────────────────────────────

/// The corrupt checksum reaches the segment, where an ordinary probe's
/// verifies.
///
/// Asserted against the checksum the segment itself implies rather than against
/// a remembered number, so this says what a host would say: recompute over what
/// arrived, and it does not match.
///
/// Nothing at this seam drops the segment for it, which is the honest limit
/// here and also the shape of what the knob is for. A conformant host would
/// discard it and only a middlebox would answer, so a scan that gets a reply to
/// one must go on working normally rather than treat the answer as suspect, and
/// this is where that is checked.
#[tokio::test]
async fn a_corrupt_checksum_reaches_the_segment_and_the_scan_reads_the_reply_anyway() {
    let (_session, honest) = syn_scan(&EvasionProfile::default(), &[(80, Policy::open())]).await;
    let honest = only_probe(&honest).bytes;
    let honest = TcpPacket::new(&honest).expect("a probe is a segment");
    assert_eq!(
        pnet_packet::tcp::ipv4_checksum(&honest, &SCANNER_V4, &target_v4()),
        honest.get_checksum(),
        "an ordinary probe carries a checksum a host accepts"
    );

    let profile = EvasionProfile::default().with_bad_tcp_checksum(true);
    let (session, net) = syn_scan(&profile, &[(80, Policy::open())]).await;

    let bytes = only_probe(&net).bytes;
    let segment = TcpPacket::new(&bytes).expect("a corrupt checksum is still a segment");
    assert_ne!(
        pnet_packet::tcp::ipv4_checksum(&segment, &SCANNER_V4, &target_v4()),
        segment.get_checksum(),
        "the checksum on the wire has to be one a conformant host rejects"
    );

    assert_eq!(
        port_state(&session, TARGET, 80),
        Some(PortState::Open),
        "whoever answered a corrupt probe answered it, and the scan reads that"
    );
}

// ── A default profile changes nothing ──────────────────────────────────────

/// The promise `config`'s module doc makes to callers, checked on the one
/// protocol where it can be checked exactly: a UDP probe has no per-attempt
/// randomness at all, so two scans differing only in whether a default profile
/// was applied emit the same bytes.
///
/// This is the test that keeps evasion from becoming something a scan does by
/// accident. A default profile that started padding by one byte, or moved the
/// hop limit, would change what every ordinary scan puts on the wire and
/// nothing else would notice.
#[tokio::test]
async fn a_default_profile_leaves_a_udp_probe_byte_for_byte_unchanged() {
    let (_session, bare) = udp_scan_without_a_profile(&[(53, Policy::open())]).await;
    let (_session, defaulted) = udp_scan(&EvasionProfile::default(), &[(53, Policy::open())]).await;

    let bare = only_probe(&bare);
    let defaulted = only_probe(&defaulted);

    assert_eq!(
        bare.bytes, defaulted.bytes,
        "a default profile must not change a single byte of the datagram"
    );
    assert_eq!(bare.source, defaulted.source);
    assert_eq!(bare.source_port, defaulted.source_port);
    assert_eq!(
        bare.emission, defaulted.emission,
        "nor anything the sender was told about the header around it"
    );
}

/// The same promise for TCP, where two probes can never be byte-identical: a
/// scan draws a fresh nonce and a fresh timestamp for every attempt, on
/// purpose, so that a reply names the attempt it answers.
///
/// Those bytes are blanked and everything else is compared, which is still the
/// whole segment: the flags, the window, the option list, the header length and
/// the absence of a payload.
#[tokio::test]
async fn a_default_profile_leaves_a_tcp_probe_unchanged_but_for_its_nonce() {
    let (_session, bare) = syn_scan_without_a_profile(&[(80, Policy::open())]).await;
    let (_session, defaulted) = syn_scan(&EvasionProfile::default(), &[(80, Policy::open())]).await;

    let bare = only_probe(&bare);
    let defaulted = only_probe(&defaulted);

    assert_eq!(
        blanked(&bare.bytes),
        blanked(&defaulted.bytes),
        "a default profile must not change anything a scan did not randomise"
    );
    assert_eq!(bare.flags, defaulted.flags);
    assert_eq!(bare.source, defaulted.source);
    assert_eq!(bare.source_port, defaulted.source_port);
    assert_eq!(bare.emission, defaulted.emission);
}

// ── The header the sender is told to build ─────────────────────────────────

/// A chosen hop limit reaches every probe, and an unset one leaves the routed
/// default alone.
///
/// Both halves in one test because the failure worth catching is not a hop
/// limit that never arrives, which any single assertion finds, but one that
/// arrives whatever the profile said.
#[tokio::test]
async fn a_chosen_hop_limit_reaches_every_probe() {
    let (_session, routed) = syn_scan(&EvasionProfile::default(), &[(80, Policy::open())]).await;
    assert_eq!(only_probe(&routed).emission.hop_limit, HOP_LIMIT_ROUTED);

    let profile = EvasionProfile::default().with_ttl(7);
    let (_session, near) = syn_scan(&profile, &[(80, Policy::open()), (81, Policy::open())]).await;

    let probes = near.probes();
    assert_eq!(probes.len(), 2);
    assert!(
        probes.iter().all(|probe| probe.emission.hop_limit == 7),
        "every probe should expire seven hops out, got {:?}",
        probes
            .iter()
            .map(|p| p.emission.hop_limit)
            .collect::<Vec<_>>()
    );
}

/// A framing technique is carried to the sender as something only a self-built
/// frame can do, on every probe.
///
/// This is as far as the seam reaches on the send-mode question. Which sender a
/// scan opens is decided by `effective_send_mode` before a transport exists,
/// and here the transport is supplied, so what can be shown is the other side
/// of the same coin: the per-probe emission says it needs the link layer, which
/// is what makes the raw-socket sender refuse it rather than quietly send a
/// probe with the technique missing. The two are asserted together so they
/// cannot drift apart.
#[tokio::test]
async fn a_framing_technique_reaches_every_probe_as_a_link_layer_requirement() {
    let mac = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0xAA);
    let profile = EvasionProfile::default()
        .with_spoof_mac(mac)
        .with_fragment(28);

    assert_eq!(
        profile.effective_send_mode(SendMode::Auto),
        SendMode::Ethernet,
        "a scan asked to choose would have opened the link layer for this"
    );

    let (_session, net) = syn_scan(&profile, &[(80, Policy::open())]).await;
    let emission = only_probe(&net).emission;

    assert_eq!(emission.source_mac, Some(mac));
    assert_eq!(emission.fragment, Some(28));
    assert!(
        emission.requires_link_layer(),
        "so a raw socket refuses the probe instead of sending it unspoofed"
    );

    let (_session, plain) = syn_scan(&EvasionProfile::default(), &[(80, Policy::open())]).await;
    assert!(
        !only_probe(&plain).emission.requires_link_layer(),
        "and an ordinary scan is left on whatever path it opened"
    );
}

// ── Decoys ─────────────────────────────────────────────────────────────────

/// Every probe goes out, one per decoy plus the real one, and only the real
/// one's answer resolves the port.
///
/// A decoy is a probe in its own right, from its own address and its own
/// source port, which is what makes it look like a separate scanner rather
/// than a copy. Its reply therefore comes back to a port this scan is not
/// listening on, and that is what must keep a decoy from ever resolving
/// anything: a port credited to a decoy's answer would be a finding about a
/// packet this host did not send.
#[tokio::test]
async fn a_scan_among_decoys_sends_every_probe_and_resolves_the_port_from_the_real_one() {
    let decoys: Vec<IpAddr> = vec![
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 61)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 62)),
    ];
    let profile = EvasionProfile::default().with_decoys(decoys.clone());
    let (session, net) = udp_scan(&profile, &[(53, Policy::open())]).await;

    let probes = net.probes();
    assert_eq!(
        probes.len(),
        decoys.len() + 1,
        "one probe per decoy and one real one, got {probes:?}"
    );

    let mut sources: Vec<IpAddr> = probes.iter().map(|probe| probe.source).collect();
    sources.sort();
    let mut expected: Vec<IpAddr> = decoys.clone();
    expected.push(IpAddr::V4(SCANNER_V4));
    expected.sort();
    assert_eq!(
        sources, expected,
        "each decoy sends once and the real probe travels among them"
    );

    let real_ports: Vec<u16> = probes
        .iter()
        .filter(|probe| probe.source == IpAddr::V4(SCANNER_V4))
        .map(|probe| probe.source_port)
        .collect();
    assert_eq!(real_ports, vec![PINNED_SRC_PORT]);
    assert!(
        probes
            .iter()
            .filter(|probe| probe.source != IpAddr::V4(SCANNER_V4))
            .all(|probe| probe.source_port != PINNED_SRC_PORT),
        "a decoy leaving from this scan's own port would have its reply read"
    );

    let host = session.hosts().get(TARGET).expect("host recorded");
    assert_eq!(
        host.ports().filter(|port| port.number() == 53).count(),
        1,
        "three probes describe one port"
    );
    assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Open));
}

/// A decoy of the wrong address family is left out rather than sent to an
/// address it cannot reach.
#[tokio::test]
async fn a_decoy_is_only_used_against_a_target_of_its_own_family() {
    let usable: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 61));
    let profile = EvasionProfile::default()
        .with_decoys(vec![usable, "2001:db8::61".parse().expect("a v6 decoy")]);
    let (_session, net) = udp_scan(&profile, &[(53, Policy::open())]).await;

    let probes = net.probes();
    assert_eq!(
        probes.len(),
        2,
        "only the v4 decoy belongs beside a v4 probe, got {probes:?}"
    );
    assert!(probes.iter().any(|probe| probe.source == usable));
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// [`TARGET`] as the address type a checksum wants.
fn target_v4() -> Ipv4Addr {
    match TARGET {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => unreachable!("the simulated target is v4"),
    }
}

/// The bytes of a SYN probe a scan deliberately draws afresh for every attempt,
/// as offsets into the segment: the sequence number carrying the nonce, the
/// checksum computed over it, and the timestamp option's own value.
///
/// The option list begins at twenty, the maximum segment size takes four bytes
/// and SACK-permitted two, so the timestamp option's kind and length sit at 26
/// and its value at 28. [`blanked`] checks that rather than trusting it.
const PER_ATTEMPT: [Range<usize>; 3] = [4..8, 16..18, 28..32];

/// Where the timestamp option starts, and the two bytes that say it is one:
/// kind 8, length 10 (RFC 7323 §3).
const TIMESTAMP_OPTION: usize = 26;
const TIMESTAMP_KIND: [u8; 2] = [8, 10];

/// `segment` with its per-attempt bytes zeroed, so two probes from different
/// runs can be compared for everything a scan did not randomise.
fn blanked(segment: &[u8]) -> Vec<u8> {
    assert_eq!(
        segment[TIMESTAMP_OPTION..TIMESTAMP_OPTION + 2],
        TIMESTAMP_KIND,
        "the option list moved, so the blanked offsets no longer name what they say"
    );

    let mut blanked = segment.to_vec();
    for range in PER_ATTEMPT {
        blanked[range].fill(0);
    }
    blanked
}

/// [`syn_scan`] with no profile applied at all, which is what a default profile
/// has to be indistinguishable from.
async fn syn_scan_without_a_profile(ports: &[(u16, Policy)]) -> (ScanSession, FakeNet) {
    let mut net = FakeNet::new(Layer4::Tcp);
    for (port, policy) in ports {
        net = net.host(TARGET, *port, *policy);
    }

    let (session, ctx) = ScanSession::new();
    let mut scanner = TcpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        TcpScanTechnique::Syn,
        net.transport(),
        ports.len(),
    );
    // The one thing pinned rather than left alone: an unpinned TCP scan draws a
    // random source port per run, and two runs have to agree on it before their
    // segments can be compared.
    scanner.core_mut().src_port = PINNED_SRC_PORT;

    let targets = ports.iter().map(|(port, _)| tcp(TARGET, *port)).collect();
    run_port_scanner(&mut scanner, targets).await;

    (session, net)
}

/// [`udp_scan`] with no profile applied at all.
async fn udp_scan_without_a_profile(ports: &[(u16, Policy)]) -> (ScanSession, FakeNet) {
    let mut net = FakeNet::new(Layer4::Udp);
    for (port, policy) in ports {
        net = net.host(TARGET, *port, *policy);
    }

    let (session, ctx) = ScanSession::new();
    let mut scanner = UdpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        net.transport(),
        ports.len(),
        PINNED_SRC_PORT,
    );

    let targets = ports.iter().map(|(port, _)| udp(TARGET, *port)).collect();
    run_port_scanner(&mut scanner, targets).await;

    (session, net)
}

/// A profile a scan cannot put on the wire is refused when the scan is asked
/// for, not on the probes it would then fail to send.
///
/// The failure this closes: every probe refusing looks exactly like a network
/// with nothing on it. The scan returned a session, the session found no hosts,
/// and nothing anywhere said the fragment size was the reason.
#[tokio::test]
async fn a_scan_refuses_an_evasion_profile_it_could_never_honour() {
    use zond_engine::evasion::EvasionError;
    use zond_engine::protocols::ip::SMALLEST_FRAGMENT_MTU;
    use zond_engine::{ScanError, discover, scan};

    let mut cfg = common::test_config();
    cfg.evasion = EvasionProfile::default().with_fragment(SMALLEST_FRAGMENT_MTU - 1);

    let refused = discover(common::ip_set(common::LOOPBACK), &cfg)
        .await
        .err()
        .expect("the sweep is refused before it starts");
    assert!(
        matches!(
            refused,
            ScanError::Evasion(EvasionError::FragmentTooSmall { .. })
        ),
        "got {refused:?}"
    );

    let refused = scan(common::target_map(common::LOOPBACK, "80"), &cfg)
        .await
        .err()
        .expect("and so is the port scan");
    assert!(
        matches!(
            refused,
            ScanError::Evasion(EvasionError::FragmentTooSmall { .. })
        ),
        "got {refused:?}"
    );

    // And a profile that is merely unusual still runs.
    cfg.evasion = EvasionProfile::default().with_ttl(12).with_padding(8);
    assert!(
        discover(common::ip_set(common::LOOPBACK), &cfg)
            .await
            .is_ok(),
        "a valid profile is not refused"
    );
}
