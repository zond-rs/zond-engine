// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local-segment discovery against the simulated LAN.
//!
//! This is the path with the least coverage historically, because it is the one
//! that cannot be faked with sockets: it builds Ethernet frames, sends them on
//! an interface, and identifies a neighbour by the source MAC of what comes
//! back. Until the segment could be simulated, none of it ran outside a real
//! network with real privileges.
//!
//! The cases worth guarding are the ones where discovery decides *identity*
//! rather than mere presence: one host answering at several addresses must be
//! recorded once, and a targeted run must not solicit the whole segment.

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use common::fake_lan::{FakeLan, LanHost, LanProbe};
use common::*;
use pnet::datalink::MacAddr;
use zond_engine::core::models::host::HostStatus;
use zond_engine::core::models::ip::set::IpSet;
use zond_engine::core::session::ScanSession;
use zond_engine::scanner::NetworkExplorer;
use zond_engine::scanner::local::{LocalScanner, Scope};

const PEER_A: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0xAA);
const PEER_B: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0xBB);

fn v4(host: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, host))
}

/// Runs one sweep of `lan` over `targets` and returns the session to assert
/// against.
async fn sweep(lan: &FakeLan, targets: &[IpAddr], scope: Scope) -> ScanSession {
    let mut ips = IpSet::new();
    for ip in targets {
        ips.insert(*ip);
    }
    ips.canonicalize();

    let (session, ctx) = ScanSession::new();
    let scanner =
        LocalScanner::with_handle(scanner_interface(), ips, ctx, None, scope, lan.handle())
            .expect("scanner builds over the simulated segment");

    Box::new(scanner)
        .discover_hosts()
        .await
        .expect("sweep runs to completion");

    session
}

/// A host that answers ARP is discovered, and its MAC is recorded from the
/// reply rather than guessed.
#[tokio::test]
async fn an_answering_host_is_discovered_with_its_mac() {
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A));
    let session = sweep(&lan, &[v4(10)], Scope::Targeted).await;

    let host = session.store.get(&v4(10)).expect("host discovered");
    assert_eq!(
        host.mac().map(|m| m.to_string()),
        Some(PEER_A.to_string()),
        "the MAC must come from the ARP reply"
    );
}

/// A discovered host records *why* it is considered alive, from the scan rather
/// than from a fixture.
///
/// This is the assertion the engine went without: for as long as no scanner
/// wrote a status, every host in every report came back `unknown` and
/// `hosts_alive` was always `0`, while the tests that should have caught it
/// compared a summary against the hosts in the same report - `0 == 0` - or set
/// the status themselves on a hand-built host. An ARP reply is the strongest
/// liveness evidence obtainable, so if anything is ever `Up`, this is.
#[tokio::test]
async fn an_answering_host_records_what_proved_it_alive() {
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A));
    let session = sweep(&lan, &[v4(10)], Scope::Targeted).await;

    let host = session.store.get(&v4(10)).expect("host discovered");
    assert_eq!(host.status(), HostStatus::Up);
    assert!(host.is_alive());
    assert_eq!(status_protocols(&session, v4(10)), vec!["Arp".to_string()]);
    assert!(
        host.reasons().iter().all(|reason| reason.source.is_none()),
        "the host answered for itself, so no reason may name another sender"
    );
}

/// The IPv6 half of the same contract: an IPv6 neighbour is alive on its own
/// evidence, and that evidence names the probe that actually found it.
///
/// The probe is an ICMPv6 echo request to the all-nodes group, so what comes
/// back is an echo reply and `icmp_echo` is what a report has to say. Recording
/// it as `Ndp` - which the engine did, and which every export and every
/// benchmark then repeated - claims a neighbor advertisement nobody sent, over a
/// protocol the engine does not yet speak. It is the difference between a
/// measurement of IPv6 coverage and a label, and it matters most at the moment
/// NDP does arrive: with both credited to `ndp`, no before-and-after could tell
/// the two mechanisms apart.
#[tokio::test]
async fn an_ipv6_neighbour_is_alive_by_the_probe_that_found_it() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let lan = FakeLan::new()
        .host(v4(10), LanHost::at(PEER_A))
        .host(peer_v6, LanHost::at(PEER_B));

    let targets: Vec<IpAddr> = (10..=20).map(v4).collect();
    let session = sweep(&lan, &targets, Scope::Sweep).await;

    let host = session.store.get(&peer_v6).expect("neighbour discovered");
    assert_eq!(host.status(), HostStatus::Up);
    assert_eq!(
        status_protocols(&session, peer_v6),
        vec!["IcmpEcho".to_string()],
        "an echo reply is evidence of an echo probe, not of neighbour discovery"
    );
}

/// A neighbour found at a link-local address carries the interface it was found
/// on, and that address can be connected to.
///
/// Without it, local discovery hands every later phase an address it cannot use.
/// `fe80::AA` names a different machine on every segment, and a `SocketAddrV6`
/// with a zero scope id is refused by the kernel however reachable the neighbour
/// is — so service detection, fingerprinting and the connect fallback would each
/// fail against a host discovery had just proved was there, with an error
/// describing the network rather than the omission.
///
/// The local scanner is the only strategy that can supply this. A routed probe
/// crosses whatever path the kernel chose and never learns which interface it
/// left by; this one is bound to a segment by construction.
#[tokio::test]
async fn an_ipv6_neighbour_carries_the_interface_it_was_found_on() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let lan = FakeLan::new().host(peer_v6, LanHost::at(PEER_B));

    let targets: Vec<IpAddr> = (10..=20).map(v4).collect();
    let session = sweep(&lan, &targets, Scope::Sweep).await;

    let host = session.store.get(&peer_v6).expect("neighbour discovered");
    let zone = host
        .zone()
        .expect("a link-local neighbour needs its interface");
    assert_eq!(zone.name(), "sim0");

    let address = host.scoped_ip();
    assert_eq!(address.to_string(), "fe80::aa%sim0");
    assert!(
        !address.is_unusable(),
        "an address discovery found must be one the next phase can open a socket to"
    );
    match address
        .to_socket_addr(443)
        .expect("a scoped address is usable")
    {
        std::net::SocketAddr::V6(v6) => assert_eq!(
            v6.scope_id(),
            7,
            "the scope id is what makes a link-local destination reachable"
        ),
        std::net::SocketAddr::V4(_) => panic!("an IPv6 host produced a V4 socket address"),
    }
}

/// A targeted IPv6 run probes the address it was given.
///
/// This is what neighbour discovery buys that the all-nodes echo cannot. That
/// echo asks the whole segment one question, so a targeted scan must not send it
/// — scanning one host may not wake its neighbours — and before solicitation
/// existed that left a targeted IPv6 run sending *no packet at all*: the ARP
/// iterator is built from the IPv4 targets, the echo is gated off, and the loop
/// idled to its deadline reporting nothing. A solicitation names one address, so
/// it can be asked without asking anyone else.
#[tokio::test]
async fn a_targeted_ipv6_run_probes_its_target() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let bystander = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xBB));
    let lan = FakeLan::new()
        .host(peer_v6, LanHost::at(PEER_B))
        .host(bystander, LanHost::at(PEER_A));

    let session = sweep(&lan, &[peer_v6], Scope::Targeted).await;

    assert!(
        session.store.contains_key(&peer_v6),
        "a targeted IPv6 run must probe the address it was given"
    );
    assert_eq!(
        status_protocols(&session, peer_v6),
        vec!["Ndp".to_string()],
        "an advertisement is evidence of neighbour discovery, and now there is some"
    );
    assert!(
        !session.store.contains_key(&bystander),
        "asking about one address must not wake the rest of the segment"
    );
    assert!(
        !lan.probes()
            .iter()
            .any(|probe| matches!(probe, LanProbe::Solicitation { .. })),
        "the all-nodes echo is a sweep's probe, not a targeted run's"
    );
}

/// A lost solicitation is retried, so an IPv6 neighbour is not reported absent
/// because one frame went missing.
///
/// The IPv6 half of the contract `retransmission.rs` holds the ARP path to.
/// Solicitation is what makes it expressible at all: the ledger owns an
/// outstanding probe per address, which the all-nodes echo — one packet answered
/// by whoever feels like it — gives it nothing to do with.
#[tokio::test]
async fn a_lost_solicitation_is_retried_and_the_neighbour_is_still_found() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let lan = FakeLan::new().host(peer_v6, LanHost::at(PEER_B).drop_first(1));

    let session = sweep(&lan, &[peer_v6], Scope::Targeted).await;

    assert!(
        session.store.contains_key(&peer_v6),
        "a neighbour that answered the second solicitation is still a live host"
    );
    let solicits = lan
        .probes()
        .iter()
        .filter(|probe| matches!(probe, LanProbe::Solicit { .. }))
        .count();
    assert!(
        solicits > 1,
        "the lost solicitation should have been retried, saw {solicits}"
    );
}

/// A neighbour that answers from a different address than the one asked about is
/// still credited to the address that was asked about, with a round trip.
///
/// This is the shape a real segment produced. A host with several IPv6 addresses
/// answers a solicitation from whichever its stack prefers, so a phone solicited
/// at `…::21e9` replied from `…:14f0:ca99:5818:74ee`. Keyed on the frame's
/// source, that reply retires no probe — the ledger is holding one for the
/// address that was solicited — so it yields no round trip and files the host
/// under an address the scan never asked about. Measured on the real network:
/// only the router, whose advertisement happened to come from the solicited
/// address, produced a latency at all.
///
/// The advertisement's target field is what ties the reply to the question, and
/// reading it is the difference between a host with a measurement and a host
/// with a blank where one belongs.
#[tokio::test]
async fn a_neighbour_answering_from_another_address_is_still_measured() {
    let solicited = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x21e9);
    let preferred = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0x14f0, 0xca99, 0x5818, 0x74ee);
    let lan = FakeLan::new().host(
        IpAddr::V6(solicited),
        LanHost::at(PEER_B).answering_from(preferred),
    );

    let session = sweep(&lan, &[IpAddr::V6(solicited)], Scope::Targeted).await;

    let host = session
        .store
        .get(&IpAddr::V6(solicited))
        .expect("the host must be keyed by the address that was asked about");
    assert!(
        host.min_rtt().is_some(),
        "an advertisement answering our solicitation is a round trip we can measure"
    );
    assert!(
        host.ips().contains(&IpAddr::V6(preferred)),
        "the address it answered from belongs to the same host and is worth recording"
    );
    assert_eq!(
        status_protocols(&session, IpAddr::V6(solicited)),
        vec!["Ndp".to_string()]
    );
}

/// A neighbour found by overhearing is asked directly, so it arrives with a
/// round trip rather than a blank.
///
/// Measured on a real segment: nearly every IPv6 host a sweep reported came from
/// an advertisement nobody had solicited — neighbours resolving each other,
/// announcing an address, answering somebody else's question, all of it visible
/// to a promiscuous capture. That is genuine evidence the host exists, and it is
/// evidence of a conversation we were not part of, so there was no probe to
/// measure against and every one of those hosts arrived with no latency at all.
///
/// One packet settles it. The address came off the wire seconds ago, so a
/// solicitation to it is answered by the host itself, which both times the path
/// and proves the neighbour is answering now rather than having answered someone
/// else a moment earlier.
#[tokio::test]
async fn an_overheard_neighbour_is_asked_directly_and_then_measured() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    // Declared on the segment but never a target, so the only way it is heard of
    // first is the unsolicited advertisement the fake sends on its own.
    let lan = FakeLan::new()
        .host(peer_v6, LanHost::at(PEER_B))
        .advertising_unsolicited(peer_v6);

    let session = sweep(&lan, &[v4(10)], Scope::Sweep).await;

    let host = session
        .store
        .get(&peer_v6)
        .expect("an overheard advertisement is still a discovered host");
    assert!(
        host.min_rtt().is_some(),
        "an overheard neighbour must be asked directly so its path can be measured"
    );

    let solicits = lan
        .probes()
        .iter()
        .filter(|probe| matches!(probe, LanProbe::Solicit { target, .. } if IpAddr::V6(*target) == peer_v6))
        .count();
    assert_eq!(
        solicits, 1,
        "asked exactly once: a second solicitation is identical on the wire, so an \
         advertisement answering either could not say which - and the measurement \
         this exists for would be discarded, having already cost a packet"
    );
}

/// A neighbour slow to answer its confirmation is still measured.
///
/// This is the case that broke on a real segment. The retry schedule is sized
/// from whatever the scan has been measuring, and on a LAN that is ARP replies
/// arriving in single-digit milliseconds — so a solicitation is retried within
/// tens of milliseconds, long before a device on wifi rouses itself to answer.
/// Two solicitations are identical on the wire, so the advertisement cannot say
/// which it answers, Karn's rule discards the sample, and the host arrives with
/// a blank where its latency belongs. Every wifi neighbour on the test segment
/// landed exactly there: `answered over Ndp after 2 attempts, so it is not
/// timed`.
///
/// A confirmation is not retried, so the reply is unambiguous however long it
/// takes. The host was already known to exist — only the measurement was ever at
/// stake, and retrying is what loses it.
#[tokio::test]
async fn a_slow_confirmation_is_still_measured() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let lan = FakeLan::new()
        .host(
            peer_v6,
            LanHost::at(PEER_B).delay(Duration::from_millis(400)),
        )
        .advertising_unsolicited(peer_v6);

    let session = sweep(&lan, &[v4(10)], Scope::Sweep).await;

    let host = session.store.get(&peer_v6).expect("neighbour discovered");
    assert!(
        host.min_rtt().is_some(),
        "a reply slower than the retry schedule is still the answer to the one \
         solicitation that was sent"
    );
    assert_eq!(
        lan.probes()
            .iter()
            .filter(|probe| matches!(probe, LanProbe::Solicit { target, .. } if IpAddr::V6(*target) == peer_v6))
            .count(),
        1,
        "waiting is what makes the sample usable; asking again is what destroys it"
    );
}

/// A sweep does not stop listening for a confirmation it has just paid a packet
/// for.
///
/// The confirmation is deliberately outside the retry ledger, and the ledger is
/// what keeps the loop alive for every other outstanding probe — so without a
/// window of its own the sweep sends a solicitation and then exits, which is a
/// strange thing to spend a packet on. The delay here is longer than the sweep
/// would otherwise run for.
#[tokio::test]
async fn a_sweep_waits_for_the_confirmation_it_sent() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let lan = FakeLan::new()
        .host(
            peer_v6,
            LanHost::at(PEER_B).delay(Duration::from_millis(900)),
        )
        .advertising_unsolicited(peer_v6);

    let session = sweep(&lan, &[v4(10)], Scope::Sweep).await;

    assert!(
        session
            .store
            .get(&peer_v6)
            .is_some_and(|host| host.min_rtt().is_some()),
        "the answer arrived within the window a neighbour is allowed to take"
    );
}

/// A solicited neighbour answering on IPv6's timescale is timed, not written off.
///
/// The measurement this exists for, taken from a capture of a real sweep. Three
/// solicitations to one address left within **75 milliseconds** of each other and
/// the advertisement arrived **670 ms to 1.7 s later**: every attempt spent, the
/// probe written off, and the answer landing to find no record of the question.
/// The same segment answers ARP in six milliseconds, and that is exactly the
/// problem — the retry schedule was derived from a round-trip estimate ARP
/// dominates, so it collapsed to its floor and dragged the IPv6 probe down with
/// it.
///
/// 700 ms is inside the range those replies actually landed in, and comfortably
/// past anything ARP's schedule would have waited.
#[tokio::test]
async fn a_solicited_neighbour_answering_slowly_is_still_timed() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let lan = FakeLan::new().host(
        peer_v6,
        LanHost::at(PEER_B).delay(Duration::from_millis(700)),
    );

    let session = sweep(&lan, &[peer_v6], Scope::Targeted).await;

    let host = session.store.get(&peer_v6).expect("neighbour discovered");
    assert!(
        host.min_rtt().is_some(),
        "an answer at 700ms is what an IPv6 neighbour on wifi does, not a timeout"
    );
    assert_eq!(
        lan.probes()
            .iter()
            .filter(|probe| matches!(probe, LanProbe::Solicit { .. }))
            .count(),
        1,
        "the first attempt must still be outstanding when the answer arrives, or \
         two identical solicitations make the sample unattributable"
    );
}

/// An address with nothing on it produces no host. Discovery must not invent a
/// neighbour from silence.
#[tokio::test]
async fn an_empty_address_produces_no_host() {
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A));
    let session = sweep(&lan, &[v4(10), v4(11)], Scope::Targeted).await;

    assert!(session.store.contains_key(&v4(10)));
    assert!(
        !session.store.contains_key(&v4(11)),
        "silence is not evidence of a host"
    );
}

/// A slow ARP reply still counts. The adaptive deadline has to hold the sweep
/// open long enough for a segment that is merely busy.
#[tokio::test]
async fn a_slow_arp_reply_still_discovers_the_host() {
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A).delay(Duration::from_millis(50)));
    let session = sweep(&lan, &[v4(10)], Scope::Targeted).await;

    assert!(session.store.contains_key(&v4(10)));
}

/// One machine holding two addresses is one host, not two.
///
/// This is what the MAC-to-IP map exists for, and getting it wrong inflates
/// every result on a segment where multi-homing is normal. The second address
/// must be folded into the host discovered first rather than creating a new
/// entry.
#[tokio::test]
async fn one_machine_answering_at_two_addresses_is_recorded_once() {
    let lan = FakeLan::new()
        .host(v4(10), LanHost::at(PEER_A))
        .host(v4(11), LanHost::at(PEER_A));
    let session = sweep(&lan, &[v4(10), v4(11)], Scope::Targeted).await;

    assert_eq!(
        session.store.len(),
        1,
        "two addresses behind one MAC are one machine"
    );
}

/// Two machines are two hosts, which is the other half of the check above: the
/// deduplication must key on the MAC and not collapse everything it sees.
#[tokio::test]
async fn two_machines_are_recorded_separately() {
    let lan = FakeLan::new()
        .host(v4(10), LanHost::at(PEER_A))
        .host(v4(11), LanHost::at(PEER_B));
    let session = sweep(&lan, &[v4(10), v4(11)], Scope::Targeted).await;

    assert_eq!(session.store.len(), 2);
}

/// Discovery of a named address does not report the neighbours it never asked
/// about.
///
/// A sweep records every IPv6 neighbour that answers the all-nodes echo, target
/// set or not, which is what makes `lan` find IPv6-only devices. Applying it to
/// every discovery made `zond <one-address>` report eight machines — surprising
/// on your own network and indiscreet on somebody else's. The behaviour still
/// exists; it now has to be asked for.
#[tokio::test]
async fn discovery_of_one_address_does_not_report_the_whole_segment() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let bystander = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xBB));
    let lan = FakeLan::new()
        .host(peer_v6, LanHost::at(PEER_B))
        .host(bystander, LanHost::at(PEER_A));

    let session = sweep(&lan, &[peer_v6], Scope::Targeted).await;

    assert!(session.store.contains_key(&peer_v6));
    assert_eq!(
        session.store.len(),
        1,
        "only the address that was asked about belongs in the report"
    );
}

/// A targeted run must not send the all-nodes solicitation.
///
/// That probe makes every IPv6 neighbour on the segment answer. Scanning one
/// host is not permission to light up its neighbours, and a scan that does so
/// is both noisy and surprising.
#[tokio::test]
async fn a_targeted_run_does_not_solicit_the_whole_segment() {
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A));
    let _ = sweep(&lan, &[v4(10)], Scope::Targeted).await;

    assert!(
        !lan.probes()
            .iter()
            .any(|p| matches!(p, LanProbe::Solicitation { .. })),
        "a targeted run must probe only what it was given"
    );
}

/// A sweep, by contrast, does solicit, and picks up IPv6 neighbours that no
/// ARP request would ever have found.
#[tokio::test]
async fn a_sweep_discovers_ipv6_neighbours_through_the_solicitation() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let lan = FakeLan::new()
        .host(v4(10), LanHost::at(PEER_A))
        .host(peer_v6, LanHost::at(PEER_B));

    // A range wide enough that the sweep does not finish the moment its IPv4
    // targets have all answered. See the ignored test below for why that
    // matters.
    let targets: Vec<IpAddr> = (10..=20).map(v4).collect();
    let session = sweep(&lan, &targets, Scope::Sweep).await;

    assert!(
        lan.probes()
            .iter()
            .any(|p| matches!(p, LanProbe::Solicitation { .. })),
        "a sweep should solicit the segment"
    );
    assert!(
        session.store.contains_key(&peer_v6),
        "an IPv6 neighbour answering the solicitation is a discovered host"
    );
}

/// A neighbour found only by the all-nodes echo still arrives with a round trip.
///
/// This is the common case and it reported no latency at all: a device that
/// answers the segment-wide echo but never a neighbor solicitation — a TV, a
/// console — was recorded as up, with a MAC, a vendor and a hostname, and an
/// empty space where every IPv4 host had a number. The reason given was that a
/// multicast probe cannot be attributed, since every neighbour may answer the
/// same packet on a schedule of its own.
///
/// That is true of *which host* answers and false of *which request* was
/// answered. RFC 4443 requires an echo reply to carry back the identifier and
/// sequence number it was asked with, so unlike two neighbor solicitations —
/// identical on the wire, and unmeasurable for exactly that reason — the echo
/// names its own request. The scan sends three; a neighbour that wakes in time
/// for the third is measured against the third.
#[tokio::test]
async fn a_neighbour_answering_only_the_all_nodes_echo_is_timed() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let lan = FakeLan::new()
        .host(v4(10), LanHost::at(PEER_A))
        .host(peer_v6, LanHost::at(PEER_B));

    let targets: Vec<IpAddr> = (10..=20).map(v4).collect();
    let session = sweep(&lan, &targets, Scope::Sweep).await;

    let host = session.store.get(&peer_v6).expect("neighbour discovered");
    assert_eq!(
        status_protocols(&session, peer_v6),
        vec!["IcmpEcho".to_string()],
        "the echo is what found it, so the echo is what has to be timed"
    );
    assert!(
        host.min_rtt().is_some(),
        "an echo reply names the request it answers, so it yields a round trip"
    );
}

/// A sweep whose IPv4 targets have all answered stops before draining IPv6
/// replies that are already queued, losing them.
///
/// `all_targets_responded` compares the count of responders against the size of
/// the address range, but under [`Scope::Sweep`] only in-range IPv4 addresses
/// are ever counted as responders. An IPv6 neighbour can therefore have answered
/// the solicitation, with its reply sitting in the receive queue, at the moment
/// the sweep decides it is finished.
///
/// The comment at the check says it "effectively never trips" for a sweep, which
/// holds for a /24 and does not hold for a sweep of a handful of addresses. That
/// is the case reproduced here: one IPv4 target that answers, and one IPv6
/// neighbour that is silently dropped.
#[tokio::test]
#[ignore = "known bug: a fully-answered sweep drops queued IPv6 replies"]
async fn a_small_sweep_does_not_drop_ipv6_neighbours() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let lan = FakeLan::new()
        .host(v4(10), LanHost::at(PEER_A))
        .host(peer_v6, LanHost::at(PEER_B));

    let session = sweep(&lan, &[v4(10)], Scope::Sweep).await;

    assert!(
        session.store.contains_key(&peer_v6),
        "the neighbour answered before the sweep ended and must not be lost"
    );
}
