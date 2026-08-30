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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use common::fake_lan::{FakeLan, LanHost, LanProbe};
use common::*;
use pnet_base::MacAddr;
use zond_engine::config::ZondConfig;
use zond_engine::model::exclusion::Exclusions;
use zond_engine::model::host::telemetry::RttSource;
use zond_engine::model::host::{HostStatus, NetworkRole};
use zond_engine::model::ip::set::IpSet;
use zond_engine::report::{AttachmentSource, ScanKind, TargetScope};
use zond_engine::scanner::recorder::PhaseRecorder;
use zond_engine::scanner::session::ScanSession;
use zond_engine::scanner::strategy::HostScanner;
use zond_engine::scanner::strategy::local::{LocalScanner, Scope};
use zond_engine::system::privilege::Privilege;

const PEER_A: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0xAA);
const PEER_B: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0xBB);

fn v4(host: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, host))
}

/// Runs one sweep of `lan` over `targets` and returns the session to assert
/// against.
async fn sweep(lan: &FakeLan, targets: &[IpAddr], scope: Scope) -> ScanSession {
    sweep_audited(lan, targets, scope).await.0
}

/// [`sweep`], keeping the context so a test can read what the scanner filed
/// about its own run.
async fn sweep_audited(
    lan: &FakeLan,
    targets: &[IpAddr],
    scope: Scope,
) -> (ScanSession, zond_engine::scanner::session::ScanContext) {
    let mut ips = IpSet::new();
    for ip in targets {
        ips.insert(*ip);
    }
    ips.canonicalize();

    let (session, ctx) = ScanSession::new();
    let mut scanner = LocalScanner::with_handle(
        scanner_interface(),
        ips,
        ctx.clone(),
        None,
        scope,
        lan.handle(),
    )
    .expect("scanner builds over the simulated segment");

    scanner
        .discover_hosts()
        .await
        .expect("sweep runs to completion");

    (session, ctx)
}

/// A link-local is meaningless without the interface it was seen on, and which
/// of a machine's addresses happens to answer first must not decide whether it
/// has one.
///
/// Found on a live segment. A host records the zone its *key* carried, and a key
/// carries one only where the address needs it — so a machine whose IPv4 replied
/// before its link-local was created unscoped, and the link-local it advertised
/// a moment later was then reported bare. Two runs of the same sweep against the
/// same phone printed `fe80::41a:992a:fb73:5c91%en1` and
/// `fe80::41a:992a:fb73:5c91`, decided by nothing but which reply arrived first.
#[tokio::test]
async fn a_link_local_carries_its_interface_even_when_ipv4_answered_first() {
    let peer_v6 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));

    // One machine at both addresses, with the IPv6 half held back so the record
    // is created from the IPv4 reply — the order that used to lose the zone.
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A)).host(
        peer_v6,
        LanHost::at(PEER_A).delay(Duration::from_millis(60)),
    );

    let session = sweep(&lan, &[v4(10)], Scope::Sweep).await;

    let host = session
        .hosts()
        .snapshot()
        .into_iter()
        .find(|host| host.ips().contains(&peer_v6))
        .expect("the machine answered at its link-local");

    assert_eq!(
        host.primary_ip(),
        v4(10),
        "IPv4 still leads, which is what made the key unscoped"
    );
    assert_eq!(
        host.zone().map(|zone| zone.name().to_owned()),
        Some("sim0".to_owned()),
        "the sweep read every one of these frames off one interface, so it knows"
    );

    let scoped = zond_engine::model::ip::scoped::ScopedIp::scoped(
        peer_v6,
        host.zone().expect("a zone").clone(),
    );
    assert!(
        !scoped.is_unusable(),
        "a link-local a scan reports has to be one the next phase can open a \
         socket to: {scoped}"
    );
}

/// A host that answers ARP is discovered, and its MAC is recorded from the
/// reply rather than guessed.
#[tokio::test]
async fn an_answering_host_is_discovered_with_its_mac() {
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A));
    let session = sweep(&lan, &[v4(10)], Scope::Targeted).await;

    let host = session.hosts().get(v4(10)).expect("host discovered");
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

    let host = session.hosts().get(v4(10)).expect("host discovered");
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

    let host = session
        .hosts()
        .get(on_segment(peer_v6))
        .expect("neighbour discovered");
    assert_eq!(host.status(), HostStatus::Up);
    assert_eq!(
        status_protocols(&session, on_segment(peer_v6)),
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

    let host = session
        .hosts()
        .get(on_segment(peer_v6))
        .expect("neighbour discovered");
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
        session.hosts().contains(on_segment(peer_v6)),
        "a targeted IPv6 run must probe the address it was given"
    );
    assert_eq!(
        status_protocols(&session, on_segment(peer_v6)),
        vec!["Ndp".to_string()],
        "an advertisement is evidence of neighbour discovery, and now there is some"
    );
    assert!(
        !session.hosts().contains(on_segment(bystander)),
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
        session.hosts().contains(on_segment(peer_v6)),
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
        .hosts()
        .get(IpAddr::V6(solicited))
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
        .hosts()
        .get(on_segment(peer_v6))
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

    let host = session
        .hosts()
        .get(on_segment(peer_v6))
        .expect("neighbour discovered");
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
            .hosts()
            .get(on_segment(peer_v6))
            .is_some_and(|host| host.min_rtt().is_some()),
        "the answer arrived within the window a neighbour is allowed to take"
    );
}

/// A solicited neighbour answering on IPv6's timescale is timed, not written off.
///
/// A neighbour on wifi answers far slower than ARP's six milliseconds, and the
/// solicitation schedule has to outlast that: every attempt spent before the
/// advertisement lands means the answer arrives to find no record of the
/// question, and a second identical solicitation would make it unattributable
/// even if it did.
///
/// **The delay is 400 ms because that is roughly the slowest a real neighbour
/// answers**, measured one address at a time with `benches/ndp_pace.rs`, and
/// what `NDP_RETRY_POLICY`'s first timeout is sized against. Keep it clear of
/// that timeout's jitter: a fixture set close to the schedule makes this test
/// fail intermittently while saying nothing about the behaviour.
#[tokio::test]
async fn a_solicited_neighbour_answering_slowly_is_still_timed() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let lan = FakeLan::new().host(
        peer_v6,
        LanHost::at(PEER_B).delay(Duration::from_millis(400)),
    );

    let session = sweep(&lan, &[peer_v6], Scope::Targeted).await;

    let host = session
        .hosts()
        .get(on_segment(peer_v6))
        .expect("neighbour discovered");
    assert!(
        host.min_rtt().is_some(),
        "the slowest answer ever measured on a real segment is 408ms, so a \
         schedule that cannot time one at 400ms is not sized for its own network"
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

    assert!(session.hosts().contains(v4(10)));
    assert!(
        !session.hosts().contains(v4(11)),
        "silence is not evidence of a host"
    );
}

/// A slow ARP reply still counts. The adaptive deadline has to hold the sweep
/// open long enough for a segment that is merely busy.
#[tokio::test]
async fn a_slow_arp_reply_still_discovers_the_host() {
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A).delay(Duration::from_millis(50)));
    let session = sweep(&lan, &[v4(10)], Scope::Targeted).await;

    assert!(session.hosts().contains(v4(10)));
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
        session.hosts().len(),
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

    assert_eq!(session.hosts().len(), 2);
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

    assert!(session.hosts().contains(on_segment(peer_v6)));
    assert_eq!(
        session.hosts().len(),
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
        session.hosts().contains(on_segment(peer_v6)),
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

    let host = session
        .hosts()
        .get(on_segment(peer_v6))
        .expect("neighbour discovered");
    assert_eq!(
        status_protocols(&session, on_segment(peer_v6)),
        vec!["IcmpEcho".to_string()],
        "the echo is what found it, so the echo is what has to be timed"
    );
    assert!(
        host.min_rtt().is_some(),
        "an echo reply names the request it answers, so it yields a round trip"
    );
}

/// A host that answers both an addressed probe and the segment-wide echo
/// reports the addressed probe's round trip, not a blend of the two.
///
/// A node answering a question put to the whole segment waits before it
/// answers — implementations spread their replies deliberately — so that
/// interval is an upper bound rather than a round trip, however precisely the
/// echoed token attributes it. Pooling the two made every host on a segment
/// report a latency an order of magnitude above what it answers a directed
/// probe in.
#[tokio::test]
async fn a_directed_probe_outranks_the_segment_wide_one_for_latency() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    // The shape a real device has: prompt when asked directly, and an order of
    // magnitude slower to answer a question put to the whole segment.
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A)).host(
        peer_v6,
        LanHost::at(PEER_B).echo_delay(Duration::from_millis(120)),
    );

    // The neighbour is in the target set, so it is asked directly *and* hears
    // the segment-wide echo - which is the case the ranking exists for.
    let mut targets: Vec<IpAddr> = (10..=20).map(v4).collect();
    targets.push(peer_v6);
    let session = sweep(&lan, &targets, Scope::Sweep).await;

    let host = session
        .hosts()
        .get(on_segment(peer_v6))
        .expect("neighbour discovered");
    let samples = host.telemetry().history();

    // Asserted against the samples themselves rather than a wall-clock bound.
    // Both replies are delayed by whatever else the machine is doing, so a
    // threshold like "under 100 ms" measures the test host under load and not
    // the rule: this passed alone and failed in a full-suite run, reporting
    // 426 ms for a reply the simulator sent immediately.
    let direct: Vec<Duration> = samples
        .iter()
        .filter(|sample| sample.source == RttSource::Direct)
        .map(|sample| sample.rtt)
        .collect();
    assert!(
        !direct.is_empty(),
        "the solicitation this neighbour answered has to be recorded as a \
         directed sample, or the ranking has nothing to prefer"
    );
    assert!(
        samples
            .iter()
            .any(|sample| sample.source == RttSource::SegmentWide),
        "the neighbour answered the all-nodes echo too, so both kinds must be on \
         record - a run where only one kind exists would pass either way"
    );

    let reported = host
        .median_rtt()
        .expect("a neighbour that answered is timed");
    let slowest_direct = direct.iter().max().copied().expect("a directed sample");
    assert!(
        reported <= slowest_direct,
        "the reported latency has to come from the directed samples alone; \
         {reported:?} exceeds the slowest of them ({slowest_direct:?}), so the \
         segment-wide reply was blended in"
    );
}

/// An address mDNS announces, and nothing has answered for, is asked about.
///
/// The segment names itself constantly and the scanner's capture already sees
/// all of it, so these addresses arrive whether or not anything asks for them.
/// The hostname resolver caches mDNS records too, but applies them to hosts
/// *already in the store*, so a record about an address nothing has answered
/// for goes nowhere there.
///
/// The lead is worth exactly one solicitation. An mDNS record is a claim
/// somebody else made — the address may have moved on, and the announcer is
/// often speaking for a different machine entirely — which is the same standing
/// a neighbour-table entry has, and it earns its report the same way.
#[tokio::test]
async fn an_address_only_mdns_knows_about_is_asked_about() {
    let announced = std::net::Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0x4b);
    let announcer = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0xCC);

    // Declared as a host so it can answer, but named by *another* machine's
    // announcement — nothing else in the sweep would ever ask about it.
    let lan = FakeLan::new()
        .host(IpAddr::V6(announced), LanHost::at(PEER_B))
        .announcing_over_mdns("tv.local", announced, announcer);

    let session = sweep(&lan, &[v4(10)], Scope::Sweep).await;

    assert!(
        lan.probes().iter().any(|probe| matches!(
            probe,
            LanProbe::Solicit { target, .. } if *target == announced
        )),
        "an announced address nothing has answered for is a lead worth one probe"
    );
    let host = session
        .hosts()
        .get(IpAddr::V6(announced))
        .expect("it answered the solicitation, so it is a host");
    assert!(
        host.min_rtt().is_some(),
        "one solicitation is unambiguous, so the answer yields a round trip"
    );
}

/// Announcing over mDNS is not what makes the announcer a host.
///
/// A frame off the segment does prove its sender exists, but crediting a host
/// to "was chatty on mDNS" files it under a mechanism that did not find it —
/// the same distinction `Icmpv6EchoProtocol` is careful about, and the reason a
/// coverage measurement can tell a working probe from a talkative network.
#[tokio::test]
async fn announcing_over_mdns_does_not_make_the_announcer_a_host() {
    let announced = std::net::Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0x4b);
    let announcer = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0xCC);

    // The announcer is not a declared host, so it answers nothing.
    let lan = FakeLan::new().announcing_over_mdns("tv.local", announced, announcer);

    let session = sweep(&lan, &[v4(10)], Scope::Sweep).await;

    assert!(
        session.hosts().is_empty(),
        "nothing answered a probe, so nothing is a discovered host"
    );
}

/// A sweep with no target addresses at all still finds the segment.
///
/// This is what a link addressed only in IPv6 resolves to: a `/64` cannot be
/// enumerated and there is no IPv4 range to walk, so nothing goes in the target
/// set — and the sweep's most important probe does not need one. The all-nodes
/// echo is a single packet the whole segment may answer, and on such a link it
/// is the only thing that finds anything.
///
/// Two separate defects had to be fixed for this to hold, and either alone
/// makes it fail: `spawn_explorers` skipped an interface whose target set was
/// empty, so no scanner was built at all; and `all_targets_responded` compared
/// `0 >= 0`, ending the run on its first iteration if one had been.
#[tokio::test]
async fn a_sweep_with_no_targets_still_finds_the_segment() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    // Answers late enough that the reply cannot win a race against the sweep
    // deciding it is finished. Without the delay this passes either way, which
    // is worse than failing: the run ends at a couple of milliseconds and the
    // reply happens to already be in the queue.
    let lan = FakeLan::new().host(
        peer_v6,
        LanHost::at(PEER_B).echo_delay(Duration::from_millis(300)),
    );

    let session = sweep(&lan, &[], Scope::Sweep).await;

    assert!(
        lan.probes()
            .iter()
            .any(|probe| matches!(probe, LanProbe::Solicitation { .. })),
        "a sweep with nothing to address still owes the segment an echo"
    );
    assert!(
        session.hosts().contains(on_segment(peer_v6)),
        "the neighbour answered it, so it is a discovered host"
    );
}

/// A sweep whose IPv4 targets have all answered must not stop before draining
/// the IPv6 replies already queued behind them.
///
/// `all_targets_responded` compared the count of responders against the size of
/// the address range, but under [`Scope::Sweep`] only in-range IPv4 addresses
/// are ever counted as responders — an IPv6 neighbour found through the
/// all-nodes echo was never in the range. So the check asked whether the IPv4
/// half was done and stopped the IPv6 half on the answer, with advertisements
/// sitting in the receive queue.
///
/// It hid because the comment at the check was true of the case anyone ran: on
/// a /24 the count never reaches the range size, so the sweep runs to its
/// deadline and the bug never fires. It takes a sweep of a handful of addresses
/// that all answer, which is what this reproduces — and the same arithmetic,
/// `0 >= 0`, ended a sweep of a link with no IPv4 targets at all before its
/// echo could be answered.
///
/// Asking the question only under [`Scope::Targeted`], where it means something,
/// is the fix.
#[tokio::test]
async fn a_small_sweep_does_not_drop_ipv6_neighbours() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    // The IPv4 target answers at once and the neighbour a moment later, which
    // is the order that matters: the sweep must not treat "every address I was
    // given has answered" as "there is nothing left to hear".
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A)).host(
        peer_v6,
        LanHost::at(PEER_B).echo_delay(Duration::from_millis(300)),
    );

    let session = sweep(&lan, &[v4(10)], Scope::Sweep).await;

    assert!(
        session.hosts().contains(on_segment(peer_v6)),
        "the neighbour answered before the sweep ended and must not be lost"
    );
}

/// The audit counts the sweep's own first attempts, not only its retries.
///
/// **The number this pins used to be wrong by a whole pass.** First attempts
/// went out through a second send path that never touched the audit, so
/// `sends_attempted` described the retries and confirmations while reading like
/// a total — and `sends_failed` could not see a first attempt that failed at
/// all, which is exactly the case the scanner reports a failure for.
///
/// Every target answers, which is what makes the assertion mean anything: a
/// host that replies to its first ARP request retires its own probe, so no retry
/// is ever scheduled, and a targeted sweep sends no all-nodes solicitation
/// either. The only frames in the run are therefore the first attempts, and the
/// count has nowhere else to come from. Asserted as a floor because the sweep
/// may legitimately send its own gratuitous traffic; the failing shape is
/// *fewer*, which is a send path the audit cannot see.
#[tokio::test]
async fn every_frame_the_sweep_sends_is_counted() {
    let targets = [v4(1), v4(2), v4(3), v4(4)];
    let lan = FakeLan::new()
        .host(targets[0], LanHost::at(PEER_A))
        .host(targets[1], LanHost::at(PEER_B))
        .host(targets[2], LanHost::at(MacAddr(0x02, 0, 0, 0, 0, 0xCC)))
        .host(targets[3], LanHost::at(MacAddr(0x02, 0, 0, 0, 0, 0xDD)));

    let (_session, ctx) = sweep_audited(&lan, &targets, Scope::Targeted).await;

    let stats = ctx.probe_stats_snapshot();
    let filed = stats.first().expect("the sweep files its counters");

    assert!(
        filed.sends_attempted() >= targets.len() as u64,
        "a sweep of {} addresses that all answered on the first ask counted only \
         {} sends, so a send path is invisible to the audit",
        targets.len(),
        filed.sends_attempted()
    );
    assert_eq!(
        filed.sends_failed(),
        0,
        "the simulated segment accepts every frame"
    );
}

// ---------------------------------------------------------------------------
// What the phase records about the ground it covered
// ---------------------------------------------------------------------------

/// The phase a sweep produces says it covered the whole link, not only the
/// addresses it was handed.
///
/// A sweep sends one all-nodes solicitation that every IPv6 neighbour on the
/// segment is required to answer, so it reaches hosts holding addresses no
/// target set could have named. Nothing else in a report expresses that: a link
/// is not an address range. Without this the neighbours a sweep finds read as
/// ground nobody covered, and a comparison can never say a new device *appeared*
/// on a segment somebody was watching.
///
/// Asserted through the finished report rather than through the context,
/// because the whole path — strategy, context, recorder, scope — is what has to
/// work. Reading the context would pass with the last two links missing.
#[tokio::test]
async fn a_segment_sweep_records_the_link_it_covered() {
    use zond_engine::ZondConfig;
    use zond_engine::model::exclusion::Exclusions;
    use zond_engine::report::{ScanKind, TargetScope};
    use zond_engine::scanner::recorder::PhaseRecorder;

    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A));
    let (_session, ctx) = sweep_audited(&lan, &[v4(10)], Scope::Sweep).await;

    let mut ips = IpSet::new();
    ips.insert(v4(10));
    let scope = TargetScope::from_ip_set(&mut ips, &Exclusions::none());
    let report = PhaseRecorder::start(
        ScanKind::Discovery,
        Privilege::Raw,
        scope,
        &ZondConfig::default(),
    )
    .finish(&ctx);

    let links = report.phases()[0].targets().links();
    assert_eq!(
        links.len(),
        1,
        "a sweep covers the link it was run on: {links:?}"
    );
    assert_eq!(links[0].name(), scanner_interface().name());
}

/// A targeted run sends no all-nodes solicitation, so it covers the addresses it
/// was given and no more.
///
/// The other half of the pair, and the one that stops the record over-claiming:
/// `zond scan` on one host must not report that it swept the segment that host
/// is on.
#[tokio::test]
async fn a_targeted_run_claims_no_link() {
    use zond_engine::ZondConfig;
    use zond_engine::model::exclusion::Exclusions;
    use zond_engine::report::{ScanKind, TargetScope};
    use zond_engine::scanner::recorder::PhaseRecorder;

    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A));
    let (_session, ctx) = sweep_audited(&lan, &[v4(10)], Scope::Targeted).await;

    let mut ips = IpSet::new();
    ips.insert(v4(10));
    let scope = TargetScope::from_ip_set(&mut ips, &Exclusions::none());
    let report = PhaseRecorder::start(
        ScanKind::Discovery,
        Privilege::Raw,
        scope,
        &ZondConfig::default(),
    )
    .finish(&ctx);

    assert!(
        report.phases()[0].targets().links().is_empty(),
        "nothing was sent that every host on the link would answer"
    );
}

/// A sweep asks the segment's routers to identify themselves, and the answer is
/// a role rather than merely another host.
///
/// The evidence a network is *shaped* by — which box forwards — cannot be
/// obtained by asking any address a question. A router advertisement is sent to
/// the segment, and the one thing that makes it reliable to collect during a
/// scan of seconds is asking for it: unprompted, a router sends one every few
/// minutes.
#[tokio::test]
async fn a_sweep_asks_the_segment_for_its_routers_and_names_the_one_that_answers() {
    let router = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let lan = FakeLan::new().routing(router, PEER_A);

    let session = sweep(&lan, &[v4(10)], Scope::Sweep).await;

    assert!(
        lan.probes()
            .iter()
            .any(|probe| matches!(probe, LanProbe::RouterSolicit { .. })),
        "a sweep has to ask, or it finds a router only by luck"
    );

    let host = session
        .hosts()
        .get(on_segment(IpAddr::V6(router)))
        .expect("the router answered, so it is a host like any other");
    assert!(
        host.network_roles().contains(&NetworkRole::Router),
        "an advertisement is a machine saying it forwards"
    );
    assert_eq!(host.status(), HostStatus::Up);
}

/// The IPv4 half of the same idea, and the only way a DHCP server can be found:
/// the protocol is built on broadcast, so no address can be asked the question.
#[tokio::test]
async fn a_sweep_asks_the_segment_who_configures_it() {
    let server = Ipv4Addr::new(192, 168, 1, 1);
    let lan = FakeLan::new().serving_dhcp(server, PEER_B);

    let session = sweep(&lan, &[v4(1), v4(10)], Scope::Sweep).await;

    assert!(
        lan.probes()
            .iter()
            .any(|probe| matches!(probe, LanProbe::DhcpInform { .. })),
        "an inform asks for configuration without asking for an address"
    );

    let host = session
        .hosts()
        .get(IpAddr::V4(server))
        .expect("the server answered");
    assert!(host.network_roles().contains(&NetworkRole::DhcpServer));
}

/// The switch on the far end of the cable, and the port this machine is on.
///
/// The one finding in this crate that no probe can obtain: a managed switch
/// announces itself to each of its ports on its own timer, and the sweep is
/// listening anyway. It is not a claim about any host in the report — it is
/// where the *scan* was run from — so it is closed into the phase rather than
/// written against an address.
#[tokio::test]
async fn a_sweep_learns_which_switch_port_it_is_running_from() {
    let lan = FakeLan::new().wired_through(PEER_B, "core-sw-02", "GigabitEthernet1/0/14", 40);

    let mut targets = IpSet::new();
    targets.insert(v4(10));

    let recorder = PhaseRecorder::start(
        ScanKind::Discovery,
        Privilege::Raw,
        TargetScope::from_ip_set(&mut targets.clone(), &Exclusions::none()),
        &ZondConfig::default(),
    );

    let (_session, ctx) = sweep_audited(&lan, &[v4(10)], Scope::Sweep).await;
    let report = recorder.finish(&ctx);

    let attachment = report.phases()[0]
        .attachments()
        .first()
        .expect("the switch announced itself");

    assert_eq!(attachment.device_name(), Some("core-sw-02"));
    assert_eq!(attachment.port(), Some("GigabitEthernet1/0/14"));
    assert_eq!(attachment.native_vlan(), Some(40));
    assert_eq!(
        attachment.source(),
        AttachmentSource::Lldp,
        "and says which protocol told it"
    );
    assert_eq!(
        attachment.link().name(),
        "sim0",
        "a link-scoped finding is worthless without the link it was read on"
    );
}

/// An announcement proves where its sender is and says nothing about any
/// address, so it must not put a host in the report.
///
/// A switch generally holds no address on the segment it serves, so the role it
/// claims has nothing to attach to — and inventing a host for it would be the
/// same mistake a router advertisement was already guarded against.
#[tokio::test]
async fn a_switch_announcing_itself_does_not_become_a_host() {
    let lan = FakeLan::new().wired_through(PEER_B, "core-sw-02", "Gi1/0/14", 40);

    let session = sweep(&lan, &[v4(10)], Scope::Sweep).await;

    assert_eq!(
        session.hosts().len(),
        0,
        "nothing answered a probe, so nothing is a host"
    );
}

/// A relay agent forwards for a server on another segment, so the address the
/// reply comes from and the address the message names are two different
/// machines. Neither reading is safe: marking the sender names a relay a DHCP
/// server, and marking the named address attaches the role to a machine this
/// frame is no evidence about.
#[tokio::test]
async fn a_relayed_answer_names_nobody_a_dhcp_server() {
    let relay = Ipv4Addr::new(192, 168, 1, 1);
    let elsewhere = Ipv4Addr::new(10, 0, 0, 53);
    let lan = FakeLan::new().serving_dhcp_as(relay, elsewhere, PEER_B);

    let session = sweep(&lan, &[v4(1), v4(10)], Scope::Sweep).await;

    let host = session
        .hosts()
        .get(IpAddr::V4(relay))
        .expect("the relay answered, which proves the relay is there");
    assert_eq!(host.status(), HostStatus::Up);
    assert!(
        !host.network_roles().contains(&NetworkRole::DhcpServer),
        "the machine that answered is not the one the message named"
    );
}

/// A targeted run asks the segment its two questions, and still reports only
/// the hosts it was asked about.
///
/// Both halves are the decision. Neither question can be put to an address —
/// a router answers from a link-local nobody named, a DHCP server answers a
/// broadcast — so a scan that declines to ask them reports a segment without
/// the two machines it is built around, which is most of what a person scans a
/// segment to learn. What keeps the run targeted is not silence but what may be
/// *recorded*: a declaration is filed against the hardware address that made it
/// and applied only if that machine turns out to be one the scan asked about.
///
/// The ordering this exercises is the one that decides whether any of it works.
/// The advertisement arrives within half a second of the solicitation, and the
/// ARP request that identifies its sender leaves on a paced ticker some way
/// into the run — so the claim almost always arrives before there is a host to
/// put it on.
#[tokio::test]
async fn a_targeted_run_asks_the_segment_and_records_only_what_it_asked_about() {
    // One machine, as a home network has: the router at .1 is also the segment's
    // IPv6 router and its DHCP server.
    let gateway = Ipv4Addr::new(192, 168, 1, 1);
    let lan = FakeLan::new()
        .host(v4(1), LanHost::at(PEER_A))
        .routing(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), PEER_A)
        .serving_dhcp(gateway, PEER_A);

    let session = sweep(&lan, &[v4(1)], Scope::Targeted).await;

    assert!(
        lan.probes()
            .iter()
            .any(|probe| matches!(probe, LanProbe::RouterSolicit { .. })),
        "the question a router answers cannot be put to an address"
    );
    assert!(
        !lan.probes()
            .iter()
            .any(|probe| matches!(probe, LanProbe::Solicitation { .. })),
        "the all-nodes echo is still the sweep's alone: everything it draws is \
         an address nobody asked about"
    );

    let host = session
        .hosts()
        .get(v4(1))
        .expect("the address the scan was given");
    assert!(
        host.network_roles().contains(&NetworkRole::Router),
        "the advertisement came from a link-local, and the machine that sent it \
         is the one at the address we asked about"
    );
    assert!(host.network_roles().contains(&NetworkRole::DhcpServer));

    assert_eq!(
        session.hosts().len(),
        1,
        "and nothing the scan was not asked about became a host"
    );
}
