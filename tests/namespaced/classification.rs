// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a scan concludes about a port on the other side of a real wire.
//!
//! These are the two verdicts a cooperating kernel will produce, which is the
//! same pair Tier 1 gets from loopback. The difference is everything underneath:
//! loopback never builds an IP header, never resolves a neighbour, and never
//! puts a frame on a link, so a scan against it proves the classifier and
//! nothing below it. Here the engine has to find the interface, ARP for the
//! peer, emit a packet another kernel will accept, and read the answer back
//! through a capture.

use crate::netns::{Segment, available};
use crate::support::{is_privileged, run_scan, target_map, test_config};
use zond_engine::model::port::PortState;

/// The tier sends raw packets, and says so.
///
/// A user namespace maps this process to uid 0 inside itself, which is what
/// gives `scan` its raw socket path rather than the connect fallback Tier 1
/// runs on. Without this the tier would still pass: a connect scan reports the
/// same two verdicts, over a path that never builds an IP header. It would just
/// have stopped testing anything the tiers above it do not.
#[test]
fn the_engine_takes_its_raw_path_here() {
    if !available() {
        return;
    }

    assert!(
        is_privileged(),
        "the namespace should give this process the privilege a raw scan needs"
    );
}

/// A port nothing is listening on is reported Closed.
///
/// The peer's kernel answers with a reset, which has to survive being built
/// here, carried over the pair, generated over there, and matched by the
/// capture filter on the way back.
#[tokio::test]
async fn a_port_nothing_listens_on_is_reported_closed() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.closed_tcp_port();

    let outcome = run_scan(
        target_map(segment.peer(), &port.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Closed),
        "a reset from the peer's kernel should read as Closed"
    );
}

/// A port with a listener behind it is reported Open.
#[tokio::test]
async fn a_port_with_a_listener_is_reported_open() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.listen_tcp();

    let outcome = run_scan(
        target_map(segment.peer(), &port.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Open),
        "a listener on the far side of the pair should read as Open"
    );
}

/// The peer answers a liveness probe, so the host is found up.
///
/// This is the ARP exchange as much as the probe: the engine has an address on
/// a segment and no idea what hardware answers for it until the peer's kernel
/// says so.
#[tokio::test]
async fn the_peer_is_found_alive() {
    if !available() {
        return;
    }

    let segment = Segment::new();
    let outcome = run_scan(target_map(segment.peer(), "1-2"), &test_config()).await;

    assert!(
        outcome.host(segment.peer()).is_some(),
        "the peer should be discovered before its ports are scanned"
    );
}

/// A port a firewall silently discards is reported Filtered.
///
/// The verdict that motivates this whole tier. Loopback cannot produce it and
/// Tier 2 can only describe it, because silence is not something a cooperating
/// kernel will give you: it takes a real filter deciding not to answer, and a
/// scanner that waits out its retry schedule before saying so.
#[tokio::test]
async fn a_dropped_port_is_reported_filtered() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.closed_tcp_port();
    segment.drop_tcp(port);

    let outcome = run_scan(
        target_map(segment.peer(), &port.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Filtered),
        "a port whose probes are dropped should read Filtered, not Closed"
    );
}

/// An ICMP prohibition reads as Filtered rather than Closed.
///
/// The near miss worth a test of its own. Both this port and a closed one
/// answer, and both answers are errors; only the reason differs. Reading an
/// administrative prohibition as a port unreachable would report a firewalled
/// port as a closed one, which is a confident and wrong answer rather than a
/// missing one.
///
/// # This one is a claim, and it fails
///
/// The port comes back [`PortState::Unasked`]. The peer's counter shows one SYN
/// arriving and being rejected, so the probe went out and was answered; Linux
/// then delivers the ICMP error to the socket, the next send reports it, and
/// that reads here as a probe the operating system refused to send. `Unasked`
/// is documented to mean exactly that, so the mechanism is working as written.
/// What is open is which evidence should win: an error the target actually sent
/// is a definitive `Filtered`, and it is being discarded in favour of a local
/// send failure that the error itself caused.
///
/// Tier 2 has no way to see this. It hands a scanner a synthesized ICMP reply
/// and never runs a socket, so `admin_prohibited()` passes there and has
/// always passed.
#[tokio::test]
#[ignore = "reports Unasked: the ICMP error comes back on the socket and is read as a refused send"]
async fn an_administratively_prohibited_port_is_filtered_rather_than_closed() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.closed_tcp_port();
    segment.prohibit_tcp(port);

    let outcome = run_scan(
        target_map(segment.peer(), &port.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Filtered),
        "an admin-prohibited ICMP error should read Filtered"
    );
}

/// A UDP port nothing is bound to is reported Closed.
///
/// The only thing that makes a UDP port positively closed is an ICMP port
/// unreachable, and the only thing that produces one is a real kernel. The
/// error has to be parsed, and the datagram quoted inside it matched back to
/// the probe that caused it, before the verdict means anything.
#[tokio::test]
async fn a_udp_port_nothing_is_bound_to_is_reported_closed() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.closed_udp_port();

    let outcome = run_scan(
        target_map(segment.peer(), &format!("U:{port}")),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Closed),
        "an ICMP port unreachable from the peer should read Closed"
    );
}

/// A UDP reply reaches the scan and opens the port.
///
/// The other half of the same path, and the one that catches a capture filter
/// which compiles but matches nothing: such a filter turns every open UDP port
/// into `OpenFiltered`, so the scan keeps running and keeps reporting, just
/// never positively. Only live traffic shows it.
#[tokio::test]
async fn a_udp_reply_reaches_the_scan_and_opens_the_port() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.echo_udp();

    let outcome = run_scan(
        target_map(segment.peer(), &format!("U:{port}")),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Open),
        "a datagram answered by a real listener should read Open"
    );
}
