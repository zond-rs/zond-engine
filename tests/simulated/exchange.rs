// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One crafted segment out, and whatever answers it.
//!
//! `transport::exchange` assembles four things a caller would otherwise have to
//! assemble itself: the source address for a destination, the zone a link-local
//! one is valid on, the send, and a bounded wait on the capture. The pieces are
//! each covered elsewhere; what is asserted here is that the assembly puts the
//! caller's bytes on the wire unchanged and hands back what came home.
//!
//! The seam sits above IP, as everywhere in this tier, so nothing here says
//! anything about the header the sender would have built.

use std::time::{Duration, Instant};

use crate::support::fake_net::{FakeNet, Layer4, Policy};
use crate::support::*;
use zond_engine::protocols::craft::{Packet, Tcp, tcp_flags};
use zond_engine::transport::exchange::{Exchange, ExchangeError};
use zond_engine::transport::probe::Emission;

/// The port every probe below leaves from.
const SOURCE_PORT: u16 = 50_000;

/// How long a probe waits for an answer. Long enough for the fake network to
/// reply immediately, short enough that a silent target does not slow the suite.
const WAIT: Duration = Duration::from_millis(200);

/// A SYN to `port`, built the way a caller crafting its own would.
fn syn(port: u16) -> Packet {
    Packet::new().push(Tcp::new(SOURCE_PORT, port).with_flags(tcp_flags::SYN))
}

#[tokio::test]
async fn a_crafted_segment_reaches_the_network_as_it_was_built() {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET, 80, Policy::open());
    let mut exchange = Exchange::from_parts(net.transport(), scanner_resolver());

    let replies = exchange
        .send(&syn(80), TARGET, WAIT)
        .await
        .expect("the probe went out");

    let probes = net.probes();
    assert_eq!(probes.len(), 1, "one send put one probe on the network");
    let probe = &probes[0];

    assert_eq!(probe.target, TARGET);
    assert_eq!(probe.port, 80);
    assert_eq!(probe.source_port, SOURCE_PORT);
    assert_eq!(
        probe.flags,
        tcp_flags::SYN,
        "the flags the caller crafted are the flags that left"
    );
    assert_eq!(
        probe.bytes,
        syn(80).build().expect("the same segment builds"),
        "the bytes on the network are not the bytes the caller built"
    );

    assert!(
        !replies.is_empty(),
        "an open port answered and the exchange collected nothing"
    );
}

/// Silence is an empty collection rather than an error, because a port that says
/// nothing is a result and not a failure. The wait is spent rather than skipped.
#[tokio::test]
async fn a_silent_target_returns_no_replies_after_waiting() {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET, 80, Policy::silent());
    let mut exchange = Exchange::from_parts(net.transport(), scanner_resolver());

    let started = Instant::now();
    let replies = exchange
        .send(&syn(80), TARGET, WAIT)
        .await
        .expect("a silent target is not a failed send");

    assert!(replies.is_empty());
    assert!(
        started.elapsed() >= WAIT,
        "the wait was cut short, so a late reply would have been missed"
    );
}

/// A segment that cannot be serialized is refused before anything is sent, and
/// the refusal carries what the builder said rather than a bare failure.
///
/// Forty-one option bytes: past the forty a TCP data offset can describe, and
/// not a multiple of four either. What matters as much as the error is that the
/// network saw nothing, since a caller told its probe was refused must not have
/// to wonder whether it went out anyway.
#[tokio::test]
async fn a_segment_that_cannot_be_built_sends_nothing() {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET, 80, Policy::open());
    let mut exchange = Exchange::from_parts(net.transport(), scanner_resolver());

    let refused = Packet::new().push(Tcp {
        options: vec![0u8; 41],
        ..Tcp::new(SOURCE_PORT, 80)
    });

    let error = exchange
        .send(&refused, TARGET, WAIT)
        .await
        .expect_err("a TCP header cannot describe forty-one bytes of options");

    assert!(matches!(error, ExchangeError::Build(_)), "{error}");
    assert!(
        net.probes().is_empty(),
        "a probe went out for a segment that could not be built"
    );
}

/// The emission is what the sender is told about the IP header it will build.
/// Nothing here builds one, so what a test can say is that the caller's choice
/// reached the sender on every probe.
#[tokio::test]
async fn the_emission_a_caller_sets_reaches_the_sender() {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET, 80, Policy::open());
    let mut exchange = Exchange::from_parts(net.transport(), scanner_resolver())
        .with_emission(Emission::routed().with_hop_limit(3));

    exchange
        .send(&syn(80), TARGET, WAIT)
        .await
        .expect("the probe went out");

    let probes = net.probes();
    assert_eq!(probes[0].emission.hop_limit, 3);
}
