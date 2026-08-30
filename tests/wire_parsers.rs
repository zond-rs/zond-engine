// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Every wire parser, against bytes it did not choose
//!
//! A scanner reads frames somebody else wrote. In a listening phase it reads
//! them from a promiscuous capture, so what arrives is under the control of
//! whoever is on the segment, and a parser that panics on a malformed one takes
//! down the process the engine was embedded in.
//!
//! The unit tests beside each parser feed it frames this project believes in.
//! This file feeds it frames nobody believes in, and asserts only that it
//! returns.
//!
//! ## Shaped bytes, not just random ones
//!
//! Uniform random bytes are refused at the first length check and prove almost
//! nothing about what is behind it. So most of the generators below build a
//! *structurally plausible* frame — a real Ethernet header, a real ethertype,
//! TLVs whose length fields are real lengths — and fill everything the parser
//! actually reads with arbitrary values. Random bytes are covered too, because
//! that path must also return, but they are the cheap half of this.
//!
//! ## What is asserted
//!
//! That the call returns, which for a parser reading hostile input is the
//! whole property. Where a parser hands back a borrowed view, the view's own
//! bounds are checked as well: a `Frame` that claims a payload longer than the
//! buffer it came from would be a parser handing out an out-of-bounds slice
//! without ever panicking itself.

use proptest::prelude::*;

use pnet_base::MacAddr;
use pnet_packet::ethernet::EtherType;
use pnet_packet::ip::IpNextHeaderProtocols;
use std::net::{Ipv4Addr, Ipv6Addr};

use zond_engine::protocols::ethernet::Frame;
use zond_engine::protocols::{cdp, craft, dhcp, dns, ethernet, icmp, lldp, mdns, ndp, sctp, tcp};

/// Ethertypes the readers below branch on, plus a few they should decline.
const ETHERTYPES: &[u16] = &[
    0x0800, // IPv4
    0x86dd, // IPv6
    0x0806, // ARP
    0x88cc, // LLDP
    0x8100, // 802.1Q, which sends the reader looking for another tag
    0x88a8, // 802.1ad, stacked tags
    0x0000, // an 802.3 length of zero
    0x05dc, // an 802.3 length at the boundary, 1500
    0x0600, // the smallest assigned ethertype, 1536
];

/// Arbitrary bytes, in the sizes a frame actually arrives in.
fn any_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..64),
        proptest::collection::vec(any::<u8>(), 0..1518),
    ]
}

/// A well-formed Ethernet header carrying an arbitrary payload, optionally
/// behind one or two VLAN tags.
fn any_frame_bytes() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<[u8; 6]>(),
        any::<[u8; 6]>(),
        proptest::sample::select(ETHERTYPES),
        0usize..3,
        any::<u16>(),
        any_bytes(),
    )
        .prop_map(|(dst, src, ethertype, tags, tag_value, payload)| {
            let mut frame = Vec::with_capacity(14 + tags * 4 + payload.len());
            frame.extend_from_slice(&dst);
            frame.extend_from_slice(&src);
            for _ in 0..tags {
                frame.extend_from_slice(&0x8100u16.to_be_bytes());
                frame.extend_from_slice(&tag_value.to_be_bytes());
            }
            frame.extend_from_slice(&ethertype.to_be_bytes());
            frame.extend_from_slice(&payload);
            frame
        })
}

/// A well-formed Ethernet frame carrying `payload` behind `ethertype`.
fn frame_around(ethertype: u16, payload: Vec<u8>) -> Vec<u8> {
    craft::Packet::new()
        .push(
            craft::Ethernet::new(MacAddr::zero(), MacAddr::zero())
                .with_ethertype(EtherType(ethertype)),
        )
        .push(craft::Layer::Raw(payload))
        .build()
        .expect("an Ethernet header and a payload cannot overflow")
}

/// LLDP's TLVs: seven bits of type and nine of length, packed across two bytes,
/// and an end-of-unit TLV, without which the walk runs off the end and the whole
/// advertisement is refused.
///
/// Kinds are drawn from the ones the reader acts on as well as from the whole
/// range, because a stream of types it ignores exercises the walk and nothing
/// behind it.
fn any_lldp_frame() -> impl Strategy<Value = Vec<u8>> {
    const READ: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 127];

    let kind = prop_oneof![proptest::sample::select(READ), 1u8..=127];
    proptest::collection::vec((kind, any_bytes()), 0..10).prop_map(|tlvs| {
        let mut payload = Vec::new();
        for (kind, value) in tlvs {
            let length = value.len().min(511);
            payload.push((kind << 1) | (length >> 8) as u8);
            payload.push((length & 0xff) as u8);
            payload.extend_from_slice(&value[..length]);
        }
        payload.extend_from_slice(&[0, 0]);
        frame_around(0x88cc, payload)
    })
}

/// CDP arrives under 802.3 framing, so the ethertype field is a length and the
/// records sit behind an LLC/SNAP header. A record's length counts its own
/// header, which is the one place it differs from LLDP.
fn any_cdp_frame() -> impl Strategy<Value = Vec<u8>> {
    const LLC_SNAP: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00];
    const READ: &[u16] = &[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0xA, 0xB, 0x16];

    let kind = prop_oneof![proptest::sample::select(READ), any::<u16>()];
    proptest::collection::vec((kind, any_bytes()), 0..8).prop_map(|records| {
        let mut payload = LLC_SNAP.to_vec();
        payload.extend_from_slice(&[0x02, 0xB4, 0x00, 0x00]);
        for (kind, value) in records {
            let value = &value[..value.len().min(300)];
            payload.extend_from_slice(&kind.to_be_bytes());
            payload.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
            payload.extend_from_slice(value);
        }
        let claimed = payload.len().min(1500) as u16;
        frame_around(claimed, payload)
    })
}

/// An IPv6 frame whose next header really is ICMPv6, carrying arbitrary bytes
/// where a neighbour or router advertisement would be.
fn any_icmpv6_frame() -> impl Strategy<Value = Vec<u8>> {
    let kind = prop_oneof![Just(134u8), Just(135u8), Just(136u8), any::<u8>()];
    (
        any::<u8>(),
        kind,
        proptest::collection::vec(any::<u8>(), 0..80),
    )
        .prop_map(|(hop_limit, kind, rest)| {
            let mut message = vec![kind, 0, 0, 0];
            message.extend_from_slice(&rest);

            let header = craft::Ipv6 {
                next_header: craft::Field::Exact(IpNextHeaderProtocols::Icmpv6),
                ..craft::Ipv6::new(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED)
                    .with_hop_limit(hop_limit)
            };

            let mut payload = header.header_bytes(message.len() as u16);
            payload.extend_from_slice(&message);
            frame_around(0x86dd, payload)
        })
}

/// An IPv4/UDP datagram from a DHCP port, carrying a BOOTP message whose options
/// are shaped the way DHCP shapes them, behind the magic cookie.
///
/// The message type is drawn from the values that make a reply a reply, because
/// a message carrying none is BOOTP and the reader says so and stops. Codes and
/// values otherwise vary freely, so the option walk is what is under test.
fn any_dhcp_options() -> impl Strategy<Value = Vec<u8>> {
    const READ: &[u8] = &[3, 6, 12, 15, 50, 53, 54, 55, 60];

    let code = prop_oneof![proptest::sample::select(READ), any::<u8>()];
    let value = proptest::collection::vec(any::<u8>(), 0..24);
    let kind = prop_oneof![Just(2u8), Just(5u8), Just(6u8), any::<u8>()];

    (kind, proptest::collection::vec((code, value), 0..8)).prop_map(|(kind, options)| {
        let mut out = vec![53, 1, kind];
        for (code, value) in options {
            out.push(code);
            out.push(value.len() as u8);
            out.extend_from_slice(&value);
        }
        out.push(255);
        out
    })
}

fn any_dhcp_frame() -> impl Strategy<Value = Vec<u8>> {
    let op = prop_oneof![Just(1u8), Just(2u8), any::<u8>()];
    let ports = prop_oneof![Just((67u16, 68u16)), Just((68u16, 67u16))];

    (op, ports, any_dhcp_options()).prop_map(|(op, (source, destination), options)| {
        // The fixed BOOTP header, then the cookie its options follow.
        let mut message = vec![0u8; 236];
        message[0] = op;
        message[1] = 1; // Ethernet, so the hardware address is read.
        message[2] = 6;
        message.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        message.extend_from_slice(&options);

        let datagram = craft::Udp::new(source, destination)
            .with_payload(message)
            .to_bytes(None)
            .expect("a UDP header over a bounded payload");

        let header = craft::Ipv4 {
            protocol: craft::Field::Exact(IpNextHeaderProtocols::Udp),
            ..craft::Ipv4::new(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST)
        };
        let mut payload = header
            .header_bytes(datagram.len() as u16)
            .expect("an IPv4 header over a bounded payload");
        payload.extend_from_slice(&datagram);
        frame_around(0x0800, payload)
    })
}

/// A parsed frame never lends out more than it was built from.
fn frame_is_within_its_buffer(frame: &Frame<'_>, buffer: &[u8]) -> bool {
    let range = buffer.as_ptr_range();
    let payload = frame.payload().as_ptr_range();
    frame.payload().is_empty()
        || (range.start <= payload.start && payload.end <= range.end)
            && frame.payload().len() <= buffer.len()
}

proptest! {
    /// The Ethernet reader is the one every other reader is behind, so it sees
    /// every frame a capture admits.
    #[test]
    fn reading_a_frame_returns_and_borrows_only_what_it_was_given(bytes in any_frame_bytes()) {
        if let Ok(frame) = ethernet::parse(&bytes) {
            prop_assert!(frame_is_within_its_buffer(&frame, &bytes));
            prop_assert!(frame.vlans().len() <= 2);
            let _ = frame.destination();
            let _ = frame.source();
            let _ = frame.payload_as_claimed();
        }
    }

    /// And on bytes with no header at all.
    #[test]
    fn reading_arbitrary_bytes_as_a_frame_returns(bytes in any_bytes()) {
        if let Ok(frame) = ethernet::parse(&bytes) {
            prop_assert!(frame_is_within_its_buffer(&frame, &bytes));
        }
    }

    /// Every reader that takes a parsed frame, over the same frames.
    ///
    /// These are the announcements a device sends unprompted, so in a listening
    /// phase they are read without anything having been asked for.
    #[test]
    fn every_frame_reader_returns(bytes in any_frame_bytes()) {
        let Ok(frame) = ethernet::parse(&bytes) else { return Ok(()); };

        let _ = lldp::parse(&frame);
        let _ = cdp::parse(&frame);
        let _ = ndp::advertisement(&frame);
        let _ = dhcp::server_reply(&frame);
        let _ = dhcp::client_request(&frame);
    }

    /// LLDP, over TLV streams shaped the way LLDP shapes them.
    #[test]
    fn an_lldp_advertisement_of_arbitrary_tlvs_returns(bytes in any_lldp_frame()) {
        let frame = ethernet::parse(&bytes).expect("the generator builds a whole header");
        let _ = lldp::parse(&frame);
    }

    /// CDP, over the 802.3 framing and header-counting lengths it actually uses.
    #[test]
    fn a_cdp_announcement_of_arbitrary_records_returns(bytes in any_cdp_frame()) {
        let frame = ethernet::parse(&bytes).expect("the generator builds a whole header");
        let _ = cdp::parse(&frame);
    }

    /// Neighbour discovery, over arbitrary ICMPv6 message bodies.
    #[test]
    fn a_neighbour_advertisement_of_arbitrary_bytes_returns(bytes in any_icmpv6_frame()) {
        let frame = ethernet::parse(&bytes).expect("the generator builds a whole header");
        let _ = ndp::advertisement(&frame);
        let _ = ndp::is_router_advertisement(&frame);
    }

    /// DHCP, over arbitrary option streams behind a real BOOTP header.
    #[test]
    fn a_dhcp_message_of_arbitrary_options_returns(bytes in any_dhcp_frame()) {
        let frame = ethernet::parse(&bytes).expect("the generator builds a whole header");
        if let Some(reply) = dhcp::server_reply(&frame) {
            let _ = reply.routers().count();
            let _ = reply.resolvers().count();
        }
        let _ = dhcp::client_request(&frame);
    }

    /// The readers that take a bare buffer: a segment off a capture, or a
    /// datagram a resolver drew.
    #[test]
    fn every_buffer_reader_returns(bytes in any_bytes(), identifier in any::<u16>()) {
        let _ = tcp::parse(&bytes);
        let _ = sctp::parse(&bytes);
        let _ = icmp::classify_echo_reply(&bytes, identifier, false);
        let _ = icmp::classify_echo_reply(&bytes, identifier, true);
        let _ = dns::parse_ptr_response(&bytes);
        let _ = mdns::extract_hosts(&bytes);
    }

    /// A parsed segment is classified by the same code that reads a reply, so
    /// it sees whatever the parser let through.
    #[test]
    fn classifying_a_parsed_segment_returns(bytes in any_bytes()) {
        if let Ok(segment) = tcp::parse(&bytes) {
            let _ = tcp::classify_probe_response(&segment);
        }
        if let Ok(segment) = sctp::parse(&bytes) {
            let _ = sctp::classify_probe_response(&segment);
        }
    }
}

/// **The test that keeps the tests above honest.**
///
/// Every property here is "the parser returns", which a generator producing
/// bytes no parser accepts satisfies perfectly while proving nothing. The first
/// draft of this file did exactly that: one LLDP advertisement in four thousand
/// got past the walk, and none of the others got past theirs at all.
///
/// So the generators are measured. Each is run against its reader and has to
/// reach it often enough that the walk behind it is under test, which turns a
/// generator that drifts out of shape into a failure here rather than into
/// silence up there.
///
/// The floors are well under what the generators currently manage and are meant
/// to catch a shape that broke, not to pin a rate.
#[test]
fn the_generators_reach_the_parsers_they_are_written_for() {
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::TestRunner;

    fn rate<S: Strategy>(strategy: S, reaches: impl Fn(&S::Value) -> bool) -> f64 {
        const CASES: usize = 1_000;

        let mut runner = TestRunner::deterministic();
        let hits = (0..CASES)
            .filter(|_| {
                let value = strategy
                    .new_tree(&mut runner)
                    .expect("the generator produces a value")
                    .current();
                reaches(&value)
            })
            .count();
        hits as f64 / CASES as f64
    }

    let reached = |name: &str, rate: f64, floor: f64| {
        assert!(
            rate >= floor,
            "{name} reached its parser {:.1}% of the time, under the {:.0}% floor: \
             the generator is no longer producing what the reader accepts, so the \
             property test above is passing on frames it never reads",
            rate * 100.0,
            floor * 100.0
        );
    };

    reached(
        "lldp",
        rate(any_lldp_frame(), |bytes| {
            ethernet::parse(bytes)
                .ok()
                .and_then(|frame| lldp::parse(&frame))
                .is_some()
        }),
        0.20,
    );
    reached(
        "cdp",
        rate(any_cdp_frame(), |bytes| {
            ethernet::parse(bytes)
                .ok()
                .and_then(|frame| cdp::parse(&frame))
                .is_some()
        }),
        0.05,
    );
    reached(
        "ndp",
        rate(any_icmpv6_frame(), |bytes| {
            ethernet::parse(bytes)
                .ok()
                .and_then(|frame| ndp::advertisement(&frame))
                .is_some()
        }),
        0.05,
    );
    reached(
        "dhcp",
        rate(any_dhcp_frame(), |bytes| {
            ethernet::parse(bytes)
                .ok()
                .and_then(|frame| dhcp::server_reply(&frame))
                .is_some()
        }),
        0.03,
    );
}
