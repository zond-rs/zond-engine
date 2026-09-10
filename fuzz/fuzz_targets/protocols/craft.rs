// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The builder every probe this engine sends goes through.
//!
//! The other targets read bytes somebody else wrote. This one writes them, and
//! it is here because a scanner's builder fails in a direction a reader does
//! not: a header whose declared length disagrees with the bytes behind it is
//! dropped by the receiver, and the scan reads the silence as a firewall. A
//! wrong packet that goes out looks exactly like a filtered port.
//!
//! The input is a recipe rather than a buffer, since a builder takes a
//! description. Every derived field is an `Option`, which is [`Field`]'s own
//! shape: absent is `Computed` and present is `Exact`, so the fuzzer chooses,
//! per field, between the value the builder derives and one it must write
//! untouched.
//!
//! ## The oracles
//!
//! **Building twice writes the same bytes, unless a field is meant to vary.**
//! Two fields are drawn fresh on every build: an IPv4 identification and an IPv6
//! flow label, both left `Computed`. Everything else is a function of the recipe,
//! so two builds that differ anywhere else have found something reading a clock,
//! an address, or an uninitialised buffer.
//!
//! **And where a field is meant to vary, it varies.** A recipe whose IPv4
//! identification or IPv6 flow label is `Computed` is built [`VARIANCE_BUILDS`]
//! times, and they must not all come out the same. This is the sharper half.
//! A predictable identification is precisely what
//! [`ports::idle`](zond_engine::scanner::strategy::ports::idle) reads out of
//! *other* stacks to learn what they answered without addressing them, so a
//! build that ever settled into a fixed or counting identifier would make this
//! engine's own probes readable the same way. Nothing else in the crate states
//! that, and no unit test can: one draw is indistinguishable from a constant.
//!
//! **One more byte inside makes the packet one byte longer.** A [`Raw`] layer of
//! a single byte is pushed innermost and the packet is built again. This holds
//! whatever the layers are and whatever the fields say, because `Exact` changes
//! what a length field *claims* and never what is written, so it covers a layer
//! added six months from now without being told about it. Where the extra byte
//! carries a length past what its field can hold, the longer build is refused,
//! and a refusal is not a disagreement.
//!
//! **A declared length describes what actually follows it.** Read out of the
//! built bytes by hand rather than through `pnet`, which is what wrote them: an
//! oracle that parses with the writer's own library asks the writer whether it
//! agrees with itself. Asserted for the outermost IPv4 or IPv6 header, with or
//! without an Ethernet frame in front of it, and only where the field was left
//! `Computed`. An `Exact` one is under no obligation to be true, which is the
//! whole point of it.
//!
//! **A packet written as a document reads back as the same packet.** `craft`
//! carries five hand-written `serde` adapters, for hex bytes, a fixed-length
//! header remainder, a hardware address, a protocol number and an ethertype, and
//! a hand-written pair for `Field` itself. A derive cannot drift from its struct
//! and those can. The comparison is on the `Packet` rather than on its bytes,
//! which is the sharper end of it: two builds of one recipe differ in the fields
//! that are meant to, and a value that came back equal is equal in every field
//! including the ones left `Computed`.
//!
//! **Options are refused rather than truncated.** Both IPv4 and TCP carry their
//! option length in four bits of words above a five-word fixed header, so
//! anything past forty bytes or not a multiple of four cannot be described. A
//! builder that wrote them anyway would produce a header claiming a length that
//! runs into the payload. So a recipe holding options like that must not build,
//! and one that builds must have a header length field counting its options
//! exactly.
//!
//! ## What is not asserted
//!
//! **That a computed checksum is correct.** The arithmetic is `pnet`'s, verified
//! against published vectors by the unit tests, and recomputing it here would
//! compare a transcription against the original. What this target owns is the
//! surrounding assembly: which bytes the checksum is taken over, and whether an
//! `Exact` one survives to the wire.
//!
//! **That the packet parses.** Most recipes describe nothing a stack would
//! accept, deliberately: a malformed packet is what this module exists to make.
//!
//! [`Field`]: zond_engine::protocols::craft::Field
//! [`Raw`]: zond_engine::protocols::craft::Layer::Raw

#![no_main]

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use pnet_base::MacAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use zond_engine::protocols::craft::{
    Arp, Ethernet, Field, Icmpv4, Icmpv6, Ipv4, Ipv6, Layer, Packet, Sctp, Tcp, Udp,
};

/// How many layers one recipe may stack.
///
/// A packet is a handful of headers; past that the fuzzer is spending its input
/// budget on depth rather than on the field values, which is where the
/// interesting inputs are.
const MAX_LAYERS: usize = 6;

/// The fixed part of an IPv4 header, and of a TCP one: five words each, which
/// is what the four-bit length field counts above.
const FIXED_HEADER: usize = 20;

/// The most option bytes either header can describe: fifteen words less the
/// five fixed ones.
const LARGEST_OPTIONS: usize = (15 - 5) * 4;

/// An Ethernet II header, which is what sits in front of an IP header when the
/// recipe frames one.
const ETHERNET_HEADER: usize = 14;

/// How many times a recipe with a randomised field is built before its outputs
/// are required to differ.
///
/// Four, because the assertion has to hold for every input rather than usually:
/// two independent draws of a sixteen-bit identification collide once in 65 536,
/// and four in a row agree about once in 2.8 x 10^14 builds, which no campaign
/// reaches.
const VARIANCE_BUILDS: usize = 4;

#[derive(Debug, Arbitrary)]
struct Recipe {
    layers: Vec<LayerSpec>,
}

/// One header, with every derived field optional.
///
/// [`None`] is [`Field::Computed`] and [`Some`] is [`Field::Exact`], so the
/// fuzzer decides field by field whether the builder derives a value or writes
/// one it was handed.
#[derive(Debug, Arbitrary)]
enum LayerSpec {
    Ethernet {
        source: [u8; 6],
        destination: [u8; 6],
        ethertype: Option<u16>,
    },
    Ipv4 {
        source: [u8; 4],
        destination: [u8; 4],
        dscp: u8,
        ecn: u8,
        flags: u8,
        fragment_offset: u16,
        ttl: u8,
        identification: Option<u16>,
        protocol: Option<u8>,
        total_length: Option<u16>,
        checksum: Option<u16>,
        options: Vec<u8>,
    },
    Ipv6 {
        source: [u8; 16],
        destination: [u8; 16],
        traffic_class: u8,
        hop_limit: u8,
        flow_label: Option<u32>,
        next_header: Option<u8>,
        payload_length: Option<u16>,
    },
    Tcp {
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        acknowledgement: u32,
        tcp_flags: u8,
        window: u16,
        urgent_pointer: u16,
        data_offset: Option<u8>,
        checksum: Option<u16>,
        options: Vec<u8>,
        payload: Vec<u8>,
    },
    Udp {
        source_port: u16,
        destination_port: u16,
        length: Option<u16>,
        checksum: Option<u16>,
        payload: Vec<u8>,
    },
    Sctp {
        source_port: u16,
        destination_port: u16,
        verification_tag: u32,
        checksum: Option<u32>,
        chunks: Vec<u8>,
    },
    Icmpv4 {
        icmp_type: u8,
        code: u8,
        checksum: Option<u16>,
        rest_of_header: [u8; 4],
        payload: Vec<u8>,
    },
    Icmpv6 {
        icmp_type: u8,
        code: u8,
        checksum: Option<u16>,
        rest_of_header: [u8; 4],
        payload: Vec<u8>,
    },
    Arp {
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_ip: [u8; 4],
    },
    Raw(Vec<u8>),
}

/// A derived field the fuzzer either left to the builder or pinned itself.
fn field<T>(chosen: Option<T>) -> Field<T> {
    chosen.map_or(Field::Computed, Field::Exact)
}

impl LayerSpec {
    fn build(&self) -> Layer {
        match self {
            Self::Ethernet {
                source,
                destination,
                ethertype,
            } => Layer::Ethernet(Ethernet {
                source: MacAddr::from(*source),
                destination: MacAddr::from(*destination),
                ethertype: field(ethertype.map(pnet_ethertype)),
            }),
            Self::Ipv4 {
                source,
                destination,
                dscp,
                ecn,
                flags,
                fragment_offset,
                ttl,
                identification,
                protocol,
                total_length,
                checksum,
                options,
            } => Layer::Ipv4(Ipv4 {
                dscp: *dscp,
                ecn: *ecn,
                flags: *flags,
                fragment_offset: *fragment_offset,
                ttl: *ttl,
                identification: field(*identification),
                protocol: field(protocol.map(pnet_protocol)),
                total_length: field(*total_length),
                checksum: field(*checksum),
                options: options.clone(),
                ..Ipv4::new(Ipv4Addr::from(*source), Ipv4Addr::from(*destination))
            }),
            Self::Ipv6 {
                source,
                destination,
                traffic_class,
                hop_limit,
                flow_label,
                next_header,
                payload_length,
            } => Layer::Ipv6(Ipv6 {
                traffic_class: *traffic_class,
                hop_limit: *hop_limit,
                flow_label: field(*flow_label),
                next_header: field(next_header.map(pnet_protocol)),
                payload_length: field(*payload_length),
                ..Ipv6::new(Ipv6Addr::from(*source), Ipv6Addr::from(*destination))
            }),
            Self::Tcp {
                source_port,
                destination_port,
                sequence,
                acknowledgement,
                tcp_flags,
                window,
                urgent_pointer,
                data_offset,
                checksum,
                options,
                payload,
            } => Layer::Tcp(Tcp {
                sequence: *sequence,
                acknowledgement: *acknowledgement,
                flags: *tcp_flags,
                window: *window,
                urgent_pointer: *urgent_pointer,
                data_offset: field(*data_offset),
                checksum: field(*checksum),
                options: options.clone(),
                payload: payload.clone(),
                ..Tcp::new(*source_port, *destination_port)
            }),
            Self::Udp {
                source_port,
                destination_port,
                length,
                checksum,
                payload,
            } => Layer::Udp(Udp {
                length: field(*length),
                checksum: field(*checksum),
                payload: payload.clone(),
                ..Udp::new(*source_port, *destination_port)
            }),
            Self::Sctp {
                source_port,
                destination_port,
                verification_tag,
                checksum,
                chunks,
            } => Layer::Sctp(Sctp {
                verification_tag: *verification_tag,
                checksum: field(*checksum),
                chunks: chunks.clone(),
                ..Sctp::new(*source_port, *destination_port)
            }),
            Self::Icmpv4 {
                icmp_type,
                code,
                checksum,
                rest_of_header,
                payload,
            } => Layer::Icmpv4(Icmpv4 {
                icmp_type: *icmp_type,
                code: *code,
                checksum: field(*checksum),
                rest_of_header: *rest_of_header,
                payload: payload.clone(),
            }),
            Self::Icmpv6 {
                icmp_type,
                code,
                checksum,
                rest_of_header,
                payload,
            } => Layer::Icmpv6(Icmpv6 {
                icmp_type: *icmp_type,
                code: *code,
                checksum: field(*checksum),
                rest_of_header: *rest_of_header,
                payload: payload.clone(),
            }),
            Self::Arp {
                sender_mac,
                sender_ip,
                target_ip,
            } => Layer::Arp(Arp::request(
                MacAddr::from(*sender_mac),
                Ipv4Addr::from(*sender_ip),
                Ipv4Addr::from(*target_ip),
            )),
            Self::Raw(bytes) => Layer::Raw(bytes.clone()),
        }
    }

    /// The option bytes this header carries, for the headers that carry any.
    fn options(&self) -> Option<&[u8]> {
        match self {
            Self::Ipv4 { options, .. } | Self::Tcp { options, .. } => Some(options),
            _ => None,
        }
    }
}

fn pnet_ethertype(raw: u16) -> pnet_packet::ethernet::EtherType {
    pnet_packet::ethernet::EtherType(raw)
}

fn pnet_protocol(raw: u8) -> pnet_packet::ip::IpNextHeaderProtocol {
    pnet_packet::ip::IpNextHeaderProtocol(raw)
}

fuzz_target!(|recipe: Recipe| {
    if recipe.layers.is_empty() || recipe.layers.len() > MAX_LAYERS {
        return;
    }

    let assemble = |extra: Option<Layer>| {
        let mut packet = Packet::new();
        for spec in &recipe.layers {
            packet = packet.push(spec.build());
        }
        if let Some(layer) = extra {
            packet = packet.push(layer);
        }
        packet
    };

    // Options past what four bits of words can describe have to be refused. A
    // header written anyway would claim a length running into its own payload.
    let describable = recipe.layers.iter().all(|spec| {
        spec.options()
            .is_none_or(|options| options.len() <= LARGEST_OPTIONS && options.len().is_multiple_of(4))
    });

    let Ok(bytes) = assemble(None).build() else {
        return;
    };
    assert!(
        describable,
        "a header built with options no length field can describe"
    );

    let mut builds: Vec<Vec<u8>> = (1..VARIANCE_BUILDS)
        .map(|_| assemble(None).build().expect("the first build succeeded"))
        .collect();
    builds.push(bytes.clone());

    if randomised(&recipe) {
        assert!(
            builds.windows(2).any(|pair| pair[0] != pair[1]),
            "every build of a recipe with a computed identifier came out identical, \
             so the identifier a stack must not be able to predict is fixed"
        );
    } else {
        assert!(
            builds.windows(2).all(|pair| pair[0] == pair[1]),
            "building one recipe twice wrote two different packets, and nothing in it \
             was meant to vary"
        );
    }

    // One byte more inside, and the packet is one byte longer. A length field
    // that cannot describe the result refuses, which says nothing either way.
    if let Ok(longer) = assemble(Some(Layer::Raw(vec![0]))).build() {
        assert_eq!(
            longer.len(),
            bytes.len() + 1,
            "a packet carrying one more byte did not grow by one byte"
        );
    }

    check_declared_lengths(&recipe, &bytes);
    check_document_round_trip(&assemble(None));
});

/// Holds that a packet survives being written down and read back.
///
/// JSON rather than TOML because the fuzz crate already carries a JSON
/// implementation, and because the format is not the subject: `craft` names
/// none, and what is under test is the adapters between its types and `serde`.
fn check_document_round_trip(packet: &Packet) {
    let written = serde_json::to_string(packet).expect("a packet is a document");
    let read: Packet = serde_json::from_str(&written)
        .unwrap_or_else(|error| panic!("a packet this crate wrote is not one it reads: {error}"));

    assert_eq!(
        &read, packet,
        "the packet that came back is not the packet that went in: {written}"
    );
}

/// Whether the recipe leaves a field the builder draws at random.
///
/// Two of them: an IPv4 identification and an IPv6 flow label. Both are
/// `Computed` when the fuzzer chose no value, and both are what a stack varies
/// per packet rather than a function of what is being sent.
fn randomised(recipe: &Recipe) -> bool {
    recipe.layers.iter().any(|spec| {
        matches!(
            spec,
            LayerSpec::Ipv4 {
                identification: None,
                ..
            } | LayerSpec::Ipv6 {
                flow_label: None,
                ..
            }
        )
    })
}

/// Holds that the outermost IP header's computed length fields describe the
/// bytes that actually follow them.
fn check_declared_lengths(recipe: &Recipe, bytes: &[u8]) {
    let (offset, header) = match recipe.layers.first() {
        Some(spec @ (LayerSpec::Ipv4 { .. } | LayerSpec::Ipv6 { .. })) => (0, spec),
        Some(LayerSpec::Ethernet { .. }) => match recipe.layers.get(1) {
            Some(spec @ (LayerSpec::Ipv4 { .. } | LayerSpec::Ipv6 { .. })) => {
                (ETHERNET_HEADER, spec)
            }
            _ => return,
        },
        _ => return,
    };

    let Some(ip) = bytes.get(offset..) else {
        return;
    };

    match header {
        LayerSpec::Ipv4 {
            total_length,
            options,
            ..
        } => {
            let header_len = FIXED_HEADER + options.len();
            assert_eq!(
                usize::from(ip[0] & 0x0f) * 4,
                header_len,
                "the IPv4 header length field does not count the options behind it"
            );
            if total_length.is_none() {
                assert_eq!(
                    usize::from(u16::from_be_bytes([ip[2], ip[3]])),
                    ip.len(),
                    "the IPv4 total length does not describe the datagram behind it"
                );
            }
        }
        LayerSpec::Ipv6 { payload_length, .. } => {
            if payload_length.is_none() {
                assert_eq!(
                    usize::from(u16::from_be_bytes([ip[4], ip[5]])),
                    ip.len() - 40,
                    "the IPv6 payload length does not describe the payload behind it"
                );
            }
        }
        _ => unreachable!("only an IP header reaches here"),
    }
}
