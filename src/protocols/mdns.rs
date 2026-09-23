// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Multicast DNS
//!
//! Builds a forward mDNS query, and reads the hosts an mDNS message names.
//!
//! [`build_query`] asks for a `.local` name's addresses; [`extract_hosts`]
//! reads the addresses out of the answer. The two are the wire-format half of
//! resolution and know nothing about sockets: sending the query on the multicast
//! group and reading the reply belong to [`crate::resolve`], the same way
//! [`crate::protocols::dns`] leaves the query socket to
//! [`crate::scanner::rdns`].
//!
//! A hostname comes from the *owner* of an address record: `raspberrypi.local.
//! A 192.168.0.150` says that this address belongs to that name, and says it
//! about one host. The PTR records in the same message do not - service
//! discovery answers `_airplay._tcp.local. PTR Living Room._airplay._tcp.local.`,
//! which names a service instance and not the machine hosting it. The one PTR
//! worth reading is a reverse one, whose owner is an `in-addr.arpa` or
//! `ip6.arpa` name and so names an address outright.
//!
//! One message can speak for several hosts, since responders answer with
//! whatever else they know in the additional section. Records are therefore
//! grouped by owner, and each group comes back as its own [`MdnsHost`], so a
//! name is never paired with an address that belongs to a different machine.

use crate::protocols::error::{PacketError, Result};

use dns_parser::{Packet, RData};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use crate::protocols::dns;

/// The transaction ID every multicast query carries, which RFC 6762 §18.1
/// requires to be zero. Nothing correlates on it; see [`build_query`].
const MULTICAST_QUERY_ID: u16 = 0;

/// The port multicast DNS is spoken on, in both directions.
pub const PORT: u16 = 5353;

/// Builds a forward mDNS query for the addresses of `name`.
///
/// Asks for A and AAAA together in one message, so a single exchange learns a
/// host's addresses in both families rather than costing a query each. The
/// trailing dot a fully-qualified `.local` name may carry is stripped, since the
/// wire form never includes it.
///
/// The transaction ID is zero, as RFC 6762 §18.1 requires of a multicast query.
/// That is not how the answer is correlated: an mDNS response echoes no ID worth
/// trusting, so the caller matches the address records back to the name they own
/// (see [`extract_hosts`]), which is the same reason the reverse path in
/// [`crate::protocols::dns`] correlates on the question name.
///
/// Recursion is not asked for, since a multicast query has nobody to ask it of
/// (RFC 6762 §18.6), and the unicast-response bit is not set: the resolver sends
/// from an ephemeral port, and a responder seeing a query from any port other
/// than 5353 must answer it directly under the legacy rule of §6.7.
///
/// # Errors
///
/// [`PacketError::UnwritableName`] for a name that has no wire form, which for
/// an mDNS lookup means a label past 63 octets or a name past 255. `name` is
/// whatever a caller was asked to resolve, so this is the ordinary way a bad
/// hostname arrives rather than a rare one.
pub fn build_query(name: &str) -> Result<Vec<u8>> {
    dns::build_query(
        MULTICAST_QUERY_ID,
        false,
        &[(name, dns::record_type::A), (name, dns::record_type::AAAA)],
    )
}

/// One host as an mDNS message described it.
///
/// `#[non_exhaustive]`: a responder says more about a host than its name and its
/// addresses, and reading another of those adds a field here. [`Default`] is
/// what to build one from.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdnsHost {
    /// The name the host answers to, without its trailing dot.
    pub hostname: String,
    /// Every address the message gave for that name, in address order.
    ///
    /// Ordered rather than hashed so two runs over one message hand back the
    /// same list. A responder may name an address twice across the answer and
    /// additional sections, so this is a set; what it must not be is a set whose
    /// order moves between processes, since these addresses reach a report.
    pub ips: BTreeSet<IpAddr>,
}

/// The name a host's device-info record is published under, or `None` for a
/// name no responder publishes one under.
///
/// Bonjour hangs it off the hostname rather than advertising it as a service, so
/// it does not appear in a `_services._dns-sd._udp` enumeration and cannot be
/// asked for without knowing what the host calls itself. Measured against
/// mDNSResponder: `_device-info._tcp.local` alone draws nothing, and
/// `<host>._device-info._tcp.local` draws the record.
///
/// # Which names have one
///
/// A name in `.local`, whose host part is what the record hangs off, and a bare
/// label, which is how a device names itself in its DHCP request. A name in any
/// other zone came from a unicast resolver: multicast DNS answers for `.local`
/// and nothing else (RFC 6762 §3), so `x.fritz.box._device-info._tcp.local` is
/// a question no responder answers, and the zone's own label for the device is
/// whatever whoever runs the zone chose, which need not be what the device
/// calls itself.
///
/// The trailing dot of a fully-qualified name is dropped first, and the zone
/// is recognised whatever its case, as DNS compares names (RFC 4343), so
/// `mac.`, `mac.local.` and `mac.LOCAL` all name the record under `mac`.
pub fn device_info_name(hostname: &str) -> Option<String> {
    let name = hostname.trim_end_matches('.');
    let host = match name.rsplit_once('.') {
        Some((host, zone)) if zone.eq_ignore_ascii_case("local") => host,
        Some(_) => return None,
        // The zone on its own, which names no host.
        None if name.eq_ignore_ascii_case("local") => return None,
        None => name,
    };
    (!host.is_empty()).then(|| format!("{host}._device-info._tcp.local"))
}

/// A query asking a host what it calls itself, by the reverse name of its
/// address.
///
/// The device-info record is published under the host's own name, so a scan that
/// does not already know that name cannot ask for the record. A responder
/// answers a reverse lookup about its own address, which is where the name comes
/// from when nothing else resolved one: measured against mDNSResponder, and it is
/// what makes the device-info query reachable on a host the scan learned nothing
/// else about.
pub fn build_reverse_query(ip: IpAddr) -> Result<Vec<u8>> {
    dns::build_query(
        MULTICAST_QUERY_ID,
        false,
        &[(&dns::reverse_pointer_name(ip), dns::record_type::PTR)],
    )
}

/// A query for a host's device-info record, asked of that host directly, or
/// `None` where `hostname` has no record under it: see [`device_info_name`].
///
/// Sent to the host directly rather than to the multicast group. A scan is asking
/// one host about itself, so telling the whole segment would make the answer
/// harder to attribute rather than easier.
///
/// The question carries an ordinary `IN` class. RFC 6762 §5.4 defines a top bit
/// asking for a unicast reply, and it is not set here because it is not needed:
/// measured against mDNSResponder, a query sent to a responder's own port is
/// answered either way, and the bit exists for queries put on the group.
///
/// # Errors
///
/// [`PacketError::UnwritableName`], inside the `Some`, for a name that has no
/// wire form.
pub fn build_device_info_query(hostname: &str) -> Option<Result<Vec<u8>>> {
    let name = device_info_name(hostname)?;
    Some(dns::build_query(
        MULTICAST_QUERY_ID,
        false,
        &[(&name, dns::record_type::TXT)],
    ))
}

/// The strings a TXT record carries, one per character-string.
///
/// Kept apart rather than joined, because that is the unit the signature corpus
/// is written against: a device-info record answers `model=Mac16,10`,
/// `osxvers=25`, `icolor=0`, and a rule reads one of them. Joining them would
/// reach none.
pub fn text_records(data: &[u8]) -> Result<Vec<String>> {
    let packet =
        Packet::parse(data).map_err(|error| PacketError::unreadable("an mDNS message", error))?;

    Ok(packet
        .answers
        .iter()
        .chain(packet.additional.iter())
        .filter_map(|record| match &record.data {
            RData::TXT(txt) => Some(txt.iter()),
            _ => None,
        })
        .flatten()
        .filter_map(|chunk| String::from_utf8(chunk.to_vec()).ok())
        .filter(|text| !text.is_empty())
        .collect())
}

/// Reads every host an mDNS message names, in name order.
///
/// A message that names none - a query, or a response carrying only service
/// records - yields an empty list rather than an error. Only bytes that are not
/// a DNS message at all are rejected.
pub fn extract_hosts(data: &[u8]) -> Result<Vec<MdnsHost>> {
    let packet =
        Packet::parse(data).map_err(|error| PacketError::unreadable("an mDNS message", error))?;
    let mut by_hostname: BTreeMap<String, BTreeSet<IpAddr>> = BTreeMap::new();

    for record in packet.answers.iter().chain(packet.additional.iter()) {
        let (hostname, ip) = match &record.data {
            RData::A(a) => (owner_name(&record.name), IpAddr::V4(a.0)),
            RData::AAAA(aaaa) => (owner_name(&record.name), IpAddr::V6(aaaa.0)),
            // A reverse PTR is the mirror image: its owner is the address and
            // its target is the name.
            RData::PTR(ptr) => match dns::address_from_pointer_name(&record.name.to_string()) {
                Some(ip) => (trim_root(&ptr.0.to_string()), ip),
                None => continue,
            },
            _ => continue,
        };

        by_hostname.entry(hostname).or_default().insert(ip);
    }

    Ok(by_hostname
        .into_iter()
        .map(|(hostname, ips)| MdnsHost { hostname, ips })
        .collect())
}

/// The name a record is about, without the root label a wire name ends in.
fn owner_name(name: &dns_parser::Name<'_>) -> String {
    trim_root(&name.to_string())
}

/// Drops the trailing dot a fully-qualified name carries, which is on the wire
/// and is not what anybody writes or reads.
fn trim_root(name: &str) -> String {
    name.trim_end_matches('.').to_string()
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
    use dns_parser::QueryType;

    /// The plain case: a responder announcing its own addresses.
    #[test]
    fn an_address_record_names_its_owner() {
        let message = response(&[
            record("raspberrypi.local", Rdata::A([192, 168, 0, 150])),
            record("raspberrypi.local", Rdata::Aaaa("fe80::1".parse().unwrap())),
        ]);

        assert_eq!(
            extract_hosts(&message).unwrap(),
            vec![MdnsHost {
                hostname: "raspberrypi.local".to_string(),
                ips: BTreeSet::from(["192.168.0.150".parse().unwrap(), "fe80::1".parse().unwrap()]),
            }]
        );
    }

    /// A service PTR names an instance of a service, not the machine running
    /// it. Reading one as a hostname puts "Living Room._airplay._tcp.local" on
    /// a host in the scan report.
    #[test]
    fn a_service_record_names_no_host() {
        let message = response(&[
            record(
                "_airplay._tcp.local",
                Rdata::Ptr("Living Room._airplay._tcp.local"),
            ),
            record(
                "_services._dns-sd._udp.local",
                Rdata::Ptr("_airplay._tcp.local"),
            ),
        ]);

        assert_eq!(extract_hosts(&message).unwrap(), Vec::new());
    }

    /// A reverse PTR is the one PTR that does name a host, because its owner
    /// is the address itself.
    #[test]
    fn a_reverse_record_names_the_host_at_that_address() {
        let message = response(&[record(
            "150.0.168.192.in-addr.arpa",
            Rdata::Ptr("raspberrypi.local"),
        )]);

        assert_eq!(
            extract_hosts(&message).unwrap(),
            vec![MdnsHost {
                hostname: "raspberrypi.local".to_string(),
                ips: BTreeSet::from(["192.168.0.150".parse().unwrap()]),
            }]
        );
    }

    /// A responder answers with what else it knows, so one message routinely
    /// covers several machines. Merging them would hand one host's name to
    /// another host's address.
    #[test]
    fn each_owner_in_a_message_is_a_host_of_its_own() {
        let message = response(&[
            record("appletv.local", Rdata::A([192, 168, 0, 40])),
            record(
                "_airplay._tcp.local",
                Rdata::Ptr("Living Room._airplay._tcp.local"),
            ),
            record("printer.local", Rdata::A([192, 168, 0, 30])),
        ]);

        assert_eq!(
            extract_hosts(&message).unwrap(),
            vec![
                MdnsHost {
                    hostname: "appletv.local".to_string(),
                    ips: BTreeSet::from(["192.168.0.40".parse().unwrap()]),
                },
                MdnsHost {
                    hostname: "printer.local".to_string(),
                    ips: BTreeSet::from(["192.168.0.30".parse().unwrap()]),
                },
            ]
        );
    }

    #[test]
    fn bytes_that_are_not_dns_are_rejected() {
        assert!(extract_hosts(b"not dns").is_err());
    }

    /// A query has to be a DNS message a responder will parse, ask about the
    /// name it was given, and carry the zero ID a multicast query is required
    /// to. Building bytes a responder would drop would fail silently as a
    /// network that never answers.
    #[test]
    fn a_forward_query_asks_for_the_name_in_both_families() {
        let query = build_query("raspberrypi.local").expect("the query builds");
        let packet = Packet::parse(&query).expect("a responder can parse it");

        assert!(packet.header.query, "it is a query, not a response");
        assert_eq!(packet.header.id, 0, "a multicast query carries the zero ID");

        let asked: Vec<_> = packet
            .questions
            .iter()
            .map(|q| (q.qname.to_string(), q.qtype))
            .collect();
        assert_eq!(
            asked,
            vec![
                ("raspberrypi.local".to_string(), QueryType::A),
                ("raspberrypi.local".to_string(), QueryType::AAAA),
            ]
        );
    }

    /// A name with no wire form comes back as an error.
    ///
    /// Not a panic that aborts the process. `name` is whatever a caller was
    /// asked to resolve, and a builder that asserted the label bound rather
    /// than reporting it would panic inside a dependency on a label past 63
    /// octets. The panic would reach `Resolver::resolve` through two layers
    /// written to turn every failure into an empty vector, so nothing between
    /// here and the caller could catch it.
    #[test]
    fn a_name_with_no_wire_form_is_refused_rather_than_fatal() {
        let long_label = format!("{}.local", "a".repeat(64));
        assert!(matches!(
            build_query(&long_label),
            Err(PacketError::UnwritableName { .. })
        ));

        // 63 is the bound and is legal: the refusal must not start one short.
        assert!(build_query(&format!("{}.local", "a".repeat(63))).is_ok());

        // A name inside every label bound can still be too long as a whole.
        let long_name = std::iter::repeat_n("label", 60)
            .collect::<Vec<_>>()
            .join(".");
        assert!(matches!(
            build_query(&long_name),
            Err(PacketError::UnwritableName { .. })
        ));

        // A doubled dot is an empty label, which no name may carry.
        assert!(matches!(
            build_query("printer..local"),
            Err(PacketError::UnwritableName { .. })
        ));
    }

    /// The wire form of a name never carries the trailing dot, so a
    /// fully-qualified name must reach the wire without it or the question names
    /// something one label longer than the host.
    #[test]
    fn a_trailing_dot_is_stripped_from_the_question() {
        let query = build_query("printer.local.").expect("the query builds");
        let packet = Packet::parse(&query).expect("parses");

        assert_eq!(
            packet.questions.first().map(|q| q.qname.to_string()),
            Some("printer.local".to_string())
        );
    }

    enum Rdata<'a> {
        A([u8; 4]),
        Aaaa(std::net::Ipv6Addr),
        Ptr(&'a str),
    }

    struct TestRecord<'a> {
        owner: &'a str,
        data: Rdata<'a>,
    }

    fn record<'a>(owner: &'a str, data: Rdata<'a>) -> TestRecord<'a> {
        TestRecord { owner, data }
    }

    /// Assembles an mDNS response by hand; `dns_parser` only builds queries.
    fn response(records: &[TestRecord<'_>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes()); // mDNS responses carry no ID
        bytes.extend_from_slice(&0x8400u16.to_be_bytes()); // response, authoritative
        bytes.extend_from_slice(&0u16.to_be_bytes()); // questions
        bytes.extend_from_slice(&(records.len() as u16).to_be_bytes()); // answers
        bytes.extend_from_slice(&0u16.to_be_bytes()); // authority
        bytes.extend_from_slice(&0u16.to_be_bytes()); // additional

        for record in records {
            write_name(&mut bytes, record.owner);

            let (rtype, rdata) = match &record.data {
                Rdata::A(octets) => (1u16, octets.to_vec()),
                Rdata::Aaaa(addr) => (28u16, addr.octets().to_vec()),
                Rdata::Ptr(target) => {
                    let mut rdata = Vec::new();
                    write_name(&mut rdata, target);
                    (12u16, rdata)
                }
            };

            bytes.extend_from_slice(&rtype.to_be_bytes());
            bytes.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            bytes.extend_from_slice(&120u32.to_be_bytes()); // TTL
            bytes.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&rdata);
        }

        bytes
    }

    fn write_name(bytes: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
    }

    /// A real answer from mDNSResponder, captured 2026-09-05 by asking a Mac's
    /// own responder over unicast. The three strings are what the corpus reads.
    const DEVICE_INFO: &[u8] = &[
        0x00, 0x00, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x6d, 0x61,
        0x63, 0x0c, 0x5f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x69, 0x6e, 0x66, 0x6f, 0x04,
        0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x10, 0x80, 0x01,
        0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x23, 0x0e, 0x6d, 0x6f,
        0x64, 0x65, 0x6c, 0x3d, 0x4d, 0x61, 0x63, 0x31, 0x36, 0x2c, 0x31, 0x30, 0x0a, 0x6f, 0x73,
        0x78, 0x76, 0x65, 0x72, 0x73, 0x3d, 0x32, 0x35, 0x08, 0x69, 0x63, 0x6f, 0x6c, 0x6f, 0x72,
        0x3d, 0x30,
    ];

    /// Each character-string separately, because that is the unit a rule reads.
    #[test]
    fn a_device_info_record_yields_one_string_per_field() {
        assert_eq!(
            text_records(DEVICE_INFO).expect("a well-formed answer"),
            vec!["model=Mac16,10", "osxvers=25", "icolor=0"]
        );
    }

    /// The name the record hangs off, which is a hostname and not a service.
    #[test]
    fn the_query_name_is_built_from_the_host_rather_than_browsed_for() {
        for name in ["mac", "mac.local", "mac.local."] {
            assert_eq!(
                device_info_name(name).as_deref(),
                Some("mac._device-info._tcp.local"),
                "{name}"
            );
        }
    }

    /// A trailing dot is dropped from a bare label as it is from a `.local`
    /// name, and the zone is recognised whatever its case.
    ///
    /// Kept, the dot would be an empty label in the middle of the question,
    /// `mac.._device-info._tcp.local`, which names nothing a responder
    /// publishes.
    #[test]
    fn a_fully_qualified_or_capitalised_name_asks_the_same_question() {
        assert_eq!(
            device_info_name("mac.").as_deref(),
            Some("mac._device-info._tcp.local")
        );
        assert_eq!(
            device_info_name("Mac.LOCAL").as_deref(),
            Some("Mac._device-info._tcp.local")
        );
    }

    /// A name in any zone but `.local` asks no question, rather than one no
    /// responder answers.
    ///
    /// Such a name came from a unicast resolver, and a query built from it is
    /// a datagram spent on silence. Refusing it is what lets a caller ask the
    /// host what it calls itself instead, which is the name the record is
    /// published under.
    #[test]
    fn a_name_outside_local_asks_no_question() {
        assert_eq!(device_info_name("x.fritz.box"), None);
        assert!(build_device_info_query("x.fritz.box").is_none());

        // Nor does a name with no host in it.
        for empty in ["", ".", ".local", "local."] {
            assert_eq!(device_info_name(empty), None, "{empty:?}");
        }
    }

    /// The query a responder answered with the bytes above.
    #[test]
    fn the_query_asks_for_text_under_that_name() {
        let query = build_device_info_query("mac")
            .expect("a name with a record under it")
            .expect("a name that fits a label");
        let packet = Packet::parse(&query).expect("a responder can parse it");

        let question = packet.questions.first().expect("one question");
        assert_eq!(question.qname.to_string(), "mac._device-info._tcp.local");
        assert_eq!(question.qtype, QueryType::TXT);
    }

    #[test]
    fn a_message_carrying_no_text_yields_nothing() {
        let query = build_device_info_query("mac")
            .expect("a name with a record under it")
            .expect("a query");
        assert!(
            text_records(&query)
                .expect("a parseable message")
                .is_empty()
        );
    }

    #[test]
    fn bytes_that_are_not_a_message_are_refused_rather_than_read() {
        assert!(text_records(b"not an mdns message at all").is_err());
    }

    /// The question asked of a host that has not been named any other way. Its
    /// answer is what makes the device-info query possible at all.
    #[test]
    fn the_reverse_query_asks_for_the_name_of_an_address() {
        let ip: IpAddr = "192.168.0.160".parse().expect("a literal address");
        let query = build_reverse_query(ip).expect("a reverse name fits");
        let packet = Packet::parse(&query).expect("a responder can parse it");

        let question = packet.questions.first().expect("one question");
        assert_eq!(
            question.qname.to_string(),
            "160.0.168.192.in-addr.arpa",
            "the reverse name names the address"
        );
        assert_eq!(question.qtype, QueryType::PTR);
    }
}
