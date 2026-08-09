// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reverse DNS
//!
//! Building reverse (PTR) queries and reading the responses they draw.
//!
//! The reverse name is the correlation key throughout. A response echoes the
//! question it answers, so [`address_from_pointer_name`] recovers the address a
//! response is *about* from the response itself, rather than trusting its
//! transaction ID to say. That matters because the resolver also reads DNS
//! traffic it never asked for: a transaction ID means nothing in a packet
//! addressed to someone else, while the question name means the same thing in
//! every packet that carries it.

use anyhow::{Context, Result, anyhow};
use dns_parser::{Builder, Packet, QueryClass, QueryType, RData};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The zone every IPv4 reverse name sits under.
const IPV4_ARPA_SUFFIX: &str = ".in-addr.arpa";
/// The zone every IPv6 reverse name sits under.
const IPV6_ARPA_SUFFIX: &str = ".ip6.arpa";
/// How many labels spell out an IPv6 address: one hex digit per nibble.
const IPV6_NIBBLES: usize = 32;

/// A DNS response to a reverse question, reduced to what hostname resolution
/// needs from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtrResponse {
    /// The transaction ID of the query being answered.
    pub id: u16,
    /// The address the question was about, recovered from the reverse name the
    /// response echoes back. `None` when the response carries no question, or
    /// one that is not a reverse lookup.
    pub subject: Option<IpAddr>,
    /// The name the first PTR answer carries. `None` for a negative answer,
    /// which is still an answer: the address simply has no name.
    pub hostname: Option<String>,
}

/// Reads a DNS response to a reverse lookup.
///
/// Both callers feed this bytes they did not choose - replies arriving on the
/// query socket, and DNS traffic sniffed off the wire - so "this says nothing
/// about any address" is an ordinary outcome, not a failure. It comes back as a
/// [`PtrResponse`] with an empty `subject` or `hostname` rather than an error.
/// Only bytes that are not a DNS message at all, or that are a query rather
/// than a response, are rejected.
pub fn parse_ptr_response(payload: &[u8]) -> Result<PtrResponse> {
    let packet = Packet::parse(payload).context("not a parseable DNS message")?;

    if packet.header.query {
        return Err(anyhow!("DNS message is a query, not a response"));
    }

    let subject = packet
        .questions
        .first()
        .filter(|question| question.qtype == QueryType::PTR)
        .and_then(|question| address_from_pointer_name(&question.qname.to_string()));

    // The first PTR answer wins. Its owner name is deliberately not required to
    // equal the question: RFC 2317 delegation answers a reverse question with a
    // CNAME into another zone, and the PTR that follows is owned by that name.
    let hostname = packet.answers.iter().find_map(|record| match &record.data {
        RData::PTR(ptr) => Some(ptr.0.to_string().trim_end_matches('.').to_string()),
        _ => None,
    });

    Ok(PtrResponse {
        id: packet.header.id,
        subject,
        hostname,
    })
}

/// The reverse name `ip` is looked up under: `in-addr.arpa` for IPv4, and
/// `ip6.arpa` - one label per nibble, least significant first - for IPv6.
pub fn reverse_pointer_name(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(ipv4) => {
            let [a, b, c, d] = ipv4.octets();
            format!("{d}.{c}.{b}.{a}{IPV4_ARPA_SUFFIX}")
        }
        IpAddr::V6(ipv6) => {
            let mut name = String::with_capacity(IPV6_NIBBLES * 2 + IPV6_ARPA_SUFFIX.len());

            for byte in ipv6.octets().iter().rev() {
                use std::fmt::Write;
                write!(name, "{:x}.{:x}.", byte & 0x0F, byte >> 4)
                    .expect("writing to a String cannot fail");
            }
            name.truncate(name.len() - 1);
            name.push_str(IPV6_ARPA_SUFFIX);

            name
        }
    }
}

/// The address a reverse name refers to, or `None` when `name` is not one.
///
/// The inverse of [`reverse_pointer_name`], and the reason a response can be
/// tied to an address without trusting whoever sent it. Names are compared
/// case-insensitively, since a resolver may echo a question back in any case.
pub fn address_from_pointer_name(name: &str) -> Option<IpAddr> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();

    if let Some(prefix) = name.strip_suffix(IPV4_ARPA_SUFFIX) {
        return parse_ipv4_pointer(prefix);
    }

    if let Some(prefix) = name.strip_suffix(IPV6_ARPA_SUFFIX) {
        return parse_ipv6_pointer(prefix);
    }

    None
}

/// Reads the four octet labels of an `in-addr.arpa` name, which spells the
/// address out backwards.
fn parse_ipv4_pointer(prefix: &str) -> Option<IpAddr> {
    let labels: Vec<&str> = prefix.split('.').collect();
    let [d, c, b, a] = <[&str; 4]>::try_from(labels).ok()?;

    Some(IpAddr::V4(Ipv4Addr::new(
        a.parse().ok()?,
        b.parse().ok()?,
        c.parse().ok()?,
        d.parse().ok()?,
    )))
}

/// Reads the 32 nibble labels of an `ip6.arpa` name. Each label is one hex
/// digit, least significant first, so taking them two at a time from the end
/// yields the address's bytes in order.
fn parse_ipv6_pointer(prefix: &str) -> Option<IpAddr> {
    let labels: Vec<&str> = prefix.split('.').collect();
    if labels.len() != IPV6_NIBBLES {
        return None;
    }

    let mut octets = [0u8; 16];
    for (byte, pair) in octets.iter_mut().zip(labels.rchunks(2)) {
        let low = hex_nibble(pair[0])?;
        let high = hex_nibble(pair[1])?;
        *byte = (high << 4) | low;
    }

    Some(IpAddr::V6(Ipv6Addr::from(octets)))
}

/// The value of a single-hex-digit label, or `None` for anything else.
fn hex_nibble(label: &str) -> Option<u8> {
    let mut chars = label.chars();
    let digit = chars.next()?.to_digit(16)?;
    chars.next().is_none().then_some(digit as u8)
}

/// Builds a reverse (PTR) query for `ip_addr`, tagged with transaction ID `id`.
pub fn create_ptr_packet(ip_addr: &IpAddr, id: u16) -> Result<Vec<u8>> {
    let ptr_name: String = reverse_pointer_name(ip_addr);

    let mut builder: Builder = Builder::new_query(id, true);

    builder.add_question(&ptr_name, false, QueryType::PTR, QueryClass::IN);

    let packet_bytes: Vec<u8> = builder
        .build()
        .map_err(|e| anyhow!("Failed to build DNS packet: {:?}", e))?;

    Ok(packet_bytes)
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

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The name a query is asked under and the address a response is read back
    /// as have to agree, or correlation silently stops matching anything.
    #[test]
    fn a_reverse_name_round_trips_through_the_address_it_names() {
        for address in [
            ip("192.168.0.1"),
            ip("10.0.0.255"),
            ip("0.0.0.0"),
            ip("255.255.255.255"),
            ip("2a02:908:8c1:b880:ca52:61ff:fec7:594"),
            ip("fe80::1"),
            ip("::"),
        ] {
            let name = reverse_pointer_name(&address);
            assert_eq!(
                address_from_pointer_name(&name),
                Some(address),
                "round trip failed through {name}"
            );
        }
    }

    #[test]
    fn reverse_names_are_spelled_out_backwards_under_their_zone() {
        assert_eq!(
            reverse_pointer_name(&ip("192.168.0.1")),
            "1.0.168.192.in-addr.arpa"
        );
        assert_eq!(
            reverse_pointer_name(&ip("2001:db8::1")),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    /// A resolver may echo a question back in any case, so the comparison that
    /// ties a response to an address cannot be case-sensitive.
    #[test]
    fn a_reverse_name_is_read_regardless_of_case() {
        assert_eq!(
            address_from_pointer_name("1.0.168.192.IN-ADDR.ARPA."),
            Some(ip("192.168.0.1"))
        );
        assert_eq!(
            address_from_pointer_name(
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.B.D.0.1.0.0.2.IP6.ARPA"
            ),
            Some(ip("2001:db8::1"))
        );
    }

    /// Anything that is not a reverse name has to come back as "no address"
    /// rather than a wrong one - this is what stands between unrelated sniffed
    /// traffic and a hostname landing on the wrong host.
    #[test]
    fn a_name_that_is_not_a_reverse_name_names_no_address() {
        for name in [
            "example.com",
            "in-addr.arpa",
            "1.0.168.in-addr.arpa",
            "1.0.168.192.0.in-addr.arpa",
            "256.0.168.192.in-addr.arpa",
            "x.0.168.192.in-addr.arpa",
            "1.0.0.2.ip6.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.zz.ip6.arpa",
        ] {
            assert_eq!(address_from_pointer_name(name), None, "accepted {name}");
        }
    }

    /// A response has to be readable as the answer to the question that was
    /// asked, since the question is what identifies the address it concerns.
    #[test]
    fn a_response_reports_the_address_asked_about_and_the_name_returned() {
        let response = parse_ptr_response(&ptr_response(
            0x1234,
            "1.0.168.192.in-addr.arpa",
            Some("kabelbox.local"),
        ))
        .unwrap();

        assert_eq!(
            response,
            PtrResponse {
                id: 0x1234,
                subject: Some(ip("192.168.0.1")),
                hostname: Some("kabelbox.local".to_string()),
            }
        );
    }

    /// A resolver that will not answer for private space - which RFC 6303 asks
    /// it to do - answers with no records at all. That is a real answer about a
    /// known address, not a parse failure, and has to read as one.
    #[test]
    fn a_negative_response_still_names_the_address_it_answers_for() {
        let response =
            parse_ptr_response(&ptr_response(7, "30.0.168.192.in-addr.arpa", None)).unwrap();

        assert_eq!(response.id, 7);
        assert_eq!(response.subject, Some(ip("192.168.0.30")));
        assert_eq!(response.hostname, None);
    }

    /// Sniffed traffic is mostly forward lookups. They parse fine and simply
    /// concern no address, which is what keeps them out of the host store.
    #[test]
    fn a_forward_lookup_concerns_no_address() {
        let mut builder = Builder::new_query(1, true);
        builder.add_question("example.com", false, QueryType::A, QueryClass::IN);
        let mut bytes = builder.build().unwrap();
        bytes[2] |= 0x80; // flip QR: this is now a response

        let response = parse_ptr_response(&bytes).unwrap();
        assert_eq!(response.subject, None);
        assert_eq!(response.hostname, None);
    }

    #[test]
    fn a_query_is_not_a_response() {
        let query = create_ptr_packet(&ip("192.168.0.1"), 9).unwrap();
        assert!(parse_ptr_response(&query).is_err());
    }

    #[test]
    fn bytes_that_are_not_dns_are_rejected() {
        assert!(parse_ptr_response(b"not dns").is_err());
    }

    /// Builds a PTR response by hand: `dns_parser`'s builder only writes
    /// queries, and these tests need answers to read back.
    fn ptr_response(id: u16, question: &str, answer: Option<&str>) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(&0x8180u16.to_be_bytes()); // response, recursion available
        bytes.extend_from_slice(&1u16.to_be_bytes()); // questions
        bytes.extend_from_slice(&u16::from(answer.is_some()).to_be_bytes()); // answers
        bytes.extend_from_slice(&0u16.to_be_bytes()); // authority
        bytes.extend_from_slice(&0u16.to_be_bytes()); // additional

        write_name(&mut bytes, question);
        bytes.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
        bytes.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

        if let Some(answer) = answer {
            bytes.extend_from_slice(&[0xC0, 0x0C]); // owner: pointer to the question
            bytes.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
            bytes.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            bytes.extend_from_slice(&60u32.to_be_bytes()); // TTL

            let mut rdata = Vec::new();
            write_name(&mut rdata, answer);
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
}
