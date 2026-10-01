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
//! The reverse name is the correlation key. A response echoes its question, so
//! [`address_from_pointer_name`] recovers the address a response is about from
//! the response itself. The resolver also reads DNS traffic it never asked for,
//! where a transaction ID means nothing but the question name still does.

use crate::protocols::error::{PacketError, Result};
use crate::protocols::sizes::DNS_HDR_LEN;
use dns_parser::{Packet, QueryType, RData};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The zone every IPv4 reverse name sits under.
const IPV4_ARPA_SUFFIX: &str = ".in-addr.arpa";
/// The zone every IPv6 reverse name sits under.
const IPV6_ARPA_SUFFIX: &str = ".ip6.arpa";
/// How many labels spell out an IPv6 address: one hex digit per nibble.
const IPV6_NIBBLES: usize = 32;

/// A DNS response to a reverse question, reduced to what hostname resolution
/// needs from it.
///
/// `#[non_exhaustive]`: built only by [`parse_ptr_response`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtrResponse {
    /// The transaction ID of the query being answered.
    pub id: u16,
    /// The address the question was about, recovered from the reverse name the
    /// response echoes back. `None` when the response carries no question, or
    /// one that is not a reverse lookup.
    pub subject: Option<IpAddr>,
    /// The name the first PTR answer carries. `None` for a negative answer: the
    /// address has no name.
    pub hostname: Option<String>,
}

/// Reads a DNS response to a reverse lookup.
///
/// Both callers feed this bytes they did not choose (replies on the query
/// socket and DNS traffic sniffed off the wire), so a response about no address
/// is ordinary and comes back with an empty `subject` or `hostname`. Only bytes
/// that are not a DNS response are rejected.
pub fn parse_ptr_response(payload: &[u8]) -> Result<PtrResponse> {
    let packet =
        Packet::parse(payload).map_err(|error| PacketError::unreadable("a DNS response", error))?;

    if packet.header.query {
        return Err(PacketError::UnexpectedMessage {
            expected: "a DNS response",
            got: "a query",
        });
    }

    let subject = packet
        .questions
        .first()
        .filter(|question| question.qtype == QueryType::PTR)
        .and_then(|question| address_from_pointer_name(&question.qname.to_string()));

    // The first PTR answer wins, and its owner name is not required to equal
    // the question: RFC 2317 delegation answers a reverse question with a
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

/// The text of the first TXT answer in a DNS response.
///
/// What a `version.bind` query draws: a nameserver's account of its build,
/// which several hundred corpus rules match. Runs of text inside one record are
/// joined without a separator, since a value longer than one 255-byte chunk
/// arrives split.
///
/// The question is not inspected, for the reason [`is_response`] gives.
/// [`None`] for anything that is not a response, carries no TXT answer, or
/// whose text is not UTF-8.
pub fn first_text_answer(payload: &[u8]) -> Option<String> {
    let packet = Packet::parse(payload).ok()?;
    if packet.header.query {
        return None;
    }

    let text = packet
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::TXT(txt) => Some(txt.iter().collect::<Vec<_>>().concat()),
            _ => None,
        })?;

    let text = String::from_utf8(text).ok()?;
    (!text.is_empty()).then_some(text)
}

/// Whether `payload` is a DNS server answering a question.
///
/// The evidence behind [`NetworkRole::DnsServer`]: something bound to 53 is a
/// socket, something that answers in DNS is a name server.
///
/// The question is not compared against the one the engine asked. The reply
/// already came from port 53 to the scan's probe source port after a DNS query
/// went there, and comparing questions would put the corpus's choice of probe
/// inside the scanner. Instead the whole message must parse: a header and every
/// question and record it claims, which arbitrary bytes do not.
///
/// `REFUSED` and `NOTIMP` still count: only a nameserver declines in DNS.
///
/// [`NetworkRole::DnsServer`]: crate::model::host::NetworkRole::DnsServer
pub fn is_response(payload: &[u8]) -> bool {
    Packet::parse(payload).is_ok_and(|packet| !packet.header.query)
}

/// The reverse name `ip` is looked up under: `in-addr.arpa` for IPv4, and
/// `ip6.arpa` (one label per nibble, least significant first) for IPv6.
pub fn reverse_pointer_name(ip: IpAddr) -> String {
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
/// The inverse of [`reverse_pointer_name`], which ties a response to an
/// address without trusting the sender. Case-insensitive, since a resolver may
/// echo a question in any case.
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
        octet(a)?,
        octet(b)?,
        octet(c)?,
        octet(d)?,
    )))
}

/// One label of an `in-addr.arpa` name as the octet it spells.
///
/// Read as strictly as [`reverse_pointer_name`] writes it, so one address has
/// one name. `str::parse::<u8>` would accept a leading `+` and leading zeros,
/// making `001.002.000.192.in-addr.arpa` and `+1.2.0.192.in-addr.arpa` both
/// name 192.0.2.1.
fn octet(label: &str) -> Option<u8> {
    let value: u8 = label.parse().ok()?;
    (label == value.to_string()).then_some(value)
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
///
/// Infallible: reverse names are spelled from an address, with labels of one
/// to three characters and at most 74 bytes (IPv6), well inside the bounds in
/// [`build_query`].
pub fn build_ptr_packet(ip_addr: IpAddr, id: u16) -> Vec<u8> {
    build_query(
        id,
        true,
        &[(&reverse_pointer_name(ip_addr), record_type::PTR)],
    )
    .expect("a reverse name is spelled from an address and cannot break a name bound")
}

/// Record type numbers, from the registry in RFC 1035 §3.2.2 and RFC 3596 §2.1.
///
/// Only the three this crate asks for.
pub mod record_type {
    /// A host's IPv4 address.
    pub const A: u16 = 1;
    /// A pointer to a name, which under `in-addr.arpa` is a reverse lookup.
    pub const PTR: u16 = 12;
    /// A host's IPv6 address.
    pub const AAAA: u16 = 28;
    /// Free-form text, used by device-info records and `version.bind` answers.
    pub const TXT: u16 = 16;
}

/// The internet class.
const CLASS_IN: u16 = 1;

/// The flag bit a query sets to ask a resolver to chase the answer for it.
const FLAG_RECURSION_DESIRED: u16 = 0x0100;

/// The longest a single label may be, and the longest a whole name may be on the
/// wire (RFC 1035 §2.3.4).
///
/// The one-byte length prefix reserves its top two bits for compression
/// pointers, hence 63. The 255 counts every length byte and the terminating
/// zero.
const MAX_LABEL_OCTETS: usize = 63;
const MAX_NAME_OCTETS: usize = 255;

/// Builds a DNS query carrying `questions`, each a name and the record type
/// being asked for.
///
///
/// `recursion_desired` asks a resolver to chase the answer. A unicast lookup
/// sets it; a multicast one must not (RFC 6762 §18.6).
///
/// # Errors
///
/// [`PacketError::UnwritableName`] for a label past 63 octets, a name past 255,
/// or an empty label (from a leading or doubled dot). A trailing dot is
/// trimmed.
pub fn build_query(id: u16, recursion_desired: bool, questions: &[(&str, u16)]) -> Result<Vec<u8>> {
    let flags = if recursion_desired {
        FLAG_RECURSION_DESIRED
    } else {
        0
    };

    let mut bytes = Vec::with_capacity(DNS_HDR_LEN + questions.len() * 32);
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&[0; 6]); // no answers, authorities or additionals
    debug_assert_eq!(bytes.len(), DNS_HDR_LEN);

    for (name, kind) in questions {
        write_name(name, &mut bytes)?;
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
    }

    Ok(bytes)
}

/// Writes `name` as the run of length-prefixed labels a question carries,
/// refusing anything that has no such form.
fn write_name(name: &str, out: &mut Vec<u8>) -> Result<()> {
    let trimmed = name.trim_end_matches('.');

    // Built aside and appended whole, so a refusal leaves `out` untouched.
    let mut encoded = Vec::with_capacity(trimmed.len() + 2);
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(PacketError::unwritable_name(
                name,
                "it has an empty label, which no name may carry",
            ));
        }
        if label.len() > MAX_LABEL_OCTETS {
            return Err(PacketError::unwritable_name(
                name,
                format_args!(
                    "the label {label:?} is {} octets, and a label holds at most {MAX_LABEL_OCTETS}",
                    label.len()
                ),
            ));
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);

    if encoded.len() > MAX_NAME_OCTETS {
        return Err(PacketError::unwritable_name(
            name,
            format_args!(
                "it is {} octets on the wire, and a name holds at most {MAX_NAME_OCTETS}",
                encoded.len()
            ),
        ));
    }

    out.extend_from_slice(&encoded);
    Ok(())
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
pub(crate) mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The query name and the address read back from a response must agree, or
    /// correlation silently stops matching.
    #[test]
    fn a_reverse_name_round_trips_through_the_address_it_names() {
        for address in [
            ip("203.0.113.1"),
            ip("198.51.100.255"),
            ip("0.0.0.0"),
            ip("255.255.255.255"),
            ip("2001:db8:85a3:8d3:1319:8a2e:370:7348"),
            ip("fe80::1"),
            ip("::"),
        ] {
            let name = reverse_pointer_name(address);
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
            reverse_pointer_name(ip("203.0.113.1")),
            "1.113.0.203.in-addr.arpa"
        );
        assert_eq!(
            reverse_pointer_name(ip("2001:db8::1")),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    /// A resolver may echo a question back in any case.
    #[test]
    fn a_reverse_name_is_read_regardless_of_case() {
        assert_eq!(
            address_from_pointer_name("1.113.0.203.IN-ADDR.ARPA."),
            Some(ip("203.0.113.1"))
        );
        assert_eq!(
            address_from_pointer_name(
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.B.D.0.1.0.0.2.IP6.ARPA"
            ),
            Some(ip("2001:db8::1"))
        );
    }

    /// Anything that is not a reverse name gives no address, which keeps
    /// unrelated sniffed traffic from landing a hostname on the wrong host.
    #[test]
    fn a_name_that_is_not_a_reverse_name_names_no_address() {
        for name in [
            "example.com",
            "in-addr.arpa",
            "1.113.0.in-addr.arpa",
            "1.113.0.203.0.in-addr.arpa",
            "256.113.0.203.in-addr.arpa",
            "x.113.0.203.in-addr.arpa",
            "1.0.0.2.ip6.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.zz.ip6.arpa",
        ] {
            assert_eq!(address_from_pointer_name(name), None, "accepted {name}");
        }
    }

    /// The question in a response identifies the address it concerns.
    #[test]
    fn a_response_reports_the_address_asked_about_and_the_name_returned() {
        let response = parse_ptr_response(&ptr_response(
            0x1234,
            "1.113.0.203.in-addr.arpa",
            Some("router.local"),
        ))
        .unwrap();

        assert_eq!(
            response,
            PtrResponse {
                id: 0x1234,
                subject: Some(ip("203.0.113.1")),
                hostname: Some("router.local".to_string()),
            }
        );
    }

    /// A resolver that will not answer for private space (as RFC 6303 asks)
    /// answers with no records. That is a real answer about a known address.
    #[test]
    fn a_negative_response_still_names_the_address_it_answers_for() {
        let response =
            parse_ptr_response(&ptr_response(7, "30.0.0.10.in-addr.arpa", None)).unwrap();

        assert_eq!(response.id, 7);
        assert_eq!(response.subject, Some(ip("10.0.0.30")));
        assert_eq!(response.hostname, None);
    }

    /// A reverse name is read as strictly as it is written, so one address has
    /// one name. `str::parse::<u8>` takes a leading `+` and leading zeros.
    #[test]
    fn a_reverse_name_is_read_only_as_it_would_be_written() {
        let address = ip("192.0.2.1");
        assert_eq!(
            address_from_pointer_name(&reverse_pointer_name(address)),
            Some(address)
        );

        for spelling in [
            "001.002.000.192.in-addr.arpa",
            "+1.2.0.192.in-addr.arpa",
            "1.2.0.0192.in-addr.arpa",
            "01.2.0.192.in-addr.arpa",
        ] {
            assert_eq!(
                address_from_pointer_name(spelling),
                None,
                "{spelling} is not a name this writes"
            );
        }

        // Zero is still an octet, and its one spelling is a single digit.
        assert_eq!(
            address_from_pointer_name("1.113.0.203.in-addr.arpa"),
            Some(ip("203.0.113.1"))
        );
    }

    /// Sniffed traffic is mostly forward lookups, which parse fine and concern no
    /// address.
    #[test]
    fn a_forward_lookup_concerns_no_address() {
        let mut bytes = build_query(1, true, &[("example.com", record_type::A)]).unwrap();
        bytes[2] |= 0x80; // flip QR: this is now a response

        let response = parse_ptr_response(&bytes).unwrap();
        assert_eq!(response.subject, None);
        assert_eq!(response.hostname, None);
    }

    #[test]
    fn a_query_is_not_a_response() {
        let query = build_ptr_packet(ip("203.0.113.1"), 9);
        assert!(parse_ptr_response(&query).is_err());
    }

    #[test]
    fn bytes_that_are_not_dns_are_rejected() {
        assert!(parse_ptr_response(b"not dns").is_err());
    }

    /// Builds a PTR response by hand. [`build_query`] writes only questions, and
    /// these tests need answers to read back.
    pub(crate) fn ptr_response(id: u16, question: &str, answer: Option<&str>) -> Vec<u8> {
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
