// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Multicast DNS
//!
//! Reads the hosts an mDNS message names.
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

use anyhow::{Context, Result};
use dns_parser::{Packet, RData};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};

use crate::protocols::dns;

/// One host as an mDNS message described it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MdnsHost {
    /// The name the host answers to, without its trailing dot.
    pub hostname: String,
    /// Every address the message gave for that name.
    pub ips: HashSet<IpAddr>,
}

/// Reads every host an mDNS message names, in name order.
///
/// A message that names none - a query, or a response carrying only service
/// records - yields an empty list rather than an error. Only bytes that are not
/// a DNS message at all are rejected.
pub fn extract_hosts(data: &[u8]) -> Result<Vec<MdnsHost>> {
    let packet = Packet::parse(data).context("not a parseable mDNS message")?;
    let mut by_hostname: BTreeMap<String, HashSet<IpAddr>> = BTreeMap::new();

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

fn owner_name(name: &dns_parser::Name<'_>) -> String {
    trim_root(&name.to_string())
}

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
                ips: HashSet::from(["192.168.0.150".parse().unwrap(), "fe80::1".parse().unwrap()]),
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
                ips: HashSet::from(["192.168.0.150".parse().unwrap()]),
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
                    ips: HashSet::from(["192.168.0.40".parse().unwrap()]),
                },
                MdnsHost {
                    hostname: "printer.local".to_string(),
                    ips: HashSet::from(["192.168.0.30".parse().unwrap()]),
                },
            ]
        );
    }

    #[test]
    fn bytes_that_are_not_dns_are_rejected() {
        assert!(extract_hosts(b"not dns").is_err());
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
}
