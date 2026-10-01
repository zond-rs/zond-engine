// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # UDP Probe Payloads
//!
//! What to put inside a UDP probe so the service on the other side has a reason
//! to answer.
//!
//! An open UDP port answers only if the application recognizes what arrived, and
//! most discard an empty datagram silently. A payload-free scan sees only the
//! ICMP errors from closed ports; every open one times out as
//! [`OpenOrNoReply`](crate::model::port::PortState::OpenOrNoReply).
//!
//! ## Where the payloads live
//!
//! In the fingerprint corpus, `assets/fingerprinting/**/*.toml`, as
//! `protocol = "udp"` entries beside each service's match rules. A scan payload
//! and a fingerprint probe are the same packet for these services, so adding a
//! protocol is one file, `build.rs` validates the payloads with the rest of the
//! corpus, and the reply a probe draws sits next to the rules that could
//! identify it.
//!
//! Scanners ask this module what to send, so the payload-per-port policy has one
//! home and the scanners carry no protocol knowledge.
//!
//! ## What an answer proves
//!
//! [`declared_role`] and [`declared_names`] read the reply. For a few ports the
//! reply's own protocol proves what the host is. The raw UDP scanner and the
//! unprivileged fallback both ask here, so a scan concludes the same roles on
//! either transport.

use crate::fingerprint::SignatureDb;
use crate::model::host::{HostName, NameKind, NameSource, NetworkRole};
use crate::protocols::{dns, netbios};

/// The DNS port.
const DNS: u16 = 53;

/// The NetBIOS name service port, where a Windows machine lists every name it
/// has registered.
const NETBIOS_NS: u16 = 137;

/// The payload to send when probing `port`.
///
/// Returns an empty slice for a port with no registered UDP probe. A closed port
/// there still answers with an ICMP error, but an open one can only be reported
/// `OpenOrNoReply`.
///
/// Keyed on the destination port alone, the only thing known before anything
/// answers. Where a port registers several probes the first is used, since any
/// single reply answers the question.
pub fn for_port(port: u16) -> &'static [u8] {
    SignatureDb::global()
        .udp_probe_payloads(port)
        .first()
        .map_or(&[], Vec::as_slice)
}

/// What a reply to the probe for `port` proves the host *does*, if its own
/// protocol says so.
///
/// The port only picks which parser reads the reply. An open UDP/53 is a port
/// verdict; only a DNS response makes the host a name server.
///
/// [`NtpServer`](NetworkRole::NtpServer) and [`SnmpAgent`](NetworkRole::SnmpAgent)
/// have no arm yet: their probes are sent, but their replies are not parsed for
/// a role.
pub fn declared_role(port: u16, reply: &[u8]) -> Option<NetworkRole> {
    match port {
        DNS => dns::is_response(reply).then_some(NetworkRole::DnsServer),
        // See `netbios::NameTable::domain_controller` for which suffixes count.
        NETBIOS_NS => netbios::node_status(reply)
            .is_some_and(|table| table.domain_controller())
            .then_some(NetworkRole::DomainController),
        _ => None,
    }
}

/// The names a reply to the probe for `port` gives for the host, where its
/// protocol states any.
///
/// The counterpart to [`declared_role`]. Only a NetBIOS name table states names:
/// the machine's workstation name and the domain or workgroup it joined (see
/// [`netbios::NameTable::workstation`] for how the group bit separates them).
///
/// Returned separately from the port's text because host names are masked in a
/// report on request and port text is not.
pub(crate) fn declared_names(port: u16, reply: &[u8]) -> Vec<HostName> {
    match port {
        NETBIOS_NS => netbios::node_status(reply)
            .map(|table| {
                [
                    (NameKind::NetbiosHost, table.workstation()),
                    (NameKind::NetbiosDomain, table.domain()),
                ]
                .into_iter()
                .filter_map(|(kind, name)| HostName::new(kind, NameSource::Netbios, name?))
                .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
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

    /// NTP, which describes itself only in answer to a second kind of probe.
    const NTP: u16 = 123;

    /// L2TP, where a repeated request draws only an acknowledgement.
    const L2TP: u16 = 1701;

    /// The ports the shipped corpus is expected to carry a UDP probe for.
    ///
    /// Listed by hand so that a probe lost from the corpus fails this test; these
    /// are the ports a UDP scan can report `Open` on.
    const EXPECTED: &[u16] = &[53, 123, 137, 161, 1900, 5353];

    #[test]
    fn every_expected_port_has_a_payload() {
        for &port in EXPECTED {
            assert!(
                !for_port(port).is_empty(),
                "port {port} lost its UDP probe from the corpus"
            );
        }
    }

    /// The engine's own query with the QR bit set, as a name server returns it.
    fn dns_response() -> Vec<u8> {
        let mut message = for_port(DNS).to_vec();
        message[2] |= 0b1000_0000;
        message
    }

    /// The role comes from the reply. Our own query echoed back by a reflector is
    /// not an answer, and a DNS message on 5353 is mDNS, which nearly every laptop
    /// and printer speaks.
    #[test]
    fn a_role_is_read_from_the_reply_and_not_from_the_port() {
        assert_eq!(
            declared_role(DNS, &dns_response()),
            Some(NetworkRole::DnsServer)
        );

        assert_eq!(
            declared_role(DNS, for_port(DNS)),
            None,
            "a query is not an answer"
        );
        assert_eq!(declared_role(DNS, b"not a dns message at all"), None);
        assert_eq!(declared_role(DNS, &[]), None);

        assert_eq!(
            declared_role(5353, &dns_response()),
            None,
            "an mDNS responder is not a name server"
        );
    }

    /// A node-status answer listing the domain controllers group, built here so
    /// the test does not depend on the parser's fixtures.
    fn node_status_from_a_controller() -> Vec<u8> {
        let mut out = vec![0x80, 0xf0, 0x84, 0x00];
        out.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&[0u8; 4]); // NSCOUNT, ARCOUNT
        out.push(0x20);
        out.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        out.push(0x00);
        out.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // NBSTAT, IN
        out.extend_from_slice(&0u32.to_be_bytes()); // TTL
        out.extend_from_slice(&(1u16 + 18 + 46).to_be_bytes()); // RDLENGTH

        out.push(1); // one name
        out.extend_from_slice(b"CORP           ");
        out.push(0x1C); // the domain controllers group
        out.extend_from_slice(&0x8000u16.to_be_bytes()); // registered as a group
        out.extend_from_slice(&[0u8; 46]); // statistics
        out
    }

    /// The name table is the evidence, not an open 137. A workstation answers
    /// with a table of the same shape, and must not be marked a controller.
    #[test]
    fn a_name_table_names_a_controller_and_a_workstation_is_not_one() {
        assert_eq!(
            declared_role(NETBIOS_NS, &node_status_from_a_controller()),
            Some(NetworkRole::DomainController)
        );

        assert_eq!(
            declared_role(NETBIOS_NS, for_port(NETBIOS_NS)),
            None,
            "our own query echoed back is not a name table"
        );

        let mut workstation = node_status_from_a_controller();
        let suffix = 12 + 34 + 10 + 1 + 15;
        workstation[suffix] = 0x00; // the workstation service
        assert_eq!(
            declared_role(NETBIOS_NS, &workstation),
            None,
            "an ordinary domain member is not a controller"
        );

        assert_eq!(declared_role(NETBIOS_NS, b"not netbios at all"), None);
        assert_eq!(declared_role(NETBIOS_NS, &[]), None);
    }

    /// The machine is named by its workstation name and the workgroup by the
    /// group under the same suffix; other entries add nothing. Anything but a
    /// name table names nothing.
    #[test]
    fn a_name_table_names_the_machine_and_the_workgroup_it_joined() {
        use crate::protocols::netbios::tests::response;

        let table = response(&[
            ("FILESERVER", 0x00, false),
            ("FILESERVER", 0x20, false),
            ("EXAMPLEGRP", 0x00, true),
            ("EXAMPLEGRP", 0x1E, true),
        ]);
        let names: Vec<_> = declared_names(NETBIOS_NS, &table)
            .into_iter()
            .map(|name| (name.kind(), name.source(), name.name().to_owned()))
            .collect();
        assert_eq!(
            names,
            [
                (
                    NameKind::NetbiosHost,
                    NameSource::Netbios,
                    "FILESERVER".to_owned()
                ),
                (
                    NameKind::NetbiosDomain,
                    NameSource::Netbios,
                    "EXAMPLEGRP".to_owned()
                ),
            ]
        );

        assert!(declared_names(NETBIOS_NS, for_port(NETBIOS_NS)).is_empty());
        assert!(declared_names(NETBIOS_NS, b"not netbios at all").is_empty());
        assert!(declared_names(53, &table).is_empty(), "keyed on the port");
    }

    /// NTP registers two probes, and the order matters. A port scan sends only
    /// the first, so it is the client request every server answers. The control
    /// message comes second for the service pass, since many daemons carry
    /// `noquery` and ignore it.
    #[test]
    fn ntp_registers_a_client_request_first_and_a_control_message_behind_it() {
        const MODE: u8 = 0b0000_0111;
        const MODE_CLIENT: u8 = 3;
        const MODE_CONTROL: u8 = 6;

        let payloads = SignatureDb::global().udp_probe_payloads(NTP);
        assert_eq!(
            payloads.len(),
            2,
            "NTP registers a client and a control probe"
        );

        assert_eq!(
            payloads[0][0] & MODE,
            MODE_CLIENT,
            "the port scan sends the first probe and needs the one every server answers"
        );
        assert!(
            payloads
                .iter()
                .any(|payload| payload[0] & MODE == MODE_CONTROL),
            "the control message is what the readvar rules were written for"
        );
    }

    /// L2TP registers two requests that differ only in the tunnel they name.
    ///
    /// A concentrator answers a repeated tunnel request with a zero-length
    /// acknowledgement. A scan probes the port twice (open, then identify), so
    /// the identification pass needs a request the concentrator has not seen.
    #[test]
    fn l2tp_registers_two_requests_naming_different_tunnels() {
        let payloads = SignatureDb::global().udp_probe_payloads(L2TP);
        assert_eq!(payloads.len(), 2, "L2TP registers a second tunnel request");

        let tunnel = |payload: &Vec<u8>| payload[payload.len() - 2..].to_vec();
        assert_ne!(
            tunnel(&payloads[0]),
            tunnel(&payloads[1]),
            "both requests name the same tunnel, so the second draws only an acknowledgement"
        );
    }

    #[test]
    fn a_port_with_no_probe_yields_an_empty_payload() {
        assert!(for_port(9_999).is_empty());
    }

    /// A payload big enough to fragment costs more than the one reply it can
    /// return.
    #[test]
    fn payloads_fit_in_one_datagram() {
        for &port in EXPECTED {
            assert!(
                for_port(port).len() < 512,
                "port {port} payload is oversized"
            );
        }
    }

    /// Escapes authored in TOML must reach the wire as raw bytes; a literal
    /// `\x30` would be ignored by every target and read back as silence.
    #[test]
    fn payloads_are_decoded_to_wire_bytes() {
        let snmp = for_port(161);
        assert_eq!(snmp[0], 0x30, "SNMP must start with a BER SEQUENCE tag");
        assert!(
            !snmp.starts_with(b"\\x"),
            "escapes reached the wire undecoded"
        );

        let dns = for_port(53);
        assert!(
            dns.windows(7).any(|w| w == b"version"),
            "DNS payload lost its QNAME"
        );
    }

    /// mDNS is a separate service definition that reuses the DNS question.
    #[test]
    fn mdns_reuses_the_dns_question() {
        assert_eq!(for_port(5353), for_port(53));
    }
}
