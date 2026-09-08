// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # UDP Probe Payloads
//!
//! What to put *inside* a UDP probe so that the service on the other side has
//! a reason to answer it.
//!
//! ## Why an empty datagram is not enough
//!
//! A TCP scanner gets an answer for free: the handshake is part of the
//! transport, so a SYN is answered by a stack that knows nothing about the
//! service above it. UDP has no such layer. An open port answers only if the
//! *application* recognizes what arrived, and an application handed zero bytes
//! almost always discards them without a word.
//!
//! So a payload-free UDP scan can only ever observe the ICMP half - closed
//! ports - while every genuinely open port falls to the deadline and reports
//! [`OpenFiltered`](crate::model::port::PortState::OpenFiltered). That
//! is a correct verdict for what was asked, and a nearly useless one. Sending
//! something a service will recognize is what turns "no evidence" into
//! evidence.
//!
//! ## Where the payloads live
//!
//! In the fingerprint corpus, `assets/fingerprinting/**/*.toml`, as
//! `protocol = "udp"` entries beside each service's match rules - not in a
//! table of their own.
//!
//! They are the same artifact. A scan payload has to elicit *any* reply; a
//! fingerprint probe has to elicit a *distinguishing* one; and for these
//! services that is one packet, authored once. Keeping them together means
//! adding support for a protocol is one file rather than two, the corpus's
//! build-time validation covers them (`build.rs` rejects a malformed payload
//! outright), and - the part that matters next - the reply a probe draws is
//! already sitting next to the rules that could identify it. A `version.bind`
//! response carries the BIND version string; today the scan counts it as
//! evidence the port is open and discards it.
//!
//! This module is the seam. Scanners ask it what to send, and it answers from
//! the corpus, so the "which payload for this port" policy has one home and the
//! scanners keep no protocol knowledge of their own.
//!
//! ## And what an answer proves
//!
//! [`declared_role`] is the same seam read in the other direction. A reply is
//! already counted as evidence the port is open; for a handful of ports it is
//! also proof of what the host *is*, and that proof is in the reply's own
//! protocol rather than in the port number it came from. Both scanners that
//! send UDP probes, the raw one and the unprivileged fallback, ask here, so a
//! scan concludes the same roles whichever transport it had available.

use crate::fingerprint::SignatureDb;
use crate::model::host::NetworkRole;
use crate::protocols::{dns, netbios};

/// Where a name server answers. The rest of the vocabulary a role is read from
/// lives beside each protocol's own parser.
const DNS: u16 = 53;

/// Where the NetBIOS name service answers, and where a Windows machine lists
/// every name it has registered.
const NETBIOS_NS: u16 = 137;

/// The payload to send when probing `port`.
///
/// Returns an empty slice for a port no service registers a UDP probe for. The
/// scan still works there - a closed port answers with an ICMP error either
/// way - but an open one has nothing to react to and can only ever be reported
/// open-filtered.
///
/// Keyed on the destination port alone, because it is the only thing known
/// about a target before anything answers, which is the whole difficulty of UDP
/// scanning. Where a port registers several probes the first is used: sending
/// all of them would multiply the traffic for a question already answered by
/// any single reply.
pub fn for_port(port: u16) -> &'static [u8] {
    SignatureDb::global()
        .udp_probe_payloads(port)
        .first()
        .map_or(&[], Vec::as_slice)
}

/// What a reply to the probe for `port` proves the host *does*, if its own
/// protocol says so.
///
/// The port is which question to ask, never the answer. UDP/53 open means
/// something is bound there; a DNS response means a name server answered. The
/// first is a port verdict and already recorded as one, and promoting it to a
/// role would put an infrastructure marking on every host with a socket open.
///
/// One arm per role, and the arms that are missing are missing on purpose.
/// [`NtpServer`](NetworkRole::NtpServer) and [`SnmpAgent`](NetworkRole::SnmpAgent)
/// have probes in the corpus already, 123 and 161 are both sent, so each is
/// one validated reply away from being concluded here, and neither is concluded
/// until that reply is actually read.
pub fn declared_role(port: u16, reply: &[u8]) -> Option<NetworkRole> {
    match port {
        DNS => dns::is_response(reply).then_some(NetworkRole::DnsServer),
        // The name table names the machine's part in a domain. See
        // [`netbios::NameTable::domain_controller`] for which suffixes say so
        // and why the others do not.
        NETBIOS_NS => netbios::node_status(reply)
            .is_some_and(|table| table.domain_controller())
            .then_some(NetworkRole::DomainController),
        _ => None,
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

    /// Where a time server answers, and where its own account of itself comes
    /// back only to a second kind of question.
    const NTP: u16 = 123;

    /// Where an L2TP concentrator answers, and where asking the same thing
    /// twice gets an acknowledgement the second time.
    const L2TP: u16 = 1701;

    /// The ports the shipped corpus is expected to carry a UDP probe for.
    ///
    /// Asserting the list rather than reading it back from the corpus is the
    /// point: these are the ports the scanner can report `Open` on, so losing
    /// one to an editing accident is a silent regression in coverage, not a
    /// test that quietly adjusts to it.
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

    /// The engine's own question with the QR bit set: what a name server sends
    /// back, built from the probe so the test cannot drift from what is asked.
    fn dns_response() -> Vec<u8> {
        let mut message = for_port(DNS).to_vec();
        message[2] |= 0b1000_0000;
        message
    }

    /// A role is read from the reply, and the port only decides which question
    /// to ask of it.
    ///
    /// Two of the three cases here are the ones that would put the marking on a
    /// host that never earned it. **Our own probe echoed back** is a query, not
    /// an answer, and a reflector or a proxy that returns it must not be read as
    /// a name server. **A DNS message on 5353** is mDNS, which nearly every
    /// laptop and printer on a segment speaks: sharing DNS's framing does not
    /// make a responder a nameserver, and reading it as one would put the role
    /// on half a network.
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

    /// A node-status answer listing the domain controllers group, in the layout
    /// a responder writes it. Built here rather than imported so this test is
    /// about what `declared_role` concludes and not about the parser's fixtures.
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

    /// The same standard the DNS arm is held to, one protocol over: the name
    /// table is the evidence, and an open 137 is not.
    ///
    /// The third case is the one that matters most. A workstation answers this
    /// probe as readily as a controller does, with a table that is the
    /// same shape and says something else entirely, so a role read from the
    /// reply arriving rather than from what it holds would mark every Windows
    /// machine on a segment as running the domain.
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

    /// NTP registers two probes, and which is first matters.
    ///
    /// A port scan sends one datagram and stops, so the first probe has to be
    /// the one a daemon is most likely to answer: an ordinary client request,
    /// which every server replies to. The control message is the second, and
    /// the service pass is what asks it, because many daemons carry `noquery`
    /// and would leave the port looking filtered if it were asked first.
    ///
    /// This is the pairing a scan of a real ntpd showed was wrong. The service
    /// pass took `first` and stopped, so the control message never went out and
    /// the rules that had just been given a decoder still read nothing.
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
    /// The protocol remembers. A concentrator answers a repeat of a tunnel
    /// request with a zero-length acknowledgement rather than with its own name,
    /// and a scan sends this port a probe twice: once to establish it is open,
    /// once to identify it. The second request exists so the identification pass
    /// has one the concentrator has not seen.
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

    /// Probes go to one port at a time, so a payload big enough to fragment
    /// costs more than the single reply it can return.
    #[test]
    fn payloads_fit_in_one_datagram() {
        for &port in EXPECTED {
            assert!(
                for_port(port).len() < 512,
                "port {port} payload is oversized"
            );
        }
    }

    /// The escapes authored in TOML have to survive the build as raw bytes. A
    /// payload that arrived at the wire still spelled `\x30` would be discarded
    /// by every target, and the scan would read it back as silence.
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

    /// mDNS is a separate service definition that reuses the DNS question, so
    /// the two ports must resolve to the same bytes. If they ever diverge it
    /// should be a deliberate edit, not a copy that drifted.
    #[test]
    fn mdns_reuses_the_dns_question() {
        assert_eq!(for_port(5353), for_port(53));
    }
}
