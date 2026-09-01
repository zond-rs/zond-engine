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
use crate::protocols::dns;

/// Where a name server answers. The rest of the vocabulary a role is read from
/// lives beside each protocol's own parser.
const DNS: u16 = 53;

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
/// **The port is which question to ask, never the answer.** UDP/53 open means
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
