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

use crate::fingerprinting::SignatureDb;

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
