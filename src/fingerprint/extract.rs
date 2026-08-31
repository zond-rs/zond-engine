// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Turning a response into the text the corpus is written against
//!
//! A signature matches a field, not a reply. Every rule declares the
//! `context` it reads, `ssh.banner`, `snmp.sys_description`,
//! `http.server_header`, and anchors its pattern on that field's text alone.
//! Something has to produce that field from what actually arrived, and this is
//! where that happens.
//!
//! ## The mistake this module exists to stop repeating
//!
//! It has been made twice, silently, and cost a working corpus both times.
//!
//! RFC 4253 §4.2 gives an SSH identification line as
//! `SSH-protoversion-softwareversion SP comments`, and the corpus anchors on
//! the software identifier: `^OpenSSH_(9\.2p1) (Debian-\d\d?\+deb12u\d+)$`. Fed
//! the whole line, that `^` can never match, so **every release-naming SSH rule
//! was unreachable**, and a host announcing `SSH-2.0-OpenSSH_9.2p1
//! Debian-2+deb12u10` was reported as `Linux` while the corpus held a rule
//! mapping that exact string to Debian 12.
//!
//! SNMP is the same shape one protocol over: `sysDescr` is a BER-encoded octet
//! string inside a `GetResponse`, and the rules match the decoded text. A
//! datagram handed to them matches nothing.
//!
//! Both failures look identical from outside, a scan that names a family and
//! stops, and neither shows up as a broken test, because a test that feeds the
//! matcher a field directly passes while the engine feeds it a whole response.
//!
//! ## Keyed on the port, because that is what is known
//!
//! [`from_datagram`] selects a decoder by destination port, exactly as
//! [`payload`](crate::scanner::payload) selects a probe by one. It is the only
//! thing known about a UDP target before anything answers, which is the whole
//! difficulty of UDP scanning, and pairing the two on the same key keeps the
//! probe and the reading of its answer from drifting apart.

use crate::model::port::Protocol;

/// The texts one banner should be matched against, most complete first.
///
/// Usually just the banner. A structured one also yields the field the corpus
/// anchors on, and **both are offered** rather than the field replacing the
/// line: a rule may legitimately be written against either, and which is more
/// specific is a question for the matcher's own ranking rather than for this.
pub(crate) fn texts(banner: &str) -> Vec<&str> {
    let mut texts = vec![banner];
    texts.extend(super::ssh::software_version(banner));
    texts
}

/// The text a UDP reply carries, where this engine knows how to read one.
///
/// `None` for a port whose replies it cannot decode, which is most of them: a
/// datagram nothing can read is still proof the port is open, and that is what
/// the scan already took from it.
///
/// Returns an owned string because decoding is not always a borrow, a value
/// lifted out of a binary encoding has no text in the datagram to point at.
pub(crate) fn from_datagram(port: u16, datagram: &[u8]) -> Option<String> {
    match port {
        // The one field worth a decoder: on a Unix host `sysDescr` is the output
        // of `uname -a`, which names the exact kernel. See [`snmp`](super::snmp).
        161 => super::snmp::sys_descr(datagram).map(ToOwned::to_owned),
        _ => None,
    }
}

/// Whether this engine can read a reply from `port` over `protocol` at all.
///
/// What decides whether a UDP port is worth a second datagram: there is no
/// point dialling one whose answer nothing here could turn into text. A TCP
/// port always qualifies, every one of them can be read for a banner.
pub(crate) fn reads(port: u16, protocol: Protocol) -> bool {
    match protocol {
        Protocol::Tcp => true,
        Protocol::Udp => DECODED_UDP_PORTS.contains(&port),
    }
}

/// What kind of text a reply from `port` over `protocol` is, for weighing what a
/// rule matched against it says about the *host*.
///
/// Almost everything a scan reads is a banner: a string a daemon carries from
/// its own build, which is why [`ceiling`](super::os::ceiling) holds it below a
/// stack reading. SNMP is the exception this exists for, `sysDescr` is the
/// machine's management agent describing the machine, and it is keyed on the
/// same port [`from_datagram`] decodes, so the decoder and the weight put on
/// what it decodes cannot drift apart.
pub(crate) fn attested_by(port: u16, protocol: Protocol) -> crate::model::host::OsSource {
    match (protocol, port) {
        (Protocol::Udp, 161) => crate::model::host::OsSource::SnmpAgent,
        _ => crate::model::host::OsSource::ServiceBanner,
    }
}

/// The UDP ports [`from_datagram`] has a decoder for.
///
/// Stated rather than derived, because a decoder cannot be asked whether it
/// would succeed without a datagram to try it on, and this question is asked
/// before one has been drawn.
const DECODED_UDP_PORTS: &[u16] = &[161];

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

    /// The whole line and the field, both offered, because a rule may be
    /// written against either and only the matcher can say which fits better.
    #[test]
    fn a_structured_banner_offers_its_field_as_well_as_itself() {
        let texts = texts("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10");
        assert_eq!(
            texts,
            [
                "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10",
                "OpenSSH_9.2p1 Debian-2+deb12u10",
            ]
        );
    }

    /// An unstructured one offers itself and nothing else, rather than a second
    /// text that would only cost the matcher a pass.
    #[test]
    fn an_ordinary_banner_offers_only_itself() {
        assert_eq!(
            texts("220 mail.example ESMTP Postfix"),
            ["220 mail.example ESMTP Postfix"]
        );
    }

    /// A port with no decoder yields nothing rather than the datagram as text.
    /// A reply nothing can read is still proof the port is open, which is what
    /// the scan already took from it.
    #[test]
    fn a_datagram_from_an_unreadable_port_yields_nothing() {
        assert_eq!(from_datagram(9_999, b"anything at all"), None);
        assert!(!reads(9_999, Protocol::Udp));
    }

    /// Every port the corpus sends a UDP probe to has a decoder for the answer,
    /// or is named here as one that does not.
    ///
    /// The two lists are authored in different places for different reasons.
    /// `assets/fingerprinting` says what to send, [`DECODED_UDP_PORTS`] says what
    /// can be read back, and nothing but this connects them: a UDP probe
    /// authored for a port with no decoder draws a reply the fingerprinter
    /// throws away, and the only symptom is a service that is never identified.
    ///
    /// The sibling test on the service side
    /// (`every_port_with_a_signature_is_a_port_the_default_scan_reaches`) holds
    /// the same kind of join and is what this is modelled on.
    #[test]
    fn a_udp_probe_either_has_a_decoder_or_is_listed_as_having_none() {
        use crate::fingerprint::SignatureDb;

        /// Ports the corpus probes over UDP for *liveness* rather than for
        /// identification. A UDP probe is what establishes the port is open at
        /// all, since UDP offers no handshake to infer it from, so a probe here
        /// earns its place without a decoder. Each entry is a decoder somebody
        /// could write.
        const PROBED_BUT_NOT_DECODED: &[u16] = &[53, 123, 137, 1900, 5353];

        let db = SignatureDb::global();
        let probed: Vec<u16> = (0..=u16::MAX)
            .filter(|port| !db.udp_probe_payloads(*port).is_empty())
            .collect();

        for port in &probed {
            assert!(
                DECODED_UDP_PORTS.contains(port) || PROBED_BUT_NOT_DECODED.contains(port),
                "the corpus sends a UDP probe to {port} and nothing here reads the \
                 answer. Write a decoder in `from_datagram`, or list the port in \
                 PROBED_BUT_NOT_DECODED to say the probe is for liveness alone."
            );
        }

        for port in DECODED_UDP_PORTS {
            assert!(
                probed.contains(port),
                "there is a decoder for {port} and the corpus sends it nothing, so \
                 the decoder can never run"
            );
        }
        for port in PROBED_BUT_NOT_DECODED {
            assert!(
                probed.contains(port),
                "{port} is listed as probed without a decoder and is not probed"
            );
        }
    }

    /// And a port that has one is worth the second datagram it costs.
    #[test]
    fn a_port_with_a_decoder_is_worth_dialling() {
        assert!(reads(161, Protocol::Udp));
        assert!(
            reads(22, Protocol::Tcp),
            "every TCP port can be read for a banner"
        );
        assert!(!reads(53, Protocol::Udp), "no decoder for a DNS reply yet");
    }
}
