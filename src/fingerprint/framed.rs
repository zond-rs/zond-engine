// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Replies that carry text behind a few bytes of framing
//!
//! A group of UDP services answer with something a signature can read directly,
//! wrapped in a header that a regex cannot see past. The SQL Server Browser puts
//! three bytes in front of its instance list; memcached over UDP puts eight in
//! front of the same `VERSION` line it sends over TCP. Handing the matcher the
//! datagram reaches none of the rules, and handing it nothing loses a service
//! that named itself.
//!
//! Each reader here takes a datagram and hands back the text inside it, or
//! [`None`] where the datagram is not the reply it was written for.
//! [`from_datagram`](super::extract::from_datagram) is what pairs each with its
//! port.
//!
//! These are readers, not decoders. Nothing here parses a protocol further than
//! finding where its text begins and ends: a service whose answer needs real
//! decoding, an SNMP varbind or a DNS answer section, has a module of its own.

/// The reply's length as the SQL Server Browser states it, and the header that
/// precedes the instance list.
const BROWSER_HEADER_BYTES: usize = 3;

/// What the Browser puts in the first byte of a response.
const BROWSER_SVR_RESP: u8 = 0x05;

/// The frame memcached wraps a UDP request and its reply in: a request id, a
/// sequence number, a datagram count, and two reserved bytes.
const MEMCACHED_FRAME_BYTES: usize = 8;

/// The instance list a SQL Server Browser answers with.
///
/// The response is `0x05`, a little-endian length, and then a semicolon-delimited
/// list naming every instance the host runs:
///
/// ```text
/// ServerName;WIN-DB01;InstanceName;SQLEXPRESS;IsClustered;No;Version;15.0.2000.5;tcp;1433;;
/// ```
///
/// Worth more than the version it carries. `tcp;1433` is the port that instance
/// actually listens on, and a named instance is very often not on 1433 at all,
/// so this answers a question a port scan would otherwise have to guess at.
///
/// [`None`] for a datagram that is not a Browser response, or whose stated
/// length disagrees with the bytes that follow it.
#[must_use]
pub(super) fn sql_server_browser(datagram: &[u8]) -> Option<&str> {
    if *datagram.first()? != BROWSER_SVR_RESP {
        return None;
    }
    let stated = u16::from_le_bytes([*datagram.get(1)?, *datagram.get(2)?]) as usize;
    let body = datagram.get(BROWSER_HEADER_BYTES..)?;

    // A length longer than the datagram is a truncated reply rather than a
    // malicious one, since the Browser sends a single datagram. Read what
    // arrived.
    let body = body.get(..stated.min(body.len()))?;
    std::str::from_utf8(body).ok().map(str::trim_end)
}

/// The command response inside a memcached UDP frame.
///
/// The frame is eight bytes and the rest is what the same command returns over
/// TCP, so the corpus rule written for the TCP banner reads this
/// unchanged.
///
/// [`None`] for a datagram too short to hold the frame, or whose body is not
/// text.
#[must_use]
pub(super) fn memcached_udp(datagram: &[u8]) -> Option<&str> {
    let body = datagram.get(MEMCACHED_FRAME_BYTES..)?;
    let body = std::str::from_utf8(body).ok()?.trim();

    (!body.is_empty()).then_some(body)
}

/// The device types a WS-Discovery responder claims.
///
/// A `ProbeMatches` reply is SOAP, and the element worth reading is `Types`: a
/// space-separated list of qualified names saying what kind of thing answered.
/// A Windows machine says `Device Computer`, a printer says `PrintDeviceType`,
/// and a camera says `NetworkVideoTransmitter`.
///
/// The namespace prefixes are stripped, because a responder picks its own and
/// two devices of the same kind will not agree on them. `wsdp:Device
/// pub:Computer` and `a:Device b:Computer` both read as `Device Computer`, which
/// is what a rule can be written against.
///
/// [`None`] where the reply carries no such element. Nothing here parses XML
/// further than one element's text.
#[must_use]
pub(super) fn wsd_types(datagram: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(datagram).ok()?;
    let inner = element_text(text, "Types")?;

    let types: Vec<&str> = inner
        .split_whitespace()
        .map(|name| name.rsplit(':').next().unwrap_or(name))
        .filter(|name| !name.is_empty())
        .collect();

    (!types.is_empty()).then(|| types.join(" "))
}

/// The text of the first `<...:name>` element in `xml`, whatever prefix it
/// carries.
///
/// Enough for reading one known element out of a small SOAP message, and no more
/// than that: it does not resolve namespaces, handle CDATA, or decode entities.
fn element_text<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let mut search = xml;
    loop {
        let at = search.find('<')?;
        let rest = &search[at + 1..];
        let close = rest.find('>')?;
        let tag = &rest[..close];

        let bare = tag.rsplit(':').next().unwrap_or(tag);
        if bare.trim_end_matches('/') == name && !tag.starts_with('/') {
            let body = &rest[close + 1..];
            let end = body.find('<')?;
            let text = body[..end].trim();
            return (!text.is_empty()).then_some(text);
        }
        search = &rest[close..];
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

    /// Builds a Browser response carrying `body`, with the length it states.
    fn browser(body: &str) -> Vec<u8> {
        let mut out = vec![BROWSER_SVR_RESP];
        out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        out.extend_from_slice(body.as_bytes());
        out
    }

    const INSTANCES: &str = "ServerName;WIN-DB01;InstanceName;SQLEXPRESS;IsClustered;No;\
                             Version;15.0.2000.5;tcp;1433;;";

    #[test]
    fn a_browser_response_yields_its_instance_list() {
        assert_eq!(sql_server_browser(&browser(INSTANCES)), Some(INSTANCES));
    }

    /// The Browser answers one datagram, so a stated length past its end is a
    /// truncated reply. What arrived is still read.
    #[test]
    fn a_length_past_the_datagram_reads_what_arrived() {
        let mut short = browser(INSTANCES);
        short.truncate(3 + 20);
        assert_eq!(sql_server_browser(&short), Some("ServerName;WIN-DB01;"));
    }

    #[test]
    fn anything_that_is_not_a_browser_response_yields_nothing() {
        assert!(sql_server_browser(b"").is_none());
        assert!(sql_server_browser(b"\x02").is_none());
        assert!(sql_server_browser(b"\x05\x10").is_none());
        assert!(sql_server_browser(&[0x05, 0x02, 0x00, 0xff, 0xfe]).is_none());
    }

    #[test]
    fn a_memcached_frame_yields_the_line_inside_it() {
        let packet = b"\x00\x01\x00\x00\x00\x01\x00\x00VERSION 1.6.21\r\n";
        assert_eq!(memcached_udp(packet), Some("VERSION 1.6.21"));
    }

    #[test]
    fn a_datagram_shorter_than_the_frame_yields_nothing() {
        assert!(memcached_udp(b"\x00\x01\x00\x00").is_none());
        assert!(memcached_udp(b"\x00\x01\x00\x00\x00\x01\x00\x00").is_none());
    }

    /// What a Windows machine answers a Probe with, cut to the element that is
    /// read. Two different prefixes for the same two types, which is the case
    /// stripping them exists for.
    #[test]
    fn a_probe_match_yields_its_types_without_prefixes() {
        let reply = r#"<?xml version="1.0"?><s:Envelope><s:Body><d:ProbeMatches>
            <d:ProbeMatch><a:EndpointReference/><d:Types>wsdp:Device pub:Computer</d:Types>
            </d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"#;
        assert_eq!(
            wsd_types(reply.as_bytes()).as_deref(),
            Some("Device Computer")
        );
    }

    #[test]
    fn a_printer_answers_with_its_own_type() {
        let reply = "<d:ProbeMatches><d:Types>print:PrintDeviceType</d:Types></d:ProbeMatches>";
        assert_eq!(
            wsd_types(reply.as_bytes()).as_deref(),
            Some("PrintDeviceType")
        );
    }

    #[test]
    fn a_reply_naming_no_types_yields_nothing() {
        assert!(wsd_types(b"<d:ProbeMatches></d:ProbeMatches>").is_none());
        assert!(wsd_types(b"not xml at all").is_none());
        assert!(wsd_types(b"").is_none());
        assert!(wsd_types(b"<d:Types></d:Types>").is_none());
    }

    /// Anything at all, without panicking. Each of these reads a datagram from
    /// an unauthenticated stranger.
    #[test]
    fn arbitrary_bytes_are_refused_rather_than_read() {
        for bytes in [
            &b""[..],
            &[0xff; 64][..],
            &[0x05, 0xff, 0xff][..],
            &[0x3c; 200][..],
        ] {
            let _ = sql_server_browser(bytes);
            let _ = memcached_udp(bytes);
            let _ = wsd_types(bytes);
        }
    }
}
