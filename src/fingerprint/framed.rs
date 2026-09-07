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

/// What an XDMCP display manager says when asked whether it is willing.
///
/// A Willing response carries three counted strings: the authentication name it
/// would use, the host it manages, and a free-text status. The status is the one
/// worth reading, since a display manager writes its own name and often the
/// machine's into it.
///
/// Returned as `host: status` where both are present, because either alone is
/// half an answer: the host names the machine and the status names the software.
///
/// [`None`] for anything that is not a Willing response, or whose counted
/// lengths run past the datagram.
#[must_use]
pub(super) fn xdmcp_willing(datagram: &[u8]) -> Option<String> {
    const OPCODE_WILLING: u16 = 5;

    let opcode = u16::from_be_bytes([*datagram.get(2)?, *datagram.get(3)?]);
    if opcode != OPCODE_WILLING {
        return None;
    }

    // Three ARRAY8s back to back, each a two-byte count and that many bytes.
    let mut at = 6;
    let mut fields = Vec::with_capacity(3);
    for _ in 0..3 {
        let len = u16::from_be_bytes([*datagram.get(at)?, *datagram.get(at + 1)?]) as usize;
        let value = datagram.get(at + 2..at + 2 + len)?;
        fields.push(String::from_utf8_lossy(value).trim().to_string());
        at += 2 + len;
    }

    let (host, status) = (&fields[1], &fields[2]);
    match (host.is_empty(), status.is_empty()) {
        (true, true) => None,
        (true, false) => Some(status.clone()),
        (false, true) => Some(host.clone()),
        (false, false) => Some(format!("{host}: {status}")),
    }
}

/// What a Source engine server answers a query with.
///
/// Two replies are possible and both identify the service. `I` is the info
/// response, which names the server, its game and its build. `A` is the
/// challenge Valve added in 2020, which carries no detail but is sent by
/// nothing else.
///
/// The info response is a header, a protocol byte, and then four NUL-terminated
/// strings: the server name, the map, the game directory, and the game. They are
/// joined with `;` so a rule can anchor across them, and the trailing binary
/// fields are left alone.
///
/// [`None`] for a datagram carrying neither reply.
#[must_use]
pub(super) fn source_engine(datagram: &[u8]) -> Option<String> {
    const HEADER: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF];
    const INFO: u8 = b'I';
    const CHALLENGE: u8 = b'A';

    if !datagram.starts_with(HEADER) {
        return None;
    }
    match *datagram.get(4)? {
        CHALLENGE => Some("challenge".to_string()),
        INFO => {
            // Header, kind, and the protocol version, then the strings.
            let mut rest = datagram.get(6..)?;
            let mut fields = Vec::with_capacity(4);
            for _ in 0..4 {
                let end = rest.iter().position(|byte| *byte == 0)?;
                fields.push(String::from_utf8_lossy(&rest[..end]).to_string());
                rest = rest.get(end + 1..)?;
            }
            Some(fields.join(";"))
        }
        _ => None,
    }
}

/// The status line a Minecraft Bedrock server answers an unconnected ping with.
///
/// The pong repeats the ping's magic and then carries one counted string, which
/// the server builds from its own configuration:
///
/// ```text
/// MCPE;Dedicated Server;390;1.14.60;0;10;13253860892328930865;Bedrock level;Survival
/// ```
///
/// Edition, message of the day, protocol number, version, players, capacity, and
/// then the level. The version is the fourth field and is what a rule reads.
///
/// [`None`] for a datagram that is not a pong, or that does not repeat the
/// magic. The magic is what separates this from any other protocol that happens
/// to start with the same byte.
#[must_use]
pub(super) fn raknet_pong(datagram: &[u8]) -> Option<&str> {
    const UNCONNECTED_PONG: u8 = 0x1C;
    /// The constant every RakNet offline message carries, so a reply can be told
    /// from an unrelated datagram.
    const MAGIC: &[u8] = &[
        0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56,
        0x78,
    ];

    if *datagram.first()? != UNCONNECTED_PONG {
        return None;
    }
    // The pong's own timestamp and server identifier sit before the magic.
    if datagram.get(17..33)? != MAGIC {
        return None;
    }

    let len = u16::from_be_bytes([*datagram.get(33)?, *datagram.get(34)?]) as usize;
    let status = datagram.get(35..35 + len)?;

    std::str::from_utf8(status).ok().map(str::trim)
}

/// The resource list a CoAP endpoint serves at `/.well-known/core`.
///
/// The payload is link format, a comma-separated list of the resources the
/// device exposes with their attributes:
///
/// ```text
/// </sensors/temp>;rt="temperature";if="sensor",</actuators/led>;rt="light"
/// ```
///
/// Worth more than a version string on a device that has none. It is the
/// closest thing the protocol has to a directory listing, and the resource
/// names are what say whether this is a sensor, a lock or a light.
///
/// [`None`] for a reply that is not CoAP, or that carries no payload. Options
/// are walked rather than skipped by a fixed offset, since their count and
/// length vary with what the endpoint chose to say.
#[must_use]
pub(super) fn coap_payload(datagram: &[u8]) -> Option<&str> {
    /// The byte separating the options from the payload.
    const PAYLOAD_MARKER: u8 = 0xFF;
    /// The two high bits of the first byte, which must be version 1.
    const VERSION_1: u8 = 0b0100_0000;

    let first = *datagram.first()?;
    if first & 0b1100_0000 != VERSION_1 {
        return None;
    }
    // Header, then a token as long as the low nibble says.
    let mut at = 4 + (first & 0x0F) as usize;

    // Options run until the payload marker or the end. Each is a delta/length
    // pair whose nibbles may be extended by one or two further bytes.
    while let Some(byte) = datagram.get(at) {
        if *byte == PAYLOAD_MARKER {
            let payload = datagram.get(at + 1..)?;
            let text = std::str::from_utf8(payload).ok()?.trim();
            return (!text.is_empty()).then_some(text);
        }
        at += 1;
        let mut length = (*byte & 0x0F) as usize;
        for nibble in [*byte >> 4, *byte & 0x0F] {
            at += match nibble {
                13 => 1,
                14 => 2,
                15 => return None,
                _ => 0,
            };
        }
        if length == 13 {
            length = *datagram.get(at - 1)? as usize + 13;
        } else if length == 14 {
            length =
                u16::from_be_bytes([*datagram.get(at - 2)?, *datagram.get(at - 1)?]) as usize + 269;
        }
        at += length;
    }
    None
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

    /// Builds a Willing response carrying the three counted strings.
    fn willing(auth: &str, host: &str, status: &str) -> Vec<u8> {
        let mut out = vec![0x00, 0x01, 0x00, 0x05, 0x00, 0x00];
        for field in [auth, host, status] {
            out.extend_from_slice(&(field.len() as u16).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out
    }

    #[test]
    fn a_willing_response_names_the_host_and_the_manager() {
        let reply = willing("", "workstation", "Linux 6.1 gdm");
        assert_eq!(
            xdmcp_willing(&reply).as_deref(),
            Some("workstation: Linux 6.1 gdm")
        );
    }

    /// Either field alone is still an answer; neither is not.
    #[test]
    fn a_willing_response_missing_a_field_yields_what_it_has() {
        assert_eq!(
            xdmcp_willing(&willing("", "", "gdm")).as_deref(),
            Some("gdm")
        );
        assert_eq!(
            xdmcp_willing(&willing("", "kiosk", "")).as_deref(),
            Some("kiosk")
        );
        assert!(xdmcp_willing(&willing("", "", "")).is_none());
    }

    /// A Query echoed back by a reflector is not a Willing, and a counted length
    /// past the datagram is refused rather than read through.
    #[test]
    fn anything_that_is_not_a_willing_response_yields_nothing() {
        assert!(xdmcp_willing(b"\x00\x01\x00\x02\x00\x01\x00").is_none());
        assert!(xdmcp_willing(b"").is_none());
        let mut lying = willing("", "host", "status");
        lying[6] = 0xff;
        assert!(xdmcp_willing(&lying).is_none());
    }

    #[test]
    fn a_source_info_reply_yields_the_server_and_its_game() {
        let mut reply = vec![0xFF, 0xFF, 0xFF, 0xFF, b'I', 17];
        for field in ["Zond Test Server", "de_dust2", "csgo", "Counter-Strike"] {
            reply.extend_from_slice(field.as_bytes());
            reply.push(0);
        }
        reply.extend_from_slice(&[0x00, 0x01, 0x02]);
        assert_eq!(
            source_engine(&reply).as_deref(),
            Some("Zond Test Server;de_dust2;csgo;Counter-Strike")
        );
    }

    /// The challenge Valve added in 2020, which carries no detail and is still
    /// proof of what answered.
    #[test]
    fn a_source_challenge_is_recognised_as_one() {
        let reply = [0xFF, 0xFF, 0xFF, 0xFF, b'A', 0x11, 0x22, 0x33, 0x44];
        assert_eq!(source_engine(&reply).as_deref(), Some("challenge"));
    }

    #[test]
    fn a_datagram_with_the_wrong_header_is_not_a_source_reply() {
        assert!(source_engine(b"\xff\xff\xff\xffZ").is_none());
        assert!(source_engine(b"\x00\x00\x00\x00I").is_none());
        assert!(source_engine(b"\xff\xff\xff\xffItruncated").is_none());
        assert!(source_engine(b"").is_none());
    }

    /// Builds an unconnected pong carrying `status`.
    fn pong(status: &str) -> Vec<u8> {
        let mut out = vec![0x1C];
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&[
            0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34,
            0x56, 0x78,
        ]);
        out.extend_from_slice(&(status.len() as u16).to_be_bytes());
        out.extend_from_slice(status.as_bytes());
        out
    }

    const MOTD: &str = "MCPE;Dedicated Server;390;1.14.60;0;10;13253860892328930865;Bedrock level";

    #[test]
    fn a_pong_yields_the_status_line() {
        assert_eq!(raknet_pong(&pong(MOTD)), Some(MOTD));
    }

    /// The magic is what separates a pong from an unrelated datagram that
    /// happens to start with the same byte.
    #[test]
    fn a_datagram_without_the_magic_is_not_a_pong() {
        let mut wrong = pong(MOTD);
        wrong[18] = 0x00; // the first 0xFF of the magic
        assert!(raknet_pong(&wrong).is_none());
        assert!(raknet_pong(b"\x1c").is_none());
        assert!(raknet_pong(b"").is_none());
    }

    #[test]
    fn a_coap_reply_yields_its_link_format_payload() {
        // ACK, code 2.05 Content, one option, then the payload.
        let mut reply = vec![0x60, 0x45, 0x7a, 0x6e, 0xC1, 0x28, 0xFF];
        reply.extend_from_slice(br#"</sensors/temp>;rt="temperature""#);
        assert_eq!(
            coap_payload(&reply),
            Some(r#"</sensors/temp>;rt="temperature""#)
        );
    }

    /// A reply with no payload marker, and one that is not CoAP at all.
    #[test]
    fn a_coap_reply_without_a_payload_yields_nothing() {
        assert!(coap_payload(&[0x60, 0x45, 0x7a, 0x6e, 0xC1, 0x28]).is_none());
        assert!(coap_payload(&[0x60, 0x45, 0x7a, 0x6e, 0xFF]).is_none());
        assert!(coap_payload(b"\x00\x01\x02\x03").is_none());
        assert!(coap_payload(b"").is_none());
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
            let _ = xdmcp_willing(bytes);
            let _ = source_engine(bytes);
            let _ = raknet_pong(bytes);
            let _ = coap_payload(bytes);
        }
    }
}
