// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Replies that carry text behind a few bytes of framing
//!
//! Some services answer with readable text behind a binary header: the SQL
//! Server Browser puts three bytes before its instance list, and memcached over
//! UDP puts eight before the `VERSION` line it sends over TCP.
//!
//! Each reader takes a reply and returns the text inside it, or [`None`] where
//! it is not the reply it was written for.
//! [`from_datagram`](super::extract::from_datagram) pairs each with its port.
//! Answers that need real decoding (SNMP varbinds, DNS answers) have their own
//! modules.

use crate::model::host::{HostName, NameKind, NameSource};

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
/// `tcp;1433` is the port the instance listens on; a named instance is often
/// not on 1433.
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

    // A length past the datagram is a truncated reply; read what arrived.
    let body = body.get(..stated.min(body.len()))?;
    std::str::from_utf8(body).ok().map(str::trim_end)
}

/// The command response inside a memcached UDP frame.
///
/// After the eight-byte frame comes what the command returns over TCP, so the
/// TCP banner rule reads it unchanged.
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
/// A Willing response carries three counted strings: the authentication name,
/// the host it manages, and a free-text status in which a display manager
/// usually names itself.
///
/// Returned as `host: status` where both are present.
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
/// `I` is the info response, naming the server, its game and its build. `A` is
/// the challenge Valve added in 2020, which carries no detail but is sent by
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

/// What a Steam master server answers a server-list query with.
///
/// The reply is the out-of-band header every Valve datagram carries, the
/// response type `f` and a line feed, and then a run of six-byte entries, an
/// IPv4 address and a port each, which a master pages through and closes with
/// the unspecified address. The entries are other hosts' servers and are not
/// read; the reply yields `server list`.
///
/// [`None`] for a datagram without the header, or whose body is not whole
/// entries.
#[must_use]
pub(super) fn steam_master_list(datagram: &[u8]) -> Option<&'static str> {
    const HEADER: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, b'f', b'\n'];
    const ENTRY_BYTES: usize = 6;

    let entries = datagram.strip_prefix(HEADER)?;
    (entries.len() % ENTRY_BYTES == 0).then_some("server list")
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
/// [`None`] for a datagram that is not a pong or does not repeat the magic.
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
/// The resource names say whether this is a sensor, a lock or a light.
///
/// [`None`] for a reply that is not CoAP, or that carries no payload. Options
/// vary in count and length, so they are walked.
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

/// Every RPC program a portmapper says it has registered, with its version and
/// the port it is on.
///
/// A `PMAPPROC_DUMP` reply is a chain of records, each preceded by a boolean
/// saying another follows, ending in a false. Each carries a program number, a
/// version, a transport and a port:
///
/// ```text
/// nfs 3 tcp 2049, mountd 3 udp 20048, nlockmgr 4 tcp 46283
/// ```
///
/// A handful of well-known programs are named; the rest keep their number. The
/// ports are often not the registered ones.
///
/// [`None`] for a reply that is not an accepted RPC response, or whose record
/// chain runs past the datagram.
#[must_use]
pub(super) fn rpc_program_dump(datagram: &[u8]) -> Option<String> {
    /// The programs spelled by name.
    const NAMED: &[(u32, &str)] = &[
        (100000, "portmapper"),
        (100003, "nfs"),
        (100005, "mountd"),
        (100021, "nlockmgr"),
        (100024, "status"),
        (100227, "nfs_acl"),
        (100011, "rquotad"),
        (100002, "rusersd"),
    ];

    let body = accepted_rpc_reply(datagram)?;
    let word = |at: usize| -> Option<u32> {
        body.get(at..at + 4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };

    let mut at = 0;
    let mut entries = Vec::new();
    // A record chain: each entry is preceded by a one meaning another follows.
    while word(at)? == 1 {
        let (program, version, protocol, port) =
            (word(at + 4)?, word(at + 8)?, word(at + 12)?, word(at + 16)?);
        at += 20;

        let name = NAMED
            .iter()
            .find(|(number, _)| *number == program)
            .map_or_else(|| program.to_string(), |(_, name)| (*name).to_string());
        let transport = match protocol {
            6 => "tcp",
            17 => "udp",
            other => return Some(format!("{name} {version} proto{other} {port}")),
        };
        entries.push(format!("{name} {version} {transport} {port}"));

        // A busy host registers dozens; cap the list.
        if entries.len() >= 64 {
            break;
        }
    }

    (!entries.is_empty()).then(|| entries.join(", "))
}

/// What versions of a program an RPC server says it supports.
///
/// The probe calls a version nothing implements, so an accepted reply is a
/// mismatch carrying the supported range.
///
/// ```text
/// versions 3-4
/// ```
///
/// [`None`] where the reply is not a mismatch, which includes a server that does
/// not run the program at all.
#[must_use]
pub(super) fn rpc_version_range(datagram: &[u8]) -> Option<String> {
    /// `PROG_MISMATCH`, the accept status that carries the range.
    const PROG_MISMATCH: u32 = 2;

    let (status, body) = rpc_reply_status(datagram)?;
    if status != PROG_MISMATCH {
        return None;
    }

    let word = |at: usize| -> Option<u32> {
        body.get(at..at + 4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };
    let (low, high) = (word(0)?, word(4)?);

    (low <= high && high < 100).then(|| format!("versions {low}-{high}"))
}

/// The RPC message a TCP stream carries, its record marks taken out.
///
/// Over TCP, RFC 5531 §11 splits a message into fragments, each behind a
/// four-byte mark whose top bit says it is the last and whose other bits give
/// its length. Without the marks it is the datagram's message, so the UDP
/// readers apply.
///
/// [`None`] for a stream that ends before its last fragment does, which is
/// either not RPC or more than one read of it.
#[must_use]
pub(super) fn rpc_record(stream: &[u8]) -> Option<Vec<u8>> {
    const LAST_FRAGMENT: u32 = 0x8000_0000;

    let mut record = Vec::new();
    let mut at = 0;
    loop {
        let mark = u32::from_be_bytes(stream.get(at..at + 4)?.try_into().ok()?);
        let length = (mark & !LAST_FRAGMENT) as usize;
        record.extend_from_slice(stream.get(at + 4..at + 4 + length)?);
        at += 4 + length;
        if mark & LAST_FRAGMENT != 0 {
            return Some(record);
        }
    }
}

/// The version a SQL Server states in answer to a pre-login, as
/// `Microsoft SQL Server 15.0.2000`.
///
/// A pre-login response (MS-TDS, PRELOGIN) is a TDS packet of type 4 holding
/// a table of options, each a token, an offset and a length, ended by 0xFF.
/// The VERSION option, token 0, is six bytes: the major and minor version, the
/// build as a big-endian word, and a sub-build. The server states it before
/// anything is authenticated or encrypted.
///
/// [`None`] for a reply that is not a pre-login response or carries no
/// version.
#[must_use]
pub(super) fn tds_version(stream: &[u8]) -> Option<String> {
    const TABULAR_RESULT: u8 = 0x04;
    const HEADER_BYTES: usize = 8;
    const VERSION: u8 = 0x00;
    const TERMINATOR: u8 = 0xFF;

    if *stream.first()? != TABULAR_RESULT {
        return None;
    }
    let length = u16::from_be_bytes([*stream.get(2)?, *stream.get(3)?]) as usize;
    let data = stream.get(HEADER_BYTES..length)?;

    let mut at = 0;
    loop {
        let token = *data.get(at)?;
        if token == TERMINATOR {
            return None;
        }
        let option = data.get(at + 1..at + 5)?;
        let offset = u16::from_be_bytes([option[0], option[1]]) as usize;
        let size = u16::from_be_bytes([option[2], option[3]]) as usize;
        if token == VERSION && size >= 6 {
            let version = data.get(offset..offset + 6)?;
            let build = u16::from_be_bytes([version[2], version[3]]);
            return Some(format!(
                "Microsoft SQL Server {}.{}.{build}",
                version[0], version[1]
            ));
        }
        at += 5;
    }
}

/// The body of an RPC reply that was accepted and succeeded.
fn accepted_rpc_reply(datagram: &[u8]) -> Option<&[u8]> {
    match rpc_reply_status(datagram)? {
        (0, body) => Some(body),
        _ => None,
    }
}

/// The accept status of an RPC reply and whatever follows it.
///
/// Walks the header, since the verifier before the accept status has variable
/// length.
fn rpc_reply_status(datagram: &[u8]) -> Option<(u32, &[u8])> {
    const MSG_TYPE_REPLY: u32 = 1;
    const MSG_ACCEPTED: u32 = 0;

    let word = |at: usize| -> Option<u32> {
        datagram
            .get(at..at + 4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };

    if word(4)? != MSG_TYPE_REPLY || word(8)? != MSG_ACCEPTED {
        return None;
    }
    // The verifier: a flavour and a length, then that many bytes rounded up to
    // a four-byte boundary.
    let verifier = word(16)? as usize;
    let at = 20 + verifier.next_multiple_of(4);

    Some((word(at)?, datagram.get(at + 4..)?))
}

/// What a BMC says about how it may be logged into.
///
/// A Get Channel Authentication Capabilities response states the IPMI version
/// the channel speaks and, in its status byte, whether it will accept a session
/// with no user name and whether the null user is enabled. Either means anyone
/// who can route to it can log in.
///
/// ```text
/// IPMI-2.0 anonymous-login null-user
/// ```
///
/// [`None`] for a datagram that is not an RMCP-wrapped IPMI response, or whose
/// completion code says the command failed.
#[must_use]
pub(super) fn ipmi_auth_capabilities(datagram: &[u8]) -> Option<String> {
    /// The RMCP class byte that marks the payload as IPMI.
    const CLASS_IPMI: u8 = 0x07;
    /// Where the response data begins: the RMCP header, the v1.5 session
    /// header, the message length, and the IPMB header up to the completion
    /// code.
    const DATA_AT: usize = 4 + 9 + 1 + 7;

    if *datagram.first()? != 0x06 || *datagram.get(3)? != CLASS_IPMI {
        return None;
    }
    // A non-zero completion code means the BMC refused the command.
    if *datagram.get(DATA_AT - 1)? != 0x00 {
        return None;
    }

    let support = *datagram.get(DATA_AT + 1)?;
    let status = *datagram.get(DATA_AT + 2)?;

    let mut said = Vec::new();
    // Bit 7 of the auth support byte is set by a channel that speaks IPMI 2.0.
    said.push(match support & 0b1000_0000 != 0 {
        true => "IPMI-2.0",
        false => "IPMI-1.5",
    });
    if status & 0b0000_0001 != 0 {
        said.push("anonymous-login");
    }
    if status & 0b0000_0010 != 0 {
        said.push("null-user");
    }
    // Bit 2 (non-null user names enabled) is the ordinary state and is not
    // reported; `non-null-user` would also match a rule for `null-user`.

    Some(said.join(" "))
}

/// The system variables an NTP server reports in answer to a mode 6 control
/// message.
///
/// The data is the text `ntpq` prints, a comma-separated list the daemon builds
/// from its own configuration:
///
/// ```text
/// version="ntpd 4.2.8p15@1.3728-o Wed May 12", processor="x86_64", system="Linux/6.1.0"
/// ```
///
/// Many imported rules read this; the ordinary client probe's reply holds only
/// timestamps.
///
/// Line breaks are folded to spaces, since a daemon wraps this text and the
/// rules match across the wrap with `.*`. Spacing around commas is kept, since
/// rules distinguish products by it.
///
/// [`None`] for a reply that is not a mode 6 response, or that carries no data.
/// Only the first packet is read; daemons put these variables there.
#[must_use]
pub(super) fn ntp_control_variables(datagram: &[u8]) -> Option<String> {
    /// Bit 7 of the second byte, set on a response.
    const RESPONSE: u8 = 0b1000_0000;
    /// The low five bits of the same byte, which carry the operation.
    const OPCODE: u8 = 0b0001_1111;
    /// Read variables, the operation the probe asks for.
    const READVAR: u8 = 2;
    /// The fixed control header, before the data the count describes.
    const HEADER_BYTES: usize = 12;

    let mode = *datagram.first()? & 0b0000_0111;
    if mode != 6 {
        return None;
    }
    let second = *datagram.get(1)?;
    if second & RESPONSE == 0 || second & OPCODE != READVAR {
        return None;
    }

    let count = u16::from_be_bytes([*datagram.get(10)?, *datagram.get(11)?]) as usize;
    let data = datagram.get(HEADER_BYTES..HEADER_BYTES + count)?;
    let text = std::str::from_utf8(data).ok()?;

    // A run of line breaks becomes one space, so CRLF does not become two.
    let mut folded = String::with_capacity(text.len());
    let mut breaking = false;
    for character in text.chars() {
        match character {
            '\r' | '\n' => breaking = true,
            _ => {
                if breaking {
                    folded.push(' ');
                    breaking = false;
                }
                folded.push(character);
            }
        }
    }
    let folded = folded.trim().to_string();

    (!folded.is_empty()).then_some(folded)
}

/// What a STUN server calls itself.
///
/// `SOFTWARE` names the implementation. A server that omits it is still
/// identified as STUN by the reply's shape.
///
/// The mapped address describes the client's apparent address, not the host,
/// and is not read.
///
/// [`None`] for a datagram that is not a binding response with the RFC 5389
/// magic cookie; the type field alone is too weak to key on.
#[must_use]
pub(super) fn stun_binding(datagram: &[u8]) -> Option<String> {
    /// The value RFC 5389 fixed so a response can be told from anything else.
    const MAGIC_COOKIE: u32 = 0x2112_A442;
    /// A successful binding response.
    const BINDING_SUCCESS: u16 = 0x0101;
    /// The attribute naming the implementation.
    const SOFTWARE: u16 = 0x8022;
    const HEADER_BYTES: usize = 20;

    let kind = u16::from_be_bytes([*datagram.first()?, *datagram.get(1)?]);
    let cookie = u32::from_be_bytes([
        *datagram.get(4)?,
        *datagram.get(5)?,
        *datagram.get(6)?,
        *datagram.get(7)?,
    ]);
    if cookie != MAGIC_COOKIE || kind != BINDING_SUCCESS {
        return None;
    }

    let mut at = HEADER_BYTES;
    while at + 4 <= datagram.len() {
        let attribute = u16::from_be_bytes([datagram[at], datagram[at + 1]]);
        let length = u16::from_be_bytes([datagram[at + 2], datagram[at + 3]]) as usize;
        let value = datagram.get(at + 4..at + 4 + length)?;

        if attribute == SOFTWARE
            && let Ok(name) = std::str::from_utf8(value)
            && let name = name.trim().trim_end_matches('\0')
            && !name.is_empty()
        {
            return Some(name.to_string());
        }
        // Attributes are padded to a four-byte boundary, and the padding is not
        // counted in the length.
        at += 4 + length.next_multiple_of(4);
    }

    Some("stun".to_string())
}

/// What an IKE responder announces about itself.
///
/// The Vendor ID payloads in a gateway's answer are fixed per implementation,
/// usually a hash of its name and version. Returned as lowercase hex, space
/// separated.
///
/// A responder that liked none of the proposal answers with a Notify, which
/// still proves an IKE daemon and is returned named.
///
/// [`None`] for a datagram too short to be ISAKMP, or whose payload chain runs
/// past its end.
#[must_use]
pub(super) fn ike_response(datagram: &[u8]) -> Option<String> {
    /// The ISAKMP header: two cookies, the next payload, the version, the
    /// exchange type, flags, a message id and a length.
    const HEADER_BYTES: usize = 28;
    const PAYLOAD_VENDOR_ID: u8 = 13;
    const PAYLOAD_NOTIFY: u8 = 11;
    /// A payload header: next type, reserved, and the length including itself.
    const PAYLOAD_HEADER_BYTES: usize = 4;

    if datagram.len() < HEADER_BYTES {
        return None;
    }
    // The responder cookie is zero in a request (such as our own probe echoed
    // back) and set in every reply.
    if datagram.get(8..16)? == [0u8; 8] {
        return None;
    }

    let mut next = *datagram.get(16)?;
    let mut at = HEADER_BYTES;
    let mut vendor_ids = Vec::new();
    let mut notified = false;

    while next != 0 && at + PAYLOAD_HEADER_BYTES <= datagram.len() {
        let length = u16::from_be_bytes([datagram[at + 2], datagram[at + 3]]) as usize;
        if length < PAYLOAD_HEADER_BYTES {
            return None;
        }
        let body = datagram.get(at + PAYLOAD_HEADER_BYTES..at + length)?;

        match next {
            PAYLOAD_VENDOR_ID => vendor_ids.push(
                body.iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            ),
            PAYLOAD_NOTIFY => notified = true,
            _ => {}
        }

        next = datagram[at];
        at += length;
        if vendor_ids.len() >= 16 {
            break;
        }
    }

    match (vendor_ids.is_empty(), notified) {
        (false, _) => Some(vendor_ids.join(" ")),
        (true, true) => Some("notify".to_string()),
        (true, false) => Some("isakmp".to_string()),
    }
}

/// The realm a probe names, so the reader can tell an answer from an echo.
///
/// A KDC replies to an unknown principal by repeating the realm it was asked
/// about, so the realm in the reply is usually this string coming back. See
/// [`kerberos_realm`].
const PROBE_REALM: &str = "ZOND-SCAN";

/// What a Kerberos KDC says about a request it cannot serve.
///
/// The probe asks for a principal in a realm nothing serves, and the reply is a
/// `KRB-ERROR` (RFC 4120 §5.9.1). Two of its fields are read as the service's
/// description: the error code, and the human text where the implementation
/// sends one.
///
/// ```text
/// krb-error 6 CLIENT_NOT_FOUND
/// ```
///
/// The realm is not included, since reports do not mask service descriptions;
/// [`kerberos_realm`] reads it as a host name.
///
/// [`None`] for anything that is not a `KRB-ERROR`.
#[must_use]
pub(super) fn kerberos_error(datagram: &[u8]) -> Option<String> {
    let error = KrbError::read(datagram)?;
    let mut said = format!("krb-error {}", error.code);
    if let Some(text) = error.text.filter(|text| !text.is_empty()) {
        said.push(' ');
        said.push_str(text);
    }
    Some(said)
}

/// The realm a KDC's `KRB-ERROR` names, as the domain it serves.
///
/// ## Why the realm is usually absent
///
/// The probe must name a realm and invents one. MIT krb5 on Debian 12 repeats
/// it in both `crealm` and `realm`, so the realm is read only when it differs
/// from [`PROBE_REALM`].
///
/// RFC 4120 has a KDC serving another realm answer `KDC_ERR_WRONG_REALM` and
/// name the right one, which on a domain controller is the Active Directory
/// domain. That branch follows the specification; MIT answered
/// `KDC_ERR_C_PRINCIPAL_UNKNOWN` instead.
///
/// [`None`] for anything that is not a `KRB-ERROR`, and for one naming no
/// realm but the probe's.
#[must_use]
pub(super) fn kerberos_realm(datagram: &[u8]) -> Option<HostName> {
    let realm = KrbError::read(datagram)?
        .realm
        .filter(|realm| *realm != PROBE_REALM)?;
    HostName::new(NameKind::Domain, NameSource::Kerberos, realm)
}

/// The fields of a `KRB-ERROR` anything here reads.
struct KrbError<'a> {
    /// `error-code`.
    code: u32,
    /// `realm`, the service realm, where it is text.
    realm: Option<&'a str>,
    /// `e-text`, which MIT fills in and which names the implementation.
    text: Option<&'a str>,
}

impl<'a> KrbError<'a> {
    /// Reads `datagram` as a `KRB-ERROR`, or [`None`] where it is not one or
    /// carries no error code.
    fn read(datagram: &'a [u8]) -> Option<Self> {
        /// `[APPLICATION 30]`, which is what a `KRB-ERROR` is tagged with.
        const KRB_ERROR: u8 = 0x7E;

        if *datagram.first()? != KRB_ERROR {
            return None;
        }
        // The application tag wraps a SEQUENCE, and the fields are
        // context-tagged inside it.
        let body = der_value(datagram)?;
        let fields = der_value(body)?;

        let mut code = None;
        let mut realm = None;
        let mut text = None;
        let mut at = 0;
        while at < fields.len() {
            let (tag, value, next) = der_element(&fields[at..])?;
            match tag {
                // error-code, an INTEGER inside its context tag.
                0xA6 => code = der_value(value).map(der_unsigned),
                // realm and e-text, each a GeneralString.
                0xA9 => realm = der_value(value).and_then(|v| std::str::from_utf8(v).ok()),
                0xAB => text = der_value(value).and_then(|v| std::str::from_utf8(v).ok()),
                _ => {}
            }
            at += next;
        }

        Some(Self {
            code: code?,
            realm,
            text,
        })
    }
}

/// The contents of the DER element at the start of `bytes`.
fn der_value(bytes: &[u8]) -> Option<&[u8]> {
    der_element(bytes).map(|(_, value, _)| value)
}

/// The tag, contents and total encoded length of the DER element at the start
/// of `bytes`.
///
/// Long-form lengths are read up to four bytes, which is past anything a
/// datagram can hold. Nothing here recurses on its own: callers walk.
fn der_element(bytes: &[u8]) -> Option<(u8, &[u8], usize)> {
    let tag = *bytes.first()?;
    let first = *bytes.get(1)? as usize;

    let (length, header) = if first & 0x80 == 0 {
        (first, 2)
    } else {
        let count = first & 0x7F;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for index in 0..count {
            length = (length << 8) | *bytes.get(2 + index)? as usize;
        }
        (length, 2 + count)
    };

    let value = bytes.get(header..header + length)?;
    Some((tag, value, header + length))
}

/// A DER INTEGER's value, as far as one fits.
fn der_unsigned(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .take(4)
        .fold(0u32, |value, byte| (value << 8) | u32::from(*byte))
}

/// What an L2TP concentrator says about itself when a tunnel is proposed.
///
/// An `SCCRQ` draws an `SCCRP` carrying the vendor name, returned here, and the
/// host name, which [`l2tp_host_name`] reads.
///
/// ```text
/// vendor=xelerance.com
/// ```
///
/// `xl2tpd` on Debian 12 fills in both. A reply naming no vendor still says an
/// L2TP daemon answered.
///
/// [`None`] for a datagram that is not a control message, whose attribute
/// chain runs past its end, or that carries no attributes at all.
#[must_use]
pub(super) fn l2tp_control(datagram: &[u8]) -> Option<String> {
    Some(match L2tpControl::read(datagram)?.vendor {
        Some(vendor) => format!("vendor={vendor}"),
        // No vendor named, but still an L2TP daemon.
        None => "l2tp".to_string(),
    })
}

/// The Host Name attribute of an L2TP control message (RFC 2661 §4.4.3), as
/// the machine's own name.
///
/// The name of the concentrator that sent it: xl2tpd sends the machine's
/// hostname, and Cisco and Windows RRAS their configured host names.
///
/// [`None`] for anything [`l2tp_control`] would not read, and for a message
/// naming no host.
#[must_use]
pub(super) fn l2tp_host_name(datagram: &[u8]) -> Option<HostName> {
    let host = L2tpControl::read(datagram)?.host?;
    HostName::new(NameKind::Host, NameSource::L2tp, host)
}

/// The attributes of an L2TP control message anything here reads.
struct L2tpControl<'a> {
    vendor: Option<&'a str>,
    host: Option<&'a str>,
}

impl<'a> L2tpControl<'a> {
    /// [`None`] for a datagram that is not a version 2 control message, whose
    /// attribute chain runs past its end, or that carries no attributes.
    fn read(datagram: &'a [u8]) -> Option<Self> {
        /// The first byte of a control message: type and length bits set, and
        /// the version in the low nibble of the second.
        const CONTROL: u8 = 0b1100_0000;
        /// A control header carries a length, a tunnel and session id, and two
        /// sequence numbers.
        const HEADER_BYTES: usize = 12;
        const ATTRIBUTE_HEADER_BYTES: usize = 6;
        const VENDOR_NAME: u16 = 8;
        const HOST_NAME: u16 = 7;

        if *datagram.first()? & CONTROL != CONTROL {
            return None;
        }
        if *datagram.get(1)? & 0x0F != 2 {
            return None;
        }

        let mut at = HEADER_BYTES;
        let mut read = Self {
            vendor: None,
            host: None,
        };
        let mut attributes = 0usize;
        while at + ATTRIBUTE_HEADER_BYTES <= datagram.len() {
            attributes += 1;
            // Six flag bits, then a ten-bit length that includes this header.
            let length = (u16::from_be_bytes([datagram[at], datagram[at + 1]]) & 0x03FF) as usize;
            if length < ATTRIBUTE_HEADER_BYTES {
                return None;
            }
            let attribute = u16::from_be_bytes([datagram[at + 4], datagram[at + 5]]);
            let value = datagram.get(at + ATTRIBUTE_HEADER_BYTES..at + length)?;

            let text = |value: &'a [u8]| {
                std::str::from_utf8(value)
                    .ok()
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
            };
            match attribute {
                VENDOR_NAME => read.vendor = text(value),
                HOST_NAME => read.host = text(value),
                _ => {}
            }
            at += length;
        }

        // No attributes is a ZLB acknowledgement, which a concentrator sends for
        // a repeated tunnel request (the scan probes twice). It says nothing.
        (attributes > 0).then_some(read)
    }
}

/// The operating system and LAN manager an SMB1 session setup answers with.
///
/// A server that accepts a session names the operating system it runs and the
/// LAN manager dialect it speaks:
///
/// ```text
/// Windows 6.1
/// Samba 4.17.12-Debian
/// ```
///
/// Each is returned on its own, since the corpus rules anchor on one field
/// (`^Windows 6.1$`). Eighty-five imported rules read these, which arrive only
/// in answer to a session setup.
///
/// The domain, third, is read by [`smb_session_names`] as a host name.
///
/// The stream holds a negotiate response and then the session setup, each
/// behind a four-byte NetBIOS length; this walks to the second.
///
/// Empty where no session setup was accepted, including any current server
/// with SMB1 off (Windows since 2017, Samba since 4.11).
#[must_use]
pub(super) fn smb_session_setup(stream: &[u8]) -> Vec<String> {
    SessionSetup::read(stream)
        .map(|setup| {
            [setup.native_os, setup.native_lan_man]
                .into_iter()
                .filter(|text| !text.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// The domain an SMB1 session setup names, as the NetBIOS name of the domain
/// or workgroup the server belongs to.
///
/// Empty where no session setup was accepted, and where the server named no
/// domain.
#[must_use]
pub(super) fn smb_session_names(stream: &[u8]) -> Vec<HostName> {
    SessionSetup::read(stream)
        .and_then(|setup| {
            HostName::new(
                NameKind::NetbiosDomain,
                NameSource::Smb,
                &setup.primary_domain,
            )
        })
        .into_iter()
        .collect()
}

/// The three strings of an accepted SMB1 `SESSION_SETUP_ANDX` response, each
/// trimmed, and empty where the server sent it empty or left it out.
struct SessionSetup {
    /// `NativeOS`, the operating system the server runs.
    native_os: String,
    /// `NativeLanMan`, the LAN manager it speaks.
    native_lan_man: String,
    /// `PrimaryDomain`, the domain or workgroup it belongs to.
    primary_domain: String,
}

impl SessionSetup {
    /// The first accepted session setup in `stream`, read by position.
    ///
    /// MS-CIFS 2.2.4.53.2 lays the response out as three words, a byte count,
    /// and then `NativeOS`, `NativeLanMan` and `PrimaryDomain` in that order,
    /// each ended by a NUL, behind one byte of padding where the strings are
    /// UTF-16 and would otherwise start at an odd offset from the header. The
    /// extended-security form, MS-SMB 2.2.4.6.2, adds a fourth word giving the
    /// length of a security blob before the padding. Read by position, so an
    /// empty operating system does not shift the other two.
    fn read(stream: &[u8]) -> Option<Self> {
        /// `SESSION_SETUP_ANDX`.
        const SESSION_SETUP: u8 = 0x73;
        /// The flags2 bit saying the strings are UTF-16.
        const UNICODE: u16 = 0x8000;
        /// The NetBIOS session header before each SMB message.
        const NBSS_HEADER_BYTES: usize = 4;
        const SMB_HEADER_BYTES: usize = 32;
        /// The word counts of the two forms: MS-CIFS 2.2.4.53.2 and, with a
        /// security blob, MS-SMB 2.2.4.6.2.
        const PLAIN_WORDS: u8 = 3;
        const EXTENDED_WORDS: u8 = 4;

        let mut at = 0;
        while at + NBSS_HEADER_BYTES <= stream.len() {
            // A NetBIOS length is three bytes, big-endian, behind a message type.
            let length =
                u32::from_be_bytes([0, stream[at + 1], stream[at + 2], stream[at + 3]]) as usize;
            let Some(message) = stream.get(at + NBSS_HEADER_BYTES..at + NBSS_HEADER_BYTES + length)
            else {
                break;
            };
            at += NBSS_HEADER_BYTES + length;

            if !message.starts_with(b"\xffSMB") || message.get(4) != Some(&SESSION_SETUP) {
                continue;
            }
            if message.len() < SMB_HEADER_BYTES + 3 {
                continue;
            }
            // A non-zero status is a refusal, and the fields behind it are absent.
            if u32::from_le_bytes([message[5], message[6], message[7], message[8]]) != 0 {
                continue;
            }

            let unicode = u16::from_le_bytes([message[10], message[11]]) & UNICODE != 0;
            let word = |index: usize| {
                let at = SMB_HEADER_BYTES + 1 + index * 2;
                Some(u16::from_le_bytes([*message.get(at)?, *message.get(at + 1)?]) as usize)
            };
            // The parameter block: a word count, that many words, then a byte
            // count and the bytes it counts.
            let words = message[SMB_HEADER_BYTES];
            let blob = match words {
                PLAIN_WORDS => 0,
                EXTENDED_WORDS => word(3)?,
                _ => continue,
            };
            let count = word(usize::from(words))?;
            let bytes_at = SMB_HEADER_BYTES + 1 + usize::from(words) * 2 + 2;
            let Some(bytes) = message.get(bytes_at..bytes_at + count) else {
                continue;
            };

            // The padding is counted from the start of the SMB header, which
            // is where `bytes_at` is counted from as well.
            let mut strings_at = blob;
            if unicode && (bytes_at + strings_at) % 2 == 1 {
                strings_at += 1;
            }
            let mut strings = bytes.get(strings_at..).unwrap_or_default();
            let mut next = || -> String {
                let (text, rest) = match unicode {
                    true => utf16_string(strings),
                    false => oem_string(strings),
                };
                strings = rest;
                text.trim().to_string()
            };
            return Some(Self {
                native_os: next(),
                native_lan_man: next(),
                primary_domain: next(),
            });
        }
        None
    }
}

/// The NUL-terminated UTF-16 string at the start of `bytes`, and what follows
/// its terminator. A string the field ends before terminating runs to the end.
fn utf16_string(bytes: &[u8]) -> (String, &[u8]) {
    let (units, _) = bytes.as_chunks::<2>();
    let end = units.iter().position(|unit| *unit == [0, 0]);
    let text: Vec<u16> = units[..end.unwrap_or(units.len())]
        .iter()
        .map(|unit| u16::from_le_bytes(*unit))
        .collect();
    let rest = match end {
        Some(end) => &bytes[(end + 1) * 2..],
        None => &[],
    };
    (String::from_utf16_lossy(&text), rest)
}

/// The NUL-terminated OEM string at the start of `bytes`, and what follows its
/// terminator. A string the field ends before terminating runs to the end.
fn oem_string(bytes: &[u8]) -> (String, &[u8]) {
    match bytes.iter().position(|byte| *byte == 0) {
        Some(end) => (
            String::from_utf8_lossy(&bytes[..end]).into_owned(),
            &bytes[end + 1..],
        ),
        None => (String::from_utf8_lossy(bytes).into_owned(), &[]),
    }
}

/// What an SMB2 server says in answer to a negotiate and a session setup that
/// offers NTLM.
///
/// Two texts, each for its own rules:
///
/// ```text
/// dialect 3.1.1; signing not required
/// Windows 10.0 Build 20348
/// ```
///
/// The first is from the negotiate response (MS-SMB2 2.2.4): the chosen dialect
/// and whether signing is required. Without required signing, sessions can be
/// relayed to the server.
///
/// The second is the `Version` of the NTLM challenge (MS-NLMP 2.2.1.2), which
/// Windows fills before authentication. Left out where the build is zero, as
/// Samba sends it.
///
/// The machine and domain names in the challenge are read by [`smb2_names`].
///
/// Empty for a stream that holds no SMB2 message.
#[must_use]
pub(super) fn smb2_exchange(stream: &[u8]) -> Vec<String> {
    const NEGOTIATE: u16 = 0;
    /// The dialect a server answers an SMB1 negotiate with when it wants the
    /// client to negotiate again in SMB2, which names no dialect it speaks.
    const WILDCARD: u16 = 0x02FF;
    const SIGNING_REQUIRED: u16 = 0x0002;

    let mut texts = Vec::new();
    for message in smb2_messages(stream) {
        let word = |at: usize| u16::from_le_bytes([message[at], message[at + 1]]);
        let status = u32::from_le_bytes([message[8], message[9], message[10], message[11]]);
        let body = SMB2_HEADER_BYTES;

        if word(12) == NEGOTIATE && status == 0 {
            let dialect = word(body + 4);
            if dialect == WILDCARD {
                continue;
            }
            let signing = match word(body + 2) & SIGNING_REQUIRED {
                0 => "not required",
                _ => "required",
            };
            texts.push(format!(
                "dialect {}.{}{}; signing {signing}",
                dialect >> 8,
                (dialect >> 4) & 0xF,
                match dialect & 0xF {
                    0 => String::new(),
                    revision => format!(".{revision}"),
                }
            ));
        }
        if let Some(version) = smb2_session_token(message).and_then(ntlm_challenge_version) {
            texts.push(version);
        }
    }
    texts
}

/// The names an SMB2 server gives for itself in the NTLM challenge its session
/// setup answer carries: the target information of MS-NLMP 2.2.1.2, which
/// Windows and Samba both fill in before anything is authenticated.
///
/// Five of its pairs are names (MS-NLMP 2.2.2.1), and each is read into its
/// own kind:
///
/// | pair | `AvId` | kind |
/// |---|---|---|
/// | `MsvAvNbComputerName` | 1 | [`NetbiosHost`](NameKind::NetbiosHost) |
/// | `MsvAvNbDomainName` | 2 | [`NetbiosDomain`](NameKind::NetbiosDomain) |
/// | `MsvAvDnsComputerName` | 3 | [`Host`](NameKind::Host) |
/// | `MsvAvDnsDomainName` | 4 | [`Domain`](NameKind::Domain) |
/// | `MsvAvDnsTreeName` | 5 | [`Forest`](NameKind::Forest) |
///
/// The first of each is taken, since the specification allows one of each, and
/// the walk stops at the end-of-list pair or at the first pair the bytes cannot
/// hold. A name the model refuses, such as an empty one, is left out; the rest
/// of the list is still read.
///
/// Empty for a stream that holds no challenge, and for one whose challenge
/// carries no target information.
#[must_use]
pub(super) fn smb2_names(stream: &[u8]) -> Vec<HostName> {
    smb2_messages(stream)
        .filter_map(smb2_session_token)
        .find_map(|token| {
            let names = ntlm_target_names(token);
            (!names.is_empty()).then_some(names)
        })
        .unwrap_or_default()
}

/// Bytes of an SMB2 header (MS-SMB2 2.2.1.2).
const SMB2_HEADER_BYTES: usize = 64;

/// The SMB2 messages in `stream`, each without the NetBIOS length in front of
/// it, and each long enough to hold a header and the first words of a body.
///
/// Stops at the first message the stream does not hold whole, which is where a
/// truncated reply ends.
fn smb2_messages(stream: &[u8]) -> impl Iterator<Item = &[u8]> {
    const NBSS_HEADER_BYTES: usize = 4;

    let mut at = 0;
    std::iter::from_fn(move || {
        loop {
            let header = stream.get(at..at + NBSS_HEADER_BYTES)?;
            let length = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
            let message = stream.get(at + NBSS_HEADER_BYTES..at + NBSS_HEADER_BYTES + length)?;
            at += NBSS_HEADER_BYTES + length;
            if message.starts_with(b"\xfeSMB") && message.len() >= SMB2_HEADER_BYTES + 8 {
                return Some(message);
            }
        }
    })
}

/// The security buffer of an SMB2 SESSION_SETUP response (MS-SMB2 2.2.6),
/// where the server's NTLM challenge travels.
///
/// Read whatever the status: the challenge arrives under
/// `STATUS_MORE_PROCESSING_REQUIRED`.
fn smb2_session_token(message: &[u8]) -> Option<&[u8]> {
    const SESSION_SETUP: u16 = 1;

    let word = |at: usize| u16::from_le_bytes([message[at], message[at + 1]]);
    if word(12) != SESSION_SETUP {
        return None;
    }
    let offset = word(SMB2_HEADER_BYTES + 4) as usize;
    let length = word(SMB2_HEADER_BYTES + 6) as usize;
    message.get(offset..offset + length)
}

/// The NTLM CHALLENGE_MESSAGE inside `token`, from its signature to the end.
///
/// Found by its signature, since a server may or may not wrap it in SPNEGO.
fn ntlm_challenge(token: &[u8]) -> Option<&[u8]> {
    const CHALLENGE: &[u8] = b"NTLMSSP\0\x02\0\0\0";

    let start = token
        .windows(CHALLENGE.len())
        .position(|window| window == CHALLENGE)?;
    Some(&token[start..])
}

/// The Windows version an NTLM challenge inside `token` states, as
/// `Windows 10.0 Build 20348`.
///
/// [`None`] where there is no challenge, where it carries no version, or where
/// the build is zero.
fn ntlm_challenge_version(token: &[u8]) -> Option<String> {
    /// The flag saying the `Version` field is filled in.
    const NEGOTIATE_VERSION: u32 = 0x0200_0000;
    const VERSION_AT: usize = 48;

    let message = ntlm_challenge(token)?;
    let flags = u32::from_le_bytes(message.get(20..24)?.try_into().ok()?);
    if flags & NEGOTIATE_VERSION == 0 {
        return None;
    }
    let version = message.get(VERSION_AT..VERSION_AT + 4)?;
    let build = u16::from_le_bytes([version[2], version[3]]);
    (build != 0).then(|| format!("Windows {}.{} Build {build}", version[0], version[1]))
}

/// The names in the target information of an NTLM challenge inside `token`.
/// See [`smb2_names`] for which pairs are read and how.
fn ntlm_target_names(token: &[u8]) -> Vec<HostName> {
    /// Where the challenge's `TargetInfoFields` sit: a length, a maximum
    /// length, and an offset from the start of the message.
    const TARGET_INFO_AT: usize = 40;
    const AV_EOL: u16 = 0;

    let Some(message) = ntlm_challenge(token) else {
        return Vec::new();
    };
    let field = || -> Option<&[u8]> {
        let fields = message.get(TARGET_INFO_AT..TARGET_INFO_AT + 8)?;
        let length = u16::from_le_bytes([fields[0], fields[1]]) as usize;
        let offset = u32::from_le_bytes([fields[4], fields[5], fields[6], fields[7]]) as usize;
        message.get(offset..offset.checked_add(length)?)
    };
    let Some(pairs) = field() else {
        return Vec::new();
    };

    let mut names: Vec<HostName> = Vec::new();
    let mut seen = Vec::new();
    let mut at = 0;
    while let Some(pair) = pairs.get(at..at + 4) {
        let id = u16::from_le_bytes([pair[0], pair[1]]);
        let length = u16::from_le_bytes([pair[2], pair[3]]) as usize;
        let Some(value) = pairs.get(at + 4..at + 4 + length) else {
            break;
        };
        at += 4 + length;

        let kind = match id {
            AV_EOL => break,
            1 => NameKind::NetbiosHost,
            2 => NameKind::NetbiosDomain,
            3 => NameKind::Host,
            4 => NameKind::Domain,
            5 => NameKind::Forest,
            _ => continue,
        };
        if seen.contains(&kind) {
            continue;
        }
        seen.push(kind);

        let units: Vec<u16> = value
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        names.extend(HostName::new(
            kind,
            NameSource::Ntlm,
            &String::from_utf16_lossy(&units),
        ));
    }
    names
}

/// The `Server` value of an RTSP response.
///
/// The HTTP reader declines a `RTSP/1.0` status line. Twelve imported rules
/// anchor on this value: `GStreamer RTSP server`, `Wowza Streaming Engine
/// 4.7.7`, `AvigilonOnvifNvt/2.6.0.130`.
///
/// [`None`] for a reply that is not RTSP, or that names no server.
#[must_use]
pub(super) fn rtsp_server(stream: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(stream).ok()?;
    if !text.starts_with("RTSP/") {
        return None;
    }

    text.lines()
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("server")
                .then(|| value.trim().to_string())
        })
        .filter(|value| !value.is_empty())
}

/// The device types a WS-Discovery responder claims.
///
/// A `ProbeMatches` reply is SOAP, and the element worth reading is `Types`: a
/// space-separated list of qualified names saying what kind of thing answered.
/// A Windows machine says `Device Computer`, a printer says `PrintDeviceType`,
/// and a camera says `NetworkVideoTransmitter`.
///
/// Namespace prefixes are stripped, since responders choose their own:
/// `wsdp:Device pub:Computer` and `a:Device b:Computer` both read as
/// `Device Computer`.
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
/// Does not resolve namespaces, handle CDATA, or decode entities.
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

    /// A stated length past the end is a truncated reply, still read.
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

    /// A Windows machine's ProbeMatches, cut to the element read, with two
    /// different prefixes.
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

    /// A Query echoed back is not a Willing, and a length past the datagram is
    /// refused.
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

    /// The challenge reply still names the service.
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

    /// A master's answer is recognised whatever servers it lists, including
    /// none but the terminator.
    #[test]
    fn a_steam_master_list_is_recognised_as_one() {
        let mut reply = vec![0xFF, 0xFF, 0xFF, 0xFF, b'f', b'\n'];
        reply.extend_from_slice(&[192, 0, 2, 7, 0x69, 0x87]);
        reply.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        assert_eq!(steam_master_list(&reply), Some("server list"));
        assert_eq!(steam_master_list(&reply[..6]), Some("server list"));
    }

    /// A Source info reply shares the header and is not a master's list, and a
    /// list cut mid-entry is not a whole reply.
    #[test]
    fn a_datagram_that_is_not_a_whole_master_list_yields_nothing() {
        assert!(steam_master_list(b"\xff\xff\xff\xffI\x11name\x00").is_none());
        assert!(steam_master_list(b"\xff\xff\xff\xfff\n\xc0\x00\x02").is_none());
        assert!(steam_master_list(b"").is_none());
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

    /// Without the magic it is not a pong.
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

    /// An accepted RPC reply header with an empty verifier, then `body`.
    fn rpc_reply(accept_status: u32, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x7a6f6e64u32.to_be_bytes()); // xid
        out.extend_from_slice(&1u32.to_be_bytes()); // REPLY
        out.extend_from_slice(&0u32.to_be_bytes()); // MSG_ACCEPTED
        out.extend_from_slice(&0u32.to_be_bytes()); // verifier flavour
        out.extend_from_slice(&0u32.to_be_bytes()); // verifier length
        out.extend_from_slice(&accept_status.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// A pre-login answer names the build; one cut short, or whose version
    /// option points past its end, names nothing.
    #[test]
    fn a_prelogin_answer_names_its_build_and_a_short_one_nothing() {
        let answer: &[u8] = b"\x04\x01\x00\x1a\x00\x00\x01\x00\
            \x00\x00\x0b\x00\x06\x01\x00\x11\x00\x01\xff\x10\x00\x10\x7a\x00\x00\x02";
        assert_eq!(
            tds_version(answer).as_deref(),
            Some("Microsoft SQL Server 16.0.4218")
        );
        for end in 0..answer.len() {
            assert!(tds_version(&answer[..end]).is_none(), "cut at {end}");
        }
        let mut pointing_past = answer.to_vec();
        pointing_past[10] = 0x40;
        assert!(tds_version(&pointing_past).is_none());
    }

    /// Over TCP the same reply arrives behind record marks, here split in two
    /// fragments, and reads as the datagram would once they are taken out.
    #[test]
    fn a_record_marked_reply_reads_as_its_datagram() {
        let mut body = 1u32.to_be_bytes().to_vec();
        for field in [100000u32, 2, 6, 111] {
            body.extend_from_slice(&field.to_be_bytes());
        }
        body.extend_from_slice(&0u32.to_be_bytes());
        let reply = rpc_reply(0, &body);

        let (first, last) = reply.split_at(10);
        let mut stream = (first.len() as u32).to_be_bytes().to_vec();
        stream.extend_from_slice(first);
        stream.extend_from_slice(&(0x8000_0000 | last.len() as u32).to_be_bytes());
        stream.extend_from_slice(last);

        assert_eq!(rpc_record(&stream).as_deref(), Some(reply.as_slice()));
        assert_eq!(
            crate::fingerprint::extract::from_stream(111, &stream),
            ["portmapper 2 tcp 111"]
        );
        assert!(
            rpc_record(&stream[..stream.len() - 1]).is_none(),
            "a stream that ends inside its last fragment is not a record"
        );
    }

    #[test]
    fn a_program_dump_names_the_services_and_their_ports() {
        let mut body = Vec::new();
        for (program, version, protocol, port) in [
            (100000u32, 2u32, 17u32, 111u32),
            (100003, 3, 6, 2049),
            (100005, 3, 17, 20048),
        ] {
            body.extend_from_slice(&1u32.to_be_bytes());
            for field in [program, version, protocol, port] {
                body.extend_from_slice(&field.to_be_bytes());
            }
        }
        body.extend_from_slice(&0u32.to_be_bytes());

        assert_eq!(
            rpc_program_dump(&rpc_reply(0, &body)).as_deref(),
            Some("portmapper 2 udp 111, nfs 3 tcp 2049, mountd 3 udp 20048")
        );
    }

    /// An unnamed program keeps its number.
    #[test]
    fn an_unnamed_program_keeps_its_number() {
        let mut body = 1u32.to_be_bytes().to_vec();
        for field in [391_002u32, 2, 6, 39_845] {
            body.extend_from_slice(&field.to_be_bytes());
        }
        body.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            rpc_program_dump(&rpc_reply(0, &body)).as_deref(),
            Some("391002 2 tcp 39845")
        );
    }

    /// The mismatch reply carries the supported range.
    #[test]
    fn a_version_mismatch_yields_the_range_the_server_supports() {
        let mut body = 3u32.to_be_bytes().to_vec();
        body.extend_from_slice(&4u32.to_be_bytes());
        assert_eq!(
            rpc_version_range(&rpc_reply(2, &body)).as_deref(),
            Some("versions 3-4")
        );
    }

    /// A server not running the program answers with another status and no
    /// range.
    #[test]
    fn anything_but_a_mismatch_yields_no_range() {
        assert!(rpc_version_range(&rpc_reply(0, &[])).is_none());
        assert!(rpc_version_range(&rpc_reply(1, &[])).is_none());
        assert!(rpc_version_range(b"").is_none());
        assert!(rpc_program_dump(&rpc_reply(1, &[])).is_none());
    }

    /// A call echoed back is not a reply, and a chain past the datagram is
    /// refused.
    #[test]
    fn an_rpc_call_is_not_read_as_a_reply() {
        let mut call = 0x7a6f6e64u32.to_be_bytes().to_vec();
        call.extend_from_slice(&0u32.to_be_bytes()); // CALL
        call.extend_from_slice(&[0u8; 32]);
        assert!(rpc_program_dump(&call).is_none());

        let mut truncated = rpc_reply(0, &1u32.to_be_bytes());
        truncated.truncate(truncated.len() - 1);
        assert!(rpc_program_dump(&truncated).is_none());
    }

    /// An IPMI response with `support` and `status` in the two bytes read.
    fn ipmi(support: u8, status: u8) -> Vec<u8> {
        let mut out = vec![0x06, 0x00, 0xFF, 0x07];
        out.extend_from_slice(&[0u8; 9]); // v1.5 session header
        out.push(8); // message length
        out.extend_from_slice(&[0x81, 0x1C, 0x00, 0x20, 0x00, 0x38]); // IPMB header
        out.push(0x00); // completion code, success
        out.push(0x01); // channel number
        out.push(support);
        out.push(status);
        out
    }

    #[test]
    fn a_bmc_states_its_version_and_how_it_may_be_logged_into() {
        assert_eq!(
            ipmi_auth_capabilities(&ipmi(0b0000_0000, 0b0000_0011)).as_deref(),
            Some("IPMI-1.5 anonymous-login null-user")
        );
        assert_eq!(
            ipmi_auth_capabilities(&ipmi(0b1000_0000, 0b0000_0010)).as_deref(),
            Some("IPMI-2.0 null-user")
        );
    }

    /// A controller with neither weakness names only its version; bit 2 is not
    /// reported.
    #[test]
    fn a_bmc_that_requires_a_real_user_says_only_what_it_speaks() {
        assert_eq!(
            ipmi_auth_capabilities(&ipmi(0b1000_0000, 0b0000_0100)).as_deref(),
            Some("IPMI-2.0")
        );
    }

    /// A non-zero completion code is a refusal.
    #[test]
    fn a_refused_ipmi_command_yields_nothing() {
        let mut refused = ipmi(0b1000_0000, 0b0000_0001);
        refused[20] = 0xC1; // invalid command
        assert!(ipmi_auth_capabilities(&refused).is_none());

        let mut wrong_class = ipmi(0b1000_0000, 0b0000_0001);
        wrong_class[3] = 0x06; // ASF rather than IPMI
        assert!(ipmi_auth_capabilities(&wrong_class).is_none());
        assert!(ipmi_auth_capabilities(b"").is_none());
    }

    /// A mode 6 response carrying `data` as its variables.
    fn control_response(data: &str) -> Vec<u8> {
        let mut out = vec![0x16, 0x82]; // VN 2 mode 6; response, opcode 2
        out.extend_from_slice(&1u16.to_be_bytes()); // sequence
        out.extend_from_slice(&0u16.to_be_bytes()); // status
        out.extend_from_slice(&0u16.to_be_bytes()); // association id
        out.extend_from_slice(&0u16.to_be_bytes()); // offset
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data.as_bytes());
        out
    }

    #[test]
    fn a_control_response_yields_the_variables_a_daemon_reports() {
        const VARS: &str =
            r#"version="ntpd 4.2.8p15@1.3728-o", processor="x86_64", system="Linux/6.1.0""#;
        assert_eq!(
            ntp_control_variables(&control_response(VARS)).as_deref(),
            Some(VARS)
        );
    }

    /// Line breaks are folded; spacing around commas is kept.
    #[test]
    fn line_breaks_are_folded_and_nothing_else_is_touched() {
        let wrapped =
            "version=\"ntpd 4.2.8p15\",\r\nprocessor=\"x86_64\",\r\nsystem=\"Linux/6.1.0\"";
        assert_eq!(
            ntp_control_variables(&control_response(wrapped)).as_deref(),
            Some("version=\"ntpd 4.2.8p15\", processor=\"x86_64\", system=\"Linux/6.1.0\"")
        );
    }

    /// The ordinary client reply: forty-eight bytes of timestamps.
    #[test]
    fn a_client_mode_reply_is_not_a_control_response() {
        let mut client = vec![0x24];
        client.extend_from_slice(&[0u8; 47]);
        assert!(ntp_control_variables(&client).is_none());

        // A control *request* echoed back is not a response either.
        assert!(ntp_control_variables(&[0x16, 0x02, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]).is_none());
        assert!(ntp_control_variables(b"").is_none());
    }

    /// A binding response carrying `attributes` after the header.
    fn binding_response(attributes: &[u8]) -> Vec<u8> {
        let mut out = 0x0101u16.to_be_bytes().to_vec();
        out.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        out.extend_from_slice(&0x2112_A442u32.to_be_bytes());
        out.extend_from_slice(b"zond-scan-01");
        out.extend_from_slice(attributes);
        out
    }

    #[test]
    fn a_binding_response_yields_the_software_that_sent_it() {
        let name = b"Coturn-4.5.2";
        let mut attributes = 0x8022u16.to_be_bytes().to_vec();
        attributes.extend_from_slice(&(name.len() as u16).to_be_bytes());
        attributes.extend_from_slice(name);
        assert_eq!(
            stun_binding(&binding_response(&attributes)).as_deref(),
            Some("Coturn-4.5.2")
        );
    }

    /// A server naming no software is still STUN.
    #[test]
    fn a_binding_response_without_software_is_still_stun() {
        // A mapped address, which is not read.
        let mut attributes = 0x0020u16.to_be_bytes().to_vec();
        attributes.extend_from_slice(&8u16.to_be_bytes());
        attributes.extend_from_slice(&[0x00, 0x01, 0x2B, 0x3C, 0x5E, 0x12, 0xA4, 0x43]);
        assert_eq!(
            stun_binding(&binding_response(&attributes)).as_deref(),
            Some("stun")
        );
    }

    #[test]
    fn a_datagram_without_the_magic_cookie_is_not_stun() {
        let mut wrong = binding_response(&[]);
        wrong[4] = 0x00;
        assert!(stun_binding(&wrong).is_none());
        assert!(stun_binding(b"").is_none());
    }

    /// An ISAKMP reply whose payload chain starts with `first` and carries
    /// `payloads` as (type, body) pairs.
    fn isakmp(payloads: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = b"initiator".to_vec();
        out.truncate(8);
        out.extend_from_slice(b"responder"); // a non-zero responder cookie
        out.truncate(16);
        out.push(payloads.first().map_or(0, |(kind, _)| *kind));
        out.extend_from_slice(&[0x10, 0x02, 0x00]); // version, exchange, flags
        out.extend_from_slice(&0u32.to_be_bytes()); // message id
        out.extend_from_slice(&0u32.to_be_bytes()); // length, not read

        for (index, (_, body)) in payloads.iter().enumerate() {
            let next = payloads.get(index + 1).map_or(0, |(kind, _)| *kind);
            out.push(next);
            out.push(0);
            out.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
            out.extend_from_slice(body);
        }
        out
    }

    #[test]
    fn a_gateway_is_named_by_the_vendor_ids_it_announces() {
        let reply = isakmp(&[
            (1, vec![0u8; 8]), // an SA payload
            (13, vec![0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45]),
            (13, vec![0xaf, 0xca, 0xd7, 0x13]),
        ]);
        assert_eq!(
            ike_response(&reply).as_deref(),
            Some("4a131c8107035845 afcad713")
        );
    }

    /// A Notify still proves an IKE daemon.
    #[test]
    fn a_notify_is_a_reply_rather_than_a_refusal_to_answer() {
        assert_eq!(
            ike_response(&isakmp(&[(11, vec![0u8; 12])])).as_deref(),
            Some("notify")
        );
    }

    /// Our own probe echoed back (zero responder cookie) is not a gateway.
    #[test]
    fn a_request_echoed_back_is_not_a_response() {
        let mut echoed = isakmp(&[(13, vec![0xaa; 8])]);
        echoed[8..16].fill(0);
        assert!(ike_response(&echoed).is_none());
        assert!(ike_response(b"too short").is_none());
    }

    /// A zero-length body is an acknowledgement, not an answer.
    ///
    /// A concentrator sends one for a repeated tunnel request, and a scan sends
    /// the probe twice.
    #[test]
    fn a_zero_length_body_is_an_acknowledgement_and_not_an_answer() {
        let zlb = [0xC8u8, 0x02, 0x00, 0x0C, 0x7A, 0x6F, 0, 0, 0, 0, 0, 1];
        assert!(l2tp_control(&zlb).is_none());
    }

    /// An SCCRP as xl2tpd sends it: the control header, then a Vendor Name
    /// and a Host Name attribute.
    fn sccrp(vendor: &str, host: &str) -> Vec<u8> {
        let mut message = vec![0xC8u8, 0x02, 0x00, 0x00, 0x7A, 0x6F, 0, 0, 0, 0, 0, 1];
        // Message Type = 2, SCCRP.
        message.extend_from_slice(&[0x80, 0x08, 0, 0, 0, 0, 0, 2]);
        for (attribute, value) in [(8u8, vendor), (7, host)] {
            let length = u8::try_from(6 + value.len()).expect("a short value");
            message.extend_from_slice(&[0x00, length, 0, 0, 0, attribute]);
            message.extend_from_slice(value.as_bytes());
        }
        message
    }

    /// The Host Name attribute becomes a host name, not corpus text.
    #[test]
    fn the_host_name_is_a_name_of_the_host_and_not_text() {
        let reply = sccrp("xelerance.com", "lns01.example.net");

        assert_eq!(
            l2tp_control(&reply).as_deref(),
            Some("vendor=xelerance.com")
        );
        assert_eq!(
            l2tp_host_name(&reply),
            HostName::new(NameKind::Host, NameSource::L2tp, "lns01.example.net")
        );
        assert_eq!(l2tp_host_name(&sccrp("Microsoft", " ")), None);
    }

    /// A control message that carries attributes but names neither the vendor
    /// nor the host is still a daemon answering.
    #[test]
    fn a_control_message_naming_nothing_is_still_l2tp() {
        let mut message = vec![0xC8u8, 0x02, 0x00, 0x14, 0x7A, 0x6F, 0, 0, 0, 0, 0, 1];
        // Message Type = 4, StopCCN.
        message.extend_from_slice(&[0x80, 0x08, 0, 0, 0, 0, 0, 4]);
        assert_eq!(l2tp_control(&message).as_deref(), Some("l2tp"));
    }

    /// No reader panics on arbitrary input.
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
            let _ = steam_master_list(bytes);
            let _ = raknet_pong(bytes);
            let _ = coap_payload(bytes);
            let _ = rpc_program_dump(bytes);
            let _ = rpc_version_range(bytes);
            let _ = ipmi_auth_capabilities(bytes);
            let _ = ntp_control_variables(bytes);
            let _ = stun_binding(bytes);
            let _ = ike_response(bytes);
            let _ = kerberos_error(bytes);
            let _ = l2tp_control(bytes);
            let _ = l2tp_host_name(bytes);
        }
    }
}
