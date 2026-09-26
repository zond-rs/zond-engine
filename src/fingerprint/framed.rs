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
/// Programs are named where the number is one of the handful worth naming, and
/// left as their number where it is not. That is the identifying half: a host
/// running `nfs` and `mountd` is a file server, and the ports they are on are
/// very often not the registered ones.
///
/// [`None`] for a reply that is not an accepted RPC response, or whose record
/// chain runs past the datagram.
#[must_use]
pub(super) fn rpc_program_dump(datagram: &[u8]) -> Option<String> {
    /// The programs worth spelling. Everything else keeps its number, which is
    /// still what somebody would look up.
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

        // A portmapper on a busy host registers dozens; the identifying part is
        // which programs, not how many times each is bound.
        if entries.len() >= 64 {
            break;
        }
    }

    (!entries.is_empty()).then(|| entries.join(", "))
}

/// What versions of a program an RPC server says it supports.
///
/// The probe calls a version nothing implements, so an accepted reply is a
/// mismatch carrying the range the server does support. That says more than a
/// success would: a call that worked would confirm only the version it was made
/// with.
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
/// its length. What is left once the marks are gone is the message a datagram
/// would have carried, so the readers written for UDP read it unchanged.
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

/// The body of an RPC reply that was accepted and succeeded.
fn accepted_rpc_reply(datagram: &[u8]) -> Option<&[u8]> {
    match rpc_reply_status(datagram)? {
        (0, body) => Some(body),
        _ => None,
    }
}

/// The accept status of an RPC reply and whatever follows it.
///
/// Walks the header rather than indexing past it, because the verifier between
/// the reply status and the accept status is variable length and a server may
/// send one.
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
/// with no user name and whether the null user is enabled. Either is worth
/// reporting: a management controller that authenticates nobody is reachable by
/// anybody who can route to it.
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
    // A non-zero completion code means the BMC refused the command rather than
    // answering it, and the bytes after it mean nothing.
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
    // Bit 2 says non-null user names are enabled, which is the ordinary state
    // of a controller somebody configured. It is not reported: it says nothing
    // a reader would act on, and `non-null-user` contains `null-user`, so a
    // rule reading the second matched a controller that had neither problem.

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
/// This is what the corpus's largest block of otherwise unreachable rules is
/// written against. The ordinary client probe on this port draws a packet of
/// timestamps with nothing in it to read, which leaves them unreached: the
/// field is not a decoding problem, the client probe asks the wrong question.
///
/// Line breaks are folded to spaces and nothing else is touched. A daemon wraps
/// this text for a terminal, and the imported rules match across the wrap with
/// `.*`, which does not cross a newline. Spacing around the commas is left
/// exactly as sent, because the rules distinguish products by it.
///
/// [`None`] for a reply that is not a mode 6 response, or that carries no data.
/// A response split across several packets is read as far as the first, which
/// is where a daemon puts these three variables.
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

    // A run of line-break characters becomes one space, not one space each: a
    // daemon wraps with CRLF, and turning that into two spaces would put a gap
    // where a rule expects `", processor=`.
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
/// A binding response carries attributes, and `SOFTWARE` is the one that names
/// the implementation. Most servers send it; the ones that do not are still
/// identified as STUN by the reply's own shape, which is what the second return
/// covers.
///
/// The mapped address is deliberately not read. It is the address the *client*
/// appears to come from, which says something about the network between here
/// and there rather than about the host being scanned.
///
/// [`None`] for a datagram that is not a binding response. The magic cookie is
/// what establishes that: without it this is RFC 3489 and the type field alone
/// is too weak to key on.
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
/// A gateway answers a proposal with its own payload chain, and the Vendor ID
/// payloads in it are the fingerprint: an implementation puts a fixed value
/// there, usually a hash of its own name and version, and no two products send
/// the same one. They are returned as hex, lowercase and space separated, which
/// is what a rule can be written against.
///
/// A responder that liked none of the proposal answers with a Notify instead.
/// That is a reply too, and it still proves an IKE daemon is listening, so it
/// comes back named rather than dropped.
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
    // The responder cookie is zero in a request and set in every reply, which
    // is what separates an answer from this engine's own probe echoed back.
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
/// [`kerberos_error`].
const PROBE_REALM: &str = "ZOND-SCAN";

/// What a Kerberos KDC says about a request it cannot serve.
///
/// The probe asks for a principal in a realm nothing serves, and the reply is a
/// `KRB-ERROR`. Three of its fields are worth reading: the error code, the
/// human text where the implementation sends one, and the realm.
///
/// ```text
/// krb-error 6 CLIENT_NOT_FOUND
/// ```
///
/// ## Why the realm is usually absent
///
/// A realm has to be named in the request and a scanner does not know the
/// target's, so the probe invents one. Measured against MIT krb5 on Debian 12:
/// the KDC repeats that invented realm back in both `crealm` and `realm`, so
/// what looks like a discovered domain is this engine's own guess reflected.
///
/// The realm is therefore reported only when it differs from
/// [`PROBE_REALM`]. RFC 4120 has a KDC that serves a different realm answer
/// `KDC_ERR_WRONG_REALM` and name the right one, and that case is worth the
/// whole probe: on a domain controller it is the Active Directory domain, from
/// one unauthenticated datagram. It was not reproduced here, MIT answered
/// `KDC_ERR_C_PRINCIPAL_UNKNOWN` for a realm it does not serve, so the branch
/// is written from the specification rather than from a measurement.
///
/// [`None`] for anything that is not a `KRB-ERROR`.
#[must_use]
pub(super) fn kerberos_error(datagram: &[u8]) -> Option<String> {
    /// `[APPLICATION 30]`, which is what a `KRB-ERROR` is tagged with.
    const KRB_ERROR: u8 = 0x7E;

    if *datagram.first()? != KRB_ERROR {
        return None;
    }
    // The application tag wraps a SEQUENCE, and the fields are context-tagged
    // inside it.
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
            // realm, the service realm, a GeneralString.
            0xA9 => realm = der_value(value).and_then(|v| std::str::from_utf8(v).ok()),
            // e-text, which MIT fills in and which names the implementation.
            0xAB => text = der_value(value).and_then(|v| std::str::from_utf8(v).ok()),
            _ => {}
        }
        at += next;
    }

    let code = code?;
    let mut said = format!("krb-error {code}");
    if let Some(realm) = realm.filter(|realm| *realm != PROBE_REALM) {
        said.push_str(&format!(" realm={realm}"));
    }
    if let Some(text) = text.filter(|text| !text.is_empty()) {
        said.push(' ');
        said.push_str(text);
    }
    Some(said)
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
/// An `SCCRQ` draws an `SCCRP`, and the reply carries the two attributes worth
/// reading: the vendor name, which identifies the implementation, and the host
/// name, which is the machine's own.
///
/// ```text
/// vendor=xelerance.com host=lima-deb12
/// ```
///
/// Measured against `xl2tpd` on Debian 12, which fills in both. Either may be
/// absent, and a reply carrying neither still says an L2TP daemon answered.
///
/// [`None`] for a datagram that is not a control message, or whose attribute
/// chain runs past its end.
#[must_use]
pub(super) fn l2tp_control(datagram: &[u8]) -> Option<String> {
    /// The first byte of a control message: type and length bits set, and the
    /// version in the low nibble of the second.
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
    let mut vendor = None;
    let mut host = None;
    let mut attributes = 0usize;
    while at + ATTRIBUTE_HEADER_BYTES <= datagram.len() {
        attributes += 1;
        // The top six bits are flags and the low ten are the length, which
        // counts this header along with the value.
        let length = (u16::from_be_bytes([datagram[at], datagram[at + 1]]) & 0x03FF) as usize;
        if length < ATTRIBUTE_HEADER_BYTES {
            return None;
        }
        let attribute = u16::from_be_bytes([datagram[at + 4], datagram[at + 5]]);
        let value = datagram.get(at + ATTRIBUTE_HEADER_BYTES..at + length)?;

        let text = |value: &[u8]| {
            std::str::from_utf8(value)
                .ok()
                .map(|text| text.trim().to_string())
                .filter(|text| !text.is_empty())
        };
        match attribute {
            VENDOR_NAME => vendor = text(value),
            HOST_NAME => host = text(value),
            _ => {}
        }
        at += length;
    }

    // A control message carrying no attributes at all is a zero-length body,
    // which acknowledges a message rather than answering one. A concentrator
    // sends it for a repeat of a tunnel request it has already seen, so a scan
    // that probes this port twice gets the real answer once and an
    // acknowledgement after. Reading that as a service would name L2TP from a
    // datagram that says nothing.
    if attributes == 0 {
        return None;
    }

    let mut said = Vec::new();
    if let Some(vendor) = vendor {
        said.push(format!("vendor={vendor}"));
    }
    if let Some(host) = host {
        said.push(format!("host={host}"));
    }
    match said.is_empty() {
        // Some other control message: a refusal names no vendor and is still an
        // L2TP daemon answering.
        true => Some("l2tp".to_string()),
        false => Some(said.join(" ")),
    }
}

/// The three strings an SMB1 session setup answers with.
///
/// A server that accepts a session names the operating system it runs, the LAN
/// manager dialect it speaks, and the domain it belongs to:
///
/// ```text
/// Windows 6.1
/// Samba 4.17.12-Debian
/// ZONDLAB
/// ```
///
/// Each is returned on its own, because the corpus rules are anchored at both
/// ends of one field: `^Windows 6.1$` matches the first of those and nothing
/// that contains it.
///
/// This is what eighty-five imported rules are written against. A probe that
/// stops at a protocol negotiate leaves every one of them unread, since a
/// negotiate response carries none of these: they arrive only in answer to a
/// session setup, which is a second message on the same connection.
///
/// ## Why this reads a stream rather than a datagram
///
/// The reply is several SMB messages back to back, each behind a four-byte
/// NetBIOS length. Both of the probe's messages are answered, so the stream
/// holds a negotiate response and then the session setup, and this walks to the
/// second.
///
/// Empty where no session setup was accepted, which includes a server that
/// refused the null session and one that speaks no SMB1 at all. Windows has
/// shipped with SMB1 off since 2017 and Samba since 4.11, so silence here is
/// the ordinary answer from anything current.
#[must_use]
pub(super) fn smb_session_setup(stream: &[u8]) -> Vec<String> {
    /// `SESSION_SETUP_ANDX`.
    const SESSION_SETUP: u8 = 0x73;
    /// The flags2 bit saying the strings are UTF-16.
    const UNICODE: u16 = 0x8000;
    /// The NetBIOS session header before each SMB message.
    const NBSS_HEADER_BYTES: usize = 4;
    const SMB_HEADER_BYTES: usize = 32;

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
        // The parameter block: a word count, that many words, then a byte count.
        let words = message[SMB_HEADER_BYTES] as usize;
        let bytes_at = SMB_HEADER_BYTES + 1 + words * 2;
        let (Some(low), Some(high)) = (message.get(bytes_at), message.get(bytes_at + 1)) else {
            continue;
        };
        let count = u16::from_le_bytes([*low, *high]) as usize;
        let Some(field) = message.get(bytes_at + 2..bytes_at + 2 + count) else {
            continue;
        };

        let names = match unicode {
            true => utf16_strings(field),
            false => field
                .split(|byte| *byte == 0)
                .map(|part| String::from_utf8_lossy(part).trim().to_string())
                .filter(|part| !part.is_empty())
                .collect(),
        };
        if !names.is_empty() {
            return names;
        }
    }
    Vec::new()
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
/// The first is the negotiate response (MS-SMB2 2.2.4): the dialect the server
/// chose from the ones offered, and whether it insists on signing. A server
/// that does not is one whose sessions can be relayed to it.
///
/// The second is the `Version` of the NTLM challenge the session setup draws
/// (MS-NLMP 2.2.1.2), which Windows fills with its own major and minor version
/// and build before anything is authenticated. It is left out where the build
/// is zero, which is what Samba sends beside a version it does not run, so
/// that a Samba server is not read as a Windows release.
///
/// The challenge also names the machine and its domain, and those are not
/// returned. They are the host's names, which a report masks where it is asked
/// to, and a service's description is not where it looks for them.
///
/// Empty for a stream that holds no SMB2 message.
#[must_use]
pub(super) fn smb2_exchange(stream: &[u8]) -> Vec<String> {
    const NBSS_HEADER_BYTES: usize = 4;
    const HEADER_BYTES: usize = 64;
    const NEGOTIATE: u16 = 0;
    const SESSION_SETUP: u16 = 1;
    /// The dialect a server answers an SMB1 negotiate with when it wants the
    /// client to negotiate again in SMB2, which names no dialect it speaks.
    const WILDCARD: u16 = 0x02FF;
    const SIGNING_REQUIRED: u16 = 0x0002;

    let mut texts = Vec::new();
    let mut at = 0;
    while at + NBSS_HEADER_BYTES <= stream.len() {
        let length =
            u32::from_be_bytes([0, stream[at + 1], stream[at + 2], stream[at + 3]]) as usize;
        let Some(message) = stream.get(at + NBSS_HEADER_BYTES..at + NBSS_HEADER_BYTES + length)
        else {
            break;
        };
        at += NBSS_HEADER_BYTES + length;

        if !message.starts_with(b"\xfeSMB") || message.len() < HEADER_BYTES + 8 {
            continue;
        }
        let word = |at: usize| u16::from_le_bytes([message[at], message[at + 1]]);
        let status = u32::from_le_bytes([message[8], message[9], message[10], message[11]]);
        let body = HEADER_BYTES;

        match word(12) {
            NEGOTIATE if status == 0 => {
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
            // The challenge comes back under a status saying more is needed,
            // which is the answer and not a refusal.
            SESSION_SETUP => {
                let offset = word(body + 4) as usize;
                let length = word(body + 6) as usize;
                if let Some(version) = message
                    .get(offset..offset + length)
                    .and_then(ntlm_challenge_version)
                {
                    texts.push(version);
                }
            }
            _ => {}
        }
    }
    texts
}

/// The Windows version an NTLM challenge inside `token` states, as
/// `Windows 10.0 Build 20348`.
///
/// The challenge is found by its signature rather than by unwrapping the
/// SPNEGO around it, which a server may or may not send. [`None`] where there
/// is none, where it carries no version, or where the build is zero.
fn ntlm_challenge_version(token: &[u8]) -> Option<String> {
    const CHALLENGE: &[u8] = b"NTLMSSP\0\x02\0\0\0";
    /// The flag saying the `Version` field is filled in.
    const NEGOTIATE_VERSION: u32 = 0x0200_0000;
    const VERSION_AT: usize = 48;

    let start = token
        .windows(CHALLENGE.len())
        .position(|window| window == CHALLENGE)?;
    let message = &token[start..];
    let flags = u32::from_le_bytes(message.get(20..24)?.try_into().ok()?);
    if flags & NEGOTIATE_VERSION == 0 {
        return None;
    }
    let version = message.get(VERSION_AT..VERSION_AT + 4)?;
    let build = u16::from_le_bytes([version[2], version[3]]);
    (build != 0).then(|| format!("Windows {}.{} Build {build}", version[0], version[1]))
}

/// The NUL-terminated UTF-16 strings in `field`, in order.
///
/// A server may pad to an even offset before the first, so a leading odd byte is
/// skipped rather than folded into the text.
fn utf16_strings(field: &[u8]) -> Vec<String> {
    let field = match field.first() {
        Some(0) if field.len() % 2 == 1 => &field[1..],
        _ => field,
    };

    let units: Vec<u16> = field
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();

    units
        .split(|unit| *unit == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf16_lossy(part).trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

/// The `Server` value of an RTSP response.
///
/// An `OPTIONS` request draws a reply whose status line is `RTSP/1.0` rather
/// than `HTTP/1.1`, so the HTTP reader declines it, and the header carries what
/// twelve imported rules are anchored on: `GStreamer RTSP server`,
/// `Wowza Streaming Engine 4.7.7`, `AvigilonOnvifNvt/2.6.0.130`. Cameras,
/// recorders and streaming servers, which is most of what answers this port.
///
/// The value alone rather than the response, for the reason every other rule of
/// this shape has: they are anchored at both ends of the header value and match
/// nothing that merely contains it.
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

    /// A program number nothing names keeps its number, which is still what
    /// somebody would look up.
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

    /// The probe calls a version nothing implements, so the useful reply is the
    /// mismatch carrying the range the server does support.
    #[test]
    fn a_version_mismatch_yields_the_range_the_server_supports() {
        let mut body = 3u32.to_be_bytes().to_vec();
        body.extend_from_slice(&4u32.to_be_bytes());
        assert_eq!(
            rpc_version_range(&rpc_reply(2, &body)).as_deref(),
            Some("versions 3-4")
        );
    }

    /// A server that does not run the program at all answers with a different
    /// status, and there is no range in it to read.
    #[test]
    fn anything_but_a_mismatch_yields_no_range() {
        assert!(rpc_version_range(&rpc_reply(0, &[])).is_none());
        assert!(rpc_version_range(&rpc_reply(1, &[])).is_none());
        assert!(rpc_version_range(b"").is_none());
        assert!(rpc_program_dump(&rpc_reply(1, &[])).is_none());
    }

    /// A call echoed back by a reflector is not a reply, and a chain that runs
    /// past the datagram is refused rather than read through.
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

    /// A controller with neither weakness names its version and stops. Bit 2 is
    /// the ordinary state and is not reported, which is also what keeps
    /// `non-null-user` from being read as `null-user`.
    #[test]
    fn a_bmc_that_requires_a_real_user_says_only_what_it_speaks() {
        assert_eq!(
            ipmi_auth_capabilities(&ipmi(0b1000_0000, 0b0000_0100)).as_deref(),
            Some("IPMI-2.0")
        );
    }

    /// A completion code the BMC set is a refusal, and the bytes behind it mean
    /// nothing.
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

    /// A daemon wraps this text for a terminal. The imported rules match across
    /// the wrap with `.*`, which does not cross a newline, so the breaks are
    /// folded and the spacing around the commas is left alone.
    #[test]
    fn line_breaks_are_folded_and_nothing_else_is_touched() {
        let wrapped =
            "version=\"ntpd 4.2.8p15\",\r\nprocessor=\"x86_64\",\r\nsystem=\"Linux/6.1.0\"";
        assert_eq!(
            ntp_control_variables(&control_response(wrapped)).as_deref(),
            Some("version=\"ntpd 4.2.8p15\", processor=\"x86_64\", system=\"Linux/6.1.0\"")
        );
    }

    /// The ordinary client reply on this port, which is what a client-mode probe
    /// draws: forty-eight bytes of timestamps and nothing to read.
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

    /// A server naming no software is still STUN, which the magic cookie and the
    /// response type together establish.
    #[test]
    fn a_binding_response_without_software_is_still_stun() {
        // A mapped address, which is read for nothing: it describes the network
        // between here and there, not the host.
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

    /// A responder that liked none of the proposal still proves an IKE daemon
    /// is listening.
    #[test]
    fn a_notify_is_a_reply_rather_than_a_refusal_to_answer() {
        assert_eq!(
            ike_response(&isakmp(&[(11, vec![0u8; 12])])).as_deref(),
            Some("notify")
        );
    }

    /// This engine's own probe echoed back carries a zero responder cookie, and
    /// a reflector must not be read as a gateway.
    #[test]
    fn a_request_echoed_back_is_not_a_response() {
        let mut echoed = isakmp(&[(13, vec![0xaa; 8])]);
        echoed[8..16].fill(0);
        assert!(ike_response(&echoed).is_none());
        assert!(ike_response(b"too short").is_none());
    }

    /// A zero-length body is an acknowledgement, not an answer.
    ///
    /// A concentrator sends one for a repeat of a tunnel request it has already
    /// seen, and a scan sends the same probe twice: once to establish the port
    /// is open, once to identify it. Reading these twelve bytes as a service
    /// would name L2TP from a datagram that says nothing, and a scan of xl2tpd
    /// would report the port with no product.
    #[test]
    fn a_zero_length_body_is_an_acknowledgement_and_not_an_answer() {
        let zlb = [0xC8u8, 0x02, 0x00, 0x0C, 0x7A, 0x6F, 0, 0, 0, 0, 0, 1];
        assert!(l2tp_control(&zlb).is_none());
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
            let _ = rpc_program_dump(bytes);
            let _ = rpc_version_range(bytes);
            let _ = ipmi_auth_capabilities(bytes);
            let _ = ntp_control_variables(bytes);
            let _ = stun_binding(bytes);
            let _ = ike_response(bytes);
            let _ = kerberos_error(bytes);
            let _ = l2tp_control(bytes);
        }
    }
}
