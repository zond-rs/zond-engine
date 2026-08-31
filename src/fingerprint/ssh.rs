// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # SSH analyzer
//!
//! The first **active** analyzer: where the banner-regex and TLS-cert analyzers
//! read data the transport already captured, this one speaks the protocol
//! itself. Its [`collect`](Analyzer::collect) opens its own connection, performs
//! the SSH identification-string exchange, and reads the server's
//! `SSH_MSG_KEXINIT`; its [`analyze`](Analyzer::analyze) parses that packet's
//! algorithm name-lists. It is the reference for every active analyzer to come
//! (JARM, the nerva binary/ICS handlers): probe on the reactor, parse off it.
//!
//! ## What it adds over the banner
//!
//! The version banner (`SSH-2.0-OpenSSH_9.6p1 …`) is already grabbed on first
//! contact and matched by the banner analyzer, which supplies product/version.
//! Completing the exchange adds two things the banner cannot:
//!
//! * **Protocol confirmation.** A completed version + `KEXINIT` exchange is
//!   strong proof the port really speaks SSH, not merely that it emitted a line
//!   beginning `SSH-`. Reported as service `ssh` at [`Strong`] confidence.
//! * **Host-key algorithms.** The server's offered host-key algorithm list
//!   (`ssh-ed25519,rsa-sha2-512,…`) is surfaced as `extrainfo`. It is useful in
//!   its own right and the basis for future HASSH-style identification of
//!   servers whose banner is generic or spoofed.
//!
//! ## Scope
//!
//! Active probing is gated to the well-known SSH ports (a fresh connection is
//! not free, so we do not dial every port). SSH on a non-standard port is still
//! identified from its banner by the banner analyzer; driving the active probe
//! from an accumulating service guess belongs to whatever plans probes, not to a
//! port list here.
//!
//! [`Strong`]: super::model::Confidence::Strong

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::analyzer::{Analyzer, PortContext};
use super::model::{Evidence, SourceId};
use super::response::{Collected, ResponseSet};
use crate::model::confidence::Confidence;

/// Ports where an SSH server is expected, and thus worth an active probe.
const SSH_PORTS: &[u16] = &[22, 2222];

/// The software identifier out of an SSH identification line, or `None` if the
/// line is not one.
///
/// RFC 4253 §4.2 defines the line as `SSH-protoversion-softwareversion SP
/// comments`, and **the fingerprint corpus is written against the part after
/// the protocol version**, `OpenSSH_9.2p1 Debian-2+deb12u10`, because that is
/// what a stack actually chose. Its patterns anchor on it: `^OpenSSH_...$`.
///
/// So a rule naming a release can never match the whole line, and that is not a
/// hypothetical. Fed the complete banner, every version-bearing Debian rule
/// failed and only a loose rule naming the family fired, a host announcing
/// `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10` was reported as `Linux` when the
/// corpus held a rule mapping that exact string to Debian 12 with a CPE.
///
/// This is the SSH counterpart of what `HttpHeadersAnalyzer` does for a `Server`
/// header: the corpus matches a *field*, so something has to extract the field.
///
/// The protocol version cannot itself contain a hyphen, so the first one after
/// the prefix ends it; the comment part may, and is kept, because the corpus
/// matches on it.
///
/// ```text
/// SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10
///         └───────────── this ───────────┘
/// ```
pub(crate) fn software_version(line: &str) -> Option<&str> {
    let (_protocol_version, software) = line
        .trim_end_matches(['\r', '\n'])
        .strip_prefix("SSH-")?
        .split_once('-')?;

    (!software.is_empty()).then_some(software)
}

/// Our SSH identification string. The `SSH-2.0-` prefix is mandatory (RFC 4253
/// §4.2); the software name is ours.
const CLIENT_ID: &[u8] = b"SSH-2.0-Zond_1.0\r\n";

/// Whole-exchange budget: connect, read the banner, read one packet. Kept
/// tight, a reachable SSH server completes this well under a second.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);

/// RFC 4253 caps an (uncompressed) packet at 35 000 bytes; we never accept a
/// length header larger, so a hostile server cannot make us allocate unbounded.
const MAX_PACKET_LEN: usize = 35_000;

/// The SSH identification line cannot exceed 255 bytes including CRLF (RFC 4253
/// §4.2). Bounds the banner read.
const MAX_ID_LINE: usize = 255;

/// How many lines a server may send before its identification string.
///
/// RFC 4253 §4.2 permits a server to send other lines first and requires a
/// client to skip them, and it sets no limit on how many. A login banner is the
/// usual reason and runs to a few dozen lines at most; the bound is here because
/// these lines come from a peer that has not identified itself yet, and a
/// preamble with no end is a peer holding the exchange open for free.
///
/// The whole exchange is already under [`EXCHANGE_TIMEOUT`], so this bounds the
/// work rather than the wait.
const MAX_PREAMBLE_LINES: usize = 64;

/// `SSH_MSG_KEXINIT` message number (RFC 4253 §12).
const SSH_MSG_KEXINIT: u8 = 20;

/// Identifies SSH by completing the version + `KEXINIT` exchange. See the module
/// docs for what it probes and what it claims.
pub struct SshAnalyzer;

#[async_trait]
impl Analyzer for SshAnalyzer {
    fn id(&self) -> SourceId {
        SourceId::Ssh
    }

    fn interested(&self, ctx: &PortContext) -> bool {
        // Active probe: only where SSH is expected, only over the transport it
        // speaks, only with a socket to dial, and never inside a tunnel (SSH is
        // not carried over TLS here).
        //
        // The protocol test is not redundant with the port test. Without it a
        // scan that found UDP 22 open would have this dial *TCP* 22, a service
        // nobody asked about, at an address that never offered one.
        ctx.protocol == crate::model::port::Protocol::Tcp
            && ctx.tunnel.is_none()
            && ctx.addr.is_some()
            && SSH_PORTS.contains(&ctx.port)
    }

    /// I/O phase. Runs the exchange and returns the raw `KEXINIT` packet as a
    /// single frame, or nothing if the peer is not reachable / not SSH.
    async fn collect(&self, ctx: &PortContext) -> Collected {
        let Some(addr) = ctx.addr else {
            return Collected::default();
        };
        match timeout(EXCHANGE_TIMEOUT, kexinit_exchange(addr)).await {
            Ok(Some(packet)) => Collected::from_frames(vec![packet]),
            _ => Collected::default(),
        }
    }

    /// CPU phase. Parses the collected `KEXINIT` into evidence: protocol
    /// confirmation plus the server's host-key algorithm list.
    fn analyze(
        &self,
        _ctx: &PortContext,
        _responses: &ResponseSet,
        collected: &Collected,
    ) -> Vec<Evidence> {
        let Some(kexinit) = collected.frames.first() else {
            return Vec::new();
        };
        let Some(host_key_algorithms) = server_host_key_algorithms(kexinit) else {
            return Vec::new();
        };

        // A completed exchange confirms SSH; the host-key list rides along as
        // extrainfo. Product/version come from the banner analyzer.
        let mut evidence = Evidence::new(SourceId::Ssh, Confidence::Strong).with_service("ssh");
        if !host_key_algorithms.is_empty() {
            evidence = evidence.with_extrainfo(format!("hostkey {host_key_algorithms}"));
        }
        vec![evidence]
    }
}

/// Performs the exchange against `addr`: connect, send our identification
/// string, read the server's, then read one binary packet (its `KEXINIT`).
/// Returns the raw packet payload (message byte onward), or `None` on any I/O
/// or protocol error, the caller treats that as "not SSH here".
async fn kexinit_exchange(addr: SocketAddr) -> Option<Vec<u8>> {
    let stream = TcpStream::connect(addr).await.ok()?;
    let mut reader = BufReader::new(stream);

    // Send our identification string first; the server needs it to proceed.
    reader.write_all(CLIENT_ID).await.ok()?;
    reader.flush().await.ok()?;

    // Read the server's identification line, skipping whatever it sends first.
    read_identification(&mut reader).await?;

    // Read one binary packet. The server sends its KEXINIT immediately after the
    // identification exchange, so this is it.
    read_packet_payload(&mut reader).await
}

/// Reads the server's `SSH-…` identification string, skipping whatever it sends
/// before one.
///
/// RFC 4253 §4.2 permits a server to send other lines first, and requires a
/// client to be able to skip them. A login banner ahead of the identifier is
/// near-universal on hardened and enterprise hosts, which is to say on exactly
/// the fleet an operator most wants a scanner to work against. Reading one line
/// and giving up if it did not begin `SSH-` left this analyzer silent on every
/// one of them, and silent invisibly: the passive banner grab still named the
/// service, so only the corroboration went missing.
///
/// Bounded twice, because a peer that has not identified itself is sending
/// these: [`MAX_ID_LINE`] per line, [`MAX_PREAMBLE_LINES`] lines before the
/// identifier.
async fn read_identification<R>(reader: &mut R) -> Option<Vec<u8>>
where
    R: AsyncReadExt + Unpin,
{
    for _ in 0..=MAX_PREAMBLE_LINES {
        let line = read_line(reader).await?;
        if line.starts_with(b"SSH-") {
            return Some(line);
        }
    }
    None // a preamble with no identifier at the end of it
}

/// Reads one CRLF- or LF-terminated line, bounded to [`MAX_ID_LINE`].
async fn read_line<R>(reader: &mut R) -> Option<Vec<u8>>
where
    R: AsyncReadExt + Unpin,
{
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    while line.len() < MAX_ID_LINE {
        let n = reader.read(&mut byte).await.ok()?;
        if n == 0 {
            return None; // connection closed before a full line
        }
        if byte[0] == b'\n' {
            // Strip a trailing CR; done.
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Some(line);
        }
        line.push(byte[0]);
    }
    None // line too long: not a well-formed SSH line
}

/// Reads one SSH binary packet (RFC 4253 §6) and returns its payload, the bytes
/// after the padding-length field, before the random padding. `None` on a
/// malformed or over-long packet.
///
/// Pre-key-exchange there is no MAC and no encryption, so the wire layout is
/// `uint32 packet_length | byte padding_length | payload | padding`.
async fn read_packet_payload<R>(reader: &mut R) -> Option<Vec<u8>>
where
    R: AsyncReadExt + Unpin,
{
    let mut length = [0u8; 4];
    reader.read_exact(&mut length).await.ok()?;
    let packet_length = u32::from_be_bytes(length) as usize;

    // A valid packet has at least a padding-length byte and one payload byte,
    // and never exceeds the RFC cap, which also bounds the allocation below.
    if !(2..=MAX_PACKET_LEN).contains(&packet_length) {
        return None;
    }

    let mut packet = vec![0u8; packet_length];
    reader.read_exact(&mut packet).await.ok()?;

    // packet = [padding_length: u8][payload][padding]; payload length is what
    // remains after removing the padding-length byte and the trailing padding.
    let padding_length = packet[0] as usize;
    let payload_end = packet_length.checked_sub(padding_length)?;
    if payload_end < 1 {
        return None; // padding claims to cover the padding-length byte or more
    }
    Some(packet[1..payload_end].to_vec())
}

/// Extracts the `server_host_key_algorithms` name-list from a `KEXINIT` payload.
///
/// Payload layout (RFC 4253 §7.1): `byte msg | byte[16] cookie | name-list
/// kex_algorithms | name-list server_host_key_algorithms | …`. Every field is
/// bounds-checked against untrusted input; a malformed packet yields `None`.
fn server_host_key_algorithms(payload: &[u8]) -> Option<String> {
    // msg byte + 16-byte cookie precede the name-lists.
    if payload.first().copied()? != SSH_MSG_KEXINIT {
        return None;
    }
    let mut cursor = 1 + 16;

    // Skip the first name-list (kex_algorithms); return the second.
    skip_name_list(payload, &mut cursor)?;
    read_name_list(payload, &mut cursor)
}

/// Reads a length-prefixed name-list at `*cursor`, advancing past it, and returns
/// it as a UTF-8 string. `None` if the declared length runs past the buffer.
fn read_name_list(buf: &[u8], cursor: &mut usize) -> Option<String> {
    let start = *cursor;
    let len_end = start.checked_add(4)?;
    let len = u32::from_be_bytes(buf.get(start..len_end)?.try_into().ok()?) as usize;
    let data_end = len_end.checked_add(len)?;
    let data = buf.get(len_end..data_end)?;
    *cursor = data_end;
    // Name-lists are ASCII by spec; lossy is a safe floor for hostile input.
    Some(String::from_utf8_lossy(data).into_owned())
}

/// Advances `*cursor` past a name-list without materialising it. `None` if it
/// runs past the buffer.
fn skip_name_list(buf: &[u8], cursor: &mut usize) -> Option<()> {
    let len_end = cursor.checked_add(4)?;
    let len = u32::from_be_bytes(buf.get(*cursor..len_end)?.try_into().ok()?) as usize;
    *cursor = len_end.checked_add(len)?;
    // Confirm the skipped range is actually within the buffer.
    (*cursor <= buf.len()).then_some(())
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
    use proptest::prelude::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// Builds a length-prefixed SSH name-list.
    fn name_list(s: &str) -> Vec<u8> {
        let mut out = (s.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(s.as_bytes());
        out
    }

    /// Builds a `KEXINIT` payload with the given kex and host-key lists (the two
    /// this analyzer reads) followed by empty lists for the rest.
    fn kexinit_payload(kex: &str, host_key: &str) -> Vec<u8> {
        let mut p = vec![SSH_MSG_KEXINIT];
        p.extend_from_slice(&[0u8; 16]); // cookie
        p.extend_from_slice(&name_list(kex));
        p.extend_from_slice(&name_list(host_key));
        for _ in 0..8 {
            p.extend_from_slice(&name_list("")); // enc/mac/comp/lang lists
        }
        p.push(0); // first_kex_packet_follows
        p.extend_from_slice(&0u32.to_be_bytes()); // reserved
        p
    }

    /// Wraps a payload in the pre-key SSH binary framing.
    fn frame_packet(payload: &[u8]) -> Vec<u8> {
        // padding_length(1) + payload + padding; pad to an 8-byte block, min 4.
        let mut padding = 8 - ((1 + payload.len()) % 8);
        if padding < 4 {
            padding += 8;
        }
        let packet_length = 1 + payload.len() + padding;
        let mut out = (packet_length as u32).to_be_bytes().to_vec();
        out.push(padding as u8);
        out.extend_from_slice(payload);
        out.extend(std::iter::repeat_n(0u8, padding));
        out
    }

    #[test]
    fn parses_host_key_algorithms_from_a_kexinit() {
        let payload = kexinit_payload(
            "curve25519-sha256,ecdh-sha2-nistp256",
            "ssh-ed25519,rsa-sha2-512",
        );
        assert_eq!(
            server_host_key_algorithms(&payload).as_deref(),
            Some("ssh-ed25519,rsa-sha2-512")
        );
    }

    #[test]
    fn rejects_a_non_kexinit_message() {
        let mut payload = kexinit_payload("kex", "keys");
        payload[0] = 21; // SSH_MSG_NEWKEYS, not KEXINIT
        assert!(server_host_key_algorithms(&payload).is_none());
    }

    #[test]
    fn truncated_name_list_is_rejected_not_panicked() {
        // A length field that overruns the buffer must be refused, not read OOB.
        let mut payload = vec![SSH_MSG_KEXINIT];
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&name_list("kex"));
        payload.extend_from_slice(&1000u32.to_be_bytes()); // claims 1000 bytes...
        payload.extend_from_slice(b"short"); // ...but only 5 follow
        assert!(server_host_key_algorithms(&payload).is_none());
    }

    #[tokio::test]
    async fn read_packet_payload_rejects_an_over_long_length() {
        // A hostile length header must be refused before allocation.
        let (client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = server.write_all(&(u32::MAX).to_be_bytes()).await;
        });
        let mut reader = BufReader::new(client);
        assert!(read_packet_payload(&mut reader).await.is_none());
    }

    #[tokio::test]
    async fn collect_drives_the_exchange_against_a_mock_server_end_to_end() {
        // A loopback "SSH server": sends an identifier, reads ours, sends a
        // KEXINIT. Proves the active collect→analyze path over a real socket.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"SSH-2.0-OpenSSH_9.6p1\r\n").await.unwrap();
            let packet = frame_packet(&kexinit_payload("curve25519-sha256", "ssh-ed25519"));
            sock.write_all(&packet).await.unwrap();
            // Drain our client id so the write side doesn't race a close.
            let mut buf = [0u8; 64];
            let _ = sock.read(&mut buf).await;
        });

        let ctx = PortContext::new(22, crate::model::port::Protocol::Tcp).with_addr(Some(addr));
        assert!(SshAnalyzer.interested(&ctx));

        let collected = SshAnalyzer.collect(&ctx).await;
        let evidence = SshAnalyzer.analyze(&ctx, &ResponseSet::default(), &collected);

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].service.as_deref(), Some("ssh"));
        assert_eq!(evidence[0].confidence, Confidence::Strong);
        assert_eq!(
            evidence[0].extrainfo.as_deref(),
            Some("hostkey ssh-ed25519")
        );
    }

    proptest! {
        /// The `KEXINIT` parser runs on bytes straight off an untrusted socket,
        /// so on *any* input it must return cleanly, never panic, never read
        /// out of bounds, never allocate on a hostile length. If this completes
        /// for every generated buffer, parsing is both safe and bounded.
        #[test]
        fn kexinit_parser_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..4096)
        ) {
            let _ = server_host_key_algorithms(&bytes);
        }

        /// A well-formed message byte + cookie followed by fuzzed bytes drives
        /// the name-list cursor itself under adversarial lengths, past the early
        /// message-type rejection.
        #[test]
        fn kexinit_name_list_cursor_survives_fuzzed_lengths(
            tail in proptest::collection::vec(any::<u8>(), 0..512)
        ) {
            let mut payload = vec![SSH_MSG_KEXINIT];
            payload.extend_from_slice(&[0u8; 16]);
            payload.extend_from_slice(&tail);
            let _ = server_host_key_algorithms(&payload);
        }
    }

    /// A server with a login banner is still an SSH server.
    ///
    /// RFC 4253 §4.2 lets a server send lines before its identification string
    /// and requires a client to skip them; a legal notice ahead of the
    /// identifier is near-universal on hardened hosts. Reading exactly one line
    /// left this analyzer silent on all of them, and silent invisibly, since the
    /// passive banner grab still named the service.
    #[tokio::test]
    async fn a_server_that_greets_before_identifying_is_still_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(
                b"*******************************************\r\n\
                  * Authorised access only. Activity is logged. *\r\n\
                  *******************************************\r\n\
                  SSH-2.0-OpenSSH_9.6p1\r\n",
            )
            .await
            .unwrap();
            let packet = frame_packet(&kexinit_payload("curve25519-sha256", "ssh-ed25519"));
            sock.write_all(&packet).await.unwrap();
            let mut buf = [0u8; 64];
            let _ = sock.read(&mut buf).await;
        });

        let ctx = PortContext::new(22, crate::model::port::Protocol::Tcp).with_addr(Some(addr));
        let collected = SshAnalyzer.collect(&ctx).await;
        let evidence = SshAnalyzer.analyze(&ctx, &ResponseSet::default(), &collected);

        assert_eq!(evidence.len(), 1, "the preamble is skipped, not fatal");
        assert_eq!(evidence[0].service.as_deref(), Some("ssh"));
    }

    /// A preamble that never ends is a peer holding the exchange open, and is
    /// given up on rather than followed.
    #[tokio::test]
    async fn a_preamble_with_no_identifier_is_given_up_on() {
        let (client, mut server) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            for _ in 0..(MAX_PREAMBLE_LINES * 4) {
                if server
                    .write_all(b"still not an identifier\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });

        let mut reader = BufReader::new(client);
        assert!(read_identification(&mut reader).await.is_none());
    }

    /// The active probe dials the ports the corpus registers SSH on, and the two
    /// lists are written in different places: this one in code, the other in
    /// `assets/fingerprinting`. Nothing but this holds them together.
    #[test]
    fn the_probed_ports_are_the_ports_the_corpus_claims() {
        use crate::fingerprint::SignatureDb;

        let db = SignatureDb::global();
        let claimed: Vec<u16> = db
            .indexed_ports()
            .filter(|port| db.service_name(*port).as_deref() == Some("ssh"))
            .collect();

        for port in &claimed {
            assert!(
                SSH_PORTS.contains(port),
                "the corpus registers ssh on {port} and the active probe never dials it"
            );
        }
        for port in SSH_PORTS {
            assert!(
                claimed.contains(port),
                "the active probe dials {port} and no ssh signature is registered there"
            );
        }
    }

    #[tokio::test]
    async fn not_interested_off_ssh_ports_or_without_an_address() {
        let no_addr = PortContext::new(22, crate::model::port::Protocol::Tcp);
        assert!(!SshAnalyzer.interested(&no_addr));

        let wrong_port = PortContext::new(80, crate::model::port::Protocol::Tcp)
            .with_addr(Some("127.0.0.1:80".parse().unwrap()));
        assert!(!SshAnalyzer.interested(&wrong_port));
    }
}
