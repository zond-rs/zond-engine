// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # SMB analyzer
//!
//! An **active** analyzer for port 445, and the second half of a conversation
//! the corpus opens.
//!
//! ## Why a conversation, and why here
//!
//! SMB has two protocols on one port, and what a server answers depends on
//! which it is asked in. Windows has shipped with SMB1 off since 2017 and Samba
//! since 4.11, and both drop a connection that opens in SMB1 alone; a server
//! from before SMB2 drops one that opens in SMB2. No single question gets an
//! answer from both, and the question that follows the first depends on what
//! the first drew.
//!
//! So the corpus's probe for the port is an SMB1 negotiate that offers the SMB2
//! dialects as well, which every SMB server answers, as MS-SMB2 has it: in SMB2
//! where it speaks it, in SMB1 where it does not. That names the service
//! and says which protocol the server prefers. This analyzer reads that answer
//! and continues in the protocol it names, on a connection of its own, since a
//! connection that has negotiated one protocol will not carry the other:
//!
//! * **SMB2.** A negotiate offering every dialect from 2.0.2 to 3.1.1 and a
//!   session setup offering NTLM, in one write. The server answers the second
//!   with an NTLM challenge before anything is authenticated, and Windows puts
//!   its own version and build in it. See [`framed::smb2_exchange`].
//! * **SMB1**, asked where the server answered in SMB1, and where SMB2 did not
//!   name a Windows build: a negotiate and a null session setup, whose answer
//!   names the operating system and the LAN manager, which is where a Samba
//!   server states its version. See [`framed::smb_session_setup`]. A server
//!   that named its build over SMB2 is not asked, since SMB1 would add no more
//!   than an edition, and asking it of a server that dropped SMB1 is a refused
//!   connection.
//!
//! What either reads is matched against the corpus like any banner, so the
//! rules that name releases live in `assets/fingerprinting` beside the probe.
//!
//! The NTLM challenge also carries the machine's names and its domain's, which
//! are recorded on the host as [`HostName`](crate::model::host::HostName)s
//! rather than matched: they are a report's to mask, and a service's
//! description is not masked. See [`framed::smb2_names`].
//!
//! [`framed::smb2_exchange`]: super::framed::smb2_exchange
//! [`framed::smb2_names`]: super::framed::smb2_names
//! [`framed::smb_session_setup`]: super::framed::smb_session_setup

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use super::analyzer::{Analyzer, PortContext};
use super::db::SignatureDb;
use super::model::{Evidence, SourceId};
use super::response::{Collected, ResponseSet};
use crate::model::confidence::Confidence;

/// The one port this analyzer dials. SMB over 139 sits behind a NetBIOS
/// session request, and its own rung reads that.
const SMB_PORT: u16 = 445;

/// Whole-exchange budget: connect, write, read both replies. A reachable
/// server answers well under a second on a path that costs nothing; a scan
/// allows for the path it measured on top (see [`on_path`](super::on_path)).
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);

/// How long to wait for the next part of a reply once one has arrived.
const READ_GRACE: Duration = Duration::from_millis(1_000);

/// The most read from one exchange. Both replies together are a few hundred
/// bytes; this bounds what a hostile peer can make the analyzer hold.
const MAX_EXCHANGE_BYTES: usize = 16 * 1024;

/// An SMB1 negotiate offering NT LM 0.12 and a null session setup, in one
/// write; a server that accepts the session names itself in the answer.
///
/// ```text
/// 00 00 00 2f  NetBIOS length, then SMB_COM_NEGOTIATE offering NT LM 0.12
/// 00 00 00 71  NetBIOS length, then SESSION_SETUP_ANDX with no credentials
/// ```
///
/// The session setup asks for nothing: no password, no extended security, an
/// empty account. A server configured to allow it answers as the guest or
/// anonymous user; one that is not refuses, and the refusal is read as no
/// answer rather than as a service.
const SMB1_SESSION: &[u8] = b"\x00\x00\x00\x2f\xffSMBr\x00\x00\x00\x00\x18\x01\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x01\x00\x00\x0c\x00\x02NT LM 0.12\x00\x00\x00\x00\x71\xffSMBs\x00\x00\x00\x00\x18\x01\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x01\x00\x0d\xff\x00\x00\x04\x11\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5c\x00\x00\x00\x35\x00\x00z\x00o\x00n\x00d\x00\x00\x00Z\x00O\x00N\x00D\x00L\x00A\x00B\x00\x00\x00Z\x00o\x00n\x00d\x00 \x00S\x00c\x00a\x00n\x00n\x00e\x00r\x00\x00\x00";

/// Continues an SMB conversation in the protocol the server chose. See the
/// module docs.
pub(crate) struct SmbAnalyzer;

#[async_trait]
impl Analyzer for SmbAnalyzer {
    fn id(&self) -> SourceId {
        SourceId::BannerRegex
    }

    fn interested(&self, ctx: &PortContext) -> bool {
        ctx.protocol == crate::model::port::Protocol::Tcp
            && ctx.tunnel.is_none()
            && ctx.addr.is_some()
            && ctx.port == SMB_PORT
    }

    /// I/O phase. Reads which protocol the corpus probe drew and continues in
    /// it; returns what each exchange read, one frame per exchange.
    async fn collect(&self, ctx: &PortContext, responses: &ResponseSet) -> Collected {
        let Some(addr) = ctx.addr else {
            return Collected::default();
        };
        // The corpus probe's answer, as the transport read it: the protocol id
        // behind the NetBIOS header, 0xFE for SMB2 and 0xFF for SMB1, each its
        // own code point since neither byte is ever UTF-8.
        let answered = |id: &str| responses.banners.iter().any(|text| text.contains(id));
        let (smb2, smb1) = (answered("\u{fe}SMB"), answered("\u{ff}SMB"));

        let mut frames = Vec::new();
        let mut named_a_build = false;
        if smb2 && let Some(reply) = exchange(addr, &smb2_session(), 2).await {
            named_a_build = super::framed::smb2_exchange(&reply)
                .iter()
                .any(|text| text.starts_with("Windows "));
            frames.push(reply);
        }
        if (smb1 || smb2) && !named_a_build {
            frames.extend(exchange(addr, SMB1_SESSION, 2).await);
        }
        Collected::from_frames(frames)
    }

    /// CPU phase. What each exchange read, matched against the corpus, and the
    /// names the NTLM challenge gave for the machine.
    ///
    /// The names travel as an observation of their own, at the lowest
    /// confidence, because they identify the machine and nothing about the
    /// service: whether any rule matched has no bearing on them.
    fn analyze(
        &self,
        ctx: &PortContext,
        _responses: &ResponseSet,
        collected: &Collected,
    ) -> Vec<Evidence> {
        let db = SignatureDb::global();
        let mut evidence: Vec<Evidence> = collected
            .frames
            .iter()
            .flat_map(|frame| {
                let mut texts = super::framed::smb2_exchange(frame);
                texts.extend(super::framed::smb_session_setup(frame));
                texts
            })
            .filter_map(|text| db.identify(ctx.port, ctx.protocol, &text))
            .collect();

        let names: Vec<_> = collected
            .frames
            .iter()
            .flat_map(|frame| super::framed::smb2_names(frame))
            .collect();
        if !names.is_empty() {
            evidence.push(Evidence::new(self.id(), Confidence::Heuristic).with_names(names));
        }
        evidence
    }
}

/// Writes `request` to `addr` on a connection of its own and reads until
/// `messages` NetBIOS messages have arrived, the peer closes, or it goes quiet.
///
/// [`None`] when nothing at all came back.
async fn exchange(addr: SocketAddr, request: &[u8], messages: usize) -> Option<Vec<u8>> {
    let talk = async {
        let mut stream = super::analyzer_connect(addr).await.ok()?;
        stream.write_all(request).await.ok()?;

        let mut reply = Vec::new();
        let mut buffer = [0u8; 4096];
        while reply.len() < MAX_EXCHANGE_BYTES && complete_messages(&reply) < messages {
            match timeout(super::on_path(READ_GRACE), stream.read(&mut buffer)).await {
                Ok(Ok(read)) if read > 0 => reply.extend_from_slice(&buffer[..read]),
                _ => break,
            }
        }
        (!reply.is_empty()).then_some(reply)
    };
    timeout(super::on_path(EXCHANGE_TIMEOUT), talk)
        .await
        .ok()
        .flatten()
}

/// How many whole NetBIOS session messages `stream` holds.
fn complete_messages(stream: &[u8]) -> usize {
    let mut count = 0;
    let mut at = 0;
    while let Some(header) = stream.get(at..at + 4) {
        let length = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
        if stream.len() < at + 4 + length {
            break;
        }
        count += 1;
        at += 4 + length;
    }
    count
}

/// An SMB2 negotiate and a session setup offering NTLM, each behind its
/// NetBIOS length, for one write.
///
/// A server processes the two in order on one connection, and the negotiate
/// response grants the credit the session setup spends, so one exchange draws
/// both answers.
fn smb2_session() -> Vec<u8> {
    let mut out = Vec::new();
    for message in [smb2_negotiate(), smb2_session_setup()] {
        out.extend_from_slice(&(message.len() as u32).to_be_bytes());
        out.extend_from_slice(&message);
    }
    out
}

/// An SMB2 header (MS-SMB2 2.2.1.2) for `command`, message `id`.
fn smb2_header(command: u16, id: u64) -> Vec<u8> {
    let mut header = Vec::with_capacity(64);
    header.extend_from_slice(b"\xfeSMB");
    header.extend_from_slice(&64u16.to_le_bytes()); // structure size
    header.extend_from_slice(&u16::from(id > 0).to_le_bytes()); // credit charge
    header.extend_from_slice(&[0; 4]); // status
    header.extend_from_slice(&command.to_le_bytes());
    header.extend_from_slice(&31u16.to_le_bytes()); // credits requested
    header.extend_from_slice(&[0; 4]); // flags
    header.extend_from_slice(&[0; 4]); // next command
    header.extend_from_slice(&id.to_le_bytes());
    header.extend_from_slice(&[0; 4]); // process id
    header.extend_from_slice(&[0; 4]); // tree id
    header.extend_from_slice(&[0; 8]); // session id
    header.extend_from_slice(&[0; 16]); // signature
    header
}

/// A NEGOTIATE (MS-SMB2 2.2.3) offering 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1, with
/// the preauthentication integrity context 3.1.1 requires.
///
/// Every dialect is offered so the answer is the highest the server speaks,
/// which is the fact worth reporting.
fn smb2_negotiate() -> Vec<u8> {
    const DIALECTS: [u16; 5] = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
    /// The header, the fixed body and the dialects, padded to eight bytes,
    /// which is where the context list must start.
    const CONTEXTS_AT: u32 = 112;

    let mut message = smb2_header(0, 0);
    message.extend_from_slice(&36u16.to_le_bytes()); // structure size
    message.extend_from_slice(&(DIALECTS.len() as u16).to_le_bytes());
    message.extend_from_slice(&1u16.to_le_bytes()); // signing enabled
    message.extend_from_slice(&[0; 2]); // reserved
    message.extend_from_slice(&[0; 4]); // capabilities
    message.extend_from_slice(b"zond-smb2-client"); // client guid
    message.extend_from_slice(&CONTEXTS_AT.to_le_bytes());
    message.extend_from_slice(&1u16.to_le_bytes()); // context count
    message.extend_from_slice(&[0; 2]); // reserved
    for dialect in DIALECTS {
        message.extend_from_slice(&dialect.to_le_bytes());
    }
    message.resize(CONTEXTS_AT as usize, 0);

    // SMB2_PREAUTH_INTEGRITY_CAPABILITIES: one hash, SHA-512, and a salt.
    let salt = [0x5a_u8; 32];
    let data_length = 2 + 2 + 2 + salt.len() as u16;
    message.extend_from_slice(&1u16.to_le_bytes()); // context type
    message.extend_from_slice(&data_length.to_le_bytes());
    message.extend_from_slice(&[0; 4]); // reserved
    message.extend_from_slice(&1u16.to_le_bytes()); // hash algorithm count
    message.extend_from_slice(&(salt.len() as u16).to_le_bytes());
    message.extend_from_slice(&1u16.to_le_bytes()); // SHA-512
    message.extend_from_slice(&salt);
    message
}

/// A SESSION_SETUP (MS-SMB2 2.2.5) carrying an NTLM NEGOTIATE_MESSAGE
/// (MS-NLMP 2.2.1.1) inside a SPNEGO NegTokenInit (RFC 4178).
///
/// The NTLM flags ask for the server's version, which is what the challenge
/// is read for, and for its target information.
fn smb2_session_setup() -> Vec<u8> {
    /// Unicode, request target, NTLM, always sign, extended session security,
    /// version, 128-bit and 56-bit.
    const NTLM_FLAGS: u32 = 0xA208_8205;

    let mut ntlm = b"NTLMSSP\0".to_vec();
    ntlm.extend_from_slice(&1u32.to_le_bytes()); // NEGOTIATE_MESSAGE
    ntlm.extend_from_slice(&NTLM_FLAGS.to_le_bytes());
    ntlm.extend_from_slice(&[0; 8]); // domain name fields
    ntlm.extend_from_slice(&[0; 8]); // workstation fields
    ntlm.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x0f]); // version, revision 15

    // NegTokenInit: the NTLMSSP mechanism, then the token.
    const NTLMSSP_OID: &[u8] = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a";
    let mech_types = der(0xa0, &der(0x30, NTLMSSP_OID));
    let mech_token = der(0xa2, &der(0x04, &ntlm));
    let init = der(0xa0, &der(0x30, &[mech_types, mech_token].concat()));
    const SPNEGO_OID: &[u8] = b"\x06\x06\x2b\x06\x01\x05\x05\x02";
    let token = der(0x60, &[SPNEGO_OID, &init].concat());

    let mut message = smb2_header(1, 1);
    message.extend_from_slice(&25u16.to_le_bytes()); // structure size
    message.push(0); // flags
    message.push(1); // signing enabled
    message.extend_from_slice(&[0; 4]); // capabilities
    message.extend_from_slice(&[0; 4]); // channel
    message.extend_from_slice(&(64u16 + 24).to_le_bytes()); // buffer offset
    message.extend_from_slice(&(token.len() as u16).to_le_bytes());
    message.extend_from_slice(&[0; 8]); // previous session id
    message.extend_from_slice(&token);
    message
}

/// A DER element: `tag`, a short-form length, `content`. Everything built here
/// is under 128 bytes.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    debug_assert!(content.len() < 0x80);
    let mut out = vec![tag, content.len() as u8];
    out.extend_from_slice(content);
    out
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
    use crate::fingerprint::framed;
    use crate::model::host::{HostName, NameKind, NameSource};
    use crate::testing::loopback::accept_from_this_process;

    /// `message` behind its NetBIOS session header.
    fn framed_message(message: &[u8]) -> Vec<u8> {
        let mut out = (message.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(message);
        out
    }

    /// An SMB2 response header for `command` with `status`, then `body`.
    fn smb2_response(command: u16, status: u32, body: &[u8]) -> Vec<u8> {
        let mut message = smb2_header(command, 0);
        message[8..12].copy_from_slice(&status.to_le_bytes());
        message.extend_from_slice(body);
        framed_message(&message)
    }

    /// A NEGOTIATE response (MS-SMB2 2.2.4) choosing `dialect` under
    /// `security_mode`.
    fn negotiate_response(security_mode: u16, dialect: u16) -> Vec<u8> {
        let mut body = 65u16.to_le_bytes().to_vec();
        body.extend_from_slice(&security_mode.to_le_bytes());
        body.extend_from_slice(&dialect.to_le_bytes());
        body.resize(64, 0);
        smb2_response(0, 0, &body)
    }

    /// A SESSION_SETUP response carrying an NTLM challenge (MS-NLMP 2.2.1.2)
    /// that states version `major.minor` build `build`.
    fn challenge_response(major: u8, minor: u8, build: u16) -> Vec<u8> {
        challenge_naming(major, minor, build, &[])
    }

    /// The same challenge carrying `pairs` as its target information
    /// (MS-NLMP 2.2.2.1), each an `AvId` and a value written in UTF-16, with
    /// the end-of-list pair after them.
    fn challenge_naming(major: u8, minor: u8, build: u16, pairs: &[(u16, &str)]) -> Vec<u8> {
        /// The fixed part of a challenge, where its payload begins.
        const PAYLOAD_AT: u32 = 56;

        let mut info = Vec::new();
        for (id, value) in pairs {
            let value: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
            info.extend_from_slice(&id.to_le_bytes());
            info.extend_from_slice(&(value.len() as u16).to_le_bytes());
            info.extend_from_slice(&value);
        }
        if !pairs.is_empty() {
            info.extend_from_slice(&[0; 4]); // MsvAvEOL
        }

        let mut ntlm = b"NTLMSSP\0".to_vec();
        ntlm.extend_from_slice(&2u32.to_le_bytes());
        ntlm.extend_from_slice(&[0; 8]); // target name fields
        ntlm.extend_from_slice(&0xE289_8215u32.to_le_bytes()); // flags, with version
        ntlm.extend_from_slice(b"\x01\x23\x45\x67\x89\xab\xcd\xef"); // challenge
        ntlm.extend_from_slice(&[0; 8]); // reserved
        ntlm.extend_from_slice(&(info.len() as u16).to_le_bytes()); // target info fields
        ntlm.extend_from_slice(&(info.len() as u16).to_le_bytes());
        ntlm.extend_from_slice(&PAYLOAD_AT.to_le_bytes());
        ntlm.extend_from_slice(&[major, minor]);
        ntlm.extend_from_slice(&build.to_le_bytes());
        ntlm.extend_from_slice(&[0, 0, 0, 0x0f]);
        ntlm.extend_from_slice(&info);
        // Wrapped the way a server answers, in a SPNEGO NegTokenResp, whose
        // lengths pass 127 once the challenge names anything.
        let token = long_der(
            0xa1,
            &long_der(0x30, &long_der(0xa2, &long_der(0x04, &ntlm))),
        );

        let mut body = 9u16.to_le_bytes().to_vec();
        body.extend_from_slice(&[0; 2]); // session flags
        body.extend_from_slice(&72u16.to_le_bytes());
        body.extend_from_slice(&(token.len() as u16).to_le_bytes());
        body.extend_from_slice(&token);
        smb2_response(1, 0xC000_0016, &body)
    }

    /// A DER element whose length takes the long form where it has to
    /// (X.690 §8.1.3.5), which the requests this analyzer builds never need.
    fn long_der(tag: u8, content: &[u8]) -> Vec<u8> {
        if content.len() < 0x80 {
            return der(tag, content);
        }
        let mut out = vec![tag, 0x82];
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.extend_from_slice(content);
        out
    }

    /// What a current Windows server answers: the dialect it chose, that it
    /// does not insist on signing, and the build its NTLM challenge states.
    #[test]
    fn an_smb2_answer_yields_the_dialect_and_the_windows_build() {
        let stream = [
            negotiate_response(0x0001, 0x0311),
            challenge_response(10, 0, 20348),
        ]
        .concat();
        assert_eq!(
            framed::smb2_exchange(&stream),
            [
                "dialect 3.1.1; signing not required",
                "Windows 10.0 Build 20348"
            ]
        );

        let signed = negotiate_response(0x0003, 0x0210);
        assert_eq!(
            framed::smb2_exchange(&signed),
            ["dialect 2.1; signing required"]
        );
    }

    /// Samba states version 6.1 with a build of zero beside a release it does
    /// not run. Read as Windows, every Samba server would be named Windows 7.
    #[test]
    fn a_build_of_zero_names_no_windows_release() {
        let stream = [
            negotiate_response(0x0001, 0x0311),
            challenge_response(6, 1, 0),
        ]
        .concat();
        assert_eq!(
            framed::smb2_exchange(&stream),
            ["dialect 3.1.1; signing not required"]
        );
    }

    /// The wildcard is the server asking to negotiate again, not a dialect.
    #[test]
    fn the_wildcard_dialect_names_nothing() {
        assert!(framed::smb2_exchange(&negotiate_response(0x0001, 0x02ff)).is_empty());
    }

    /// The decoder reads bytes off an untrusted socket and returns on any of
    /// them.
    #[test]
    fn the_smb2_decoder_survives_truncation_anywhere() {
        let stream = [
            negotiate_response(0x0001, 0x0311),
            challenge_response(10, 0, 20348),
        ]
        .concat();
        let named = [
            negotiate_response(0x0001, 0x0311),
            challenge_naming(10, 0, 20348, DOMAIN_CONTROLLER),
        ]
        .concat();
        for end in 0..stream.len() {
            let _ = framed::smb2_exchange(&stream[..end]);
        }
        for end in 0..named.len() {
            let _ = framed::smb2_exchange(&named[..end]);
            let _ = framed::smb2_names(&named[..end]);
        }
    }

    /// The target information a domain controller's challenge carries, in the
    /// order Windows writes it: the two NetBIOS names, the three DNS names, and
    /// a timestamp, which is not a name.
    const DOMAIN_CONTROLLER: &[(u16, &str)] = &[
        (2, "CORP"),
        (1, "DC01"),
        (4, "corp.example"),
        (3, "dc01.corp.example"),
        (5, "corp.example"),
        (7, "\u{1}\u{2}\u{3}\u{4}"),
    ];

    /// What [`DOMAIN_CONTROLLER`] names, in the order it names them.
    fn domain_controller_names() -> Vec<HostName> {
        [
            (NameKind::NetbiosDomain, "CORP"),
            (NameKind::NetbiosHost, "DC01"),
            (NameKind::Domain, "corp.example"),
            (NameKind::Host, "dc01.corp.example"),
            (NameKind::Forest, "corp.example"),
        ]
        .into_iter()
        .map(|(kind, name)| HostName::new(kind, NameSource::Ntlm, name).expect("a name"))
        .collect()
    }

    /// An unauthenticated challenge names the machine, its domain and its
    /// forest, each pair read into the kind MS-NLMP gives it, and none of them
    /// reaches the text the corpus matches, which is a service's description
    /// and is not masked where a report is.
    #[test]
    fn an_ntlm_challenge_names_the_machine_its_domain_and_its_forest() {
        let stream = [
            negotiate_response(0x0001, 0x0311),
            challenge_naming(10, 0, 20348, DOMAIN_CONTROLLER),
        ]
        .concat();

        assert_eq!(framed::smb2_names(&stream), domain_controller_names());
        assert_eq!(
            framed::smb2_exchange(&stream),
            [
                "dialect 3.1.1; signing not required",
                "Windows 10.0 Build 20348"
            ],
            "the names are not a service's description"
        );
    }

    /// MS-NLMP allows each pair once, so a second of one is not read, and an
    /// empty value is a server that states no such name rather than one whose
    /// name is empty.
    #[test]
    fn a_pair_is_read_once_and_an_empty_one_names_nothing() {
        let stream = challenge_naming(
            10,
            0,
            20348,
            &[(1, "DC01"), (1, "IMPOSTOR"), (2, ""), (4, "corp.example")],
        );
        let names = framed::smb2_names(&stream);
        let named: Vec<(NameKind, &str)> = names
            .iter()
            .map(|name| (name.kind(), name.name()))
            .collect();
        assert_eq!(
            named,
            [
                (NameKind::NetbiosHost, "DC01"),
                (NameKind::Domain, "corp.example")
            ]
        );
    }

    /// The requests as MS-SMB2 lays them out: two whole NetBIOS messages, the
    /// negotiate context list on an eight-byte boundary where the negotiate
    /// says it is, and the security buffer where the session setup says.
    #[test]
    fn the_smb2_requests_are_laid_out_where_their_offsets_say() {
        let negotiate = smb2_negotiate();
        let at = u32::from_le_bytes(negotiate[64 + 28..64 + 32].try_into().unwrap()) as usize;
        assert_eq!(at % 8, 0);
        assert_eq!(&negotiate[at..at + 2], [1, 0], "the preauth context");
        let data = u16::from_le_bytes([negotiate[at + 2], negotiate[at + 3]]) as usize;
        assert_eq!(
            negotiate.len(),
            at + 8 + data,
            "the context ends the message"
        );
        assert_eq!(
            &negotiate[64 + 36..64 + 46],
            [2, 2, 0x10, 2, 0, 3, 2, 3, 0x11, 3],
            "the dialects follow the fixed body"
        );

        let setup = smb2_session_setup();
        let offset = u16::from_le_bytes([setup[64 + 12], setup[64 + 13]]) as usize;
        let length = u16::from_le_bytes([setup[64 + 14], setup[64 + 15]]) as usize;
        assert_eq!(setup.len(), offset + length);
        assert_eq!(setup[offset], 0x60, "a GSS-API initial context token");
        assert!(setup.windows(8).any(|window| window == b"NTLMSSP\0"));

        assert_eq!(complete_messages(&smb2_session()), 2);
    }

    /// The shipped signing detection, run against a server that answers its
    /// negotiate with `reply`. Hands back what it sent and whether it found
    /// signing not required.
    fn signing_detection(reply: Vec<u8>) -> (Vec<u8>, bool) {
        use crate::detect::flow::{FlowSeed, Probe, run};

        struct Answering {
            reply: Vec<u8>,
            sent: Vec<u8>,
        }
        impl Probe for Answering {
            fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
                self.sent.extend_from_slice(bytes);
                Some(self.reply.clone())
            }
        }

        let flow = crate::detect::flow::db::shipped_flow("smb-signing-not-required");
        let mut probe = Answering {
            reply,
            sent: Vec::new(),
        };
        let findings = run(&flow, "", &FlowSeed::new("192.0.2.45", 445), &mut probe);
        (probe.sent, !findings.is_empty())
    }

    /// The detection that reports signing not required asks the question this
    /// analyzer asks, byte for byte, so the two cannot give different accounts
    /// of one server. Offering 3.1.1 without the preauthentication context is
    /// a request MS-SMB2 has a server refuse, and one that honours it anyway
    /// can pick a different dialect under a different security mode.
    #[test]
    fn the_signing_detection_negotiates_as_this_analyzer_does() {
        let (sent, _) = signing_detection(Vec::new());
        assert_eq!(sent, framed_message(&smb2_negotiate()));
    }

    /// Only a successful negotiate answer is read for the signing bit. The
    /// error a server sends a request it refuses has a zero where a negotiate
    /// answer keeps its security mode, and reading it as one reports a server
    /// that insists on signing as one that does not.
    #[test]
    fn the_signing_detection_reads_only_a_negotiate_that_succeeded() {
        const SIGNING_ENABLED: u16 = 0x0001;
        const SIGNING_REQUIRED: u16 = 0x0002;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

        let (_, found) = signing_detection(negotiate_response(SIGNING_ENABLED, 0x0311));
        assert!(found, "signing enabled and not required");
        let (_, found) = signing_detection(negotiate_response(
            SIGNING_ENABLED | SIGNING_REQUIRED,
            0x0311,
        ));
        assert!(!found, "signing required");

        // The SMB2 ERROR response: structure size 9, no error contexts.
        let refused = smb2_response(0, STATUS_INVALID_PARAMETER, &[9, 0, 0, 0, 0, 0, 0, 0, 0]);
        let (_, found) = signing_detection(refused);
        assert!(!found, "a refused negotiate read as signing not required");
    }

    /// A loopback SMB server: answers the corpus probe in the protocol given,
    /// and each of the analyzer's own connections with `follow_up`.
    async fn smb_server(rung: Vec<u8>, follow_up: Vec<u8>) -> std::net::SocketAddr {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a socket");
        let addr = listener.local_addr().expect("its address");
        tokio::spawn(async move {
            while let Ok(mut sock) = accept_from_this_process(&listener).await {
                let (rung, follow_up) = (rung.clone(), follow_up.clone());
                tokio::spawn(async move {
                    let mut request = [0u8; 1024];
                    let Ok(read) = sock.read(&mut request).await else {
                        return;
                    };
                    // The corpus probe offers `SMB 2.???`; the analyzer's
                    // requests do not.
                    let answer = match request[..read].windows(9).any(|w| w == b"SMB 2.???") {
                        true => rung,
                        false => follow_up,
                    };
                    let _ = sock.write_all(&answer).await;
                    let _ = sock.read(&mut request).await;
                });
            }
        });
        addr
    }

    /// Fingerprints `addr` as port 445, the way a scan would.
    async fn fingerprint_445(addr: std::net::SocketAddr) -> crate::fingerprint::Fingerprinted {
        use crate::model::port::{PortState, Protocol};

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connects");
        let port = crate::fingerprint::baseline_port(445, Protocol::Tcp, PortState::Open);
        crate::fingerprint::fingerprint_tcp_detailed(
            stream,
            port,
            crate::config::ServiceDetection::Probe,
        )
        .await
    }

    /// A current Windows server, which drops a connection opened in SMB1
    /// alone, is named with its dialect, its signing policy and its release,
    /// over sockets end to end.
    #[tokio::test]
    async fn a_server_that_speaks_smb2_is_named_with_its_release() {
        let addr = smb_server(
            negotiate_response(0x0001, 0x02ff),
            [
                negotiate_response(0x0001, 0x0311),
                challenge_response(10, 0, 20348),
            ]
            .concat(),
        )
        .await;

        let identified = fingerprint_445(addr).await;
        let service = identified.port.service().expect("the port is named");
        assert_eq!(service.name(), "smb");
        assert_eq!(service.extrainfo(), Some("SMB 3.1.1, signing not required"));
        let os = identified
            .about_the_host
            .os
            .iter()
            .find_map(|os| os.product.as_deref());
        assert_eq!(os, Some("Windows Server 2022"));
    }

    /// **What a Windows server calls itself reaches its host, and is masked
    /// where a report is asked to mask.** Over sockets end to end: the corpus
    /// probe, the analyzer's own session setup, the challenge naming the
    /// machine and its domain, and the host record a report is written from.
    ///
    /// The names are the most identifying strings a scan of a domain learns,
    /// and a service's description is not masked; carried there, or not
    /// carried at all, a redacted report would leak the domain or lose it.
    #[tokio::test]
    async fn a_server_s_ntlm_names_reach_its_host_masked_where_a_report_masks() {
        use crate::export::schema::HostDto;
        use crate::export::{ExportOptions, Redaction};
        use crate::model::host::Host;

        let addr = smb_server(
            negotiate_response(0x0001, 0x02ff),
            [
                negotiate_response(0x0001, 0x0311),
                challenge_naming(10, 0, 20348, DOMAIN_CONTROLLER),
            ]
            .concat(),
        )
        .await;

        let identified = fingerprint_445(addr).await;
        let service = identified.port.service().expect("the port is named");
        assert_eq!(service.extrainfo(), Some("SMB 3.1.1, signing not required"));

        let mut host = Host::new(addr.ip());
        identified.about_the_host.apply(&mut host);

        let render = |options: ExportOptions| {
            serde_json::to_value(HostDto::new(&host, &options)).expect("a host renders")
        };
        let plain = render(ExportOptions::new());
        let names = plain["names"].as_array().expect("the host carries names");
        assert_eq!(names.len(), 5, "{names:?}");
        assert!(
            names.contains(&serde_json::json!({
                "source": "ntlm",
                "kind": "netbios_host",
                "name": "DC01",
            })),
            "{names:?}"
        );

        let masked = render(ExportOptions::new().with_redaction(Redaction::Standard)).to_string();
        assert!(
            !masked.contains("corp") && !masked.contains("DC01") && masked.contains("dcXXXXXle"),
            "a name survived redaction: {masked}"
        );
    }

    /// A server from before SMB2 answers the probe in SMB1 and is asked for a
    /// session in SMB1, whose answer names its operating system as it did
    /// before SMB2 was asked for.
    #[tokio::test]
    async fn a_server_that_speaks_only_smb1_still_names_its_system() {
        /// An SMB1 header for `command`, Unicode strings, success.
        fn smb1(command: u8, words: &[u8], bytes: &[u8]) -> Vec<u8> {
            let mut message = b"\xffSMB".to_vec();
            message.push(command);
            message.extend_from_slice(&[0; 4]); // status
            message.push(0x98); // flags
            message.extend_from_slice(&0xc801u16.to_le_bytes()); // flags2
            message.resize(32, 0);
            message.push((words.len() / 2) as u8);
            message.extend_from_slice(words);
            message.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
            message.extend_from_slice(bytes);
            framed_message(&message)
        }
        let utf16 = |text: &str| -> Vec<u8> {
            text.encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect()
        };
        let mut names = vec![0u8]; // pad to an even offset
        for name in ["Windows 5.1", "Windows 2000 LAN Manager", "WORKGROUP"] {
            names.extend(utf16(name));
        }

        let negotiated = smb1(0x72, &[0, 0], &[]);
        let session = smb1(0x73, &[0xff, 0, 0, 0, 0, 0], &names);
        let addr = smb_server(negotiated.clone(), [negotiated, session].concat()).await;

        let identified = fingerprint_445(addr).await;
        assert_eq!(identified.port.service().map(|s| s.name()), Some("smb"));
        let os = identified
            .about_the_host
            .os
            .iter()
            .find_map(|os| os.product.as_deref());
        assert_eq!(os, Some("Windows XP"));
    }
}
