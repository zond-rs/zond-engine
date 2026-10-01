// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # TLS handshake probes
//!
//! Builds the ClientHello an enumeration puts on the wire and reads the first
//! record that comes back. What an answer means about an endpoint is the
//! caller's to decide, as with [`tcp`](super::tcp) and [`sctp`](super::sctp).
//!
//! ## Asking, without answering
//!
//! An enumeration offers a version and a set of cipher suites, reads which one
//! the server picked out of the ServerHello, and hangs up. No key is derived and
//! no record decrypted, so no crypto library is needed.
//!
//! Building hellos by hand also lets the enumeration offer what real clients
//! refuse to. `rustls` (used by `fingerprint::tls` for certificates) speaks TLS
//! 1.2 and 1.3 with the nine AEAD suites of its ring provider, and will not
//! speak SSL 3.0, RC4, 3DES or export ciphers, which are exactly what a report
//! is asked about.
//!
//! ## TLS 1.3 negotiates its version in an extension
//!
//! Through 1.2 the version is named in the ClientHello's version field and
//! echoed in the ServerHello's. RFC 8446 §4.1.2 freezes both at `0x0303` for
//! TLS 1.3 and negotiates in the `supported_versions` extension, so
//! [`read_response`] looks there first and falls back to the field. Trusting
//! the field would report every TLS 1.3 server as 1.2.
//!
//! ## HelloRetryRequest is a ServerHello
//!
//! RFC 8446 §4.1.4 lets a TLS 1.3 server ask for a different key share with a
//! ServerHello carrying a fixed random ([`HELLO_RETRY_RANDOM`]). It names the
//! selected suite like an ordinary ServerHello, so it is read as an answer and
//! flagged.

use crate::model::tls::{CipherSuite, TlsVersion};

/// Record content types (RFC 8446 §5.1): the two an enumeration can receive as
/// a first record.
mod content_type {
    /// A handshake message: what a ServerHello arrives in.
    pub const HANDSHAKE: u8 = 22;
    /// An alert: a peer speaking TLS and declining the terms.
    pub const ALERT: u8 = 21;
}

/// Handshake message types (RFC 8446 §4).
mod handshake_type {
    /// The message this module builds.
    pub const CLIENT_HELLO: u8 = 1;
    /// The message it reads, HelloRetryRequest included.
    pub const SERVER_HELLO: u8 = 2;
}

/// Extension numbers (IANA TLS ExtensionType registry).
mod extension {
    /// RFC 6066 §3, the name the client is asking for.
    pub const SERVER_NAME: u16 = 0;
    /// RFC 8422 §5.1.1, the curves and finite-field groups on offer.
    pub const SUPPORTED_GROUPS: u16 = 10;
    /// RFC 8422 §5.1.2. Legacy, and some stacks still refuse ECDHE without it.
    pub const EC_POINT_FORMATS: u16 = 11;
    /// RFC 8446 §4.2.3. Mandatory from TLS 1.2 upward.
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    /// RFC 8446 §4.2.1, where TLS 1.3 is actually asked for.
    pub const SUPPORTED_VERSIONS: u16 = 43;
    /// RFC 8446 §4.2.8, the client's share of the TLS 1.3 key exchange.
    pub const KEY_SHARE: u16 = 51;
}

/// The random a TLS 1.3 server writes into a HelloRetryRequest, which is the
/// SHA-256 of the string `"HelloRetryRequest"` (RFC 8446 §4.1.3).
///
///
/// A reader that does not check this reports a retry as a completed
/// negotiation.
pub const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// The bytes of a record header: content type, version, and a two-byte length.
pub const RECORD_HEADER_LEN: usize = 5;

/// The bytes of a handshake message's header: its type and a three-byte
/// length.
const HANDSHAKE_HEADER_LEN: usize = 4;

/// The largest record TLS permits (RFC 8446 §5.1), which bounds how much a
/// reader buffers.
pub const MAX_RECORD_LEN: usize = 16_384 + 2_048;

/// The groups a hello offers, which decide whether an ECDHE or DHE suite can be
/// negotiated at all.
///
/// A server with none in common must fall back to a static key exchange or
/// refuse, so a short list would report forward-secret suites unsupported on a
/// server that supports them. These are the groups current stacks implement.
const SUPPORTED_GROUPS: [u16; 7] = [
    0x001D, // x25519
    0x0017, // secp256r1
    0x0018, // secp384r1
    0x0019, // secp521r1
    0x0100, // ffdhe2048
    0x0101, // ffdhe3072
    0x0102, // ffdhe4096
];

/// The signature algorithms a hello offers.
///
/// Wide, SHA-1 and DSA included. A modern client omits those, but a server that
/// will only sign with SHA-1 is exactly what an enumeration looks for, and
/// would otherwise report as supporting nothing.
const SIGNATURE_ALGORITHMS: [u16; 14] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0603, // ecdsa_secp521r1_sha512
    0x0807, // ed25519
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0401, // rsa_pkcs1_sha256
    0x0501, // rsa_pkcs1_sha384
    0x0601, // rsa_pkcs1_sha512
    0x0402, // dsa_sha256
    0x0201, // rsa_pkcs1_sha1
    0x0203, // ecdsa_sha1
    0x0202, // dsa_sha1
];

/// The group a TLS 1.3 key share is offered under, and the length of a share in
/// it. X25519 (RFC 7748), which every TLS 1.3 stack implements.
const KEY_SHARE_GROUP: u16 = 0x001D;
const KEY_SHARE_LEN: usize = 32;

/// What a hello is asking for.
/// A version and the suites to offer under it. An enumeration narrows the
/// suites between attempts to discover what a server accepts.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct Offer<'a> {
    /// The version to negotiate. Decides where the number is written and
    /// whether the hello carries extensions at all.
    pub version: TlsVersion,
    /// The suites to offer, in the order they go on the wire. A server with a
    /// preference of its own ignores the order; one that takes the client's
    /// picks the first it can, so the strongest belongs first.
    pub suites: &'a [CipherSuite],
    /// The name to ask for, where the scan knows one: the name a target
    /// reached the address by.
    ///
    /// `None` sends no `server_name` extension. A growing number of servers answer
    /// a nameless hello with an alert or nothing, so an endpoint known only by
    /// address may show less than it would to a client that named it.
    pub server_name: Option<&'a str>,
}

/// What a server said in the first record it sent back.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerResponse {
    /// A ServerHello: the terms were accepted, and these are the ones chosen.
    Hello {
        /// The version negotiated, read from `supported_versions` where the
        /// server sent one and from the legacy field otherwise. `None` for a
        /// number no known version claims.
        version: Option<TlsVersion>,
        /// The suite selected, by its wire number, not a [`CipherSuite`]: a server
        /// may name one this build does not carry.
        suite: u16,
        /// Whether this was a HelloRetryRequest. The suite is chosen either way.
        retry: bool,
    },
    /// An alert: the peer speaks TLS and declined these terms.
    Alert {
        /// 1 for a warning, 2 for fatal (RFC 8446 §6).
        level: u8,
        /// The reason, such as 40 `handshake_failure` or 70
        /// `protocol_version`.
        description: u8,
    },
}

impl ServerResponse {
    /// Whether the server accepted the terms offered.
    pub const fn accepted(self) -> bool {
        matches!(self, Self::Hello { .. })
    }
}

/// Builds the ClientHello `offer` describes, wrapped in its record.
///
/// The random is drawn fresh for every hello, as a real client's is; a
/// constant random across the dozens of hellos an enumeration sends would be
/// a signature a filter could match.
///
/// SSL 3.0 hellos carry no extensions: they predate them (RFC 6066 extends
/// TLS, not SSL), and a stack old enough to offer SSL 3.0 is the most likely to
/// drop a hello it cannot parse.
pub fn client_hello(offer: &Offer<'_>) -> Vec<u8> {
    let mut body = Vec::with_capacity(512);

    // TLS 1.3 says 1.2 here and negotiates in the extension (RFC 8446 §4.1.2).
    let legacy_version = match offer.version {
        TlsVersion::Tls13 => TlsVersion::Tls12.code(),
        version => version.code(),
    };
    body.extend_from_slice(&legacy_version.to_be_bytes());

    let random: [u8; 32] = rand::random();
    body.extend_from_slice(&random);

    // No session to resume.
    body.push(0);

    let suites_len = offer.suites.len() * 2;
    body.extend_from_slice(&(suites_len as u16).to_be_bytes());
    for suite in offer.suites {
        body.extend_from_slice(&suite.code().to_be_bytes());
    }

    // Null compression only. Offering DEFLATE is the CRIME question, asked
    // separately.
    body.push(1);
    body.push(0);

    if offer.version != TlsVersion::Ssl30 {
        let extensions = extensions(offer);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
    }

    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(handshake_type::CLIENT_HELLO);
    handshake.extend_from_slice(&three_byte_len(body.len()));
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(handshake.len() + RECORD_HEADER_LEN);
    record.push(content_type::HANDSHAKE);
    // RFC 8446 §5.1 fixes a first record's version at 0x0301 whatever is
    // negotiated inside it; middleboxes drop records announcing anything else.
    record.extend_from_slice(&TlsVersion::Tls10.code().to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// The extension block for `offer`.
fn extensions(offer: &Offer<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);

    if let Some(name) = offer.server_name {
        // RFC 6066 §3: a list of names, each a type byte and a length-prefixed
        // string. Only `host_name`, type 0, is defined.
        let name = name.as_bytes();
        let mut value = Vec::with_capacity(name.len() + 5);
        value.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        value.push(0);
        value.extend_from_slice(&(name.len() as u16).to_be_bytes());
        value.extend_from_slice(name);
        push_extension(&mut out, extension::SERVER_NAME, &value);
    }

    let mut groups = Vec::with_capacity(SUPPORTED_GROUPS.len() * 2 + 2);
    groups.extend_from_slice(&((SUPPORTED_GROUPS.len() * 2) as u16).to_be_bytes());
    for group in SUPPORTED_GROUPS {
        groups.extend_from_slice(&group.to_be_bytes());
    }
    push_extension(&mut out, extension::SUPPORTED_GROUPS, &groups);

    // One format, uncompressed. RFC 8422 §5.1.2.
    push_extension(&mut out, extension::EC_POINT_FORMATS, &[1, 0]);

    let mut algorithms = Vec::with_capacity(SIGNATURE_ALGORITHMS.len() * 2 + 2);
    algorithms.extend_from_slice(&((SIGNATURE_ALGORITHMS.len() * 2) as u16).to_be_bytes());
    for algorithm in SIGNATURE_ALGORITHMS {
        algorithms.extend_from_slice(&algorithm.to_be_bytes());
    }
    push_extension(&mut out, extension::SIGNATURE_ALGORITHMS, &algorithms);

    if offer.version == TlsVersion::Tls13 {
        // A one-entry list: offering more would let the server answer about a
        // version this hello carries no suites for.
        push_extension(&mut out, extension::SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);

        // A valid key share, so the server answers with a ServerHello and not the
        // HelloRetryRequest an empty share would provoke. The bytes are random:
        // X25519 accepts any 32 bytes as a public key (RFC 7748 §5), and the
        // connection closes before the result matters.
        let share: [u8; KEY_SHARE_LEN] = rand::random();
        let mut key_share = Vec::with_capacity(KEY_SHARE_LEN + 6);
        key_share.extend_from_slice(&((KEY_SHARE_LEN + 4) as u16).to_be_bytes());
        key_share.extend_from_slice(&KEY_SHARE_GROUP.to_be_bytes());
        key_share.extend_from_slice(&(KEY_SHARE_LEN as u16).to_be_bytes());
        key_share.extend_from_slice(&share);
        push_extension(&mut out, extension::KEY_SHARE, &key_share);
    }

    out
}

/// Appends one extension: its number, its length, and its value.
fn push_extension(out: &mut Vec<u8>, number: u16, value: &[u8]) {
    out.extend_from_slice(&number.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// A handshake message's three-byte length field.
fn three_byte_len(len: usize) -> [u8; 3] {
    let bytes = (len as u32).to_be_bytes();
    [bytes[1], bytes[2], bytes[3]]
}

/// How many bytes the first record in `bytes` occupies in total, header
/// included, or `None` while the header itself is incomplete.
///
/// TCP delivers a record in pieces; a reader loops until this says enough has
/// arrived. A length past [`MAX_RECORD_LEN`] is refused at once, so a stranger
/// cannot decide how much a reader buffers.
pub fn record_length(bytes: &[u8]) -> Option<usize> {
    let header: &[u8; RECORD_HEADER_LEN] = bytes.first_chunk()?;
    let declared = usize::from(u16::from_be_bytes([header[3], header[4]]));
    (declared <= MAX_RECORD_LEN).then_some(RECORD_HEADER_LEN + declared)
}

/// Reads the first record of `bytes` as a server's answer to a hello, or `None`
/// where it is not one.
///
/// `None` for bytes that are not TLS, a record carrying neither a handshake
/// nor an alert, and a record too short for what it claims.
///
/// Every offset is checked against what arrived, so the walk terminates on any
/// input.
pub fn read_response(bytes: &[u8]) -> Option<ServerResponse> {
    let (content, body) = record_body(bytes)?;

    match content {
        content_type::ALERT => {
            let alert: &[u8; 2] = body.first_chunk()?;
            Some(ServerResponse::Alert {
                level: alert[0],
                description: alert[1],
            })
        }
        content_type::HANDSHAKE => read_server_hello(body),
        _ => None,
    }
}

/// Where the ServerHello a server's first record opens with ends, counted
/// from the start of `bytes`, or `None` where the record does not open with a
/// whole one.
///
/// For a reader that walks the hello by its own offsets and needs to know that
/// all of it arrived and where it stops. Bounded exactly as [`read_response`]
/// reads.
pub(crate) fn server_hello_end(bytes: &[u8]) -> Option<usize> {
    let (content, body) = record_body(bytes)?;
    if content != content_type::HANDSHAKE {
        return None;
    }
    let message = hello_message(body)?;
    Some(RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + message.len())
}

/// The first record's content type and its body.
///
/// A record announcing more than it delivered is read for what it delivered,
/// and its contents are then judged by their own lengths.
fn record_body(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let header: &[u8; RECORD_HEADER_LEN] = bytes.first_chunk()?;
    let declared = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let body = bytes.get(RECORD_HEADER_LEN..)?;
    Some((header[0], body.get(..declared.min(body.len()))?))
}

/// Reads a ServerHello out of a handshake record's body.
///
/// ```text
/// 02 | 00 00 46 | 03 03 | 32 bytes random | 20 <session id> | 13 01 | 00 | 00 2e <extensions>
/// └ type        └ length  └ legacy version                    └ suite  └ compression
/// ```
fn read_server_hello(body: &[u8]) -> Option<ServerResponse> {
    let message = hello_message(body)?;

    let legacy_version = u16::from_be_bytes([*message.first()?, *message.get(1)?]);
    let random: &[u8; 32] = message.get(2..34)?.try_into().ok()?;
    let retry = *random == HELLO_RETRY_RANDOM;

    let session_len = usize::from(*message.get(34)?);
    let rest = message.get(35 + session_len..)?;

    let suite = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]);

    // Compression method and extensions are both optional in a TLS 1.2
    // ServerHello, so a message that ends here still yields its version.
    let version = rest
        .get(3..)
        .and_then(negotiated_version)
        .or_else(|| TlsVersion::from_code(legacy_version));

    Some(ServerResponse::Hello {
        version,
        suite,
        retry,
    })
}

/// The ServerHello a handshake record's body opens with, from its legacy
/// version to the end of its extensions, or `None` where the body opens with
/// something else or the message has not all arrived.
///
/// Exactly as long as the message declares itself, and both bounds matter.
/// Short of it, a TLS 1.3 hello cut before `supported_versions` would read as
/// the TLS 1.2 its legacy field says. Past it is whatever the server coalesced
/// into the record (RFC 8446 §5.1): after a hello without extensions, the next
/// message would be walked as its extensions.
fn hello_message(body: &[u8]) -> Option<&[u8]> {
    if *body.first()? != handshake_type::SERVER_HELLO {
        return None;
    }
    let declared = u32::from_be_bytes([0, *body.get(1)?, *body.get(2)?, *body.get(3)?]) as usize;
    body.get(HANDSHAKE_HEADER_LEN..)?.get(..declared)
}

/// The version a ServerHello's `supported_versions` extension names, or `None`
/// where it carries none.
///
/// The only place a TLS 1.3 negotiation is visible. `extensions` is the
/// two-byte-prefixed block after the compression method.
fn negotiated_version(extensions: &[u8]) -> Option<TlsVersion> {
    let declared = usize::from(u16::from_be_bytes([
        *extensions.first()?,
        *extensions.get(1)?,
    ]));
    let mut rest = extensions.get(2..)?;
    rest = rest.get(..declared.min(rest.len()))?;

    while rest.len() >= 4 {
        let number = u16::from_be_bytes([rest[0], rest[1]]);
        let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        let value = rest.get(4..4 + len)?;

        if number == extension::SUPPORTED_VERSIONS {
            // In a ServerHello the extension carries one version with no list header
            // (RFC 8446 §4.2.1).
            let selected: &[u8; 2] = value.first_chunk()?;
            return TlsVersion::from_code(u16::from_be_bytes(*selected));
        }

        rest = rest.get(4 + len..)?;
    }
    None
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

    fn offer(version: TlsVersion) -> Vec<CipherSuite> {
        CipherSuite::offered_under(version).take(4).collect()
    }

    /// A server silently drops a hello whose length fields disagree with its
    /// contents, so the record and the handshake each count exactly what follows.
    #[test]
    fn a_hello_declares_its_own_lengths_correctly() {
        for &version in TlsVersion::ALL {
            let suites = offer(version);
            let hello = client_hello(&Offer {
                version,
                suites: &suites,
                server_name: None,
            });

            assert_eq!(hello[0], content_type::HANDSHAKE, "{version}");
            let record_len = u16::from_be_bytes([hello[3], hello[4]]);
            assert_eq!(
                usize::from(record_len),
                hello.len() - RECORD_HEADER_LEN,
                "the record must count everything after its header, under {version}"
            );

            assert_eq!(hello[5], handshake_type::CLIENT_HELLO, "{version}");
            let handshake_len = u32::from_be_bytes([0, hello[6], hello[7], hello[8]]);
            assert_eq!(
                handshake_len as usize,
                hello.len() - 9,
                "the handshake must count everything after its own header, under {version}"
            );

            assert_eq!(
                record_length(&hello),
                Some(hello.len()),
                "a reader must find the whole record, under {version}"
            );
        }
    }

    /// The suites go on the wire in the order given, which a server honouring
    /// the client's preference reads.
    #[test]
    fn a_hello_offers_the_suites_it_was_given_in_order() {
        let suites: Vec<_> = CipherSuite::offered_under(TlsVersion::Tls12)
            .take(6)
            .collect();
        let hello = client_hello(&Offer {
            version: TlsVersion::Tls12,
            suites: &suites,
            server_name: None,
        });

        // Past the record header, the handshake header, the version, the random
        // and the empty session id.
        let offset = RECORD_HEADER_LEN + 4 + 2 + 32 + 1;
        let declared = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
        assert_eq!(usize::from(declared), suites.len() * 2);

        let on_the_wire: Vec<u16> = hello[offset + 2..offset + 2 + suites.len() * 2]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .collect();
        let expected: Vec<u16> = suites.iter().map(|suite| suite.code()).collect();
        assert_eq!(on_the_wire, expected);
    }

    /// TLS 1.3 is asked for only in the extension. `0x0304` in the version field
    /// would be refused by every conformant server.
    #[test]
    fn tls13_is_asked_for_in_the_extension_and_not_the_version_field() {
        let suites = offer(TlsVersion::Tls13);
        let hello = client_hello(&Offer {
            version: TlsVersion::Tls13,
            suites: &suites,
            server_name: None,
        });

        let version_field = u16::from_be_bytes([hello[9], hello[10]]);
        assert_eq!(
            version_field,
            TlsVersion::Tls12.code(),
            "RFC 8446 §4.1.2 freezes the field at 0x0303"
        );
        assert!(
            contains_extension(&hello, extension::SUPPORTED_VERSIONS),
            "1.3 has to be asked for through supported_versions"
        );
        assert!(
            contains_extension(&hello, extension::KEY_SHARE),
            "a share the server can answer without a retry"
        );
    }

    /// Every other version is named in the field, without the 1.3 extensions.
    #[test]
    fn the_older_versions_are_asked_for_in_the_version_field() {
        for version in [TlsVersion::Tls10, TlsVersion::Tls11, TlsVersion::Tls12] {
            let suites = offer(version);
            let hello = client_hello(&Offer {
                version,
                suites: &suites,
                server_name: None,
            });
            assert_eq!(u16::from_be_bytes([hello[9], hello[10]]), version.code());
            assert!(!contains_extension(&hello, extension::SUPPORTED_VERSIONS));
            assert!(!contains_extension(&hello, extension::KEY_SHARE));
        }
    }

    /// SSL 3.0 predates extensions.
    #[test]
    fn an_ssl3_hello_carries_no_extensions_at_all() {
        let suites = offer(TlsVersion::Ssl30);
        let hello = client_hello(&Offer {
            version: TlsVersion::Ssl30,
            suites: &suites,
            server_name: None,
        });

        // The message ends at the compression list: version, random, session id,
        // suites, and one compression method.
        let expected = RECORD_HEADER_LEN + 4 + 2 + 32 + 1 + 2 + suites.len() * 2 + 2;
        assert_eq!(
            hello.len(),
            expected,
            "an SSLv3 hello has nothing after compression"
        );
    }

    /// A name goes on the wire as RFC 6066 §3 gives it; with no name there is no
    /// extension.
    #[test]
    fn a_server_name_reaches_the_wire_and_its_absence_sends_nothing() {
        let suites = offer(TlsVersion::Tls12);
        let named = client_hello(&Offer {
            version: TlsVersion::Tls12,
            suites: &suites,
            server_name: Some("example.test"),
        });
        assert!(contains_extension(&named, extension::SERVER_NAME));
        assert!(
            named
                .windows(b"example.test".len())
                .any(|window| window == b"example.test"),
            "the name itself has to be on the wire"
        );

        let anonymous = client_hello(&Offer {
            version: TlsVersion::Tls12,
            suites: &suites,
            server_name: None,
        });
        assert!(!contains_extension(&anonymous, extension::SERVER_NAME));
    }

    /// Two hellos have different randoms.
    #[test]
    fn two_hellos_do_not_carry_the_same_random() {
        let suites = offer(TlsVersion::Tls12);
        let build = || {
            client_hello(&Offer {
                version: TlsVersion::Tls12,
                suites: &suites,
                server_name: None,
            })
        };
        assert_ne!(build(), build());
    }

    // ── Reading ──────────────────────────────────────────────────────────────

    /// A ServerHello built from the RFC layout independently of the code above,
    /// so the tests assert the protocol.
    fn server_hello(
        legacy_version: u16,
        suite: u16,
        random: [u8; 32],
        extensions: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut body = vec![handshake_type::SERVER_HELLO, 0, 0, 0];
        body.extend_from_slice(&legacy_version.to_be_bytes());
        body.extend_from_slice(&random);
        body.push(0); // no session id
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0); // null compression
        if let Some(extensions) = extensions {
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(extensions);
        }
        let length = body.len() - 4;
        body[1..4].copy_from_slice(&three_byte_len(length));

        let mut record = vec![content_type::HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }

    /// The ordinary case: a server names its version in the field and its suite
    /// beside it.
    #[test]
    fn a_server_hello_names_the_version_and_the_suite() {
        let record = server_hello(0x0303, 0xC02F, [0u8; 32], None);
        assert_eq!(
            read_response(&record),
            Some(ServerResponse::Hello {
                version: Some(TlsVersion::Tls12),
                suite: 0xC02F,
                retry: false,
            })
        );
    }

    /// Every TLS 1.3 server writes 1.2 in the field and 1.3 in the extension.
    #[test]
    fn tls13_is_read_from_the_extension_rather_than_the_field() {
        let extensions = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04];
        let record = server_hello(0x0303, 0x1301, [0u8; 32], Some(&extensions));
        assert_eq!(
            read_response(&record),
            Some(ServerResponse::Hello {
                version: Some(TlsVersion::Tls13),
                suite: 0x1301,
                retry: false,
            })
        );
    }

    /// The extension is found behind others, since servers order their own.
    #[test]
    fn the_version_extension_is_found_behind_others() {
        let extensions = [
            0x00, 0x33, 0x00, 0x02, 0xAA, 0xBB, // key_share, skipped
            0xFF, 0x01, 0x00, 0x01, 0x00, // renegotiation_info, skipped
            0x00, 0x2B, 0x00, 0x02, 0x03, 0x04, // supported_versions
        ];
        let record = server_hello(0x0303, 0x1302, [0u8; 32], Some(&extensions));
        assert!(matches!(
            read_response(&record),
            Some(ServerResponse::Hello {
                version: Some(TlsVersion::Tls13),
                ..
            })
        ));
    }

    /// A HelloRetryRequest names the suite like a completed ServerHello, and is
    /// flagged so a caller does not mistake it for a negotiation.
    #[test]
    fn a_hello_retry_request_is_an_answer_and_says_so() {
        let extensions = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04];
        let record = server_hello(0x0303, 0x1301, HELLO_RETRY_RANDOM, Some(&extensions));
        assert_eq!(
            read_response(&record),
            Some(ServerResponse::Hello {
                version: Some(TlsVersion::Tls13),
                suite: 0x1301,
                retry: true,
            })
        );
    }

    /// A session id shifts everything behind it.
    #[test]
    fn a_session_id_does_not_move_the_suite() {
        let mut body = vec![handshake_type::SERVER_HELLO, 0, 0, 0];
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(32);
        body.extend_from_slice(&[0xAB; 32]);
        body.extend_from_slice(&0x009Cu16.to_be_bytes());
        body.push(0);
        let length = body.len() - 4;
        body[1..4].copy_from_slice(&three_byte_len(length));

        let mut record = vec![content_type::HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);

        assert!(matches!(
            read_response(&record),
            Some(ServerResponse::Hello { suite: 0x009C, .. })
        ));
    }

    /// An alert is the peer declining these terms, which an enumeration reads as
    /// the end of a version.
    #[test]
    fn an_alert_is_read_as_a_refusal_with_its_reason() {
        // Fatal, handshake_failure.
        let record = [content_type::ALERT, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert_eq!(
            read_response(&record),
            Some(ServerResponse::Alert {
                level: 2,
                description: 40,
            })
        );
        assert!(!read_response(&record).expect("an answer").accepted());
    }

    /// Anything that is not a server answering a hello names nothing, and a
    /// truncated record is refused.
    #[test]
    fn what_is_not_an_answer_is_not_read_as_one() {
        assert_eq!(read_response(b"HTTP/1.1 200 OK"), None);
        assert_eq!(read_response(b"SSH-2.0-OpenSSH_9.6p1"), None);
        assert_eq!(read_response(&[]), None);
        // A record header with nothing behind it.
        assert_eq!(read_response(&[0x16, 0x03, 0x03, 0x00, 0x4A]), None);
        // A handshake that is not a ServerHello.
        assert_eq!(
            read_response(&[0x16, 0x03, 0x03, 0x00, 0x04, 0x0B, 0x00, 0x00, 0x00]),
            None
        );
        // A ServerHello cut off inside its random.
        let mut short = server_hello(0x0303, 0xC02F, [0u8; 32], None);
        short.truncate(RECORD_HEADER_LEN + 20);
        assert_eq!(read_response(&short), None);
        // A content type that is neither a handshake nor an alert.
        assert_eq!(
            read_response(&[0x17, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00]),
            None
        );
    }

    /// A record announcing more than any peer may send is refused immediately.
    #[test]
    fn a_record_longer_than_tls_permits_is_refused() {
        let absurd = [0x16, 0x03, 0x03, 0xFF, 0xFF];
        assert_eq!(record_length(&absurd), None);

        let largest = u16::try_from(MAX_RECORD_LEN).expect("fits").to_be_bytes();
        let permitted = [0x16, 0x03, 0x03, largest[0], largest[1]];
        assert_eq!(
            record_length(&permitted),
            Some(RECORD_HEADER_LEN + MAX_RECORD_LEN)
        );
        assert_eq!(
            record_length(&[0x16, 0x03]),
            None,
            "the header is not here yet"
        );
    }

    /// Whether an extension is present in a built hello, found by walking the
    /// block: a two-byte value could also appear inside the random.
    fn contains_extension(hello: &[u8], number: u16) -> bool {
        let after_random = RECORD_HEADER_LEN + 4 + 2 + 32;
        let session_len = usize::from(hello[after_random]);
        let mut rest = &hello[after_random + 1 + session_len..];

        let suites_len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        rest = &rest[2 + suites_len..];
        let compression_len = usize::from(rest[0]);
        rest = &rest[1 + compression_len..];

        if rest.len() < 2 {
            return false;
        }
        let declared = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        let mut block = &rest[2..2 + declared];
        while block.len() >= 4 {
            let found = u16::from_be_bytes([block[0], block[1]]);
            let len = usize::from(u16::from_be_bytes([block[2], block[3]]));
            if found == number {
                return true;
            }
            block = &block[4 + len..];
        }
        false
    }

    proptest::proptest! {
        /// These bytes come from a stranger, so both walks terminate on any input.
        #[test]
        fn reading_an_answer_never_panics(
            record in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)
        ) {
            let _ = read_response(&record);
            let _ = record_length(&record);
        }

        /// The same for a record that starts like a handshake, which reaches
        /// furthest into the walk.
        #[test]
        fn reading_a_malformed_handshake_never_panics(
            body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)
        ) {
            let mut record = vec![content_type::HANDSHAKE, 0x03, 0x03];
            record.extend_from_slice(&(body.len() as u16).to_be_bytes());
            record.extend_from_slice(&body);
            let _ = read_response(&record);
        }
    }

    // ── Reading a stranger's bytes ───────────────────────────────────────────

    /// **The truncation property**, as `wire/ethernet_frame` holds it for frames:
    /// reading more bytes never changes what a shorter read reported, so a peer
    /// dribbling a record out in pieces cannot change the answer.
    ///
    /// Held across every prefix of a well-formed ServerHello. The record is only
    /// whole at the last prefix, so every earlier one must yield `None`.
    #[test]
    fn a_prefix_of_a_record_never_reads_as_more_than_the_whole_does() {
        let extensions = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04];
        let record = server_hello(0x0303, 0x1301, [0x5A; 32], Some(&extensions));
        let whole = read_response(&record);
        assert!(
            whole.is_some(),
            "the fixture has to be readable to test this"
        );

        for cut in 0..record.len() {
            let short = read_response(&record[..cut]);
            assert!(
                short.is_none() || short == whole,
                "a {cut}-byte prefix read as {short:?}, where the whole record reads as {whole:?}"
            );
        }
    }

    /// The same property for the alert path, which has its own early return.
    #[test]
    fn a_prefix_of_an_alert_never_invents_one() {
        let alert = vec![content_type::ALERT, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        let whole = read_response(&alert);
        assert_eq!(
            whole,
            Some(ServerResponse::Alert {
                level: 2,
                description: 40
            })
        );
        for cut in 0..alert.len() {
            assert!(read_response(&alert[..cut]).is_none(), "cut at {cut}");
        }
    }

    /// Every length field in a ServerHello is a stranger's. None may cause a
    /// panic.
    #[test]
    fn no_length_field_can_walk_the_reader_off_the_end() {
        let base = server_hello(
            0x0303,
            0xC02F,
            [0u8; 32],
            Some(&[0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]),
        );

        // Every byte set to each extreme a length field can take. The assertion is
        // that the call returns.
        for at in 0..base.len() {
            for poison in [0x00u8, 0x01, 0x7F, 0x80, 0xFE, 0xFF] {
                let mut bytes = base.clone();
                bytes[at] = poison;
                let _ = read_response(&bytes);
                let _ = record_length(&bytes);
            }
        }
    }

    /// A record whose declared length runs past what arrived is read for what
    /// arrived; one past what TLS permits is refused outright.
    #[test]
    fn a_lying_record_length_neither_panics_nor_is_believed() {
        let mut record = server_hello(0x0303, 0xC02F, [0u8; 32], None);

        // Claims far more than it carries.
        record[3..5].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert_eq!(
            record_length(&record),
            None,
            "a record past MAX_RECORD_LEN is refused rather than buffered toward"
        );
        // And is still read for the bytes that are really there.
        assert!(read_response(&record).is_some());

        // Claims fewer bytes than the ServerHello needs, so the walk runs out.
        record[3..5].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(read_response(&record), None);
    }

    /// Extension entries claiming more than the block holds end the search, and
    /// the reader falls back to the legacy version field.
    #[test]
    fn an_overlong_extension_does_not_escape_its_block() {
        // One extension declaring 0xFFFF bytes of value and carrying none.
        let extensions = [0x00, 0x2B, 0xFF, 0xFF];
        let record = server_hello(0x0303, 0xC02F, [0u8; 32], Some(&extensions));

        assert_eq!(
            read_response(&record),
            Some(ServerResponse::Hello {
                version: Some(TlsVersion::Tls12),
                suite: 0xC02F,
                retry: false,
            }),
            "the block is bounded and the legacy field answers"
        );
    }

    /// The largest session id shifts the suite past the end of every real
    /// message.
    #[test]
    fn a_session_id_longer_than_the_message_is_refused() {
        let mut body = vec![handshake_type::SERVER_HELLO, 0, 0, 0];
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(255); // claims 255 bytes of session id
        body.extend_from_slice(&0xC02Fu16.to_be_bytes());
        body.push(0);
        let length = body.len() - 4;
        body[1..4].copy_from_slice(&three_byte_len(length));

        let mut record = vec![content_type::HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);

        assert_eq!(read_response(&record), None);
    }

    /// **A hello cut short is refused**, by checking the handshake's declared
    /// length.
    ///
    /// A TLS 1.3 ServerHello cut before `supported_versions` reads fine and says
    /// `0x0303` in the legacy field, so answering from it would report a 1.3 server
    /// as 1.2 whenever a peer stops sending.
    #[test]
    fn a_truncated_tls13_hello_is_refused_rather_than_read_as_tls12() {
        let extensions = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04];
        let record = server_hello(0x0303, 0x1301, [0x5A; 32], Some(&extensions));

        // Everything up to but not including the extension block: version,
        // random, empty session id, suite, compression.
        let short = RECORD_HEADER_LEN + 4 + 2 + 32 + 1 + 2 + 1;
        assert!(short < record.len());

        assert_eq!(
            read_response(&record[..short]),
            None,
            "a hello whose extensions have not arrived settles nothing"
        );
        assert!(matches!(
            read_response(&record),
            Some(ServerResponse::Hello {
                version: Some(TlsVersion::Tls13),
                ..
            })
        ));
    }

    /// Several handshake messages in one record are legal (RFC 8446 §5.1), so
    /// bytes past this message do not contradict its length.
    #[test]
    fn a_coalesced_record_is_read_for_its_first_message() {
        let mut record = server_hello(0x0303, 0xC02F, [0u8; 32], None);
        let body_len = record.len() - RECORD_HEADER_LEN;

        // Append a second handshake message and widen the record to cover it.
        let trailer = [0x0Bu8, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        record.extend_from_slice(&trailer);
        let widened = (body_len + trailer.len()) as u16;
        record[3..5].copy_from_slice(&widened.to_be_bytes());

        assert_eq!(
            read_response(&record),
            Some(ServerResponse::Hello {
                version: Some(TlsVersion::Tls12),
                suite: 0xC02F,
                retry: false,
            })
        );
    }

    /// Where a hello ends, for a reader walking it by its own offsets: at the end
    /// of its message, and `None` on every prefix short of that.
    #[test]
    fn a_hello_ends_where_its_message_does() {
        let extensions = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04];
        let hello = server_hello(0x0303, 0x1301, [0u8; 32], Some(&extensions));

        assert_eq!(server_hello_end(&hello), Some(hello.len()));
        for cut in 0..hello.len() {
            assert_eq!(server_hello_end(&hello[..cut]), None, "{cut} bytes");
        }

        let mut coalesced = hello.clone();
        let trailer = [0x0Bu8, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        coalesced.extend_from_slice(&trailer);
        let widened = (hello.len() - RECORD_HEADER_LEN + trailer.len()) as u16;
        coalesced[3..5].copy_from_slice(&widened.to_be_bytes());
        assert_eq!(server_hello_end(&coalesced), Some(hello.len()));

        let alert = [content_type::ALERT, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert_eq!(server_hello_end(&alert), None);
    }

    /// The message's own length is where its extensions end.
    ///
    /// A TLS 1.2 ServerHello may carry no extensions, and the bytes after its
    /// compression method are then the next message. The trailer here is a
    /// Certificate built to spell TLS 1.3 if misread as an extension block.
    #[test]
    fn a_hello_without_extensions_does_not_read_the_next_message_as_them() {
        let mut record = server_hello(0x0303, 0xC02F, [0u8; 32], None);
        let body_len = record.len() - RECORD_HEADER_LEN;

        // Read as an extension block: a block length of 0x0B00, then
        // `supported_versions` naming 0x0304.
        let mut trailer = vec![0x0B, 0x00, 0x00, 0x2B, 0x00, 0x02, 0x03, 0x04];
        trailer.resize(4 + 0x2B, 0xAA);
        record.extend_from_slice(&trailer);
        let widened = (body_len + trailer.len()) as u16;
        record[3..5].copy_from_slice(&widened.to_be_bytes());

        assert_eq!(
            read_response(&record),
            Some(ServerResponse::Hello {
                version: Some(TlsVersion::Tls12),
                suite: 0xC02F,
                retry: false,
            }),
            "the hello named 1.2 and carried nothing that says otherwise"
        );
    }
}
