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
//! record that comes back. What an answer *means* about an endpoint is the
//! caller's to decide, as with [`tcp`](super::tcp) and [`sctp`](super::sctp);
//! this module knows only what a handshake record is.
//!
//! ## Asking, without answering
//!
//! An enumeration never completes a handshake. It offers a version and a set of
//! cipher suites, reads which one the server picked out of the ServerHello, and
//! hangs up. That is the whole exchange, and it is why none of this needs a
//! crypto library: no key is derived, no record is decrypted, and nothing is
//! sent that a key would protect.
//!
//! It is also why the enumeration can ask about the versions and suites a real
//! TLS client refuses to offer. `rustls`, which
//! the `fingerprint::tls` module uses for certificates,
//! implements TLS 1.2 and 1.3 and the nine AEAD suites of its ring provider, and
//! declines by design to speak SSL 3.0, RC4, 3DES or an export cipher. Those are
//! precisely the configurations a report is asked about, so the question has to
//! be put by hand.
//!
//! ## TLS 1.3 negotiates its version somewhere else
//!
//! Every version through 1.2 is named in the ClientHello's version field and
//! echoed in the ServerHello's. TLS 1.3 is not: RFC 8446 §4.1.2 freezes both
//! fields at `0x0303` and moves the real negotiation into the
//! `supported_versions` extension, in the ClientHello and again in the
//! ServerHello. A reader that trusted the version field would report every TLS
//! 1.3 server as 1.2, so [`read_response`] looks in the extension first and
//! falls back to the field.
//!
//! ## HelloRetryRequest is a ServerHello
//!
//! RFC 8446 §4.1.4 gives a TLS 1.3 server a way to ask for a different key
//! share, and the message it sends is a ServerHello carrying a fixed random
//! ([`HELLO_RETRY_RANDOM`]) rather than a message type of its own. It names the
//! selected cipher suite exactly as an ordinary ServerHello does, which is all
//! an enumeration wanted, so it is read as an answer and flagged rather than
//! treated as a refusal.

use crate::model::tls::{CipherSuite, TlsVersion};

/// Record content types (RFC 8446 §5.1). Only the two an enumeration can
/// receive as a first record.
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
/// A fixed value rather than a message type is how the RFC keeps the retry
/// indistinguishable from a ServerHello to anything that does not know to look,
/// so a reader that does not check this reports a retry as a completed
/// negotiation.
pub const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// The bytes of a record header: content type, version, and a two-byte length.
pub const RECORD_HEADER_LEN: usize = 5;

/// The largest record TLS permits (RFC 8446 §5.1), which bounds what a reader
/// has to be willing to buffer before it can refuse.
pub const MAX_RECORD_LEN: usize = 16_384 + 2_048;

/// The groups a hello offers, which decide whether an ECDHE or DHE suite can be
/// negotiated at all.
///
/// A server with none of these in common has to fall back to a static key
/// exchange or refuse, so a list that is too short would report forward-secret
/// suites unsupported on a server that supports them. These are the curves and
/// finite-field groups current stacks implement.
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
/// Deliberately wide, SHA-1 and DSA included. A modern client omits those and an
/// enumeration must not: a server that will only sign with SHA-1 is exactly the
/// server this exists to find, and refusing to offer the algorithm would report
/// it as supporting nothing.
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
///
/// A version and the suites to offer under it. The suites are the caller's
/// because an enumeration narrows them between attempts, which is the whole of
/// how it discovers what a server accepts.
#[derive(Debug, Clone, Copy)]
pub struct Offer<'a> {
    /// The version to negotiate. Decides where the number is written and
    /// whether the hello carries extensions at all.
    pub version: TlsVersion,
    /// The suites to offer, in the order they go on the wire. A server with a
    /// preference of its own ignores the order; one that takes the client's
    /// picks the first it can, so the strongest belongs first.
    pub suites: &'a [CipherSuite],
    /// The name to ask for, where the scan knows one.
    ///
    /// `None` sends no `server_name` extension, and a growing number of servers
    /// answer a nameless hello with an alert or nothing at all. That is a real
    /// limit on what an enumeration can see, and it is the same one
    /// the `fingerprint::tls` module documents: the fix is
    /// upstream, in recording the name a target was resolved from, rather than
    /// here.
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
        /// The suite selected, by its wire number. A number rather than a
        /// [`CipherSuite`] because a server may name one this build does not
        /// carry, and a caller has to be able to tell that from a suite it
        /// offered.
        suite: u16,
        /// Whether this was a HelloRetryRequest rather than a completed
        /// selection. The suite is chosen either way.
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

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

/// Builds the ClientHello `offer` describes, wrapped in its record.
///
/// The random is drawn fresh for every hello. The legacy probe this module grew
/// out of used a fixed one, on the reasoning that nothing in it is a security
/// context; that holds for one packet and stops holding across the dozens an
/// enumeration sends, where a constant random is a signature any filter could
/// match the scan by. A real client draws a fresh one, so this does.
///
/// Extensions are omitted entirely under SSL 3.0, which predates them (RFC 6066
/// extends TLS, not SSL) and where a stack old enough to still be offering it is
/// the stack most likely to drop a hello it cannot parse. Every other version
/// carries the full block.
pub fn client_hello(offer: &Offer<'_>) -> Vec<u8> {
    let mut body = Vec::with_capacity(512);

    // The version field, which for TLS 1.3 says 1.2 and leaves the real answer
    // to the extension. RFC 8446 §4.1.2.
    let legacy_version = match offer.version {
        TlsVersion::Tls13 => TlsVersion::Tls12.code(),
        version => version.code(),
    };
    body.extend_from_slice(&legacy_version.to_be_bytes());

    let random: [u8; 32] = rand::random();
    body.extend_from_slice(&random);

    // No session to resume: a scan has never spoken to this endpoint before.
    body.push(0);

    let suites_len = offer.suites.len() * 2;
    body.extend_from_slice(&(suites_len as u16).to_be_bytes());
    for suite in offer.suites {
        body.extend_from_slice(&suite.code().to_be_bytes());
    }

    // One compression method, null. Offering DEFLATE is what CRIME is about and
    // is a question of its own rather than part of this one.
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
    // The record's own version, which RFC 8446 §5.1 fixes at 0x0301 for a first
    // record whatever is being negotiated inside it. Middleboxes drop records
    // announcing anything else.
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
        // string. Only `host_name`, type 0, has ever been defined.
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
        // The extension that actually asks for 1.3. A one-entry list, because
        // offering more would let the server answer about a version this hello
        // did not carry suites for.
        push_extension(&mut out, extension::SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);

        // A key share the server can complete against, so an ordinary
        // ServerHello comes back rather than the HelloRetryRequest an empty
        // share would provoke. The bytes are random and nothing is ever derived
        // from them: X25519 accepts any 32-byte string as a public key (RFC
        // 7748 §5), the server does one scalar multiplication, and this hangs up
        // before the result could matter.
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

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// How many bytes the first record in `bytes` occupies in total, header
/// included, or `None` while the header itself is incomplete.
///
/// What a reader loops on: TCP delivers a record in as many pieces as it likes,
/// and this says when enough has arrived to stop reading. A length past
/// [`MAX_RECORD_LEN`] is refused rather than waited for, since no conformant
/// peer sends one and a reader that trusted it would buffer whatever a stranger
/// asked it to.
pub fn record_length(bytes: &[u8]) -> Option<usize> {
    let header: &[u8; RECORD_HEADER_LEN] = bytes.first_chunk()?;
    let declared = usize::from(u16::from_be_bytes([header[3], header[4]]));
    (declared <= MAX_RECORD_LEN).then_some(RECORD_HEADER_LEN + declared)
}

/// Reads the first record of `bytes` as a server's answer to a hello, or `None`
/// where it is not one.
///
/// `None` covers three different things a caller treats alike: bytes that are
/// not TLS at all, a TLS record carrying something other than a handshake or an
/// alert, and a record too short to hold what it claims. None of them is a
/// server accepting the terms, which is the only question asked here.
///
/// Every offset is checked against what actually arrived. These bytes are a
/// stranger's and the walk has to terminate on any input rather than merely on a
/// well-formed one.
pub fn read_response(bytes: &[u8]) -> Option<ServerResponse> {
    let header: &[u8; RECORD_HEADER_LEN] = bytes.first_chunk()?;
    let declared = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let body = bytes.get(RECORD_HEADER_LEN..)?;
    // Trust the length field only as far as what arrived: a record announcing
    // more than it delivered is read for what it delivered.
    let body = body.get(..declared.min(body.len()))?;

    match header[0] {
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

/// Reads a ServerHello out of a handshake record's body.
///
/// ```text
/// 02 | 00 00 46 | 03 03 | 32 bytes random | 20 <session id> | 13 01 | 00 | 00 2e <extensions>
/// └ type        └ length  └ legacy version                    └ suite  └ compression
/// ```
fn read_server_hello(body: &[u8]) -> Option<ServerResponse> {
    if *body.first()? != handshake_type::SERVER_HELLO {
        return None;
    }

    // The handshake length, which says whether the whole message is here.
    //
    // It used to be skipped, on the reasoning that the record already bounds the
    // walk. That holds for a record which arrived whole and fails for one that
    // did not, and a peer decides which it sends: closing the connection part
    // way through a ServerHello leaves a body containing the version, the
    // random, the suite and no extensions, which every offset below then reads
    // successfully. A truncated TLS 1.3 hello was therefore reported as TLS 1.2,
    // because `supported_versions` had not arrived and the legacy field RFC 8446
    // §4.1.2 freezes at `0x0303` was taken at face value — the single reading
    // this module's own documentation exists to prevent.
    //
    // `<=` rather than `==`: RFC 8446 §5.1 lets a sender coalesce several
    // handshake messages into one record, so bytes beyond this message are
    // somebody else's and not a disagreement.
    let declared = u32::from_be_bytes([0, *body.get(1)?, *body.get(2)?, *body.get(3)?]) as usize;
    let after_header = body.get(4..)?;
    if declared > after_header.len() {
        return None;
    }

    let legacy_version = u16::from_be_bytes([*after_header.first()?, *after_header.get(1)?]);
    let random: &[u8; 32] = after_header.get(2..34)?.try_into().ok()?;
    let retry = *random == HELLO_RETRY_RANDOM;

    let session_len = usize::from(*after_header.get(34)?);
    let rest = after_header.get(35 + session_len..)?;

    let suite = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]);

    // The compression method, then the extension block. Both are optional in a
    // TLS 1.2 ServerHello that carries neither, so a message that simply ends
    // here is still a well-formed answer and yields the version it named.
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

/// The version a ServerHello's `supported_versions` extension names, or `None`
/// where it carries none.
///
/// The only place a TLS 1.3 negotiation is visible. `extensions` is the
/// two-byte-prefixed block that follows the compression method.
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
            // In a ServerHello the extension carries one version and no list
            // header, unlike the client's (RFC 8446 §4.2.1).
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

    /// A hello whose length fields disagree with its contents is dropped without
    /// a word, and the port reads as one that does not speak TLS at all. So the
    /// record and the handshake must each count exactly what follows them.
    #[test]
    fn a_hello_declares_its_own_lengths_correctly() {
        for version in TlsVersion::ALL {
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

    /// The suites go on the wire in the order they were given, because that is
    /// what a server taking the client's preference reads.
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

    /// TLS 1.3 is asked for in an extension and nowhere else. A hello that put
    /// `0x0304` in the version field would be refused by every conformant server
    /// and the whole version reported unsupported.
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

    /// Every other version says so in the field, and none of them carries the
    /// 1.3 extensions.
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

    /// SSL 3.0 predates extensions, and a stack old enough to still offer it is
    /// the one most likely to drop a hello carrying a block it cannot parse.
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

    /// A name reaches the wire in the shape RFC 6066 §3 gives it, and a hello
    /// without one carries no extension rather than an empty name.
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

    /// Two hellos differ, because a constant random across the dozens an
    /// enumeration sends is a signature a filter could match the scan by.
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

    /// A ServerHello, built here from the RFC layout rather than from anything
    /// above, so what these tests assert is the protocol and not the engine's
    /// reading of it.
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

    /// The case a reader that trusted the version field gets wrong. Every TLS
    /// 1.3 server writes 1.2 in the field and 1.3 in the extension, so trusting
    /// the field reports the entire modern web as TLS 1.2.
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

    /// The extension is found behind others rather than only when it comes
    /// first, since a server orders its own however it likes.
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

    /// A HelloRetryRequest is a ServerHello with a fixed random, and it names the
    /// suite exactly as a completed one does. Read as an answer, and flagged, so
    /// a caller neither loses the suite nor mistakes a retry for a negotiation.
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

    /// A session id shifts everything behind it, and a reader that assumed the
    /// field was empty would read the suite out of the middle of it.
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

    /// An alert is the peer speaking TLS and declining these terms, which is the
    /// answer an enumeration reads as the end of a version.
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
    /// truncated record is refused rather than read past.
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

    /// A record announcing more than any peer may send is refused rather than
    /// waited for, or a stranger decides how much this process buffers.
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

    /// Whether an extension is present in a built hello, read by walking the
    /// block rather than by searching for the number anywhere in the packet: a
    /// two-byte value could appear inside a random and answer this wrongly.
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
        /// These bytes come off a socket a scanner opened to a stranger, so both
        /// walks have to terminate on any input rather than merely on a
        /// well-formed one.
        #[test]
        fn reading_an_answer_never_panics(
            record in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)
        ) {
            let _ = read_response(&record);
            let _ = record_length(&record);
        }

        /// The same for a record that starts out looking like a handshake, which
        /// is the shape that reaches furthest into the walk.
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

    /// **The truncation property**, the one `wire/ethernet_frame` holds for
    /// frames: reading more bytes never changes what a shorter read already
    /// reported. A reader that satisfies it cannot be walked off the end of a
    /// short buffer, and cannot be made to answer differently by a peer that
    /// dribbles a record out in pieces.
    ///
    /// Held here across every prefix of a well-formed ServerHello. The record
    /// is only whole at the last prefix, so every earlier one must yield
    /// `None` — never a `Hello` assembled out of bytes that had not arrived.
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

    /// Every length field in a ServerHello is a stranger's, and each one is a
    /// separate opportunity to be walked past the end of the buffer. None of
    /// them may panic, whatever it claims.
    #[test]
    fn no_length_field_can_walk_the_reader_off_the_end() {
        let base = server_hello(
            0x0303,
            0xC02F,
            [0u8; 32],
            Some(&[0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]),
        );

        // Every byte of the message, set to every extreme a length field can
        // take. Cheap, exhaustive over the positions, and it needs no oracle:
        // the assertion is that the call returns at all.
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
    /// arrived, and one whose declared length is past what TLS permits is
    /// refused outright rather than waited for. Together these are what stop a
    /// peer deciding how much this process buffers.
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

    /// An extension block whose entries claim more than the block holds ends the
    /// search rather than reading past it, and the reader still answers from the
    /// legacy version field.
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

    /// A session id is a stranger's length too, and the largest one shifts the
    /// suite past the end of every real message.
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

    /// **The defect the handshake length now catches**, named so it stays
    /// caught.
    ///
    /// A TLS 1.3 ServerHello cut off before its `supported_versions` extension
    /// leaves a body that reads perfectly well and says `0x0303` in the legacy
    /// field. Answering from that field reports a 1.3 server as 1.2 — which is
    /// the exact misreading this module was built to prevent, arriving by the
    /// one route the design did not cover: a peer that stops sending.
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

    /// Several handshake messages in one record is legal (RFC 8446 §5.1), so
    /// bytes past this message are not a disagreement with its length.
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
}
