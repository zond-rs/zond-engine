// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a TLS endpoint may be asked to accept
//!
//! The vocabulary an enumeration speaks: the protocol versions worth offering,
//! the cipher suites worth offering under each, and what is wrong with the ones
//! that are wrong. No I/O and no wire format; [`protocols::tls`](crate::protocols::tls)
//! builds the packet and [`fingerprint`](crate::fingerprint) sends it.
//!
//! ## Why a suite's faults are derived rather than stored
//!
//! A cipher suite is not an opaque name. `TLS_RSA_WITH_3DES_EDE_CBC_SHA` says,
//! in order, that it exchanges keys with static RSA, encrypts with 3DES in CBC
//! mode, and authenticates with SHA-1, and each of those three is a separate
//! thing a report should say about it. So a suite here is its parts, and
//! [`CipherSuite::faults`] reads the parts rather than a verdict written beside
//! them. A table of verdicts drifts from the suites it grades the first time one
//! is added; a derivation cannot.
//!
//! ## The list is curated, and says so
//!
//! IANA's registry holds several hundred suites, most of them never deployed.
//! [`CipherSuite::ALL`] is the ones a scan has any reason to offer: everything a
//! current server negotiates, and everything with a fault worth reporting, so
//! that a range coming back clean is evidence rather than a gap in the list. A
//! suite nobody has ever configured is absent, and a server that somehow
//! negotiates one is reported by its number; see
//! [`CipherSuite::from_code`].

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

use crate::model::confidence::Confidence;
use crate::model::finding::{
    ClaimId, DetectionClass, DetectionId, Excerpt, Finding, Reference, Severity, Standing, Version,
};

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

/// A TLS protocol version, by the number it carries on the wire.
///
/// Ordered oldest to newest, so a scan reporting the range an endpoint accepts
/// can name its floor and ceiling by comparison rather than by a table.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TlsVersion {
    /// SSL 3.0. Prohibited by RFC 7568 and broken by POODLE; no current client
    /// offers it and no current server should accept it.
    Ssl30,
    /// TLS 1.0. Deprecated by RFC 8996.
    Tls10,
    /// TLS 1.1. Deprecated by RFC 8996 alongside 1.0.
    Tls11,
    /// TLS 1.2. Still the floor most deployments sit on.
    Tls12,
    /// TLS 1.3. The version whose handshake is negotiated through an extension
    /// rather than through the version field; see
    /// [`protocols::tls`](crate::protocols::tls).
    Tls13,
}

impl TlsVersion {
    /// Every version worth offering, oldest first.
    ///
    /// An enumeration walks this in order, so the report's version list is in
    /// the same order for every endpoint and two scans diff cleanly.
    pub const ALL: [Self; 5] = [
        Self::Ssl30,
        Self::Tls10,
        Self::Tls11,
        Self::Tls12,
        Self::Tls13,
    ];

    /// The two-byte number this version carries on the wire.
    ///
    /// TLS 1.3's is `0x0304`, which never appears in a record header or in a
    /// ClientHello's version field: RFC 8446 §4.1.2 puts it in the
    /// `supported_versions` extension and leaves the legacy field reading
    /// `0x0303`. The number is still this one, and the wire module is what knows
    /// where to write it.
    pub const fn code(self) -> u16 {
        match self {
            Self::Ssl30 => 0x0300,
            Self::Tls10 => 0x0301,
            Self::Tls11 => 0x0302,
            Self::Tls12 => 0x0303,
            Self::Tls13 => 0x0304,
        }
    }

    /// The version a wire number names, or `None` for a number no version here
    /// claims.
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            0x0300 => Some(Self::Ssl30),
            0x0301 => Some(Self::Tls10),
            0x0302 => Some(Self::Tls11),
            0x0303 => Some(Self::Tls12),
            0x0304 => Some(Self::Tls13),
            _ => None,
        }
    }

    /// The name this version is written under, in a report and wherever it
    /// arrives as text.
    ///
    /// The spelling every other tool prints, so a reader comparing two scanners'
    /// output is comparing findings rather than formatting.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ssl30 => "SSLv3",
            Self::Tls10 => "TLSv1.0",
            Self::Tls11 => "TLSv1.1",
            Self::Tls12 => "TLSv1.2",
            Self::Tls13 => "TLSv1.3",
        }
    }

    /// Whether a standards body has withdrawn this version.
    ///
    /// RFC 7568 prohibits SSL 3.0; RFC 8996 deprecates TLS 1.0 and 1.1. An
    /// endpoint still accepting one of these is the single most quotable line a
    /// TLS enumeration produces, because the remedy is a configuration change
    /// rather than an upgrade.
    pub const fn is_deprecated(self) -> bool {
        matches!(self, Self::Ssl30 | Self::Tls10 | Self::Tls11)
    }

    /// How much a report should make of an endpoint that still accepts this
    /// version.
    ///
    /// SSL 3.0 outranks the other two because POODLE is a practical attack
    /// against it rather than a deprecation on paper: an attacker who can make a
    /// client retry recovers plaintext a byte at a time. TLS 1.0 and 1.1 are
    /// withdrawn and, on their own, are a compliance failure rather than a way
    /// in. `None` for a version still in good standing.
    pub const fn severity(self) -> Option<Severity> {
        match self {
            Self::Ssl30 => Some(Severity::High),
            Self::Tls10 | Self::Tls11 => Some(Severity::Medium),
            Self::Tls12 | Self::Tls13 => None,
        }
    }

    /// The document that withdrew this version, for a finding that has to cite
    /// one. `None` for a version still in good standing.
    pub const fn deprecated_by(self) -> Option<&'static str> {
        match self {
            Self::Ssl30 => Some("RFC 7568"),
            Self::Tls10 | Self::Tls11 => Some("RFC 8996"),
            Self::Tls12 | Self::Tls13 => None,
        }
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The error [`TlsVersion::from_str`] returns, naming the versions that would
/// have worked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "unknown TLS version '{input}', expected one of: {}",
    TlsVersion::expected()
)]
pub struct UnknownTlsVersion {
    /// What the caller wrote.
    pub input: String,
}

impl TlsVersion {
    /// The accepted names, comma-separated, oldest first.
    fn expected() -> String {
        Self::ALL
            .iter()
            .map(|version| version.name())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl FromStr for TlsVersion {
    type Err = UnknownTlsVersion;

    /// Parses a version by the name it prints, ignoring case and surrounding
    /// space, so a report read back names the same version it recorded.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|version| version.name().to_ascii_lowercase() == name)
            .ok_or_else(|| UnknownTlsVersion {
                input: s.to_string(),
            })
    }
}

// ---------------------------------------------------------------------------
// What a suite is made of
// ---------------------------------------------------------------------------

/// How a suite establishes the shared secret.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyExchange {
    /// Ephemeral elliptic-curve Diffie-Hellman. Forward secret.
    Ecdhe,
    /// Ephemeral finite-field Diffie-Hellman. Forward secret, and the one Logjam
    /// is about where the group is small.
    Dhe,
    /// The client encrypts the premaster secret to the server's long-term RSA
    /// key. Not forward secret: one key recovered later decrypts every session
    /// ever recorded.
    Rsa,
    /// Static elliptic-curve Diffie-Hellman, the server's share fixed in its
    /// certificate. Not forward secret.
    Ecdh,
    /// Anonymous Diffie-Hellman, finite-field or elliptic-curve. Forward secret
    /// and worthless: nothing authenticates the peer, so anyone in the path is
    /// the peer.
    Anonymous,
    /// TLS 1.3, where key exchange is negotiated by extension and is not part of
    /// the suite at all. Always ephemeral.
    Negotiated,
}

impl KeyExchange {
    /// Whether a key recovered afterwards leaves past sessions unreadable.
    pub const fn is_forward_secret(self) -> bool {
        matches!(
            self,
            Self::Ecdhe | Self::Dhe | Self::Anonymous | Self::Negotiated
        )
    }
}

/// What proves the server is who it claims to be.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Authentication {
    /// An RSA signature or an RSA key exchange against the certificate's key.
    Rsa,
    /// An ECDSA signature.
    Ecdsa,
    /// A DSA signature, under the name TLS gives it. Effectively extinct, and
    /// bound to SHA-1 in every suite that carries it.
    Dss,
    /// Nothing at all. The suite completes a handshake with a peer that proved
    /// nothing, which makes the channel confidential against a passive observer
    /// and transparent to an active one.
    Anonymous,
    /// TLS 1.3, where the signature algorithm is negotiated by extension rather
    /// than fixed by the suite.
    Negotiated,
}

/// What encrypts the records.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BulkCipher {
    /// AES in Galois/Counter mode, 128- or 256-bit. Authenticated encryption.
    AesGcm(u16),
    /// AES in CCM mode. Authenticated encryption, and the shortened-tag variant
    /// is the one worth telling apart.
    AesCcm {
        /// The key size in bits.
        bits: u16,
        /// Whether the authentication tag is truncated to eight bytes.
        short_tag: bool,
    },
    /// ChaCha20-Poly1305. Authenticated encryption.
    ChaCha20Poly1305,
    /// AES in CBC mode with a separate MAC. Sound in principle and the source of
    /// BEAST, Lucky13 and every padding-oracle variant in practice.
    AesCbc(u16),
    /// Camellia in CBC mode. The same structural problem as AES-CBC, with far
    /// less scrutiny behind the primitive.
    CamelliaCbc(u16),
    /// Triple DES. A 64-bit block, which is what Sweet32 (CVE-2016-2183) turns
    /// into a plaintext recovery against a long-lived connection.
    TripleDes,
    /// Single DES. A 56-bit key, brute-forced in public since 1998.
    Des,
    /// RC4. Prohibited by RFC 7465: its keystream is biased and the biases
    /// recover plaintext from enough sessions.
    Rc4,
    /// SEED in CBC mode, a Korean national cipher.
    SeedCbc,
    /// IDEA in CBC mode. A 64-bit block, so Sweet32 applies here too.
    IdeaCbc,
    /// No encryption at all. The handshake authenticates and the records go out
    /// in the clear.
    Null,
}

impl BulkCipher {
    /// Whether the cipher authenticates its own records, so the suite needs no
    /// separate MAC.
    pub const fn is_aead(self) -> bool {
        matches!(
            self,
            Self::AesGcm(_) | Self::AesCcm { .. } | Self::ChaCha20Poly1305
        )
    }

    /// Whether records are encrypted in cipher-block-chaining mode, which is
    /// what every padding oracle in TLS has needed.
    pub const fn is_cbc(self) -> bool {
        matches!(
            self,
            Self::AesCbc(_)
                | Self::CamelliaCbc(_)
                | Self::TripleDes
                | Self::Des
                | Self::SeedCbc
                | Self::IdeaCbc
        )
    }

    /// Whether the block is 64 bits, which is the precondition for Sweet32.
    pub const fn has_64_bit_block(self) -> bool {
        matches!(self, Self::TripleDes | Self::Des | Self::IdeaCbc)
    }
}

/// What authenticates a record where the cipher does not.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mac {
    /// The cipher authenticates its own records; the suite carries no separate
    /// MAC. The hash named in an AEAD suite is the one its key schedule uses,
    /// not a record MAC.
    Aead,
    /// HMAC-MD5. Collision resistance gone since 2004, and unfit even where a
    /// MAC needs less than that.
    Md5,
    /// HMAC-SHA-1. Not broken as a MAC, and carried only by suites old enough to
    /// have other problems.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-384.
    Sha384,
    /// No integrity protection whatsoever.
    Null,
}

// ---------------------------------------------------------------------------
// What is wrong with a suite
// ---------------------------------------------------------------------------

/// One thing wrong with a cipher suite, in the terms a report states it.
///
/// A suite may carry several: `TLS_RSA_EXPORT_WITH_RC4_40_MD5` is export-grade,
/// uses RC4, has no forward secrecy and MACs with MD5, and a reader deciding
/// what to do about it is served by all four rather than by whichever one an
/// engine happened to rank first.
///
/// Ordered by how much each costs the endpoint, so
/// [`CipherSuite::worst_fault`] is a comparison rather than a table.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SuiteFault {
    /// The key exchange is not ephemeral, so a long-term key recovered at any
    /// point in the future decrypts every session recorded before it.
    NoForwardSecrecy,
    /// Records are authenticated with HMAC-SHA-1.
    Sha1Mac,
    /// Records are encrypted in CBC mode with a separate MAC, the construction
    /// behind BEAST, Lucky13 and the padding oracles.
    CbcMode,
    /// The block cipher has a 64-bit block, which Sweet32 (CVE-2016-2183) turns
    /// into plaintext recovery over a long-lived connection.
    SmallBlock,
    /// Records are encrypted with RC4, which RFC 7465 prohibits.
    Rc4,
    /// Records are authenticated with HMAC-MD5.
    Md5Mac,
    /// The key is deliberately shortened to the length an export regulation once
    /// required. FREAK and Logjam are both about servers that still offer these.
    Export,
    /// Nothing authenticates the peer, so an active attacker in the path is
    /// indistinguishable from the server.
    Anonymous,
    /// Records are not encrypted at all.
    NullCipher,
}

impl SuiteFault {
    /// Every fault this build recognises, least costly first.
    pub const ALL: [Self; 9] = [
        Self::NoForwardSecrecy,
        Self::Sha1Mac,
        Self::CbcMode,
        Self::SmallBlock,
        Self::Rc4,
        Self::Md5Mac,
        Self::Export,
        Self::Anonymous,
        Self::NullCipher,
    ];

    /// The name this fault is written under wherever it reaches text.
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoForwardSecrecy => "no_forward_secrecy",
            Self::Sha1Mac => "sha1_mac",
            Self::CbcMode => "cbc_mode",
            Self::SmallBlock => "small_block",
            Self::Rc4 => "rc4",
            Self::Md5Mac => "md5_mac",
            Self::Export => "export_grade",
            Self::Anonymous => "anonymous",
            Self::NullCipher => "null_cipher",
        }
    }

    /// One sentence a report can print beside the suite, saying what the fault
    /// costs rather than restating its name.
    pub const fn summary(self) -> &'static str {
        match self {
            Self::NoForwardSecrecy => {
                "the server's long-term key decrypts every session recorded under it"
            }
            Self::Sha1Mac => "records are authenticated with HMAC-SHA-1",
            Self::CbcMode => "CBC with a separate MAC, the construction behind Lucky13 and BEAST",
            Self::SmallBlock => "a 64-bit block, which Sweet32 recovers plaintext from",
            Self::Rc4 => "RC4, prohibited by RFC 7465",
            Self::Md5Mac => "records are authenticated with HMAC-MD5",
            Self::Export => "a deliberately shortened key, from the export era",
            Self::Anonymous => "nothing authenticates the server",
            Self::NullCipher => "records are not encrypted",
        }
    }

    /// How much a report should make of an endpoint that accepts a suite
    /// carrying this fault.
    ///
    /// Graded against what the fault buys somebody who is already in a position
    /// to use it, which is what separates the three tiers here. The top tier
    /// needs a position in the path and then hands over the traffic or the
    /// identity; the middle needs a position and a great deal of patience; the
    /// bottom is a hardening step left undone.
    ///
    /// Nothing here reaches [`Critical`](Severity::Critical). Every fault below
    /// costs an attacker a position on the network first, and the crate reserves
    /// that level for what needs nothing the internet does not already have.
    pub const fn severity(self) -> Severity {
        match self {
            // The channel is not what it claims to be at all: unencrypted, or
            // authenticated by nobody, or shortened to a length that has been
            // brute-forceable for thirty years.
            Self::NullCipher | Self::Anonymous | Self::Export => Severity::High,
            // Published attacks that work, and need a great deal of traffic or a
            // very long-lived connection to do it.
            Self::Rc4 | Self::SmallBlock | Self::Md5Mac => Severity::Medium,
            // Structural weaknesses worth removing, none of which is a way in on
            // its own.
            Self::CbcMode | Self::Sha1Mac | Self::NoForwardSecrecy => Severity::Low,
        }
    }

    /// Whether this fault alone makes the suite unfit for use, rather than
    /// merely worth replacing.
    ///
    /// The line between [`SuiteStrength::Weak`] and
    /// [`SuiteStrength::Insecure`]: below it a suite has a structural weakness
    /// somebody should plan to remove, and at or above it the suite provides
    /// materially less than it appears to.
    pub const fn is_disqualifying(self) -> bool {
        matches!(
            self,
            Self::SmallBlock
                | Self::Rc4
                | Self::Md5Mac
                | Self::Export
                | Self::Anonymous
                | Self::NullCipher
        )
    }
}

impl fmt::Display for SuiteFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How much a suite is worth, in three steps a report can act on.
///
/// Derived from [`CipherSuite::faults`] and never stored, so a suite added to
/// the registry is graded by the same rule as every other one.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SuiteStrength {
    /// Authenticated encryption with forward secrecy, and nothing against it.
    Strong,
    /// Usable, with a structural weakness worth planning out: no forward
    /// secrecy, CBC mode, or a SHA-1 MAC.
    Weak,
    /// Provides materially less than it appears to. Somebody should have removed
    /// it already.
    Insecure,
}

impl SuiteStrength {
    /// Every grade, strongest first.
    pub const ALL: [Self; 3] = [Self::Strong, Self::Weak, Self::Insecure];

    /// The name this grade is written under wherever it reaches text.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Strong => "strong",
            Self::Weak => "weak",
            Self::Insecure => "insecure",
        }
    }
}

impl fmt::Display for SuiteStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// The suite itself
// ---------------------------------------------------------------------------

/// One cipher suite: the number it is offered under, the name it is known by,
/// and the four parts that decide what it is worth.
///
/// Construction is closed to the registry below. A suite assembled by hand could
/// name one thing and describe another, and every finding this module produces
/// rests on the name and the parts agreeing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CipherSuite {
    code: u16,
    name: &'static str,
    kex: KeyExchange,
    auth: Authentication,
    cipher: BulkCipher,
    mac: Mac,
    export: bool,
}

impl CipherSuite {
    /// The two-byte number this suite is offered and selected under.
    pub const fn code(self) -> u16 {
        self.code
    }

    /// The name IANA registers it under, which is the name every other tool
    /// prints.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// How the shared secret is established.
    pub const fn key_exchange(self) -> KeyExchange {
        self.kex
    }

    /// What proves the server's identity.
    pub const fn authentication(self) -> Authentication {
        self.auth
    }

    /// What encrypts the records.
    pub const fn bulk_cipher(self) -> BulkCipher {
        self.cipher
    }

    /// What authenticates them, where the cipher does not.
    pub const fn mac(self) -> Mac {
        self.mac
    }

    /// Whether the key is deliberately shortened to an export-era length.
    pub const fn is_export(self) -> bool {
        self.export
    }

    /// Whether a key recovered later leaves past sessions unreadable.
    pub const fn is_forward_secret(self) -> bool {
        self.kex.is_forward_secret()
    }

    /// Whether the suite carries this fault.
    ///
    /// Read off the parts every time rather than from a table beside them, so a
    /// suite added to the registry is judged by the same rule as the rest and
    /// cannot arrive ungraded.
    pub const fn has_fault(self, fault: SuiteFault) -> bool {
        match fault {
            // Anonymous key exchange is forward secret and proves nothing, so it
            // is reported under its own fault rather than this one.
            SuiteFault::NoForwardSecrecy => !self.kex.is_forward_secret(),
            SuiteFault::Sha1Mac => matches!(self.mac, Mac::Sha1),
            SuiteFault::CbcMode => self.cipher.is_cbc(),
            SuiteFault::SmallBlock => self.cipher.has_64_bit_block(),
            SuiteFault::Rc4 => matches!(self.cipher, BulkCipher::Rc4),
            SuiteFault::Md5Mac => matches!(self.mac, Mac::Md5),
            SuiteFault::Export => self.export,
            SuiteFault::Anonymous => matches!(self.auth, Authentication::Anonymous),
            SuiteFault::NullCipher => matches!(self.cipher, BulkCipher::Null),
        }
    }

    /// Everything wrong with this suite, least costly first. Empty for a suite
    /// with nothing against it.
    pub fn faults(self) -> Vec<SuiteFault> {
        SuiteFault::ALL
            .into_iter()
            .filter(|fault| self.has_fault(*fault))
            .collect()
    }

    /// The costliest thing wrong with this suite, or `None` for one with
    /// nothing against it.
    pub fn worst_fault(self) -> Option<SuiteFault> {
        SuiteFault::ALL
            .into_iter()
            .rev()
            .find(|fault| self.has_fault(*fault))
    }

    /// What the suite is worth, from its faults.
    ///
    /// A suite with no fault is [`Strong`](SuiteStrength::Strong); one whose
    /// worst fault is disqualifying is [`Insecure`](SuiteStrength::Insecure);
    /// anything else is [`Weak`](SuiteStrength::Weak).
    pub fn strength(self) -> SuiteStrength {
        match self.worst_fault() {
            None => SuiteStrength::Strong,
            Some(fault) if fault.is_disqualifying() => SuiteStrength::Insecure,
            Some(_) => SuiteStrength::Weak,
        }
    }

    /// Whether this suite can be offered under `version`.
    ///
    /// The two families do not mix. RFC 8446 §B.4 gives TLS 1.3 its own suites,
    /// which name only the AEAD and the hash because everything else moved into
    /// extensions; offering one under TLS 1.2 names a suite that version has
    /// never heard of, and offering a 1.2 suite under 1.3 is equally meaningless.
    /// An enumeration that mixed them would report a whole version unsupported
    /// on the strength of having asked the wrong question.
    pub const fn is_offered_under(self, version: TlsVersion) -> bool {
        let tls13_suite = matches!(self.kex, KeyExchange::Negotiated);
        match version {
            TlsVersion::Tls13 => tls13_suite,
            // A suite whose MAC is SHA-256 or SHA-384 needs the PRF that arrived
            // with TLS 1.2 (RFC 5246 §5), and so does every AEAD suite. Offering
            // one to a 1.0 or 1.1 server asks for something the version cannot
            // express.
            TlsVersion::Ssl30 | TlsVersion::Tls10 | TlsVersion::Tls11 => {
                !tls13_suite && matches!(self.mac, Mac::Md5 | Mac::Sha1 | Mac::Null)
            }
            TlsVersion::Tls12 => !tls13_suite,
        }
    }

    /// The suite a wire number names, or `None` for one this build does not
    /// carry.
    ///
    /// A server selecting a number absent from [`ALL`](Self::ALL) has selected
    /// something it was never offered, which an enumeration treats as the end of
    /// that version rather than as a suite.
    pub fn from_code(code: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|suite| suite.code == code)
    }
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

/// Builds one registry entry, so that a row is its wire number, its name and its
/// four parts and nothing else can be written between them.
macro_rules! suite {
    ($code:literal, $name:literal, $kex:expr, $auth:expr, $cipher:expr, $mac:expr) => {
        CipherSuite {
            code: $code,
            name: $name,
            kex: $kex,
            auth: $auth,
            cipher: $cipher,
            mac: $mac,
            export: false,
        }
    };
    (export $code:literal, $name:literal, $kex:expr, $auth:expr, $cipher:expr, $mac:expr) => {
        CipherSuite {
            code: $code,
            name: $name,
            kex: $kex,
            auth: $auth,
            cipher: $cipher,
            mac: $mac,
            export: true,
        }
    };
}

use Authentication as A;
use BulkCipher as C;
use KeyExchange as K;
use Mac as M;

impl CipherSuite {
    /// Every suite a scan offers, grouped by the document that defines it.
    ///
    /// Curated rather than complete; see the module documentation for the
    /// criterion. Ordered strongest first within each group, which is the order
    /// they go into a ClientHello: a server with its own preference ignores the
    /// order, and one that takes the client's should be handed the best suite it
    /// can accept rather than the worst.
    pub const ALL: [Self; 85] = [
        // ── TLS 1.3 (RFC 8446 §B.4) ──────────────────────────────────────────
        // Named for their AEAD and hash alone: key exchange and authentication
        // moved into extensions, so they are properties of the connection rather
        // than of the suite.
        suite!(
            0x1302,
            "TLS_AES_256_GCM_SHA384",
            K::Negotiated,
            A::Negotiated,
            C::AesGcm(256),
            M::Aead
        ),
        suite!(
            0x1303,
            "TLS_CHACHA20_POLY1305_SHA256",
            K::Negotiated,
            A::Negotiated,
            C::ChaCha20Poly1305,
            M::Aead
        ),
        suite!(
            0x1301,
            "TLS_AES_128_GCM_SHA256",
            K::Negotiated,
            A::Negotiated,
            C::AesGcm(128),
            M::Aead
        ),
        suite!(
            0x1304,
            "TLS_AES_128_CCM_SHA256",
            K::Negotiated,
            A::Negotiated,
            C::AesCcm {
                bits: 128,
                short_tag: false
            },
            M::Aead
        ),
        suite!(
            0x1305,
            "TLS_AES_128_CCM_8_SHA256",
            K::Negotiated,
            A::Negotiated,
            C::AesCcm {
                bits: 128,
                short_tag: true
            },
            M::Aead
        ),
        // ── ECDHE with AEAD (RFC 5289, RFC 7905) ─────────────────────────────
        // What a current TLS 1.2 deployment should be negotiating and nothing
        // else.
        suite!(
            0xC030,
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            K::Ecdhe,
            A::Rsa,
            C::AesGcm(256),
            M::Aead
        ),
        suite!(
            0xC02C,
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            K::Ecdhe,
            A::Ecdsa,
            C::AesGcm(256),
            M::Aead
        ),
        suite!(
            0xC02F,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            K::Ecdhe,
            A::Rsa,
            C::AesGcm(128),
            M::Aead
        ),
        suite!(
            0xC02B,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            K::Ecdhe,
            A::Ecdsa,
            C::AesGcm(128),
            M::Aead
        ),
        suite!(
            0xCCA8,
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            K::Ecdhe,
            A::Rsa,
            C::ChaCha20Poly1305,
            M::Aead
        ),
        suite!(
            0xCCA9,
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            K::Ecdhe,
            A::Ecdsa,
            C::ChaCha20Poly1305,
            M::Aead
        ),
        // ── DHE with AEAD (RFC 5288, RFC 7905) ───────────────────────────────
        suite!(
            0x009F,
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            K::Dhe,
            A::Rsa,
            C::AesGcm(256),
            M::Aead
        ),
        suite!(
            0x009E,
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            K::Dhe,
            A::Rsa,
            C::AesGcm(128),
            M::Aead
        ),
        suite!(
            0xCCAA,
            "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            K::Dhe,
            A::Rsa,
            C::ChaCha20Poly1305,
            M::Aead
        ),
        // ── Static RSA with AEAD (RFC 5288) ──────────────────────────────────
        // Modern encryption on a key exchange that has none of its own: the
        // records are fine and the secrecy is only as durable as the server's
        // private key.
        suite!(
            0x009D,
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            K::Rsa,
            A::Rsa,
            C::AesGcm(256),
            M::Aead
        ),
        suite!(
            0x009C,
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            K::Rsa,
            A::Rsa,
            C::AesGcm(128),
            M::Aead
        ),
        // ── ECDHE with CBC and a SHA-2 MAC (RFC 5289) ────────────────────────
        suite!(
            0xC028,
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            K::Ecdhe,
            A::Rsa,
            C::AesCbc(256),
            M::Sha384
        ),
        suite!(
            0xC024,
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            K::Ecdhe,
            A::Ecdsa,
            C::AesCbc(256),
            M::Sha384
        ),
        suite!(
            0xC027,
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            K::Ecdhe,
            A::Rsa,
            C::AesCbc(128),
            M::Sha256
        ),
        suite!(
            0xC023,
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            K::Ecdhe,
            A::Ecdsa,
            C::AesCbc(128),
            M::Sha256
        ),
        // ── DHE and static RSA with CBC and a SHA-2 MAC (RFC 5246) ───────────
        suite!(
            0x006B,
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            K::Dhe,
            A::Rsa,
            C::AesCbc(256),
            M::Sha256
        ),
        suite!(
            0x0067,
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            K::Dhe,
            A::Rsa,
            C::AesCbc(128),
            M::Sha256
        ),
        suite!(
            0x003D,
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            K::Rsa,
            A::Rsa,
            C::AesCbc(256),
            M::Sha256
        ),
        suite!(
            0x003C,
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            K::Rsa,
            A::Rsa,
            C::AesCbc(128),
            M::Sha256
        ),
        suite!(
            0x006A,
            "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
            K::Dhe,
            A::Dss,
            C::AesCbc(256),
            M::Sha256
        ),
        suite!(
            0x0040,
            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
            K::Dhe,
            A::Dss,
            C::AesCbc(128),
            M::Sha256
        ),
        // ── CBC with a SHA-1 MAC (RFC 5246, RFC 4492) ────────────────────────
        // The floor a great many deployments still sit on, and the reason a
        // report needs the MAC as well as the cipher.
        suite!(
            0xC014,
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            K::Ecdhe,
            A::Rsa,
            C::AesCbc(256),
            M::Sha1
        ),
        suite!(
            0xC00A,
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            K::Ecdhe,
            A::Ecdsa,
            C::AesCbc(256),
            M::Sha1
        ),
        suite!(
            0xC013,
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            K::Ecdhe,
            A::Rsa,
            C::AesCbc(128),
            M::Sha1
        ),
        suite!(
            0xC009,
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            K::Ecdhe,
            A::Ecdsa,
            C::AesCbc(128),
            M::Sha1
        ),
        suite!(
            0x0039,
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            K::Dhe,
            A::Rsa,
            C::AesCbc(256),
            M::Sha1
        ),
        suite!(
            0x0033,
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            K::Dhe,
            A::Rsa,
            C::AesCbc(128),
            M::Sha1
        ),
        suite!(
            0x0038,
            "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
            K::Dhe,
            A::Dss,
            C::AesCbc(256),
            M::Sha1
        ),
        suite!(
            0x0032,
            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
            K::Dhe,
            A::Dss,
            C::AesCbc(128),
            M::Sha1
        ),
        suite!(
            0x0035,
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            K::Rsa,
            A::Rsa,
            C::AesCbc(256),
            M::Sha1
        ),
        suite!(
            0x002F,
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            K::Rsa,
            A::Rsa,
            C::AesCbc(128),
            M::Sha1
        ),
        // ── Static ECDH (RFC 4492) ───────────────────────────────────────────
        // The server's Diffie-Hellman share fixed in its certificate, so the
        // exchange looks ephemeral and is not.
        suite!(
            0xC00F,
            "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
            K::Ecdh,
            A::Rsa,
            C::AesCbc(256),
            M::Sha1
        ),
        suite!(
            0xC00E,
            "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
            K::Ecdh,
            A::Rsa,
            C::AesCbc(128),
            M::Sha1
        ),
        suite!(
            0xC005,
            "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
            K::Ecdh,
            A::Ecdsa,
            C::AesCbc(256),
            M::Sha1
        ),
        suite!(
            0xC004,
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
            K::Ecdh,
            A::Ecdsa,
            C::AesCbc(128),
            M::Sha1
        ),
        // ── Camellia and SEED (RFC 5932, RFC 4162) ───────────────────────────
        suite!(
            0x0088,
            "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
            K::Dhe,
            A::Rsa,
            C::CamelliaCbc(256),
            M::Sha1
        ),
        suite!(
            0x0084,
            "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
            K::Rsa,
            A::Rsa,
            C::CamelliaCbc(256),
            M::Sha1
        ),
        suite!(
            0x0045,
            "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
            K::Dhe,
            A::Rsa,
            C::CamelliaCbc(128),
            M::Sha1
        ),
        suite!(
            0x0041,
            "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
            K::Rsa,
            A::Rsa,
            C::CamelliaCbc(128),
            M::Sha1
        ),
        suite!(
            0x0096,
            "TLS_RSA_WITH_SEED_CBC_SHA",
            K::Rsa,
            A::Rsa,
            C::SeedCbc,
            M::Sha1
        ),
        // ── Triple DES (RFC 5246, RFC 4492) ──────────────────────────────────
        // A 64-bit block, and Sweet32 is a practical attack rather than a
        // theoretical one.
        suite!(
            0xC012,
            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
            K::Ecdhe,
            A::Rsa,
            C::TripleDes,
            M::Sha1
        ),
        suite!(
            0xC008,
            "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
            K::Ecdhe,
            A::Ecdsa,
            C::TripleDes,
            M::Sha1
        ),
        suite!(
            0x0016,
            "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
            K::Dhe,
            A::Rsa,
            C::TripleDes,
            M::Sha1
        ),
        suite!(
            0x0013,
            "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
            K::Dhe,
            A::Dss,
            C::TripleDes,
            M::Sha1
        ),
        suite!(
            0x000A,
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            K::Rsa,
            A::Rsa,
            C::TripleDes,
            M::Sha1
        ),
        suite!(
            0xC00D,
            "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
            K::Ecdh,
            A::Rsa,
            C::TripleDes,
            M::Sha1
        ),
        suite!(
            0x0007,
            "TLS_RSA_WITH_IDEA_CBC_SHA",
            K::Rsa,
            A::Rsa,
            C::IdeaCbc,
            M::Sha1
        ),
        // ── RC4 (RFC 7465 prohibits every one of these) ──────────────────────
        suite!(
            0xC011,
            "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
            K::Ecdhe,
            A::Rsa,
            C::Rc4,
            M::Sha1
        ),
        suite!(
            0xC007,
            "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
            K::Ecdhe,
            A::Ecdsa,
            C::Rc4,
            M::Sha1
        ),
        suite!(
            0x0005,
            "TLS_RSA_WITH_RC4_128_SHA",
            K::Rsa,
            A::Rsa,
            C::Rc4,
            M::Sha1
        ),
        suite!(
            0x0004,
            "TLS_RSA_WITH_RC4_128_MD5",
            K::Rsa,
            A::Rsa,
            C::Rc4,
            M::Md5
        ),
        suite!(
            0xC016,
            "TLS_ECDH_anon_WITH_RC4_128_SHA",
            K::Anonymous,
            A::Anonymous,
            C::Rc4,
            M::Sha1
        ),
        suite!(
            0x0018,
            "TLS_DH_anon_WITH_RC4_128_MD5",
            K::Anonymous,
            A::Anonymous,
            C::Rc4,
            M::Md5
        ),
        // ── Anonymous key exchange (RFC 5246 §A.5, RFC 4492) ─────────────────
        // Confidential against a passive observer and transparent to an active
        // one, which is the worse of the two to be wrong about.
        suite!(
            0x006D,
            "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
            K::Anonymous,
            A::Anonymous,
            C::AesCbc(256),
            M::Sha256
        ),
        suite!(
            0x006C,
            "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
            K::Anonymous,
            A::Anonymous,
            C::AesCbc(128),
            M::Sha256
        ),
        suite!(
            0x003A,
            "TLS_DH_anon_WITH_AES_256_CBC_SHA",
            K::Anonymous,
            A::Anonymous,
            C::AesCbc(256),
            M::Sha1
        ),
        suite!(
            0x0034,
            "TLS_DH_anon_WITH_AES_128_CBC_SHA",
            K::Anonymous,
            A::Anonymous,
            C::AesCbc(128),
            M::Sha1
        ),
        suite!(
            0xC019,
            "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
            K::Anonymous,
            A::Anonymous,
            C::AesCbc(256),
            M::Sha1
        ),
        suite!(
            0xC018,
            "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
            K::Anonymous,
            A::Anonymous,
            C::AesCbc(128),
            M::Sha1
        ),
        suite!(
            0x001B,
            "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
            K::Anonymous,
            A::Anonymous,
            C::TripleDes,
            M::Sha1
        ),
        suite!(
            0xC017,
            "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
            K::Anonymous,
            A::Anonymous,
            C::TripleDes,
            M::Sha1
        ),
        // ── No encryption (RFC 5246, RFC 4492) ───────────────────────────────
        // A handshake that authenticates and then sends everything in the clear.
        // Offered by more management interfaces than anyone expects.
        suite!(
            0x003B,
            "TLS_RSA_WITH_NULL_SHA256",
            K::Rsa,
            A::Rsa,
            C::Null,
            M::Sha256
        ),
        suite!(
            0x0002,
            "TLS_RSA_WITH_NULL_SHA",
            K::Rsa,
            A::Rsa,
            C::Null,
            M::Sha1
        ),
        suite!(
            0x0001,
            "TLS_RSA_WITH_NULL_MD5",
            K::Rsa,
            A::Rsa,
            C::Null,
            M::Md5
        ),
        suite!(
            0xC010,
            "TLS_ECDHE_RSA_WITH_NULL_SHA",
            K::Ecdhe,
            A::Rsa,
            C::Null,
            M::Sha1
        ),
        suite!(
            0xC006,
            "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
            K::Ecdhe,
            A::Ecdsa,
            C::Null,
            M::Sha1
        ),
        suite!(
            0xC001,
            "TLS_ECDH_ECDSA_WITH_NULL_SHA",
            K::Ecdh,
            A::Ecdsa,
            C::Null,
            M::Sha1
        ),
        suite!(
            0xC00B,
            "TLS_ECDH_RSA_WITH_NULL_SHA",
            K::Ecdh,
            A::Rsa,
            C::Null,
            M::Sha1
        ),
        suite!(
            0xC015,
            "TLS_ECDH_anon_WITH_NULL_SHA",
            K::Anonymous,
            A::Anonymous,
            C::Null,
            M::Sha1
        ),
        // ── Export grade (RFC 4346 §A.5, withdrawn in RFC 5246) ──────────────
        // Keys shortened to satisfy an export regulation that has not existed
        // since 2000. FREAK and Logjam are both about servers that still offer
        // them.
        suite!(export 0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", K::Rsa, A::Rsa, C::Rc4, M::Md5),
        suite!(export 0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", K::Rsa, A::Rsa, C::Des, M::Md5),
        suite!(export 0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", K::Rsa, A::Rsa, C::Des, M::Sha1),
        suite!(export 0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", K::Dhe, A::Rsa, C::Des, M::Sha1),
        suite!(export 0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", K::Dhe, A::Dss, C::Des, M::Sha1),
        suite!(export 0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", K::Anonymous, A::Anonymous, C::Rc4, M::Md5),
        suite!(export 0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", K::Anonymous, A::Anonymous, C::Des, M::Sha1),
        // ── Single DES (RFC 4346 §A.5) ───────────────────────────────────────
        suite!(
            0x0009,
            "TLS_RSA_WITH_DES_CBC_SHA",
            K::Rsa,
            A::Rsa,
            C::Des,
            M::Sha1
        ),
        suite!(
            0x0015,
            "TLS_DHE_RSA_WITH_DES_CBC_SHA",
            K::Dhe,
            A::Rsa,
            C::Des,
            M::Sha1
        ),
        suite!(
            0x0012,
            "TLS_DHE_DSS_WITH_DES_CBC_SHA",
            K::Dhe,
            A::Dss,
            C::Des,
            M::Sha1
        ),
        suite!(
            0x001A,
            "TLS_DH_anon_WITH_DES_CBC_SHA",
            K::Anonymous,
            A::Anonymous,
            C::Des,
            M::Sha1
        ),
    ];

    /// Every suite that may be offered under `version`, in registry order.
    pub fn offered_under(version: TlsVersion) -> impl Iterator<Item = Self> {
        Self::ALL
            .into_iter()
            .filter(move |suite| suite.is_offered_under(version))
    }

    /// How many suites [`offered_under`](Self::offered_under) yields for the
    /// version that has the most of them.
    ///
    /// The tight bound on how many questions an enumeration can put to one
    /// endpoint under one version, and so the only defensible ceiling to stop
    /// one at: a walk that narrows its offer by a suite per answer cannot ask
    /// more times than the version had suites. Derived here rather than written
    /// down, so a suite added to the registry raises it and no ceiling
    /// elsewhere has to be remembered.
    ///
    /// TLS 1.2 is the version that decides it, carrying every suite that is not
    /// 1.3-only.
    pub const MOST_OFFERED_UNDER_ONE_VERSION: usize = {
        let mut most = 0;
        let mut version = 0;
        while version < TlsVersion::ALL.len() {
            let mut offered = 0;
            let mut suite = 0;
            while suite < Self::ALL.len() {
                if Self::ALL[suite].is_offered_under(TlsVersion::ALL[version]) {
                    offered += 1;
                }
                suite += 1;
            }
            if offered > most {
                most = offered;
            }
            version += 1;
        }
        most
    };
}

// ---------------------------------------------------------------------------
// What an endpoint turned out to accept
// ---------------------------------------------------------------------------

/// What one endpoint accepted under one protocol version.
///
/// The suites are in the order the server chose them, which is worth keeping.
/// An enumeration offers its list strongest first and removes each suite as it
/// is selected, so a server with a preference of its own reveals it: the first
/// entry is that server's favourite among everything offered, not the scan's.
///
/// A server taking the *client's* preference produces the same list in the same
/// order, and nothing here tells the two apart. Separating them needs the offer
/// repeated in a second order, which is a question this does not yet ask.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSupport {
    version: TlsVersion,
    suites: Vec<CipherSuite>,
    unrecognised: Vec<u16>,
}

impl VersionSupport {
    /// Records that `version` was accepted, with the suites chosen under it.
    ///
    /// `unrecognised` holds any suite the server selected by a number
    /// [`CipherSuite::ALL`] does not carry. Kept rather than dropped: it is a
    /// server negotiating something this build cannot grade, and a reader who
    /// sees an empty suite list beside an accepted version would otherwise
    /// conclude the endpoint negotiated nothing.
    pub fn new(version: TlsVersion, suites: Vec<CipherSuite>, unrecognised: Vec<u16>) -> Self {
        Self {
            version,
            suites,
            unrecognised,
        }
    }

    /// The version this describes.
    pub fn version(&self) -> TlsVersion {
        self.version
    }

    /// The suites accepted under it, in the order the server chose them.
    pub fn suites(&self) -> &[CipherSuite] {
        &self.suites
    }

    /// Suites the server chose that this build does not carry, by number.
    pub fn unrecognised(&self) -> &[u16] {
        &self.unrecognised
    }

    /// The worst grade among the suites accepted here, or `None` where the
    /// version was accepted and no suite was ever named.
    pub fn weakest(&self) -> Option<SuiteStrength> {
        self.suites.iter().map(|suite| suite.strength()).max()
    }
}

/// Why a version's walk ended before the endpoint had declined an offer.
///
/// A walk is finished when the server declines what is left of the offer, and
/// only then are the suites it found the whole of what it accepts. A walk that
/// ended any other way found a floor, and what it missed is the tail of the
/// server's own preference order, where a legacy configuration keeps its worst
/// suites. The causes are kept apart because they are acted on apart: one is a
/// property of the path to the endpoint, one of the scan's budget, and one of
/// the machine the scan ran on.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Interruption {
    /// The endpoint stopped answering: connections failed, timed out or were
    /// closed unanswered, and went on doing so when the offer was put again.
    /// Rate limiters and busy embedded stacks are the usual cause, and a slower
    /// scan the usual remedy.
    Unanswered,
    /// The scan stopped asking: the host's budget ran out, which also puts its
    /// address in the phase's
    /// [`timed_out`](crate::report::ScanPhase::timed_out) list, or the scan
    /// itself was stopped.
    Stopped,
    /// The scan had no socket to put the offer on: the process held as many
    /// files as its descriptor limit allows for as long as the offer would
    /// wait for one. Nothing was asked of the endpoint, so this says nothing
    /// about it, and raising the limit is the remedy.
    FileLimit,
}

impl Interruption {
    /// Every cause, in the order the enum declares them.
    pub const ALL: [Self; 3] = [Self::Unanswered, Self::Stopped, Self::FileLimit];

    /// The name this cause is written under wherever it reaches text.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unanswered => "unanswered",
            Self::Stopped => "stopped",
            Self::FileLimit => "file-limit",
        }
    }

    /// [`name`](Self::name) read back, or `None` for a name this build does
    /// not know.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|cause| cause.name() == name)
    }
}

impl fmt::Display for Interruption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A version whose walk did not finish, and why.
///
/// Held apart from [`VersionSupport`] because the two answer different
/// questions: that one says a version was accepted, and a walk can be cut
/// before the server has said anything about its version at all. Such a
/// version is neither accepted nor refused, and this is the only place a
/// reader learns that it is unknown rather than absent.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnfinishedVersion {
    version: TlsVersion,
    interruption: Interruption,
}

impl UnfinishedVersion {
    /// Records that the walk under `version` ended for `interruption`.
    pub fn new(version: TlsVersion, interruption: Interruption) -> Self {
        Self {
            version,
            interruption,
        }
    }

    /// The version whose walk did not finish.
    pub fn version(&self) -> TlsVersion {
        self.version
    }

    /// Why it did not.
    pub fn interruption(&self) -> Interruption {
        self.interruption
    }
}

/// What an endpoint accepts, version by version.
///
/// The answer a TLS enumeration exists to produce, and a different question from
/// the one a single handshake answers. [`Security`](super::port::Security)
/// records what *was* negotiated; this records what *would be*, which is what a
/// PCI scan, an ASV report or an internal audit is actually asking.
///
/// Empty for an endpoint that accepted nothing under any version and left no
/// walk unfinished, which is a real outcome rather than a failure: a server
/// refusing every offer is either very strictly configured or was asked
/// without the name it insists on. See
/// [`Offer::server_name`](crate::protocols::tls::Offer::server_name).
///
/// A version under [`unfinished`](Self::unfinished) is one whose accepted
/// suites, if it has any here, are a floor rather than the whole answer.
#[must_use]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsSupport {
    versions: Vec<VersionSupport>,
    unfinished: Vec<UnfinishedVersion>,
}

impl TlsSupport {
    /// An empty record, for an endpoint nothing has been established about yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds what one version turned out to accept, keeping the list oldest
    /// first however the caller walked them.
    pub fn record(&mut self, support: VersionSupport) {
        let at = self
            .versions
            .partition_point(|held| held.version < support.version);
        match self.versions.get(at) {
            Some(held) if held.version == support.version => self.versions[at] = support,
            _ => self.versions.insert(at, support),
        }
    }

    /// Builder form of [`record`](Self::record).
    pub fn accepting(mut self, support: VersionSupport) -> Self {
        self.record(support);
        self
    }

    /// Adds a version whose walk did not finish, keeping the list oldest first
    /// and one entry to a version.
    pub fn record_unfinished(&mut self, unfinished: UnfinishedVersion) {
        let at = self
            .unfinished
            .partition_point(|held| held.version < unfinished.version);
        match self.unfinished.get(at) {
            Some(held) if held.version == unfinished.version => self.unfinished[at] = unfinished,
            _ => self.unfinished.insert(at, unfinished),
        }
    }

    /// Builder form of [`record_unfinished`](Self::record_unfinished).
    pub fn leaving_unfinished(mut self, unfinished: UnfinishedVersion) -> Self {
        self.record_unfinished(unfinished);
        self
    }

    /// Folds another enumeration of this endpoint into this one, version by
    /// version: this record's account of a version stands unless the other's
    /// is the more complete of the two and holds every suite this one found.
    ///
    /// More complete is a walk that finished over one that was cut short, or of
    /// two cut short, the one that got further. That alone does not decide it,
    /// because a walk offers what is left and the server chooses: of one
    /// configuration, a walk cut short finds part of what a further walk finds
    /// and nothing else. So where the account on record found a suite the other
    /// does not list, the two were answered by different configurations rather
    /// than being two accounts of one, and the one on record stands. A fold
    /// across scans puts the newer on record, so a server whose configuration
    /// changed is described as it is now.
    ///
    /// A version is taken whole from one account, its suites in the order that
    /// server chose them and its interruption with them. Spliced from two walks
    /// of two configurations it would be a list no server accepted.
    ///
    /// A record with nothing in it was never asked, and displaces nothing. One
    /// with anything in it walked every version, so a version it lists nowhere
    /// was refused, which is a finished walk that found nothing.
    pub(crate) fn merge(&mut self, other: TlsSupport) {
        if other.is_empty() {
            return;
        }
        if self.is_empty() {
            *self = other;
            return;
        }

        let named: BTreeSet<TlsVersion> = [&*self, &other]
            .into_iter()
            .flat_map(|record| {
                let accepted = record.versions.iter().map(|held| held.version);
                let unfinished = record.unfinished.iter().map(|held| held.version);
                accepted.chain(unfinished)
            })
            .collect();
        let taken: Vec<TlsVersion> = named
            .into_iter()
            .filter(|version| other.account(*version).supersedes(&self.account(*version)))
            .collect();

        // Destructured rather than reached through `other.…`, so a field added
        // to this struct is a compile error here and not a value that quietly
        // stops being folded.
        let TlsSupport {
            versions,
            unfinished,
        } = other;
        self.versions.retain(|held| !taken.contains(&held.version));
        self.unfinished
            .retain(|held| !taken.contains(&held.version));
        for held in versions {
            if taken.contains(&held.version) {
                self.record(held);
            }
        }
        for held in unfinished {
            if taken.contains(&held.version) {
                self.record_unfinished(held);
            }
        }
    }

    /// What this record says about `version`, for weighing against another
    /// record's. Only meaningful for a record that is not empty.
    fn account(&self, version: TlsVersion) -> Account {
        let found = self
            .versions
            .iter()
            .find(|held| held.version == version)
            .map(|held| {
                let named = held.suites.iter().map(|suite| suite.code());
                named.chain(held.unrecognised.iter().copied()).collect()
            })
            .unwrap_or_default();
        let finished = !self.unfinished.iter().any(|held| held.version == version);
        Account { finished, found }
    }

    /// Every version accepted, oldest first.
    pub fn versions(&self) -> &[VersionSupport] {
        &self.versions
    }

    /// Every version whose walk did not finish, oldest first.
    ///
    /// Accepted or not: a version listed here and under
    /// [`versions`](Self::versions) accepts at least the suites found, and one
    /// listed only here was never settled either way.
    pub fn unfinished(&self) -> &[UnfinishedVersion] {
        &self.unfinished
    }

    /// Whether every version's walk finished, so that what is recorded is the
    /// whole of what the endpoint accepts.
    pub fn is_complete(&self) -> bool {
        self.unfinished.is_empty()
    }

    /// Whether nothing was recorded at all: no version accepted, and no walk
    /// left unfinished.
    ///
    /// An enumeration that settled nothing because the endpoint stopped
    /// answering is not empty. It is the one a reader most needs to see,
    /// since the alternative reading is an endpoint that refused everything.
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty() && self.unfinished.is_empty()
    }

    /// Whether `version` was accepted.
    pub fn accepts(&self, version: TlsVersion) -> bool {
        self.versions.iter().any(|held| held.version == version)
    }

    /// The oldest version accepted, which is the one a report leads with: it is
    /// the floor an attacker gets to choose from.
    pub fn floor(&self) -> Option<TlsVersion> {
        self.versions.first().map(|held| held.version)
    }

    /// The newest version accepted.
    pub fn ceiling(&self) -> Option<TlsVersion> {
        self.versions.last().map(|held| held.version)
    }

    /// Every accepted version a standards body has withdrawn, oldest first.
    pub fn deprecated_versions(&self) -> impl Iterator<Item = TlsVersion> + '_ {
        self.versions
            .iter()
            .map(|held| held.version)
            .filter(|version| version.is_deprecated())
    }

    /// Every suite accepted anywhere, deduplicated, in registry order.
    ///
    /// For a reader asking what the endpoint will negotiate rather than what it
    /// will negotiate under which version.
    pub fn suites(&self) -> Vec<CipherSuite> {
        let mut all: Vec<CipherSuite> = self
            .versions
            .iter()
            .flat_map(|held| held.suites.iter().copied())
            .collect();
        all.sort_unstable_by_key(|suite| suite.code());
        all.dedup();
        all
    }

    /// The worst grade among every suite accepted anywhere, or `None` where no
    /// suite was named.
    pub fn weakest(&self) -> Option<SuiteStrength> {
        self.versions
            .iter()
            .filter_map(VersionSupport::weakest)
            .max()
    }

    /// Every distinct fault carried by any accepted suite, least costly first.
    ///
    /// What a finding is written from: a reader acts on "this endpoint still
    /// negotiates RC4" rather than on the nine suite names that establish it.
    pub fn faults(&self) -> Vec<SuiteFault> {
        SuiteFault::ALL
            .into_iter()
            .filter(|fault| {
                self.versions
                    .iter()
                    .flat_map(|held| held.suites.iter())
                    .any(|suite| suite.has_fault(*fault))
            })
            .collect()
    }
}

/// One record's account of one version: whether its walk finished, and every
/// suite it found, by number.
struct Account {
    finished: bool,
    found: BTreeSet<u16>,
}

impl Account {
    /// Whether this account replaces `standing`, by the rule
    /// [`TlsSupport::merge`] states.
    fn supersedes(&self, standing: &Account) -> bool {
        let further = match (self.finished, standing.finished) {
            (_, true) => false,
            (true, false) => true,
            (false, false) => self.found.len() > standing.found.len(),
        };
        further && self.found.is_superset(&standing.found)
    }
}

// ---------------------------------------------------------------------------
// What to report about it
// ---------------------------------------------------------------------------

/// The id every finding this module produces is stamped under, which is how
/// one is recognised again once it is on a port.
const DETECTION: &str = "zond:tls";

/// The identity every finding this module produces is stamped with.
///
/// A built-in derivation rather than a dataset, so its identity is this build
/// and the rules compiled into it. The content hash is taken over the registry
/// itself, which means a suite added, removed or reclassified changes the hash
/// and two reports drawn by different rules can be told apart. The engine
/// version alone would not do that: the registry can move within a patch
/// release.
fn detection_id() -> DetectionId {
    static ID: OnceLock<DetectionId> = OnceLock::new();
    ID.get_or_init(|| {
        let version = env!("CARGO_PKG_VERSION")
            .parse::<Version>()
            .unwrap_or(Version::new(0, 0, 0));

        // The registry as a string, in declaration order: every number, name,
        // and derived grade. The grade is included so that a change to the fault
        // rules moves the hash even when no suite did.
        let mut census = String::with_capacity(CipherSuite::ALL.len() * 64);
        for suite in CipherSuite::ALL {
            use std::fmt::Write;
            let _ = write!(
                census,
                "{:04x}:{}:{};",
                suite.code(),
                suite.name(),
                suite.strength().name()
            );
        }
        let digest = ring::digest::digest(&ring::digest::SHA256, census.as_bytes());
        let mut hash = String::with_capacity(digest.as_ref().len() * 2);
        for byte in digest.as_ref() {
            use std::fmt::Write;
            let _ = write!(hash, "{byte:02x}");
        }

        DetectionId::new(DETECTION, version, hash).expect("the identifier is a non-empty literal")
    })
    .clone()
}

impl TlsSupport {
    /// Everything about this endpoint's configuration worth reporting, one
    /// finding per thing wrong with it.
    ///
    /// Grouped by the fault rather than by the suite, which is the difference
    /// between a report somebody reads and a list somebody scrolls past. An
    /// endpoint accepting nine RC4 suites has one problem, not nine, and the
    /// remedy is one line of configuration; the suite names are carried in the
    /// finding's excerpt for whoever needs to see them.
    ///
    /// A withdrawn version is its own finding, separately from whatever suites
    /// sit under it, because the two are fixed by different edits: one removes a
    /// protocol version and the other removes ciphers.
    ///
    /// Empty for an endpoint with nothing against it, which is the answer a
    /// clean scan should produce rather than an `Info` finding saying so.
    pub fn findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        for version in self.deprecated_versions() {
            let Some(severity) = version.severity() else {
                continue;
            };
            let withdrawn_by = version.deprecated_by().unwrap_or("a published standard");

            let Ok(finding) = Finding::new(
                detection_id(),
                format!("{version} is still accepted"),
                severity,
                // The server selected terms under it, in answer to a hello
                // offering it. There is no inference between the evidence and
                // the claim.
                Confidence::Certain,
                DetectionClass::ActiveBenign,
            ) else {
                continue;
            };

            // What the scan actually observed, and not a word more. An
            // enumeration offers a version and reads the ServerHello that comes
            // back; it derives no key, sends no Finished and completes no
            // handshake — see `protocols::tls`. The excerpt said "completed a
            // negotiation", which claimed an exchange that never happens here,
            // and claimed it most loudly for a HelloRetryRequest, whose whole
            // meaning is that the server wants to start again. A report signed
            // as evidence has to survive being read closely by somebody who
            // disagrees with it.
            let mut finding = finding.with_excerpt(Excerpt::new(format!(
                "the endpoint answered a {version} hello by selecting a suite under it; \
                 {withdrawn_by} withdrew it"
            )));
            if let Some(reference) = rfc_reference(withdrawn_by) {
                finding = finding.with_reference(reference);
            }
            findings.push(finding);
        }

        for fault in self.faults() {
            // Each suite once, however many versions accept it: the remedy is
            // to remove that cipher, which is one edit whether it was offered
            // under one protocol version or three, and a name listed once per
            // version would read as the same suite repeated with nothing to
            // tell the repeats apart.
            let mut carriers: Vec<&'static str> = Vec::new();
            for held in &self.versions {
                for suite in &held.suites {
                    if suite.has_fault(fault) && !carriers.contains(&suite.name()) {
                        carriers.push(suite.name());
                    }
                }
            }

            let Ok(finding) = Finding::new(
                detection_id(),
                format!("cipher suites accepted with {}", fault.summary()),
                fault.severity(),
                Confidence::Certain,
                DetectionClass::ActiveBenign,
            ) else {
                continue;
            };

            let mut finding = finding.with_excerpt(Excerpt::new(format!(
                "{} of the accepted suites carry this: {}",
                carriers.len(),
                carriers.join(", ")
            )));
            if let Some(reference) = fault_reference(fault) {
                finding = finding.with_reference(reference);
            }
            findings.push(finding);
        }

        findings
    }

    /// Where this record leaves a claim [`findings`](Self::findings) drew
    /// from `basis`, or `None` where `finding` is not one it draws from there.
    ///
    /// A claim rests on the versions whose accepted suites draw it: a
    /// withdrawn version on that version alone, and a fault on every version
    /// with a suite carrying it. This record upholds the claim where it draws
    /// it too. Where it does not, it overturned the claim only if it finished
    /// every version the claim rests on, because a walk cut short there found a
    /// floor and the claim may sit in the tail it never reached. A record with
    /// nothing in it made no walk, as [`merge`](Self::merge) reads it, and
    /// settles nothing.
    ///
    /// `None` covers a finding another detection produced, and one of this
    /// detection's that these rules do not draw from `basis`, as a build with
    /// other rules may have written. What such a claim rests on is not this
    /// build's to say, and a caller leaves it as it found it.
    pub(crate) fn standing(&self, finding: &Finding, basis: &TlsSupport) -> Option<Standing> {
        if finding.detection().id() != DETECTION {
            return None;
        }
        let claim = finding.claim_id();

        let rests_on = basis.resting(&claim);
        if rests_on.is_empty() {
            return None;
        }

        if self.claims().contains(&claim) {
            Some(Standing::Upheld)
        } else if rests_on
            .into_iter()
            .any(|version| self.leaves_open(version))
        {
            Some(Standing::Unsettled)
        } else {
            Some(Standing::Overturned)
        }
    }

    /// The excerpt `finding`, drawn from `basis`, should carry beside this
    /// record, or `None` where the one it was written with already fits.
    ///
    /// A claim's excerpt lists the evidence behind it, the suites carrying a
    /// fault under every version that accepts one, and carried beside a record
    /// that holds other evidence it would name what that record does not say.
    /// Where this record upholds the claim, the excerpt is the one this record
    /// draws for it. Where it leaves the claim unsettled, it is the one `basis`
    /// draws from the versions this record left open, since a version this
    /// record finished has its own answer and a suite `basis` found there is
    /// no part of why the claim still stands. A claim this record overturned,
    /// or one with no [`standing`](Self::standing) here, is not this function's
    /// to word.
    ///
    /// `None` too where the excerpt comes out as the one `basis` itself draws,
    /// which is what makes a finding whose evidence did not move travel as it
    /// was written, in whatever words the build that wrote it chose.
    pub(crate) fn restate(&self, finding: &Finding, basis: &TlsSupport) -> Option<Excerpt> {
        let claim = finding.claim_id();
        let excerpt = |record: &TlsSupport| {
            record
                .findings()
                .into_iter()
                .find(|drawn| drawn.claim_id() == claim)
                .map(|drawn| drawn.excerpt().clone())
        };

        let restated = match self.standing(finding, basis)? {
            Standing::Upheld => excerpt(self),
            Standing::Unsettled => excerpt(&TlsSupport {
                versions: basis
                    .versions
                    .iter()
                    .filter(|held| self.leaves_open(held.version))
                    .cloned()
                    .collect(),
                unfinished: Vec::new(),
            }),
            Standing::Overturned => None,
        }?;
        (excerpt(basis).as_ref() != Some(&restated)).then_some(restated)
    }

    /// The versions a claim drawn from this record rests on: those whose
    /// accepted suites draw it on their own.
    fn resting(&self, claim: &ClaimId) -> Vec<TlsVersion> {
        self.versions
            .iter()
            .filter(|held| {
                let alone = TlsSupport::new().accepting((*held).clone());
                alone.claims().contains(claim)
            })
            .map(|held| held.version)
            .collect()
    }

    /// Whether this record left `version` unsettled: its walk there was cut
    /// short, or this record made no walk at all.
    fn leaves_open(&self, version: TlsVersion) -> bool {
        self.is_empty() || self.unfinished.iter().any(|held| held.version == version)
    }

    /// Every claim [`findings`](Self::findings) draws from this record.
    fn claims(&self) -> BTreeSet<ClaimId> {
        self.findings().iter().map(Finding::claim_id).collect()
    }
}

/// The reference a version's withdrawal cites, where the document is an RFC.
fn rfc_reference(document: &str) -> Option<Reference> {
    let number = document.strip_prefix("RFC ")?;
    Some(Reference::url(format!(
        "https://www.rfc-editor.org/rfc/rfc{number}"
    )))
}

/// The document a fault is best read against, where one says it plainly.
fn fault_reference(fault: SuiteFault) -> Option<Reference> {
    match fault {
        SuiteFault::Rc4 => Some(Reference::url("https://www.rfc-editor.org/rfc/rfc7465")),
        SuiteFault::SmallBlock => Reference::cve("CVE-2016-2183"),
        _ => None,
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
    use std::collections::BTreeSet;

    /// A number appearing twice would make one of the two unreachable through
    /// [`CipherSuite::from_code`], so a server selecting it would be reported as
    /// the wrong suite: the wrong name, and the wrong faults under it.
    #[test]
    fn every_suite_has_a_number_of_its_own() {
        let mut seen = BTreeSet::new();
        for suite in CipherSuite::ALL {
            assert!(
                seen.insert(suite.code()),
                "0x{:04X} is registered twice, the second as {}",
                suite.code(),
                suite.name()
            );
        }
    }

    /// The same for names, which is what a reader and a diff key on.
    #[test]
    fn every_suite_has_a_name_of_its_own() {
        let mut seen = BTreeSet::new();
        for suite in CipherSuite::ALL {
            assert!(seen.insert(suite.name()), "{} is registered twice", suite);
        }
    }

    /// The registry's own consistency check, and the one that earns its keep.
    ///
    /// An IANA suite name states its parts in order, so the name and the fields
    /// beside it are two statements of the same fact. A transcription error in
    /// the fields is otherwise invisible: the scan offers a real suite, a server
    /// accepts it, and the report names the right suite with the wrong faults
    /// under it, which is worse than not asking. This reads the name and holds
    /// the fields to it.
    ///
    /// It cannot check the number, which nothing but the registry states. The
    /// numbers are grouped by their defining document above so that a reader can.
    #[test]
    fn every_suite_describes_what_its_name_says() {
        for suite in CipherSuite::ALL {
            let name = suite.name();

            // TLS 1.3 names its AEAD and hash and nothing else, RFC 8446 §B.4.
            if matches!(suite.key_exchange(), KeyExchange::Negotiated) {
                assert!(
                    !name.contains("_WITH_"),
                    "{name} is a 1.3 suite and should not name a key exchange"
                );
                assert!(suite.bulk_cipher().is_aead(), "{name} must be AEAD");
                assert_eq!(suite.mac(), Mac::Aead, "{name} carries no separate MAC");
                continue;
            }

            let (kex_part, cipher_part) = name
                .strip_prefix("TLS_")
                .and_then(|rest| rest.split_once("_WITH_"))
                .unwrap_or_else(|| panic!("{name} is not an IANA suite name"));

            // Key exchange and authentication, which the name states together.
            let expected_kex = if kex_part.starts_with("ECDHE_") {
                KeyExchange::Ecdhe
            } else if kex_part.starts_with("DHE_") {
                KeyExchange::Dhe
            } else if kex_part.contains("anon") {
                KeyExchange::Anonymous
            } else if kex_part.starts_with("ECDH_") {
                KeyExchange::Ecdh
            } else {
                KeyExchange::Rsa
            };
            assert_eq!(suite.key_exchange(), expected_kex, "key exchange of {name}");

            let expected_auth = if kex_part.contains("anon") {
                Authentication::Anonymous
            } else if kex_part.contains("ECDSA") {
                Authentication::Ecdsa
            } else if kex_part.contains("DSS") {
                Authentication::Dss
            } else {
                Authentication::Rsa
            };
            assert_eq!(
                suite.authentication(),
                expected_auth,
                "authentication of {name}"
            );

            assert_eq!(
                suite.is_export(),
                kex_part.contains("EXPORT"),
                "export grade of {name}"
            );

            // The MAC is the last element of the name for every non-AEAD suite.
            let expected_mac = if cipher_part.ends_with("_SHA256") {
                Mac::Sha256
            } else if cipher_part.ends_with("_SHA384") {
                Mac::Sha384
            } else if cipher_part.ends_with("_SHA") {
                Mac::Sha1
            } else if cipher_part.ends_with("_MD5") {
                Mac::Md5
            } else {
                panic!("{name} names no MAC this test can read")
            };
            let expected_mac = match suite.bulk_cipher().is_aead() {
                true => Mac::Aead,
                false => expected_mac,
            };
            assert_eq!(suite.mac(), expected_mac, "MAC of {name}");

            // And the cipher, which the middle of the name states.
            let cipher = suite.bulk_cipher();
            let claims = |needle: &str| cipher_part.contains(needle);
            match cipher {
                C::AesGcm(bits) => {
                    assert!(claims("AES_") && claims("_GCM_"), "cipher of {name}");
                    assert!(claims(&bits.to_string()), "key size of {name}");
                }
                C::AesCbc(bits) => {
                    assert!(claims("AES_") && claims("_CBC_"), "cipher of {name}");
                    assert!(claims(&bits.to_string()), "key size of {name}");
                }
                C::CamelliaCbc(bits) => {
                    assert!(claims("CAMELLIA_") && claims("_CBC_"), "cipher of {name}");
                    assert!(claims(&bits.to_string()), "key size of {name}");
                }
                C::ChaCha20Poly1305 => assert!(claims("CHACHA20_POLY1305"), "cipher of {name}"),
                C::TripleDes => assert!(claims("3DES_EDE_CBC"), "cipher of {name}"),
                // RC2 is carried as DES: both are export-era block ciphers this
                // engine only needs to recognise and report, and neither is
                // worth a variant of its own.
                C::Des => assert!(
                    claims("DES") || claims("RC2"),
                    "cipher of {name} is not a DES-class cipher"
                ),
                C::Rc4 => assert!(claims("RC4_"), "cipher of {name}"),
                C::SeedCbc => assert!(claims("SEED_CBC"), "cipher of {name}"),
                C::IdeaCbc => assert!(claims("IDEA_CBC"), "cipher of {name}"),
                C::Null => assert!(claims("NULL"), "cipher of {name}"),
                C::AesCcm { .. } => panic!("{name} is a CCM suite outside TLS 1.3"),
            }
        }
    }

    /// The grading rule, stated once here so that a change to it is a change to
    /// a test rather than a silent reclassification of ninety suites.
    #[test]
    fn a_suite_is_graded_by_the_worst_thing_about_it() {
        let named = |name: &str| {
            CipherSuite::ALL
                .into_iter()
                .find(|suite| suite.name() == name)
                .unwrap_or_else(|| panic!("{name} is in the registry"))
        };

        // Nothing against it: AEAD over an ephemeral exchange.
        let strong = named("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        assert_eq!(strong.strength(), SuiteStrength::Strong);
        assert!(strong.faults().is_empty());

        // Modern records, no forward secrecy. Usable, worth removing.
        let no_fs = named("TLS_RSA_WITH_AES_128_GCM_SHA256");
        assert_eq!(no_fs.strength(), SuiteStrength::Weak);
        assert_eq!(no_fs.faults(), vec![SuiteFault::NoForwardSecrecy]);

        // Ephemeral and CBC with a SHA-1 MAC: two faults, neither disqualifying.
        let cbc = named("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        assert_eq!(cbc.strength(), SuiteStrength::Weak);
        assert_eq!(
            cbc.faults(),
            vec![SuiteFault::Sha1Mac, SuiteFault::CbcMode],
            "both faults are reported, not only the worst"
        );

        // A 64-bit block disqualifies whatever else is right about the suite.
        let sweet32 = named("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
        assert_eq!(sweet32.strength(), SuiteStrength::Insecure);
        assert_eq!(sweet32.worst_fault(), Some(SuiteFault::SmallBlock));

        // And the ones that are simply broken.
        for name in [
            "TLS_RSA_WITH_RC4_128_SHA",
            "TLS_DH_anon_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_NULL_SHA",
            "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        ] {
            assert_eq!(
                named(name).strength(),
                SuiteStrength::Insecure,
                "{name} is not usable"
            );
        }
    }

    /// Anonymous suites are reported for what they are rather than filed under
    /// the missing forward secrecy they do not have: an anonymous exchange *is*
    /// ephemeral, and calling it "no forward secrecy" would be both wrong and
    /// the less alarming of the two things to say.
    #[test]
    fn an_anonymous_suite_is_not_reported_as_lacking_forward_secrecy() {
        let anon = CipherSuite::from_code(0x0034).expect("TLS_DH_anon_WITH_AES_128_CBC_SHA");
        assert!(anon.is_forward_secret());
        assert!(!anon.has_fault(SuiteFault::NoForwardSecrecy));
        assert!(anon.has_fault(SuiteFault::Anonymous));
    }

    /// The two families never mix, and the split is what keeps an enumeration
    /// from reporting a whole version unsupported because it asked with suites
    /// that version cannot express.
    #[test]
    fn each_version_is_offered_the_suites_it_can_express() {
        let thirteen: Vec<_> = CipherSuite::offered_under(TlsVersion::Tls13).collect();
        assert_eq!(thirteen.len(), 5, "RFC 8446 §B.4 defines five");
        assert!(thirteen.iter().all(
            |suite| suite.name().starts_with("TLS_A") || suite.name().starts_with("TLS_CHACHA")
        ));

        for version in [TlsVersion::Ssl30, TlsVersion::Tls10, TlsVersion::Tls11] {
            for suite in CipherSuite::offered_under(version) {
                assert!(
                    matches!(suite.mac(), Mac::Md5 | Mac::Sha1 | Mac::Null),
                    "{suite} needs the TLS 1.2 PRF and cannot be offered under {version}"
                );
            }
        }

        let twelve: Vec<_> = CipherSuite::offered_under(TlsVersion::Tls12).collect();
        assert_eq!(
            twelve.len(),
            CipherSuite::ALL.len() - 5,
            "everything but the 1.3 suites"
        );
    }

    /// Every version round-trips through its wire number and through its name,
    /// so a report read back names the version it recorded.
    #[test]
    fn every_version_round_trips_through_its_number_and_its_name() {
        for version in TlsVersion::ALL {
            assert_eq!(TlsVersion::from_code(version.code()), Some(version));
            assert_eq!(version.to_string().parse(), Ok(version));
        }
        assert_eq!(TlsVersion::from_code(0x0305), None);
        assert!("TLSv1.4".parse::<TlsVersion>().is_err());
    }

    /// The withdrawn versions are exactly the three that were withdrawn, and
    /// each names the document that did it.
    #[test]
    fn the_deprecated_versions_are_the_ones_a_standard_withdrew() {
        for version in TlsVersion::ALL {
            assert_eq!(
                version.is_deprecated(),
                version.deprecated_by().is_some(),
                "{version} must cite a document exactly when it is deprecated"
            );
        }
        assert_eq!(TlsVersion::Ssl30.deprecated_by(), Some("RFC 7568"));
        assert_eq!(TlsVersion::Tls10.deprecated_by(), Some("RFC 8996"));
        assert_eq!(TlsVersion::Tls11.deprecated_by(), Some("RFC 8996"));
        assert_eq!(TlsVersion::Tls12.deprecated_by(), None);
        assert_eq!(TlsVersion::Tls13.deprecated_by(), None);
    }

    /// Every suite is reachable by the number a server would select it with.
    #[test]
    fn every_suite_is_found_by_its_number() {
        for suite in CipherSuite::ALL {
            assert_eq!(CipherSuite::from_code(suite.code()), Some(suite));
        }
        assert_eq!(CipherSuite::from_code(0xFFFF), None);
    }

    /// A fault is disqualifying or it is not, and the grade follows from that
    /// alone. Stated as a property over the whole registry so a suite added
    /// later cannot land outside the rule.
    #[test]
    fn the_grade_follows_from_the_worst_fault_for_every_suite() {
        for suite in CipherSuite::ALL {
            let expected = match suite.worst_fault() {
                None => SuiteStrength::Strong,
                Some(fault) if fault.is_disqualifying() => SuiteStrength::Insecure,
                Some(_) => SuiteStrength::Weak,
            };
            assert_eq!(suite.strength(), expected, "grade of {suite}");

            // And the faults reported are exactly the ones the parts imply.
            for fault in suite.faults() {
                assert!(suite.has_fault(fault), "{suite} reported {fault} it lacks");
            }
        }
    }

    // ── What an enumeration turns into ───────────────────────────────────────

    fn suite(code: u16) -> CipherSuite {
        CipherSuite::from_code(code).expect("a suite in the registry")
    }

    /// The record keeps its versions oldest first however they were recorded,
    /// so a report's version list is in the same order for every endpoint and
    /// two scans diff cleanly.
    #[test]
    fn recorded_versions_are_ordered_oldest_first() {
        let support = TlsSupport::new()
            .accepting(VersionSupport::new(TlsVersion::Tls13, vec![], vec![]))
            .accepting(VersionSupport::new(TlsVersion::Tls10, vec![], vec![]))
            .accepting(VersionSupport::new(TlsVersion::Tls12, vec![], vec![]));

        let order: Vec<_> = support.versions().iter().map(|v| v.version()).collect();
        assert_eq!(
            order,
            vec![TlsVersion::Tls10, TlsVersion::Tls12, TlsVersion::Tls13]
        );
        assert_eq!(support.floor(), Some(TlsVersion::Tls10));
        assert_eq!(support.ceiling(), Some(TlsVersion::Tls13));
    }

    /// Recording a version twice replaces it rather than listing it twice: a
    /// second enumeration of one endpoint answers the same question.
    #[test]
    fn recording_a_version_twice_keeps_one_entry() {
        let mut support = TlsSupport::new();
        support.record(VersionSupport::new(TlsVersion::Tls12, vec![], vec![]));
        support.record(VersionSupport::new(
            TlsVersion::Tls12,
            vec![suite(0xC030)],
            vec![],
        ));

        assert_eq!(support.versions().len(), 1);
        assert_eq!(support.suites().len(), 1);
    }

    /// A version whose walk was cut before the server said anything about it
    /// is unknown, and must read as neither of the two things it is not.
    ///
    /// Read as accepted, an unfinished TLS 1.0 walk would report the most
    /// quotable finding a TLS scan produces about a server that may never have
    /// spoken 1.0. Read as nothing, the enumeration would look like an endpoint
    /// that refused every offer, and be dropped as carrying no new fact.
    #[test]
    fn a_version_never_settled_is_neither_accepted_nor_nothing() {
        let support = TlsSupport::new().leaving_unfinished(UnfinishedVersion::new(
            TlsVersion::Tls10,
            Interruption::Unanswered,
        ));

        assert!(!support.accepts(TlsVersion::Tls10));
        assert!(support.findings().is_empty(), "nothing was established");
        assert!(!support.is_complete());
        assert!(
            !support.is_empty(),
            "a walk the endpoint cut short is a fact about it"
        );
    }

    /// Every cause round-trips through its name, so a record read back says why
    /// a walk did not finish in the words it was written with.
    #[test]
    fn every_interruption_round_trips_through_its_name() {
        for cause in Interruption::ALL {
            assert_eq!(Interruption::from_name(cause.name()), Some(cause));
        }
        assert_eq!(Interruption::from_name("abandoned"), None);
    }

    // ── Two enumerations of one endpoint ─────────────────────────────────────

    /// TLS 1.2 walked until the server declined, having found `suites`.
    fn finished(suites: &[u16]) -> TlsSupport {
        TlsSupport::new().accepting(VersionSupport::new(
            TlsVersion::Tls12,
            suites.iter().map(|code| suite(*code)).collect(),
            vec![],
        ))
    }

    /// TLS 1.2 cut short for `why`, having found `suites`.
    fn cut_short(suites: &[u16], why: Interruption) -> TlsSupport {
        let support =
            TlsSupport::new().leaving_unfinished(UnfinishedVersion::new(TlsVersion::Tls12, why));
        if suites.is_empty() {
            return support;
        }
        support.accepting(VersionSupport::new(
            TlsVersion::Tls12,
            suites.iter().map(|code| suite(*code)).collect(),
            vec![],
        ))
    }

    /// `other` folded into `on_record`.
    fn folded(on_record: &TlsSupport, other: &TlsSupport) -> TlsSupport {
        let mut folded = on_record.clone();
        folded.merge(other.clone());
        folded
    }

    /// A walk that finished is the whole answer, and one cut short that found
    /// nothing it lacks is part of that answer, whichever is on record. A
    /// resumed sitting finishing the walk its predecessor was stopped in is one
    /// way round, and a merge whose newer scan was stopped is the other.
    #[test]
    fn a_finished_walk_stands_over_a_cut_short_one_whichever_is_on_record() {
        let whole = finished(&[0xC030, 0xC02F, 0x000A]);
        let floor = cut_short(&[0xC030], Interruption::Stopped);

        assert_eq!(folded(&whole, &floor), whole);
        assert_eq!(folded(&floor, &whole), whole);
    }

    /// A walk cut short that found a suite a finished walk does not list was
    /// answered by a different configuration, and the finished list is no
    /// answer for it. Taken instead, a server that has since started accepting
    /// 3DES would be reported as refusing it.
    #[test]
    fn a_walk_that_found_what_the_other_does_not_list_is_not_displaced() {
        let whole = finished(&[0xC030, 0xC02F]);
        let changed = cut_short(&[0x000A], Interruption::Unanswered);

        assert_eq!(folded(&changed, &whole), changed);
    }

    /// Two walks of one configuration cut short each found the head of the
    /// same preference order, and the longer head is the better floor. It
    /// carries its own interruption, since that is why it ended where it did.
    #[test]
    fn of_two_cut_short_walks_the_one_that_got_further_stands() {
        let short = cut_short(&[0xC030], Interruption::Stopped);
        let further = cut_short(&[0xC030, 0xC02F], Interruption::Unanswered);

        assert_eq!(folded(&short, &further), further);
        assert_eq!(folded(&further, &short), further);
    }

    /// A version an enumeration lists nowhere was walked and refused, which is
    /// a finished answer. A walk cut short before the server said anything
    /// about the version is no evidence against it.
    #[test]
    fn a_refused_version_stands_over_one_never_settled() {
        let thirteen = VersionSupport::new(TlsVersion::Tls13, vec![suite(0x1301)], vec![]);
        let refused = TlsSupport::new().accepting(thirteen.clone());
        let unsettled = cut_short(&[], Interruption::Unanswered).accepting(thirteen);

        assert_eq!(folded(&unsettled, &refused), refused);
    }

    /// An empty record is an endpoint nobody enumerated. Read version by
    /// version it would be five refusals, each a finished answer, so it is set
    /// aside whole: it neither displaces an enumeration nor stands over one.
    #[test]
    fn a_record_nobody_enumerated_displaces_nothing() {
        let whole = finished(&[0xC030]);

        assert_eq!(folded(&whole, &TlsSupport::new()), whole);
        assert_eq!(folded(&TlsSupport::new(), &whole), whole);
    }

    /// A suite accepted under two versions is one suite, and the faults it
    /// carries are reported once.
    #[test]
    fn a_suite_accepted_twice_is_counted_once() {
        let support = TlsSupport::new()
            .accepting(VersionSupport::new(
                TlsVersion::Tls11,
                vec![suite(0x002F)],
                vec![],
            ))
            .accepting(VersionSupport::new(
                TlsVersion::Tls12,
                vec![suite(0x002F)],
                vec![],
            ));

        assert_eq!(support.suites().len(), 1);
    }

    /// An endpoint with nothing against it produces no findings at all. A clean
    /// scan should be quiet rather than carry an `Info` saying it is clean.
    #[test]
    fn a_sound_endpoint_produces_no_findings() {
        let support = TlsSupport::new()
            .accepting(VersionSupport::new(
                TlsVersion::Tls13,
                vec![suite(0x1302)],
                vec![],
            ))
            .accepting(VersionSupport::new(
                TlsVersion::Tls12,
                vec![suite(0xC030), suite(0xC02B)],
                vec![],
            ));

        assert_eq!(support.weakest(), Some(SuiteStrength::Strong));
        assert!(support.faults().is_empty());
        assert!(support.findings().is_empty());
    }

    /// A withdrawn version is its own finding, separate from the suites under
    /// it: the two are fixed by different edits, one removing a protocol version
    /// and one removing ciphers.
    #[test]
    fn a_withdrawn_version_is_reported_on_its_own_terms() {
        let support = TlsSupport::new().accepting(VersionSupport::new(
            TlsVersion::Tls10,
            // Nothing wrong with the suite beyond what its era implies, so the
            // version finding cannot be confused with a suite finding.
            vec![suite(0x002F)],
            vec![],
        ));

        let findings = support.findings();
        let version_finding = findings
            .iter()
            .find(|finding| finding.title().contains("TLSv1.0"))
            .expect("the version is reported");

        assert_eq!(version_finding.severity(), Severity::Medium);
        assert!(
            version_finding
                .references()
                .any(|reference| matches!(reference, Reference::Url(url) if url.contains("8996"))),
            "the finding cites the document that withdrew the version"
        );
    }

    /// Nine RC4 suites are one problem and one line of configuration, so they
    /// are one finding with the suites in its excerpt rather than nine findings.
    #[test]
    fn one_fault_across_many_suites_is_one_finding() {
        let rc4: Vec<CipherSuite> = CipherSuite::ALL
            .into_iter()
            .filter(|suite| suite.has_fault(SuiteFault::Rc4) && !suite.is_export())
            .collect();
        assert!(rc4.len() > 3, "the registry carries several RC4 suites");

        let support = TlsSupport::new().accepting(VersionSupport::new(
            TlsVersion::Tls12,
            rc4.clone(),
            vec![],
        ));

        let rc4_findings: Vec<_> = support
            .findings()
            .into_iter()
            .filter(|finding| finding.title().contains("RC4"))
            .collect();

        assert_eq!(rc4_findings.len(), 1, "one problem, one finding");
        assert!(
            rc4_findings[0]
                .excerpt()
                .as_str()
                .contains("TLS_RSA_WITH_RC4_128_SHA"),
            "the suites are carried in the excerpt for whoever needs them"
        );
    }

    /// A suite accepted under several versions is one cipher to remove, so the
    /// excerpt names it once with a count to match, not once per version with
    /// nothing to tell the repeats apart.
    #[test]
    fn a_suite_accepted_under_several_versions_is_listed_once() {
        let rc4 = CipherSuite::ALL
            .into_iter()
            .find(|suite| suite.has_fault(SuiteFault::Rc4) && !suite.is_export())
            .expect("the registry carries an RC4 suite");

        let support = TlsSupport::new()
            .accepting(VersionSupport::new(TlsVersion::Tls10, vec![rc4], vec![]))
            .accepting(VersionSupport::new(TlsVersion::Tls11, vec![rc4], vec![]))
            .accepting(VersionSupport::new(TlsVersion::Tls12, vec![rc4], vec![]));

        let excerpt = support
            .findings()
            .into_iter()
            .find(|finding| finding.title().contains("RC4"))
            .expect("the RC4 fault is one finding")
            .excerpt()
            .as_str()
            .to_string();

        assert_eq!(
            excerpt.matches(rc4.name()).count(),
            1,
            "the suite is named once across three versions: {excerpt}"
        );
        assert!(
            excerpt.starts_with("1 of the accepted suites"),
            "and the count matches the list: {excerpt}"
        );
    }

    /// The severity a fault earns is the one the report prints, and the ceiling
    /// is deliberate: every fault here costs an attacker a position on the
    /// network first, which is not what this crate calls critical.
    #[test]
    fn no_tls_fault_is_reported_as_critical() {
        for fault in SuiteFault::ALL {
            assert!(
                fault.severity() < Severity::Critical,
                "{fault} reached critical"
            );
        }
        assert_eq!(SuiteFault::NullCipher.severity(), Severity::High);
        assert_eq!(SuiteFault::Rc4.severity(), Severity::Medium);
        assert_eq!(SuiteFault::CbcMode.severity(), Severity::Low);
    }

    /// Every finding is stamped with the same identity, and the hash moves with
    /// the registry rather than only with the release: the rules can change
    /// inside a patch version and two reports have to be tellable apart.
    #[test]
    fn every_finding_carries_the_registry_it_was_drawn_from() {
        let support = TlsSupport::new().accepting(VersionSupport::new(
            TlsVersion::Ssl30,
            vec![suite(0x0004)],
            vec![],
        ));

        let findings = support.findings();
        assert!(!findings.is_empty());
        for finding in &findings {
            assert_eq!(finding.detection().id(), "zond:tls");
            assert_eq!(
                finding.detection().content_hash().len(),
                64,
                "a SHA-256 of the registry, in hex"
            );
        }
    }

    /// Every finding this produces survives being filed against one port.
    ///
    /// The assumption the whole reporting path rests on, and it is not obvious:
    /// a port deduplicates findings by claim, which is the producing detection's
    /// id paired with its first CVE or, failing that, its title. Every finding
    /// here carries the same detection id, so what keeps them apart is the
    /// title alone. Two faults whose summaries read the same, or two versions
    /// phrased alike, would collapse into one and the rest would be silently
    /// lost.
    #[test]
    fn every_finding_survives_being_filed_against_one_port() {
        use crate::model::port::{Port, PortState, Protocol};

        // A thoroughly bad endpoint: three withdrawn versions and a suite from
        // every fault class the registry can produce.
        let mut support = TlsSupport::new();
        for version in [TlsVersion::Ssl30, TlsVersion::Tls10, TlsVersion::Tls11] {
            let carriers: Vec<CipherSuite> = SuiteFault::ALL
                .into_iter()
                .filter_map(|fault| {
                    CipherSuite::offered_under(version).find(|suite| suite.has_fault(fault))
                })
                .collect();
            support.record(VersionSupport::new(version, carriers, vec![]));
        }

        let findings = support.findings();
        assert_eq!(
            findings.len(),
            support.faults().len() + 3,
            "one per fault, plus one per withdrawn version"
        );

        let mut port = Port::new(443, Protocol::Tcp, PortState::Open);
        for finding in findings.clone() {
            port.add_finding(finding);
        }

        assert_eq!(
            port.findings().count(),
            findings.len(),
            "two findings collapsed into one claim and the difference was lost"
        );
    }

    // ── Where a later record leaves a claim ──────────────────────────────────

    /// A fault claim rests on every version that drew it, so a later record
    /// refutes it only by finishing all of them.
    ///
    /// The reading a comparison and a merge both act on: one that called a
    /// claim overturned on the strength of a walk cut short would report a fix
    /// nobody made, and one that called it unsettled after every walk finished
    /// would never report the fix at all.
    #[test]
    fn a_claim_is_overturned_only_where_every_walk_it_rests_on_finished() {
        use TlsVersion::{Tls10, Tls12};

        let rc4 = suite(0x0005);
        let basis = TlsSupport::new()
            .accepting(VersionSupport::new(Tls10, vec![rc4], vec![]))
            .accepting(VersionSupport::new(Tls12, vec![rc4], vec![]));
        let claim = basis
            .findings()
            .into_iter()
            .find(|finding| finding.title().contains("RC4"))
            .expect("the basis draws an RC4 claim");

        let strong = VersionSupport::new(Tls12, vec![suite(0xC030)], vec![]);
        let refused_and_finished = TlsSupport::new().accepting(strong.clone());
        let refused_and_cut_short = refused_and_finished
            .clone()
            .leaving_unfinished(UnfinishedVersion::new(Tls12, Interruption::Stopped));
        let still_accepted =
            TlsSupport::new().accepting(VersionSupport::new(Tls12, vec![rc4], vec![]));

        assert_eq!(
            refused_and_finished.standing(&claim, &basis),
            Some(Standing::Overturned)
        );
        assert_eq!(
            refused_and_cut_short.standing(&claim, &basis),
            Some(Standing::Unsettled),
            "TLS 1.0 is settled, but the TLS 1.2 walk may have stopped short of RC4"
        );
        assert_eq!(
            TlsSupport::new().standing(&claim, &basis),
            Some(Standing::Unsettled),
            "a record with nothing in it made no walk"
        );
        assert_eq!(
            still_accepted.standing(&claim, &basis),
            Some(Standing::Upheld)
        );
    }

    /// A claim this derivation does not draw from the record it is said to
    /// rest on has nothing this build can name, and is left alone.
    #[test]
    fn a_claim_these_rules_do_not_draw_has_no_standing() {
        let basis = TlsSupport::new().accepting(VersionSupport::new(
            TlsVersion::Tls10,
            vec![suite(0x002F)],
            vec![],
        ));
        let foreign = Finding::new(
            detection_id(),
            "a claim worded by other rules",
            Severity::Low,
            Confidence::Certain,
            DetectionClass::ActiveBenign,
        )
        .expect("a titled finding");

        assert_eq!(TlsSupport::new().standing(&foreign, &basis), None);
    }

    /// The version this build reports itself as, which is what stamps a finding.
    #[test]
    fn the_detection_identity_names_this_build() {
        let id = detection_id();
        let expected: Version = env!("CARGO_PKG_VERSION").parse().expect("a valid version");
        assert_eq!(id.version(), expected);
    }
}
