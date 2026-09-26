// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Collected responses
//!
//! [`ResponseSet`] is everything the transport gathered from a port, handed to
//! the analyzers as one value. It is a struct rather than a bare `Vec<String>`
//! so that non-banner evidence, such as a TLS certificate, has a typed home
//! instead of being squeezed through a lossy `String`.
//!
//! The transport owns collection (I/O); analyzers own interpretation (CPU). So
//! the TLS certificate lives here as **raw DER bytes**, not a parsed structure:
//! parsing is x509 work that belongs in [`TlsCertAnalyzer`], off the reactor,
//! and keeping rustls/x509 types out of this model stops them leaking into every
//! analyzer.
//!
//! [`TlsCertAnalyzer`]: super::tls_cert::TlsCertAnalyzer

use crate::model::host::HostName;

/// What a TLS handshake yielded: what was negotiated, and the certificate chain
/// the peer presented as raw DER, leaf first.
///
/// Empty `certificates` still means "this port completed a TLS handshake", a
/// signal in itself, but the analyzers here need a leaf cert to say anything.
///
/// The negotiated parameters are captured here rather than re-derived later
/// because they exist only on the live connection: once the tunnel is dropped,
/// what version and cipher were agreed is unrecoverable without handshaking
/// again.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct TlsInfo {
    /// The presented chain in DER form, leaf first. Owned so nothing borrows the
    /// live connection.
    pub certificates: Vec<Vec<u8>>,
    /// The protocol version agreed, as the RFCs write it: `"TLSv1.3"`.
    ///
    /// `None` for a version this engine does not offer, which cannot happen
    /// through its own connector and can if a caller supplies its own.
    pub version: Option<&'static str>,
    /// The cipher suite the server selected, under its IANA name.
    pub cipher_suite: Option<&'static str>,
    /// The protocol agreed over ALPN, if the server chose one.
    ///
    /// A single value rather than a list: ALPN negotiation *selects*, so this is
    /// what the server picked and not what it would have accepted. Nothing short
    /// of one handshake per candidate reveals the latter.
    pub alpn: Option<String>,
}

impl TlsInfo {
    /// A handshake result carrying `certificates`, leaf first, and nothing
    /// negotiated yet.
    #[must_use]
    pub fn new(certificates: Vec<Vec<u8>>) -> Self {
        Self {
            certificates,
            ..Self::default()
        }
    }

    /// Records the protocol version agreed, as the RFCs write it.
    #[must_use]
    pub fn with_version(mut self, version: &'static str) -> Self {
        self.version = Some(version);
        self
    }

    /// Records the cipher suite the server selected, under its IANA name.
    #[must_use]
    pub fn with_cipher_suite(mut self, suite: &'static str) -> Self {
        self.cipher_suite = Some(suite);
        self
    }

    /// Records the protocol agreed over ALPN.
    #[must_use]
    pub fn with_alpn(mut self, alpn: impl Into<String>) -> Self {
        self.alpn = Some(alpn.into());
        self
    }

    /// The leaf (end-entity) certificate's DER bytes, if the peer presented one.
    pub fn leaf(&self) -> Option<&[u8]> {
        self.certificates.first().map(Vec::as_slice)
    }
}

/// Every response the transport collected from a single port.
///
/// Analyzers read only the fields they understand: [`BannerRegexAnalyzer`] reads
/// [`banners`](Self::banners); [`TlsCertAnalyzer`] reads [`tls`](Self::tls). A
/// field being empty simply means that source produced nothing.
///
/// [`BannerRegexAnalyzer`]: super::analyzer::BannerRegexAnalyzer
/// [`TlsCertAnalyzer`]: super::tls_cert::TlsCertAnalyzer
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct ResponseSet {
    /// Plaintext banner and active-probe responses, in the order collected.
    pub banners: Vec<String>,
    /// The TLS handshake result, if one was attempted and completed.
    pub tls: Option<TlsInfo>,
    /// The names the responses gave for the machine, read from their
    /// structure: the realm a Kerberos KDC names, for one.
    ///
    /// Kept out of [`banners`](Self::banners) because a banner is matched,
    /// and what a rule captures from it becomes a service's description,
    /// which no report masks. A name is the host's, and a report masks it
    /// where it masks a hostname.
    pub names: Vec<HostName>,
}

impl ResponseSet {
    /// A response set from plaintext banners alone (no TLS attempted).
    #[must_use]
    pub fn from_banners(banners: Vec<String>) -> Self {
        Self {
            banners,
            ..Self::default()
        }
    }

    /// Adds what `other` collected after what this one did.
    ///
    /// For responses gathered in the clear, which carry no handshake: a
    /// handshake belongs to the one connection it completed on, and the
    /// caller holding it is the one to record it.
    pub(crate) fn extend(&mut self, other: ResponseSet) {
        debug_assert!(other.tls.is_none(), "a handshake is not merged");
        self.banners.extend(other.banners);
        self.names.extend(other.names);
    }

    /// Records what a completed handshake yielded beside the banners.
    #[must_use]
    pub fn with_tls(mut self, tls: TlsInfo) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Whether nothing at all was collected: no banners and no TLS.
    pub fn is_empty(&self) -> bool {
        self.banners.is_empty() && self.tls.is_none()
    }
}

/// The raw frames an [`Analyzer`] gathered from its *own* probes during the
/// collect phase, kept separate from the shared first-contact data in
/// [`ResponseSet`].
///
/// Bytes, not text: an active analyzer speaks a specific protocol (a JARM
/// ClientHello sweep, an SSH `KEXINIT`, a Modbus request) and parses the reply
/// byte-for-byte, so there is no lossy `String` in the way. A passive analyzer,
/// one that reads only the shared [`ResponseSet`], never overrides `collect`,
/// so its `Collected` is simply empty.
///
/// [`Analyzer`]: super::analyzer::Analyzer
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct Collected {
    /// Raw frames read from this analyzer's own probes, in the order collected.
    pub frames: Vec<Vec<u8>>,
}

impl Collected {
    /// What an active analyzer's own probe exchange read, in order.
    #[must_use]
    pub fn from_frames(frames: Vec<Vec<u8>>) -> Self {
        Self { frames }
    }
}
