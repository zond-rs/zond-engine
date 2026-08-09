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
//! the analyzers as one value. It replaces the bare `Vec<String>` the engine
//! started with so that non-banner evidence — a TLS certificate now, raw binary
//! protocol frames later — has a typed home instead of being squeezed through a
//! lossy `String`.
//!
//! The transport owns collection (I/O); analyzers own interpretation (CPU). So
//! the TLS certificate lives here as **raw DER bytes**, not a parsed structure:
//! parsing is x509 work that belongs in [`TlsCertAnalyzer`], off the reactor,
//! and keeping rustls/x509 types out of this model stops them leaking into every
//! analyzer.
//!
//! [`TlsCertAnalyzer`]: super::tls_cert::TlsCertAnalyzer

/// What a TLS handshake yielded: the certificate chain the peer presented, as
/// raw DER, leaf first.
///
/// Empty `certificates` still means "this port completed a TLS handshake" — a
/// signal in itself — but the analyzers here need a leaf cert to say anything.
#[derive(Debug, Clone, Default)]
pub struct TlsInfo {
    /// The presented chain in DER form, leaf first. Owned so nothing borrows the
    /// live connection.
    pub certificates: Vec<Vec<u8>>,
}

impl TlsInfo {
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
#[derive(Debug, Clone, Default)]
pub struct ResponseSet {
    /// Plaintext banner and active-probe responses, in the order collected.
    pub banners: Vec<String>,
    /// The TLS handshake result, if one was attempted and completed.
    pub tls: Option<TlsInfo>,
}

impl ResponseSet {
    /// A response set from plaintext banners alone (no TLS attempted).
    pub fn from_banners(banners: Vec<String>) -> Self {
        Self { banners, tls: None }
    }

    /// Whether nothing at all was collected — no banners and no TLS.
    pub fn is_empty(&self) -> bool {
        self.banners.is_empty() && self.tls.is_none()
    }
}

/// The raw frames an [`Analyzer`] gathered from its *own* probes during the
/// collect phase, kept separate from the shared first-contact data in
/// [`ResponseSet`].
///
/// Bytes, not text: an active analyzer speaks a specific protocol (a JARM
/// ClientHello sweep, an SSH `KEXINIT`, a Modbus request, and the future
/// nerva-derived binary handlers) and parses the reply byte-for-byte, so there
/// is no lossy `String` in the way. A passive analyzer — one that reads only the
/// shared [`ResponseSet`] — never overrides `collect`, so its `Collected` is
/// simply empty.
///
/// [`Analyzer`]: super::analyzer::Analyzer
#[derive(Debug, Clone, Default)]
pub struct Collected {
    /// Raw frames read from this analyzer's own probes, in the order collected.
    pub frames: Vec<Vec<u8>>,
}
