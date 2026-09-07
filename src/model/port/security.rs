// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a TLS endpoint negotiated
//!
//! [`Security`] is what a completed handshake established about a port: the
//! version and cipher agreed, the protocols offered over ALPN, and a summary of
//! the certificate presented.
//!
//! The certificate is summarized, not stored. A chain is kilobytes and a
//! report may hold thousands; what a reader acts on is the name it was issued
//! to, who issued it, when it expires and its fingerprint, so those are kept
//! and the DER is not. A caller needing the chain itself has to re-fetch it,
//! which is the right trade for a record meant to be written to a file and read
//! later.
//!
//! Validity is reported against a time the caller supplies rather than assumed
//! from the clock; see [`Security::is_cert_valid_at`]. A scan is read long
//! after it ran, and "expired" answered from the current time would relabel a
//! report every time it was opened.

use std::sync::{Arc, OnceLock};

use crate::model::confidence::Confidence;
use crate::model::finding::{
    DetectionClass, DetectionId, Excerpt, Finding, Reference, Severity, Version,
};
use crate::model::tls::TlsSupport;
use std::time::{Duration, SystemTime};

/// Information about transport security (TLS/SSL) successfully negotiated on a port.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Security {
    /// The TLS version negotiated, such as `"TLSv1.3"`.
    ///
    /// Shared rather than owned: a scan of any size negotiates the same two or
    /// three versions and the same handful of cipher suites across every TLS
    /// port it touches.
    tls_version: Option<Arc<str>>,

    /// The cipher suite the server selected, such as
    /// `"TLS_AES_256_GCM_SHA384"`.
    cipher_suite: Option<Arc<str>>,

    /// The protocols agreed over ALPN, such as `["h2"]`.
    alpn: Vec<Arc<str>>,

    /// Public key information and lifecycle summaries for the presented X.509 certificate.
    certificate: Option<CertificateInfo>,

    /// What the endpoint turned out to *accept*, where a scan asked.
    ///
    /// A different fact from every field above it, and the reason the two sit
    /// together: those record what one handshake negotiated, and this records
    /// what the endpoint would negotiate given the choice. A port reporting
    /// `TLSv1.3` above and TLS 1.0 here is not a contradiction; it is a server
    /// that prefers the modern version and still accepts the withdrawn one,
    /// which is the configuration an audit is looking for.
    ///
    /// Empty for every scan that did not ask. See
    /// [`ZondConfig::tls_enumeration`](crate::config::ZondConfig::tls_enumeration).
    support: TlsSupport,
}

impl Security {
    /// Creates a new, empty security record.
    pub fn new() -> Self {
        Self {
            tls_version: None,
            cipher_suite: None,
            alpn: Vec::new(),
            certificate: None,
            support: TlsSupport::new(),
        }
    }

    /// What the endpoint accepts, where a scan enumerated it. Empty otherwise.
    pub fn support(&self) -> &TlsSupport {
        &self.support
    }

    /// Records what an enumeration established the endpoint accepts.
    pub fn set_support(&mut self, support: TlsSupport) {
        self.support = support;
    }

    /// Builder form of [`set_support`](Self::set_support).
    pub fn with_support(mut self, support: TlsSupport) -> Self {
        self.support = support;
        self
    }

    /// Returns the negotiated TLS version, if any.
    pub fn tls_version(&self) -> Option<&str> {
        self.tls_version.as_deref()
    }

    /// Returns the negotiated cipher suite, if any.
    pub fn cipher_suite(&self) -> Option<&str> {
        self.cipher_suite.as_deref()
    }

    /// Returns the negotiated ALPN protocols.
    pub fn alpn(&self) -> &[Arc<str>] {
        &self.alpn
    }

    /// Returns the certificate information, if available.
    pub fn certificate(&self) -> Option<&CertificateInfo> {
        self.certificate.as_ref()
    }

    /// Builder method to set the negotiated TLS version.
    pub fn with_tls_version(mut self, version: impl Into<Arc<str>>) -> Self {
        self.tls_version = Some(version.into());
        self
    }

    /// Builder method to set the negotiated cipher suite.
    pub fn with_cipher_suite(mut self, cipher: impl Into<Arc<str>>) -> Self {
        self.cipher_suite = Some(cipher.into());
        self
    }

    /// Records an ALPN protocol, if it is not already recorded.
    ///
    /// Takes `&mut self`, so a record already attached to a port can be added
    /// to; [`with_alpn`](Self::with_alpn) is the builder form.
    pub fn add_alpn(&mut self, protocol: impl Into<Arc<str>>) {
        let protocol = protocol.into();
        if !self.alpn.contains(&protocol) {
            self.alpn.push(protocol);
        }
    }

    /// Builder form of [`add_alpn`](Self::add_alpn).
    pub fn with_alpn(mut self, protocol: impl Into<Arc<str>>) -> Self {
        self.add_alpn(protocol);
        self
    }

    /// Builder method to attach parsed certificate information.
    pub fn with_certificate(mut self, cert: CertificateInfo) -> Self {
        self.certificate = Some(cert);
        self
    }

    /// Folds another handshake's account of this endpoint into this one.
    ///
    /// Every field fills a gap and displaces nothing: the version, the cipher
    /// suite and the certificate are kept where they are already recorded, and
    /// the ALPN lists union without repeating. That is the module's rule that a
    /// tie keeps what is on record, applied to a type where there is no
    /// confidence to break the tie with, since a completed handshake is a
    /// completed handshake.
    pub fn merge(&mut self, other: Security) {
        // Destructured rather than reached through `other.…`, so a field added
        // to this struct is a compile error here and not a value that quietly
        // stops being folded. The doc above used to name the version and the
        // cipher suite and not the certificate, which is the field a caller is
        // most likely to be reading the record for.
        let Security {
            tls_version,
            cipher_suite,
            alpn,
            certificate,
            support,
        } = other;

        self.tls_version = self.tls_version.take().or(tls_version);
        self.cipher_suite = self.cipher_suite.take().or(cipher_suite);
        self.certificate = self.certificate.take().or(certificate);

        // Filled where nothing is recorded, and left alone where something is.
        // Two enumerations of one endpoint answer the same question, so the
        // second says nothing the first did not; a partial one folded over a
        // complete one would lose what the complete one found.
        if self.support.is_empty() {
            self.support = support;
        }

        for protocol in alpn {
            if !self.alpn.contains(&protocol) {
                self.alpn.push(protocol);
            }
        }
    }

    /// Whether the certificate is valid *now*, by this machine's clock.
    ///
    /// For a caller acting on a live scan. Anything reading a scan back
    /// afterwards wants [`is_cert_valid_at`](Self::is_cert_valid_at) with the
    /// time the scan ran, or the same report answers differently every time it
    /// is opened.
    pub fn is_cert_valid(&self) -> bool {
        self.is_cert_valid_at(SystemTime::now())
    }

    /// Whether the certificate is valid at `target_time`.
    ///
    /// `false` for a certificate that is expired, not yet valid, or absent. The
    /// three are different, and a caller that needs to tell them apart reads
    /// [`certificate`](Self::certificate) directly.
    pub fn is_cert_valid_at(&self, target_time: SystemTime) -> bool {
        self.certificate
            .as_ref()
            .is_some_and(|c| target_time >= c.validity_start() && target_time <= c.validity_end())
    }

    /// Returns `true` if the certificate is currently valid, but expires within the given threshold.
    ///
    /// A certificate that has *already* expired is not expiring: it is a
    /// different problem, reported by [`is_cert_valid`](Self::is_cert_valid),
    /// and folding the two together would bury an outage in a renewal queue.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{Duration, SystemTime};
    /// use zond_engine::model::port::{CertificateInfo, Security};
    ///
    /// let thirty_days = Duration::from_secs(86_400 * 30);
    /// let ten_days = Duration::from_secs(86_400 * 10);
    ///
    /// let security = Security::new().with_certificate(CertificateInfo::new(
    ///     "test.local",
    ///     "Local CA",
    ///     SystemTime::now() - thirty_days,
    ///     SystemTime::now() + ten_days,
    ///     "deadbeef",
    /// ));
    ///
    /// assert!(security.is_cert_valid());
    /// assert!(security.is_cert_expiring(thirty_days), "it has ten days left");
    /// assert!(!security.is_cert_expiring(Duration::from_secs(86_400 * 5)));
    /// ```
    pub fn is_cert_expiring(&self, threshold: Duration) -> bool {
        self.is_cert_expiring_at(threshold, SystemTime::now())
    }

    /// Whether the certificate is valid at `at` and expires within `threshold`
    /// of it.
    ///
    /// The counterpart of [`is_cert_valid_at`](Self::is_cert_valid_at), and the
    /// one to use on a stored scan. "Expires within thirty days" is a question
    /// about a moment, and the moment a report is *read* is not the moment it
    /// was taken: asked with the current time, a scan from last quarter reports
    /// a renewal queue that was never true of the network it describes.
    /// A `threshold` no clock can reach reads as one that covers everything, and
    /// never as a panic. `SystemTime + Duration` is checked because the threshold
    /// arrives from a caller and [`DiffOptions::with_expiry_threshold`] takes any
    /// `Duration` there is. A horizon past the end of representable time is a
    /// caller saying every certificate is on the queue, which is an answer rather
    /// than an error.
    ///
    /// [`DiffOptions::with_expiry_threshold`]: crate::diff::DiffOptions::with_expiry_threshold
    pub fn is_cert_expiring_at(&self, threshold: Duration, at: SystemTime) -> bool {
        self.certificate.as_ref().is_some_and(|c| {
            // An already-expired certificate is not expiring; see above.
            if at < c.validity_start() || at > c.validity_end() {
                return false;
            }
            match at.checked_add(threshold) {
                Some(horizon) => c.validity_end() < horizon,
                None => true,
            }
        })
    }
}

impl Default for Security {
    fn default() -> Self {
        Self::new()
    }
}

/// The most Subject Alternative Names one certificate will have recorded
/// against it.
///
/// A bound on what a single target can make this process allocate. The names
/// come out of a certificate the scanned host presented, so their number is the
/// host's to choose, and the only thing standing between this and an
/// unbounded list was whatever the TLS layer admits as a handshake message,
/// which is not a bound this crate states. A `Security` is held per port and a
/// port per host.
///
/// A hundred is past what a real certificate carries. A wildcard covers a domain
/// in one name, and the shared-hosting certificates that do enumerate carry tens
/// rather than hundreds; past that the list has stopped describing what the
/// endpoint is for. The same argument [`MAX_CPES_PER_SERVICE`] makes, about the
/// other thing on a port that a target writes.
///
/// Over-length lists are truncated rather than refused, as an
/// [`Excerpt`] is: the names are evidence, and
/// dropping a certificate because it carried too many would lose the whole
/// finding over the part of it that ran long.
///
/// [`MAX_CPES_PER_SERVICE`]: crate::model::port::service::MAX_CPES_PER_SERVICE
pub const MAX_SANS_PER_CERTIFICATE: usize = 100;

/// A parsed summary of a service's X.509 security certificate.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    /// The Common Name of the certificate subject.
    common_name: Arc<str>,

    /// Every other name the certificate claims, from its Subject Alternative
    /// Name extension.
    sans: Vec<Arc<str>>,

    /// The Common Name of the issuing authority.
    ///
    /// Shared rather than owned, because an estate's certificates come from a
    /// handful of issuers and most of them from one internal CA.
    issuer: Arc<str>,

    /// The timestamp when the certificate becomes valid.
    validity_start: SystemTime,

    /// The timestamp when the certificate expires.
    validity_end: SystemTime,

    /// The public key algorithm, such as `"RSA"` or `"EC"`.
    pubkey_type: Arc<str>,

    /// The size of the public key in bits (e.g., 2048, 4096, 256).
    pubkey_bits: u32,

    /// The SHA-256 fingerprint of the raw DER, lowercase hex.
    fingerprint_sha256: Arc<str>,
}

impl CertificateInfo {
    /// Creates a certificate record from what identifies it: who it is for,
    /// who issued it, the window it is valid in, and its fingerprint.
    ///
    /// The names it also claims and the key it carries are attached with
    /// [`with_sans`](Self::with_sans) and
    /// [`with_public_key`](Self::with_public_key). Splitting them off keeps the
    /// required arguments few enough to read at a call site, where eight
    /// positional ones included two adjacent `SystemTime`s that could be
    /// swapped without any diagnostic.
    pub fn new(
        common_name: impl Into<Arc<str>>,
        issuer: impl Into<Arc<str>>,
        validity_start: SystemTime,
        validity_end: SystemTime,
        fingerprint_sha256: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            common_name: common_name.into(),
            sans: Vec::new(),
            issuer: issuer.into(),
            validity_start,
            validity_end,
            pubkey_type: Arc::from("unknown"),
            pubkey_bits: 0,
            fingerprint_sha256: fingerprint_sha256.into(),
        }
    }

    /// Attaches the other names the certificate claims, up to
    /// [`MAX_SANS_PER_CERTIFICATE`].
    ///
    /// Truncated rather than refused, for the reason the bound gives.
    pub fn with_sans(mut self, sans: impl IntoIterator<Item = Arc<str>>) -> Self {
        self.sans = sans.into_iter().take(MAX_SANS_PER_CERTIFICATE).collect();
        self
    }

    /// Builder method to attach the public key's algorithm and size in bits.
    ///
    /// Both together, because neither is worth much alone: `2048` means nothing
    /// without knowing it is RSA, and a size of zero is how an unparseable key
    /// is reported.
    pub fn with_public_key(mut self, kind: impl Into<Arc<str>>, bits: u32) -> Self {
        self.pubkey_type = kind.into();
        self.pubkey_bits = bits;
        self
    }

    /// Returns the Common Name (CN) of the certificate.
    pub fn common_name(&self) -> &str {
        &self.common_name
    }

    /// Returns the Subject Alternative Names (SANs).
    pub fn sans(&self) -> &[Arc<str>] {
        &self.sans
    }

    /// Returns the issuer of the certificate.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the start time of the certificate's validity.
    pub fn validity_start(&self) -> SystemTime {
        self.validity_start
    }

    /// Returns the expiration time of the certificate.
    pub fn validity_end(&self) -> SystemTime {
        self.validity_end
    }

    /// Returns the public key type (e.g., "RSA").
    pub fn pubkey_type(&self) -> &str {
        &self.pubkey_type
    }

    /// Returns the size of the public key in bits.
    pub fn pubkey_bits(&self) -> u32 {
        self.pubkey_bits
    }

    /// Returns the SHA-256 fingerprint of the certificate.
    pub fn fingerprint_sha256(&self) -> &str {
        &self.fingerprint_sha256
    }

    /// What is wrong with this certificate's own posture at `at`, one finding per
    /// problem, derived from what the handshake already produced: no probe of its
    /// own.
    ///
    /// Three checks the parsed fields settle on their own: a certificate past its
    /// validity window (CWE-324); one whose issuer names its own subject, a
    /// heuristic on the common names and so a `Probable` self-signed rather than a
    /// certain one (CWE-295); and an RSA key below the 2048-bit floor, gated on the
    /// key type so an elliptic-curve key is not judged against an RSA floor
    /// (CWE-326).
    ///
    /// Two neighbouring checks are deliberately absent. Hostname match is not one:
    /// the scan reaches the endpoint by address with no SNI, so there is no name it
    /// asked the certificate to present and nothing to hold its names against. Nor
    /// is the signature algorithm, which is not among the fields parsed here. A
    /// not-yet-valid certificate is left alone too: a scanner clock running ahead
    /// is the likelier cause, and flagging it would cry wolf.
    pub fn findings(&self, at: SystemTime) -> Vec<Finding> {
        let mut findings = Vec::new();
        let id = certificate_detection_id();

        if at > self.validity_end
            && let Ok(finding) = Finding::new(
                id.clone(),
                "TLS certificate has expired",
                Severity::Medium,
                Confidence::Certain,
                DetectionClass::Passive,
            )
        {
            findings.push(
                finding
                    .with_excerpt(Excerpt::new(format!(
                        "the certificate for {} is past its validity window",
                        self.common_name
                    )))
                    .with_reference(Reference::Cwe(324)),
            );
        }
        if !self.common_name.is_empty()
            && self.issuer.eq_ignore_ascii_case(self.common_name.as_ref())
            && let Ok(finding) = Finding::new(
                id.clone(),
                "TLS certificate is self-signed",
                Severity::Low,
                Confidence::Probable,
                DetectionClass::Passive,
            )
        {
            findings.push(
                finding
                    .with_excerpt(Excerpt::new(format!(
                        "issuer and subject are both {}",
                        self.common_name
                    )))
                    .with_reference(Reference::Cwe(295)),
            );
        }
        if self.pubkey_type.eq_ignore_ascii_case("RSA")
            && self.pubkey_bits < 2048
            && let Ok(finding) = Finding::new(
                id,
                "TLS certificate uses a weak RSA key",
                Severity::Medium,
                Confidence::Certain,
                DetectionClass::Passive,
            )
        {
            findings.push(
                finding
                    .with_excerpt(Excerpt::new(format!(
                        "the RSA public key is {} bits, below the 2048-bit floor",
                        self.pubkey_bits
                    )))
                    .with_reference(Reference::Cwe(326)),
            );
        }

        findings
    }
}

/// The identity the certificate-posture findings are stamped with.
///
/// A built-in derivation like the TLS-suite one, so its content hash is taken
/// over the checks it runs rather than a dataset: changing the set moves the hash,
/// and two reports drawn by different rules can be told apart.
fn certificate_detection_id() -> DetectionId {
    static ID: OnceLock<DetectionId> = OnceLock::new();
    ID.get_or_init(|| {
        let version = env!("CARGO_PKG_VERSION")
            .parse::<Version>()
            .unwrap_or_else(|_| Version::new(0, 0, 0));
        let census = "expired;self-signed;weak-rsa-key";
        let digest = ring::digest::digest(&ring::digest::SHA256, census.as_bytes());
        let mut hash = String::with_capacity(digest.as_ref().len() * 2);
        for byte in digest.as_ref() {
            use std::fmt::Write;
            let _ = write!(hash, "{byte:02x}");
        }
        DetectionId::new("zond:certificate", version, hash)
            .expect("the identifier is a non-empty literal")
    })
    .clone()
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

    /// The names on a certificate are the scanned host's to choose, so the list
    /// needs a bound this crate decides.
    ///
    /// It had none. `subject_alt_names` collects every DNS and IP name in the
    /// extension and hands the vector straight here, so the only ceiling was
    /// whatever the TLS layer admits as a handshake message, which is not
    /// something this crate states. A `Security` is held per port and a port per
    /// host.
    ///
    /// Truncated rather than refused, so a certificate is not lost over the part
    /// of it that ran long.
    #[test]
    fn a_certificates_names_are_held_to_the_bound() {
        let many: Vec<Arc<str>> = (0..MAX_SANS_PER_CERTIFICATE * 3)
            .map(|i| Arc::from(format!("n{i}.example").as_str()))
            .collect();

        let cert = CertificateInfo::new(
            "host.example",
            "Internal CA",
            SystemTime::now(),
            SystemTime::now(),
            "deadbeef",
        )
        .with_sans(many);

        assert_eq!(cert.sans().len(), MAX_SANS_PER_CERTIFICATE);
        assert_eq!(
            cert.common_name(),
            "host.example",
            "the certificate survives its own name list"
        );
        assert_eq!(
            cert.sans()[0].as_ref(),
            "n0.example",
            "the first names kept"
        );
    }

    fn mock_cert(start_offset: i64, end_offset: i64) -> CertificateInfo {
        let now = SystemTime::now();

        let start = if start_offset < 0 {
            now - Duration::from_secs(start_offset.unsigned_abs())
        } else {
            now + Duration::from_secs(start_offset as u64)
        };

        let end = if end_offset < 0 {
            now - Duration::from_secs(end_offset.unsigned_abs())
        } else {
            now + Duration::from_secs(end_offset as u64)
        };

        CertificateInfo::new("test.local", "Local CA", start, end, "deadbeef")
            .with_sans([Arc::from("*.test.local")])
            .with_public_key("RSA", 2048)
    }

    /// ALPN is a list where the rest are single values, and it deduplicates on
    /// the way in, since a server offering the same protocol twice is offering
    /// one protocol.
    #[test]
    fn a_record_carries_what_the_handshake_agreed() {
        let sec = Security::new()
            .with_tls_version("TLSv1.3")
            .with_cipher_suite("TLS_AES_256_GCM_SHA384")
            .with_alpn("h2")
            .with_alpn("http/1.1");

        assert_eq!(sec.tls_version(), Some("TLSv1.3"));
        assert_eq!(sec.cipher_suite(), Some("TLS_AES_256_GCM_SHA384"));
        assert_eq!(sec.alpn().len(), 2);
    }

    /// Two probes of one endpoint may each have completed a different part of
    /// the handshake. A merge fills what is missing and keeps what is held,
    /// which is the rule every merge in this module follows.
    #[test]
    fn a_merge_fills_the_gaps_without_displacing_what_is_recorded() {
        let mut s1 = Security::new()
            .with_tls_version("TLSv1.2")
            .with_alpn("http/1.1");

        let s2 = Security::new()
            .with_cipher_suite("AES128-GCM")
            .with_alpn("h2")
            .with_alpn("http/1.1"); // Should be deduplicated

        s1.merge(s2);

        assert_eq!(s1.tls_version(), Some("TLSv1.2"));
        assert_eq!(s1.cipher_suite(), Some("AES128-GCM"));
        assert_eq!(s1.alpn().len(), 2);
        assert!(s1.alpn().iter().any(|p| &**p == "h2"));
    }

    /// Both questions have to be answerable against the time the scan ran, or a
    /// stored report answers differently every time it is opened. Expiry is the
    /// one that was missing: only the wall-clock form existed, so a report from
    /// last quarter described a renewal queue that was never true of the
    /// network it recorded.
    #[test]
    fn validity_and_expiry_are_both_answerable_at_a_caller_chosen_time() {
        let day = Duration::from_secs(86_400);
        let scanned_at = SystemTime::UNIX_EPOCH + day * 365;

        let security = Security::new().with_certificate(CertificateInfo::new(
            "test.local",
            "Local CA",
            scanned_at - day * 30,
            scanned_at + day * 10,
            "deadbeef",
        ));

        assert!(security.is_cert_valid_at(scanned_at));
        assert!(
            security.is_cert_expiring_at(day * 30, scanned_at),
            "ten days left"
        );
        assert!(!security.is_cert_expiring_at(day * 5, scanned_at));

        // Read a year later, the same record says the certificate had already
        // expired, and an expired certificate is not an expiring one.
        let read_at = scanned_at + day * 365;
        assert!(!security.is_cert_valid_at(read_at));
        assert!(!security.is_cert_expiring_at(day * 30, read_at));
    }

    /// The three states a certificate can be in against the current clock, and
    /// the distinction that matters most: an already-expired certificate is not
    /// an expiring one. Folding the two together buries an outage in a renewal
    /// queue.
    #[test]
    fn an_expired_certificate_is_not_reported_as_one_about_to_expire() {
        // Valid from 10 days ago until 10 days from now
        let valid_cert = mock_cert(-864000, 864000);
        let sec_valid = Security::new().with_certificate(valid_cert);

        assert!(sec_valid.is_cert_valid());
        // Threshold check: Does it expire in the next 5 days? No.
        assert!(!sec_valid.is_cert_expiring(Duration::from_secs(86400 * 5)));
        // Threshold check: Does it expire in the next 15 days? Yes.
        assert!(sec_valid.is_cert_expiring(Duration::from_secs(86400 * 15)));

        // Expired 5 days ago
        let expired_cert = mock_cert(-864000, -432000);
        let sec_expired = Security::new().with_certificate(expired_cert);

        assert!(!sec_expired.is_cert_valid());
        // An already expired cert shouldn't trigger "expiring soon" alerts
        assert!(!sec_expired.is_cert_expiring(Duration::from_secs(86400 * 30)));

        // Not yet valid (starts tomorrow)
        let future_cert = mock_cert(86400, 864000);
        let sec_future = Security::new().with_certificate(future_cert);

        assert!(!sec_future.is_cert_valid());
    }

    #[test]
    fn a_clean_certificate_has_no_posture_findings() {
        let now = SystemTime::now();
        let cert = CertificateInfo::new(
            "web.example",
            "Example Root CA",
            now - Duration::from_secs(86_400 * 30),
            now + Duration::from_secs(86_400 * 300),
            "deadbeef",
        )
        .with_public_key("RSA", 2048);
        assert!(cert.findings(now).is_empty());
    }

    #[test]
    fn certificate_posture_reports_expiry_self_signing_and_a_weak_key() {
        let now = SystemTime::now();
        let id = "zond:certificate";

        let expired = CertificateInfo::new(
            "web.example",
            "Example Root CA",
            now - Duration::from_secs(86_400 * 400),
            now - Duration::from_secs(86_400 * 30),
            "aa",
        )
        .with_public_key("RSA", 2048);
        let findings = expired.findings(now);
        assert_eq!(findings.len(), 1, "expired alone");
        assert_eq!(findings[0].detection().id(), id);
        assert_eq!(findings[0].severity(), Severity::Medium);
        assert!(findings[0].title().contains("expired"));

        let self_signed = CertificateInfo::new(
            "box.local",
            "box.local",
            now - Duration::from_secs(86_400 * 30),
            now + Duration::from_secs(86_400 * 300),
            "bb",
        )
        .with_public_key("RSA", 2048);
        let findings = self_signed.findings(now);
        assert_eq!(findings.len(), 1, "self-signed alone");
        assert_eq!(findings[0].severity(), Severity::Low);
        assert!(findings[0].title().contains("self-signed"));

        let weak = CertificateInfo::new(
            "legacy.example",
            "Example Root CA",
            now - Duration::from_secs(86_400 * 30),
            now + Duration::from_secs(86_400 * 300),
            "cc",
        )
        .with_public_key("RSA", 1024);
        let findings = weak.findings(now);
        assert_eq!(findings.len(), 1, "weak key alone");
        assert_eq!(findings[0].severity(), Severity::Medium);
        assert!(findings[0].title().contains("weak RSA key"));
    }

    #[test]
    fn a_256_bit_elliptic_curve_key_is_not_read_as_weak() {
        let now = SystemTime::now();
        let cert = CertificateInfo::new(
            "ec.example",
            "Example Root CA",
            now - Duration::from_secs(86_400 * 30),
            now + Duration::from_secs(86_400 * 300),
            "dd",
        )
        .with_public_key("EC", 256);
        assert!(cert.findings(now).is_empty());
    }
}
