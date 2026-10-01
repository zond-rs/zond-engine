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
//! The certificate is summarized: a chain is kilobytes and a report may hold thousands,
//! so the name, issuer, validity and fingerprint are kept and the DER is not. A caller
//! needing the chain re-fetches it.
//!
//! Validity is checked against a time the caller supplies; see
//! [`Security::is_cert_valid_at`]. A report is read long after the scan, and the current
//! time would relabel it on every opening.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use crate::model::confidence::Confidence;
use crate::model::finding::{
    DetectionClass, DetectionId, Excerpt, Finding, Reference, Severity, Standing, Version,
};
use crate::model::tls::TlsSupport;
use std::time::{Duration, SystemTime};

/// Information about transport security (TLS/SSL) successfully negotiated on a port.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Security {
    /// The TLS version negotiated, such as `"TLSv1.3"`.
    ///
    /// Shared, since a scan sees the same few versions and suites everywhere.
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
    /// The fields above record what one handshake negotiated; this records what the
    /// endpoint would negotiate. `TLSv1.3` above with TLS 1.0 here is a server that
    /// prefers the modern version and still accepts the withdrawn one.
    ///
    /// Empty unless a scan asked. See
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
    /// [`with_alpn`](Self::with_alpn) is the builder form.
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
    /// The version, cipher suite and certificate only fill gaps, and ALPN lists union.
    ///
    /// What the endpoint [accepts](Self::support) folds version by version, as
    /// `TlsSupport`'s merge describes: the account on record stands unless the other is
    /// more complete and found every suite this one did.
    pub fn merge(&mut self, other: Security) {
        // Destructured, so a new field fails to compile until it is merged.
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

        self.support.merge(support);

        for protocol in alpn {
            if !self.alpn.contains(&protocol) {
                self.alpn.push(protocol);
            }
        }
    }

    /// Where this record leaves a finding drawn from `basis`, another
    /// account of the same endpoint, or `None` where the finding is not one
    /// drawn from evidence a record like this holds.
    ///
    /// Two derivations draw from it. For what the endpoint accepts, see
    /// [`TlsSupport::standing`]. A certificate-posture claim rests on the certificate
    /// as a whole (lapsed, self-issued, short key, or not naming the host asked for,
    /// which does not change between sittings), so the record upholds it while it holds
    /// the same certificate and overturns it once it holds another. A certificate with
    /// no fingerprint cannot be compared, so a claim resting on it has no standing.
    ///
    /// A record with no comparable certificate leaves the claim unsettled: a failed
    /// handshake or an unparseable leaf records nothing, and must not retire every
    /// posture claim on the endpoint.
    pub(crate) fn standing(&self, finding: &Finding, basis: &Security) -> Option<Standing> {
        if finding.detection().id() == CERTIFICATE_DETECTION {
            fn fingerprint(security: &Security) -> Option<&str> {
                security
                    .certificate
                    .as_ref()
                    .map(CertificateInfo::fingerprint_sha256)
                    .filter(|fingerprint| !fingerprint.is_empty())
            }
            let then = fingerprint(basis)?;
            return Some(match fingerprint(self) {
                Some(now) if now == then => Standing::Upheld,
                Some(_) => Standing::Overturned,
                None => Standing::Unsettled,
            });
        }
        self.support.standing(finding, &basis.support)
    }

    /// The excerpt `finding`, drawn from `basis`, should carry beside this
    /// record, or `None` where the one it was written with already fits.
    ///
    /// Only a claim drawn from what the endpoint accepts can need one; see
    /// [`TlsSupport::restate`]. An upheld posture claim rests on the same certificate,
    /// so its excerpt still fits.
    pub(crate) fn restate(&self, finding: &Finding, basis: &Security) -> Option<Excerpt> {
        if finding.detection().id() == CERTIFICATE_DETECTION {
            return None;
        }
        self.support.restate(finding, &basis.support)
    }

    /// Whether the certificate is valid *now*, by this machine's clock.
    ///
    /// For a live scan. Reading a scan back, use
    /// [`is_cert_valid_at`](Self::is_cert_valid_at) with the time it ran.
    pub fn is_cert_valid(&self) -> bool {
        self.is_cert_valid_at(SystemTime::now())
    }

    /// Whether the certificate is valid at `target_time`.
    ///
    /// `false` for a certificate that is expired, not yet valid, or absent; read
    /// [`certificate`](Self::certificate) to tell which.
    pub fn is_cert_valid_at(&self, target_time: SystemTime) -> bool {
        self.certificate
            .as_ref()
            .is_some_and(|c| target_time >= c.validity_start() && target_time <= c.validity_end())
    }

    /// Returns `true` if the certificate is currently valid, but expires within the given threshold.
    ///
    /// A certificate that has *already* expired is not expiring; that is
    /// [`is_cert_valid`](Self::is_cert_valid)'s concern.
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
    /// The counterpart of [`is_cert_valid_at`](Self::is_cert_valid_at), for a stored
    /// scan.
    ///
    /// A `threshold` past the end of representable time covers everything; it does
    /// not panic, since [`DiffOptions::with_expiry_threshold`] accepts any `Duration`.
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
/// Bounds what a single target can make this process allocate, since the scanned host
/// chooses how many names its certificate carries.
///
/// A hundred is more than a real certificate carries: a wildcard covers a domain in
/// one name, and shared-hosting certificates carry tens. Compare
/// [`MAX_CPES_PER_SERVICE`].
///
/// Over-length lists are truncated, as an [`Excerpt`] is, so the certificate is kept.
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
    /// Shared, since most certificates come from a handful of issuers.
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
    /// Further names and the key are attached with [`with_sans`](Self::with_sans) and
    /// [`with_public_key`](Self::with_public_key).
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
    /// Truncated past the bound.
    pub fn with_sans(mut self, sans: impl IntoIterator<Item = Arc<str>>) -> Self {
        self.sans = sans.into_iter().take(MAX_SANS_PER_CERTIFICATE).collect();
        self
    }

    /// Builder method to attach the public key's algorithm and size in bits.
    ///
    /// Both together, since `2048` means little without the algorithm. A size of zero
    /// reports an unparseable key.
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
    /// problem, derived from the handshake without a probe of its own.
    ///
    /// Three checks: past its validity window (CWE-324); issuer naming its own subject,
    /// a heuristic on common names and so a `Probable` self-signed (CWE-295); and an
    /// RSA key below 2048 bits, checked only for RSA keys (CWE-326).
    ///
    /// The name check is [`name_mismatch`](Self::name_mismatch). The signature
    /// algorithm is not parsed, so not checked. A not-yet-valid certificate is not
    /// flagged, since a scanner clock running ahead is the likelier cause.
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

    /// Whether the certificate names `name` among the identities it claims, by
    /// the rules RFC 9525 section 6.3 gives a client checking a server's.
    ///
    /// A host name is held against the DNS names in the Subject Alternative
    /// Name extension, ignoring ASCII case and a trailing dot. A name there
    /// whose leftmost label is a lone `*` covers any one label in its place and
    /// no more, so `*.example.com` covers `www.example.com` and neither
    /// `example.com` nor `a.b.example.com`. An address is held against the
    /// addresses in the same extension. The subject's common name is not read, as RFC
    /// 9525 requires of clients.
    ///
    /// Only the names kept (up to [`MAX_SANS_PER_CERTIFICATE`]) are read, so a
    /// certificate claiming more may cover a name this says it does not.
    pub fn covers(&self, name: &str) -> bool {
        let name = name.strip_suffix('.').unwrap_or(name);
        if let Ok(address) = name.parse::<IpAddr>() {
            return self
                .sans
                .iter()
                .any(|san| san.parse::<IpAddr>() == Ok(address));
        }
        self.sans
            .iter()
            .filter(|san| san.parse::<IpAddr>().is_err())
            .any(|san| dns_name_covers(san, name))
    }

    /// The finding that this certificate does not answer to `name`, the host
    /// name the handshake that presented it asked for, or `None` where it does.
    ///
    /// Separate from [`findings`](Self::findings) because it depends on the name: a
    /// certificate wrong for one site behind a shared address is right for another.
    /// Ask it only with the server name the handshake sent.
    ///
    /// Also `None` where the certificate claims as many names as this record keeps;
    /// see [`covers`](Self::covers).
    pub fn name_mismatch(&self, name: &str) -> Option<Finding> {
        if self.sans.len() >= MAX_SANS_PER_CERTIFICATE || self.covers(name) {
            return None;
        }
        let bare = name.strip_suffix('.').unwrap_or(name);
        let only_common_name = dns_name_covers(&self.common_name, bare);
        let excerpt = if only_common_name {
            format!("{name} is named only in the subject common name, which clients do not read")
        } else {
            match self.sans.as_slice() {
                [] => format!("asked for {name}; the certificate lists no alternative names"),
                [first, rest @ ..] => {
                    let more = match rest.len() {
                        0 => String::new(),
                        1 => format!(" and {}", rest[0]),
                        n => format!(" and {n} more"),
                    };
                    format!("asked for {name}; the certificate names {first}{more}")
                }
            }
        };
        Finding::new(
            certificate_detection_id(),
            "TLS certificate does not match the host name",
            Severity::Medium,
            Confidence::Certain,
            DetectionClass::Passive,
        )
        .ok()
        .map(|finding| {
            finding
                .with_excerpt(Excerpt::new(excerpt))
                .with_reference(Reference::Cwe(297))
        })
    }
}

/// Whether one DNS name from a certificate covers the host name `name`,
/// ignoring ASCII case and a trailing dot, with a leftmost `*` label standing
/// for exactly one label of `name`; see [`CertificateInfo::covers`].
fn dns_name_covers(pattern: &str, name: &str) -> bool {
    let pattern = pattern.strip_suffix('.').unwrap_or(pattern);
    match pattern.strip_prefix("*.") {
        Some(parent) => name.split_once('.').is_some_and(|(label, rest)| {
            !label.is_empty() && !parent.is_empty() && rest.eq_ignore_ascii_case(parent)
        }),
        None => !pattern.is_empty() && pattern.eq_ignore_ascii_case(name),
    }
}

/// The id every certificate-posture finding is stamped under, which is how
/// one is recognised again once it is on a port.
const CERTIFICATE_DETECTION: &str = "zond:certificate";

/// The identity the certificate-posture findings are stamped with.
///
/// A built-in derivation like the TLS-suite one, so its content hash covers the checks
/// it runs.
fn certificate_detection_id() -> DetectionId {
    static ID: OnceLock<DetectionId> = OnceLock::new();
    ID.get_or_init(|| {
        let version = env!("CARGO_PKG_VERSION")
            .parse::<Version>()
            .unwrap_or_else(|_| Version::new(0, 0, 0));
        let census = "expired;self-signed;weak-rsa-key;name-mismatch";
        let digest = ring::digest::digest(&ring::digest::SHA256, census.as_bytes());
        let mut hash = String::with_capacity(digest.as_ref().len() * 2);
        for byte in digest.as_ref() {
            use std::fmt::Write;
            let _ = write!(hash, "{byte:02x}");
        }
        DetectionId::new(CERTIFICATE_DETECTION, version, hash)
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

    /// The SAN list is bounded and truncated, not refused.
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

    /// ALPN deduplicates on the way in.
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

    /// A merge fills what is missing and keeps what is held.
    #[test]
    fn a_merge_fills_the_gaps_without_displacing_what_is_recorded() {
        let mut s1 = Security::new()
            .with_tls_version("TLSv1.2")
            .with_alpn("http/1.1");

        let s2 = Security::new()
            .with_cipher_suite("AES128-GCM")
            .with_alpn("h2")
            .with_alpn("http/1.1"); // deduplicated

        s1.merge(s2);

        assert_eq!(s1.tls_version(), Some("TLSv1.2"));
        assert_eq!(s1.cipher_suite(), Some("AES128-GCM"));
        assert_eq!(s1.alpn().len(), 2);
        assert!(s1.alpn().iter().any(|p| &**p == "h2"));
    }

    /// Both checks can be asked at the time the scan ran.
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

        // A year later it has expired, which is not expiring.
        let read_at = scanned_at + day * 365;
        assert!(!security.is_cert_valid_at(read_at));
        assert!(!security.is_cert_expiring_at(day * 30, read_at));
    }

    /// Valid, expired and not-yet-valid against the current clock; an expired
    /// certificate is not expiring.
    #[test]
    fn an_expired_certificate_is_not_reported_as_one_about_to_expire() {
        // Valid from 10 days ago until 10 days from now
        let valid_cert = mock_cert(-864000, 864000);
        let sec_valid = Security::new().with_certificate(valid_cert);

        assert!(sec_valid.is_cert_valid());
        // Not within 5 days.
        assert!(!sec_valid.is_cert_expiring(Duration::from_secs(86400 * 5)));
        // Within 15 days.
        assert!(sec_valid.is_cert_expiring(Duration::from_secs(86400 * 15)));

        // Expired 5 days ago
        let expired_cert = mock_cert(-864000, -432000);
        let sec_expired = Security::new().with_certificate(expired_cert);

        assert!(!sec_expired.is_cert_valid());
        // An expired certificate is not expiring.
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

    /// A certificate for `names`, the rest of it clean.
    fn naming(common_name: &str, names: &[&str]) -> CertificateInfo {
        let now = SystemTime::now();
        CertificateInfo::new(
            common_name,
            "Example Root CA",
            now - Duration::from_secs(86_400 * 30),
            now + Duration::from_secs(86_400 * 300),
            "ee",
        )
        .with_sans(names.iter().map(|name| Arc::from(*name)))
        .with_public_key("RSA", 2048)
    }

    /// The names covered are the ones a client connecting by name would accept.
    #[test]
    fn a_certificate_covers_the_names_a_client_would_accept_it_for() {
        let cert = naming("ignored.example", &["www.example.com", "*.api.example.com"]);

        assert!(cert.covers("www.example.com"));
        assert!(cert.covers("WWW.Example.COM."), "case and a trailing dot");
        assert!(cert.covers("v1.api.example.com"), "a wildcard, one label");

        assert!(!cert.covers("example.com"));
        assert!(
            !cert.covers("api.example.com"),
            "a wildcard needs its label"
        );
        assert!(!cert.covers("a.v1.api.example.com"), "and only one");
        assert!(
            !cert.covers("ignored.example"),
            "the common name is not read"
        );

        let addressed = naming("", &["192.0.2.7", "2001:db8::7"]);
        assert!(addressed.covers("192.0.2.7"));
        assert!(addressed.covers("2001:db8:0::7"), "compared as addresses");
        assert!(!addressed.covers("192.0.2.8"));
    }

    /// A certificate not naming the host asked for is a finding, unless it may have
    /// named it past the names kept.
    #[test]
    fn a_certificate_not_naming_the_host_asked_for_is_a_mismatch() {
        let cert = naming("web.example", &["web.example", "www.web.example"]);
        assert!(cert.name_mismatch("web.example").is_none());

        let finding = cert
            .name_mismatch("shop.example")
            .expect("a certificate for another site is a mismatch");
        assert_eq!(finding.detection().id(), "zond:certificate");
        assert_eq!(finding.severity(), Severity::Medium);
        assert!(finding.title().contains("host name"));
        let excerpt = finding.excerpt().as_str();
        assert!(excerpt.contains("shop.example"), "{excerpt}");
        assert!(excerpt.contains("web.example"), "{excerpt}");

        // Named only in the common name, which the excerpt says.
        let legacy = naming("legacy.example", &[]);
        let finding = legacy
            .name_mismatch("legacy.example")
            .expect("a name in the common name alone does not cover it");
        let excerpt = finding.excerpt().as_str();
        assert!(excerpt.contains("common name"), "{excerpt}");

        // At the bound, the covering name may have been dropped.
        let many: Vec<String> = (0..MAX_SANS_PER_CERTIFICATE)
            .map(|i| format!("n{i}.example"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(
            naming("", &many)
                .name_mismatch("elsewhere.example")
                .is_none()
        );
    }
}
