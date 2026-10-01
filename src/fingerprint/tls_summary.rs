// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The record a TLS handshake leaves behind
//!
//! Turns a completed handshake ([`TlsInfo`]) into the [`Security`] a port
//! carries in the report.
//!
//! [`TlsCertAnalyzer`](super::tls_cert::TlsCertAnalyzer) reads the same
//! certificate to decide what the service is, as `Evidence` competing with other
//! analyzers. This module records what the handshake established, which nothing
//! competes with, so the certificate is reported whichever service name wins.
//!
//! ## What is kept
//!
//! A summary of the leaf (see [`security`](crate::model::port::security)): who
//! the certificate claims to be, who issued it, its validity window, and a
//! fingerprint to compare sightings by.
//!
//! Nothing here is a trust decision. The handshake accepts any certificate so
//! that expired, self-signed and wrong-host ones are seen. Validity is recorded
//! as two instants for the reader to compare.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use super::response::TlsInfo;
use crate::model::port::{CertificateInfo, Security};

/// The security record for a port that completed a handshake.
///
/// Produced for every handshake, even if the certificate is missing or
/// unparseable, since the negotiated version and cipher stand on their own.
pub fn security(tls: &TlsInfo) -> Security {
    let mut record = Security::new();

    if let Some(version) = tls.version {
        record = record.with_tls_version(version);
    }
    if let Some(cipher) = tls.cipher_suite {
        record = record.with_cipher_suite(cipher);
    }
    if let Some(alpn) = &tls.alpn {
        record = record.with_alpn(alpn.as_str());
    }
    if let Some(certificate) = tls.leaf().and_then(certificate_info) {
        record = record.with_certificate(certificate);
    }

    record
}

/// Summarizes a leaf certificate, or `None` if the DER does not parse.
///
/// A scanner meets truncated and malformed chains routinely, so a parse failure
/// is not an error; the rest of the record still stands.
fn certificate_info(der: &[u8]) -> Option<CertificateInfo> {
    let (_, cert) = parse_x509_certificate(der).ok()?;

    let validity = cert.validity();
    let (pubkey_type, pubkey_bits) = public_key_summary(&cert);

    Some(
        CertificateInfo::new(
            first_common_name(cert.subject()).unwrap_or_default(),
            first_common_name(cert.issuer()).unwrap_or_default(),
            asn1_to_system_time(validity.not_before),
            asn1_to_system_time(validity.not_after),
            fingerprint_sha256(der),
        )
        .with_sans(subject_alt_names(&cert))
        .with_public_key(pubkey_type, pubkey_bits),
    )
}

/// The first `CN=` in a distinguished name.
///
/// The first is the one other tools print. Non-UTF-8 attributes are skipped,
/// since a lossily rendered name would not compare equal across scans.
fn first_common_name(name: &X509Name<'_>) -> Option<Arc<str>> {
    name.iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(Arc::from)
}

/// Every name the certificate claims, from its Subject Alternative Name
/// extension.
///
/// DNS names and IP addresses, rendered as a certificate viewer writes them
/// (`DNS:...`, `IP:10.0.0.5`). An absent extension yields an empty list.
fn subject_alt_names(cert: &X509Certificate<'_>) -> Vec<Arc<str>> {
    let Ok(Some(extension)) = cert.subject_alternative_name() else {
        return Vec::new();
    };

    extension
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some(Arc::from(*dns)),
            GeneralName::IPAddress(bytes) => render_ip_san(bytes),
            _ => None,
        })
        .collect()
}

/// An `IPAddress` SAN, which is stored as raw octets: four for IPv4, sixteen for
/// IPv6. Any other length is a malformed extension and is dropped.
fn render_ip_san(bytes: &[u8]) -> Option<Arc<str>> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes.try_into().ok()?;
            Some(Arc::from(std::net::Ipv4Addr::from(octets).to_string()))
        }
        16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(Arc::from(std::net::Ipv6Addr::from(octets).to_string()))
        }
        _ => None,
    }
}

/// The public key's algorithm and size in bits.
///
/// For an elliptic curve the size is the field size, as other tools report
/// P-256 as 256 bits.
///
/// A key that cannot be parsed is reported as `unknown` with zero bits, a size
/// no real key has.
fn public_key_summary(cert: &X509Certificate<'_>) -> (&'static str, u32) {
    let Ok(key) = cert.public_key().parsed() else {
        return ("unknown", 0);
    };

    let algorithm = match key {
        PublicKey::RSA(_) => "RSA",
        PublicKey::EC(_) => "EC",
        PublicKey::DSA(_) => "DSA",
        PublicKey::GostR3410(_) | PublicKey::GostR3410_2012(_) => "GOST",
        PublicKey::Unknown(_) => "unknown",
    };

    (algorithm, key.key_size() as u32)
}

/// The SHA-256 of the raw DER, lowercase hex.
///
/// Over the certificate as it arrived, so it matches
/// `openssl x509 -fingerprint -sha256` without the colons.
fn fingerprint_sha256(der: &[u8]) -> Arc<str> {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut hex = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    Arc::from(hex)
}

/// An ASN.1 time as a [`SystemTime`].
///
/// A timestamp before the Unix epoch is clamped to the epoch.
fn asn1_to_system_time(time: ASN1Time) -> SystemTime {
    let seconds = time.timestamp();
    if seconds < 0 {
        SystemTime::UNIX_EPOCH
    } else {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds as u64)
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

    /// A self-signed RSA-2048 appliance certificate: `CN=zond-device.local`,
    /// two DNS SANs and an IP SAN, valid 2026-07-27 to 2036-07-24.
    const SELF_SIGNED: &[u8] = include_bytes!("testdata/selfsigned.der");

    fn info() -> CertificateInfo {
        certificate_info(SELF_SIGNED).expect("the fixture parses")
    }

    /// `openssl x509 -fingerprint -sha256` on the fixture, colons removed.
    #[test]
    fn the_fingerprint_is_the_one_openssl_computes() {
        assert_eq!(
            info().fingerprint_sha256(),
            "5c8125bb969ab3388da2ab86ce9799828922bdb2c489d33861bc96e47033b3ae"
        );
    }

    #[test]
    fn the_subject_issuer_and_key_are_read_off_the_certificate() {
        let cert = info();

        assert_eq!(cert.common_name(), "zond-device.local");
        assert_eq!(cert.issuer(), "zond-device.local", "self-signed");
        assert_eq!(cert.pubkey_type(), "RSA");
        assert_eq!(cert.pubkey_bits(), 2048);
    }

    /// DNS and IP SANs both.
    #[test]
    fn every_name_the_certificate_claims_is_recorded() {
        let cert = info();
        let names = cert.sans();

        let names: Vec<&str> = names.iter().map(|name| &**name).collect();
        assert!(names.contains(&"zond-device.local"));
        assert!(names.contains(&"appliance.zond.internal"));
        assert!(names.contains(&"10.0.0.5"), "the IP SAN too");
    }

    /// Validity is two absolute instants.
    #[test]
    fn validity_is_recorded_as_the_window_the_certificate_names() {
        let cert = info();

        // 2026-07-27T20:56:01Z and 2036-07-24T20:56:01Z.
        let not_before = SystemTime::UNIX_EPOCH + Duration::from_secs(1_785_185_761);
        let not_after = SystemTime::UNIX_EPOCH + Duration::from_secs(2_100_545_761);

        assert_eq!(cert.validity_start(), not_before);
        assert_eq!(cert.validity_end(), not_after);
    }

    /// A handshake with no readable certificate still records the version.
    #[test]
    fn a_handshake_without_a_usable_certificate_still_records_what_was_negotiated() {
        let tls = TlsInfo {
            certificates: vec![b"not a certificate".to_vec()],
            version: Some("TLSv1.3"),
            cipher_suite: Some("TLS13_AES_256_GCM_SHA384"),
            alpn: Some("h2".to_string()),
        };

        let record = security(&tls);

        assert_eq!(record.tls_version(), Some("TLSv1.3"));
        assert_eq!(record.cipher_suite(), Some("TLS13_AES_256_GCM_SHA384"));
        assert_eq!(record.alpn(), [Arc::<str>::from("h2")]);
        assert!(
            record.certificate().is_none(),
            "unparseable is absent, not fabricated"
        );
    }

    #[test]
    fn a_complete_handshake_records_both_halves() {
        let tls = TlsInfo {
            certificates: vec![SELF_SIGNED.to_vec()],
            version: Some("TLSv1.2"),
            cipher_suite: Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            alpn: None,
        };

        let record = security(&tls);

        assert_eq!(record.tls_version(), Some("TLSv1.2"));
        assert!(record.alpn().is_empty(), "the server chose no protocol");
        assert_eq!(
            record.certificate().expect("parsed").common_name(),
            "zond-device.local"
        );
    }
}
