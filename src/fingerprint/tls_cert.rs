// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # TLS certificate analyzer
//!
//! The first non-regex [`Analyzer`]: it turns a captured certificate chain into
//! [`Evidence`], proving out the extension point on a source that is structured
//! binary rather than a text banner.
//!
//! What a certificate reliably says about what a port runs is
//! modest, and this analyzer claims only that much:
//!
//! * **The port speaks TLS**, reported as service `ssl` at [`Probable`]
//!   confidence. That is a real, useful label (far better than a raw handshake
//!   blob) but shallow: it does not name the application protocol inside the
//!   tunnel. A later phase re-probes *through* the tunnel and will override this
//!   with a stronger, more specific verdict.
//! * **A self-signed cert's organization names its operator/vendor.** When the
//!   subject equals the issuer, which is typical of appliances and internal
//!   services, the subject `O=` reliably names who stood the service up, so it is
//!   surfaced as `vendor`. For CA-signed certs `O=` names the CA or the cert
//!   owner, neither of which is the product vendor, so we do not guess.
//! * **A name the corpus recognises identifies the product outright.** Both the
//!   subject and the issuer are rendered and matched against the signature set,
//!   which carries rules for the names appliances present. Those devices are
//!   often reachable on no other identifying port, so the certificate is the
//!   only place they say what they are. See [`distinguished_name`] for why the
//!   rendering is this module's own.
//!
//! Host attribution (subject CN / SAN hostnames) is intentionally *not* produced
//! here: it describes the host, not the service, and has no home on [`Evidence`]
//! yet. It is a separate follow-up.
//!
//! [`Analyzer`]: super::analyzer::Analyzer
//! [`Probable`]: super::model::Confidence::Probable

use async_trait::async_trait;
use x509_parser::objects::oid2abbrev;
use x509_parser::oid_registry::asn1_rs::Oid;
use x509_parser::parse_x509_certificate;
use x509_parser::x509::X509Name;

use super::analyzer::{Analyzer, PortContext};
use super::model::{Evidence, SourceId};
use super::response::{Collected, ResponseSet};
use crate::model::confidence::Confidence;

/// Renders a certificate name the way the signature corpus writes it: RFC 4514,
/// most specific relative name first, joined by a comma with no space after it.
///
/// The rendering matters as much as the parsing, because a corpus rule anchors
/// on the whole string. Measured against the 166 shipped `x509.subject`
/// examples: 160 lead with `CN=`, 126 close with `C=`, and 30 carry an escaped
/// comma inside a value. `X509Name`'s own `Display` agrees with none of that. It
/// walks the sequence in encoding order, separates with `", "`, and escapes
/// nothing, so a rule held against it would match no certificate ever issued.
fn distinguished_name(name: &X509Name<'_>) -> String {
    let registry = x509_parser::objects::oid_registry();

    let mut names: Vec<String> = name
        .iter()
        .map(|rdn| {
            // A multi-valued relative name is one component, and RFC 4514 §2.2
            // joins its parts with `+` rather than promoting them to siblings.
            rdn.iter()
                .map(|attr| {
                    let key = oid2abbrev(attr.attr_type(), registry)
                        .map(str::to_string)
                        .unwrap_or_else(|_| id_string(attr.attr_type()));
                    let value = attr.as_str().map(escape_value).unwrap_or_default();
                    format!("{key}={value}")
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect();

    // The encoding runs general to specific and the string form runs the other
    // way, which is what puts `CN=` first.
    names.reverse();
    names.join(",")
}

/// An attribute type nothing has a short name for, as dotted decimal. Three of
/// the shipped examples end in one.
fn id_string(oid: &Oid<'_>) -> String {
    oid.iter()
        .map(|arcs| {
            arcs.map(|arc| arc.to_string())
                .collect::<Vec<_>>()
                .join(".")
        })
        .unwrap_or_default()
}

/// Escapes one attribute value per RFC 4514 §2.4.
///
/// The characters that would otherwise be read as structure, plus a leading `#`
/// or space and a trailing space, which are positional rather than literal.
fn escape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let last = value.chars().count().saturating_sub(1);

    for (at, ch) in value.chars().enumerate() {
        let positional = (at == 0 && (ch == '#' || ch == ' ')) || (at == last && ch == ' ');
        if positional || matches!(ch, '"' | '+' | ',' | ';' | '<' | '>' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Identifies TLS-bearing ports from the certificate captured during the
/// handshake. See the module docs for what it does and does not claim.
pub struct TlsCertAnalyzer;

#[async_trait]
impl Analyzer for TlsCertAnalyzer {
    fn id(&self) -> SourceId {
        SourceId::TlsCert
    }

    fn interested(&self, _ctx: &PortContext) -> bool {
        // Interest depends on whether a certificate was actually captured, which
        // is a fact about the response, not the port. `analyze` gates on that;
        // when no TLS was collected it does no work and returns nothing.
        true
    }

    // Passive: the certificate was captured by the transport's handshake and
    // lives in the shared `ResponseSet`, so the default `collect` no-op applies.
    fn analyze(
        &self,
        _ctx: &PortContext,
        responses: &ResponseSet,
        _collected: &Collected,
    ) -> Vec<Evidence> {
        let Some(leaf) = responses.tls.as_ref().and_then(|tls| tls.leaf()) else {
            return Vec::new();
        };

        // A completed handshake alone establishes TLS. If the cert fails to
        // parse (truncated/adversarial), we still know the port speaks TLS, so
        // emit the base evidence without vendor detail rather than nothing.
        let mut evidence =
            Evidence::new(SourceId::TlsCert, Confidence::Probable).with_service("ssl");

        if let Ok((_, cert)) = parse_x509_certificate(leaf) {
            let tbs = &cert.tbs_certificate;

            // The corpus has rules written against a certificate name directly,
            // for appliances that identify themselves nowhere else. They match
            // the whole rendered name, so each is offered as its own text.
            let db = super::db::SignatureDb::global();
            let names = [
                distinguished_name(&tbs.subject),
                distinguished_name(&tbs.issuer),
            ];
            let mut found: Vec<Evidence> = names
                .iter()
                .filter_map(|name| db.identify_field(name))
                .collect();

            let self_signed = tbs.subject.as_raw() == tbs.issuer.as_raw();
            if self_signed
                && let Some(org) = tbs
                    .subject
                    .iter_organization()
                    .next()
                    .and_then(|attr| attr.as_str().ok())
            {
                evidence = evidence.with_vendor(org.to_string());
            }

            found.insert(0, evidence);
            return found;
        }

        vec![evidence]
    }
}

#[cfg(test)]
mod names {
    use super::*;

    const CERT: &[u8] = include_bytes!("testdata/selfsigned.der");

    fn fixture() -> x509_parser::certificate::X509Certificate<'static> {
        parse_x509_certificate(CERT).expect("the fixture parses").1
    }

    /// The rendering the corpus is written against, and the one this type's own
    /// `Display` produces, are different strings. A rule held against the second
    /// matches no certificate, which is why the renderer exists.
    #[test]
    fn a_name_renders_the_way_the_corpus_writes_one() {
        let cert = fixture();
        let subject = &cert.tbs_certificate.subject;

        assert_eq!(
            distinguished_name(subject),
            "CN=zond-device.local,O=Zond Appliance,C=SE"
        );
        assert_eq!(
            subject.to_string(),
            "C=SE, O=Zond Appliance, CN=zond-device.local"
        );
    }

    /// Thirty of the shipped subject examples carry one of these, and an
    /// unescaped comma would split one relative name into two.
    #[test]
    fn a_comma_inside_a_value_is_escaped_rather_than_read_as_structure() {
        assert_eq!(escape_value("Cisco-Linksys, LLC"), r"Cisco-Linksys\, LLC");
        assert_eq!(escape_value("VMware, Inc."), r"VMware\, Inc.");
    }

    /// RFC 4514 §2.4. The positional ones are escaped only where they are
    /// positional, so an interior space or hash stays as it was written.
    #[test]
    fn the_remaining_rfc_4514_escapes_are_applied() {
        assert_eq!(escape_value(r"a+b;c<d>e"), r"a\+b\;c\<d\>e");
        assert_eq!(escape_value(r#"quo"te"#), r#"quo\"te"#);
        assert_eq!(escape_value(r"back\slash"), r"back\\slash");
        assert_eq!(escape_value("#leading"), r"\#leading");
        assert_eq!(escape_value(" pad "), r"\ pad\ ");
        assert_eq!(escape_value("mid dle#in"), "mid dle#in");
    }

    /// The whole path, on the string a real appliance presents: rendered name in,
    /// corpus verdict out.
    #[test]
    fn a_certificate_name_the_corpus_knows_names_its_product() {
        let db = crate::fingerprint::SignatureDb::global();
        let evidence = db
            .identify_field(r"CN=SRM01,OU=SRM,O=VMware\, Inc.,L=Palo Alto,ST=California,C=US")
            .expect("the corpus names it");
        assert_eq!(evidence.product.as_deref(), Some("Site Recovery Manager"));
    }

    /// A name nothing has a rule for is not forced into a verdict.
    #[test]
    fn an_unremarkable_name_yields_nothing() {
        let db = crate::fingerprint::SignatureDb::global();
        assert!(
            db.identify_field("CN=example.invalid,O=Nobody,C=ZZ")
                .is_none()
        );
    }
}
