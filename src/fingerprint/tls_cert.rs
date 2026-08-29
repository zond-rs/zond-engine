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
//! What a certificate reliably tells us about *what a port runs* is deliberately
//! modest, and this analyzer claims only that much:
//!
//! * **The port speaks TLS** — reported as service `ssl` at [`Probable`]
//!   confidence. That is a real, useful label (far better than a raw handshake
//!   blob) but shallow: it does not name the application protocol inside the
//!   tunnel. A later phase re-probes *through* the tunnel and will override this
//!   with a stronger, more specific verdict.
//! * **A self-signed cert's organization names its operator/vendor.** When the
//!   subject equals the issuer (self-signed — typical of appliances and internal
//!   services) the subject `O=` reliably names who stood the service up, so it is
//!   surfaced as `vendor`. For CA-signed certs `O=` names the CA or the cert
//!   owner, neither of which is the product vendor, so we do not guess.
//!
//! Host attribution (subject CN / SAN hostnames) is intentionally *not* produced
//! here: it describes the host, not the service, and has no home on [`Evidence`]
//! yet. It is a separate follow-up.
//!
//! [`Analyzer`]: super::analyzer::Analyzer
//! [`Probable`]: super::model::Confidence::Probable

use async_trait::async_trait;
use x509_parser::parse_x509_certificate;

use super::analyzer::{Analyzer, PortContext};
use super::model::{Evidence, SourceId};
use super::response::{Collected, ResponseSet};
use crate::model::confidence::Confidence;

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
        }

        vec![evidence]
    }
}
