// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What is listening
//!
//! A [`Service`] is an identification, and every identification here carries
//! the confidence that says how much to believe it. That number is the point of
//! the type: a guess from a port-number table and a conclusion from a completed
//! protocol handshake are both "ssh", and a consumer that cannot tell them
//! apart will report the first as if it were the second.
//!
//! Identification is progressive. A port is named from its number the moment it
//! is found open, then refined as a banner is read and analyzers run, so the
//! same `Service` is merged into repeatedly and only ever improves. See
//! [`Service::merge`] for the rule.

use std::collections::BTreeSet;
use std::sync::Arc;

/// The most CPE identifiers one service will have recorded against it.
///
/// The same bound [`MAX_CPES_PER_OS`](crate::model::host::os::MAX_CPES_PER_OS)
/// applies to an OS fingerprint, and it matters more here. An OS fingerprint is
/// derived from stack behaviour, where a service's is derived from a banner:
/// text the target chose and can make as long and as varied as it likes.
pub const MAX_CPES_PER_SERVICE: usize = 50;

/// A service identified on a port, and how sure the identification is.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// The high-level service protocol name, such as `"ssh"` or `"http"`.
    ///
    /// Shared rather than owned, like every other repeated string in the model:
    /// a scan finds the same few dozen service names across every host it
    /// touches.
    name: Arc<str>,

    /// A metric from 0 to 100 representing the certainty of this identification.
    ///
    /// For example: `0` = Table lookup by port number. `100` = Full protocol handshake.
    confidence: u8,

    /// The specific product or daemon name, such as `"OpenSSH"` or `"nginx"`.
    product: Option<Arc<str>>,

    /// The organization behind the product, when an analyzer can attribute one
    /// (e.g., "NGINX", "Apache Software Foundation", a self-signed cert's `O=`).
    vendor: Option<Arc<str>>,

    /// The version string reported or detected, such as `"8.9p1"`.
    version: Option<Arc<str>>,

    /// Additional metadata or environment hints (e.g., "protocol 2.0", "Debian",
    /// an HTTP `X-Powered-By` technology like "PHP/8.2.1").
    extrainfo: Option<Arc<str>>,

    /// Common Platform Enumeration identifiers, deduplicated and bounded by
    /// [`MAX_CPES_PER_SERVICE`].
    ///
    /// A set rather than a vector, so adding one is a lookup rather than a scan
    /// of everything already there, and so two services carrying the same
    /// identifiers compare equal whatever order the analyzers found them in.
    cpe: BTreeSet<Arc<str>>,
}

impl Service {
    /// Creates a service identity named `name`, believed to the degree
    /// `confidence` says.
    ///
    /// `confidence` is clamped to 100, so a caller computing a score cannot
    /// produce one that outranks a completed handshake.
    pub fn new(name: impl Into<Arc<str>>, confidence: u8) -> Self {
        Self {
            name: name.into(),
            confidence: confidence.min(100),
            product: None,
            vendor: None,
            version: None,
            extrainfo: None,
            cpe: BTreeSet::new(),
        }
    }

    /// Returns the high-level service protocol name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the name came from the port number rather than from the service.
    ///
    /// A confidence of zero is what every scan path seeds a classified port
    /// with: the label the port number is registered under, or a placeholder
    /// where it is registered under none. **It is not a finding.** Nothing was
    /// asked and nothing answered, and a port called `http` on the strength of
    /// being port 80 may be anything at all — which is the point
    /// [`ServiceDetection::Off`](crate::config::ServiceDetection::Off) makes
    /// about the same label.
    ///
    /// Read by anything that must not mistake a guess for an identification:
    /// [`diff`](crate::diff) ignores an inferred service entirely, because two
    /// tools with different port catalogues would otherwise appear to disagree
    /// about every port on the network.
    pub fn is_inferred(&self) -> bool {
        self.confidence == 0
    }

    /// Returns the identification confidence score (0-100).
    pub fn confidence(&self) -> u8 {
        self.confidence
    }

    /// Returns the detected product name, if any.
    pub fn product(&self) -> Option<&str> {
        self.product.as_deref()
    }

    /// Returns the attributed vendor/organization, if any.
    pub fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    /// Returns the detected version string, if any.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Returns additional environmental metadata, if any.
    pub fn extrainfo(&self) -> Option<&str> {
        self.extrainfo.as_deref()
    }

    /// The CPE identifiers recorded for this service, in sorted order.
    pub fn cpes(&self) -> &BTreeSet<Arc<str>> {
        &self.cpe
    }

    /// Builder method to assign a product string.
    pub fn with_product(mut self, product: impl Into<Arc<str>>) -> Self {
        self.product = Some(product.into());
        self
    }

    /// Builder method to assign a vendor string.
    pub fn with_vendor(mut self, vendor: impl Into<Arc<str>>) -> Self {
        self.vendor = Some(vendor.into());
        self
    }

    /// Builder method to assign a version string.
    pub fn with_version(mut self, version: impl Into<Arc<str>>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Builder method to assign an extrainfo string.
    pub fn with_extrainfo(mut self, extrainfo: impl Into<Arc<str>>) -> Self {
        self.extrainfo = Some(extrainfo.into());
        self
    }

    /// Records a CPE identifier, if [`MAX_CPES_PER_SERVICE`] leaves room.
    ///
    /// Takes `&mut self`, so a service already attached to a port can be
    /// enriched by a later analyzer. That is the whole point of progressive
    /// identification, and a builder that consumed the service would rule it
    /// out.
    pub fn add_cpe(&mut self, cpe: impl Into<Arc<str>>) {
        if self.cpe.len() < MAX_CPES_PER_SERVICE {
            self.cpe.insert(cpe.into());
        }
    }

    /// Builder form of [`add_cpe`](Self::add_cpe), for constructing a service
    /// in one expression.
    pub fn with_cpe(mut self, cpe: impl Into<Arc<str>>) -> Self {
        self.add_cpe(cpe);
        self
    }

    /// Folds another identification of this endpoint into this one.
    ///
    /// Confidence decides. A strictly surer `other` names the service and
    /// supplies every detail it carries: `name`, `product`, `vendor`, `version`
    /// and `extrainfo`. An equally sure or less sure one fills the gaps it finds
    /// and displaces nothing, which is the module's rule that a tie keeps what
    /// is already recorded.
    ///
    /// CPEs union whatever the confidences were, since a CPE claims that an
    /// identifier applies rather than that this is the service, and a probe that
    /// was less sure of the name can still have extracted a valid one. The cap
    /// still applies, so a fold cannot smuggle past what
    /// [`add_cpe`](Self::add_cpe) refuses.
    pub fn merge(&mut self, other: Service) {
        // Destructured rather than reached through `other.…`, so a field added
        // to this struct is a compile error here and not a value that quietly
        // stops being folded. The doc above used to name three of the five
        // details and the body moved all five, which is the same omission one
        // step earlier.
        let Service {
            name,
            confidence,
            product,
            vendor,
            version,
            extrainfo,
            cpe,
        } = other;

        if confidence > self.confidence {
            self.name = name;
            self.confidence = confidence;

            self.product = product.or(self.product.take());
            self.vendor = vendor.or(self.vendor.take());
            self.version = version.or(self.version.take());
            self.extrainfo = extrainfo.or(self.extrainfo.take());
        } else {
            self.product = self.product.take().or(product);
            self.vendor = self.vendor.take().or(vendor);
            self.version = self.version.take().or(version);
            self.extrainfo = self.extrainfo.take().or(extrainfo);
        }

        for cpe in cpe {
            if self.cpe.len() >= MAX_CPES_PER_SERVICE {
                break;
            }
            self.cpe.insert(cpe);
        }
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

    /// Every field an analyzer can fill, filled through the builders that
    /// compose into one expression.
    #[test]
    fn a_service_carries_everything_an_analyzer_can_establish() {
        let service = Service::new("http", 85)
            .with_product("Apache")
            .with_vendor("Apache Software Foundation")
            .with_version("2.4.57")
            .with_extrainfo("PHP/8.2.1")
            .with_cpe("cpe:/a:apache:http_server:2.4.57");

        assert_eq!(service.name(), "http");
        assert_eq!(service.confidence(), 85);
        assert_eq!(service.product(), Some("Apache"));
        assert_eq!(service.vendor(), Some("Apache Software Foundation"));
        assert_eq!(service.version(), Some("2.4.57"));
        assert_eq!(service.extrainfo(), Some("PHP/8.2.1"));
        assert_eq!(service.cpes().len(), 1);
    }

    /// Confidence is what ranks two identifications, so a value above 100 would
    /// outrank a completed handshake and could never be displaced. A caller
    /// computing a score must not be able to produce one.
    #[test]
    fn a_confidence_above_100_is_clamped_rather_than_kept() {
        assert_eq!(Service::new("ssh", 101).confidence(), 100);
    }

    /// The surer identification names the service; the other still fills what
    /// it left blank. Both directions matter — a handshake that identified
    /// `http` precisely should not lose the version a banner read, and a banner
    /// guess should not rename what a handshake established.
    #[test]
    fn the_surer_identification_names_the_service_and_the_other_fills_its_gaps() {
        let mut guess = Service::new("http", 50).with_product("nginx");
        guess.merge(
            Service::new("http", 100)
                .with_product("Apache")
                .with_version("2.4"),
        );
        assert_eq!(guess.product(), Some("Apache"), "the surer product wins");
        assert_eq!(guess.confidence(), 100);
        assert_eq!(guess.version(), Some("2.4"));

        let mut established = Service::new("http", 85).with_product("nginx");
        established.merge(Service::new("unknown", 10).with_version("2.0"));
        assert_eq!(established.name(), "http", "a guess does not rename it");
        assert_eq!(established.product(), Some("nginx"));
        assert_eq!(established.confidence(), 85);
        assert_eq!(
            established.version(),
            Some("2.0"),
            "but a gap is worth filling from any source"
        );
    }

    /// A CPE claims that an identifier applies, not that this is the service,
    /// so it is kept whatever the confidences were — the same rule
    /// [`OsFingerprint::merge`](crate::model::host::OsFingerprint::merge)
    /// follows. Repeats collapse, since two analyzers commonly extract the
    /// same one.
    #[test]
    fn cpes_are_unioned_across_a_merge_whatever_the_confidence() {
        let mut ssh = Service::new("ssh", 100).with_cpe("cpe:/a:openbsd:openssh");
        ssh.merge(
            Service::new("ssh", 10)
                .with_cpe("cpe:/o:linux:linux_kernel")
                .with_cpe("cpe:/a:openbsd:openssh"),
        );

        assert_eq!(ssh.cpes().len(), 2, "one new, one already held");
    }

    /// A service's identifiers come from a banner, which the target writes.
    /// Without a bound, a host that answers with a few thousand plausible CPE
    /// strings makes this engine hold every one of them.
    #[test]
    fn a_services_cpe_list_is_bounded_like_an_os_fingerprints() {
        let mut service = Service::new("http", 50);
        for i in 0..(MAX_CPES_PER_SERVICE * 2) {
            service.add_cpe(format!("cpe:/a:vendor:product:{i}"));
        }
        assert_eq!(service.cpes().len(), MAX_CPES_PER_SERVICE);

        // And a merge cannot smuggle past what `add_cpe` refuses.
        let mut other = Service::new("http", 50);
        for i in 0..MAX_CPES_PER_SERVICE {
            other.add_cpe(format!("cpe:/a:other:product:{i}"));
        }
        service.merge(other);
        assert_eq!(service.cpes().len(), MAX_CPES_PER_SERVICE);
    }
}
