// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What is listening
//!
//! A [`Service`] is an identification with a confidence: a guess from a port-number
//! table and a conclusion from a completed handshake are both "ssh", and the confidence
//! tells them apart.
//!
//! Identification is progressive. A port is named from its number when found open,
//! then refined as a banner is read and analyzers run; see [`Service::merge`].

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::model::host::os::MAX_CPES_PER_OS;
use crate::model::port::Build;

/// The most CPE identifiers one service will have recorded against it.
///
/// The same bound as [`MAX_CPES_PER_OS`], read from it. It matters more here, since a
/// banner is text the target chose.
pub const MAX_CPES_PER_SERVICE: usize = MAX_CPES_PER_OS;

/// A service identified on a port, and how sure the identification is.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// The high-level service protocol name, such as `"ssh"` or `"http"`.
    ///
    /// Shared, since a scan finds the same few dozen names on every host.
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
    /// A set, so two services with the same identifiers compare equal whatever order
    /// they were found in.
    cpe: BTreeSet<Arc<str>>,

    /// Whose build of the software this is, where the reply said.
    ///
    /// Separate from the version: the version names the upstream release, the build
    /// says whose fixes were applied since. A vulnerability match on the version alone
    /// is routinely wrong for a distribution's build. See [`Build`].
    build: Option<Build>,
}

impl Service {
    /// Creates a service identity named `name`, believed to the degree
    /// `confidence` says.
    ///
    /// `confidence` is clamped to 100.
    pub fn new(name: impl Into<Arc<str>>, confidence: u8) -> Self {
        Self {
            name: name.into(),
            confidence: confidence.min(100),
            product: None,
            vendor: None,
            version: None,
            extrainfo: None,
            cpe: BTreeSet::new(),
            build: None,
        }
    }

    /// Returns the high-level service protocol name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the name came from the port number rather than from the service.
    ///
    /// A confidence of zero is what every scan path seeds a port with: its registered
    /// label, or a placeholder. Not a finding: port 80 called `http` may be anything (see
    /// [`ServiceDetection::Off`](crate::config::ServiceDetection::Off)).
    ///
    /// Why nothing was asked is recorded on the phase, not the port: see
    /// [`ScanSettings::listened_only_to`](crate::report::ScanSettings::listened_only_to)
    /// and the phase's service detection setting.
    ///
    /// [`diff`](crate::diff) ignores inferred services, since tools with different port
    /// catalogues would otherwise disagree about every port.
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

    /// Whose build of the software this is, if the reply said.
    pub fn build(&self) -> Option<&Build> {
        self.build.as_ref()
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

    /// Builder method to record whose build of the software this is.
    pub fn with_build(mut self, build: Build) -> Self {
        self.build = Some(build);
        self
    }

    /// Records a CPE identifier, if [`MAX_CPES_PER_SERVICE`] leaves room.
    ///
    /// Takes `&mut self`, so a later analyzer can enrich a service already attached to a
    /// port.
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
    /// Confidence decides. A strictly surer `other` supplies `name`, `product`,
    /// `vendor`, `version`, `extrainfo` and `build`; an equally or less sure one only
    /// fills gaps.
    ///
    /// Two builds by the same distributor complete each other (see [`Build::merge`]);
    /// by different distributors, the surer identification's stands.
    ///
    /// CPEs union regardless of confidence, since a less certain probe can still
    /// extract a valid one. The cap still applies.
    pub fn merge(&mut self, other: Service) {
        // Destructured, so a new field fails to compile until it is merged.
        let Service {
            name,
            confidence,
            product,
            vendor,
            version,
            extrainfo,
            cpe,
            build,
        } = other;

        let surer = confidence > self.confidence;
        self.build = match (self.build.take(), build) {
            (Some(mut held), Some(offered)) if held.distributor() == offered.distributor() => {
                held.merge(offered);
                Some(held)
            }
            (Some(_), Some(offered)) if surer => Some(offered),
            (held, offered) => held.or(offered),
        };

        if surer {
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

    /// Confidence is clamped to 100.
    #[test]
    fn a_confidence_above_100_is_clamped_rather_than_kept() {
        assert_eq!(Service::new("ssh", 101).confidence(), 100);
    }

    /// The surer identification names the service, and the other fills its blanks.
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

    /// CPEs are kept whatever the confidences, as in
    /// [`OsFingerprint::merge`](crate::model::host::OsFingerprint::merge), and repeats
    /// collapse.
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

    /// One distributor's builds complete each other; different distributors' do not.
    #[test]
    fn a_merge_completes_one_distributors_build_and_ranks_two_by_confidence() {
        use crate::model::port::{Build, Distributor, Release, ReleaseBasis};

        let mut ssh = Service::new("ssh", 90)
            .with_build(Build::new(Distributor::Ubuntu).with_revision("2ubuntu2.13"));
        ssh.merge(
            Service::new("ssh", 70).with_build(
                Build::new(Distributor::Ubuntu)
                    .with_release(Release::new("14.04", ReleaseBasis::Banner)),
            ),
        );
        let build = ssh.build().expect("the build survives");
        assert_eq!(build.revision(), Some("2ubuntu2.13"));
        assert_eq!(build.release().map(Release::name), Some("14.04"));

        let mut guess = Service::new("ssh", 50).with_build(Build::new(Distributor::Debian));
        guess.merge(Service::new("ssh", 90).with_build(Build::new(Distributor::Ubuntu)));
        assert_eq!(
            guess.build().map(Build::distributor),
            Some(Distributor::Ubuntu),
            "the surer identification's build stands"
        );

        let mut established = Service::new("ssh", 90).with_build(Build::new(Distributor::Ubuntu));
        established.merge(Service::new("ssh", 50).with_build(Build::new(Distributor::Debian)));
        assert_eq!(
            established.build().map(Build::distributor),
            Some(Distributor::Ubuntu),
            "a less sure one displaces nothing"
        );
    }

    /// CPEs are bounded, since the target writes the banner.
    #[test]
    fn a_services_cpe_list_is_bounded_like_an_os_fingerprints() {
        let mut service = Service::new("http", 50);
        for i in 0..(MAX_CPES_PER_SERVICE * 2) {
            service.add_cpe(format!("cpe:/a:vendor:product:{i}"));
        }
        assert_eq!(service.cpes().len(), MAX_CPES_PER_SERVICE);

        // A merge cannot get past what `add_cpe` refuses.
        let mut other = Service::new("http", 50);
        for i in 0..MAX_CPES_PER_SERVICE {
            other.add_cpe(format!("cpe:/a:other:product:{i}"));
        }
        service.merge(other);
        assert_eq!(service.cpes().len(), MAX_CPES_PER_SERVICE);
    }
}
