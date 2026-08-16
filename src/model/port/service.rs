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
    pub fn cpe(&self) -> &BTreeSet<Arc<str>> {
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

    /// Merges another service record into this one safely.
    ///
    /// The merge strategy is confidence-driven. If the incoming `other` service
    /// has a strictly higher confidence score, it will overwrite the primary
    /// identity (`name`, `product`, `version`). Otherwise, it behaves additively,
    /// filling in `None` fields and deduplicating CPEs.
    pub fn merge(&mut self, other: Service) {
        let higher_confidence = other.confidence > self.confidence;

        if higher_confidence {
            self.name = other.name;
            self.confidence = other.confidence;

            // Overwrite existing data with the higher-confidence payload
            if other.product.is_some() {
                self.product = other.product;
            }
            if other.vendor.is_some() {
                self.vendor = other.vendor;
            }
            if other.version.is_some() {
                self.version = other.version;
            }
            if other.extrainfo.is_some() {
                self.extrainfo = other.extrainfo;
            }
        } else {
            // Additive merge for equal or lower confidence probes
            if self.product.is_none() {
                self.product = other.product;
            }
            if self.vendor.is_none() {
                self.vendor = other.vendor;
            }
            if self.version.is_none() {
                self.version = other.version;
            }
            if self.extrainfo.is_none() {
                self.extrainfo = other.extrainfo;
            }
        }

        // CPEs are always merged, regardless of confidence: even a
        // low-confidence probe might extract a valid identifier. The cap still
        // applies, so a merge cannot smuggle past what `add_cpe` refuses.
        for cpe in other.cpe {
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

    #[test]
    fn service_builder_pattern() {
        let srv = Service::new("http", 85)
            .with_product("nginx")
            .with_version("1.21.0")
            .with_cpe("cpe:/a:igor_sysoev:nginx:1.21.0");

        assert_eq!(srv.name(), "http");
        assert_eq!(srv.confidence(), 85);
        assert_eq!(srv.product(), Some("nginx"));
        assert_eq!(srv.version(), Some("1.21.0"));
        assert_eq!(srv.cpe().len(), 1);
    }

    #[test]
    fn service_carries_vendor_and_extrainfo() {
        let srv = Service::new("http", 90)
            .with_product("Apache")
            .with_vendor("Apache Software Foundation")
            .with_extrainfo("PHP/8.2.1");

        assert_eq!(srv.vendor(), Some("Apache Software Foundation"));
        assert_eq!(srv.extrainfo(), Some("PHP/8.2.1"));
    }

    #[test]
    fn service_merge_higher_confidence_overwrites_vendor() {
        let mut srv1 = Service::new("http", 50).with_vendor("Unknown");
        let srv2 = Service::new("http", 100).with_vendor("NGINX");
        srv1.merge(srv2);
        assert_eq!(srv1.vendor(), Some("NGINX"));
    }

    #[test]
    fn service_confidence_is_clamped_to_100() {
        let srv = Service::new("ssh", 101);
        assert_eq!(srv.confidence(), 100);
    }

    #[test]
    fn service_merge_lower_confidence_does_not_overwrite_identity() {
        let mut srv1 = Service::new("http", 85).with_product("nginx");
        let srv2 = Service::new("unknown", 10).with_version("2.0");

        srv1.merge(srv2);

        // Name and product shouldn't change, but version should be adopted from lower confidence
        // if not already present.
        assert_eq!(srv1.name(), "http");
        assert_eq!(srv1.confidence(), 85);
        assert_eq!(srv1.product(), Some("nginx"));
        assert_eq!(srv1.version(), Some("2.0"));
    }

    #[test]
    fn service_merge_higher_confidence_overwrites_identity() {
        let mut srv1 = Service::new("http", 50).with_product("nginx");
        let srv2 = Service::new("http", 100)
            .with_product("Apache")
            .with_version("2.4");

        srv1.merge(srv2);

        // The higher confidence payload completely overwrites the identity
        assert_eq!(srv1.name(), "http");
        assert_eq!(srv1.confidence(), 100);
        assert_eq!(srv1.product(), Some("Apache"));
        assert_eq!(srv1.version(), Some("2.4"));
    }

    #[test]
    fn service_merge_deduplicates_cpes() {
        let mut srv1 = Service::new("ssh", 100).with_cpe("cpe:/a:openbsd:openssh");
        let srv2 = Service::new("ssh", 100).with_cpe("cpe:/o:linux:linux_kernel");

        srv1.merge(srv2);

        assert_eq!(srv1.cpe().len(), 2);
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
        assert_eq!(service.cpe().len(), MAX_CPES_PER_SERVICE);

        // And a merge cannot smuggle past what `add_cpe` refuses.
        let mut other = Service::new("http", 50);
        for i in 0..MAX_CPES_PER_SERVICE {
            other.add_cpe(format!("cpe:/a:other:product:{i}"));
        }
        service.merge(other);
        assert_eq!(service.cpe().len(), MAX_CPES_PER_SERVICE);
    }
}
