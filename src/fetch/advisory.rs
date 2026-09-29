// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The distributions' security feeds
//!
//! A distribution fixes a vulnerability by backporting the patch into the
//! version it already ships, so the upstream version a banner shows says
//! little about what the host still has. Each distribution publishes which of
//! its package builds fixed what, and these are the feeds the engine reads
//! that from.
//!
//! Declared here, beside the fetching, rather than beside the correlator:
//! what a feed *is* to the engine is where it lives, how large it may grow and
//! how it is checked, which is this module's vocabulary, and the correlator
//! takes the dataset converted from it and never a download. Each [`Feed`]
//! is one format, so turning a stored copy into the correlator's dataset is a
//! match on the feed, written where the converters are, and
//! [`Feed::of`] is how an update walking [`registry`](super::registry) finds
//! which feed a resource it just fetched is.
//!
//! None of this data is shipped with the crate. The Ubuntu feeds are licensed
//! CC BY-SA 4.0 and are fetched by whoever runs the engine, from the
//! publisher, when they ask for it.

use super::{Resource, Verify};

/// A distribution security feed the engine knows how to fetch.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Feed {
    /// Canonical's Ubuntu security notices and CVE records in OSV, one JSON
    /// document per record, as one `.tar.xz` archive.
    UbuntuOsv,
    /// Canonical's per-release package status for each CVE in OpenVEX, as one
    /// `.tar.xz` archive. What says a package is not affected, or has no fix
    /// yet, which the OSV records leave unsaid.
    UbuntuVex,
    /// The Debian security tracker's whole database as one JSON document:
    /// every source package, every CVE, and the fixed version per release.
    DebianTracker,
}

impl Feed {
    /// Every feed, in the order an update walks them.
    pub const ALL: &'static [Feed] = &[Feed::UbuntuOsv, Feed::UbuntuVex, Feed::DebianTracker];

    /// The resource this feed is fetched as.
    ///
    /// Each ceiling is several times the feed's size when it was set, so a
    /// feed that keeps growing is not refused for years, and still bounds what
    /// a publisher gone wrong could fill a disk with. None is signed or
    /// published with a digest, so each is checked by the transport alone.
    pub fn resource(self) -> Resource {
        let (id, url, max_bytes) = match self {
            // About 46 MB in 2026.
            Feed::UbuntuOsv => (
                "advisories/ubuntu-osv",
                "https://security-metadata.canonical.com/osv/osv-all.tar.xz",
                192 * MIB,
            ),
            // About 68 MB in 2026.
            Feed::UbuntuVex => (
                "advisories/ubuntu-vex",
                "https://security-metadata.canonical.com/vex/vex-all.tar.xz",
                256 * MIB,
            ),
            // About 78 MB in 2026.
            Feed::DebianTracker => (
                "advisories/debian-tracker",
                "https://security-tracker.debian.org/tracker/data/json",
                320 * MIB,
            ),
        };
        Resource::new(id, url, max_bytes, Verify::Transport)
            .expect("the built-in feeds are valid resources")
    }
}

impl Feed {
    /// The feed `resource` is fetched as, where it is one.
    pub fn of(resource: &Resource) -> Option<Feed> {
        Feed::ALL
            .iter()
            .copied()
            .find(|feed| feed.resource().id() == resource.id())
    }
}

/// A mebibyte, which the ceilings above are counted in.
const MIB: u64 = 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every feed describes, and each is fetched over HTTPS: they are checked
    /// by the transport alone, so a feed named over plain HTTP would be
    /// checked by nothing.
    #[test]
    fn every_feed_is_fetched_over_https() {
        for feed in Feed::ALL {
            let resource = feed.resource();
            assert!(resource.url().starts_with("https://"), "{feed:?}");
            assert!(resource.id().starts_with("advisories/"), "{feed:?}");
        }
    }

    /// An update walks resources and a conversion dispatches on feeds, so
    /// every feed's resource has to lead back to that feed, and nothing else
    /// to one.
    #[test]
    fn every_feed_is_found_again_from_its_resource() {
        for feed in Feed::ALL {
            assert_eq!(Feed::of(&feed.resource()), Some(*feed));
        }
        let other = Resource::new(
            "detections/x",
            "https://example.com/x",
            1,
            Verify::Transport,
        )
        .unwrap();
        assert_eq!(Feed::of(&other), None);
    }
}
