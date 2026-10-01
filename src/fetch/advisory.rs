// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The security feeds a correlation reads
//!
//! A distribution fixes a vulnerability by backporting the patch into the version it
//! already ships, so the upstream version in a banner says little about what the host
//! still has. Each distribution publishes which of its package builds fixed what, and
//! these are the feeds the engine reads that from. CISA's catalogue of vulnerabilities
//! known to be exploited sits beside them; it marks what a correlation reports and does
//! not change what is reported.
//!
//! The correlator takes the dataset converted from a feed, never a download, so a feed is
//! described here by where it lives, how large it may grow and how it is checked. Each
//! [`Feed`] is one format, and [`Feed::of`] tells an update walking
//! [`registry`](super::registry) which feed a resource it just fetched is.
//!
//! None of the distributions' data ships with the crate. The Ubuntu feeds are licensed
//! CC BY-SA 4.0 and are fetched from the publisher by whoever runs the engine. CISA's
//! catalogue is in the public domain; the crate ships the list as of release, and a
//! fetched copy replaces it.

use super::{Resource, Verify};

/// A distribution security feed the engine knows how to fetch.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Feed {
    /// Canonical's Ubuntu security notices and CVE records in OSV, one JSON
    /// document per record, as one `.tar.xz` archive.
    UbuntuOsv,
    /// Canonical's per-release package status for each CVE in OpenVEX, as one `.tar.xz`
    /// archive. It says when a package is not affected or has no fix yet, which the OSV
    /// records leave out.
    UbuntuVex,
    /// The Debian security tracker's whole database as one JSON document:
    /// every source package, every CVE, and the fixed version per release.
    DebianTracker,
    /// CISA's Known Exploited Vulnerabilities catalogue as one JSON document.
    CisaKev,
}

impl Feed {
    /// Every feed, in the order an update walks them.
    pub const ALL: &'static [Feed] = &[
        Feed::UbuntuOsv,
        Feed::UbuntuVex,
        Feed::DebianTracker,
        Feed::CisaKev,
    ];

    /// The resource this feed is fetched as.
    ///
    /// Each size ceiling is several times the feed's size when it was set, so a growing
    /// feed is not refused for years while a misbehaving publisher still cannot fill a
    /// disk. None is signed or published with a digest, so each is checked by the
    /// transport alone.
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
            // About 1.8 MB in 2026. Capped at what the list's reader takes.
            Feed::CisaKev => (
                "advisories/cisa-kev",
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                crate::cve::MAX_DOCUMENT_BYTES,
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

/// A distributor's advisory dataset, converted from its stored feeds.
///
/// What a scan consumes: a [`cve::Advisories`](crate::cve::Advisories), which the
/// correlator reads to judge a distribution's build. Converting Ubuntu's archives takes a
/// minute and a hundred megabytes, so it is done once per feed change and kept beside the
/// feeds in the [`Store`](super::Store).
#[cfg(feature = "import-distro")]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dataset {
    /// Ubuntu's, from its OSV and VEX archives.
    Ubuntu,
    /// Debian's, from its security tracker.
    Debian,
}

#[cfg(feature = "import-distro")]
impl Dataset {
    /// Every dataset, in the order an update converts them.
    pub const ALL: &'static [Dataset] = &[Dataset::Ubuntu, Dataset::Debian];

    /// The stored feeds it is made from, and the name it is kept under.
    ///
    /// Versioned by the engine's version, so a copy made by another build of the converter
    /// is never taken for current: every release reconverts once from the stored feeds.
    pub fn derived(self) -> super::Derived {
        let (id, feeds): (&str, &[Feed]) = match self {
            Dataset::Ubuntu => ("advisories/ubuntu", &[Feed::UbuntuOsv, Feed::UbuntuVex]),
            Dataset::Debian => ("advisories/debian", &[Feed::DebianTracker]),
        };
        super::Derived::new(
            id,
            concat!("zond-engine ", env!("CARGO_PKG_VERSION")),
            feeds.iter().map(|feed| feed.resource()).collect(),
        )
        .expect("the built-in datasets are valid")
    }

    /// Converts the stored feeds into the dataset and keeps it in `store`,
    /// unless the copy there was already made from these feeds by this build.
    ///
    /// Blocks for as long as the conversion takes; an async caller runs it with
    /// `spawn_blocking`.
    ///
    /// # Errors
    ///
    /// As [`Store::derive`](super::Store::derive): a feed never fetched, a
    /// feed that would not convert, or a store that could not be written.
    pub fn convert(
        self,
        store: &super::Store,
    ) -> Result<super::Derivation, super::DeriveError<crate::import::ImportError>> {
        store.derive(&self.derived(), |sources| {
            // The tracker's JSON is undated, so its dataset is dated by when
            // this copy of it was fetched.
            let debian_fetched = sources
                .first()
                .map_or(std::time::UNIX_EPOCH, |stored| stored.metadata().fetched_at);
            let mut files = sources
                .into_iter()
                .map(|stored| std::io::BufReader::new(stored.into_file()));
            let mut next = || files.next().expect("one file per declared feed");
            let advisories = match self {
                Dataset::Ubuntu => {
                    let (mut osv, mut vex) = (next(), next());
                    crate::import::ubuntu::read(&mut osv, &mut vex)?
                }
                Dataset::Debian => crate::import::debian::read_as_of(&mut next(), debian_fetched)?,
            };
            Ok(advisories.to_bytes())
        })
    }

    /// The converted dataset `store` holds, with whether it is current, or
    /// [`None`] where none has been made or the copy is not one this build
    /// can read.
    ///
    /// A copy that is not current, because a feed changed after it was made, is still
    /// returned: a scan is better judged against it than against nothing. The caller
    /// should say it is stale.
    ///
    /// # Errors
    ///
    /// [`FetchError::Storage`](super::FetchError::Storage) where a copy is
    /// there and cannot be read.
    pub fn load(self, store: &super::Store) -> Result<Option<Loaded>, super::FetchError> {
        let Some(copy) = store.open_derived(&self.derived())? else {
            return Ok(None);
        };
        let current = copy.is_current();
        let metadata = copy.metadata().clone();
        let path = copy.path().to_path_buf();
        let bytes = copy
            .read()
            .map_err(|source| super::FetchError::Storage { path, source })?;
        Ok(crate::cve::Advisories::from_bytes(&bytes)
            .ok()
            .map(|advisories| Loaded {
                advisories,
                current,
                metadata,
            }))
    }
}

/// A converted dataset as a store held it.
#[cfg(feature = "import-distro")]
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The dataset.
    pub advisories: crate::cve::Advisories,
    /// Whether it was made from the feeds stored now.
    pub current: bool,
    /// How and when it was made, and from which copies of which feeds: the
    /// oldest of those copies' fetch times is how old the data is.
    pub metadata: super::DerivedMetadata,
}

/// The list of exploited vulnerabilities read from the copy of CISA's
/// catalogue `store` holds, or [`None`] where none has been fetched.
///
/// Read from the feed on every call; it is a couple of megabytes of JSON and reads in
/// milliseconds.
///
/// # Errors
///
/// [`FetchError::Storage`](super::FetchError::Storage) where a copy is there
/// and cannot be read, or does not read as CISA's catalogue.
#[cfg(feature = "import-kev")]
pub fn known_exploited(store: &super::Store) -> Result<Option<LoadedList>, super::FetchError> {
    let Some(copy) = store.open(&Feed::CisaKev.resource())? else {
        return Ok(None);
    };
    let path = copy.path().to_path_buf();
    let metadata = copy.metadata().clone();
    let mut file = std::io::BufReader::new(copy.into_file());
    let exploited =
        crate::import::kev::exploited(&mut file).map_err(|error| super::FetchError::Storage {
            path,
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        })?;
    Ok(Some(LoadedList {
        exploited,
        metadata,
    }))
}

/// A list of exploited vulnerabilities as a store held it.
#[cfg(feature = "import-kev")]
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct LoadedList {
    /// The list.
    pub exploited: crate::cve::KnownExploited,
    /// How and when the copy it was read from was fetched.
    pub metadata: super::Metadata,
}

/// A mebibyte, which the ceilings above are counted in.
const MIB: u64 = 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every feed is fetched over HTTPS: they are checked by the transport alone, so a
    /// feed over plain HTTP would be checked by nothing.
    #[test]
    fn every_feed_is_fetched_over_https() {
        for feed in Feed::ALL {
            let resource = feed.resource();
            assert!(resource.url().starts_with("https://"), "{feed:?}");
            assert!(resource.id().starts_with("advisories/"), "{feed:?}");
        }
    }

    /// An update walks resources and a conversion dispatches on feeds, so every feed's
    /// resource leads back to that feed, and nothing else leads to one.
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

    /// Stored feeds convert into the datasets a scan loads, and a second conversion from
    /// the same copies does no work: an update calls it after every fetch, and Ubuntu's
    /// takes a minute.
    #[cfg(feature = "import-distro")]
    #[test]
    fn stored_feeds_convert_once_into_the_datasets_a_scan_loads() {
        use super::super::store::testing::put;
        use super::super::{Derivation, Store};

        let root = std::env::temp_dir().join(format!("zond-datasets-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::new(&root);
        put(
            &store,
            &Feed::UbuntuOsv.resource(),
            include_bytes!("../../tests/data/distro/ubuntu-osv.tar.xz"),
        );
        put(
            &store,
            &Feed::UbuntuVex.resource(),
            include_bytes!("../../tests/data/distro/ubuntu-vex.tar.xz"),
        );
        put(
            &store,
            &Feed::DebianTracker.resource(),
            include_bytes!("../../tests/data/distro/debian-tracker.json"),
        );

        for dataset in Dataset::ALL {
            assert!(
                matches!(dataset.convert(&store), Ok(Derivation::Built(_))),
                "{dataset:?}"
            );
            assert!(
                matches!(dataset.convert(&store), Ok(Derivation::Current(_))),
                "{dataset:?} converted twice from the same feeds"
            );
            let loaded = dataset
                .load(&store)
                .expect("the store reads")
                .expect("a dataset was made");
            assert!(loaded.current);
            assert!(!loaded.advisories.is_empty(), "{dataset:?}");
        }
        assert_eq!(
            Dataset::Ubuntu
                .load(&store)
                .unwrap()
                .unwrap()
                .advisories
                .distributor(),
            "ubuntu"
        );
        // Debian's feed carries no date, so its dataset is dated by the copy's fetch.
        assert_ne!(
            Dataset::Debian
                .load(&store)
                .unwrap()
                .unwrap()
                .advisories
                .version(),
            crate::model::finding::Version::new(0, 0, 0)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A stored copy of CISA's feed reads as the list, dated by its catalogue version; a
    /// store without one has none, and a copy that is not the feed is an error, not an
    /// empty list.
    #[cfg(feature = "import-kev")]
    #[test]
    fn a_stored_copy_of_the_kev_feed_reads_as_the_list() {
        use super::super::Store;
        use super::super::store::testing::put;

        let root = std::env::temp_dir().join(format!("zond-kev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::new(&root);
        assert!(known_exploited(&store).unwrap().is_none());

        put(
            &store,
            &Feed::CisaKev.resource(),
            br#"{"catalogVersion": "2026.09.29", "vulnerabilities": [
                {"cveID": "CVE-2021-41773", "vendorProject": "Apache", "product": "HTTP Server"}
            ]}"#,
        );
        let loaded = known_exploited(&store).unwrap().expect("a list");
        assert_eq!(loaded.exploited.id(), "cisa:kev");
        assert_eq!(
            loaded.exploited.version(),
            crate::model::finding::Version::new(2026, 9, 29)
        );
        assert!(loaded.exploited.contains("CVE-2021-41773"));

        put(
            &store,
            &Feed::CisaKev.resource(),
            b"<html>maintenance</html>",
        );
        assert!(known_exploited(&store).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
