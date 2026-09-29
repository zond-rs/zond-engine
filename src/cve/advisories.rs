// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A distribution's own verdicts on its builds
//!
//! An upstream version range says which releases of a project carry a
//! vulnerability. A distribution fixes vulnerabilities in the builds it ships
//! by backporting the patch and leaving the upstream version where it was, so
//! `OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13` sits inside ranges whose fixes it has
//! long carried. The distributor knows which, and publishes it: for every
//! vulnerability, in every release, per source package, a verdict. An
//! [`Advisories`] holds one distributor's verdicts, keyed so the correlator can
//! ask about the exact build a banner names.
//!
//! ## Three kinds of standing
//!
//! A verdict is one of three things, and they carry different weight.
//!
//! - **Fixed** names the package version that first carried the fix. A build
//!   at or past it has the fix whatever its upstream version says, and a
//!   build before it does not. It needs the build's version to be judged.
//! - **Not affected** says the release never carried the vulnerability: the
//!   code is not there, the feature is compiled out, the version predates the
//!   bug. It needs nothing from the build at all, and it is the verdict that
//!   removes false positives outright, because it holds for a build whose
//!   exact revision the scan cannot see.
//! - **Open** says the release carries it and no fix is published, with the
//!   distributor's reason where it gave one: a fix is needed, deferred, the
//!   issue ignored as not worth fixing in that release, or still to be
//!   triaged. It confirms what the upstream range says rather than
//!   overturning it.
//!
//! ## Per release
//!
//! Verdicts are keyed by release because a fix is a build of one release's
//! package: `1:6.6p1-2ubuntu2.7` fixes CVE-2016-1908 in Ubuntu 14.04 and means
//! nothing in 16.04, whose package has a lineage of its own. Comparing a build
//! with another release's fix version would compare two branches of a tree.
//! [`Lineage`] records the versions each release's package is known to have
//! had, which is how a banner's revision is tied to a release.
//!
//! ## The ESM channel
//!
//! Ubuntu keeps publishing fixes for a release after its standard support
//! ends, in Expanded Security Maintenance pockets that need an Ubuntu Pro
//! subscription. A release can then hold two verdicts on one vulnerability:
//! no fix in the archive every machine sees, and a fix in ESM that only a
//! subscribed machine has. They are kept apart as [`Channel`]s, because which
//! one applies depends on the machine, and a report that merged them would
//! call every unsubscribed machine patched or every subscribed one exposed.
//!
//! ## Kept as bytes
//!
//! A distributor's feed is tens of megabytes and a converted dataset a few
//! hundred kilobytes, so a converted one is meant to be cached.
//! [`Advisories::to_bytes`] writes a compact, pooled form behind a magic
//! header and a format number, and [`Advisories::from_bytes`] refuses a form
//! it cannot read rather than misreading it.

use std::collections::{BTreeMap, BTreeSet};

use bincode::Options as _;
use serde::{Deserialize, Serialize};

use super::{Interner, content_hash};
use crate::model::finding::Version;
use crate::version::{dpkg_cmp, dpkg_revision};

/// The first bytes of every serialized dataset.
const MAGIC: &[u8; 8] = b"ZONDADV\0";

/// The serialized form this engine writes and reads. Anything that changes
/// the bytes' meaning, a new variant of a stored enum included, takes a new
/// number, so an older engine refuses a newer cache rather than misreading it.
const FORMAT: u16 = 1;

/// The most a serialized dataset may be.
///
/// Every mapped source package of one distributor, across every release it
/// publishes data for, converts to well under a megabyte; sixty-four is a
/// mistake or a hostile file rather than a large dataset, and the bound is
/// what keeps either from taking the process's memory.
pub(crate) const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Why serialized advisory data could not be read.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum AdvisoriesError {
    /// The bytes do not start with the header every serialized dataset has.
    #[error("not advisory data: the header is missing")]
    NotAdvisories,

    /// The bytes are advisory data in a form this engine does not read.
    ///
    /// A cache written by a newer engine. Refused rather than guessed at,
    /// because a misread verdict is a vulnerability reported fixed.
    #[error("advisory data in format {found}; this engine reads format {supported}")]
    UnsupportedFormat {
        /// The form the bytes say they are in.
        found: u16,
        /// The form this engine reads.
        supported: u16,
    },

    /// The bytes are longer than any real dataset.
    #[error("the advisory data is longer than the {limit} byte limit")]
    TooLarge {
        /// The limit they passed.
        limit: u64,
    },

    /// The header is right and what follows it is not a dataset.
    #[error("the advisory data is malformed: {0}")]
    Malformed(String),
}

/// Who published a dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Distributor {
    Ubuntu,
    Debian,
}

impl Distributor {
    /// The name every key and lookup uses.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ubuntu => "ubuntu",
            Self::Debian => "debian",
        }
    }

    /// The identity a finding drawn from this distributor's data carries: the
    /// distributor's own name for the data, never this engine's `zond:`.
    fn id(self) -> &'static str {
        match self {
            Self::Ubuntu => "ubuntu:security-notices",
            Self::Debian => "debian:security-tracker",
        }
    }
}

/// Which machines a verdict applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(crate) enum Channel {
    /// The release's own archive, which every machine running it can install
    /// from.
    Archive,
    /// Ubuntu's Expanded Security Maintenance pockets, which only a machine
    /// with an Ubuntu Pro subscription receives.
    Esm,
}

/// Why a vulnerability the distributor has not fixed stays open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum OpenKind {
    /// A fix is needed and not yet published.
    Needed,
    /// A fix is postponed, usually to a later update of the release.
    Deferred,
    /// The distributor will not fix it in this release.
    Ignored,
    /// Nobody has yet judged whether the release is affected.
    NeedsTriage,
}

/// One verdict's substance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Standing {
    /// The release never carried the vulnerability, with the distributor's
    /// reason where it gave one.
    NotAffected { reason: Option<String> },
    /// Fixed from this package version on.
    Fixed { version: String },
    /// Carried and not fixed, with the distributor's note where it gave one.
    Open {
        kind: OpenKind,
        note: Option<String>,
    },
}

/// One verdict on one vulnerability in one release's package, in one channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Status {
    pub(crate) channel: Channel,
    pub(crate) standing: Standing,
    /// The notice that published it, a USN, DSA or DLA identifier, where the
    /// data names one.
    pub(crate) advisory: Option<String>,
}

/// The package versions a release's source package is known to have had, in
/// dpkg's order, oldest first.
///
/// Gathered from every version the data names for the release: fix versions,
/// the versions in its repositories, and the version lists a feed publishes.
/// The correlator reads the release's `epoch:upstream` from it and checks that
/// a banner's revision is one of this release's builds rather than another's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Lineage {
    versions: Vec<String>,
}

impl Lineage {
    /// Every known version, oldest first.
    pub(crate) fn versions(&self) -> &[String] {
        &self.versions
    }
}

/// One release's source package: its lineage and its verdicts by CVE.
#[derive(Debug, Clone, Default)]
struct Package {
    lineage: Lineage,
    verdicts: BTreeMap<String, Vec<Status>>,
}

/// What the data says about a CVE beyond its verdicts.
#[derive(Debug, Clone, Default)]
struct Cve {
    /// A priority the distributor gives the CVE everywhere.
    priority: Option<String>,
    /// A priority the distributor gives it in one release.
    by_release: BTreeMap<String, String>,
}

/// One distributor's verdicts on the vulnerabilities in the source packages it
/// ships, release by release.
///
/// Converted from the distributor's own feed by the `import-distro` readers,
/// and kept between runs through [`to_bytes`](Self::to_bytes) and
/// [`from_bytes`](Self::from_bytes). A verdict says a release's package is
/// fixed from a given version on, was never affected, or stays open; each is
/// kept per release, because a fix is a build of one release's package, and
/// per channel, because Ubuntu's ESM pockets reach only subscribed machines.
///
/// Like a [`Catalogue`](super::Catalogue), a dataset names itself and its
/// version, and both travel onto whatever it concludes.
#[derive(Debug, Clone)]
pub struct Advisories {
    distributor: Distributor,
    version: Version,
    content_hash: String,
    /// Release, then source package, both as the distributor spells them.
    releases: BTreeMap<String, BTreeMap<String, Package>>,
    cves: BTreeMap<String, Cve>,
}

impl Advisories {
    /// What a finding drawn from this data says produced it:
    /// `ubuntu:security-notices` or `debian:security-tracker`.
    pub fn id(&self) -> &str {
        self.distributor.id()
    }

    /// The distributor that published the data, `ubuntu` or `debian`.
    pub fn distributor(&self) -> &str {
        self.distributor.as_str()
    }

    /// The data's version: the date of the newest record in it, as
    /// `year.month.day`, so two conversions of the same feed agree and a
    /// refreshed one is visibly newer.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The digest of the serialized form, as hex, so a report can say exactly
    /// which data concluded what.
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// How many vulnerabilities have a verdict, counted once per release and
    /// source package.
    pub fn len(&self) -> usize {
        self.releases
            .values()
            .flat_map(BTreeMap::values)
            .map(|package| package.verdicts.len())
            .sum()
    }

    /// Whether it holds no verdict at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every verdict the distributor published on `cve` for `source_package`
    /// in `release`, one per channel. Empty where it published none.
    pub(crate) fn statuses(&self, release: &str, source_package: &str, cve: &str) -> &[Status] {
        self.package(release, source_package)
            .and_then(|package| package.verdicts.get(cve))
            .map_or(&[], Vec::as_slice)
    }

    /// The versions `source_package` is known to have had in `release`.
    pub(crate) fn lineage(&self, release: &str, source_package: &str) -> Option<&Lineage> {
        self.package(release, source_package)
            .map(|package| &package.lineage)
    }

    /// The distributor's own priority for `cve`, in `release` where it gives
    /// one per release, and otherwise the one it gives everywhere.
    ///
    /// The distributor's judgement of how much the issue matters to its
    /// users, which is information for a reader and never a severity.
    pub(crate) fn priority(&self, release: Option<&str>, cve: &str) -> Option<&str> {
        let facts = self.cves.get(cve)?;
        release
            .and_then(|release| facts.by_release.get(release))
            .or(facts.priority.as_ref())
            .map(String::as_str)
    }

    /// Every release the dataset holds verdicts or versions for.
    pub(crate) fn releases(&self) -> impl Iterator<Item = &str> {
        self.releases.keys().map(String::as_str)
    }

    /// Every release whose `source_package` has had a version with this
    /// Debian revision, and that version, in release order.
    ///
    /// How a build is placed when its banner names a revision and no release:
    /// `2ubuntu2.13` is a revision of `openssh` in one Ubuntu release alone,
    /// and the version it belongs to carries the epoch and upstream version
    /// the banner leaves out. More than one answer means the revision does not
    /// settle the release by itself.
    pub(crate) fn builds_with_revision(
        &self,
        source_package: &str,
        revision: &str,
    ) -> Vec<(&str, &str)> {
        self.releases
            .iter()
            .filter_map(|(release, packages)| Some((release, packages.get(source_package)?)))
            .flat_map(|(release, package)| {
                package
                    .lineage
                    .versions
                    .iter()
                    .filter(|version| dpkg_revision(version) == revision)
                    .map(move |version| (release.as_str(), version.as_str()))
            })
            .collect()
    }

    fn package(&self, release: &str, source_package: &str) -> Option<&Package> {
        self.releases.get(release)?.get(source_package)
    }

    /// The dataset in its compact serialized form, for a cache.
    ///
    /// A magic header, a format number, and a pooled body in which every
    /// distinct string is written once. The same dataset always serializes to
    /// the same bytes, which is what makes [`content_hash`](Self::content_hash)
    /// the same across a round trip.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&FORMAT.to_le_bytes());
        let body = options()
            .serialize(&self.to_wire())
            .expect("a dataset in memory serializes, having no maps with non-string keys");
        bytes.extend_from_slice(&body);
        bytes
    }

    /// Reads a dataset [`to_bytes`](Self::to_bytes) wrote.
    ///
    /// # Errors
    ///
    /// [`AdvisoriesError::NotAdvisories`] for bytes without the header,
    /// [`AdvisoriesError::UnsupportedFormat`] for a form this engine does not
    /// read, [`AdvisoriesError::TooLarge`] past the size bound, and
    /// [`AdvisoriesError::Malformed`] for a body that is not a dataset.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AdvisoriesError> {
        if bytes.len() as u64 > MAX_BYTES {
            return Err(AdvisoriesError::TooLarge { limit: MAX_BYTES });
        }
        let body = bytes
            .strip_prefix(MAGIC)
            .ok_or(AdvisoriesError::NotAdvisories)?;
        let (format, body) = body
            .split_first_chunk::<2>()
            .ok_or_else(|| AdvisoriesError::Malformed("the format number is cut off".into()))?;
        let format = u16::from_le_bytes(*format);
        if format != FORMAT {
            return Err(AdvisoriesError::UnsupportedFormat {
                found: format,
                supported: FORMAT,
            });
        }

        let wire: Wire = options()
            .deserialize(body)
            .map_err(|error| AdvisoriesError::Malformed(error.to_string()))?;
        let mut advisories = Self::from_wire(wire)?;
        advisories.content_hash = content_hash(bytes);
        Ok(advisories)
    }

    fn to_wire(&self) -> Wire {
        let mut pool = Interner::default();
        let mut packages = Vec::new();
        for (release, by_package) in &self.releases {
            for (name, package) in by_package {
                packages.push(WirePackage {
                    release: pool.intern(release),
                    package: pool.intern(name),
                    lineage: package
                        .lineage
                        .versions
                        .iter()
                        .map(|version| pool.intern(version))
                        .collect(),
                    verdicts: package
                        .verdicts
                        .iter()
                        .map(|(cve, statuses)| {
                            let cve = pool.intern(cve);
                            let statuses = statuses
                                .iter()
                                .map(|status| WireStatus::from(status, &mut pool))
                                .collect();
                            (cve, statuses)
                        })
                        .collect(),
                });
            }
        }
        let cves = self
            .cves
            .iter()
            .map(|(cve, facts)| WireCve {
                cve: pool.intern(cve),
                priority: pool.maybe(facts.priority.as_deref()),
                by_release: facts
                    .by_release
                    .iter()
                    .map(|(release, priority)| (pool.intern(release), pool.intern(priority)))
                    .collect(),
            })
            .collect();

        Wire {
            distributor: self.distributor,
            version: (self.version.major, self.version.minor, self.version.patch),
            pool: pool.pool,
            packages,
            cves,
        }
    }

    fn from_wire(wire: Wire) -> Result<Self, AdvisoriesError> {
        let pool = &wire.pool;
        let at = |index: u32| -> Result<String, AdvisoriesError> {
            pool.get(index as usize).cloned().ok_or_else(|| {
                AdvisoriesError::Malformed(format!("string {index} is past the pool's end"))
            })
        };
        let maybe = |index: Option<u32>| index.map(at).transpose();

        let mut releases: BTreeMap<String, BTreeMap<String, Package>> = BTreeMap::new();
        for package in wire.packages {
            let mut verdicts = BTreeMap::new();
            for (cve, statuses) in package.verdicts {
                let statuses = statuses
                    .into_iter()
                    .map(|status| {
                        let standing = match status.standing {
                            WireStanding::NotAffected { reason } => Standing::NotAffected {
                                reason: maybe(reason)?,
                            },
                            WireStanding::Fixed { version } => Standing::Fixed {
                                version: at(version)?,
                            },
                            WireStanding::Open { kind, note } => Standing::Open {
                                kind,
                                note: maybe(note)?,
                            },
                        };
                        Ok(Status {
                            channel: status.channel,
                            standing,
                            advisory: maybe(status.advisory)?,
                        })
                    })
                    .collect::<Result<_, AdvisoriesError>>()?;
                verdicts.insert(at(cve)?, statuses);
            }
            let versions = package
                .lineage
                .into_iter()
                .map(at)
                .collect::<Result<_, _>>()?;
            releases.entry(at(package.release)?).or_default().insert(
                at(package.package)?,
                Package {
                    lineage: Lineage { versions },
                    verdicts,
                },
            );
        }

        let mut cves = BTreeMap::new();
        for cve in wire.cves {
            let by_release = cve
                .by_release
                .into_iter()
                .map(|(release, priority)| Ok((at(release)?, at(priority)?)))
                .collect::<Result<_, AdvisoriesError>>()?;
            cves.insert(
                at(cve.cve)?,
                Cve {
                    priority: maybe(cve.priority)?,
                    by_release,
                },
            );
        }

        let (major, minor, patch) = wire.version;
        Ok(Self {
            distributor: wire.distributor,
            version: Version::new(major, minor, patch),
            content_hash: String::new(),
            releases,
            cves,
        })
    }
}

/// The encoding of the serialized body: variable-length integers, refusing
/// trailing bytes, and never allocating past the size bound whatever a length
/// prefix claims.
fn options() -> impl bincode::Options {
    bincode::DefaultOptions::new().with_limit(MAX_BYTES)
}

/// The serialized body: a string pool and records of indices into it.
#[derive(Serialize, Deserialize)]
struct Wire {
    distributor: Distributor,
    version: (u16, u16, u16),
    pool: Vec<String>,
    packages: Vec<WirePackage>,
    cves: Vec<WireCve>,
}

/// One release's source package in the serialized body.
#[derive(Serialize, Deserialize)]
struct WirePackage {
    release: u32,
    package: u32,
    lineage: Vec<u32>,
    verdicts: Vec<(u32, Vec<WireStatus>)>,
}

/// One verdict in the serialized body.
#[derive(Serialize, Deserialize)]
struct WireStatus {
    channel: Channel,
    standing: WireStanding,
    advisory: Option<u32>,
}

impl WireStatus {
    fn from(status: &Status, pool: &mut Interner) -> Self {
        let standing = match &status.standing {
            Standing::NotAffected { reason } => WireStanding::NotAffected {
                reason: pool.maybe(reason.as_deref()),
            },
            Standing::Fixed { version } => WireStanding::Fixed {
                version: pool.intern(version),
            },
            Standing::Open { kind, note } => WireStanding::Open {
                kind: *kind,
                note: pool.maybe(note.as_deref()),
            },
        };
        Self {
            channel: status.channel,
            standing,
            advisory: pool.maybe(status.advisory.as_deref()),
        }
    }
}

/// A verdict's substance in the serialized body, its text as pool indices.
#[derive(Serialize, Deserialize)]
enum WireStanding {
    NotAffected { reason: Option<u32> },
    Fixed { version: u32 },
    Open { kind: OpenKind, note: Option<u32> },
}

/// What the serialized body records about a CVE beyond its verdicts.
#[derive(Serialize, Deserialize)]
struct WireCve {
    cve: u32,
    priority: Option<u32>,
    by_release: Vec<(u32, u32)>,
}

/// Assembles a dataset from a feed's records, whatever order they come in.
///
/// Where two records give verdicts on the same vulnerability, release, package
/// and channel, the more informative one stands, the same whichever arrives
/// first:
///
/// - a fix outranks everything, since it names the build that settles the
///   question, and "not affected" never overrides one;
/// - "not affected" outranks an open verdict, since it is the distributor's
///   own considered answer where an open one is often a placeholder a
///   different feed of the same distributor has not caught up with;
/// - of two fixes, the later version stands, so a build is only ever read as
///   fixed once every record agrees it is.
#[cfg_attr(not(feature = "import-distro"), allow(dead_code))]
pub(crate) struct Builder {
    distributor: Distributor,
    newest: Option<Version>,
    releases: BTreeMap<String, BTreeMap<String, Draft>>,
    cves: BTreeMap<String, Cve>,
}

/// One release's source package while a dataset is assembled: its lineage
/// as a set, sorted into dpkg's order once at the end.
#[derive(Default)]
struct Draft {
    lineage: BTreeSet<String>,
    verdicts: BTreeMap<String, Vec<Status>>,
}

#[cfg_attr(not(feature = "import-distro"), allow(dead_code))]
impl Builder {
    pub(crate) fn new(distributor: Distributor) -> Self {
        Self {
            distributor,
            newest: None,
            releases: BTreeMap::new(),
            cves: BTreeMap::new(),
        }
    }

    /// Records one verdict, resolving a clash with an earlier one as the type
    /// documentation says. A fix version joins the release's lineage.
    pub(crate) fn record(&mut self, release: &str, package: &str, cve: &str, status: Status) {
        let draft = self.entry(release, package);
        if let Standing::Fixed { version } = &status.standing {
            draft.lineage.insert(version.clone());
        }
        let statuses = draft.verdicts.entry(cve.to_string()).or_default();
        match statuses
            .iter_mut()
            .find(|held| held.channel == status.channel)
        {
            None => statuses.push(status),
            Some(held) => {
                if outranks(&status, held) {
                    *held = status;
                }
            }
        }
    }

    /// Adds versions the release's package is known to have had.
    pub(crate) fn versions<'a>(
        &mut self,
        release: &str,
        package: &str,
        versions: impl IntoIterator<Item = &'a str>,
    ) {
        self.entry(release, package)
            .lineage
            .extend(versions.into_iter().map(str::to_string));
    }

    /// Records the distributor's priority for a CVE, everywhere or in one
    /// release. The first stated stands.
    pub(crate) fn priority(&mut self, release: Option<&str>, cve: &str, priority: &str) {
        let facts = self.cves.entry(cve.to_string()).or_default();
        match release {
            None => {
                facts.priority.get_or_insert_with(|| priority.to_string());
            }
            Some(release) => {
                facts
                    .by_release
                    .entry(release.to_string())
                    .or_insert_with(|| priority.to_string());
            }
        }
    }

    /// Notes a record's timestamp, an ISO date or instant; the newest dates
    /// the dataset. A timestamp that is not one is ignored.
    pub(crate) fn dated(&mut self, timestamp: &str) {
        let date = timestamp.split('T').next().unwrap_or_default();
        let mut parts = date.split('-').map(str::parse::<u16>);
        if let (Some(Ok(year)), Some(Ok(month)), Some(Ok(day)), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        {
            let version = Version::new(year, month, day);
            self.newest = self.newest.max(Some(version));
        }
    }

    /// The finished dataset. Data with no dated record is version `0.0.0`,
    /// which sorts below every real one and says plainly that it was undated.
    pub(crate) fn finish(self) -> Advisories {
        let releases = self
            .releases
            .into_iter()
            .map(|(release, packages)| {
                let packages = packages
                    .into_iter()
                    .map(|(name, Draft { lineage, verdicts })| {
                        let mut versions: Vec<String> = lineage.into_iter().collect();
                        versions.sort_by(|a, b| dpkg_cmp(a, b).then_with(|| a.cmp(b)));
                        let package = Package {
                            lineage: Lineage { versions },
                            verdicts,
                        };
                        (name, package)
                    })
                    .collect();
                (release, packages)
            })
            .collect();

        let mut advisories = Advisories {
            distributor: self.distributor,
            version: self.newest.unwrap_or(Version::new(0, 0, 0)),
            content_hash: String::new(),
            releases,
            cves: self.cves,
        };
        advisories.content_hash = content_hash(&advisories.to_bytes());
        advisories
    }

    fn entry(&mut self, release: &str, package: &str) -> &mut Draft {
        self.releases
            .entry(release.to_string())
            .or_default()
            .entry(package.to_string())
            .or_default()
    }
}

/// Whether `new` should replace `held`, a verdict in the same channel.
fn outranks(new: &Status, held: &Status) -> bool {
    use Standing::{Fixed, NotAffected, Open};
    match (&new.standing, &held.standing) {
        (Fixed { version: new }, Fixed { version: held }) => dpkg_cmp(new, held).is_gt(),
        (Fixed { .. }, _) => true,
        (NotAffected { .. }, Open { .. }) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(channel: Channel, version: &str, advisory: Option<&str>) -> Status {
        Status {
            channel,
            standing: Standing::Fixed {
                version: version.to_string(),
            },
            advisory: advisory.map(str::to_string),
        }
    }

    fn open(channel: Channel, kind: OpenKind) -> Status {
        Status {
            channel,
            standing: Standing::Open { kind, note: None },
            advisory: None,
        }
    }

    fn not_affected(channel: Channel, reason: &str) -> Status {
        Status {
            channel,
            standing: Standing::NotAffected {
                reason: Some(reason.to_string()),
            },
            advisory: None,
        }
    }

    /// A small dataset reaching every kind of record.
    fn sample() -> Advisories {
        let mut builder = Builder::new(Distributor::Ubuntu);
        builder.record(
            "14.04",
            "openssh",
            "CVE-2016-1908",
            fixed(Channel::Archive, "1:6.6p1-2ubuntu2.7", Some("USN-2966-1")),
        );
        builder.record(
            "14.04",
            "openssh",
            "CVE-2023-38408",
            fixed(Channel::Esm, "1:6.6p1-2ubuntu2.13+esm1", None),
        );
        builder.record(
            "14.04",
            "openssh",
            "CVE-2023-38408",
            open(Channel::Archive, OpenKind::Deferred),
        );
        builder.record(
            "14.04",
            "openssh",
            "CVE-2016-10010",
            not_affected(Channel::Archive, "code not present"),
        );
        builder.versions(
            "14.04",
            "openssh",
            ["1:6.6p1-2ubuntu2", "1:6.6p1-2ubuntu2.13"],
        );
        builder.record(
            "22.04",
            "openssh",
            "CVE-2023-38408",
            fixed(Channel::Archive, "1:8.9p1-3ubuntu0.3", None),
        );
        builder.priority(None, "CVE-2023-38408", "medium");
        builder.priority(Some("22.04"), "CVE-2023-38408", "high");
        builder.dated("2026-09-22T18:02:37Z");
        builder.dated("2025-01-01T00:00:00Z");
        builder.finish()
    }

    /// A release can hold one verdict per channel on the same vulnerability,
    /// and a lookup hands back both: no fix in the archive and a fix in ESM
    /// are two facts about two kinds of machine.
    #[test]
    fn a_release_holds_a_verdict_per_channel() {
        let data = sample();
        let statuses = data.statuses("14.04", "openssh", "CVE-2023-38408");
        assert_eq!(statuses.len(), 2, "{statuses:?}");
        assert!(statuses.contains(&fixed(Channel::Esm, "1:6.6p1-2ubuntu2.13+esm1", None)));
        assert!(statuses.contains(&open(Channel::Archive, OpenKind::Deferred)));

        // Keyed by release: 16.04 has no verdict, 22.04 its own.
        assert!(
            data.statuses("16.04", "openssh", "CVE-2023-38408")
                .is_empty()
        );
        assert_eq!(
            data.statuses("22.04", "openssh", "CVE-2023-38408"),
            &[fixed(Channel::Archive, "1:8.9p1-3ubuntu0.3", None)]
        );
        assert!(
            data.statuses("14.04", "apache2", "CVE-2023-38408")
                .is_empty()
        );
    }

    /// Precedence does not depend on arrival order: a fix outranks an open
    /// verdict and "not affected" in either order, "not affected" outranks an
    /// open one, and of two fixes the later version stands.
    #[test]
    fn precedence_between_verdicts_ignores_arrival_order() {
        let cases = [
            (
                fixed(Channel::Archive, "1:1.0-1", None),
                open(Channel::Archive, OpenKind::Needed),
            ),
            (
                fixed(Channel::Archive, "1:1.0-1", None),
                not_affected(Channel::Archive, "not present"),
            ),
            (
                not_affected(Channel::Archive, "not present"),
                open(Channel::Archive, OpenKind::Needed),
            ),
            (
                fixed(Channel::Archive, "1:1.0-1ubuntu0.10", None),
                fixed(Channel::Archive, "1:1.0-1ubuntu0.9", None),
            ),
        ];
        for (winner, loser) in cases {
            for order in [[&winner, &loser], [&loser, &winner]] {
                let mut builder = Builder::new(Distributor::Ubuntu);
                for status in order {
                    builder.record("20.04", "pkg", "CVE-2020-0001", status.clone());
                }
                let data = builder.finish();
                assert_eq!(
                    data.statuses("20.04", "pkg", "CVE-2020-0001"),
                    std::slice::from_ref(&winner),
                    "{winner:?} over {loser:?}"
                );
            }
        }
    }

    /// The lineage holds every version the data named, fix versions
    /// included, in dpkg's order rather than the order they arrived in.
    #[test]
    fn a_lineage_is_every_named_version_in_package_order() {
        let data = sample();
        let lineage = data.lineage("14.04", "openssh").expect("a lineage");
        assert_eq!(
            lineage.versions(),
            &[
                "1:6.6p1-2ubuntu2",
                "1:6.6p1-2ubuntu2.7",
                "1:6.6p1-2ubuntu2.13",
                "1:6.6p1-2ubuntu2.13+esm1",
            ]
        );
        assert!(data.lineage("14.04", "apache2").is_none());
    }

    /// A revision places a build in the release whose package had it, with
    /// the full version it belongs to, and the releases list what is held.
    #[test]
    fn a_revision_places_a_build_in_its_release() {
        let data = sample();
        assert_eq!(
            data.builds_with_revision("openssh", "2ubuntu2.13"),
            vec![("14.04", "1:6.6p1-2ubuntu2.13")]
        );
        assert_eq!(
            data.builds_with_revision("openssh", "3ubuntu0.3"),
            vec![("22.04", "1:8.9p1-3ubuntu0.3")]
        );
        // `2ubuntu2` is a prefix of `2ubuntu2.13` and a revision of its own.
        assert_eq!(
            data.builds_with_revision("openssh", "2ubuntu2"),
            vec![("14.04", "1:6.6p1-2ubuntu2")]
        );
        assert!(data.builds_with_revision("openssh", "2ubuntu9").is_empty());
        assert!(
            data.builds_with_revision("apache2", "2ubuntu2.13")
                .is_empty()
        );
        assert_eq!(data.releases().collect::<Vec<_>>(), ["14.04", "22.04"]);
    }

    /// A per-release priority answers for its release, the general one for
    /// every other.
    #[test]
    fn a_priority_is_answered_where_the_data_gives_one() {
        let data = sample();
        assert_eq!(data.priority(Some("22.04"), "CVE-2023-38408"), Some("high"));
        assert_eq!(
            data.priority(Some("14.04"), "CVE-2023-38408"),
            Some("medium")
        );
        assert_eq!(data.priority(None, "CVE-2023-38408"), Some("medium"));
        assert_eq!(data.priority(None, "CVE-2016-1908"), None);
    }

    /// The identity is the distributor's and the version the newest record's
    /// date, so two conversions of one feed carry the same one.
    #[test]
    fn a_dataset_names_its_distributor_and_dates_itself() {
        let data = sample();
        assert_eq!(data.id(), "ubuntu:security-notices");
        assert_eq!(data.distributor(), "ubuntu");
        assert_eq!(data.version(), Version::new(2026, 9, 22));
        assert_eq!(data.len(), 4);
        assert!(!data.is_empty());

        let debian = Builder::new(Distributor::Debian).finish();
        assert_eq!(debian.id(), "debian:security-tracker");
        assert_eq!(debian.version(), Version::new(0, 0, 0));
        assert!(debian.is_empty());
    }

    /// Everything survives the serialized form, the hash with it, and the
    /// bytes are the same each time the same data is written.
    #[test]
    fn the_serialized_form_round_trips_exactly() {
        let data = sample();
        let bytes = data.to_bytes();
        assert_eq!(
            bytes,
            sample().to_bytes(),
            "the same data writes the same bytes"
        );

        let read = Advisories::from_bytes(&bytes).expect("reads back");
        assert_eq!(read.to_bytes(), bytes);
        assert_eq!(read.content_hash(), data.content_hash());
        assert_eq!(read.version(), data.version());
        assert_eq!(read.id(), data.id());
        for (release, package, cve) in [
            ("14.04", "openssh", "CVE-2023-38408"),
            ("14.04", "openssh", "CVE-2016-10010"),
            ("14.04", "openssh", "CVE-2016-1908"),
            ("22.04", "openssh", "CVE-2023-38408"),
        ] {
            assert_eq!(
                read.statuses(release, package, cve),
                data.statuses(release, package, cve)
            );
        }
        assert_eq!(
            read.lineage("14.04", "openssh"),
            data.lineage("14.04", "openssh")
        );
        assert_eq!(read.priority(Some("22.04"), "CVE-2023-38408"), Some("high"));
    }

    /// A different dataset has a different hash.
    #[test]
    fn the_content_hash_tells_two_datasets_apart() {
        let mut builder = Builder::new(Distributor::Ubuntu);
        builder.record(
            "14.04",
            "openssh",
            "CVE-2016-1908",
            fixed(Channel::Archive, "1:6.6p1-2ubuntu2.8", None),
        );
        assert_ne!(builder.finish().content_hash(), sample().content_hash());
    }

    /// Bytes that are not a dataset, or are one in a form this engine does
    /// not read, are refused with the reason rather than misread.
    #[test]
    fn unreadable_bytes_are_refused_with_the_reason() {
        let bytes = sample().to_bytes();

        assert!(matches!(
            Advisories::from_bytes(b"not a dataset at all"),
            Err(AdvisoriesError::NotAdvisories)
        ));

        let mut newer = bytes.clone();
        newer[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&(FORMAT + 1).to_le_bytes());
        assert!(matches!(
            Advisories::from_bytes(&newer),
            Err(AdvisoriesError::UnsupportedFormat { found, supported })
                if found == FORMAT + 1 && supported == FORMAT
        ));

        assert!(matches!(
            Advisories::from_bytes(&bytes[..bytes.len() - 3]),
            Err(AdvisoriesError::Malformed(_))
        ));
        assert!(matches!(
            Advisories::from_bytes(&bytes[..MAGIC.len() + 1]),
            Err(AdvisoriesError::Malformed(_))
        ));

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            Advisories::from_bytes(&trailing),
            Err(AdvisoriesError::Malformed(_))
        ));
    }

    /// A body whose indices point past its pool is malformed, not a panic.
    #[test]
    fn an_index_past_the_pool_is_malformed() {
        let mut wire = sample().to_wire();
        wire.pool.truncate(1);
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&FORMAT.to_le_bytes());
        bytes.extend_from_slice(&options().serialize(&wire).expect("serializes"));
        assert!(matches!(
            Advisories::from_bytes(&bytes),
            Err(AdvisoriesError::Malformed(_))
        ));
    }

    /// A length prefix claiming more than the bound is refused before
    /// anything that large is allocated, and so are bytes past the bound.
    #[test]
    fn the_input_is_bounded() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&FORMAT.to_le_bytes());
        // The distributor, then a version, then a pool claiming 2^60 strings.
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes.push(253);
        bytes.extend_from_slice(&(1u64 << 60).to_le_bytes());
        assert!(matches!(
            Advisories::from_bytes(&bytes),
            Err(AdvisoriesError::Malformed(_))
        ));

        let huge = vec![0u8; MAX_BYTES as usize + 1];
        assert!(matches!(
            Advisories::from_bytes(&huge),
            Err(AdvisoriesError::TooLarge { .. })
        ));
    }
}
