// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a distributor says about its own build
//!
//! The catalogue says which vulnerabilities an upstream release has. For a
//! distribution's build that is the wrong question: the distributor patches
//! the release it ships and publishes new builds of it, and the version string
//! never moves. What does answer it is the distributor's own record of each
//! vulnerability in each of its releases, which [`Advisories`] holds: fixed
//! from this package version on, never affected, or open.
//!
//! Two steps, and this module is both.
//!
//! **Placing the build.** A verdict is about one release's package, so the
//! build has to be found among them first: the release (from the banner, or
//! failing that from the one release whose package ever carried this
//! revision), the source package the distributor files the software under, and
//! the full package version the host runs. The banner gives the revision and
//! leaves out the epoch and the upstream version as the package spells them
//! (`OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13` is package `1:6.6p1-2ubuntu2.13`), so
//! the version is read off the release's own lineage. A build that cannot be
//! placed is not guessed at; the correlator then says so.
//!
//! **Ruling on each vulnerability.** Against the placed build, in this order:
//! never affected, in any channel, withdraws it; a fix at or below the
//! installed version withdraws it; a fix above it, in the archive every
//! machine can install from, is a vulnerability with a remedy; a fix only in
//! Ubuntu's paid ESM pockets is a vulnerability for any machine without them;
//! a vulnerability the distributor has not fixed in the release is one, fixed
//! nowhere; one it has not yet triaged, or has no record of, stays unsettled.
//! Where the banner hides the patch level (`Apache/2.4.7 (Ubuntu)`), a
//! vulnerability the distributor fixed is unsettled rather than either
//! answer, because the installed build may predate the fix or not.

use std::cmp::Ordering;

use super::advisories::{Advisories, Channel, OpenKind, Standing, Status};
use super::packages::source_package;
use crate::model::port::Build;
use crate::version::{dpkg_cmp, dpkg_revision};

/// A build found among a distributor's releases.
pub(super) struct Placement<'a> {
    /// The dataset that placed it.
    pub(super) advisories: &'a Advisories,
    /// The release, as the distributor numbers it.
    pub(super) release: String,
    /// Whether the release came from the dataset rather than the banner.
    pub(super) release_inferred: bool,
    /// The source package the distributor files the software under.
    pub(super) package: &'static str,
    /// The full package version the host runs, where the banner's revision
    /// says which build it is.
    pub(super) installed: Option<String>,
}

/// Why a build could not be placed, for the excerpt of what is reported
/// instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Unplaced {
    /// No dataset for this distributor was given.
    NoData,
    /// The distributor does not package this software, as far as the map of
    /// source packages knows.
    NotPackaged,
    /// Neither the banner nor the dataset settles which release this is.
    ReleaseUnknown,
    /// The dataset holds nothing for the release: one past its support, or
    /// one it does not cover.
    ReleaseNotCovered(String),
}

impl Unplaced {
    /// Why, as a clause of an excerpt.
    pub(super) fn describe(&self, distributor: &str) -> String {
        match self {
            Self::NoData => format!("no {distributor} advisory data was loaded"),
            Self::NotPackaged => {
                format!("{distributor}'s advisory data does not cover this software")
            }
            Self::ReleaseUnknown => {
                format!("the banner does not say which {distributor} release this is")
            }
            Self::ReleaseNotCovered(release) => {
                format!("{distributor}'s advisory data does not cover release {release}")
            }
        }
    }
}

impl<'a> Placement<'a> {
    /// Places `build`, a build of `vendor_product` at upstream version
    /// `upstream`, among the datasets in `set`.
    pub(super) fn of(
        build: &Build,
        vendor_product: &str,
        upstream: &str,
        set: &'a [Advisories],
    ) -> Result<Self, Unplaced> {
        // Raspberry Pi OS builds Debian's sources with Debian's revisions, and
        // publishes no fix data of its own.
        let distributor = match build.distributor() {
            crate::model::port::Distributor::Ubuntu => "ubuntu",
            crate::model::port::Distributor::Debian | crate::model::port::Distributor::Raspbian => {
                "debian"
            }
            _ => return Err(Unplaced::NoData),
        };
        let advisories = set
            .iter()
            .find(|advisories| advisories.distributor() == distributor)
            .ok_or(Unplaced::NoData)?;
        let package_in =
            |release: &str| source_package(vendor_product, distributor, release, upstream);

        // The release the banner named, or the one release whose package ever
        // carried the banner's revision.
        let (release, release_inferred) = match build.release() {
            Some(release) => (release.name().to_owned(), false),
            None => {
                let revision = build.revision().ok_or(Unplaced::ReleaseUnknown)?;
                let mut found: Vec<&str> = Vec::new();
                for release in advisories.releases() {
                    let Some(package) = package_in(release) else {
                        continue;
                    };
                    for (holding, _) in advisories.builds_with_revision(package, revision) {
                        if holding == release && !found.contains(&holding) {
                            found.push(holding);
                        }
                    }
                }
                match found.as_slice() {
                    [only] => ((*only).to_owned(), true),
                    _ => return Err(Unplaced::ReleaseUnknown),
                }
            }
        };

        let package = package_in(&release).ok_or(Unplaced::NotPackaged)?;
        let lineage = advisories
            .lineage(&release, package)
            .ok_or_else(|| Unplaced::ReleaseNotCovered(release.clone()))?;

        // The build the revision names, from the release's own lineage. Where
        // the lineage lacks it, which a banner from a build the data never
        // listed can do, the version is the release's epoch and upstream with
        // the banner's revision: the release ships one upstream series of the
        // package, and the revision is what orders its builds.
        let installed = build.revision().and_then(|revision| {
            let versions = lineage.versions();
            versions
                .iter()
                .find(|version| dpkg_revision(version) == revision)
                .cloned()
                .or_else(|| {
                    let latest = versions.last()?;
                    let stem = latest.strip_suffix(dpkg_revision(latest))?;
                    Some(format!("{stem}{revision}"))
                })
        });

        Ok(Self {
            advisories,
            release,
            release_inferred,
            package,
            installed,
        })
    }

    /// What the distributor's data says about `cve` for this build.
    pub(super) fn rule(&self, cve: &str) -> Ruling {
        let statuses = self.advisories.statuses(&self.release, self.package, cve);
        if statuses.is_empty() {
            return Ruling::Unsettled(Unsettled::NotTracked);
        }

        // Never affected is a statement about the code, which a channel does
        // not change: whichever channel said it, the build does not carry it.
        if let Some(reason) = statuses.iter().find_map(|status| match &status.standing {
            Standing::NotAffected { reason } => Some(reason.clone()),
            _ => None,
        }) {
            return Ruling::Withdrawn(Withdrawal::NotAffected { reason });
        }

        let fixed_in = |channel: Channel| -> Option<&Status> {
            statuses.iter().find(|status| {
                status.channel == channel && matches!(status.standing, Standing::Fixed { .. })
            })
        };
        let fix = |status: &Status| -> Fix {
            let Standing::Fixed { version } = &status.standing else {
                unreachable!("filtered to fixes")
            };
            Fix {
                version: version.clone(),
                advisory: status.advisory.clone(),
            }
        };

        let judged = |fix: Fix, esm: bool| -> Ruling {
            match &self.installed {
                Some(installed) if dpkg_cmp(installed, &fix.version) != Ordering::Less => {
                    Ruling::Withdrawn(Withdrawal::Fixed {
                        version: fix.version,
                    })
                }
                Some(_) if esm => Ruling::Vulnerable(Vulnerable::EsmOnly(fix)),
                Some(_) => Ruling::Vulnerable(Vulnerable::FixAvailable(fix)),
                None => Ruling::Unsettled(Unsettled::PatchLevelHidden(fix)),
            }
        };

        if let Some(status) = fixed_in(Channel::Archive) {
            return judged(fix(status), false);
        }
        if let Some(status) = fixed_in(Channel::Esm) {
            return judged(fix(status), true);
        }

        // Open in the archive, or in ESM where the archive has no verdict.
        let open = statuses
            .iter()
            .filter_map(|status| match &status.standing {
                Standing::Open { kind, note } => Some((status.channel, *kind, note.clone())),
                _ => None,
            })
            .min_by_key(|(channel, ..)| *channel);
        match open {
            Some((_, OpenKind::NeedsTriage, _)) => Ruling::Unsettled(Unsettled::Untriaged),
            Some((_, kind, note)) => Ruling::Vulnerable(Vulnerable::NoFix { kind, note }),
            None => Ruling::Unsettled(Unsettled::NotTracked),
        }
    }
}

/// A published fix: the first package version carrying it, and the notice
/// that announced it where the data names one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Fix {
    pub(super) version: String,
    pub(super) advisory: Option<String>,
}

/// What the distributor's data concludes about one vulnerability in one
/// placed build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Ruling {
    /// The build does not carry it.
    Withdrawn(Withdrawal),
    /// The build carries it.
    Vulnerable(Vulnerable),
    /// The data does not settle it.
    Unsettled(Unsettled),
}

/// Why a vulnerability is not reported against a build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Withdrawal {
    /// Fixed at or below the installed version.
    Fixed { version: String },
    /// The release never carried it.
    NotAffected { reason: Option<String> },
}

/// A vulnerability the build carries, and whether a fix exists for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Vulnerable {
    /// Fixed in a newer build in the release's archive.
    FixAvailable(Fix),
    /// Fixed only in Ubuntu's ESM pockets, which only a machine with an
    /// Ubuntu Pro subscription receives.
    EsmOnly(Fix),
    /// Not fixed in the release at all.
    NoFix {
        kind: OpenKind,
        note: Option<String>,
    },
}

/// A vulnerability the data leaves open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Unsettled {
    /// Fixed in some build, and the banner does not say which build this is.
    PatchLevelHidden(Fix),
    /// The distributor has not yet judged whether the release is affected.
    Untriaged,
    /// The distributor's data holds nothing on it for this package.
    NotTracked,
}
