// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Debian's security tracker
//!
//! Turns the JSON the Debian security tracker publishes into the
//! [`Advisories`] the correlator judges a Debian build against. The tracker
//! holds, for every source package and every CVE, a verdict per supported
//! release: resolved at a version, resolved at `0` (never affected), open, or
//! not yet determined, with the version each of the release's repositories
//! carries.
//!
//! ```no_run
//! use std::fs::File;
//! use std::io::BufReader;
//!
//! let file = File::open("debian-security-tracker.json")?;
//! let advisories = zond_engine::import::debian::read(&mut BufReader::new(file))?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## What becomes what
//!
//! - `resolved` at `fixed_version` `0` is **not affected**: Debian's way of
//!   saying the release never carried the code.
//! - `resolved` at any other version is **fixed** from that version on.
//! - `open` is **open**, as needing a fix unless the tracker says no advisory
//!   will be issued (`nodsa`): then it is **deferred**, the fix left to a point
//!   release, or **ignored** where the reason says so, with the reason kept.
//!   An open issue rated `unimportant`, or in a package past its support, is
//!   **ignored** too: nothing will be fixed through a security update.
//! - `undetermined` is **open, needing triage**.
//!
//! The tracker's `urgency` becomes the distributor's priority for that release (not a
//! severity), and every version its repositories name joins the release's lineage. Its
//! `scope` is dropped: it reads `local` on nearly every record, network daemons included.
//!
//! ## Filtered, and streamed
//!
//! The document is close to eighty megabytes covering every package in Debian, and a scan
//! can only ask about the few hundred source packages the engine's map names. The
//! top-level object is walked one package at a time and packages outside the map are
//! skipped unread, so peak memory is what survives the filter.
//!
//! ## Undated
//!
//! The tracker's JSON carries no timestamp, so a dataset read from it is
//! version `0.0.0`. Its content hash still tells two conversions of different
//! data apart.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{BufReader, Read};
use std::time::SystemTime;

use serde::Deserialize;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};

use crate::cve::Advisories;
use crate::cve::advisories::{Builder, Channel, Distributor, OpenKind, Standing, Status};
use crate::import::{ImportError, ImportOrigin};

/// The most of the tracker's JSON this reads.
///
/// The document is under a hundred megabytes; a thousand means a source that does not
/// end, refused before it is read to the end.
const MAX_TRACKER_BYTES: u64 = 1024 * 1024 * 1024;

/// Debian's codenames and the release numbers they stand for, oldest first.
///
/// Advisories are keyed by number, as banners and lookups name releases. The rolling
/// unstable distribution has no number and keeps its name, `sid`.
const CODENAMES: &[(&str, &str)] = &[
    ("buzz", "1.1"),
    ("rex", "1.2"),
    ("bo", "1.3"),
    ("hamm", "2.0"),
    ("slink", "2.1"),
    ("potato", "2.2"),
    ("woody", "3.0"),
    ("sarge", "3.1"),
    ("etch", "4"),
    ("lenny", "5"),
    ("squeeze", "6"),
    ("wheezy", "7"),
    ("jessie", "8"),
    ("stretch", "9"),
    ("buster", "10"),
    ("bullseye", "11"),
    ("bookworm", "12"),
    ("trixie", "13"),
    ("forky", "14"),
    ("sid", "sid"),
];

/// The release number a Debian codename stands for.
fn release_of(codename: &str) -> Option<&'static str> {
    CODENAMES
        .iter()
        .find(|(name, _)| *name == codename)
        .map(|(_, number)| *number)
}

/// Reads the Debian security tracker's JSON as a dataset of Debian's
/// verdicts, keeping the source packages the engine's map names.
///
/// The tracker's JSON carries no date, so a dataset read this way is version
/// `0.0.0`; [`read_as_of`] dates it.
///
/// # Errors
///
/// [`ImportError::Malformed`] for JSON that is not the tracker's shape,
/// [`ImportError::DocumentTooLarge`] for a source that does not end, and
/// [`ImportError::Io`] where the read fails.
pub fn read(tracker: &mut dyn Read) -> Result<Advisories, ImportError> {
    read_into(tracker, Builder::new(Distributor::Debian))
}

/// [`read`], dated `as_of`, typically when this copy of the tracker was fetched; the
/// dataset's version then says how current its verdicts are.
///
/// # Errors
///
/// As [`read`].
pub fn read_as_of(tracker: &mut dyn Read, as_of: SystemTime) -> Result<Advisories, ImportError> {
    let mut builder = Builder::new(Distributor::Debian);
    builder.dated(&crate::format::time::rfc3339(as_of));
    read_into(tracker, builder)
}

/// Reads the tracker into `builder`, and finishes it.
fn read_into(tracker: &mut dyn Read, mut builder: Builder) -> Result<Advisories, ImportError> {
    let wanted: BTreeSet<&str> = crate::cve::packages::source_packages("debian").collect();
    super::bounded::within(&mut BufReader::new(tracker), MAX_TRACKER_BYTES, |input| {
        let mut deserializer = serde_json::Deserializer::from_reader(input);
        Tracker {
            wanted: &wanted,
            builder: &mut builder,
        }
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end())
        .map_err(|error| match error.io_error_kind() {
            Some(kind) => ImportError::Io(std::io::Error::new(kind, error.to_string())),
            None => ImportError::Malformed {
                format: "Debian security tracker JSON",
                origin: ImportOrigin::line(error.line() as u64),
                message: error.to_string(),
            },
        })
    })?;
    Ok(builder.finish())
}

/// The top-level object, package by package, recording what it keeps as it
/// goes.
struct Tracker<'a, 'b> {
    wanted: &'a BTreeSet<&'a str>,
    builder: &'b mut Builder,
}

impl<'de> DeserializeSeed<'de> for Tracker<'_, '_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Tracker<'_, '_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the tracker's object of source packages")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(package) = map.next_key::<String>()? {
            if !self.wanted.contains(package.as_str()) {
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            let issues: BTreeMap<String, Issue> = map.next_value()?;
            for (cve, issue) in &issues {
                record(self.builder, &package, cve, issue);
            }
        }
        Ok(())
    }
}

/// One CVE in one source package, as the tracker states it.
#[derive(Deserialize)]
struct Issue {
    #[serde(default)]
    releases: BTreeMap<String, Verdict>,
}

/// The tracker's verdict on one issue in one release.
#[derive(Deserialize)]
struct Verdict {
    status: String,
    #[serde(default)]
    fixed_version: Option<String>,
    #[serde(default)]
    urgency: Option<String>,
    #[serde(default)]
    repositories: BTreeMap<String, String>,
    #[serde(default)]
    nodsa: Option<String>,
    #[serde(default)]
    nodsa_reason: Option<String>,
}

/// Records one issue's verdicts and priorities, and the versions
/// its release's repositories name.
///
/// Only CVEs: the tracker also files issues without one under `TEMP-` names, which no
/// scan finding can refer to.
fn record(builder: &mut Builder, package: &str, cve: &str, issue: &Issue) {
    if !cve.starts_with("CVE-") {
        return;
    }
    for (codename, verdict) in &issue.releases {
        // An unknown release is newer than the table; its verdicts are skipped until the
        // table names it, since no lookup would find them under the codename.
        let Some(release) = release_of(codename) else {
            continue;
        };
        builder.versions(
            release,
            package,
            verdict.repositories.values().map(String::as_str),
        );
        if let Some(urgency) = verdict
            .urgency
            .as_deref()
            // Neither is a rating: one means none yet, the other that the package is
            // out of support.
            .filter(|urgency| !matches!(*urgency, "" | "not yet assigned" | "end-of-life"))
        {
            builder.priority(Some(release), cve, urgency);
        }
        if let Some(standing) = standing(verdict) {
            let status = Status {
                channel: Channel::Archive,
                standing,
                // The tracker's JSON names no DSA or DLA per release.
                advisory: None,
            };
            builder.record(release, package, cve, status);
        }
    }
}

/// What one release's verdict comes to, or `None` for a status this does not read.
fn standing(verdict: &Verdict) -> Option<Standing> {
    match verdict.status.as_str() {
        "resolved" => match verdict.fixed_version.as_deref()? {
            "0" => Some(Standing::NotAffected { reason: None }),
            version => Some(Standing::Fixed {
                version: version.to_string(),
            }),
        },
        "open" => {
            // Why no advisory is planned, in the tracker's words: `Minor
            // issue`, or a reason support ends.
            let note = verdict
                .nodsa
                .as_deref()
                .filter(|text| !text.is_empty())
                .map(str::to_string);
            let kind = match (verdict.nodsa_reason.as_deref(), verdict.urgency.as_deref()) {
                (Some("ignored"), _) => OpenKind::Ignored,
                // No advisory planned; the fix is left to a point release.
                (Some(_), _) => OpenKind::Deferred,
                _ if verdict.nodsa.is_some() => OpenKind::Deferred,
                // Not a security issue, or support has ended: no security update will
                // fix it.
                (None, Some("unimportant" | "end-of-life")) => OpenKind::Ignored,
                (None, _) => OpenKind::Needed,
            };
            Some(Standing::Open { kind, note })
        }
        "undetermined" => Some(Standing::Open {
            kind: OpenKind::NeedsTriage,
            note: None,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed excerpt of the tracker: four `openssh` records, one issue
    /// the tracker files without a CVE, and a package outside the map.
    const FIXTURE: &str = include_str!("../../tests/data/distro/debian-tracker.json");

    fn read_fixture() -> Advisories {
        read(&mut FIXTURE.as_bytes()).expect("the fixture converts")
    }

    fn fixed(version: &str) -> Status {
        Status {
            channel: Channel::Archive,
            standing: Standing::Fixed {
                version: version.to_string(),
            },
            advisory: None,
        }
    }

    /// Bookworm's openssh is fixed from the version the tracker names.
    #[test]
    fn a_resolved_verdict_is_a_fix_at_the_version_named() {
        let data = read_fixture();
        assert_eq!(
            data.statuses("12", "openssh", "CVE-2023-38408"),
            &[fixed("1:9.2p1-2+deb12u1")]
        );
        assert_eq!(
            data.statuses("13", "openssh", "CVE-2023-38408"),
            &[fixed("1:9.3p2-1")]
        );
        assert_eq!(
            data.statuses("sid", "openssh", "CVE-2023-38408"),
            &[fixed("1:9.3p2-1")]
        );
        assert_eq!(data.distributor(), "debian");
        assert_eq!(data.id(), "debian:security-tracker");
    }

    /// Resolved at `0` reads as not affected.
    #[test]
    fn a_fix_at_version_zero_is_not_affected() {
        let data = read_fixture();
        assert_eq!(
            data.statuses("12", "openssh", "CVE-2001-1585"),
            &[Status {
                channel: Channel::Archive,
                standing: Standing::NotAffected { reason: None },
                advisory: None,
            }]
        );
    }

    /// An open issue with no advisory planned is deferred with the tracker's reason; one
    /// rated unimportant is ignored.
    #[test]
    fn open_verdicts_keep_why_they_are_open() {
        let data = read_fixture();
        let statuses = data.statuses("12", "openssh", "CVE-2007-2768");
        assert!(
            matches!(
                statuses,
                [Status {
                    standing: Standing::Open {
                        kind: OpenKind::Ignored,
                        ..
                    },
                    ..
                }]
            ),
            "{statuses:?}"
        );
        assert_eq!(
            data.statuses("12", "openssh", "CVE-2026-55654"),
            &[Status {
                channel: Channel::Archive,
                standing: Standing::Open {
                    kind: OpenKind::Deferred,
                    note: Some("Minor issue".to_string()),
                },
                advisory: None,
            }]
        );
    }

    /// The repositories' versions are the release's lineage, and the urgency
    /// its priority.
    #[test]
    fn repositories_and_urgency_are_kept() {
        let data = read_fixture();
        let lineage = data.lineage("12", "openssh").expect("a lineage");
        for version in [
            "1:9.2p1-2+deb12u1",
            "1:9.2p1-2+deb12u9",
            "1:9.2p1-2+deb12u10",
        ] {
            assert!(
                lineage.versions().iter().any(|v| v == version),
                "{version} in {lineage:?}"
            );
        }
        assert_eq!(
            data.priority(Some("12"), "CVE-2007-2768"),
            Some("unimportant")
        );
        assert_eq!(data.priority(Some("12"), "CVE-2023-38408"), None);
    }

    /// Packages outside the map are skipped unread, and the tracker's
    /// non-CVE issues are not filed.
    #[test]
    fn only_mapped_packages_and_cves_are_kept() {
        let data = read_fixture();
        assert!(data.lineage("12", "7zip").is_none());
        assert!(data.statuses("12", "7zip", "CVE-2022-47111").is_empty());
        assert!(
            data.statuses("12", "apache2", "TEMP-0535886-8B62DC")
                .is_empty()
        );
    }

    /// Every codename the fixture uses maps to a release number.
    #[test]
    fn every_codename_in_the_tracker_maps_to_a_release() {
        let document: serde_json::Value = serde_json::from_str(FIXTURE).expect("JSON");
        let mut codenames = BTreeSet::new();
        for issues in document.as_object().expect("an object").values() {
            for issue in issues.as_object().expect("an object").values() {
                codenames.extend(issue["releases"].as_object().expect("releases").keys());
            }
        }
        assert!(codenames.len() >= 4, "{codenames:?}");
        for codename in codenames {
            assert!(release_of(codename).is_some(), "{codename}");
        }
        assert_eq!(release_of("bookworm"), Some("12"));
        assert_eq!(release_of("sid"), Some("sid"));
        assert_eq!(release_of("duke-to-be"), None);
    }

    /// A document that is not the tracker's shape is refused as malformed.
    #[test]
    fn a_document_of_another_shape_is_malformed() {
        for document in ["[1, 2]", "{\"openssh\": 3}", "{\"openssh\": {} } trailing"] {
            assert!(
                matches!(
                    read(&mut document.as_bytes()),
                    Err(ImportError::Malformed { .. })
                ),
                "{document}"
            );
        }
    }
}
