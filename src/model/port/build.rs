// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Who built the software, and which build it is
//!
//! A version says which release of the source a program was built from. It
//! does not say which fixes the program carries, and for most software on a
//! Linux server those are two different questions: a distribution fixes a
//! vulnerability by applying the patch to the release it already ships and
//! publishing a new *package* revision, leaving the upstream version where it
//! was. `OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13` is OpenSSH 6.6.1p1 as Ubuntu 14.04
//! last built it, and carries every fix Ubuntu made to 6.6 up to that build.
//!
//! So a vulnerability database keyed on the upstream version answers the wrong
//! question about it, confidently. The [`Build`] a service carries is what lets
//! the right question be asked: it names the [`Distributor`] whose fix data
//! applies, the package revision that fixes are published against, and the
//! [`Release`] whose fix data applies, since the same revision means nothing
//! outside the release it was published for.
//!
//! ## Each part is optional except the distributor
//!
//! A banner states as much as its daemon chose to. An OpenSSH banner on Debian
//! or Ubuntu carries the whole revision; `Server: Apache/2.4.7 (Ubuntu)` says
//! only who packaged it. That is still worth recording, and it is the more
//! common case: it separates *this is the upstream release* from *this is a
//! distribution's build whose patch level is not visible*, and a report
//! owes its reader that distinction even where it can go no further.
//!
//! ## Where the release comes from
//!
//! Recorded with the [`ReleaseBasis`] it rests on, because the sources differ in
//! strength. A revision that encodes its release (`+deb12u3`,
//! `0ubuntu0.22.04.1`) states it; a rule that maps a whole banner to a release
//! infers it from what that release shipped. Where two sources disagree the
//! release is left unknown rather than chosen, since both answers are about the
//! same build and one of them has to be wrong.

use std::sync::Arc;

/// Who built and packaged the software.
///
/// The distributions whose builds a service banner names often enough to be
/// worth telling apart. Debian's and Ubuntu's banners carry package revisions
/// and both publish per-release fix data; the rest are recorded so a report
/// can say a service is a distribution build even where no data can place
/// the build further.
///
/// The enum is `#[non_exhaustive]` so that adding a distributor costs a
/// recompile rather than a major version; [`ALL`](Self::ALL) is the list to
/// iterate.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum Distributor {
    /// Debian.
    Debian,
    /// Ubuntu.
    Ubuntu,
    /// Raspberry Pi OS, built from Debian's sources with Debian's revisions.
    Raspbian,
    /// Red Hat Enterprise Linux.
    RedHat,
    /// CentOS.
    CentOs,
    /// Fedora.
    Fedora,
    /// Amazon Linux.
    Amazon,
    /// Rocky Linux.
    Rocky,
    /// AlmaLinux.
    Alma,
    /// Oracle Linux.
    Oracle,
    /// SUSE Linux Enterprise and openSUSE.
    Suse,
    /// Alpine Linux.
    Alpine,
    /// FreeBSD's base system.
    FreeBsd,
}

impl Distributor {
    /// Every distributor, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Debian,
        Self::Ubuntu,
        Self::Raspbian,
        Self::RedHat,
        Self::CentOs,
        Self::Fedora,
        Self::Amazon,
        Self::Rocky,
        Self::Alma,
        Self::Oracle,
        Self::Suse,
        Self::Alpine,
        Self::FreeBsd,
    ];

    /// The name a person reads.
    ///
    /// Separate from the wire name in [`record::wire`](crate::record::wire),
    /// as every model enum's label is: this one may be reworded, that one may
    /// not.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Debian => "Debian",
            Self::Ubuntu => "Ubuntu",
            Self::Raspbian => "Raspbian",
            Self::RedHat => "Red Hat",
            Self::CentOs => "CentOS",
            Self::Fedora => "Fedora",
            Self::Amazon => "Amazon Linux",
            Self::Rocky => "Rocky Linux",
            Self::Alma => "AlmaLinux",
            Self::Oracle => "Oracle Linux",
            Self::Suse => "SUSE",
            Self::Alpine => "Alpine",
            Self::FreeBsd => "FreeBSD",
        }
    }

    /// The distributor a banner or a rule names, spelled as banners spell it.
    ///
    /// Case-insensitive, and accepting the spellings daemons actually print:
    /// `Ubuntu` in an OpenSSH comment, `Red Hat Enterprise Linux` in an Apache
    /// `Server` header, `CentOS` in both. [`None`] for anything else, which is
    /// how a word in the same position that names no distributor (`Unix`,
    /// `Win64`, an HPN patch tag) is told apart from one that does.
    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.trim().to_ascii_lowercase();
        Some(match name.as_str() {
            "debian" => Self::Debian,
            "ubuntu" => Self::Ubuntu,
            "raspbian" | "raspberry pi os" => Self::Raspbian,
            "red hat" | "redhat" | "red hat enterprise linux" | "rhel" => Self::RedHat,
            "centos" | "centos linux" | "centos stream" => Self::CentOs,
            "fedora" => Self::Fedora,
            "amazon" | "amazon linux" => Self::Amazon,
            "rocky" | "rocky linux" => Self::Rocky,
            "alma" | "almalinux" => Self::Alma,
            "oracle" | "oracle linux" => Self::Oracle,
            "suse" | "sles" | "opensuse" => Self::Suse,
            "alpine" | "alpine linux" => Self::Alpine,
            "freebsd" => Self::FreeBsd,
            _ => return None,
        })
    }

    /// Whether this distributor's revisions follow Debian's grammar, which is
    /// what makes a revision comparable against published fix versions.
    pub const fn uses_debian_revisions(self) -> bool {
        matches!(self, Self::Debian | Self::Ubuntu | Self::Raspbian)
    }
}

/// Which of a distributor's releases a build belongs to, and what says so.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Release {
    name: Arc<str>,
    basis: ReleaseBasis,
}

impl Release {
    /// A release named as the distributor numbers it: `14.04` or `22.04` for
    /// Ubuntu, `12` for Debian. Numbers rather than codenames, because they
    /// order and a codename does not.
    pub fn new(name: impl Into<Arc<str>>, basis: ReleaseBasis) -> Self {
        Self {
            name: name.into(),
            basis,
        }
    }

    /// The release, as the distributor numbers it.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What established it.
    pub fn basis(&self) -> ReleaseBasis {
        self.basis
    }
}

/// What a [`Release`] was read from.
///
/// `#[non_exhaustive]`, like the other model enums.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum ReleaseBasis {
    /// A fingerprint rule that maps the whole banner to the release that
    /// shipped it. An inference from what the release carried: a later
    /// release that happened to ship the same upstream version would read the
    /// same.
    Banner,
    /// The package revision, which names its release outright, as Debian's
    /// stable updates (`+deb12u3`) and some of Ubuntu's (`0ubuntu0.22.04.1`)
    /// do.
    Revision,
}

impl ReleaseBasis {
    /// Every basis, weakest first.
    pub const ALL: &'static [Self] = &[Self::Banner, Self::Revision];
}

/// A distributor's build of the software behind a service.
///
/// See the [module documentation](self) for why a service needs one.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Build {
    distributor: Distributor,
    revision: Option<Arc<str>>,
    release: Option<Release>,
}

impl Build {
    /// A build by `distributor`, with nothing known beyond who made it.
    pub fn new(distributor: Distributor) -> Self {
        Self {
            distributor,
            revision: None,
            release: None,
        }
    }

    /// Who built it.
    pub fn distributor(&self) -> Distributor {
        self.distributor
    }

    /// The package revision, where the banner stated one: `2ubuntu2.13`,
    /// `2+deb12u3`. For FreeBSD's base system, the date stamp its banners carry.
    pub fn revision(&self) -> Option<&str> {
        self.revision.as_deref()
    }

    /// Which release the build belongs to, where anything said.
    pub fn release(&self) -> Option<&Release> {
        self.release.as_ref()
    }

    /// Records the package revision, and the release it names if it names
    /// one.
    ///
    /// The release is read off the revision here rather than left to the
    /// caller, so no build can carry a revision that states its release and
    /// a release that contradicts it. Where the build already holds a release
    /// from a weaker source and the revision names another, the release is
    /// cleared: see [`with_release`](Self::with_release).
    pub fn with_revision(mut self, revision: impl Into<Arc<str>>) -> Self {
        let revision = revision.into();
        let stated = release_in_revision(self.distributor, &revision);
        self.revision = Some(revision);
        if let Some(stated) = stated {
            self = self.with_release(Release::new(stated, ReleaseBasis::Revision));
        }
        self
    }

    /// Records the release, reconciling it with one already held.
    ///
    /// Agreement keeps the stronger basis. Disagreement clears the release,
    /// because both readings are of the same build and one of them is wrong:
    /// guessing between them would put fix data for the wrong release behind
    /// every verdict drawn from it, which is a worse report than one that says
    /// the release is not known.
    pub fn with_release(mut self, release: Release) -> Self {
        self.release = match self.release.take() {
            None => Some(release),
            Some(held) if held.name == release.name => Some(if release.basis > held.basis {
                release
            } else {
                held
            }),
            Some(_) => None,
        };
        self
    }

    /// The build in one phrase, for a person: `Ubuntu 14.04 2ubuntu2.13`,
    /// `Debian 12`, `Ubuntu` where only the distributor is known.
    pub fn describe(&self) -> String {
        let mut text = self.distributor.label().to_owned();
        if let Some(release) = &self.release {
            text.push(' ');
            text.push_str(release.name());
        }
        if let Some(revision) = &self.revision {
            text.push(' ');
            text.push_str(revision);
        }
        text
    }

    /// Folds another account of the same build into this one.
    ///
    /// Only an account naming the same distributor contributes, and it fills
    /// what this one lacks: a banner that stated the revision and a rule that
    /// named the release describe one build between them. An account naming a
    /// different distributor describes a different build and contributes
    /// nothing; which of two such accounts a service keeps is
    /// [`Service::merge`](super::Service::merge)'s decision, by confidence.
    pub fn merge(&mut self, other: Build) {
        if other.distributor != self.distributor {
            return;
        }
        let Build {
            revision, release, ..
        } = other;
        if self.revision.is_none()
            && let Some(revision) = revision
        {
            *self = self.clone().with_revision(revision);
        }
        if let Some(release) = release {
            *self = self.clone().with_release(release);
        }
    }
}

/// The release a package revision names, where it names one.
///
/// Two conventions are read, both of which put the release into the revision
/// precisely so that one source version can be published to several releases
/// without two packages sharing a version:
///
/// - Debian's stable and security updates append `+debNuM` (`2+deb12u3`), and
///   backports append `~bpoN` (`1~bpo12+1`); the number is the release.
/// - Ubuntu's updates to a version shared across releases append the release
///   after `ubuntu0.` (`0ubuntu0.22.04.1`), and backports and PPAs after a
///   tilde (`1~22.04.1`).
///
/// Most Ubuntu revisions (`3ubuntu0.10`, `2ubuntu2.13`) name no release, and
/// for those this answers [`None`]: the release then has to come from
/// somewhere else, or stay unknown.
fn release_in_revision(distributor: Distributor, revision: &str) -> Option<String> {
    match distributor {
        Distributor::Debian | Distributor::Raspbian => {
            debian_release_after(revision, "deb").or_else(|| debian_release_after(revision, "bpo"))
        }
        Distributor::Ubuntu => ubuntu_release_after(revision, "ubuntu0.")
            .or_else(|| ubuntu_release_after(revision, "~")),
        _ => None,
    }
}

/// The digits after the last `+<marker>` or `~<marker>` in a Debian revision,
/// where they end the marker's number: `2+deb12u3` gives `12`.
fn debian_release_after(revision: &str, marker: &str) -> Option<String> {
    revision
        .match_indices(marker)
        .filter(|(at, _)| *at > 0 && matches!(revision.as_bytes()[at - 1], b'+' | b'~'))
        .filter_map(|(at, _)| {
            let digits: String = revision[at + marker.len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            (!digits.is_empty()).then_some(digits)
        })
        .last()
        .map(|digits| digits.trim_start_matches('0').to_owned())
        .filter(|release| !release.is_empty())
}

/// An Ubuntu release (`NN.NN`) directly after `marker` in a revision:
/// `0ubuntu0.22.04.1` after `ubuntu0.` gives `22.04`.
fn ubuntu_release_after(revision: &str, marker: &str) -> Option<String> {
    revision.match_indices(marker).find_map(|(at, _)| {
        let rest = &revision.as_bytes()[at + marker.len()..];
        let shaped = rest.len() >= 5
            && rest[..2].iter().all(u8::is_ascii_digit)
            && rest[2] == b'.'
            && rest[3..5].iter().all(u8::is_ascii_digit)
            && rest.get(5).is_none_or(|next| !next.is_ascii_digit());
        // Ubuntu has released every April and October since 2004, so a
        // release is `YY.04` or `YY.10`; anything else in that position is a
        // version that happens to have the same shape.
        let month = &rest.get(3..5)?;
        (shaped && matches!(*month, b"04" | b"10"))
            .then(|| String::from_utf8_lossy(&rest[..5]).into_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A banner's comment spells its distributor the way the daemon's packager
    /// wrote it, and an Apache `Server` header spells Red Hat's in full. Every
    /// spelling a real banner uses has to land on one distributor, and a word
    /// in the same position that names none has to land on nothing.
    #[test]
    fn distributors_are_read_as_banners_spell_them_and_nothing_else_is() {
        assert_eq!(Distributor::from_name("Ubuntu"), Some(Distributor::Ubuntu));
        assert_eq!(Distributor::from_name("debian"), Some(Distributor::Debian));
        assert_eq!(
            Distributor::from_name("Red Hat Enterprise Linux"),
            Some(Distributor::RedHat)
        );
        assert_eq!(Distributor::from_name("CentOS"), Some(Distributor::CentOs));
        assert_eq!(
            Distributor::from_name("FreeBSD"),
            Some(Distributor::FreeBsd)
        );
        for not_one in ["Unix", "Win64", "hpn13v11", "", "OpenSSL"] {
            assert_eq!(Distributor::from_name(not_one), None, "{not_one:?}");
        }
        for distributor in Distributor::ALL {
            assert_eq!(
                Distributor::from_name(distributor.label()),
                Some(*distributor),
                "the label reads back as the distributor it labels"
            );
        }
    }

    /// Debian names the release its stable updates were built for in the
    /// revision, and that is the one statement about a build that cannot be
    /// wrong about which release it is.
    #[test]
    fn a_debian_revision_names_its_release() {
        let release = |revision: &str| {
            Build::new(Distributor::Debian)
                .with_revision(revision)
                .release()
                .map(|release| (release.name().to_owned(), release.basis()))
        };
        assert_eq!(
            release("2+deb12u3"),
            Some(("12".into(), ReleaseBasis::Revision))
        );
        assert_eq!(
            release("5+deb11u10"),
            Some(("11".into(), ReleaseBasis::Revision))
        );
        assert_eq!(
            release("1~bpo12+1"),
            Some(("12".into(), ReleaseBasis::Revision))
        );
        assert_eq!(release("1:9.2p1-2"), None, "a revision naming no release");
        assert_eq!(release("7"), None);
    }

    /// Ubuntu's updates to a version several releases share name the release
    /// after `ubuntu0.`; its ordinary revisions name none, and reading a
    /// version-shaped number out of one would invent a release.
    #[test]
    fn an_ubuntu_revision_names_its_release_only_where_it_states_one() {
        let release = |revision: &str| {
            Build::new(Distributor::Ubuntu)
                .with_revision(revision)
                .release()
                .map(|release| release.name().to_owned())
        };
        assert_eq!(release("0ubuntu0.22.04.1").as_deref(), Some("22.04"));
        assert_eq!(release("0ubuntu0.18.04.1").as_deref(), Some("18.04"));
        assert_eq!(release("1~20.10.1").as_deref(), Some("20.10"));
        assert_eq!(release("2ubuntu2.13"), None);
        assert_eq!(release("3ubuntu0.10"), None);
        assert_eq!(release("4ubuntu0.13"), None);
        assert_eq!(release("0ubuntu0.12.34.1"), None, "not an April or October");
    }

    /// Two sources naming the same release is corroboration and keeps the
    /// stronger basis; two naming different releases is a contradiction about
    /// one build, and the release becomes unknown rather than a coin toss.
    #[test]
    fn a_release_two_sources_disagree_about_is_unknown() {
        let agreed = Build::new(Distributor::Debian)
            .with_release(Release::new("12", ReleaseBasis::Banner))
            .with_revision("2+deb12u3");
        assert_eq!(
            agreed.release().map(Release::basis),
            Some(ReleaseBasis::Revision),
            "agreement keeps the stronger basis"
        );

        let contradicted = Build::new(Distributor::Debian)
            .with_release(Release::new("11", ReleaseBasis::Banner))
            .with_revision("2+deb12u3");
        assert_eq!(contradicted.release(), None);
        assert_eq!(
            contradicted.revision(),
            Some("2+deb12u3"),
            "the revision stands"
        );
    }

    /// One banner stating the revision and a rule naming the release are two
    /// halves of one build's description, and only an account of the same
    /// distributor's build may complete it.
    #[test]
    fn a_merge_completes_a_build_only_from_the_same_distributors_account() {
        let mut build = Build::new(Distributor::Ubuntu).with_revision("2ubuntu2.13");
        build.merge(
            Build::new(Distributor::Ubuntu)
                .with_release(Release::new("14.04", ReleaseBasis::Banner)),
        );
        assert_eq!(build.release().map(Release::name), Some("14.04"));

        build.merge(
            Build::new(Distributor::Debian)
                .with_release(Release::new("12", ReleaseBasis::Revision)),
        );
        assert_eq!(
            build.release().map(Release::name),
            Some("14.04"),
            "another distributor's account describes another build"
        );
    }
}
