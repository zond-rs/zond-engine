// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Ordering version strings
//!
//! One definition of how zond compares two dotted version strings, shared by
//! everything that needs to. Two callers need the same answer today: the [CVE
//! correlator](crate::cve), deciding whether a service version falls in an
//! affected range, and a Tier-1 [detection guard](crate::detect::flow), deciding
//! whether a bound version satisfies a `<`/`>` comparison, and a version that
//! sorted one way for one and another way for the other would be a quiet source
//! of disagreement between two features that are meant to agree.
//!
//! ## The order it imposes
//!
//! Versions are compared component by component. A component's leading run of
//! digits decides first, so `9.10` outranks `9.9` (numerically, 10 > 9) rather
//! than sorting lexically (where `"10" < "9"`); a trailing non-numeric suffix
//! breaks a tie, so OpenSSH's `9.6p1` sorts after a bare `9.6` and before
//! `9.7`. A missing trailing component reads as zero, so `2.14` and `2.14.0`
//! compare equal.
//!
//! ## What a hyphen means
//!
//! Two opposite things, and both are read. `1.0.0-rc1` is a candidate for
//! `1.0.0` and comes **before** it; `1.21.0-1ubuntu2` is nginx 1.21.0 rebuilt
//! by a distribution and comes **after**. A revision starts with a digit and a
//! pre-release identifier does not, which is the rule both ecosystems follow
//! and the only thing available to separate them. See [`split_pre_release`].
//!
//! It is still a lax order, enough to rank the version strings
//! services actually emit rather than a full semver grammar. What it is not is
//! *inverted*: until September 2026 a hyphen was read as a dot throughout, so
//! every pre-release sorted after its own release, and a host running
//! `1.0.0-rc1` against a vulnerability fixed in `1.0.0` was reported not
//! affected. A missing vulnerability is the wrong direction for a scanner to be
//! wrong in, because nobody argues with it.

use std::cmp::Ordering;

/// Compares two dotted versions.
///
/// Component by component, numerically on each component's leading digits and
/// lexically to break a tie, with a missing trailing component reading as zero.
/// A pre-release suffix sorts *before* the version it precedes; see
/// [`split_pre_release`] for how one is told from a package revision.
pub(crate) fn version_cmp(a: &str, b: &str) -> Ordering {
    let (a_release, a_pre) = split_pre_release(a);
    let (b_release, b_pre) = split_pre_release(b);

    let release = components(a_release, b_release);
    if release != Ordering::Equal {
        return release;
    }

    // Equal releases, so the suffix decides. Something is less than nothing
    // here: `1.0.0-rc1` is a candidate for `1.0.0` and comes before it.
    match (a_pre, b_pre) {
        (None, None) => Ordering::Equal,
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (Some(x), Some(y)) => components(x, y),
    }
}

/// A version split into what it releases and what it is a pre-release of, if
/// anything.
///
/// A hyphen means two opposite things and the digit after it is what tells them
/// apart. Debian and Ubuntu put a package revision there, which is a
/// later build of the same source and sorts after the bare version:
/// `1.21.0-1ubuntu2` is nginx 1.21.0 rebuilt, and service banners carry these
/// constantly. Every version grammar that has a pre-release puts it in the same
/// place, and it sorts before: `1.0.0-rc1` precedes `1.0.0`.
///
/// A revision starts with a digit and a pre-release identifier does not, which
/// is the rule both ecosystems already follow and the only thing available to
/// separate them here.
///
/// This split did not exist until September 2026: `-` was treated as `.`
/// throughout, so a non-numeric component sorted after a numeric one and every
/// pre-release read as *later* than its own release. The
/// [CVE correlator](crate::cve) reads this ordering directly, so a host running
/// `1.0.0-rc1` against a vulnerability fixed in `1.0.0` was reported not
/// affected.
fn split_pre_release(version: &str) -> (&str, Option<&str>) {
    let mut from = 0;
    while let Some(at) = version[from..].find('-') {
        let at = from + at;
        let rest = &version[at + 1..];
        if !rest.starts_with(|c: char| c.is_ascii_digit()) {
            return (&version[..at], Some(rest));
        }
        from = at + 1;
    }
    (version, None)
}

/// Compares two dotted strings component by component, treating a missing
/// trailing component as zero so `2.14` and `2.14.0` compare equal.
///
/// The leading digits of a component decide first, so `9.10` outranks `9.9`
/// where a lexical order would not, and a trailing suffix breaks a tie so
/// OpenSSH's `9.6p1` sorts after a bare `9.6`.
fn components(a: &str, b: &str) -> Ordering {
    let a: Vec<&str> = a.split(['.', '-']).collect();
    let b: Vec<&str> = b.split(['.', '-']).collect();

    for index in 0..a.len().max(b.len()) {
        let x = a.get(index).copied().unwrap_or("0");
        let y = b.get(index).copied().unwrap_or("0");
        let ordering = leading_number(x)
            .cmp(&leading_number(y))
            .then_with(|| x.cmp(y));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

/// The value of the leading run of ASCII digits in `component`, or 0 where it
/// does not start with one, so `6p1` reads as 6 and `p1` as 0.
///
/// A run too long for a `u64` saturates rather than reading as zero. Nothing
/// emits a version component of eighteen quintillion, and a number that large
/// sorting *below* every real one is the wrong way for it to be wrong.
fn leading_number(component: &str) -> u64 {
    let digits = component
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap_or("");

    match digits.parse() {
        Ok(value) => value,
        Err(_) if digits.is_empty() => 0,
        Err(_) => u64::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hyphen means two opposite things, and both readings have to survive.
    ///
    /// A pre-release comes before the version it is a candidate for; a package
    /// revision is a later build of the same source and comes after. Both are
    /// written `x.y.z-something` and the digit after the hyphen is all there is
    /// to tell them apart.
    #[test]
    fn a_pre_release_precedes_its_version_and_a_revision_follows_it() {
        for pre in ["1.0.0-alpha", "1.0.0-rc1", "1.0.0-beta.2", "2.4.1-dev"] {
            let release = pre.split('-').next().expect("a release part");
            assert_eq!(
                version_cmp(pre, release),
                Ordering::Less,
                "{pre} is a candidate for {release} and comes before it"
            );
        }

        // Debian and Ubuntu put a package revision here, and it is a later
        // build of the same source.
        assert_eq!(version_cmp("1.21.0-1ubuntu2", "1.21.0"), Ordering::Greater);
        assert_eq!(version_cmp("1.21.0-3", "1.21.0-2"), Ordering::Greater);
    }

    /// Two pre-releases of one version order among themselves, so `rc2` is not
    /// merely "some suffix" beside `rc1`.
    #[test]
    fn pre_releases_of_one_version_are_ordered_against_each_other() {
        assert_eq!(version_cmp("1.0.0-alpha", "1.0.0-beta"), Ordering::Less);
        assert_eq!(version_cmp("1.0.0-rc1", "1.0.0-rc2"), Ordering::Less);
        assert_eq!(version_cmp("1.0.0-alpha", "1.0.0-alpha"), Ordering::Equal);
    }

    /// A pre-release is still after everything the release is after.
    #[test]
    fn a_pre_release_still_outranks_an_earlier_version() {
        assert_eq!(version_cmp("1.0.0-alpha", "0.9.9"), Ordering::Greater);
        assert_eq!(version_cmp("1.0.0-alpha", "1.0.1"), Ordering::Less);
    }

    /// What the inversion cost, stated as the thing that reads it: the
    /// [CVE correlator](crate::cve) asks whether a version satisfies `<bound`,
    /// so a pre-release sorting after its own release reported a vulnerable
    /// host as not affected.
    #[test]
    fn a_pre_release_satisfies_a_bound_its_release_does_not() {
        let below = |v: &str| version_cmp(v, "1.0.0") == Ordering::Less;

        assert!(below("0.9.9"));
        assert!(
            below("1.0.0-rc1"),
            "the case that was reported not affected"
        );
        assert!(below("1.0.0-alpha"));
        assert!(!below("1.0.0"));
        assert!(!below("1.0.1"));
    }

    /// A component too long for a `u64` reads as larger than every real one
    /// rather than as zero, which is what a failed parse used to give it.
    #[test]
    fn an_absurd_component_sorts_above_a_real_one_rather_than_below() {
        assert_eq!(version_cmp("18446744073709551616", "2"), Ordering::Greater);
        assert_eq!(version_cmp("2", "18446744073709551616"), Ordering::Less);
    }

    #[test]
    fn version_comparison_is_numeric_per_component_not_lexical() {
        assert_eq!(version_cmp("2.14.1", "2.15.0"), Ordering::Less);
        // The lexical trap: "10" < "9" as strings, but 10 > 9 as numbers.
        assert_eq!(version_cmp("8.10", "8.9"), Ordering::Greater);
        // A missing trailing component reads as zero.
        assert_eq!(version_cmp("2.14", "2.14.0"), Ordering::Equal);
        // A patch letter sorts after the bare number.
        assert_eq!(version_cmp("1.3.5", "1.3.5a"), Ordering::Less);
        // OpenSSH's `p` suffix: the leading number decides, the suffix breaks
        // ties, so 9.6p1 < 9.8 but 9.8p1 > 9.8.
        assert_eq!(version_cmp("9.6p1", "9.8"), Ordering::Less);
        assert_eq!(version_cmp("9.8p1", "9.8"), Ordering::Greater);
    }
}
