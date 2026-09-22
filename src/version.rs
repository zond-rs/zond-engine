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
        let ordering = component_cmp(x, y);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

/// Compares one component, digit runs numerically and the rest lexically.
///
/// It was the component's *leading* number and then the whole component
/// lexically as a tie-break, which is wrong twice for one reason: a lexical
/// comparison of text that is partly a number.
///
/// `1.02` and `1.2` are one version. Their leading numbers agree, so the tie
/// break ran and `"02" < "2"` on the first character. That made them different
/// versions, which loses an exact match and lets a `<` bound hold against the
/// very release that fixed the thing. Date-shaped versions carry leading zeros
/// constantly.
///
/// `rc10` follows `rc9`. Neither has a *leading* number, so both read as zero
/// and the tie-break put `rc10` first on `'1' < '9'`. Inside a pre-release
/// identifier the number is what counts and it sits at the end.
///
/// Walking the runs answers both: `02` and `2` are the same number, `rc` equals
/// `rc` and then `10 > 9`. A component that runs out first is the smaller, which
/// is what keeps `9.6` below `9.6p1` and `1.2.3` below `1.2.3a`.
fn component_cmp(a: &str, b: &str) -> Ordering {
    fn digits(s: &str) -> bool {
        s.starts_with(|c: char| c.is_ascii_digit())
    }
    fn take(s: &str, want_digits: bool) -> (&str, &str) {
        let end = s
            .find(|c: char| c.is_ascii_digit() != want_digits)
            .unwrap_or(s.len());
        s.split_at(end)
    }

    let (mut a, mut b) = (a, b);
    loop {
        if a.is_empty() || b.is_empty() {
            // The shorter is the smaller: a bare release precedes the same
            // release carrying a suffix.
            return a.len().cmp(&b.len());
        }

        let ordering = match (digits(a), digits(b)) {
            (true, true) => {
                let (x, rest_a) = take(a, true);
                let (y, rest_b) = take(b, true);
                (a, b) = (rest_a, rest_b);
                // Parsed rather than compared as text, so a leading zero does
                // not decide. Past `u64` the run is longer than any real
                // version, and its length is then the honest comparison.
                match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(x), Ok(y)) => x.cmp(&y),
                    _ => x.len().cmp(&y.len()).then_with(|| x.cmp(y)),
                }
            }
            (false, false) => {
                let (x, rest_a) = take(a, false);
                let (y, rest_b) = take(b, false);
                (a, b) = (rest_a, rest_b);
                x.cmp(y)
            }
            // Digits against letters at the same position: the digits are the
            // version and the letters a suffix on an earlier one, so `9.6p1`
            // sits above `9.6` and below `9.7` whichever way round it is asked.
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
        };

        if ordering != Ordering::Equal {
            return ordering;
        }
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

    /// **A leading zero is not a different version.**
    ///
    /// `1.02` and `1.2` are one release, and date-shaped versions carry zeros
    /// like this constantly. Reading them apart costs an exact match, and worse:
    /// a `<1.2` bound held against `1.02`, so the release that fixed a
    /// vulnerability read as still carrying it.
    #[test]
    fn a_leading_zero_does_not_make_a_different_version() {
        assert_eq!(version_cmp("1.02", "1.2"), Ordering::Equal);
        assert_eq!(version_cmp("2024.01.15", "2024.1.15"), Ordering::Equal);
        assert_eq!(version_cmp("1.0002.3", "1.2.3"), Ordering::Equal);

        // And a zero that is doing real work still counts.
        assert_eq!(version_cmp("1.20", "1.2"), Ordering::Greater);
        assert_eq!(version_cmp("1.02", "1.3"), Ordering::Less);
    }

    /// **A number inside a pre-release identifier counts as a number.**
    ///
    /// `rc10` follows `rc9`. Neither carries a leading digit, so both read as
    /// zero and the tie-break decided lexically on `'1' < '9'`.
    #[test]
    fn a_pre_release_counts_its_number_rather_than_spelling_it() {
        assert_eq!(version_cmp("1.0.0-rc10", "1.0.0-rc9"), Ordering::Greater);
        assert_eq!(version_cmp("1.0.0-rc2", "1.0.0-rc10"), Ordering::Less);
        assert_eq!(version_cmp("1.0.0-beta2", "1.0.0-beta10"), Ordering::Less);

        // The identifier still decides before its number.
        assert_eq!(
            version_cmp("2.0.0-beta1", "2.0.0-alpha9"),
            Ordering::Greater
        );
        // And every pre-release still precedes its own release.
        assert_eq!(version_cmp("1.0.0-rc10", "1.0.0"), Ordering::Less);
    }

    /// The suffix rules the earlier ordering got right, kept.
    ///
    /// A component that runs out first is the smaller, so a bare release sits
    /// below the same release with something appended, and a digit at the same
    /// position as a letter is the greater.
    #[test]
    fn a_suffix_still_breaks_a_tie_upward() {
        assert_eq!(version_cmp("9.6p1", "9.6"), Ordering::Greater);
        assert_eq!(version_cmp("9.6p1", "9.7"), Ordering::Less);
        assert_eq!(version_cmp("1.2.3a", "1.2.3"), Ordering::Greater);
        assert_eq!(version_cmp("9.6p2", "9.6p10"), Ordering::Less);
    }

    /// The order is a total order: whatever two versions are handed to it, the
    /// answer one way is the reverse of the answer the other, and equality is
    /// mutual. A comparison that is not gets a caller a bound that holds in one
    /// direction and not the other.
    #[test]
    fn the_order_is_antisymmetric() {
        let versions = [
            "1.02",
            "1.2",
            "1.2.0",
            "9.6",
            "9.6p1",
            "9.6p10",
            "1.0.0-rc9",
            "1.0.0-rc10",
            "1.0.0",
            "1.21.0-1ubuntu2",
            "2024.01.15",
            "",
            "0",
            "1.2.3a",
            "1.2.3",
            "10.0",
            "9.9",
        ];
        for a in versions {
            for b in versions {
                assert_eq!(
                    version_cmp(a, b),
                    version_cmp(b, a).reverse(),
                    "{a:?} against {b:?}"
                );
            }
        }
    }
}
