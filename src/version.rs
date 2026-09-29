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
//! It is a lax order, enough to rank the version strings services actually
//! emit rather than a full semver grammar. What it is not is *inverted*:
//! reading a hyphen as a dot throughout would sort every pre-release after its
//! own release, and a host running `1.0.0-rc1` against a vulnerability fixed in
//! `1.0.0` would be reported not affected. A missing vulnerability is the wrong
//! direction for a scanner to be wrong in, because nobody argues with it.
//!
//! ## Package versions, a second order
//!
//! A distribution names its builds in its own grammar, and [`dpkg_cmp`]
//! implements Debian's, the one Debian and Ubuntu publish their fix versions
//! in: `[epoch:]upstream[-revision]`, where `~` sorts before everything, even
//! the end of the string, so `1.0~rc1` precedes `1.0`, and where a letter
//! sorts before any other punctuation.
//!
//! The two orders answer different questions about different strings and are
//! never mixed. [`version_cmp`] reads what a service says about itself, an
//! upstream version with whatever a banner appends, and has to guess at a
//! hyphen; [`dpkg_cmp`] reads a version a package manager assigned, where
//! the grammar is exact and a guess would be wrong. They disagree on real
//! strings: to the lax order `1.0-rc1` is a pre-release that precedes `1.0`,
//! to dpkg's it is upstream `1.0` with revision `rc1` and follows it; `1.0~1`
//! is below `1.0` to dpkg and above it to the lax order. A comparison that
//! crossed them would put a fix on the wrong side of the build it is
//! compared with.

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
/// Without this split `-` is treated as `.` throughout, so a non-numeric
/// component sorts after a numeric one and every pre-release reads as *later*
/// than its own release. The [CVE correlator](crate::cve) reads this ordering
/// directly, so a host running `1.0.0-rc1` against a vulnerability fixed in
/// `1.0.0` would be reported not affected.
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
/// Not the component's *leading* number and then the whole component
/// lexically as a tie-break, which is wrong twice for one reason: a lexical
/// comparison of text that is partly a number.
///
/// `1.02` and `1.2` are one version. Their leading numbers agree, so such a tie
/// break would run and put `"02" < "2"` on the first character. That makes them
/// different versions, which loses an exact match and lets a `<` bound hold
/// against the very release that fixed the thing. Date-shaped versions carry
/// leading zeros constantly.
///
/// `rc10` follows `rc9`. Neither has a *leading* number, so both would read as
/// zero and the tie-break would put `rc10` first on `'1' < '9'`. Inside a
/// pre-release identifier the number is what counts and it sits at the end.
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

/// Compares two Debian package versions, as deb-version(7) defines them.
///
/// A version is `[epoch:]upstream[-revision]`. The epoch is the number before
/// the first colon and is 0 when there is none; the revision is what follows
/// the last hyphen and is `0` when there is none, so `1.2` and `1.2-0` are one
/// version. The epoch decides first, numerically, then the upstream part, then
/// the revision.
///
/// The upstream part and the revision are compared the same way, alternating
/// between a run of non-digits and a run of digits. Non-digit runs compare
/// character by character with `~` below everything, the end of the run
/// included, and letters below every other character; digit runs compare as
/// numbers. That is what puts `1.0~rc1` before `1.0`, `1.0~~` before `1.0~`,
/// and `2ubuntu2.13` before `2ubuntu2.13+esm1`.
///
/// A prefix before the first colon that is not a number is not an epoch, and
/// the colon is then read as part of the upstream version; dpkg would refuse
/// such a string, and reading it this way keeps the order total on anything a
/// feed publishes.
#[allow(dead_code)]
pub(crate) fn dpkg_cmp(a: &str, b: &str) -> Ordering {
    let (a_epoch, a_upstream, a_revision) = dpkg_parts(a);
    let (b_epoch, b_upstream, b_revision) = dpkg_parts(b);

    digit_run_cmp(a_epoch, b_epoch)
        .then_with(|| dpkg_part_cmp(a_upstream, b_upstream))
        .then_with(|| dpkg_part_cmp(a_revision, b_revision))
}

/// Splits a package version into its epoch, upstream version and revision,
/// with the defaults deb-version(7) gives a missing epoch (`0`) and a missing
/// revision (`0`).
fn dpkg_parts(version: &str) -> (&str, &str, &str) {
    let (epoch, rest) = match version.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            (epoch, rest)
        }
        _ => ("0", version),
    };
    match rest.rsplit_once('-') {
        Some((upstream, revision)) => (epoch, upstream, revision),
        None => (epoch, rest, "0"),
    }
}

/// Compares one part of a package version, the upstream version or the
/// revision, by alternating non-digit and digit runs as dpkg does.
///
/// Both runs are taken at every step, and an empty run is a real value: an
/// empty non-digit run weighs as the end of the string, which a `~` is below
/// and everything else above, and an empty digit run is zero.
fn dpkg_part_cmp(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    while !a.is_empty() || !b.is_empty() {
        let (a_text, a_rest) = split_run(a, false);
        let (b_text, b_rest) = split_run(b, false);
        let text = (0..a_text.len().max(b_text.len()))
            .map(|i| dpkg_weight(a_text.get(i)).cmp(&dpkg_weight(b_text.get(i))))
            .find(|ordering| ordering.is_ne())
            .unwrap_or(Ordering::Equal);
        if text.is_ne() {
            return text;
        }

        let (a_digits, a_rest) = split_run(a_rest, true);
        let (b_digits, b_rest) = split_run(b_rest, true);
        let number = digit_run_cmp(
            std::str::from_utf8(a_digits).unwrap_or_default(),
            std::str::from_utf8(b_digits).unwrap_or_default(),
        );
        if number.is_ne() {
            return number;
        }
        (a, b) = (a_rest, b_rest);
    }
    Ordering::Equal
}

/// Splits off the leading run of digits, or of non-digits.
fn split_run(s: &[u8], digits: bool) -> (&[u8], &[u8]) {
    let end = s
        .iter()
        .position(|b| b.is_ascii_digit() != digits)
        .unwrap_or(s.len());
    s.split_at(end)
}

/// Where one character of a non-digit run sorts: `~` below the end of the
/// run, letters above it, and every other character above every letter.
fn dpkg_weight(c: Option<&u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(&c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(&c) => i32::from(c) + 256,
    }
}

/// Compares two runs of digits as the numbers they spell, with an empty run
/// reading as zero, at any length: leading zeros are skipped, and then the
/// longer run is the larger number and equal lengths compare digit by digit.
fn digit_run_cmp(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
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

    /// What an inversion costs, stated as the thing that reads it: the
    /// [CVE correlator](crate::cve) asks whether a version satisfies `<bound`,
    /// so a pre-release sorting after its own release would report a vulnerable
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
    /// rather than as zero, which is what a failed parse would give it.
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
    /// a `<1.2` bound holds against `1.02`, so the release that fixed a
    /// vulnerability reads as still carrying it.
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
    /// `rc10` follows `rc9`. Neither carries a leading digit, so a comparison
    /// on leading numbers reads both as zero and a lexical tie-break decides on
    /// `'1' < '9'`.
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

    /// The suffix rules, which comparing digit runs must not disturb.
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

    /// Asserts that each version is strictly below the next under dpkg's
    /// order, both ways round, so a vector checks `Less` and `Greater` alike.
    fn assert_dpkg_ascending(versions: &[&str]) {
        for pair in versions.windows(2) {
            let (low, high) = (pair[0], pair[1]);
            assert_eq!(dpkg_cmp(low, high), Ordering::Less, "{low} < {high}");
            assert_eq!(dpkg_cmp(high, low), Ordering::Greater, "{high} > {low}");
        }
    }

    /// The epoch outranks everything after it, so a package that renumbered
    /// its upstream versions downward still sorts after what it replaced; a
    /// missing epoch is epoch 0.
    #[test]
    fn a_package_epoch_decides_before_the_upstream_version() {
        assert_dpkg_ascending(&["9.9-1", "1:0.1-1", "1:6.6p1-2", "2:0.1"]);
        assert_eq!(dpkg_cmp("0:1.2-3", "1.2-3"), Ordering::Equal);
        assert_eq!(dpkg_cmp("00:1.2", "1.2"), Ordering::Equal);
        assert_eq!(dpkg_cmp("10:1", "9:1"), Ordering::Greater);
    }

    /// A tilde sorts before everything, the end of the string included: it is
    /// how a distribution names a build that has to precede a release, such
    /// as a release candidate packaged ahead of the final version.
    #[test]
    fn a_tilde_sorts_before_the_end_of_a_package_version() {
        assert_dpkg_ascending(&["1.0~~", "1.0~~a", "1.0~", "1.0~rc1", "1.0", "1.0a"]);
        assert_dpkg_ascending(&["1.0~rc1", "1.0~rc2", "1.0~rc10"]);
        assert_dpkg_ascending(&["1.0-1~bpo1", "1.0-1", "1.0-1+b1"]);
    }

    /// Letters sort before every other non-digit, so `1.0a` is below `1.0+`
    /// and `1.0.`, where a plain byte order would put `+` and `.` first.
    #[test]
    fn letters_sort_before_punctuation_in_a_package_version() {
        assert_dpkg_ascending(&["1.0", "1.0a", "1.0z", "1.0+", "1.0.", "1.0.1"]);
        assert_dpkg_ascending(&["1.0Z", "1.0a"]);
        assert_dpkg_ascending(&["1.0a1", "1.0+1"]);
    }

    /// A security update appends to the revision it patches, and must sort
    /// after it: an Ubuntu Pro rebuild after the archive build it extends, and
    /// a Debian stable update numbered past nine after the ones before it.
    #[test]
    fn a_security_rebuild_sorts_after_the_revision_it_extends() {
        assert_dpkg_ascending(&["2ubuntu2.13", "2ubuntu2.13+esm1", "2ubuntu2.13+esm10"]);
        assert_dpkg_ascending(&["2+deb12u1", "2+deb12u3", "2+deb12u10"]);
        assert_dpkg_ascending(&[
            "1:6.6p1-2ubuntu2",
            "1:6.6p1-2ubuntu2.2",
            "1:6.6p1-2ubuntu2.7",
            "1:6.6p1-2ubuntu2.13",
            "1:6.6p1-2ubuntu2.13+esm1",
        ]);
        assert_dpkg_ascending(&["1:9.2p1-2", "1:9.2p1-2+deb12u1", "1:9.2p1-2+deb12u3"]);
    }

    /// A revision is what follows the *last* hyphen, so an upstream version
    /// may carry hyphens of its own, and a missing revision reads as `0`.
    #[test]
    fn a_package_revision_follows_the_last_hyphen_and_defaults_to_zero() {
        assert_eq!(dpkg_cmp("1.2", "1.2-0"), Ordering::Equal);
        assert_dpkg_ascending(&["1.2", "1.2-1", "1.2-1ubuntu1", "1.2.1"]);
        assert_dpkg_ascending(&["1.2-3-1", "1.2-3-2", "1.2-4-1"]);
        // The upstream part `1.2-3` sorts after `1.2`, whatever the revisions.
        assert_dpkg_ascending(&["1.2-9", "1.2-3-1"]);
    }

    /// The version strings a Red Hat build carries have the same shape and
    /// order the same way, the release number and dist tag as a revision.
    #[test]
    fn red_hat_style_releases_order_by_their_numbers() {
        assert_dpkg_ascending(&[
            "7.4p1-11.el7",
            "7.4p1-21.el7",
            "7.4p1-21.el7_9",
            "7.4p1-22.el7",
        ]);
        assert_dpkg_ascending(&["7.4p1-21.el7", "7.4p1-21.el8"]);
    }

    /// Digit runs compare as numbers at any length and a leading zero does
    /// not change one; a non-numeric prefix before a colon is not an epoch.
    #[test]
    fn package_version_digit_runs_are_numbers() {
        assert_dpkg_ascending(&["1.9", "1.10", "1.100"]);
        assert_eq!(dpkg_cmp("1.002", "1.2"), Ordering::Equal);
        assert_dpkg_ascending(&["1.18446744073709551615", "1.18446744073709551616"]);
        assert_dpkg_ascending(&["a:1", "b:1"]);
    }

    /// The two orders disagree on real strings, which is why nothing crosses
    /// them: a hyphen before letters is a pre-release to the lax order and a
    /// revision to dpkg's, and a tilde goes the other way round.
    #[test]
    fn the_package_order_and_the_banner_order_disagree_where_documented() {
        assert_eq!(version_cmp("1.0-rc1", "1.0"), Ordering::Less);
        assert_eq!(dpkg_cmp("1.0-rc1", "1.0"), Ordering::Greater);
        assert_eq!(version_cmp("1.0~1", "1.0"), Ordering::Greater);
        assert_eq!(dpkg_cmp("1.0~1", "1.0"), Ordering::Less);
    }

    /// dpkg's order is total: reversing the arguments reverses the answer
    /// and equality is mutual, over versions chosen to reach every rule.
    #[test]
    fn the_package_order_is_antisymmetric_and_transitive() {
        let versions = [
            "",
            "0",
            "1.0~~",
            "1.0~",
            "1.0~rc1",
            "1.0",
            "1.0-0",
            "1.0a",
            "1.0+",
            "1.0.",
            "1:0.1",
            "0:1.0",
            "1.0-1",
            "1.0-1~bpo1",
            "a:1",
            "1.002",
            "1.2",
            "1.2-3-1",
            "2ubuntu2.13+esm1",
            "7.4p1-21.el7",
        ];
        for a in versions {
            for b in versions {
                assert_eq!(
                    dpkg_cmp(a, b),
                    dpkg_cmp(b, a).reverse(),
                    "{a:?} against {b:?}"
                );
                for c in versions {
                    if dpkg_cmp(a, b).is_le() && dpkg_cmp(b, c).is_le() {
                        assert!(dpkg_cmp(a, c).is_le(), "{a:?} <= {b:?} <= {c:?}");
                    }
                }
            }
        }
    }
}
