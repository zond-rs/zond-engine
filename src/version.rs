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
//! everything that needs to. Two callers need the same answer today — the [CVE
//! correlator](crate::cve), deciding whether a service version falls in an
//! affected range, and a Tier-1 [detection guard](crate::detect::flow), deciding
//! whether a bound version satisfies a `<`/`>` comparison — and a version that
//! sorted one way for one and another way for the other would be a quiet source
//! of disagreement between two features that are meant to agree.
//!
//! ## The order it imposes
//!
//! Versions are split on `.` and `-` and compared component by component. A
//! component's leading run of digits decides first, so `9.10` outranks `9.9`
//! (numerically, 10 > 9) rather than sorting lexically (where `"10" < "9"`); a
//! trailing non-numeric suffix breaks a tie, so OpenSSH's `9.6p1` sorts after a
//! bare `9.6` and before `9.7`. A missing trailing component reads as zero, so
//! `2.14` and `2.14.0` compare equal. It is a deliberately lax order — enough to
//! rank the version strings services actually emit, not a full semver grammar.

use std::cmp::Ordering;

/// Compares two dotted versions component by component: numerically where both
/// components parse as numbers, lexically otherwise, treating a missing component
/// as zero so `2.14` and `2.14.0` compare equal.
pub(crate) fn version_cmp(a: &str, b: &str) -> Ordering {
    let a: Vec<&str> = a.split(['.', '-']).collect();
    let b: Vec<&str> = b.split(['.', '-']).collect();

    for index in 0..a.len().max(b.len()) {
        let x = a.get(index).copied().unwrap_or("0");
        let y = b.get(index).copied().unwrap_or("0");
        // The leading digits decide first — so `9.10` outranks `9.9`, and
        // OpenSSH's `9.6p1` reads its `6` against a bound's `8` as 6 < 8 — with a
        // trailing suffix like `p1` ordering after the bare number as a tiebreak.
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
/// does not start with one — so `6p1` reads as 6 and `p1` as 0.
fn leading_number(component: &str) -> u64 {
    component
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|digits| digits.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

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
