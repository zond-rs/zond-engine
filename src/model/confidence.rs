// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How sure a claim is
//!
//! A grade rather than a percentage, so that two claims reached by different
//! routes can be ranked without either knowing how the other was arrived at.
//!
//! A [`Finding`](crate::model::finding::Finding) carries one. A
//! [`Service`](crate::model::port::Service) does not: it holds the `0..=100`
//! score [`as_score`](Confidence::as_score) projects onto, because a service
//! identification is refined in place by several analyzers and the score is what
//! [`Service::merge`](crate::model::port::Service::merge) ranks them by. The two
//! are comparable through that projection rather than directly, which is worth
//! knowing before writing a report that puts them side by side.

/// How much trust to place in a single piece of [`Evidence`](crate::fingerprint::Evidence).
///
/// Ordered weakest-to-strongest, so evidence can be compared and ranked
/// directly.
///
/// Non-exhaustive, as [`Severity`](crate::model::finding::Severity) is: a grade
/// added to the scale costs a recompile rather than a major version.
/// [`ALL`](Self::ALL) is the list to iterate.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Confidence {
    /// A guess from context alone, e.g. the registered name for a port number
    /// with no probing performed.
    #[default]
    Heuristic,
    /// A plausible but non-authoritative signal.
    Weak,
    /// A signature matched, but the match is generic (no product/version).
    Probable,
    /// A specific signature matched, yielding product and/or version detail.
    Strong,
    /// Effectively certain: the service self-identified unambiguously.
    Certain,
}

impl Confidence {
    /// Projects onto the `0..=100` confidence scale used by [`Service`](crate::model::port::Service).
    pub fn as_score(self) -> u8 {
        match self {
            Confidence::Heuristic => 0,
            Confidence::Weak => 40,
            Confidence::Probable => 70,
            Confidence::Strong => 90,
            Confidence::Certain => 100,
        }
    }

    /// Every level, weakest-first, for a caller that iterates rather than writing
    /// the list out, the wire-name round trip among them.
    pub const ALL: [Confidence; 5] = [
        Self::Heuristic,
        Self::Weak,
        Self::Probable,
        Self::Strong,
        Self::Certain,
    ];
}
