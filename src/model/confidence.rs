// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How sure a claim is
//!
//! A grade rather than a percentage. Both a service identification and a
//! [`Finding`](crate::model::finding::Finding) carry one, and the vocabulary is
//! shared so that a report can rank them against each other.

/// How much trust to place in a single piece of [`Evidence`](crate::fingerprint::Evidence).
///
/// Ordered weakest-to-strongest, so evidence can be compared and ranked
/// directly.
///
/// Non-exhaustive, as [`Severity`](crate::model::finding::Severity) is and for
/// the same reason: a grade added to the scale costs a recompile rather than a
/// major version. [`ALL`](Self::ALL) is the list to iterate.
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

    /// Every level, weakest-first, for a caller that iterates rather than
    /// writing the list out — the round-trip that keeps the wire names in step
    /// with the enum, among them.
    pub const ALL: [Confidence; 5] = [
        Self::Heuristic,
        Self::Weak,
        Self::Probable,
        Self::Strong,
        Self::Certain,
    ];
}
