// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The three words every comparison is written in
//!
//! [`Change`] is a field that moved, [`Presence`] is a record that one side has
//! and the other does not, and [`Coverage`] is what a report says about whether
//! it looked. Every delta in this module is built out of these, so a consumer
//! learns them once and can then read a host, a port, a service or a
//! certificate without learning anything new.

use std::fmt;

/// A value that differs between the two scans.
///
/// The one shape every field-level difference takes. A field that is always
/// present carries the values directly, as `Change<PortState>`; a field that may
/// be absent carries `Option`s, as `Change<Option<String>>`, where `before:
/// None` reads as gained and `after: None` as lost. That is one type rather than
/// three, and `match (&change.before, &change.after)` covers every case a
/// renderer has.
///
/// A `Change` never holds two equal values. [`between`](Self::between) is the
/// constructor a comparison uses and returns `None` when nothing moved, so a
/// delta's change list contains only changes.
///
/// ```
/// use zond_engine::diff::Change;
///
/// assert_eq!(Change::between(80, 80), None);
///
/// let moved = Change::between(Some("1.18.0"), Some("1.24.0")).unwrap();
/// assert!(moved.is_replacement());
/// assert_eq!(moved.before, Some("1.18.0"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Change<T> {
    /// What the baseline scan found.
    pub before: T,
    /// What the current scan found.
    pub after: T,
}

impl<T> Change<T> {
    /// The change from `before` to `after`, or `None` if they are equal.
    pub fn between(before: T, after: T) -> Option<Self>
    where
        T: PartialEq,
    {
        (before != after).then_some(Self { before, after })
    }

    /// A change between two values a caller has already established differ.
    ///
    /// For fields whose equality is not the derived one. An operating system
    /// identified at 80% and then at 92% confidence is the same finding, so the
    /// host comparison decides that question itself and builds the change here.
    pub fn new(before: T, after: T) -> Self {
        Self { before, after }
    }

    /// The change with each side passed through `f`.
    pub fn map<U>(self, mut f: impl FnMut(T) -> U) -> Change<U> {
        Change {
            before: f(self.before),
            after: f(self.after),
        }
    }
}

impl<T> Change<Option<T>> {
    /// Whether the current scan found something the baseline did not.
    pub fn is_gain(&self) -> bool {
        self.before.is_none() && self.after.is_some()
    }

    /// Whether the baseline found something the current scan did not.
    pub fn is_loss(&self) -> bool {
        self.before.is_some() && self.after.is_none()
    }

    /// Whether both scans found something and the two differ.
    pub fn is_replacement(&self) -> bool {
        self.before.is_some() && self.after.is_some()
    }
}

impl<T: fmt::Display> fmt::Display for Change<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.before, self.after)
    }
}

/// Which of the two scans holds a record, and what the other one says about
/// having looked.
///
/// A host missing from tonight's scan is gone if tonight's scan covered its
/// address and merely unobserved if it did not. Collapsing those two into
/// "removed" is what makes a monitoring tool cry wolf every time somebody narrows
/// a scan, so the coverage travels with the presence and a consumer never has to
/// go looking for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Presence {
    /// Both scans have a record. The difference between them, if any, is in the
    /// delta's change list.
    Both,
    /// Only the current scan has a record, and `before` is what the baseline
    /// says about whether it covered this target.
    ///
    /// [`Coverage::Covered`] makes this a genuine appearance. Anything else
    /// makes it a target the baseline never asked about.
    Added {
        /// What the baseline scan says about having covered this target.
        before: Coverage,
    },
    /// Only the baseline has a record, and `after` is what the current scan says
    /// about whether it covered this target.
    ///
    /// [`Coverage::Covered`] makes this a genuine disappearance. Anything else
    /// makes it a target tonight's scan never asked about.
    Removed {
        /// What the current scan says about having covered this target.
        after: Coverage,
    },
}

impl Presence {
    /// Whether both scans hold a record.
    pub fn is_in_both(&self) -> bool {
        matches!(self, Presence::Both)
    }

    /// Whether the record is only in the current scan.
    pub fn is_added(&self) -> bool {
        matches!(self, Presence::Added { .. })
    }

    /// Whether the record is only in the baseline scan.
    pub fn is_removed(&self) -> bool {
        matches!(self, Presence::Removed { .. })
    }

    /// What the scan lacking a record says about having covered the target.
    ///
    /// `None` when both scans hold one, where the question does not arise.
    pub fn counterpart_coverage(&self) -> Option<Coverage> {
        match self {
            Presence::Both => None,
            Presence::Added { before } => Some(*before),
            Presence::Removed { after } => Some(*after),
        }
    }

    /// Whether the scan lacking a record is known to have covered the target
    /// anyway, which is what makes an appearance or a disappearance a finding
    /// about the network rather than about the scan.
    pub fn is_confirmed(&self) -> bool {
        self.counterpart_coverage()
            .is_none_or(|coverage| coverage == Coverage::Covered)
    }
}

/// What a report says about whether a target was within what it walked.
///
/// Read off the [`TargetScope`](crate::report::TargetScope) of the report's
/// phases, which record the ranges a scan iterated after its exclusion policy was
/// applied and the ranges that policy withheld. A report carrying no scope, such
/// as one rebuilt from a foreign scanner's output or from a scan that stopped
/// before it wrote a phase down, answers [`Unstated`](Self::Unstated)
/// rather than guessing.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Coverage {
    /// The report says a phase walked this target.
    Covered,
    /// The report says an exclusion policy withheld this target. The scan was
    /// forbidden to look, so nothing here is evidence about the network.
    Withheld,
    /// The report states what it walked, and this target was not in it. Nobody
    /// asked about this target, which is different from being forbidden to.
    OutOfScope,
    /// The report does not say what it covered, so whether it looked is unknown.
    Unstated,
}

impl Coverage {
    /// Whether the report is known to have walked the target.
    pub fn is_covered(&self) -> bool {
        matches!(self, Coverage::Covered)
    }

    /// Whether the report is known not to have walked the target, for either
    /// reason.
    pub fn is_excluded(&self) -> bool {
        matches!(self, Coverage::Withheld | Coverage::OutOfScope)
    }
}

impl fmt::Display for Coverage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Coverage::Covered => write!(f, "covered"),
            Coverage::Withheld => write!(f, "withheld"),
            Coverage::OutOfScope => write!(f, "out of scope"),
            Coverage::Unstated => write!(f, "unstated"),
        }
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    /// The invariant the rest of the module rests on. A delta's change list
    /// holds only changes.
    #[test]
    fn a_value_that_did_not_move_is_not_a_change() {
        assert!(Change::between(1, 1).is_none());
        assert!(Change::between(Some("ssh"), Some("ssh")).is_none());
        assert!(Change::between(None::<&str>, None).is_none());
    }

    #[test]
    fn a_value_that_moved_carries_both_sides() {
        let change = Change::between(1, 2).expect("a change");
        assert_eq!(change.before, 1);
        assert_eq!(change.after, 2);
    }

    #[test]
    fn an_optional_field_reads_as_gain_loss_or_replacement() {
        let gained = Change::new(None, Some("ssh"));
        assert!(gained.is_gain() && !gained.is_loss() && !gained.is_replacement());

        let lost = Change::new(Some("ssh"), None);
        assert!(lost.is_loss() && !lost.is_gain() && !lost.is_replacement());

        let replaced = Change::new(Some("ssh"), Some("http"));
        assert!(replaced.is_replacement() && !replaced.is_gain() && !replaced.is_loss());
    }

    #[test]
    fn mapping_a_change_keeps_both_sides_in_place() {
        let mapped = Change::new(1u8, 2u8).map(|n| n * 10);
        assert_eq!((mapped.before, mapped.after), (10, 20));
    }

    #[test]
    fn a_record_in_both_scans_raises_no_coverage_question() {
        assert!(Presence::Both.is_in_both());
        assert_eq!(Presence::Both.counterpart_coverage(), None);
        assert!(Presence::Both.is_confirmed());
    }

    /// An appearance is a finding about the network only when the scan that
    /// lacked the record is known to have looked.
    #[test]
    fn an_appearance_is_confirmed_only_where_the_baseline_covered_the_target() {
        let looked = Presence::Added {
            before: Coverage::Covered,
        };
        assert!(looked.is_added() && looked.is_confirmed());

        for unconfirmed in [Coverage::Withheld, Coverage::OutOfScope, Coverage::Unstated] {
            let presence = Presence::Added {
                before: unconfirmed,
            };
            assert!(
                !presence.is_confirmed(),
                "{unconfirmed:?} does not confirm an appearance"
            );
        }
    }

    #[test]
    fn a_disappearance_asks_the_same_question_of_the_later_scan() {
        let looked = Presence::Removed {
            after: Coverage::Covered,
        };
        assert!(looked.is_removed() && looked.is_confirmed());

        let did_not = Presence::Removed {
            after: Coverage::OutOfScope,
        };
        assert!(!did_not.is_confirmed());
    }

    #[test]
    fn only_covered_ground_counts_as_covered() {
        assert!(Coverage::Covered.is_covered());
        for other in [Coverage::Withheld, Coverage::OutOfScope, Coverage::Unstated] {
            assert!(!other.is_covered(), "{other:?} is not coverage");
        }
        assert!(Coverage::Withheld.is_excluded());
        assert!(!Coverage::Unstated.is_excluded());
    }
}
