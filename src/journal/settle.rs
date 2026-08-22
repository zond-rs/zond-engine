// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What became of a target, and whether a resume may skip it
//!
//! A raw port scan gives the same verdict to a target whose retry budget ran
//! out, one still mid-schedule when the scan stopped, and one never probed at
//! all. `RawPortScan::resolve_unasked` explains why, and is right: for a report,
//! a too-kind verdict beats a silently truncated port list.
//!
//! For a resume it is the worst bug available — a cursor advanced over a target
//! nobody probed produces a second sitting that skips it and a merged report
//! claiming coverage it never had.
//!
//! [`Outcome`] makes the distinction unforgeable: **only the settled variants
//! carry a position**, and a position is the only thing a cursor can advance
//! over.
//!
//! | Outcome | Decided at | Position |
//! |---|---|---|
//! | [`Answered`](Outcome::Answered) | `ledger.resolve(..) -> Some` | yes |
//! | [`Exhausted`](Outcome::Exhausted) | `Due::Exhausted` | yes |
//! | [`Interrupted`](Outcome::Interrupted) | `ledger.drain_unresolved()` | no |
//! | [`Unasked`](Outcome::Unasked) | still queued when the scan stopped | no |
//! | [`Unroutable`](Outcome::Unroutable) | no scanner for the protocol, or no route | no |
//!
//! Unsettled outcomes are counted, not stored. Their total is worth reporting;
//! which targets they were is not, since every one is re-probed anyway.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use super::cursor::{Checkpoint, Cursor};

/// What became of one target in one sitting.
///
/// Settled variants carry the target's position in the plan's enumeration; see
/// [`PlannedTarget`](crate::model::target::PlannedTarget).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// The target answered. **Settled.**
    Answered {
        /// Its position in the plan.
        position: u64,
    },

    /// The retry budget was spent without an answer: silence, asked for as many
    /// times as the policy allows. **Settled** — waiting longer could not have
    /// changed it.
    Exhausted {
        /// Its position in the plan.
        position: u64,
    },

    /// Outstanding mid-retry-schedule when the scan stopped. The schedule was
    /// cut off rather than spent.
    Interrupted,

    /// Still queued when the scan stopped, so nothing was sent.
    Unasked,

    /// No scanner spoke its protocol, or the host had no route — usually a
    /// missing privilege rather than a fact about the target, and privileges can
    /// differ between sittings.
    Unroutable,
}

impl Outcome {
    /// The position a resume may skip, or `None` where the scan did not earn
    /// one.
    pub fn settled_position(self) -> Option<u64> {
        match self {
            Outcome::Answered { position } | Outcome::Exhausted { position } => Some(position),
            Outcome::Interrupted | Outcome::Unasked | Outcome::Unroutable => None,
        }
    }

    /// Whether a resume may skip this target.
    pub fn is_settled(self) -> bool {
        self.settled_position().is_some()
    }

    /// The wire name, for diagnostics and for reporting a sitting's shape.
    pub fn name(self) -> &'static str {
        match self {
            Outcome::Answered { .. } => "answered",
            Outcome::Exhausted { .. } => "exhausted",
            Outcome::Interrupted => "interrupted",
            Outcome::Unasked => "unasked",
            Outcome::Unroutable => "unroutable",
        }
    }
}

/// How a sitting ended for each of its targets: a cursor over what settled, and
/// counts of what did not.
///
/// Memory follows how far out of order the scan settled, never how many targets
/// it had. A plan of sixteen billion costs the same here as one of a thousand.
#[derive(Debug, Default)]
pub struct Settlements {
    cursor: Mutex<Cursor>,
    answered: AtomicU64,
    exhausted: AtomicU64,
    interrupted: AtomicU64,
    unasked: AtomicU64,
    unroutable: AtomicU64,
}

impl Settlements {
    /// Begins from a checkpoint, so a resumed sitting keeps what the first
    /// settled.
    pub fn resuming(checkpoint: &Checkpoint) -> Self {
        Self {
            cursor: Mutex::new(Cursor::from_checkpoint(checkpoint)),
            ..Self::default()
        }
    }

    /// Records what became of one target.
    pub fn record(&self, outcome: Outcome) {
        self.counter(outcome).fetch_add(1, Ordering::Relaxed);

        if let Some(position) = outcome.settled_position() {
            self.with_cursor(|cursor| cursor.settle(position));
        }
    }

    /// A snapshot to write down.
    pub fn checkpoint(&self) -> Checkpoint {
        self.with_cursor(|cursor| cursor.checkpoint())
    }

    /// How many targets are settled in total, this sitting and any it resumed.
    pub fn settled_count(&self) -> u64 {
        self.with_cursor(|cursor| cursor.settled_count())
    }

    /// How many targets ended in `outcome`'s variant **this sitting**. The
    /// position of a settled variant is ignored; any will do.
    pub fn count(&self, outcome: Outcome) -> u64 {
        self.counter(outcome).load(Ordering::Relaxed)
    }

    fn counter(&self, outcome: Outcome) -> &AtomicU64 {
        match outcome {
            Outcome::Answered { .. } => &self.answered,
            Outcome::Exhausted { .. } => &self.exhausted,
            Outcome::Interrupted => &self.interrupted,
            Outcome::Unasked => &self.unasked,
            Outcome::Unroutable => &self.unroutable,
        }
    }

    fn with_cursor<R>(&self, read: impl FnOnce(&mut Cursor) -> R) -> R {
        let mut cursor = self.cursor.lock().unwrap_or_else(|e| e.into_inner());
        read(&mut cursor)
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚═╝     ╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule the type exists to enforce.
    #[test]
    fn only_an_earned_outcome_carries_a_position() {
        assert_eq!(
            Outcome::Answered { position: 7 }.settled_position(),
            Some(7)
        );
        assert_eq!(
            Outcome::Exhausted { position: 7 }.settled_position(),
            Some(7)
        );

        for assigned in [Outcome::Interrupted, Outcome::Unasked, Outcome::Unroutable] {
            assert_eq!(assigned.settled_position(), None, "{}", assigned.name());
            assert!(!assigned.is_settled());
        }
    }

    /// A sitting cut short gives every outstanding and unasked target the same
    /// *verdict* as an exhausted one, and must advance the cursor over none.
    #[test]
    fn a_cut_short_sitting_settles_only_what_it_earned() {
        let settlements = Settlements::default();

        settlements.record(Outcome::Answered { position: 0 });
        settlements.record(Outcome::Exhausted { position: 1 });
        for _ in 0..500 {
            settlements.record(Outcome::Interrupted);
            settlements.record(Outcome::Unasked);
        }

        let checkpoint = settlements.checkpoint();
        assert_eq!(checkpoint.watermark, 2);
        assert!(checkpoint.settled_above.is_empty());
        assert_eq!(settlements.settled_count(), 2);
        assert_eq!(settlements.count(Outcome::Interrupted), 500);
    }

    /// Unsettled outcomes cost a counter each, whatever their number, so a scan
    /// that abandons millions of targets pays no memory for them.
    #[test]
    fn unsettled_outcomes_are_counted_rather_than_stored() {
        let settlements = Settlements::default();
        for _ in 0..100_000 {
            settlements.record(Outcome::Unasked);
        }

        assert_eq!(settlements.count(Outcome::Unasked), 100_000);
        assert_eq!(settlements.settled_count(), 0);
        assert_eq!(settlements.checkpoint(), Checkpoint::default());
    }

    /// One unearned position holds the watermark however much settles above it.
    #[test]
    fn one_unearned_position_stalls_the_watermark() {
        let settlements = Settlements::default();

        settlements.record(Outcome::Answered { position: 0 });
        // Position 1 was interrupted: it carries no position, so it is re-probed.
        settlements.record(Outcome::Interrupted);
        for position in 2..1_000 {
            settlements.record(Outcome::Answered { position });
        }

        assert_eq!(settlements.checkpoint().watermark, 1);
        assert_eq!(settlements.settled_count(), 999);
    }

    /// A resumed sitting starts from what the first settled, and counts only its
    /// own work.
    #[test]
    fn resuming_keeps_the_earlier_sittings_progress() {
        let first = Settlements::default();
        for position in 0..10 {
            first.record(Outcome::Answered { position });
        }

        let second = Settlements::resuming(&first.checkpoint());
        assert_eq!(second.settled_count(), 10);
        assert_eq!(second.count(Outcome::Answered { position: 0 }), 0);

        second.record(Outcome::Exhausted { position: 10 });
        assert_eq!(second.checkpoint().watermark, 11);
    }
}
