// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Whether a wait was a host's own
//!
//! One process may serve several of a host's ports from one worker, so a
//! question to one port waits behind questions to the others. A slow answer
//! cannot distinguish that from a slow port, but a pass can tell whether it had
//! anything else in flight to the host meanwhile. This counts that, per host,
//! so a wait is blamed on the port only when nothing else overlapped it.
//!
//! Used by the detection stage (per flow exchange) and service identification
//! (per port); each decides what a crowded wait costs.

use std::sync::atomic::{AtomicU64, Ordering};

/// The conversations a pass has with one host right now, and has ever begun.
///
/// Both counts share one atomic word (begun high, in flight low), so a
/// conversation updates both in one step; two steps could let an overlapping
/// conversation go unseen.
#[derive(Debug, Default)]
pub(crate) struct HostContention {
    /// Conversations ever begun (high half) and in flight (low half).
    counts: AtomicU64,
}

/// One conversation in flight, in [`HostContention::counts`].
const IN_FLIGHT: u64 = 1;

/// One conversation begun, in [`HostContention::counts`].
const BEGUN: u64 = 1 << 32;

impl HostContention {
    /// Counts a conversation with the host in, until the [`Visit`] it returns
    /// is [`left`](Visit::leave) or dropped.
    pub(crate) fn enter(&self) -> Visit<'_> {
        let before = self.counts.fetch_add(BEGUN + IN_FLIGHT, Ordering::SeqCst);
        Visit {
            host: self,
            company: before % BEGUN,
            ticket: before / BEGUN,
        }
    }

    /// How many conversations with the host have begun, wrapping with the
    /// half word it is kept in.
    fn begun(&self) -> u64 {
        self.counts.load(Ordering::SeqCst) / BEGUN
    }
}

/// One conversation with a host, counted from [`HostContention::enter`] until
/// it is left.
#[derive(Debug)]
pub(crate) struct Visit<'h> {
    host: &'h HostContention,
    /// How many of the host's conversations were in flight when this began.
    company: u64,
    /// Which of the host's conversations this was, in the order they began.
    ticket: u64,
}

impl Visit<'_> {
    /// Ends the conversation and says whether it had the host to itself: none
    /// was in flight when it began, and none began before it ended.
    pub(crate) fn leave(self) -> bool {
        // Begun since this one, counting it, wrapping in the half word.
        let since = self.host.begun().wrapping_sub(self.ticket) % BEGUN;
        self.company == 0 && since == 1
    }
}

impl Drop for Visit<'_> {
    fn drop(&mut self) {
        self.host.counts.fetch_sub(IN_FLIGHT, Ordering::SeqCst);
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

    /// Alone only if none was running when it began and none began before it
    /// ended.
    #[test]
    fn a_visit_is_alone_only_when_nothing_overlapped_it() {
        let host = HostContention::default();
        assert!(
            host.enter().leave(),
            "a conversation with nothing beside it"
        );

        let first = host.enter();
        let second = host.enter();
        assert!(!second.leave(), "one begun while another was running");
        assert!(!first.leave(), "one another began and ended within");

        let dropped = host.enter();
        drop(dropped);
        assert!(
            host.enter().leave(),
            "a conversation dropped unleft still counted as in flight"
        );
    }

    /// Two conversations begun side by side and each in flight until the
    /// other has begun are never read as alone, however their beginnings
    /// interleave.
    ///
    /// Raced many times, since the interleaving is the scheduler's.
    #[test]
    fn conversations_begun_side_by_side_are_never_alone() {
        const RACES: usize = 500_000;
        let host = HostContention::default();
        let both_begun = std::sync::Barrier::new(2);
        let read_alone = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| {
                    for _ in 0..RACES {
                        let visit = host.enter();
                        both_begun.wait();
                        if visit.leave() {
                            read_alone.fetch_add(1, Ordering::Relaxed);
                        }
                        // Both leave before the next race.
                        both_begun.wait();
                    }
                });
            }
        });
        assert_eq!(
            read_alone.load(Ordering::Relaxed),
            0,
            "a conversation that overlapped another was read as alone"
        );
    }
}
