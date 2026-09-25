// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Whether a wait was a host's own
//!
//! Contention is a fact about the host, not the port: one process may serve
//! several of a host's ports from a single worker, and a question to one waits
//! behind the questions to the others in that worker's queue. A pass that asks
//! a host several things at once cannot tell such a queue from a slow port by
//! how long one answer took; it can tell whether anything else of its own was
//! asking the host meanwhile. That is what this counts, for the host and across
//! all of its ports, so a wait is read as the host's only when nothing the pass
//! asked overlapped it.
//!
//! Shared by the two passes that hold conversations with a host's services and
//! run them side by side: the detection stage, which counts every exchange of a
//! flow, and service identification, which counts every identification of a
//! port. Each decides for itself what a crowded wait costs a port.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// The conversations a pass has with one host right now, and has ever begun.
#[derive(Debug, Default)]
pub(crate) struct HostContention {
    /// Conversations with any of the host's ports in flight.
    in_flight: AtomicU32,
    /// Conversations with any of the host's ports ever begun, so one that ends
    /// can tell whether another began and finished while it went on.
    begun: AtomicU64,
}

impl HostContention {
    /// Counts a conversation with the host in, until the [`Visit`] it returns
    /// is [`left`](Visit::leave) or dropped.
    pub(crate) fn enter(&self) -> Visit<'_> {
        let company = self.in_flight.fetch_add(1, Ordering::SeqCst);
        let ticket = self.begun.fetch_add(1, Ordering::SeqCst);
        Visit {
            host: self,
            company,
            ticket,
        }
    }
}

/// One conversation with a host, counted from [`HostContention::enter`] until
/// it is left.
#[derive(Debug)]
pub(crate) struct Visit<'h> {
    host: &'h HostContention,
    /// How many of the host's conversations were in flight when this began.
    company: u32,
    /// Which of the host's conversations this was, in the order they began.
    ticket: u64,
}

impl Visit<'_> {
    /// Ends the conversation and says whether it had the host to itself: none
    /// was in flight when it began, and none began before it ended.
    pub(crate) fn leave(self) -> bool {
        self.company == 0 && self.host.begun.load(Ordering::SeqCst) == self.ticket + 1
    }
}

impl Drop for Visit<'_> {
    fn drop(&mut self) {
        self.host.in_flight.fetch_sub(1, Ordering::SeqCst);
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

    /// A conversation is alone only when nothing else overlapped it at either
    /// end: one already running when it began, or one that began and ended
    /// while it went on.
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
}
