// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How fast to ask, and how long to wait
//!
//! Everything a scan uses to decide *when*. Not what it found, and not what it
//! was asked for — those are [`crate::model`] and [`crate::config`]. This is the
//! machinery in between: how long until a probe is repeated, how many times, how
//! long the whole run may take, and when silence has gone on long enough to be
//! an answer.
//!
//! - [`congestion`] — how many probes a scan may have outstanding at once,
//!   grown and cut from what the targets are managing to answer. This is what
//!   paces a raw port scan; everything else here decides how long to wait, not
//!   how hard to push.
//! - [`retry`] — the schedule one probe is repeated on, and the ledger that
//!   tracks every outstanding probe against it.
//! - [`deadline`] — how long the whole scan runs, widened or narrowed by what
//!   the network is actually doing.
//! - [`rtt_window`] — the recent round trips both of those are sized from.
//! - [`timer`] — the budget a scan is given and the clock it is measured on.
//! - [`limits`](crate::config::limits) — the fixed timeouts and ceilings the unprivileged paths run
//!   against, which is the one part of this module that does not adapt.
//!
//! That last distinction is the reason [`limits`](crate::config::limits) is a module of its own rather
//! than constants scattered through the strategies. A raw scanner sizes its own
//! patience from round trips it measured; a connect probe cannot, because it
//! sends one SYN and the host stack's retransmission is the only second attempt
//! it gets. Its budget is therefore set against a number in RFC 6298 rather than
//! against the network, and a constant chosen for that reason wants saying once
//! with the reason attached.
//!
//! ## Why this is not part of the vocabulary
//!
//! It used to be, and it was the wrong place. [`crate::model`] holds what more
//! than one module has to agree on — a host, a port, an address set — and these
//! four were agreed on by exactly one: the scanner. A `ProbeLedger` is not
//! something a scan *talks about*, it is how a scan is *run*, and nothing
//! outside this module has ever needed to name one.
//!
//! The knobs a caller actually sets are the exception and stayed behind:
//! [`ScanEffort`](crate::config::ScanEffort) and
//! [`RetryConfig`](crate::config::RetryConfig) live in [`crate::config`],
//! because a person chooses those and a report records them. What they scale is
//! here.
//!
//! ## Why the timings are per path rather than global
//!
//! Every probing path has its own policy, tuned against what its protocol
//! actually requires: a SYN is answered as fast as the path allows, an ICMP
//! error only as fast as the host is permitted to send one, and an IPv6
//! neighbour answers when it next wakes. A single set of numbers describes none
//! of them. What a caller's effort setting does is *scale* each path's own
//! starting point, so asking for a fast scan cannot hand the UDP scanner a
//! schedule its protocol is incapable of satisfying.

pub mod congestion;
pub mod deadline;
pub mod retry;
pub mod rtt_window;
pub mod timer;
