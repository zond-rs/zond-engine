// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How fast to ask, and how long to wait
//!
//! The timing machinery of a scan: how long until a probe is repeated, how many
//! times, how long the whole run may take, and when silence counts as an answer.
//!
//! - [`congestion`]: how many probes a scan may have outstanding at once, grown and
//!   cut from what the targets answer. This paces a raw port scan; the rest of the
//!   module decides how long to wait.
//! - [`retry`]: the schedule one probe is repeated on, and the ledger that tracks
//!   every outstanding probe against it.
//! - [`deadline`]: how long the whole scan runs, widened or narrowed by what the
//!   network is doing.
//! - [`rtt_window`]: the recent round trips both of those are sized from.
//! - [`timer`]: the budget a scan is given and the clock it is measured on.
//! - [`limits`](crate::config::limits): the fixed timeouts and ceilings of the
//!   unprivileged paths, the one part that does not adapt. A connect probe sends one
//!   SYN and relies on the host stack's retransmission for a second attempt, so its
//!   budget is set against RFC 6298 and cannot be sized from measured round trips.
//!
//! The knobs a caller sets, [`ScanEffort`](crate::config::ScanEffort) and
//! [`RetryConfig`](crate::config::RetryConfig), live in [`crate::config`] because a
//! person chooses them and a report records them. What they scale is here.
//!
//! ## Per-path timings
//!
//! Each probing path has its own policy, tuned to its protocol: a SYN is answered as
//! fast as the path allows, an ICMP error only as fast as the host may send one, and
//! an IPv6 neighbour answers when it next wakes. A caller's effort setting scales each
//! path's own starting point, so a fast scan cannot hand the UDP scanner a schedule
//! its protocol cannot meet.

pub mod congestion;
pub mod deadline;
pub mod retry;
pub mod rtt_window;
pub mod timer;
