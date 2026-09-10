// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Tier 2: the simulated network
//!
//! A network that can be told to misbehave. `support::fake_net` receives the
//! Layer 4 segments a scanner emits and decides per target how to answer;
//! `support::fake_lan` does the same an Ethernet frame at a time. Both reach the
//! real scanners through the `from_parts` seams the `test-support` feature
//! opens, so there are no sockets, no privileges and no interfaces involved.
//!
//! This is where the behaviour that distinguishes a scanner gets tested: what it
//! does when probes are lost, answered late, answered twice, answered by a
//! router instead of the host, or never answered at all. Probabilistic policies
//! draw from a generator owned by the net and seeded per test, so a failure
//! found in CI reproduces locally from the seed alone.
//!
//! The seam sits above IP. A scanner hands down a finished Layer 4 segment and
//! gets Layer 4 segments back, so path MTU, fragmentation, real queueing delay,
//! ARP and NDP are invisible here and cannot be faked honestly. Those belong to
//! the `namespaced` tier.
//!
//! `retransmission` is the one module here that takes seconds rather than
//! milliseconds, because a bounded retry schedule is what it asserts on: a probe
//! meant to go unanswered has to wait out every attempt before the verdict it
//! produces means anything.

#[path = "../support/mod.rs"]
mod support;

mod comparison;
mod evasion;
mod exchange;
mod lan_discovery;
mod listening;
mod pacing;
mod probe_classification;
mod retransmission;
mod settlement;
