// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Linux only: the tier moves into a network namespace and drives it through
// `unshare`/`setns`, which exist nowhere else. An empty binary on other targets.
#![cfg(target_os = "linux")]

//! # Tier 3: a real kernel, on a network built for the test
//!
//! Every tier above this one stops at a seam. Tier 2 hands a scanner finished
//! Layer 4 segments and takes finished segments back, which is what makes it
//! fast and deterministic and also what puts the whole of IP out of its reach: a
//! wrong checksum, a BPF filter that matches nothing, a source address chosen
//! off the wrong interface, an ARP exchange that never happens. All of that
//! passes Tier 2 and fails in the field.
//!
//! This tier closes that gap by giving the engine a network instead of a
//! simulation. [`netns`] moves the process into a user and network namespace of
//! its own before `main`, and each test builds a veth pair with its far end in a
//! second namespace. Packets are built by the engine, put on a wire by the
//! kernel, answered by another kernel, and read back through libpcap.
//!
//! No part of that needs root. An unprivileged user namespace carries
//! `CAP_NET_ADMIN` and `CAP_NET_RAW` inside itself, so this runs under an
//! ordinary `cargo test` and can gate a pull request, which is the point of
//! building it here rather than on a privileged host somebody has to remember to
//! use.
//!
//! # What belongs here
//!
//! Only what cannot be asked anywhere else. Tier 2 can describe a thousand
//! answers a network might give and does; repeating that matrix against a real
//! link would buy nothing and cost a flake every time `netem` rounded a
//! probability the wrong way. So the cases here are the ones where the question
//! is whether the real path works at all.

#[path = "../support/mod.rs"]
mod support;

mod netns;

mod capturing;
mod characterise;
mod classification;
mod degraded;
mod listening;
mod liveness;
mod neighbours;
mod resolving;
mod resuming;
mod segment;
mod sourcing;
mod techniques;
mod tunnelled;
