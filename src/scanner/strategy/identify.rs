// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading what a machine is off what it answers
//!
//! The two active operating-system probes. Both are aimed at hosts the scan has
//! already found, and neither discovers anything: [`series`] revisits a TCP port
//! whose state is already settled and asks it the same question several times,
//! so the identifier, sequence and clock policies behind the answers become
//! visible; [`echo`] pings the machine that answered no TCP probe at all, where
//! a hop counter and an echoed code are the whole of what is available.
//!
//! ## Which one reaches which host
//!
//! The series probe is the stronger of the two wherever it applies, so it runs
//! first and the echo probe is left with what it could not reach. That ordering
//! is the orchestrator's, and it is the reason these are two modules rather than
//! one: they read different evidence off different hosts and share only the fact
//! that both are asking what a machine *is* rather than what it has open.
//!
//! ## Why they are not discovery
//!
//! Both implement [`HostScanner`](super::HostScanner), and that trait's summary
//! says a strategy which finds reachable hosts. Neither does. They take the
//! addresses the store already holds, so the trait is being used here for its
//! shape, a run loop and a [`ScannerKind`](crate::report::ScannerKind), rather
//! than for what it describes.

pub mod echo;
pub mod series;
