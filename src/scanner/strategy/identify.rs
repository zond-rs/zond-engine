// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading what a machine is off what it answers
//!
//! The two active operating-system probes, aimed at hosts the scan has already found.
//! [`series`] revisits a TCP port whose state is settled and asks it the same question
//! several times, so the identifier, sequence and clock policies behind the answers
//! become visible. [`echo`] pings a machine that answered no TCP probe, where a hop
//! counter and an echoed code are all there is to read.
//!
//! The series probe is the stronger of the two, so the orchestrator runs it first and
//! leaves the echo probe the hosts it could not reach.
//!
//! Neither implements [`HostScanner`](super::HostScanner): they discover nothing, and
//! nothing dispatches them dynamically. Each one's entry point is `probe`, and the
//! `ScannerKind` they report under is set at the call site.

pub mod echo;
pub mod series;
