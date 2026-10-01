// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What is between here and a host
//!
//! The two passes that describe the path to a host. [`traceroute`] measures how far
//! away a host is and which routers carry the traffic to it; the filter
//! characterisation [`ZondConfig::characterise`](crate::config::ZondConfig::characterise)
//! turns on asks what the filter in front of it is doing.
//!
//! Both run last, after the ports are known, because what reaches a host decides how
//! to ask about the path to it. A host with 443 open is traced with SYNs to 443, which
//! cross filters no ping survives, and the middlebox probe needs an open port to aim
//! at.
//!
//! Neither is a [`HostScanner`](super::HostScanner) or a
//! [`PortScanner`](super::PortScanner); they record a property of the path to hosts
//! the scan has already found, and are driven directly.
//!
//! The characterisation runs only as a stage of a scan, which hands it hosts already
//! held to the exclusions and to what the probing path can reach. A caller wanting it
//! sets the configuration field.

pub(crate) mod characterise;
pub mod traceroute;
