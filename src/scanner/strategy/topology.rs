// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What is between here and a host
//!
//! The two passes that describe the path rather than the endpoint.
//! [`traceroute`] measures how far away a host is and which routers carry the
//! traffic to it; [`characterise`] asks what the filter in front of it is doing.
//!
//! Both run last, after the ports are known, and for the same reason: what
//! reaches a host is what decides how to ask about the path to it. A host with
//! 443 open is traced with SYNs to 443, which crosses filters no ping survives,
//! and the middlebox probe needs an open port to aim at. Run before the port
//! scan, both would fall back to what a firewall drops.
//!
//! Neither is a [`HostScanner`](super::HostScanner) or a
//! [`PortScanner`](super::PortScanner). They are aimed at hosts the scan has
//! already found and record a property of the path rather than of the host's
//! ports, so they are driven directly rather than through either trait.

pub mod characterise;
pub mod traceroute;
