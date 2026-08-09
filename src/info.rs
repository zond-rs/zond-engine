// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Local System Information Service
//!
//! Implements the "System Info" use case.
//!
//! This service acts as a facade for gathering local machine statistics and
//! configuration, useful for debugging or self-awareness context.

use crate::core::models::localhost::{FirewallStatus, IpServiceGroup};
use pnet::datalink::NetworkInterface;

/// Retrieves a comprehensive snapshot of the local system's network state.
pub fn get_system_info() -> anyhow::Result<SystemInfo> {
    let services = crate::host_sys::get_local_services()?;
    let firewall = crate::host_sys::get_firewall_status()?;
    let interfaces = crate::host_sys::get_network_interfaces()?;

    Ok(SystemInfo {
        services,
        firewall,
        interfaces,
    })
}

pub struct SystemInfo {
    pub services: Vec<IpServiceGroup>,
    pub firewall: FirewallStatus,
    pub interfaces: Vec<NetworkInterface>,
}
