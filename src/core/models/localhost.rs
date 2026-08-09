// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Local Host Info Model
//!
//! Information about the *local machine* (where the program is running),
//! rather than remote hosts discovered on the network.
//!
//! This includes:
//! * Active network services (ports opened by local processes).
//! * Firewall status.

use std::collections::HashSet;
use std::net::IpAddr;

/// Represents a group of services running on a specific local IP address.
#[derive(Debug, Clone)]
pub struct IpServiceGroup {
    pub ip_addr: IpAddr,
    pub tcp_services: Vec<Service>,
    pub udp_services: Vec<Service>,
}

impl IpServiceGroup {
    pub fn new(ip_addr: IpAddr, tcp_services: Vec<Service>, udp_services: Vec<Service>) -> Self {
        Self {
            ip_addr,
            tcp_services,
            udp_services,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Service {
    pub name: String,
    pub local_addr: IpAddr,
    pub local_ports: HashSet<u16>,
}

impl Service {
    pub fn new(name: String, local_addr: IpAddr, local_ports: HashSet<u16>) -> Self {
        Self {
            name,
            local_addr,
            local_ports,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallStatus {
    Active,
    Inactive,
    NotDetected,
}
