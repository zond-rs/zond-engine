// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Network Target Composition
//!
//! This module defines the atomic units of a scan. It bridges the gap between
//! high-level network definitions ([`IpSet`], [`PortSet`]) and the low-level
//! packets sent by the scanner engine.

use crate::core::models::ip::set::IpSet;
use crate::core::models::port::{PortSet, Protocol};
use std::{net::IpAddr, sync::Arc};
use thiserror::Error;

/// Errors that can occur during target composition and calculation.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum TargetError {
    #[error("Target calculation resulted in an integer overflow")]
    CapacityOverflow,
}

/// Represents a single, atomic connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
}

/// A blueprint pairing a set of IP addresses with a set of ports.
///
/// **The addresses are canonical for this type's whole life.** [`IpSet`] merges
/// lazily, so a half-built one can hold overlapping ranges and answer questions
/// about them wrongly; that is a real hazard, and it has already cost this
/// project one benchmark that reported 65 536 ranges for a file holding one.
///
/// The hazard is removed rather than documented: [`new`](Self::new)
/// canonicalizes, and `ips` is private with no way to mutate it afterwards, so
/// there is no moment at which a `TargetSet` holds an unmerged set. Everything
/// that reads one therefore takes `&self` — a count is not a mutation, and a
/// signature that said otherwise was the invariant leaking into every caller.
#[derive(Debug, Clone, Default)]
pub struct TargetSet {
    /// Internal IP set, canonical by construction.
    ips: IpSet,
    /// Internal Port set. Kept private to protect lazy-evaluation invariants.
    ports: PortSet,
}

impl TargetSet {
    /// Creates a scan blueprint over `ips` and `ports`.
    ///
    /// Merges `ips` here, once, which is what lets every read below be `&self`.
    /// The work is the same either way — a set has to be merged before it can be
    /// counted or iterated — and doing it at one known point rather than at
    /// whichever read happened first is the whole of the difference.
    pub fn new(mut ips: IpSet, ports: PortSet) -> Self {
        ips.canonicalize();
        Self { ips, ports }
    }

    /// Returns a read-only reference to the underlying IP set.
    pub fn ips(&self) -> &IpSet {
        &self.ips
    }

    /// Takes the IP set, discarding the ports.
    ///
    /// For a caller moving targets to a phase that has no use for ports -
    /// [`discover`](crate::scanner::discover) asks whether a host is there at
    /// all - where cloning the addresses to drop the ports beside them would be
    /// the wrong shape for a set that may hold a /8.
    pub fn into_ips(self) -> IpSet {
        self.ips
    }

    /// Returns a read-only reference to the underlying Port set.
    pub fn ports(&self) -> &PortSet {
        &self.ports
    }

    /// Returns the number of unique IP addresses in this set.
    pub fn ip_count(&self) -> u128 {
        self.ips.len()
    }

    /// Returns the number of unique ports in this set.
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Returns the total number of targets.
    ///
    /// Returns a `TargetError::CapacityOverflow` if the calculation exceeds `u128::MAX`.
    pub fn total_targets(&self) -> Result<u128, TargetError> {
        let port_len = self.ports.len() as u128;
        self.ips
            .len()
            .checked_mul(port_len)
            .ok_or(TargetError::CapacityOverflow)
    }

    /// Creates a lazy iterator over every IP/Port combination. Performs lazy normalization.
    ///
    /// This uses `Arc` internally to prevent O(N) memory allocations when iterating
    /// over massive subnets (e.g., /8 or IPv6 ranges).
    pub fn iter(&self) -> impl Iterator<Item = Target> + Send + '_ {
        let ports_arc: Arc<[(u16, Protocol)]> = self.ports.to_vec().into();

        self.ips.iter().flat_map(move |ip| {
            let local_ports = Arc::clone(&ports_arc);
            (0..local_ports.len()).map(move |i| Target {
                ip,
                port: local_ports[i].0,
                protocol: local_ports[i].1,
            })
        })
    }

    /// Returns true if either the IP set or the Port set is completely empty.
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() || self.ports.is_empty()
    }
}

/// A collection of multiple [`TargetSet`] units.
#[derive(Debug, Clone, Default)]
pub struct TargetMap {
    pub units: Vec<TargetSet>,
}

impl TargetMap {
    /// Creates a new, empty `TargetMap`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a new unit definition to the map.
    pub fn add_unit(&mut self, unit: TargetSet) {
        self.units.push(unit);
    }

    /// Returns the gross total of target connections across all units.
    ///
    /// Gross rather than net: two units naming the same address each count it,
    /// because a unit is a set of addresses *paired with a set of ports* and two
    /// units are two different questions about that address.
    pub fn gross_targets(&self) -> Result<u128, TargetError> {
        let mut total: u128 = 0;
        for unit in &self.units {
            let unit_total = unit.total_targets()?;
            total = total
                .checked_add(unit_total)
                .ok_or(TargetError::CapacityOverflow)?;
        }
        Ok(total)
    }

    /// Returns the gross number of IP addresses across all units.
    pub fn gross_ips(&self) -> Result<u128, TargetError> {
        let mut total: u128 = 0;
        for unit in &self.units {
            total = total
                .checked_add(unit.ip_count())
                .ok_or(TargetError::CapacityOverflow)?;
        }
        Ok(total)
    }

    /// Returns true if no targets are defined across any unit.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty() || self.units.iter().all(|u| u.is_empty())
    }

    /// Creates a flattened iterator over every target in every unit.
    pub fn iter(&self) -> impl Iterator<Item = Target> + Send + '_ {
        self.units.iter().flat_map(|unit| unit.iter())
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    // Mock definitions for tests
    fn mock_ip_set(input: &str) -> IpSet {
        input.parse().expect("Valid IP input")
    }

    fn mock_port_set(input: &str) -> PortSet {
        input.parse().expect("Valid Port input")
    }

    #[test]
    fn target_set_math() {
        let ts = TargetSet::new(mock_ip_set("192.168.1.0/24"), mock_port_set("80, 443"));
        assert_eq!(ts.total_targets().unwrap(), 256 * 2);
    }

    /// The property that replaced an invariant callers had to maintain: a set is
    /// merged the moment it is a `TargetSet`, so nothing downstream can read one
    /// that is not.
    ///
    /// This is what the two tests here used to be about. They asserted that a
    /// read before `canonicalize()` returned `TargetError::UncanonicalizedState`,
    /// and that it succeeded afterwards — a state that no longer exists to test.
    /// Overlapping ranges counted twice is the failure that made it matter, so
    /// that is what this asserts instead.
    #[test]
    fn a_target_set_merges_its_addresses_on_construction() {
        let mut overlapping = mock_ip_set("192.168.1.0/24");
        overlapping.insert_range("192.168.1.128/25".parse().expect("valid range"));

        let ts = TargetSet::new(overlapping, mock_port_set("80"));

        // 256, not the 384 the two arguments add up to.
        assert_eq!(ts.ip_count(), 256);
        assert_eq!(ts.total_targets().unwrap(), 256);
    }

    #[test]
    fn target_map_aggregation() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            mock_ip_set("10.0.0.1-10.0.0.5"),
            mock_port_set("80,443"),
        ));
        assert_eq!(map.gross_targets().unwrap(), 10);
    }
}
