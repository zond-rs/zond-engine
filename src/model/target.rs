// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a scan was asked to cover
//!
//! A [`Target`] is one address, one port, one protocol: the smallest thing a
//! scan can ask about, and what a probe is built from. The two types above it
//! exist so that nothing has to hold the whole list.
//!
//! [`TargetSet`] pairs an [`IpSet`] with a [`PortSet`] and yields their cross
//! product lazily. A `/8` on a thousand ports is sixteen billion targets, which
//! is a few words to describe and more than any machine can hold; the set
//! describes it and the iterator produces them one at a time.
//!
//! [`TargetMap`] is several of those, because one scan can ask different
//! questions of different hosts — `10.0.0.1:22` and `10.0.0.0/24:80` are one
//! job with two shapes. Each unit is a set of addresses *paired with a set of
//! ports*, which is why the counts here are gross rather than net: two units
//! naming one address are two different questions about it, and both get asked.

use crate::model::ip::set::IpSet;
use crate::model::port::{PortSet, Protocol};
use std::{net::IpAddr, sync::Arc};
use thiserror::Error;

/// Errors that can occur during target composition and calculation.
#[non_exhaustive]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum TargetError {
    /// The number of targets is too large to represent in a `u128`.
    ///
    /// Reachable: `::/0` is already `u128::MAX` addresses, so any second port
    /// overflows. Reported rather than wrapped, because a scan of the entire
    /// address space reported as a small number is the one answer a budget
    /// check must never be handed.
    #[error("Target calculation resulted in an integer overflow")]
    CapacityOverflow,
}

/// One address, one port, one protocol: the smallest thing a scan can ask
/// about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    /// The address to probe.
    ///
    /// Bare, with no zone, because a target set is produced by a scan that
    /// already knows which interface it is bound to. See
    /// [`ScopedIp`](crate::model::ip::scoped::ScopedIp) for where the interface
    /// is carried when it does matter.
    pub ip: IpAddr,
    /// The port to probe.
    pub port: u16,
    /// Which transport to probe it over.
    pub protocol: Protocol,
}

/// A set of addresses paired with the ports to try on each of them.
///
/// The addresses are merged for this type's whole life. [`new`](Self::new)
/// canonicalizes them and there is no way to mutate them afterwards, so a
/// `TargetSet` never holds overlapping ranges and never miscounts them. Every
/// method that reads one takes `&self`, since counting is not a mutation.
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
    /// Merges `ips` once, here, which is what lets every read below take
    /// `&self`. The work is the same either way, since a set has to be merged
    /// before it can be counted or iterated. Doing it at one known point rather
    /// than at whichever read happens first is the whole of the difference.
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
    /// For moving targets to a phase that has no use for ports, such as
    /// [`discover`](crate::scanner::discover), which only asks whether a host is
    /// there at all. Cloning the addresses in order to drop the ports beside
    /// them would be the wrong shape for a set that may hold a `/8`.
    pub fn into_ips(self) -> IpSet {
        self.ips
    }

    /// Takes the set apart into the two halves it was built from.
    ///
    /// For rebuilding one: a unit is immutable once constructed, so narrowing
    /// the addresses of an existing set — which is what withholding an excluded
    /// range from it amounts to — means taking it apart and building a new one
    /// through [`new`](Self::new). That route is deliberate. Handing out a
    /// `&mut IpSet` would let a caller leave the addresses unmerged, and every
    /// count and every membership test downstream assumes they are not.
    pub fn into_parts(self) -> (IpSet, PortSet) {
        (self.ips, self.ports)
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

    /// Every address paired with every port, lazily.
    ///
    /// The addresses were merged when the set was constructed, so there is
    /// nothing to normalize. Nothing is materialized either. A `/8` on a
    /// thousand ports is 16 billion targets, so they are produced one at a time
    /// and the port list is shared behind an `Arc` rather than cloned for every
    /// address.
    pub fn iter(&self) -> impl Iterator<Item = Target> + Send + '_ {
        let ports_arc: Arc<[(u16, Protocol)]> = self.ports.to_vec().into();

        self.ips.iter().flat_map(move |ip| {
            let ports = Arc::clone(&ports_arc);
            (0..ports.len()).map(move |i| {
                let (port, protocol) = ports[i];
                Target { ip, port, protocol }
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
    /// The units, in the order they were added.
    ///
    /// Public because there is no invariant over the vector for an accessor to
    /// protect: a [`TargetSet`] is canonical and immutable from the moment it
    /// is built, this type caches nothing derived from them, and a scanner
    /// splitting work across units needs to iterate and partition them freely.
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

    fn ips(written: &str) -> IpSet {
        written.parse().expect("a valid address specification")
    }

    fn ports(written: &str) -> PortSet {
        written.parse().expect("a valid port specification")
    }

    /// The cross product's size, which is what a caller checks a scan budget
    /// against before anything is sent.
    #[test]
    fn a_sets_target_count_is_its_addresses_times_its_ports() {
        let ts = TargetSet::new(ips("192.168.1.0/24"), ports("80, 443"));
        assert_eq!(ts.total_targets().unwrap(), 256 * 2);
    }

    /// A set is merged the moment it becomes a `TargetSet`, so nothing
    /// downstream can read one that is not. Overlapping ranges counted twice is
    /// the failure that makes this matter, so that is what it checks.
    #[test]
    fn a_target_set_merges_its_addresses_on_construction() {
        let mut overlapping = ips("192.168.1.0/24");
        overlapping.insert_range("192.168.1.128/25".parse().expect("valid range"));

        let ts = TargetSet::new(overlapping, ports("80"));

        // 256, not the 384 the two arguments add up to.
        assert_eq!(ts.ip_count(), 256);
        assert_eq!(ts.total_targets().unwrap(), 256);
    }

    /// The cross product is the whole purpose of the type, and a count alone
    /// does not pin it: two different pairings of the same addresses and ports
    /// produce the same total. This pins the triples.
    #[test]
    fn a_set_yields_every_address_paired_with_every_port() {
        let ts = TargetSet::new(ips("10.0.0.1-10.0.0.2"), ports("80, u:53"));

        let mut targets: Vec<(String, u16, Protocol)> = ts
            .iter()
            .map(|target| (target.ip.to_string(), target.port, target.protocol))
            .collect();
        targets.sort();

        assert_eq!(
            targets,
            vec![
                ("10.0.0.1".to_string(), 53, Protocol::Udp),
                ("10.0.0.1".to_string(), 80, Protocol::Tcp),
                ("10.0.0.2".to_string(), 53, Protocol::Udp),
                ("10.0.0.2".to_string(), 80, Protocol::Tcp),
            ]
        );
    }

    /// A map's iterator is a flattening of its units, in the order they were
    /// added, which is what makes two runs over one input scan in one order.
    #[test]
    fn a_map_iterates_its_units_in_the_order_they_were_added() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(ips("10.0.0.1"), ports("80")));
        map.add_unit(TargetSet::new(ips("10.0.0.2"), ports("u:53")));

        let targets: Vec<(String, u16, Protocol)> = map
            .iter()
            .map(|target| (target.ip.to_string(), target.port, target.protocol))
            .collect();

        assert_eq!(
            targets,
            vec![
                ("10.0.0.1".to_string(), 80, Protocol::Tcp),
                ("10.0.0.2".to_string(), 53, Protocol::Udp),
            ]
        );
    }

    /// `::/0` is 2^128 addresses, which [`IpSet::len`] already saturates to
    /// `u128::MAX`. One port still fits; two do not, and the multiplication has
    /// to refuse rather than wrap. A scan of the entire address space reported
    /// as a small number is the one answer a budget check must never be given.
    #[test]
    fn a_target_count_too_large_to_represent_is_refused_rather_than_wrapped() {
        let two_ports = TargetSet::new(ips("::/0"), ports("80, 443"));
        assert_eq!(
            two_ports.total_targets(),
            Err(TargetError::CapacityOverflow)
        );

        let one_port = TargetSet::new(ips("::/0"), ports("80"));
        assert_eq!(one_port.total_targets().unwrap(), u128::MAX);
    }

    /// A map's total is the sum of its units', so a caller can budget the whole
    /// job from one number rather than walking the units itself.
    #[test]
    fn a_maps_total_is_the_sum_of_its_units() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(ips("10.0.0.1-10.0.0.5"), ports("80,443")));
        assert_eq!(map.gross_targets().unwrap(), 10);
    }
}
