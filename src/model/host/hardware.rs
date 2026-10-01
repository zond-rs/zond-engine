// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The hardware behind an address
//!
//! [`HardwareInfo`] records the MAC addresses a host has answered under and the
//! vendor its OUI attributes it to.
//!
//! A history, because one host can have several: a machine with two interfaces on one
//! segment answers under two, and a phone randomizing its address answers under a
//! series. The history is what identifies a device across a randomization.
//!
//! Each address carries when it was last seen, so [`HardwareInfo::most_recent_mac`]
//! answers which is current and [`HardwareInfo::prune_stale_macs`] drops old ones.
//!
//! The history is bounded by [`MAX_MACS_PER_HOST`] regardless of pruning, since the
//! sender chooses the addresses. Pruning is the caller's policy on top.
//!
//! Timestamps are wall-clock [`SystemTime`], like
//! [`Host::first_seen`](crate::model::host::Host::first_seen), so they can be compared
//! against a cutoff a person chose.

use crate::model::mac::{self, MacAddr};
use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

/// The most hardware addresses one host will have recorded against it.
///
/// Bounds what a single target can make this process allocate: a source MAC is a field
/// in a frame, and a host sending gratuitous ARP under a fresh one each time would
/// otherwise grow this record indefinitely.
///
/// Sixty-four exceeds every legitimate case: a multi-homed machine has two or three, a
/// first-hop redundancy pair a handful more, and a randomizing device tens over a week.
///
/// At the bound the least recently seen address makes room, so
/// [`HardwareInfo::most_recent_mac`] keeps naming the address in use.
pub const MAX_MACS_PER_HOST: usize = 64;

/// The MAC addresses a host has answered under, and who made its hardware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareInfo {
    /// Every MAC seen for this host, against the last time each was.
    ///
    /// A `BTreeMap`, so iteration order is stable.
    macs: BTreeMap<MacAddr, SystemTime>,

    /// The manufacturer the OUI attributes the hardware to, if the database
    /// recognises it.
    ///
    /// Shared, since a segment is often a rack of one vendor's equipment. `None` for a
    /// locally administered address. See [`vendor`](crate::model::mac::vendor).
    ///
    /// A vendor a service named replaces one read from the address: an OUI names whoever
    /// registered the address block, which on a Check Point firewall or a NETGEAR
    /// appliance is often the network chip's maker.
    vendor: Option<Arc<str>>,

    /// The model, where something named it: `PDR M800`, `Firewall-1`.
    ///
    /// Arrives only from a service that stated it; over a thousand shipped rules carry
    /// one.
    product: Option<Arc<str>>,

    /// The line the model belongs to, where a rule distinguishes the two:
    /// `ILOM` for an Oracle service processor, `ReadyNAS` for a NETGEAR box.
    family: Option<Arc<str>>,

    /// A Common Platform Enumeration identifier for the hardware, as the corpus writes
    /// it. Separate from the operating system's.
    cpe23: Option<Arc<str>>,

    /// A finer designation than the product, where a rule draws both: the label
    /// printers say `Thermal Label Printer` for one and `PC42t` for the other.
    model: Option<Arc<str>>,

    /// The hardware revision, distinct from the operating system's version.
    version: Option<Arc<str>>,

    /// The unit's own serial number, where it published one.
    ///
    /// The only field naming a single box, so a redacted export drops it.
    serial_number: Option<Arc<str>>,
}

/// What a service said about a box, for [`HardwareInfo::described`].
///
/// A struct, since seven positional `Option<&str>` arguments are easy to swap.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default)]
pub struct HardwareDescription<'a> {
    /// Who made the box.
    pub vendor: Option<&'a str>,
    /// What it is called.
    pub product: Option<&'a str>,
    /// The line it belongs to.
    pub family: Option<&'a str>,
    /// Its platform identifier.
    pub cpe23: Option<&'a str>,
    /// A finer designation than the product.
    pub model: Option<&'a str>,
    /// The hardware revision.
    pub version: Option<&'a str>,
    /// The unit's own serial number.
    pub serial_number: Option<&'a str>,
}

impl HardwareInfo {
    /// Creates a new `HardwareInfo` record for a specifically discovered MAC address.
    ///
    /// The vendor is resolved automatically from the MAC's OUI, if known.
    pub fn new(mac: MacAddr) -> Self {
        let mut macs = BTreeMap::new();
        macs.insert(mac, SystemTime::now());

        Self {
            macs,
            vendor: mac::vendor(&mac).map(Arc::from),
            product: None,
            family: None,
            cpe23: None,
            model: None,
            version: None,
            serial_number: None,
        }
    }

    /// A record for hardware a service described, with no address behind it.
    ///
    /// A host reached through a gateway has no MAC to read, but a banner naming
    /// `Merit LILIN PDR M800` still describes the box. `None` if it names nothing.
    pub fn described(described: HardwareDescription<'_>) -> Option<Self> {
        let built = Self {
            macs: BTreeMap::new(),
            vendor: described.vendor.map(Arc::from),
            product: described.product.map(Arc::from),
            family: described.family.map(Arc::from),
            cpe23: described.cpe23.map(Arc::from),
            model: described.model.map(Arc::from),
            version: described.version.map(Arc::from),
            serial_number: described.serial_number.map(Arc::from),
        };
        built.names_something().then_some(built)
    }

    /// Whether this record says anything at all beyond the addresses it holds.
    fn names_something(&self) -> bool {
        self.vendor.is_some()
            || self.product.is_some()
            || self.family.is_some()
            || self.cpe23.is_some()
            || self.model.is_some()
            || self.version.is_some()
            || self.serial_number.is_some()
    }

    /// The model, where something named it.
    pub fn product(&self) -> Option<&str> {
        self.product.as_deref()
    }

    /// The line the model belongs to.
    pub fn family(&self) -> Option<&str> {
        self.family.as_deref()
    }

    /// The hardware's platform identifier.
    pub fn cpe23(&self) -> Option<&str> {
        self.cpe23.as_deref()
    }

    /// A finer designation than the product, where a rule drew both.
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// The hardware revision, which is not the operating system's version.
    pub fn hardware_version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// The unit's own serial number, where it published one.
    pub fn serial_number(&self) -> Option<&str> {
        self.serial_number.as_deref()
    }

    /// Records a discovery event for a specific MAC address, updating its
    /// "last seen" timestamp.
    ///
    /// If no vendor has been identified yet, this attempts to resolve one
    /// from the newly observed MAC's OUI.
    pub fn add_mac(&mut self, mac: MacAddr) {
        self.record_mac_seen_at(mac, SystemTime::now());
    }

    /// [`add_mac`](Self::add_mac) for an address seen at a known time.
    ///
    /// For rebuilding hardware from a record, keeping the original sighting times that
    /// [`most_recent_mac`](Self::most_recent_mac) and
    /// [`prune_stale_macs`](Self::prune_stale_macs) depend on.
    ///
    /// Past [`MAX_MACS_PER_HOST`] the least recently seen address makes room, so a
    /// rebuild keeps the same set a live capture would.
    pub fn record_mac_seen_at(&mut self, mac: MacAddr, at: SystemTime) {
        let is_new = self.macs.insert(mac, at).is_none();
        if is_new {
            self.evict_oldest_past_the_bound();

            // Only for a new address: a repeat cannot resolve what the first did
            // not, and the lookup is too costly to run per frame.
            if self.vendor.is_none() {
                self.vendor = mac::vendor(&mac).map(Arc::from);
            }
        }
    }

    /// Drops the least recently seen addresses until the record is within
    /// [`MAX_MACS_PER_HOST`].
    ///
    /// The oldest goes, even if it is the address just recorded. Ties break on the
    /// address, so the result does not depend on arrival order.
    fn evict_oldest_past_the_bound(&mut self) {
        while self.macs.len() > MAX_MACS_PER_HOST {
            let Some(oldest) = self
                .macs
                .iter()
                .min_by_key(|(mac, seen)| (*seen, *mac))
                .map(|(mac, _)| *mac)
            else {
                return;
            };
            self.macs.remove(&oldest);
        }
    }

    /// Who made the box: what a service said about itself where one did, and
    /// otherwise the manufacturer the OUI attributes the address to, if the
    /// database recognises it.
    pub fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    /// Who registered the address block this hardware was seen at, as the OUI
    /// database has it: the reading of the address alone.
    ///
    /// Unlike [`vendor`](Self::vendor), no service said this, so it can stand as an
    /// independent witness beside one that did.
    ///
    /// The newest address with a registered block answers. `None` for a record with no
    /// address, or with only randomised addresses.
    pub(crate) fn registered_vendor(&self) -> Option<String> {
        let mut newest_first: Vec<(&MacAddr, &SystemTime)> = self.macs.iter().collect();
        newest_first.sort_by(|a, b| b.1.cmp(a.1));
        newest_first
            .into_iter()
            .find_map(|(address, _)| mac::vendor(address))
    }

    /// Returns a read-only view of all recorded MAC addresses and their
    /// last-seen timestamps.
    #[inline]
    pub fn macs(&self) -> &BTreeMap<MacAddr, SystemTime> {
        &self.macs
    }

    /// Returns the MAC address that was most recently observed.
    ///
    /// Typically the hardware interface currently in use.
    pub fn most_recent_mac(&self) -> Option<MacAddr> {
        self.macs
            .iter()
            .max_by_key(|&(_, time)| time)
            .map(|(mac, _)| *mac)
    }

    /// Forgets every address not seen since `cutoff`.
    ///
    /// For a long-running monitor, where randomizing devices add addresses steadily.
    /// [`MAX_MACS_PER_HOST`] is the safety bound; this is the caller's policy on age,
    /// and it discards the evidence that the host ever used those addresses.
    pub fn prune_stale_macs(&mut self, cutoff: SystemTime) {
        self.macs.retain(|_, last_seen| *last_seen >= cutoff);
    }

    /// Folds another record of this host's hardware into this one.
    ///
    /// The addresses are interleaved and the newer sighting of each wins, so
    /// neither record's timeline runs backwards. The union is held to
    /// [`MAX_MACS_PER_HOST`] afterwards, since two records that each fit the
    /// bound need not fit it together.
    pub fn merge(&mut self, other: HardwareInfo) {
        // Read before the addresses are consumed.
        let describes_a_box = other.names_more_than_a_vendor();

        for (mac, time) in other.macs {
            self.macs
                .entry(mac)
                .and_modify(|t| {
                    if time > *t {
                        *t = time;
                    }
                })
                .or_insert(time);
        }
        self.evict_oldest_past_the_bound();

        // A stated vendor wins over an OUI; see the field.
        if self.vendor.is_none() || (other.vendor.is_some() && describes_a_box) {
            self.vendor = other.vendor.or_else(|| self.vendor.take());
        }
        self.product = self.product.take().or(other.product);
        self.family = self.family.take().or(other.family);
        self.cpe23 = self.cpe23.take().or(other.cpe23);
        self.model = self.model.take().or(other.model);
        self.version = self.version.take().or(other.version);
        self.serial_number = self.serial_number.take().or(other.serial_number);
    }

    /// Whether a record carries hardware detail beyond a vendor, which is what
    /// separates one a service described from one an address block produced.
    fn names_more_than_a_vendor(&self) -> bool {
        self.product.is_some()
            || self.family.is_some()
            || self.cpe23.is_some()
            || self.model.is_some()
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
    use std::time::Duration;

    /// A sighting resolves a vendor through the OUI database and records the
    /// address that produced it.
    ///
    /// Asserts only that some vendor resolves, as [`mac::vendor`](crate::model::mac::vendor)'s
    /// test does.
    #[test]
    fn a_sighting_records_the_address_and_resolves_its_vendor() {
        let mac = MacAddr::new(0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF);
        let hw = HardwareInfo::new(mac);

        assert!(hw.vendor().is_some(), "a registered OUI");
        assert!(hw.macs().contains_key(&mac));
    }

    /// The current address comes from the timestamps, not the map's address order.
    /// Timestamps are set by hand, since two insertions may share a tick.
    #[test]
    fn the_most_recent_sighting_is_the_newest_one_not_the_last_inserted() {
        let newest = MacAddr::new(0x02, 0, 0, 0, 0, 0x01);
        let older = MacAddr::new(0x02, 0xff, 0, 0, 0, 0xff);

        let mut hw = HardwareInfo::new(older);
        hw.macs
            .insert(newest, SystemTime::now() + Duration::from_secs(60));

        assert_eq!(hw.most_recent_mac(), Some(newest));
    }

    /// The record is bounded without pruning, and the newest addresses survive.
    #[test]
    fn a_flood_of_addresses_is_held_to_the_bound_and_keeps_the_newest() {
        let start = SystemTime::now();
        let mut hw = HardwareInfo::new(MacAddr::new(0x02, 0, 0, 0, 0, 0));

        let sightings = u32::try_from(MAX_MACS_PER_HOST).expect("a small bound") * 4;
        for i in 0..sightings {
            let b = i.to_be_bytes();
            hw.record_mac_seen_at(
                MacAddr::new(0x02, b[0], b[1], b[2], b[3], 0xff),
                start + Duration::from_secs(u64::from(i) + 1),
            );
        }

        assert_eq!(hw.macs().len(), MAX_MACS_PER_HOST);

        let last = sightings - 1;
        let b = last.to_be_bytes();
        let newest = MacAddr::new(0x02, b[0], b[1], b[2], b[3], 0xff);
        assert_eq!(hw.most_recent_mac(), Some(newest), "the newest survives");
        assert!(
            !hw.macs().contains_key(&MacAddr::new(0x02, 0, 0, 0, 0, 0)),
            "and the first sighting is what made room"
        );
    }

    /// The union of two records is held to the bound too.
    #[test]
    fn merging_two_records_holds_their_union_to_the_bound() {
        let start = SystemTime::now();

        let fill = |first: u8| {
            let mut hw = HardwareInfo::new(MacAddr::new(0x02, first, 0, 0, 0, 0));
            for i in 0..u8::try_from(MAX_MACS_PER_HOST).expect("a small bound") {
                hw.record_mac_seen_at(
                    MacAddr::new(0x02, first, 0, 0, 0, i),
                    start + Duration::from_secs(u64::from(i) + 1),
                );
            }
            hw
        };

        let mut a = fill(0xaa);
        let b = fill(0xbb);
        assert_eq!(a.macs().len(), MAX_MACS_PER_HOST);
        assert_eq!(b.macs().len(), MAX_MACS_PER_HOST);

        a.merge(b);

        assert_eq!(a.macs().len(), MAX_MACS_PER_HOST);
    }

    /// The current-address accessor survives [`HardwareInfo::prune_stale_macs`]
    /// emptying the map.
    #[test]
    fn a_record_with_no_addresses_left_names_none() {
        let hw = HardwareInfo {
            macs: BTreeMap::new(),
            vendor: None,
            product: None,
            family: None,
            cpe23: None,
            model: None,
            version: None,
            serial_number: None,
        };
        assert_eq!(hw.most_recent_mac(), None);
    }

    /// Pruning drops addresses not seen since the cutoff.
    #[test]
    fn pruning_forgets_the_addresses_not_seen_since_the_cutoff() {
        let recent = MacAddr::new(1, 1, 1, 1, 1, 1);
        let stale = MacAddr::new(2, 2, 2, 2, 2, 2);

        let mut hw = HardwareInfo::new(recent);
        hw.macs
            .insert(stale, SystemTime::now() - Duration::from_secs(3600));

        hw.prune_stale_macs(SystemTime::now() - Duration::from_secs(1800));

        assert_eq!(hw.macs().len(), 1);
        assert!(hw.macs().contains_key(&recent));
    }

    /// A service can describe a box this engine has no address for.
    #[test]
    fn hardware_a_service_described_needs_no_address() {
        let described = HardwareInfo::described(HardwareDescription {
            vendor: Some("Merit LILIN"),
            product: Some("PDR M800"),
            cpe23: Some("cpe:/h:merit_lilin:pdr_m800"),
            ..HardwareDescription::default()
        })
        .expect("it names something");

        assert_eq!(described.vendor(), Some("Merit LILIN"));
        assert_eq!(described.product(), Some("PDR M800"));
        assert_eq!(described.most_recent_mac(), None);
    }

    /// A description naming nothing produces no record.
    #[test]
    fn a_description_naming_nothing_is_not_recorded() {
        assert!(HardwareInfo::described(HardwareDescription::default()).is_none());
    }

    /// A vendor a service stated replaces one read from the address block.
    #[test]
    fn a_stated_vendor_outranks_one_read_from_an_address() {
        let mut known = HardwareInfo::new(MacAddr::new(0x00, 0x1b, 0x21, 0x11, 0x22, 0x33));
        let described = HardwareInfo::described(HardwareDescription {
            vendor: Some("Check Point"),
            product: Some("Firewall-1"),
            ..HardwareDescription::default()
        })
        .expect("it names something");

        known.merge(described);

        assert_eq!(known.vendor(), Some("Check Point"));
        assert_eq!(known.product(), Some("Firewall-1"));
        assert_eq!(
            known.macs().len(),
            1,
            "merging a description must not lose the address"
        );
    }

    /// A bare vendor with nothing else does not displace one the address block
    /// supports.
    #[test]
    fn a_bare_stated_vendor_does_not_displace_the_registered_one() {
        let mut known = HardwareInfo::new(MacAddr::new(0x00, 0x1b, 0x21, 0x11, 0x22, 0x33));
        let before = known.vendor().map(str::to_string);
        let thin = HardwareInfo::described(HardwareDescription {
            vendor: Some("Unhelpful"),
            ..HardwareDescription::default()
        })
        .expect("it names something");

        known.merge(thin);

        assert_eq!(known.vendor().map(str::to_string), before);
    }
}
