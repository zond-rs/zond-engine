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
//! **A history rather than a single address, because one host genuinely has
//! several.** A machine with two interfaces on one segment answers under two;
//! a phone or laptop randomizing its address answers under a series. Keeping
//! only the newest would answer "which address is it using now" and lose
//! "which has it used", and the second question is the one that identifies a
//! device across a randomization.
//!
//! Each address carries when it was last seen, so
//! [`HardwareInfo::most_recent_mac`] can answer the first question and
//! [`HardwareInfo::prune_stale_macs`] can bound the record on a monitor that
//! runs for days against a segment full of randomizing devices.
//!
//! Those timestamps are wall-clock [`SystemTime`], matching
//! [`Host::first_seen`](crate::model::host::Host::first_seen), so they mean the
//! same thing to a report as they do to the process that recorded them and can
//! be compared against a cutoff a person chose.

use crate::model::mac::{self, MacAddr};
use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

/// The MAC addresses a host has answered under, and who made its hardware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareInfo {
    /// Every MAC seen for this host, against the last time each was.
    ///
    /// A `BTreeMap` so that iteration order is the addresses' own and not a
    /// hash seed's: a report listing them twice must list them the same way
    /// twice.
    macs: BTreeMap<MacAddr, SystemTime>,

    /// The manufacturer the OUI attributes the hardware to, if the database
    /// recognises it.
    ///
    /// Shared rather than owned because a segment is routinely a rack of one
    /// vendor's equipment, and the string is then one allocation instead of one
    /// per host. `None` for a locally administered address, which has no
    /// manufacturer to name. See [`vendor`](crate::model::mac::vendor).
    vendor: Option<Arc<str>>,
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
        }
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
    /// For rebuilding hardware from a record. The sighting times order
    /// [`most_recent_mac`](Self::most_recent_mac) and decide what
    /// [`prune_stale_macs`](Self::prune_stale_macs) removes, so stamping them
    /// with the time of the rebuild would reorder a host's addresses and make
    /// every one of them look fresh.
    pub fn record_mac_seen_at(&mut self, mac: MacAddr, at: SystemTime) {
        self.macs.insert(mac, at);

        if self.vendor.is_none() {
            self.vendor = mac::vendor(&mac).map(Arc::from);
        }
    }

    /// The manufacturer the OUI attributes this hardware to, if the database
    /// recognises it.
    pub fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    /// Returns a read-only view of all recorded MAC addresses and their
    /// last-seen timestamps.
    #[inline]
    pub fn macs(&self) -> &BTreeMap<MacAddr, SystemTime> {
        &self.macs
    }

    /// Returns the MAC address that was most recently observed.
    ///
    /// This is typically used to identify the primary hardware interface
    /// currently active on the network.
    pub fn most_recent_mac(&self) -> Option<MacAddr> {
        self.macs
            .iter()
            .max_by_key(|&(_, time)| time)
            .map(|(mac, _)| *mac)
    }

    /// Forgets every address not seen since `cutoff`.
    ///
    /// The record grows by one address every time a device randomizes its MAC,
    /// and on a segment full of phones that is a steady trickle with no natural
    /// end. A scan is short enough not to care; a monitor watching one segment
    /// for days is not, and this is what bounds it.
    ///
    /// Discarding an address discards the evidence that the host ever used it,
    /// so the cutoff is the caller's to choose: it is the age past which they
    /// would no longer act on the information.
    pub fn prune_stale_macs(&mut self, cutoff: SystemTime) {
        self.macs.retain(|_, last_seen| *last_seen >= cutoff);
    }

    /// Merges architectural findings from another hardware record.
    ///
    /// MAC addresses are interleaved, with the newest timestamp prevailing
    /// for each unique address to prevent timeline regressions.
    pub fn merge(&mut self, other: HardwareInfo) {
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

        if self.vendor.is_none() {
            self.vendor = other.vendor;
        }
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
    /// That *some* vendor resolves is the whole assertion. Naming the company
    /// would pin a third-party database's spelling of it and break on a data
    /// update this crate is not party to — see
    /// [`mac::vendor`](crate::model::mac::vendor), whose own test says the
    /// same.
    #[test]
    fn a_sighting_records_the_address_and_resolves_its_vendor() {
        let mac = MacAddr::new(0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF);
        let hw = HardwareInfo::new(mac);

        assert!(hw.vendor().is_some(), "a registered OUI");
        assert!(hw.macs().contains_key(&mac));
    }

    /// "Which address is it using now" is answered from the timestamps, not
    /// from the map's own order — that is keyed on the address so a report
    /// renders reproducibly. Reading the newest any other way would report the
    /// numerically largest MAC as the current one.
    ///
    /// Timestamps are set by hand because the point is which is newer, and two
    /// insertions are not reliably far enough apart to say.
    #[test]
    fn the_most_recent_sighting_is_the_newest_one_not_the_last_inserted() {
        let newest = MacAddr::new(0x02, 0, 0, 0, 0, 0x01);
        let older = MacAddr::new(0x02, 0xff, 0, 0, 0, 0xff);

        let mut hw = HardwareInfo::new(older);
        hw.macs
            .insert(newest, SystemTime::now() + Duration::from_secs(60));

        assert_eq!(hw.most_recent_mac(), Some(newest));
    }

    /// [`HardwareInfo::prune_stale_macs`] can empty the map, so the accessor
    /// that names the current address has to survive that rather than assume a
    /// record always holds one.
    #[test]
    fn a_record_with_no_addresses_left_names_none() {
        let hw = HardwareInfo {
            macs: BTreeMap::new(),
            vendor: None,
        };
        assert_eq!(hw.most_recent_mac(), None);
    }

    /// The record grows by one address every time a device randomizes its MAC,
    /// with no natural end on a segment full of phones. The cutoff is the
    /// caller's, because discarding an address discards the evidence the host
    /// ever used it.
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
}
