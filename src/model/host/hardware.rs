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
//! A history rather than a single address, because one host genuinely has
//! several. A machine with two interfaces on one segment answers under two;
//! a phone or laptop randomizing its address answers under a series. Keeping
//! only the newest would answer "which address is it using now" and lose
//! "which has it used", and the second question is the one that identifies a
//! device across a randomization.
//!
//! Each address carries when it was last seen, so
//! [`HardwareInfo::most_recent_mac`] can answer the first question and
//! [`HardwareInfo::prune_stale_macs`] can drop what a caller has stopped caring
//! about.
//!
//! The history is bounded by [`MAX_MACS_PER_HOST`] whether or not anybody
//! prunes it, because the addresses in it are chosen by whoever is sending
//! frames. `prune_stale_macs` is the caller's policy on top of that and not the
//! thing that makes the record safe to hold.
//!
//! Those timestamps are wall-clock [`SystemTime`], matching
//! [`Host::first_seen`](crate::model::host::Host::first_seen), so they mean the
//! same thing to a report as they do to the process that recorded them and can
//! be compared against a cutoff a person chose.

use crate::model::mac::{self, MacAddr};
use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

/// The most hardware addresses one host will have recorded against it.
///
/// A bound on what a single target can make this process allocate, in the one
/// place the addresses are entirely the target's to choose: a source MAC is a
/// field in a frame, and a host that sends gratuitous ARP under a fresh one each
/// time grows this record for as long as it is listening. Every other collection
/// in the model has such a bound. This one did not, and a segment sweep holds a
/// record per address on it.
///
/// Sixty-four is past every legitimate reason one address answers under several.
/// A multi-homed machine offers two or three, a first-hop redundancy pair
/// exchanging a virtual address offers a handful more, and a device randomizing
/// its address on one segment offers one per rotation, which is tens over a week
/// rather than thousands. It is short of where the list stops describing a
/// device and starts logging a flood.
///
/// A record at the bound drops its least recently seen address to take a new
/// one, rather than refusing the new one: the newest sighting is what
/// [`HardwareInfo::most_recent_mac`] answers with, and a record that refused it
/// would answer with an address the host has stopped using.
pub const MAX_MACS_PER_HOST: usize = 64;

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
    ///
    /// Past [`MAX_MACS_PER_HOST`] the least recently seen address makes room.
    /// A rebuild replaying more sightings than the bound therefore keeps the
    /// most recent of them, which is the same set a live capture would have
    /// been left holding.
    pub fn record_mac_seen_at(&mut self, mac: MacAddr, at: SystemTime) {
        let is_new = self.macs.insert(mac, at).is_none();
        if is_new {
            self.evict_oldest_past_the_bound();

            // Only on an address this record had not already seen. A repeated
            // sighting cannot resolve a vendor a previous one could not, and
            // the lookup renders the address to a string and queries a database
            // to answer, which is a cost worth paying once per address rather
            // than once per frame.
            if self.vendor.is_none() {
                self.vendor = mac::vendor(&mac).map(Arc::from);
            }
        }
    }

    /// Drops the least recently seen addresses until the record is within
    /// [`MAX_MACS_PER_HOST`].
    ///
    /// The oldest goes, including where that is the address just recorded: a
    /// rebuild replaying an old sighting into a full record has not learned
    /// anything newer than what is already there. Ties break on the address, so
    /// two sightings a clock could not separate are still resolved the same way
    /// twice and a report does not depend on which arrived first.
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
    /// for days is not.
    ///
    /// A policy rather than a safety bound. [`MAX_MACS_PER_HOST`] is what stops
    /// the record growing without limit, and it applies whether this is ever
    /// called; what this expresses is an age, which only the caller knows.
    /// Discarding an address discards the evidence that the host ever used it,
    /// so the cutoff is theirs to choose: it is the age past which they would no
    /// longer act on the information.
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
    /// That some vendor resolves is the whole assertion. Naming the company would
    /// pin a third-party database's spelling of it and break on a data update
    /// this crate is not party to. See [`mac::vendor`](crate::model::mac::vendor),
    /// whose own test says the same.
    #[test]
    fn a_sighting_records_the_address_and_resolves_its_vendor() {
        let mac = MacAddr::new(0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF);
        let hw = HardwareInfo::new(mac);

        assert!(hw.vendor().is_some(), "a registered OUI");
        assert!(hw.macs().contains_key(&mac));
    }

    /// Which address a host is using now is answered from the timestamps rather
    /// than from the map's own order, which is keyed on the address so a report
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

    /// A source MAC is a field in a frame, so the number of them a host answers
    /// under is whatever the sender chooses. The record has to be bounded by
    /// something this crate decides.
    ///
    /// It was not. `prune_stale_macs` was named as the bound and has never had a
    /// caller, so the map grew for as long as anything was listening: two
    /// hundred thousand sightings left two hundred thousand entries, held per
    /// address on the segment.
    ///
    /// The newest survive, since the oldest is what makes room. That is the half
    /// worth asserting: a bound that kept the *first* sixty-four addresses would
    /// leave `most_recent_mac` naming one the host stopped using.
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

    /// Two records that each fit the bound need not fit it together, so the
    /// union is held to it as well. A fold is otherwise the way past a cap.
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
