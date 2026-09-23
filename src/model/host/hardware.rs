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
    ///
    /// A vendor a service named for itself replaces one read from the address,
    /// because the two answer different questions and only one of them is about
    /// the box. An OUI names whoever registered the address block, which on a
    /// Check Point firewall or a NETGEAR appliance is routinely the maker of the
    /// network chip inside it. A device that says `Check Point` in its own
    /// banner is describing itself.
    vendor: Option<Arc<str>>,

    /// The model, where something named it: `PDR M800`, `Firewall-1`.
    ///
    /// Not derivable from an address at any prefix length, so this arrives only
    /// from a service that stated it. Over a thousand shipped rules carry one,
    /// and this field is where it lands.
    product: Option<Arc<str>>,

    /// The line the model belongs to, where a rule distinguishes the two:
    /// `ILOM` for an Oracle service processor, `ReadyNAS` for a NETGEAR box.
    family: Option<Arc<str>>,

    /// A Common Platform Enumeration identifier for the hardware, as the corpus
    /// writes it. Separate from the operating system's: a report naming both is
    /// naming two different things about one machine.
    cpe23: Option<Arc<str>>,

    /// A finer designation than the product, where a rule draws both: the label
    /// printers say `Thermal Label Printer` for one and `PC42t` for the other.
    model: Option<Arc<str>>,

    /// The hardware revision, which is not the operating system's version. An
    /// appliance running one firmware across three board revisions has one of
    /// each, and reporting either as the other is wrong in both directions.
    version: Option<Arc<str>>,

    /// The unit's own serial number, where it published one.
    ///
    /// The most identifying thing in this record and the only one that names a
    /// single box rather than a model line, which is why a redacted export drops
    /// it and keeps the rest.
    serial_number: Option<Arc<str>>,
}

/// What a service said about a box, for [`HardwareInfo::described`].
///
/// A struct rather than seven positional arguments, because seven `Option<&str>`
/// in a row is a call nobody can read and any two of which can be swapped
/// without the compiler noticing.
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
    /// The other way one of these is made. A host reached through a gateway has
    /// no MAC to read, and a banner naming `Merit LILIN PDR M800` describes the
    /// box just as well as an address block would have.
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

    /// Who made the box: what a service said about itself where one did, and
    /// otherwise the manufacturer the OUI attributes the address to, if the
    /// database recognises it. See the field for why the first outranks the
    /// second.
    pub fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    /// Who registered the address block this hardware was seen at, as the OUI
    /// database has it: the reading of the address alone.
    ///
    /// Beside [`vendor`](Self::vendor) rather than instead of it, because the
    /// two are asked for different things. `vendor` is the best answer to who
    /// made the box, and gives way to what a service says about itself. This is
    /// the one part of the record no service said, which is what lets it stand
    /// as a witness of its own beside one that did: a vendor a reply stated,
    /// read back out of the record, would be the same reply counted twice.
    ///
    /// The newest address with a registered block answers. `None` for a record
    /// with no address behind it, which is one a service described about a host
    /// reached through a gateway, and for a host seen only at randomised
    /// addresses, which have no registered block.
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
        // Read before the addresses are consumed, since the decision below is
        // about what the other record describes rather than what it saw.
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

        // A stated vendor is kept over one read from an address block, for the
        // reason the field documents: an OUI names the chip's maker and a banner
        // names the box's.
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
    /// `prune_stale_macs` cannot be that bound, since it runs only when a caller
    /// asks. Bounded by nothing else, the map would grow for as long as anything
    /// was listening: two hundred thousand sightings would leave two hundred
    /// thousand entries, held per address on the segment.
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
            product: None,
            family: None,
            cpe23: None,
            model: None,
            version: None,
            serial_number: None,
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

    /// The case that motivated the fields: a service names a box this engine has
    /// no address for, and the record has to exist without one.
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

    /// A record naming nothing is not a record. Without this every rule with an
    /// empty metadata map would attach an empty hardware entry to its host.
    #[test]
    fn a_description_naming_nothing_is_not_recorded() {
        assert!(HardwareInfo::described(HardwareDescription::default()).is_none());
    }

    /// A vendor read from an address block names whoever made the network chip;
    /// one a service stated names the box. On a Check Point firewall those are
    /// different companies, and the second is the answer.
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

    /// And a bare vendor with nothing behind it does not displace one the
    /// address block supports: it says no more, and the OUI at least came from a
    /// registry.
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
