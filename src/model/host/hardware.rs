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

use crate::model::mac::{self, MacAddr};
use std::{collections::BTreeMap, sync::Arc, time::Instant};

/// The MAC addresses a host has answered under, and who made its hardware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareInfo {
    /// Every MAC seen for this host, against the last time each was.
    ///
    /// A `BTreeMap` so that iteration order is the addresses' own and not a
    /// hash seed's: a report listing them twice must list them the same way
    /// twice.
    macs: BTreeMap<MacAddr, Instant>,

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
        macs.insert(mac, Instant::now());

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
        self.macs.insert(mac, Instant::now());

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
    pub fn macs(&self) -> &BTreeMap<MacAddr, Instant> {
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
    pub fn prune_stale_macs(&mut self, cutoff: Instant) {
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

    #[test]
    fn hardware_vendor_assignment() {
        let mac = MacAddr::new(0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF);
        let hw = HardwareInfo::new(mac);

        assert_eq!(hw.vendor(), Some("VMware, Inc"));
        assert!(hw.macs().contains_key(&mac));
    }

    #[test]
    fn test_most_recent_mac_selection() {
        let mac_old = MacAddr::new(1, 1, 1, 1, 1, 1);
        let mac_new = MacAddr::new(2, 2, 2, 2, 2, 2);

        let mut hw = HardwareInfo::new(mac_old);
        let future_time = Instant::now() + Duration::from_secs(60);
        hw.macs.insert(mac_new, future_time);

        assert_eq!(hw.most_recent_mac(), Some(mac_new));
    }

    #[test]
    fn most_recent_mac_on_empty() {
        // Construct an empty one manually via the pub(crate) field
        let hw = HardwareInfo {
            macs: BTreeMap::new(),
            vendor: None,
        };
        assert_eq!(hw.most_recent_mac(), None);
    }

    #[test]
    fn prune_stale_macs_logic() {
        let mac_keep = MacAddr::new(1, 1, 1, 1, 1, 1);
        let mac_drop = MacAddr::new(2, 2, 2, 2, 2, 2);

        let mut hw = HardwareInfo::new(mac_keep);
        let past_time = Instant::now() - Duration::from_secs(3600);
        hw.macs.insert(mac_drop, past_time);

        let cutoff = Instant::now() - Duration::from_secs(1800);
        hw.prune_stale_macs(cutoff);

        assert_eq!(hw.macs().len(), 1);
        assert!(hw.macs().contains_key(&mac_keep));
    }
}
