// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the hardware address says about the software
//!
//! Usually nothing, and saying so is most of this module's job.
//!
//! ## Only a vendor whose hardware implies something says anything
//!
//! A hardware address names whoever registered the address block. For a machine
//! whose maker also writes what runs on it, that is a real signal: an address
//! belonging to Apple is on Apple hardware, and Apple hardware runs Apple's
//! operating system unless somebody went out of their way. For a commodity
//! network adapter it is no signal at all, an Intel or Realtek chip is in
//! machines running every operating system there is, and a laptop vendor's
//! block says who assembled the case.
//!
//! So this maps the first kind and **declines the second**, rather than reaching
//! for the nearest plausible answer. Declining is the whole value: an OUI source
//! that guessed would be wrong on the commonest hardware there is, and wrong in a
//! way nothing downstream could see.
//!
//! ## What a network equipment vendor implies is a class, not a family
//!
//! Cisco, Ubiquiti and the rest write their own systems too, so it is tempting to
//! read their blocks the same way. It is the wrong reading, because a great many
//! of their boxes run Linux and announce it: the address establishes that the
//! machine is infrastructure and says nothing about what is on it.
//!
//! Written as a family, `Network device` runs against `Linux` on the ballot
//! [`resolve`](super::resolve) settles by vote, and a router that had correctly
//! named itself `Debian 12` over SSH was reported as nothing at all once the scan
//! looked up its address. Those vendors state a device class and abstain from the
//! family, which is what [`OsEvidence::device`] exists for.
//!
//! ## Randomised addresses have no vendor at all
//!
//! Measured on a labelled segment: **five of eight hosts answered from a
//! locally-administered address**, one made up by the device rather than
//! assigned from a registered block. Address randomisation is a privacy default
//! on modern mobile platforms, and a vendor lookup against such an address
//! returns nothing, or worse, a coincidental match against whoever holds the
//! block those random bits happen to land in.
//!
//! [`HardwareInfo`] already declines to name a vendor for one, so that guard is
//! upstream of here. It is restated because it is the difference between this
//! source being quiet on a phone and being confidently wrong about one.
//!
//! ## What it is worth
//!
//! Little on its own, and that is correct. Apple hardware running Linux is a real
//! thing; so is a Raspberry Pi running something other than Linux. This is a
//! prior, not an identification, and [`CONFIDENCE`] is set where a lone hit stays
//! below the floor that reports anything at all. It earns its place by *agreeing*
//! with a stack reading and pushing a verdict past what one packet could support.

use crate::model::host::HardwareInfo;

use crate::model::host::OsEvidence;
use crate::model::host::OsSource;

/// What a vendor match contributes on its own.
///
/// Deliberately below the floor [`resolve`](super::resolve) reports at, so this
/// source can never name a host by itself. Hardware and software are separable,
/// the address says who made the machine, and somebody may have installed
/// anything on it. What it is good for is confirming a reading taken from the
/// wire, and for that it does not need to be large.
pub const CONFIDENCE: f32 = 0.3;

/// Vendors who ship the operating system on their own hardware, and the family
/// that implies.
///
/// Matched case-insensitively on a prefix of the registered company name, which
/// is how these appear in the OUI registry, where "Apple, Inc." and "Apple" are
/// the same organisation across decades of registrations.
///
/// The list is short on purpose. Every entry is a vendor who makes both the
/// machine and what runs on it; the moment that stops being true the entry is a
/// guess wearing the clothes of a measurement. Commodity adapter and PC makers,
/// Intel, Realtek, Broadcom, Dell, Lenovo, HP, are absent, because
/// their silicon is in machines running everything.
const VENDOR_FAMILIES: &[(&str, &str)] = &[
    // Apple hardware runs Apple's systems. Which one, macOS, iOS, iPadOS, the
    // address cannot say, and the stack cannot either: they share a kernel.
    ("apple", "macOS"),
    // The Foundation's boards are sold to run Linux and overwhelmingly do.
    ("raspberry pi", "Linux"),
];

/// Vendors whose blocks are attached to network equipment, and the class that
/// implies.
///
/// A class, not a family, and the difference is the whole reason this table is
/// separate from the one above. These vendors ship an operating system too,
/// but a great many of their boxes run Linux and say so out loud over SSH. Read
/// as a family, `Network device` runs against `Linux` on the ballot
/// [`resolve`](super::resolve) settles by vote and both lose.
///
/// That is measured rather than argued. A Linux-based router announcing
/// `Debian 12` resolved to `Linux 55, version 12` on its banner alone, and to
/// nothing at all once the same scan looked up the address it answered from.
/// Adding a true observation removed the answer, for eight of the ten vendors
/// this module knows.
///
/// So these abstain from the family and state what they actually establish,
/// which is that the box is infrastructure. Both answers then survive: a
/// `Network device` running `Linux 12`, which is what the machine is.
const VENDOR_DEVICES: &[(&str, &str)] = &[
    ("cisco", "Network device"),
    ("juniper", "Network device"),
    ("ubiquiti", "Network device"),
    ("mikrotik", "Network device"),
    ("arista", "Network device"),
    ("netgear", "Network device"),
    ("tp-link", "Network device"),
    ("zyxel", "Network device"),
];

/// What the hardware behind a host suggests, if anything: a family for a vendor
/// who ships the system on its own machines, a device class for one whose blocks
/// are attached to network equipment.
///
/// `None`, which is the common answer, when the address was randomised and has
/// no vendor, when the vendor is in neither table, or when no hardware was
/// recorded at all.
///
/// Declining is the point rather than a shortfall. A hardware address names
/// whoever registered the block: for a maker who also writes the operating
/// system that is a real signal, and for a commodity adapter it is none at all,
/// since the same silicon sits in machines running everything. A source that
/// guessed here would be wrong on the commonest hardware there is, in a way
/// nothing downstream could see.
pub fn evidence_from(hardware: &HardwareInfo) -> Option<OsEvidence> {
    // `None` here is already the randomised-address case: `HardwareInfo` does not
    // name a vendor for a locally-administered address, because there is no
    // registered block behind one.
    let vendor = hardware.vendor()?;
    let lowered = vendor.to_ascii_lowercase();

    let matches = |table: &'static [(&str, &str)]| {
        table
            .iter()
            .find(|(prefix, _)| lowered.starts_with(prefix))
            .map(|(_, value)| (*value).to_string())
    };

    // One or the other, never both: a vendor is either one whose hardware
    // implies what runs on it, or one whose hardware implies what kind of box it
    // is. Claiming both from one address block would be counting a single
    // observation twice.
    let (family, device) = match matches(VENDOR_FAMILIES) {
        Some(family) => (Some(family), None),
        None => (None, Some(matches(VENDOR_DEVICES)?)),
    };

    Some(OsEvidence {
        source: OsSource::HardwareVendor,
        family,
        device,
        // **Not the registered company**, though that is exactly what this field
        // used to carry and it reads like the obvious value for it.
        //
        // `vendor` here means whoever publishes the *operating system*, and an
        // address block establishes whoever built the *hardware*. Those
        // coincide for Apple and come apart the moment they do not: a Raspberry
        // Pi runs Debian, so the address said `Raspberry Pi Trading Ltd`, the
        // SSH banner said `Debian`, and the resolver, correctly, given what it
        // was told, treated two answers to two different questions as a
        // contradiction and kept neither. The host was reported as `Linux
        // 12.0`: a version number no Linux has, because the name that belonged
        // with it had been thrown away.
        //
        // What an address block genuinely supports is one broad claim, which is
        // what this evidence makes and all it makes: a family for a vendor who
        // ships the system, a device class for one whose boxes are
        // infrastructure. The company is not lost, it is recorded on the host's
        // hardware, where it describes the thing it is actually about, and this
        // evidence line still names it.
        vendor: None,
        product: None,
        version: None,
        kernel: None,
        cpe: None,
        confidence: CONFIDENCE,
        evidence: format!("hardware vendor {vendor}"),
    })
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
    use crate::fingerprint::os::resolve;
    use crate::model::mac::MacAddr;

    fn evidence_for(mac: &str) -> Option<OsEvidence> {
        let mac: MacAddr = mac.parse().expect("a hardware address");
        evidence_from(&HardwareInfo::new(mac))
    }

    /// A banner from a Linux-based appliance, worth enough to name a host on its
    /// own. It is the thing every entry in the device table used to destroy.
    fn a_debian_banner() -> OsEvidence {
        OsEvidence {
            source: OsSource::ServiceBanner,
            family: Some("Linux".to_string()),
            device: None,
            vendor: None,
            product: Some("Debian".to_string()),
            version: Some("12".to_string()),
            kernel: None,
            cpe: None,
            confidence: 0.55,
            evidence: "service banner names Debian".to_string(),
        }
    }

    /// The regression this split exists for.
    ///
    /// A Linux-based router, switch or access point announces `Debian 12` over
    /// SSH and answers from a registered infrastructure block. Both observations
    /// are true. Read as rival families they annihilated: the banner alone
    /// resolved the host and the banner plus its own hardware address resolved to
    /// nothing, so looking up the address destroyed the answer.
    #[test]
    fn an_infrastructure_vendor_does_not_destroy_what_the_banner_established() {
        for mac in [
            "00:1b:54:00:00:01", // Cisco
            "50:c7:bf:00:00:01", // TP-Link
            "c0:3f:0e:00:00:01", // Netgear
            "24:5a:4c:00:00:01", // Ubiquiti
        ] {
            let oui = evidence_for(mac).expect("a registered infrastructure block");
            assert_eq!(oui.family, None, "{mac} must abstain from the family");
            assert_eq!(oui.device.as_deref(), Some("Network device"));

            let alone = resolve(vec![a_debian_banner()]).expect("the banner names the host");
            let with_hardware =
                resolve(vec![a_debian_banner(), oui]).expect("and the address does not unname it");

            assert_eq!(with_hardware.family.as_deref(), Some("Linux"));
            assert_eq!(with_hardware.version.as_deref(), Some("12"));
            assert_eq!(with_hardware.device.as_deref(), Some("Network device"));
            assert_eq!(
                with_hardware.accuracy, alone.accuracy,
                "{mac} agreed about a second question, so it cost the first nothing"
            );
        }
    }

    /// A vendor who ships the system on its own machines still claims a family,
    /// which is the case the whole table was built for.
    #[test]
    fn a_vendor_who_ships_the_system_names_a_family() {
        let apple = evidence_for("a4:83:e7:00:00:01").expect("a registered Apple block");
        assert_eq!(apple.family.as_deref(), Some("macOS"));
        assert_eq!(
            apple.device, None,
            "an address block says nothing about the box"
        );

        let pi = evidence_for("b8:27:eb:00:00:01").expect("a registered Raspberry Pi block");
        assert_eq!(pi.family.as_deref(), Some("Linux"));
        assert_eq!(pi.device, None);
    }

    /// One claim per address, never both. Claiming a family and a class from one
    /// block would count a single observation twice.
    #[test]
    fn no_address_claims_a_family_and_a_class_at_once() {
        for (prefix, _) in VENDOR_FAMILIES {
            assert!(
                !VENDOR_DEVICES.iter().any(|(other, _)| other == prefix),
                "`{prefix}` is in both tables"
            );
        }
    }

    /// A lone hit still names nothing, which is what lets this be consulted on
    /// every host. Hardware and software are separable, and the address only ever
    /// corroborates something read off the wire.
    #[test]
    fn one_hardware_reading_alone_never_names_a_host() {
        for mac in ["a4:83:e7:00:00:01", "50:c7:bf:00:00:01"] {
            let oui = evidence_for(mac).expect("a registered block");
            assert!(
                resolve(vec![oui]).is_none(),
                "{mac} named a host on its own"
            );
        }
    }

    /// A commodity adapter and a randomised address both say nothing, which is
    /// most of this module's job.
    #[test]
    fn an_address_that_implies_nothing_is_declined() {
        // Intel: silicon in machines running everything.
        assert!(evidence_for("00:1b:21:00:00:01").is_none());
        // Locally administered, so `HardwareInfo` names no vendor at all.
        assert!(evidence_for("02:00:00:00:00:01").is_none());
    }
}
