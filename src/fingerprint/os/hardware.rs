// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the hardware address says about the software
//!
//! Usually nothing.
//!
//! ## Only some vendors imply a system
//!
//! An address block names whoever registered it. Apple hardware almost always
//! runs Apple's systems, so that is a signal. An Intel or Realtek adapter, or a
//! PC maker's block, says nothing about the software, and is declined.
//!
//! ## Network equipment implies a class
//!
//! Cisco, Ubiquiti and similar vendors' boxes often run Linux, so their blocks
//! establish only that the machine is infrastructure. As a family,
//! `Network device` would cancel a router's correct `Debian 12` SSH reading in
//! [`resolve`](super::resolve)'s vote; they state a device class instead
//! ([`OsEvidence::device`]).
//!
//! ## Randomised addresses
//!
//! On a labelled segment five of eight hosts answered from a
//! locally-administered (randomised) address. [`HardwareInfo`] names no vendor
//! for one, so this source stays quiet rather than matching a random block.
//!
//! ## Worth
//!
//! A prior, not an identification: Apple hardware can run Linux. [`CONFIDENCE`]
//! keeps a lone hit below the reporting floor.

use crate::model::host::HardwareInfo;

use crate::model::host::OsEvidence;
use crate::model::host::OsSource;

/// What a vendor match contributes on its own.
///
/// Below the floor [`resolve`](super::resolve) reports at, so this source never
/// names a host by itself.
pub const CONFIDENCE: f32 = 0.3;

/// Vendors who ship the operating system on their own hardware, and the family
/// that implies.
///
/// Matched case-insensitively on a prefix of the registered company name, since
/// the OUI registry spells one organisation several ways ("Apple, Inc.",
/// "Apple").
///
/// Only vendors who make both the machine and its system. Commodity makers
/// (Intel, Realtek, Broadcom, Dell, Lenovo, HP) are absent.
const VENDOR_FAMILIES: &[(&str, &str)] = &[
    // Which Apple system (macOS, iOS, iPadOS) neither the address nor the stack
    // can say.
    ("apple", "macOS"),
    // The Foundation's boards are sold to run Linux and overwhelmingly do.
    ("raspberry pi", "Linux"),
];

/// Vendors whose blocks are attached to network equipment, and the class that
/// implies.
///
/// A class, not a family: many of these boxes run Linux and say so over SSH. As
/// a family, `Network device` and `Linux` would cancel in
/// [`resolve`](super::resolve)'s vote. As a class, both survive: a
/// `Network device` running `Linux 12`.
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
/// `None`, the common answer, when the address was randomised, the vendor is in
/// neither table, or no hardware was recorded.
pub fn evidence_from(hardware: &HardwareInfo) -> Option<OsEvidence> {
    // The address's registered vendor only: a vendor a service stated is that
    // service's evidence already, and counting it again would let one SNMP
    // reply skip the active probe.
    let vendor = hardware.registered_vendor()?;
    let lowered = vendor.to_ascii_lowercase();

    let matches = |table: &'static [(&str, &str)]| {
        table
            .iter()
            .find(|(prefix, _)| lowered.starts_with(prefix))
            .map(|(_, value)| (*value).to_string())
    };

    // A family or a class, never both from one address.
    let (family, device) = match matches(VENDOR_FAMILIES) {
        Some(family) => (Some(family), None),
        None => (None, Some(matches(VENDOR_DEVICES)?)),
    };

    Some(OsEvidence {
        source: OsSource::HardwareVendor,
        family,
        device,
        // **Not the registered company.** `vendor` is the operating system's
        // publisher; the address names the hardware maker. A Raspberry Pi
        // running Debian would otherwise contradict its own SSH banner. The
        // company stays on the host's hardware record and in the evidence line.
        vendor: None,
        product: None,
        version: None,
        kernel: None,
        arch: None,
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

    /// A banner from a Linux-based appliance, enough to name a host alone.
    fn a_debian_banner() -> OsEvidence {
        OsEvidence {
            source: OsSource::ServiceBanner,
            family: Some("Linux".to_string()),
            device: None,
            vendor: None,
            product: Some("Debian".to_string()),
            version: Some("12".to_string()),
            kernel: None,
            arch: None,
            cpe: None,
            confidence: 0.55,
            evidence: "service banner names Debian".to_string(),
        }
    }

    /// A Linux-based router announcing `Debian 12` from an infrastructure block
    /// keeps its answer when the address is added.
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

    /// A vendor who ships the system on its own machines claims a family.
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

    /// One claim per address, never both.
    #[test]
    fn no_address_claims_a_family_and_a_class_at_once() {
        for (prefix, _) in VENDOR_FAMILIES {
            assert!(
                !VENDOR_DEVICES.iter().any(|(other, _)| other == prefix),
                "`{prefix}` is in both tables"
            );
        }
    }

    /// A lone hit names nothing.
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

    /// A vendor a service stated is that service's evidence, and never this
    /// module's, whichever vendor the tables know.
    ///
    /// A mapped vendor stated by a service, on a host with no address, yields
    /// nothing. Where an address exists it is still read (the last assertion).
    #[test]
    fn a_described_vendor_is_never_counted_as_the_address_reading() {
        use crate::model::host::HardwareDescription;

        for (prefix, _) in VENDOR_FAMILIES.iter().chain(VENDOR_DEVICES) {
            let described = HardwareInfo::described(HardwareDescription {
                vendor: Some(prefix),
                product: Some("described by its own service"),
                ..HardwareDescription::default()
            })
            .expect("a vendor and a product name something");
            assert!(
                evidence_from(&described).is_none(),
                "`{prefix}`, stated by a service, was counted again as the hardware's own"
            );
        }

        // An Apple address still reads as Apple whatever a service said.
        let mut seen = HardwareInfo::new("a4:83:e7:00:00:01".parse().expect("an address"));
        seen.merge(
            HardwareInfo::described(HardwareDescription {
                vendor: Some("Check Point"),
                product: Some("Firewall-1"),
                ..HardwareDescription::default()
            })
            .expect("names something"),
        );
        assert_eq!(
            seen.vendor(),
            Some("Check Point"),
            "test premise: the stated vendor leads"
        );
        assert_eq!(
            evidence_from(&seen)
                .and_then(|evidence| evidence.family)
                .as_deref(),
            Some("macOS")
        );
    }

    /// A commodity adapter and a randomised address both say nothing.
    #[test]
    fn an_address_that_implies_nothing_is_declined() {
        // Intel.
        assert!(evidence_for("00:1b:21:00:00:01").is_none());
        // Locally administered, so `HardwareInfo` names no vendor at all.
        assert!(evidence_for("02:00:00:00:00:01").is_none());
    }
}
