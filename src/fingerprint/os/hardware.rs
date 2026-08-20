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
//! ## Only a vendor who ships the operating system tells you anything
//!
//! A hardware address names whoever registered the address block. For a machine
//! whose maker also writes what runs on it, that is a real signal: an address
//! belonging to Apple is on Apple hardware, and Apple hardware runs Apple's
//! operating system unless somebody went out of their way. For a commodity
//! network adapter it is no signal at all — an Intel or Realtek chip is in
//! machines running every operating system there is, and a laptop vendor's block
//! says who assembled the case.
//!
//! So this maps the first kind and **declines the second**, rather than reaching
//! for the nearest plausible answer. Declining is the whole value: an OUI source
//! that guessed would be wrong on the commonest hardware there is, and wrong in a
//! way nothing downstream could see.
//!
//! ## Randomised addresses have no vendor at all
//!
//! Measured on a labelled segment: **five of eight hosts answered from a
//! locally-administered address** — one made up by the device rather than
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

use super::evidence::OsEvidence;
use super::verdict::OsSource;

/// What a vendor match contributes on its own.
///
/// Deliberately below the floor [`resolve`](super::resolve) reports at, so this
/// source can never name a host by itself. Hardware and software are separable —
/// the address says who made the machine, and somebody may have installed
/// anything on it. What it is good for is confirming a reading taken from the
/// wire, and for that it does not need to be large.
pub const CONFIDENCE: f32 = 0.3;

/// Vendors who ship the operating system on their own hardware, and the family
/// that implies.
///
/// Matched case-insensitively on a prefix of the registered company name, which
/// is how these appear in the OUI registry — "Apple, Inc." and "Apple" are the
/// same organisation across decades of registrations.
///
/// **The list is short on purpose.** Every entry is a vendor who makes both the
/// machine and what runs on it; the moment that stops being true the entry is a
/// guess wearing the clothes of a measurement. Commodity adapter and PC makers —
/// Intel, Realtek, Broadcom, Dell, Lenovo, HP — are deliberately absent, because
/// their silicon is in machines running everything.
const VENDOR_FAMILIES: &[(&str, &str)] = &[
    // Apple hardware runs Apple's systems. Which one — macOS, iOS, iPadOS — the
    // address cannot say, and the stack cannot either: they share a kernel.
    ("apple", "macOS"),
    // The Foundation's boards are sold to run Linux and overwhelmingly do.
    ("raspberry pi", "Linux"),
    // Network equipment vendors, whose own systems are what these addresses are
    // attached to. The family matches the rule in
    // `assets/fingerprinting/os/network-device.toml`.
    ("cisco", "Network device"),
    ("juniper", "Network device"),
    ("ubiquiti", "Network device"),
    ("mikrotik", "Network device"),
    ("arista", "Network device"),
    ("netgear", "Network device"),
    ("tp-link", "Network device"),
    ("zyxel", "Network device"),
];

/// What the hardware behind a host suggests it runs, if anything.
///
/// `None` — which is the common answer — when the address was randomised and has
/// no vendor, when the vendor is not one that ships an operating system, or when
/// no hardware was recorded at all.
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

    let (_, family) = VENDOR_FAMILIES
        .iter()
        .find(|(prefix, _)| lowered.starts_with(prefix))?;

    Some(OsEvidence {
        source: OsSource::HardwareVendor,
        family: (*family).to_string(),
        // The registered company, not a guess at a product line.
        vendor: Some(vendor.to_string()),
        product: None,
        version: None,
        cpe: None,
        confidence: CONFIDENCE,
        evidence: format!("hardware vendor {vendor}"),
    })
}
