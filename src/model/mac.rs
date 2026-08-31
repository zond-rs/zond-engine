// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Hardware addresses
//!
//! [`MacAddr`] is the 48-bit address a device answers under on its segment, and
//! [`vendor`] is who made the hardware, looked up from the address's
//! Organizationally Unique Identifier.
//!
//! The type is this crate's own rather than a packet library's, so that the
//! vocabulary a report is written in does not change when the layer that reads
//! frames does. A MAC crosses the whole engine — an ARP reply produces one, a
//! host record keeps every one it has seen, and a report prints them — and
//! borrowing the type from whichever crate happens to parse Ethernet today
//! would put that crate in every one of those signatures.

use mac_oui::Oui;
use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

/// A 48-bit hardware address.
///
/// Ordered and hashable, so a host's addresses can be kept in a sorted map and
/// rendered in the same order twice.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// Creates a `MacAddr` from six octets, most significant first.
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self([a, b, c, d, e, f])
    }

    /// The six octets, most significant first.
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// Whether this address was assigned by whoever is using it rather than
    /// allocated to a manufacturer, which the second-least-significant bit of
    /// the first octet marks.
    ///
    /// There is no OUI to look up for one of these, so
    /// [`vendor`] returns `None`. A device randomizing its address produces
    /// them, which is worth knowing when the same host answers under a series
    /// of addresses that share nothing.
    pub const fn is_locally_administered(self) -> bool {
        self.0[0] & 0b0000_0010 != 0
    }

    /// Whether this address is a group address rather than one interface's,
    /// which the least significant bit of the first octet marks.
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 0b0000_0001 != 0
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(mac: MacAddr) -> Self {
        mac.0
    }
}

/// Why a string could not be read as a hardware address.
///
/// Open rather than `#[non_exhaustive]`, unlike every error *enum* in this
/// module. There is one way to fail here and one thing worth saying about it,
/// so a second field would be a different type rather than a growth of this
/// one, and sealing it would cost a caller the ability to write the literal
/// without buying anything.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{input}' is not a MAC address: expected six hex octets separated by ':' or '-'")]
pub struct MacAddrParseError {
    /// What the caller wrote.
    pub input: String,
}

impl FromStr for MacAddr {
    type Err = MacAddrParseError;

    /// Reads `00:1a:2b:3c:4d:5e`, in either case, and the same address written
    /// with `-` between the octets.
    ///
    /// Both separators because both are in circulation: the colon form is what
    /// Unix tooling prints and what [`fmt::Display`] writes, and the hyphen form
    /// is what Windows and most printed labels use.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fail = || MacAddrParseError {
            input: s.to_string(),
        };

        let mut octets = [0u8; 6];
        let mut parts = s.trim().split([':', '-']);

        for octet in &mut octets {
            let part = parts.next().ok_or_else(fail)?;
            if part.len() != 2 {
                return Err(fail());
            }
            *octet = u8::from_str_radix(part, 16).map_err(|_| fail())?;
        }

        if parts.next().is_some() {
            return Err(fail());
        }

        Ok(Self(octets))
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

static OUI_DB: OnceLock<Option<Oui>> = OnceLock::new();

/// The OUI database, loaded once, or `None` if it could not be loaded at all.
///
/// A failure is recorded rather than retried or raised. The database is
/// compiled in, so a load that fails once fails every time, and there is
/// nothing a caller could do about it in any case. A scan that cannot name a
/// manufacturer has still found every address it found — that is not worth
/// taking down a process that embeds this crate.
fn oui_db() -> Option<&'static Oui> {
    OUI_DB.get_or_init(|| Oui::default().ok()).as_ref()
}

/// The manufacturer `mac`'s OUI is allocated to, if the database recognises it.
///
/// `None` for a [locally administered](MacAddr::is_locally_administered)
/// address, which is allocated to nobody, and for an address whose OUI is not
/// in the database.
///
/// The first of those is answered here rather than left to the database. It is a
/// property of the address, readable from one bit, and reading it is what makes
/// the sentence above true of this function instead of true of a data file this
/// crate does not maintain. It is also the cheap answer for the case that asks
/// most often: a device randomizing its address produces a new one per rotation,
/// and each would otherwise be rendered to a string and looked up to establish
/// what its second bit already said.
pub fn vendor(mac: &MacAddr) -> Option<String> {
    if mac.is_locally_administered() {
        return None;
    }
    let entry = oui_db()?.lookup_by_mac(&mac.to_string()).ok()??;
    Some(entry.company_name.clone())
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

    /// Lowercase hex, colon-separated, and the same from both formatters.
    ///
    /// Pinned because two things read it rather than a person only: [`vendor`]
    /// queries the OUI database with this exact string, and a report prints it
    /// for a reader who will paste it into their own tooling. `Debug` matches
    /// `Display` so that an address logged inside a larger structure is the
    /// same address the report shows.
    #[test]
    fn an_address_renders_as_lowercase_colon_separated_hex() {
        let mac = MacAddr::new(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E);
        assert_eq!(mac.to_string(), "00:1a:2b:3c:4d:5e");
        assert_eq!(format!("{mac:?}"), "00:1a:2b:3c:4d:5e");
    }

    /// The conversions to and from raw octets are the boundary with the code
    /// that reads frames, which has bytes and no opinion about them. Losing the
    /// order here would misattribute every address a capture produced.
    #[test]
    fn octets_survive_the_conversions_frame_parsing_uses() {
        let octets = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mac = MacAddr::from(octets);

        assert_eq!(mac.octets(), octets);
        assert_eq!(<[u8; 6]>::from(mac), octets);
    }

    /// The form `Display` writes has to be the form `FromStr` reads, or an
    /// address cannot survive a trip through a report and back.
    #[test]
    fn an_address_round_trips_through_its_own_rendering() {
        let mac = MacAddr::new(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E);
        assert_eq!(mac.to_string().parse(), Ok(mac));
    }

    /// The hyphenated form is what Windows and most printed labels use, and
    /// case is not part of an address.
    #[test]
    fn both_separators_and_either_case_are_accepted() {
        let mac = MacAddr::new(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E);
        assert_eq!("00-1A-2B-3C-4D-5E".parse(), Ok(mac));
        assert_eq!("00:1a:2b:3c:4d:5e".parse(), Ok(mac));
    }

    /// Each of these is a plausible thing to type or to read out of a file, and
    /// each has to be refused rather than half-parsed: an address that silently
    /// loses an octet identifies the wrong device.
    #[test]
    fn malformed_addresses_are_refused() {
        for input in [
            "",
            "00:1a:2b:3c:4d",
            "00:1a:2b:3c:4d:5e:6f",
            "zz:1a:2b:3c:4d:5e",
            "001a2b3c4d5e",
        ] {
            assert!(
                input.parse::<MacAddr>().is_err(),
                "'{input}' parsed as an address"
            );
        }
    }

    /// The bit that says an address was assigned locally rather than allocated,
    /// which is why no vendor resolves for one.
    #[test]
    fn the_locally_administered_and_multicast_bits_are_read() {
        assert!(MacAddr::new(0x02, 0, 0, 0, 0, 0).is_locally_administered());
        assert!(!MacAddr::new(0x00, 0x0C, 0x29, 0, 0, 0).is_locally_administered());
        assert!(MacAddr::new(0x01, 0, 0x5e, 0, 0, 0).is_multicast());
        assert!(!MacAddr::new(0x00, 0x0C, 0x29, 0, 0, 0).is_multicast());
    }

    /// The database is queried with the address's [`fmt::Display`] form, so a
    /// change to how a MAC renders stops every vendor resolving and nothing
    /// else goes wrong to say so.
    ///
    /// That a registered OUI resolves to some vendor catches it. Asserting
    /// which one would pin a third-party database's spelling of a company name
    /// and break on a data update this crate is not party to, which tests the
    /// dependency rather than the two lines here.
    #[test]
    fn a_registered_oui_resolves_to_a_vendor() {
        let vmware = MacAddr::new(0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF);
        assert!(vendor(&vmware).is_some());
    }

    /// The second bit of the first octet marks an address as locally
    /// administered, which means it was assigned by whoever is using it rather
    /// than allocated to a manufacturer. There is no OUI to resolve, and no
    /// data update can give it one.
    ///
    /// Answered by reading the bit, so this asserts something about the two
    /// lines above it. It used to assert that the OUI database happens to hold
    /// no entry for `02:…`, which is the dependency's business and not this
    /// crate's, and which the test beside it declines to do for the same
    /// reason. The second address here is a registered OUI with the local bit
    /// set, which no database can answer for either way.
    #[test]
    fn a_locally_administered_address_has_no_vendor() {
        let local = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x00);
        assert_eq!(vendor(&local), None);

        let registered_but_local = MacAddr::new(0x02, 0x0C, 0x29, 0xAB, 0xCD, 0xEF);
        assert!(registered_but_local.is_locally_administered());
        assert_eq!(vendor(&registered_but_local), None);
    }
}
