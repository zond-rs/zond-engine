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
//! The type is this crate's own, so the packet library stays out of public signatures.
//! A MAC crosses the whole engine (an ARP reply produces one, a host record keeps them,
//! a report prints them), and the frame builders and readers in
//! [`protocols`](crate::protocols) and [`transport`](crate::transport) use it too.

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
    /// The address every station on a segment receives, `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xff; 6]);

    /// The all-zero address, which names no station: what an ARP request carries as
    /// the target hardware address it asks for, and what a reader takes as "not
    /// stated".
    pub const ZERO: Self = Self([0; 6]);

    /// Creates a `MacAddr` from six octets, most significant first.
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self([a, b, c, d, e, f])
    }

    /// The six octets, most significant first.
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// Whether this address was assigned locally, not allocated to a manufacturer,
    /// as the second-least-significant bit of the first octet marks.
    ///
    /// There is no OUI to look up for one, so [`vendor`] returns `None`. A device
    /// randomizing its address produces them, so one host may answer under a series
    /// of unrelated addresses.
    pub const fn is_locally_administered(self) -> bool {
        self.0[0] & 0b0000_0010 != 0
    }

    /// Whether this is a group address, as the least significant bit of the first
    /// octet marks.
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 0b0000_0001 != 0
    }

    /// Whether this is [`BROADCAST`](Self::BROADCAST).
    pub const fn is_broadcast(self) -> bool {
        matches!(self.0, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }

    /// Whether this is [`ZERO`](Self::ZERO).
    pub const fn is_zero(self) -> bool {
        matches!(self.0, [0, 0, 0, 0, 0, 0])
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
#[non_exhaustive]
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
    /// The colon form is what Unix tooling prints and [`fmt::Display`] writes; the
    /// hyphen form is what Windows and most printed labels use.
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

/// The manufacturer database, loaded once. `None` records a load that failed; see
/// [`oui_db`].
static OUI_DB: OnceLock<Option<Oui>> = OnceLock::new();

/// The OUI database, loaded once, or `None` if it could not be loaded at all.
///
/// A failure is remembered and not raised: the database is compiled in, so a load that
/// fails once fails every time, and a scan without manufacturer names is still a scan.
fn oui_db() -> Option<&'static Oui> {
    OUI_DB.get_or_init(|| Oui::default().ok()).as_ref()
}

/// The manufacturer `mac`'s OUI is allocated to, if the database recognises it.
///
/// `None` for a [locally administered](MacAddr::is_locally_administered)
/// address, which is allocated to nobody, and for an address whose OUI is not
/// in the database.
///
/// The first case is read from the address bit, independent of the database, which
/// also skips a lookup for every rotation of a randomized address.
pub fn vendor(mac: &MacAddr) -> Option<String> {
    if mac.is_locally_administered() {
        return None;
    }
    let entry = oui_db()?.lookup_by_mac(&mac.to_string()).ok()??;
    Some(entry.company_name.clone())
}

/// Loads the manufacturer database, where nothing has yet, on the blocking
/// pool, for a pass that reads link-layer addresses to call before its first
/// frame is read.
///
/// Otherwise the database loads the first time a host's address is recorded, inside
/// the task that read the frame. Parsing tens of thousands of entries takes some
/// hundreds of milliseconds in a debug build, and a runtime worker busy with it delays
/// every probe answer it would have read, skewing their timings.
pub(crate) async fn load_vendors() {
    // A failed load is remembered by `oui_db`, so the result can be ignored.
    let _ = tokio::task::spawn_blocking(|| {
        oui_db();
    })
    .await;
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
    /// [`vendor`] queries the OUI database with this exact string, and readers paste
    /// it into their own tooling. `Debug` matches `Display` so a logged address matches
    /// the report.
    #[test]
    fn an_address_renders_as_lowercase_colon_separated_hex() {
        let mac = MacAddr::new(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E);
        assert_eq!(mac.to_string(), "00:1a:2b:3c:4d:5e");
        assert_eq!(format!("{mac:?}"), "00:1a:2b:3c:4d:5e");
    }

    /// The conversions to and from raw octets keep their order; frame parsing relies
    /// on them.
    #[test]
    fn octets_survive_the_conversions_frame_parsing_uses() {
        let octets = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mac = MacAddr::from(octets);

        assert_eq!(mac.octets(), octets);
        assert_eq!(<[u8; 6]>::from(mac), octets);
    }

    /// The form `Display` writes is the form `FromStr` reads.
    #[test]
    fn an_address_round_trips_through_its_own_rendering() {
        let mac = MacAddr::new(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E);
        assert_eq!(mac.to_string().parse(), Ok(mac));
    }

    /// Both separators and either case parse.
    #[test]
    fn both_separators_and_either_case_are_accepted() {
        let mac = MacAddr::new(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E);
        assert_eq!("00-1A-2B-3C-4D-5E".parse(), Ok(mac));
        assert_eq!("00:1a:2b:3c:4d:5e".parse(), Ok(mac));
    }

    /// Each of these is refused outright: an address that silently loses an octet
    /// identifies the wrong device.
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

    /// The locally administered and multicast bits are read from the first octet.
    #[test]
    fn the_locally_administered_and_multicast_bits_are_read() {
        assert!(MacAddr::new(0x02, 0, 0, 0, 0, 0).is_locally_administered());
        assert!(!MacAddr::new(0x00, 0x0C, 0x29, 0, 0, 0).is_locally_administered());
        assert!(MacAddr::new(0x01, 0, 0x5e, 0, 0, 0).is_multicast());
        assert!(!MacAddr::new(0x00, 0x0C, 0x29, 0, 0, 0).is_multicast());
    }

    /// The database is queried with the address's [`fmt::Display`] form, so a change
    /// to how a MAC renders would stop every vendor resolving.
    ///
    /// Asserts only that some vendor resolves, so a data update to the third-party
    /// database cannot break it.
    #[test]
    fn a_registered_oui_resolves_to_a_vendor() {
        let vmware = MacAddr::new(0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF);
        assert!(vendor(&vmware).is_some());
    }

    /// A locally administered address has no OUI to resolve. The second address is a
    /// registered OUI with the local bit set, so this tests the bit check, not the
    /// database contents.
    #[test]
    fn a_locally_administered_address_has_no_vendor() {
        let local = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x00);
        assert_eq!(vendor(&local), None);

        let registered_but_local = MacAddr::new(0x02, 0x0C, 0x29, 0xAB, 0xCD, 0xEF);
        assert!(registered_but_local.is_locally_administered());
        assert_eq!(vendor(&registered_but_local), None);
    }
}
