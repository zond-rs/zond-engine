// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The masking [`Redaction::Standard`](super::Redaction::Standard) applies
//!
//! One function per thing a report carries that names a person or a device: a
//! hostname and a hardware address, which are the two
//! [`Redaction::Standard`](super::Redaction::Standard) masks.
//!
//! Addresses are not here. [`Redaction`](super::Redaction) states why, and it is
//! not an omission waiting to be filled: a report is a list of hosts, and a
//! masking scheme that hides which host is which collapses ten records on a /24
//! into ten copies of one string.
//!
//! [`Redaction`](super::Redaction) is where the policy is stated and where its
//! limits are, and it is the doc to read first. These are the mechanics.
//!
//! **The goal is not anonymity.** A masked hostname stays distinguishable from
//! the next one so a reader can still follow a host through a report, and that
//! is the whole of what is promised. Nothing here defeats somebody who knows the
//! network.

use crate::model::mac::MacAddr;

/// Masks a hostname, keeping its first and last two characters so two masked
/// names still read as two names.
///
/// The middle becomes a fixed run of `X`, which hides the length as well as the
/// content: a five-character name and a fifty-character one mask to the same
/// width.
///
/// A name with fewer than six characters is masked whole. Keeping two at each
/// end of a five-character name would leave four of its five, which is not a
/// masked name at all.
///
/// # Examples
/// ```
/// use zond_engine::export::redact;
///
/// assert_eq!(redact::hostname("kabelbox.local"), "kaXXXXXal");
/// assert_eq!(redact::hostname("workstation"), "woXXXXXon");
/// assert_eq!(redact::hostname("router"), "roXXXXXer");
/// assert_eq!(redact::hostname("modem"), "XXXXX");
/// assert_eq!(redact::hostname("pc"), "XXXXX");
/// ```
pub fn hostname(name: &str) -> String {
    /// Below this, the two kept at each end are most of the name.
    const SHORTEST_WORTH_KEEPING_ENDS_OF: usize = 6;

    let char_count = name.chars().count();

    if char_count < SHORTEST_WORTH_KEEPING_ENDS_OF {
        return "XXXXX".to_string();
    }

    let first_two: String = name.chars().take(2).collect();
    let last_two: String = name
        .chars()
        .rev()
        .take(2)
        .collect::<String>()
        .chars()
        .rev()
        .collect();

    format!("{}XXXXX{}", first_two, last_two)
}

/// Redacts a MAC address to prevent hardware fingerprinting.
///
/// Returns a string where the last three octets are replaced by 'XX'.
///
/// # Examples
/// ```
/// use zond_engine::model::mac::MacAddr;
/// use zond_engine::export::redact;
///
/// let mac = MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3);
/// assert_eq!(redact::mac_addr(&mac), "2c:cf:67:XX:XX:XX");
/// ```
pub fn mac_addr(mac: &MacAddr) -> String {
    let octets = mac.octets();
    format!(
        "{:02x}:{:02x}:{:02x}:XX:XX:XX",
        octets[0], octets[1], octets[2]
    )
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

    #[test]
    fn mac_redaction_upper_boundary() {
        let mac = MacAddr::new(0xff, 0xff, 0xff, 0x00, 0x11, 0x22);
        assert_eq!(mac_addr(&mac), "ff:ff:ff:XX:XX:XX");
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest::proptest! {
        /// A masked name keeps its two ends and nothing between them, whatever
        /// was there and however much of it.
        #[test]
        fn a_masked_hostname_keeps_its_ends_and_loses_its_middle(
            name in "[a-zA-Z0-9.-]{6,64}"
        ) {
            let redacted = hostname(&name);
            prop_assert!(redacted.contains("XXXXX"));
            prop_assert!(redacted.starts_with(&name[..2]));
            prop_assert!(redacted.ends_with(&name[name.len() - 2..]));
            prop_assert_eq!(redacted.len(), 9, "every masked name is one width");
        }

        /// And a name short enough that its ends would be most of it keeps
        /// neither.
        #[test]
        fn a_short_hostname_is_masked_whole(name in "[a-zA-Z0-9.-]{0,5}") {
            prop_assert_eq!(hostname(&name), "XXXXX");
        }

        /// Verify that MAC redaction always preserves only the first 3 octets (OUI).
        #[test]
        fn mac_redaction_preserves_oui(
            o1 in 0..=255u8, o2 in 0..=255u8, o3 in 0..=255u8,
            o4 in 0..=255u8, o5 in 0..=255u8, o6 in 0..=255u8
        ) {
            let mac = MacAddr::new(o1, o2, o3, o4, o5, o6);
            let redacted = mac_addr(&mac);
            let expected_prefix = format!("{:02x}:{:02x}:{:02x}", o1, o2, o3);
            prop_assert!(redacted.starts_with(&expected_prefix));
            prop_assert!(redacted.ends_with("XX:XX:XX"));
        }

    }
}
