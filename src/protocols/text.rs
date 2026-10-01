// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading a string a stranger wrote
//!
//! The three announcement protocols here carry human-readable fields inside
//! length-delimited records: a switch's system name, a printer's hostname, a
//! vendor's model string. All three clean those bytes the same way, here.

/// A length-delimited field as text, or `None` if it is not text.
///
/// Every trailing NUL is trimmed. Equipment that NUL-terminates its strings
/// often pads to the field's width, so `printer\0\0\0\0` is how a device with a
/// seven-character name fills an eleven-byte record.
///
/// Bytes that are not UTF-8 give `None`: the fields are specified as text, and
/// a device that disagrees is reported as unreadable, not rendered with
/// replacement characters.
///
/// A field that is empty once its padding is gone is `None` too, so a blank
/// record reads as an absence on the host record, not as an empty name.
pub(crate) fn field(value: &[u8]) -> Option<&str> {
    // `None` means the field was nothing but padding.
    let last = value.iter().rposition(|byte| *byte != 0)?;
    std::str::from_utf8(&value[..=last]).ok()
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

    /// A device pads to the field's width; trimming one NUL would leave the
    /// rest in the hostname.
    #[test]
    fn every_trailing_nul_is_trimmed_not_just_the_last() {
        assert_eq!(field(b"printer\0\0\0\0"), Some("printer"));
        assert_eq!(field(b"switch\0"), Some("switch"));
        assert_eq!(field(b"switch"), Some("switch"));
    }

    /// A NUL inside the string is not padding and stays, so the malformation
    /// stays visible.
    #[test]
    fn an_interior_nul_is_left_alone() {
        assert_eq!(field(b"one\0two\0\0"), Some("one\0two"));
    }

    /// A record that arrived and said nothing is an absence, not an empty name.
    #[test]
    fn a_field_that_is_only_padding_is_nothing() {
        assert_eq!(field(b""), None);
        assert_eq!(field(b"\0\0\0\0"), None);
    }

    /// The standard says these fields are text; anything else is declined.
    #[test]
    fn bytes_that_are_not_utf8_are_declined() {
        assert_eq!(field(&[0xFF, 0xFE, 0xFD]), None);
        assert_eq!(field(b"caf\xC3\xA9"), Some("café"));
    }
}
