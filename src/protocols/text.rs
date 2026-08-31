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
//! vendor's model string. They all need the same two things done to those bytes
//! before anything downstream sees them, and doing it three times is how the
//! three came to disagree.

/// A length-delimited field as text, or `None` if it is not text.
///
/// Two things happen here, and both are about a field whose width is fixed and
/// whose contents are not.
///
/// **Padding is trimmed.** Equipment that NUL-terminates its strings routinely
/// pads past the terminator to the width of the field, so `printer\0\0\0\0` is
/// how a device with a seven-character name fills an eleven-byte record. Every
/// trailing NUL goes, not just the last one: a hostname carrying three of them
/// into a report is a hostname nobody can search for.
///
/// **Bytes that are not UTF-8 are declined.** These fields are specified as
/// text, and a device that disagrees has produced something to report as
/// unreadable rather than to render with replacement characters. That is the
/// rule every reader in this module follows.
///
/// A field that is empty, or empty once its padding is gone, is `None` as well:
/// a device that sent the record and left it blank has said nothing, and an
/// empty string on a host record reads as a name rather than as an absence.
pub(crate) fn field(value: &[u8]) -> Option<&str> {
    // `trim_end_matches` is a `str` method and these are bytes, so the last
    // non-NUL is found directly. `None` means the field was nothing but padding.
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

    /// The case the three copies of this function got wrong: a device pads to
    /// the width of the field, and trimming one NUL leaves the rest in the
    /// hostname that reaches a host record.
    #[test]
    fn every_trailing_nul_is_trimmed_not_just_the_last() {
        assert_eq!(field(b"printer\0\0\0\0"), Some("printer"));
        assert_eq!(field(b"switch\0"), Some("switch"));
        assert_eq!(field(b"switch"), Some("switch"));
    }

    /// A NUL inside the string is not padding and stays, because a field that
    /// genuinely carries one is malformed in a way worth seeing rather than
    /// worth silently repairing.
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

    /// The standard says these fields are text. A device that disagrees is
    /// declined rather than rendered with replacement characters.
    #[test]
    fn bytes_that_are_not_utf8_are_declined() {
        assert_eq!(field(&[0xFF, 0xFE, 0xFD]), None);
        assert_eq!(field(b"caf\xC3\xA9"), Some("café"));
    }
}
