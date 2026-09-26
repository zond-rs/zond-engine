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
//! hostname and a hardware address. Beside them, crate-private, the mechanics
//! [`HostRedaction`](super::HostRedaction) applies to free text a host's own
//! replies filled: finding the names that host gave, and telling a reply that
//! is text from one that is not.
//!
//! [`Redaction`](super::Redaction) states the policy and its limits, including
//! why addresses are not masked. Read that first; these are the mechanics.
//!
//! The goal is not anonymity. A masked hostname stays distinguishable from the
//! next one so a reader can still follow a host through a report, and that is
//! the whole of what is promised.

use std::borrow::Cow;

use crate::model::mac::MacAddr;

/// Masks a hostname, keeping its first and last two characters so two masked
/// names still read as two names.
///
/// The middle becomes a fixed run of `X` rather than one per character, so the
/// length goes with it: `router` and a fifty-character name both mask to nine
/// characters.
///
/// A name with fewer than six characters is masked whole, and is the one case
/// that does not come out nine wide. Keeping two at each end of a five-character
/// name would leave four of its five, so a short name loses its ends as well.
///
/// # Examples
/// ```
/// use zond_engine::export::redact;
///
/// assert_eq!(redact::hostname("gateway.local"), "gaXXXXXal");
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

    format!("{first_two}XXXXX{last_two}")
}

/// Masks a hardware address, keeping the OUI.
///
/// The first three octets are the vendor and the last three are the individual
/// card, so this is the cut that leaves a report saying what a device is made
/// by without saying which one it is.
///
/// # Examples
/// ```
/// use zond_engine::model::mac::MacAddr;
/// use zond_engine::export::redact;
///
/// let mac = MacAddr::new(0x2c, 0xcf, 0x67, 0x00, 0x00, 0x01);
/// assert_eq!(redact::mac_addr(&mac), "2c:cf:67:XX:XX:XX");
/// ```
pub fn mac_addr(mac: &MacAddr) -> String {
    let octets = mac.octets();
    format!(
        "{:02x}:{:02x}:{:02x}:XX:XX:XX",
        octets[0], octets[1], octets[2]
    )
}

/// What stands in for an excerpt that is not text, under redaction.
///
/// A binary reply carries names in forms a search of the text cannot be sure
/// to find: a NetBIOS name in half-ASCII, a DNS name as length-prefixed labels,
/// a realm inside DER, a name never recorded as one at all. Its bytes are also
/// what makes such an excerpt worth reading, so a masked copy of them is
/// neither safe nor useful, and the finding keeps its title and its claim
/// without them.
pub(crate) const WITHHELD_EXCERPT: &str = "(binary reply withheld under redaction)";

/// Whether `text` holds a character no text reply carries: a control other
/// than a tab or a line break, as a reply read byte for byte has wherever the
/// protocol is binary.
pub(crate) fn is_binary(text: &str) -> bool {
    text.chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
}

/// One name to find in free text, with the mask it is replaced by.
#[derive(Debug, Clone)]
pub(crate) struct Needle {
    chars: Vec<char>,
    mask: String,
}

impl Needle {
    /// The needles for the names a host is known by: each name whole, and the
    /// first label of a dotted one, which is the machine's own name and the
    /// form a banner or a NetBIOS reply gives it in. A label that is also a
    /// name in its own right is masked as that name is, so a NetBIOS domain
    /// reads the same in the text as in its field. Longest first, so a whole
    /// name is masked before its first label could be.
    pub(crate) fn for_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<Needle> {
        let names: Vec<&str> = names.into_iter().collect();
        let mut needles: Vec<Needle> = Vec::new();
        let mut push = |name: &str| {
            let name = name.trim();
            if name.is_empty()
                || needles
                    .iter()
                    .any(|needle| same_letters(&needle.chars, name))
            {
                return;
            }
            needles.push(Needle {
                chars: name.chars().collect(),
                mask: hostname(name),
            });
        };
        for name in &names {
            push(name);
        }
        for name in &names {
            if let Some((label, _)) = name.split_once('.') {
                push(label);
            }
        }
        needles.sort_by_key(|needle| std::cmp::Reverse(needle.chars.len()));
        needles
    }

    /// How many characters of `text` from `at` this name takes up, if it is
    /// there: as itself, a word of its own and in any case, or as UTF-16LE read
    /// a byte to a character, each letter followed by a NUL, which is how SMB,
    /// NTLM and Kerberos carry a name and how a reply read byte for byte holds
    /// it.
    fn at(&self, text: &[char], at: usize) -> Option<usize> {
        let len = self.chars.len();
        let rest = &text[at..];

        let plain = rest.len() >= len
            && rest
                .iter()
                .zip(&self.chars)
                .all(|(a, b)| same_letter(*a, *b))
            && (at == 0 || !text[at - 1].is_alphanumeric())
            && rest.get(len).is_none_or(|c| !c.is_alphanumeric());
        if plain {
            return Some(len);
        }

        let wide = rest.len() >= 2 * len
            && self
                .chars
                .iter()
                .enumerate()
                .all(|(i, c)| same_letter(rest[2 * i], *c) && rest[2 * i + 1] == '\0');
        wide.then_some(2 * len)
    }
}

/// Masks every name `needles` holds wherever it appears in `text`, borrowing
/// when none does.
pub(crate) fn names_in<'a>(text: &'a str, needles: &[Needle]) -> Cow<'a, str> {
    if needles.is_empty() {
        return Cow::Borrowed(text);
    }

    let chars: Vec<char> = text.chars().collect();
    let mut masked = String::with_capacity(text.len());
    let mut changed = false;
    let mut at = 0;
    while at < chars.len() {
        match needles
            .iter()
            .find_map(|needle| needle.at(&chars, at).map(|len| (len, needle)))
        {
            Some((len, needle)) => {
                masked.push_str(&needle.mask);
                at += len;
                changed = true;
            }
            None => {
                masked.push(chars[at]);
                at += 1;
            }
        }
    }

    if changed {
        Cow::Owned(masked)
    } else {
        Cow::Borrowed(text)
    }
}

/// Two letters that are one in any case.
fn same_letter(a: char, b: char) -> bool {
    a == b || a.to_lowercase().eq(b.to_lowercase())
}

/// Two names that are one in any case.
fn same_letters(a: &[char], b: &str) -> bool {
    a.len() == b.chars().count() && a.iter().zip(b.chars()).all(|(x, y)| same_letter(*x, y))
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
    fn an_address_of_every_octet_keeps_the_three_that_name_a_vendor() {
        let mac = MacAddr::new(0xff, 0xff, 0xff, 0x00, 0x11, 0x22);
        assert_eq!(mac_addr(&mac), "ff:ff:ff:XX:XX:XX");
    }

    /// A masked name is nine characters whatever went in, so the mask hides the
    /// length as well as the letters. The short case is the documented
    /// exception and is five.
    #[test]
    fn masking_a_name_hides_how_long_it_was() {
        for name in ["router", "workstation", &"a".repeat(50)] {
            assert_eq!(hostname(name).chars().count(), 9, "{name}");
        }

        assert_eq!(hostname("modem"), "XXXXX");
    }

    /// A name is found as a word of its own and in any case, and a word it is
    /// only part of is left alone: `FS01` names the machine, `FS010` does not.
    #[test]
    fn a_name_is_masked_as_a_word_in_any_case() {
        let needles = Needle::for_names(["fs01.example.com", "EXAMPLE"]);

        assert_eq!(
            names_in("220 FS01.EXAMPLE.COM ready", &needles),
            "220 fsXXXXXom ready"
        );
        assert_eq!(
            names_in("CN=example-FS01-CA", &needles),
            "CN=EXXXXXXLE-XXXXX-CA"
        );
        assert!(matches!(
            names_in("FS010 and examples", &needles),
            Cow::Borrowed(_)
        ));
    }

    /// SMB, NTLM and Kerberos carry a name in UTF-16LE, which a reply read a
    /// byte to a character holds as each letter followed by a NUL.
    #[test]
    fn a_name_in_utf16_is_masked() {
        let needles = Needle::for_names(["EXAMPLE"]);

        assert_eq!(
            names_in("\u{ff}SMBe\0x\0a\0m\0p\0l\0e\0\0\0", &needles),
            "\u{ff}SMBEXXXXXXLE\0\0"
        );
    }

    /// A reply is text when it holds nothing but printable characters and
    /// line breaks, and binary as soon as it holds any other control.
    #[test]
    fn a_reply_holding_a_control_is_binary() {
        assert!(!is_binary("HTTP/1.1 200 OK\r\n\tServer: x\n"));
        assert!(!is_binary("caf\u{e9}"));
        assert!(is_binary("\0\0\0\x55\u{ff}SMB"));
        assert!(is_binary("\u{1b}[31m"));
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

        /// The vendor survives and the card does not, for every address there
        /// is.
        #[test]
        fn a_masked_address_keeps_its_oui_and_loses_the_rest(
            o1 in 0..=255u8, o2 in 0..=255u8, o3 in 0..=255u8,
            o4 in 0..=255u8, o5 in 0..=255u8, o6 in 0..=255u8
        ) {
            let redacted = mac_addr(&MacAddr::new(o1, o2, o3, o4, o5, o6));
            // Built outside the assertion: `prop_assert!` re-expands its
            // expression through `format_args!`, which cannot capture from
            // around it.
            let oui = format!("{o1:02x}:{o2:02x}:{o3:02x}");

            prop_assert!(redacted.starts_with(&oui));
            prop_assert!(redacted.ends_with("XX:XX:XX"));
        }
    }
}
