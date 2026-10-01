// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The masking [`Redaction::Standard`](super::Redaction::Standard) applies
//!
//! One function each for a hostname and a hardware address, plus the
//! crate-private mechanics [`HostRedaction`](super::HostRedaction) applies to
//! free text: finding a host's names, and telling a text reply from a binary
//! one. [`Redaction`](super::Redaction) states the policy and its limits.
//!
//! This is not anonymisation. A masked hostname stays distinguishable from the
//! next, so a reader can follow a host through a report; that is all that is
//! promised.

use std::borrow::Cow;

use crate::model::mac::MacAddr;

/// Masks a hostname, keeping its first and last two characters so two masked
/// names still read as two names.
///
/// The middle becomes a fixed run of five `X`, hiding the length: `router` and
/// a fifty-character name both mask to nine characters.
///
/// A name with fewer than six characters is masked whole as `XXXXX`, since its
/// ends would be most of it.
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
/// The first three octets name the vendor and the last three the individual
/// card.
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
/// A binary reply carries names in forms a text search cannot be sure to find:
/// a NetBIOS name in half-ASCII, a DNS name as length-prefixed labels, a realm
/// inside DER, a name never recorded as one. A masked copy would be neither
/// safe nor useful; the finding keeps its title and claim.
pub(crate) const WITHHELD_EXCERPT: &str = "(binary reply withheld under redaction)";

/// Whether `text` holds a control character other than a tab or a line break,
/// as a binary reply read byte for byte does.
pub(crate) fn is_binary(text: &str) -> bool {
    text.chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
}

/// Generic second-level labels under a country's top-level domain, as in
/// `example.com.au` or `example.gov.uk`. Part of the suffix, so never masked on
/// their own. See [`Needle::for_names`].
const GENERIC_LABELS: &[&str] = &[
    "com", "net", "org", "edu", "gov", "mil", "int", "ltd", "plc",
];

/// One name to find in free text, with the mask it is replaced by.
#[derive(Debug, Clone)]
pub(crate) struct Needle {
    chars: Vec<char>,
    mask: String,
}

impl Needle {
    /// The needles for the names a host is known by: each name whole, the
    /// first label of a dotted one (the machine's name as a banner or NetBIOS
    /// reply gives it), and every label between that and the last. A label
    /// that is also a name in its own right is masked as that name is, so a
    /// NetBIOS domain reads the same in the text as in its field. Sorted
    /// longest first, so a whole name is masked before any of its labels.
    ///
    /// The middle labels are needed because text spells a domain in other
    /// ways: `DC=corp,DC=example` in a directory reply, `%2E` between labels in
    /// a URL, a realm upper-cased on its own. Skipped are the top-level label,
    /// labels under three characters (too often ordinary words: `co`, `ad`,
    /// `us`), and [`GENERIC_LABELS`].
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
        for name in &names {
            let labels: Vec<&str> = name.trim().split('.').collect();
            for label in labels.iter().take(labels.len().saturating_sub(1)).skip(1) {
                if label.chars().count() >= 3
                    && !GENERIC_LABELS
                        .iter()
                        .any(|generic| generic.eq_ignore_ascii_case(label))
                {
                    push(label);
                }
            }
        }
        needles.sort_by_key(|needle| std::cmp::Reverse(needle.chars.len()));
        needles
    }

    /// How many characters of `text` from `at` this name takes up, if it is
    /// there: as a whole word in any case, or as UTF-16LE read a byte to a
    /// character (each letter followed by a NUL), as SMB, NTLM and Kerberos
    /// carry a name.
    fn at(&self, text: &[char], at: usize) -> Option<usize> {
        let len = self.chars.len();
        let rest = &text[at..];

        let plain = rest.len() >= len
            && rest
                .iter()
                .zip(&self.chars)
                .all(|(a, b)| same_letter(*a, *b))
            && (at == 0 || !text[at - 1].is_alphanumeric() || after_escape(text, at))
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

/// Whether the three characters before `at` are a URL percent escape such as
/// `%2E`. It ends in an alphanumeric but acts as a separator, so a name after
/// it starts a word.
fn after_escape(text: &[char], at: usize) -> bool {
    at >= 3 && text[at - 3] == '%' && text[at - 2..at].iter().all(char::is_ascii_hexdigit)
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

    /// A masked name is nine characters whatever went in, except the short
    /// case, which is five.
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

    /// Each label of a domain between its first and its last is masked on its
    /// own. The top-level label, a label under three characters and a generic
    /// second-level one stay.
    #[test]
    fn each_label_between_the_first_and_the_last_is_masked() {
        let needles = Needle::for_names(["fs01.ad.contoso.com.au"]);

        assert_eq!(
            names_in("DC=ad,DC=contoso,DC=com,DC=au", &needles),
            "DC=ad,DC=coXXXXXso,DC=com,DC=au"
        );
        assert_eq!(
            names_in("GET /%2Econtoso%2Ecom%2Eau", &needles),
            "GET /%2EcoXXXXXso%2Ecom%2Eau"
        );
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

    /// A reply is binary as soon as it holds a control other than whitespace.
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
        /// A masked name keeps its two ends and nothing between them.
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

        /// A name short enough that its ends would be most of it keeps neither.
        #[test]
        fn a_short_hostname_is_masked_whole(name in "[a-zA-Z0-9.-]{0,5}") {
            prop_assert_eq!(hostname(&name), "XXXXX");
        }

        /// The OUI survives and the rest does not, for every address.
        #[test]
        fn a_masked_address_keeps_its_oui_and_loses_the_rest(
            o1 in 0..=255u8, o2 in 0..=255u8, o3 in 0..=255u8,
            o4 in 0..=255u8, o5 in 0..=255u8, o6 in 0..=255u8
        ) {
            let redacted = mac_addr(&MacAddr::new(o1, o2, o3, o4, o5, o6));
            // Built outside: `prop_assert!` re-expands its expression through
            // `format_args!`, which cannot capture from around it.
            let oui = format!("{o1:02x}:{o2:02x}:{o3:02x}");

            prop_assert!(redacted.starts_with(&oui));
            prop_assert!(redacted.ends_with("XX:XX:XX"));
        }
    }
}
