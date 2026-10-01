// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the hostname says about the machine
//!
//! Sometimes a family, and nothing more.
//!
//! ## Default names
//!
//! A *default* hostname is a naming convention the operating system applies
//! when nobody overrides it. Windows names a fresh installation `DESKTOP-` plus
//! a generated token; Android prefixes `android-`; an unconfigured Mac answers
//! as `MacBook-Pro` or `iPhone`.
//!
//! For some hosts it is the only signal: a stock Windows desktop on a labelled
//! segment dropped every TCP probe and ICMP echo but announced its `DESKTOP-`
//! name over mDNS.
//!
//! ## Limits
//!
//! Family-level at best, and weak, since anyone can type any name.
//! [`CONFIDENCE`] keeps a lone hit below the floor [`resolve`](super::resolve)
//! reports at, so it only adds weight to other sources.
//!
//! ## Who said it
//!
//! A name from a reverse lookup or a DHCP request is its own witness,
//! [`OsSource::Hostname`].
//!
//! A name in `.local` comes from the host's own Bonjour responder (RFC 6762 §3),
//! the same responder that serves the device-info record. It is filed as
//! [`OsSource::MdnsResponder`] so one daemon counts once.
//!
//! The zone decides, not the route, since names from an imported report or a
//! resumed journal have no route. A unicast resolver answering in `.local`
//! (against RFC 6762 Appendix G, but home routers do) is then counted once
//! where it could count twice, which errs on the safe side.
//!
//! ## Only generated shapes
//!
//! Only patterns an operating system generates are listed; `web01` or a name
//! starting with `linux` is a person's choice.
//!
//! A bare prefix is not enough: `starts_with("desktop-")` takes
//! `desktop-alice`, and ten of twelve hand-typed names matched some prefix in a
//! bare-prefix table. A wrong vote is costly, since [`resolve`](super::resolve)
//! reduces the leader by dissent: a Linux stack reading fell from 65 to 42 on a
//! `desktop-` hostname. So each entry states the shape of its generated tail;
//! see [`Token`], and `WITHDRAWN` for conventions left out.

use crate::model::host::OsEvidence;
use crate::model::host::OsSource;

/// What a hostname match contributes on its own.
///
/// Below the floor [`resolve`](super::resolve) reports at, so this source never
/// names a host by itself.
pub const CONFIDENCE: f32 = 0.35;

/// The zone multicast DNS answers for, and the mark of a name a host's own
/// responder announced. See the module's "Who said it".
const MDNS_ZONE: &str = ".local";

/// Naming conventions an operating system applies when nobody overrides them,
/// and the family each implies.
///
/// Matched case-insensitively against the whole hostname. Every entry is a
/// pattern the system itself produces.
const DEFAULT_NAMES: &[(Pattern, &str)] = &[
    // --- Windows ---
    // Setup generates the model name plus a seven-character token: the
    // `DESKTOP-` a fresh installation takes, and the `LAPTOP-` some OEM images
    // use instead.
    (
        generated("desktop-", Token::Random { min: 7, max: 7 }),
        "Windows",
    ),
    (
        generated("laptop-", Token::Random { min: 7, max: 7 }),
        "Windows",
    ),
    // Windows Server: token width unconfirmed, so a range.
    (
        generated("win-", Token::Random { min: 8, max: 15 }),
        "Windows",
    ),
    (model("windows-phone"), "Windows"),
    // --- Apple ---
    (model("macbook-pro"), "macOS"),
    (model("macbook-air"), "macOS"),
    (model("macbook"), "macOS"),
    (model("imac-pro"), "macOS"),
    (model("imac"), "macOS"),
    (model("mac-studio"), "macOS"),
    (model("mac-mini"), "macOS"),
    (model("mac-pro"), "macOS"),
    (model("iphone"), "iOS"),
    (model("ipad"), "iPadOS"),
    (model("appletv"), "tvOS"),
    (model("apple-tv"), "tvOS"),
    (model("homepod"), "audioOS"),
    (model("apple-watch"), "watchOS"),
    (model("applewatch"), "watchOS"),
    // --- Android and ChromeOS ---
    // Android appends its install identifier, sixteen hexadecimal digits.
    (generated("android-", Token::Hex { len: 16 }), "Linux"),
    (generated("android_", Token::Hex { len: 16 }), "Linux"),
    (model("googlecast"), "Linux"),
    (model("google-home"), "Linux"),
    (model("nest-hub"), "Linux"),
    (model("nest-mini"), "Linux"),
    (model("firetv"), "Linux"),
    // --- Single-board computers, embedded and IoT Linux ---
    (model("raspberrypi"), "Linux"),
    (model("beaglebone"), "Linux"),
    (model("tegra-ubuntu"), "Linux"),
    (model("jetson"), "Linux"),
    (model("steamdeck"), "Linux"),
    // Sonos publishes the model name and its hardware address.
    (generated("sonos-", Token::Hex { len: 12 }), "Linux"),
    // --- Televisions ---
    (model("lgwebostv"), "webOS"),
    (model("webostv"), "webOS"),
    (model("samsung-tizen"), "Tizen"),
    // --- Network appliances and routers ---
    (model("openwrt"), "Linux"),
    (model("dd-wrt"), "Linux"),
    (model("pfsense"), "FreeBSD"),
    (model("opnsense"), "FreeBSD"),
    (model("truenas"), "FreeBSD"),
    (model("freenas"), "FreeBSD"),
    // --- BSD defaults ---
    (model("freebsd"), "FreeBSD"),
    (model("openbsd"), "OpenBSD"),
    (model("netbsd"), "NetBSD"),
];

/// Conventions this table leaves out, so that adding one is a decision rather
/// than a rediscovery.
///
/// Each bare prefix fires on hand-typed names (`sm-prod-db01`,
/// `galaxy-cluster-01`, `amazon-connector`, `echo-service`, `rokuro-pc`,
/// `chromebook-loaner`), and nobody has stated its generated shape. One that
/// can be written as a [`Token`] may be added.
#[cfg(test)]
const WITHDRAWN: &[&str] = &[
    "sm-",
    "galaxy-",
    "amazon-",
    "echo-",
    "roku",
    "roku-",
    "chromebook-",
    "chromeos-",
];

/// The token a naming convention appends to its prefix.
///
/// A system draws the tail from an alphabet at a fixed width; a person types a
/// word.
#[derive(Debug, Clone, Copy)]
enum Token {
    /// Between `min` and `max` alphanumerics, at least one of them a digit.
    ///
    /// Requiring a digit declines the few genuine all-letter `DESKTOP-` names,
    /// but `desktop-` plus seven letters is as often `desktop-manager`.
    ///
    /// A range where the width is unconfirmed, as after `WIN-`.
    Random { min: usize, max: usize },
    /// Exactly `len` hexadecimal digits, as Android appends its install
    /// identifier and Sonos its hardware address.
    Hex { len: usize },
}

impl Token {
    fn matches(self, tail: &str) -> bool {
        match self {
            Token::Random { min, max } => {
                (min..=max).contains(&tail.len())
                    && tail.bytes().all(|b| b.is_ascii_alphanumeric())
                    && tail.bytes().any(|b| b.is_ascii_digit())
            }
            Token::Hex { len } => tail.len() == len && tail.bytes().all(|b| b.is_ascii_hexdigit()),
        }
    }
}

/// How a pattern is matched.
#[derive(Debug, Clone, Copy)]
enum Pattern {
    /// The hostname is the model name, optionally followed by a small
    /// enumeration.
    ///
    /// Apple's mDNS names are `MacBook-Pro`, `MacBook-Pro-3`, `iPhone-2`. The
    /// tail is at most two digits, which excludes `macbook-of-alice`. The same
    /// shape fits `openwrt`, `pfsense`, `freebsd`.
    Model(&'static str),
    /// The hostname is the prefix and then a token the system generated.
    ///
    /// The token's shape is checked; see [`Token`].
    Generated(&'static str, Token),
}

/// A [`Pattern::Model`].
const fn model(text: &'static str) -> Pattern {
    Pattern::Model(text)
}

/// [`model`] for the generated-name variant, which carries what follows the
/// prefix as well as the prefix.
const fn generated(text: &'static str, token: Token) -> Pattern {
    Pattern::Generated(text, token)
}

impl Pattern {
    fn matches(self, hostname: &str) -> bool {
        match self {
            Pattern::Model(text) => match hostname.strip_prefix(text) {
                Some("") | Some("-") => true,
                Some(rest) => match rest.strip_prefix('-') {
                    // A short run of digits: at most a two-digit enumeration.
                    Some(digits) => {
                        !digits.is_empty()
                            && digits.len() <= 2
                            && digits.bytes().all(|b| b.is_ascii_digit())
                    }
                    None => false,
                },
                None => false,
            },
            Pattern::Generated(text, token) => hostname
                .strip_prefix(text)
                .is_some_and(|tail| token.matches(tail)),
        }
    }
}

/// What a host's name suggests it runs, if anything.
///
/// `None`, the common answer, when there is no hostname or it is not a
/// generated default.
///
/// A `.local` name is filed as [`OsSource::MdnsResponder`]; any other as
/// [`OsSource::Hostname`]. See the module documentation.
pub fn evidence_from(hostname: Option<&str>) -> Option<OsEvidence> {
    let hostname = hostname?;
    let lowered = hostname.to_ascii_lowercase();
    // Strip the FQDN dot; the zone is not part of the generated name.
    let name = lowered.strip_suffix('.').unwrap_or(&lowered);
    let (name, source) = match name.strip_suffix(MDNS_ZONE) {
        Some(label) => (label, OsSource::MdnsResponder),
        None => (name, OsSource::Hostname),
    };

    let (_, family) = DEFAULT_NAMES
        .iter()
        .find(|(pattern, _)| pattern.matches(name))?;

    Some(OsEvidence {
        source,
        family: Some((*family).to_string()),
        device: None,
        vendor: None,
        product: None,
        version: None,
        kernel: None,
        arch: None,
        cpe: None,
        confidence: CONFIDENCE,
        evidence: format!("hostname {hostname}"),
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

    fn family_of(hostname: Option<&str>) -> Option<String> {
        evidence_from(hostname).and_then(|evidence| evidence.family)
    }

    /// A stock Windows desktop that dropped every probe but announced its
    /// default name.
    #[test]
    fn a_windows_default_name_says_windows() {
        assert_eq!(
            family_of(Some("DESKTOP-FKV0V2O")),
            Some("Windows".to_string())
        );
        assert_eq!(
            family_of(Some("desktop-0000000")),
            Some("Windows".to_string())
        );
    }

    /// The model names the platform, which the hardware address and Darwin stack
    /// rules cannot (macOS, iOS, iPadOS and tvOS share a kernel). `.local` is
    /// tolerated.
    #[test]
    fn an_apple_device_name_names_its_platform() {
        let cases = [
            ("MacBook-Pro", "macOS"),
            ("MacBook-Pro.local", "macOS"),
            ("MacBook-Air-3", "macOS"),
            ("Mac-mini", "macOS"),
            ("Mac-Pro", "macOS"),
            ("IMac", "macOS"),
            ("iPhone-2", "iOS"),
            ("IPad", "iPadOS"),
            ("AppleTV-6", "tvOS"),
        ];
        for (name, family) in cases {
            assert_eq!(family_of(Some(name)), Some(family.to_string()), "{name}");
        }
    }

    /// A chosen name (`web01`, `linux-server`) is not evidence.
    #[test]
    fn a_persons_own_name_says_nothing() {
        for name in [
            "web01",
            "linux-server",
            "mail",
            "NAS",
            "alices-macbook",
            "macbook-of-alice",
            "macbook-12345678",
            "the-ipad",
        ] {
            assert_eq!(family_of(Some(name)), None, "{name}");
        }
    }

    /// Below the reporting floor on its own.
    #[test]
    fn a_hostname_alone_never_reaches_the_reporting_floor() {
        let evidence = evidence_from(Some("DESKTOP-FKV0V2O")).expect("a default name matches");
        assert!(
            (evidence.confidence * 100.0)
                < f32::from(super::super::verdict::MIN_REPORTABLE_ACCURACY),
            "a lone hostname must stay below the floor that reports anything"
        );
    }

    /// A name in `.local` is its responder's to count, in any spelling DNS
    /// allows for it, and a name without the zone is a witness of its own.
    ///
    /// Pinned in both directions.
    #[test]
    fn a_name_is_filed_under_whoever_stated_it() {
        let source = |name: &str| evidence_from(Some(name)).map(|evidence| evidence.source);

        for announced in [
            "MacBook-Pro.local",
            "MacBook-Pro.LOCAL",
            "MacBook-Pro.local.",
            "DESKTOP-A1B2C3D.local",
        ] {
            assert_eq!(
                source(announced),
                Some(OsSource::MdnsResponder),
                "`{announced}` is the host's responder speaking"
            );
        }
        for resolved in ["MacBook-Pro", "MacBook-Pro.", "DESKTOP-A1B2C3D"] {
            assert_eq!(
                source(resolved),
                Some(OsSource::Hostname),
                "`{resolved}` came from somewhere other than the host"
            );
        }
    }

    /// Constructed fixtures. The webOS one has a two-digit tail, the most
    /// [`Pattern::Model`] accepts.
    #[test]
    fn additional_oem_defaults_resolve_correctly() {
        let cases = [
            ("LAPTOP-G384HJ2", "Windows"),
            ("WIN-89KLP0M9", "Windows"),
            ("MacBook-Air", "macOS"),
            ("Mac-Studio-1", "macOS"),
            ("HomePod-2", "audioOS"),
            ("Apple-Watch-3", "watchOS"),
            ("steamdeck", "Linux"),
            ("openwrt.local", "Linux"),
            ("pfsense", "FreeBSD"),
            ("opnsense.local", "FreeBSD"),
            ("lgwebostv", "webOS"),
            ("lgwebostv-2", "webOS"),
        ];

        for (name, family) in cases {
            assert_eq!(
                family_of(Some(name)),
                Some(family.to_string()),
                "failed on {name}"
            );
        }
    }

    /// Hand-typed names that a bare prefix would match.
    #[test]
    fn a_name_a_person_typed_does_not_wear_a_generated_prefix() {
        for name in [
            "desktop-alice",
            "desktop-manager",
            "laptop-of-alice",
            "win-file-server",
            "sm-prod-db01",
            "echo-service",
            "amazon-connector",
            "rokuro-pc",
            "jetsonville-nas",
            "galaxy-cluster-01",
            "android-build-agent",
            "sonos-living-room",
        ] {
            assert_eq!(family_of(Some(name)), None, "`{name}` is somebody's name");
        }
    }

    /// The conventions themselves still match.
    #[test]
    fn a_generated_tail_is_still_recognised() {
        let cases = [
            ("DESKTOP-FKV0V2O", "Windows"),
            ("LAPTOP-G384HJ2", "Windows"),
            ("WIN-K3JD8FH2LQ0", "Windows"),
            ("android-a1b2c3d4e5f60718", "Linux"),
            ("Sonos-949F3EC5D2E0", "Linux"),
        ];
        for (name, family) in cases {
            assert_eq!(family_of(Some(name)), Some(family.to_string()), "{name}");
        }
    }

    /// A withdrawn prefix names nothing.
    #[test]
    fn a_withdrawn_convention_matches_nothing() {
        for prefix in WITHDRAWN {
            for tail in ["", "-01", "server", "a1b2c3d", "0123456789abcdef"] {
                let name = format!("{prefix}{tail}");
                assert_eq!(
                    family_of(Some(&name)),
                    None,
                    "`{name}` is back in the table"
                );
            }
        }
    }

    /// What a wrong vote costs a correct reading.
    #[test]
    fn a_mistaken_hostname_would_have_cost_a_correct_reading() {
        use crate::model::host::OsSource;

        let stack = crate::model::host::OsEvidence {
            source: OsSource::TcpStack,
            family: Some("Linux".to_string()),
            device: None,
            vendor: None,
            product: None,
            version: None,
            kernel: None,
            arch: None,
            cpe: None,
            confidence: 0.65,
            evidence: "a stack reading".to_string(),
        };
        let alone = super::super::resolve(vec![stack.clone()]).expect("names the host");
        assert_eq!(alone.accuracy, 65);

        // What a bare `DESKTOP-` prefix would make of `desktop-alice`.
        let mistaken = crate::model::host::OsEvidence {
            source: OsSource::Hostname,
            family: Some("Windows".to_string()),
            confidence: CONFIDENCE,
            evidence: "hostname suggests Windows".to_string(),
            ..stack.clone()
        };
        let contested = super::super::resolve(vec![stack, mistaken]).expect("still resolves");
        assert!(
            contested.accuracy < alone.accuracy - 20,
            "a dissenting vote costs the leader real accuracy: {} against {}",
            contested.accuracy,
            alone.accuracy
        );

        // The table does not produce it.
        assert_eq!(family_of(Some("desktop-alice")), None);
    }
}
