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
//! ## A default name is a decision by the operating system, not by its owner
//!
//! Most hostnames on a network are things somebody typed, and say nothing about
//! the machine they name. A *default* hostname is different: it is a naming
//! convention the operating system chose, applied when nobody overrode it, and
//! it is a fact about the system in the same way a TCP option order is. Windows
//! names every fresh installation `DESKTOP-` plus eight characters; Android
//! prefixes `android-`; a Mac answers as whatever its owner called it, but an
//! unconfigured one says `MacBook-Pro` or `iPhone`.
//!
//! This is the **only** signal a large class of host ever emits. Measured, on a
//! labelled segment: a stock Windows desktop drops every TCP probe and every
//! ICMP echo, its firewall declines rather than refuses, so no stack rule and
//! no echo rule can reach it. It still announces its name over mDNS, and the
//! name carries the `DESKTOP-` prefix. For that host there is no other route.
//!
//! ## What it is not
//!
//! It is not a version, not a vendor, and never a product. The prefixes are
//! family-level facts at best. And it is weak: a hostname is a label, and
//! whoever set the machine up could have typed anything. [`CONFIDENCE`] is set
//! where a lone hit stays below the floor [`resolve`](super::resolve) reports
//! at, so this can never name a host by itself, it earns its place by agreeing
//! with a stack reading, or with the hardware vendor, and pushing a verdict
//! past what one source could support.
//!
//! ## The table declines more than it answers
//!
//! Only patterns an operating system *generates by default* are listed, because
//! only those are authored by the system rather than by a person. `DESKTOP-`
//! qualifies; `web01` does not, and neither does a hostname that happens to
//! start with `linux`, that was a choice, and treating choices as defaults
//! would make this source confidently wrong about every carefully-named machine
//! on the network.
//!
//! A prefix is not a convention, and for a while this table treated it as one.
//! Every entry was matched with `starts_with`, so `DESKTOP-` took
//! `desktop-erik` and `sm-` took `sm-prod-db01`: ten of twelve ordinary
//! hand-typed names matched something. The cost was not the wrong family on its
//! own, since a lone hit stays under the reporting floor by design. It was what
//! a wrong vote does to a reading that was right, because
//! [`resolve`](super::resolve) reduces a leader by whatever dissents from it, a
//! Linux stack reading fell from 65 to 42 on a `desktop-` hostname, and to
//! nothing at all with a second mistaken source beside it.
//!
//! So an entry now states the shape of the tail its convention generates, and
//! an entry whose shape nobody could state came out of the table. See
//! [`Token`], and `WITHDRAWN` for what came out.

use crate::model::host::OsEvidence;
use crate::model::host::OsSource;

/// What a hostname match contributes on its own.
///
/// Deliberately below the floor [`resolve`](super::resolve) reports at, so this
/// source can never name a host by itself. A hostname is a label somebody may
/// have typed, and even a default can survive onto a machine running something
/// else. It earns its place by agreeing with the wire.
pub const CONFIDENCE: f32 = 0.35;

/// Naming conventions an operating system applies when nobody overrides them,
/// and the family each implies.
///
/// Matched case-insensitively against the whole hostname, on a prefix for the
/// generated ones. Every entry is a pattern the system itself produces; the
/// moment a pattern can also come from a person typing a name, it stops being
/// evidence and starts being a coincidence.
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
    // Windows Server, whose token is longer and whose width this engine has not
    // confirmed, so it is bounded rather than pinned.
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

/// Conventions this table used to carry and no longer does, so that re-adding
/// one is a decision rather than a rediscovery.
///
/// Each was a bare prefix matched with `starts_with`, and each fired on names a
/// person had typed: `sm-prod-db01`, `galaxy-cluster-01`, `amazon-connector`,
/// `echo-service`, `rokuro-pc`, `chromebook-loaner`. They are out because
/// nobody could state the shape the system actually generates, which is the one
/// thing that separates a default from a coincidence. A convention somebody can
/// write down as a [`Token`] is welcome back.
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
/// This is what makes a generated name evidence. A system that names a
/// machine draws the tail from an alphabet at a fixed width; a person types a
/// word. Without a shape to check, `DESKTOP-` matched `desktop-erik` and the
/// table said Windows about somebody's Linux workstation.
#[derive(Debug, Clone, Copy)]
enum Token {
    /// Between `min` and `max` alphanumerics, at least one of them a digit.
    ///
    /// The digit is the discriminator and it is not free. Windows draws its
    /// characters from letters and digits alike, so a small share of genuine
    /// `DESKTOP-` names are all letters and are declined here. That is the trade
    /// this module makes everywhere: declining costs a name the row would have
    /// liked, and guessing costs a name that is wrong. `desktop-` followed by
    /// seven letters is `desktop-manager` at least as often as it is a fresh
    /// installation.
    ///
    /// A width is a range rather than a number wherever the convention is not
    /// pinned. Seven characters after `DESKTOP-` is well established; the length
    /// Windows Server uses after `WIN-` is not, and writing down a number nobody
    /// confirmed would make the source fail by matching nothing while looking
    /// perfectly correct.
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
    /// Apple's mDNS names are `MacBook-Pro`, `MacBook-Pro-3`, `iPhone-2`: the
    /// model, then digits. Restricting the tail to a short number is what
    /// separates that from `macbook-of-erik`, which a prefix alone cannot. The
    /// suffix is bounded because an owner's name can be numeric too; two digits
    /// is Apple's own longest default, and the same shape fits the distributions
    /// that set a bare default of their own: `openwrt`, `pfsense`, `freebsd`.
    Model(&'static str),
    /// The hostname is the prefix and then a token the system generated.
    ///
    /// The token's shape is checked; see [`Token`] for why that is the whole
    /// point of the variant.
    Generated(&'static str, Token),
}

const fn model(text: &'static str) -> Pattern {
    Pattern::Model(text)
}

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
/// `None`, the common answer, when there is no hostname, or when the name is
/// not one an operating system generates by default. Declining is the point: a
/// person's hostname says what the person chose, not what the machine runs, and
/// a source that treated choice as evidence would be wrong about every
/// deliberately-named host on the network.
pub fn evidence_from(hostname: Option<&str>) -> Option<OsEvidence> {
    let hostname = hostname?;
    // mDNS answers arrive with `.local` appended, and a bare trailing dot is
    // FQDN form; neither is part of the name the operating system generated.
    let trimmed = hostname.strip_suffix(".local").unwrap_or(hostname);
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    let lowered = trimmed.to_ascii_lowercase();

    let (_, family) = DEFAULT_NAMES
        .iter()
        .find(|(pattern, _)| pattern.matches(&lowered))?;

    Some(OsEvidence {
        source: OsSource::Hostname,
        family: Some((*family).to_string()),
        device: None,
        vendor: None,
        product: None,
        version: None,
        kernel: None,
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

    /// The case this whole source exists for: the stock Windows desktop that
    /// drops every probe, measured on the labelled segment, announcing the one
    /// default name its operating system gave it.
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

    /// The model names the platform, and this is the one source that can tell
    /// them apart, the hardware address and the Darwin stack rules cannot,
    /// since macOS, iOS, iPadOS and tvOS share a kernel. The `.local` suffix
    /// mDNS appends is tolerated, not matched.
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

    /// The discipline of this source: a name a person chose is not evidence,
    /// however much it looks like it should be. Treating `web01` or
    /// `linux-server` as a signal would make this wrong about every
    /// deliberately-named machine on the network.
    #[test]
    fn a_persons_own_name_says_nothing() {
        for name in [
            "web01",
            "linux-server",
            "mail",
            "NAS",
            "eriks-macbook",
            "macbook-of-erik",
            "macbook-12345678",
            "the-ipad",
        ] {
            assert_eq!(family_of(Some(name)), None, "{name}");
        }
    }

    /// Below the reporting floor on its own, so agreement is what it is for,
    /// the same reasoning as the hardware vendor, and pinned the same way.
    #[test]
    fn a_hostname_alone_never_reaches_the_reporting_floor() {
        let evidence = evidence_from(Some("DESKTOP-FKV0V2O")).expect("a default name matches");
        assert!(
            (evidence.confidence * 100.0)
                < f32::from(super::super::verdict::MIN_REPORTABLE_ACCURACY),
            "a lone hostname must stay below the floor that reports anything"
        );
    }

    /// Constructed fixtures rather than observations, unlike the `DESKTOP-` name
    /// above. `lgwebostv-1234` was among them and is now `lgwebostv-2`: a
    /// four-digit tail is past the enumeration [`Pattern::Model`] accepts, and
    /// loosening the bound to keep an unverified fixture would have weakened the
    /// Apple case the bound was written for.
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

    /// The regression the token shapes exist for.
    ///
    /// Every one of these matched before the tails were checked, and every one
    /// is a name somebody typed. Ten of the twelve names this was measured
    /// against fired on a bare-prefix table.
    #[test]
    fn a_name_a_person_typed_does_not_wear_a_generated_prefix() {
        for name in [
            "desktop-erik",
            "desktop-manager",
            "laptop-of-erik",
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

    /// And the conventions themselves still match, which is the other half.
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

    /// A withdrawn prefix names nothing, whatever follows it. The list is here
    /// so that re-adding one is a decision somebody made rather than a bare
    /// `starts_with` creeping back in.
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

    /// A wrong vote is not free, which is why the shapes are checked at all.
    /// Pinned with the arithmetic rather than described, because the number is
    /// the argument.
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
            cpe: None,
            confidence: 0.65,
            evidence: "a stack reading".to_string(),
        };
        let alone = super::super::resolve(vec![stack.clone()]).expect("names the host");
        assert_eq!(alone.accuracy, 65);

        // What `desktop-erik` used to contribute, stated directly so the cost is
        // visible without the table having to produce it.
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

        // And the table no longer produces it.
        assert_eq!(family_of(Some("desktop-erik")), None);
    }
}
