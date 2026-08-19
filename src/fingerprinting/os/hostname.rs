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
//! ICMP echo — its firewall declines rather than refuses — so no stack rule and
//! no echo rule can reach it. It still announces its name over mDNS, and the
//! name carries the `DESKTOP-` prefix. For that host there is no other route.
//!
//! ## What it is not
//!
//! It is not a version, not a vendor, and never a product. The prefixes are
//! family-level facts at best. And it is weak: a hostname is a label, and
//! whoever set the machine up could have typed anything. [`CONFIDENCE`] is set
//! where a lone hit stays below the floor [`resolve`](super::resolve) reports
//! at, so this can never name a host by itself — it earns its place by agreeing
//! with a stack reading, or with the hardware vendor, and pushing a verdict
//! past what one source could support.
//!
//! ## The table declines more than it answers
//!
//! Only patterns an operating system *generates by default* are listed, because
//! only those are authored by the system rather than by a person. `DESKTOP-`
//! qualifies; `web01` does not, and neither does a hostname that happens to
//! start with `linux` — that was a choice, and treating choices as defaults
//! would make this source confidently wrong about every carefully-named machine
//! on the network.

use super::evidence::OsEvidence;
use super::verdict::OsSource;

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
    // --- Windows (Workstations & Windows Phone) ---
    (generated("desktop-"), "Windows"),
    // Windows laptops, tablets, and 2-in-1 defaults
    (generated("laptop-"), "Windows"),
    // Windows 11 setup defaults on virtualized/certain OEM builds
    (generated("win-"), "Windows"),
    // Legacy Windows Phone defaults
    (model("windows-phone"), "Windows"),
    // --- Apple Ecosystem ---
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
    // --- Android & ChromeOS ---
    (generated("android-"), "Linux"),
    (generated("android_"), "Linux"),
    // Samsung devices
    (generated("sm-"), "Linux"),
    (generated("galaxy-"), "Linux"),
    // Google Chromecast & Nest/Google Home
    (generated("googlecast"), "Linux"),
    (generated("google-home"), "Linux"),
    (generated("nest-hub"), "Linux"),
    (generated("nest-mini"), "Linux"),
    // Amazon Fire & Echo devices
    (generated("amazon-"), "Linux"),
    (generated("firetv"), "Linux"),
    (generated("echo-"), "Linux"),
    // ChromeOS factory hostnames
    (generated("chromebook-"), "Linux"),
    (generated("chromeos-"), "Linux"),
    // --- SBCs, Embedded & IoT Linux ---
    // Raspberry Pi OS default
    (generated("raspberrypi"), "Linux"),
    // BeagleBone default
    (generated("beaglebone"), "Linux"),
    // NVIDIA Jetson default
    (generated("tegra-ubuntu"), "Linux"),
    (generated("jetson"), "Linux"),
    // Steam Deck / SteamOS default
    (generated("steamdeck"), "Linux"),
    // Sonos speakers (typically Linux-based)
    (generated("sonos-"), "Linux"),
    // Roku OS (Linux kernel)
    (generated("roku-"), "Linux"),
    (generated("roku"), "Linux"),
    // LG webOS smart TVs
    (generated("lgwebostv"), "webOS"),
    (generated("webostv"), "webOS"),
    // Tizen smart TVs
    (generated("samsung-tizen"), "Tizen"),
    // --- Network Appliances & Routers (OpenWrt / FreeBSD) ---
    (generated("openwrt"), "Linux"),
    (generated("dd-wrt"), "Linux"),
    (generated("pfsense"), "FreeBSD"),
    (generated("opnsense"), "FreeBSD"),
    (generated("truenas"), "FreeBSD"),
    (generated("freenas"), "FreeBSD"),
    // --- BSD Defaults ---
    (generated("freebsd"), "FreeBSD"),
    (generated("openbsd"), "OpenBSD"),
    (generated("netbsd"), "NetBSD"),
];

/// How a pattern is matched.
#[derive(Debug, Clone, Copy)]
enum Pattern {
    /// The hostname starts here, possibly followed by a separator and more.
    ///
    /// The separator matters: `MacBook-Pro` and `MacBook-Pro-3` are the model
    /// name a Mac announces, and `eriks-macbook` is a person's name that merely
    /// contains one. A bare `contains` cannot tell those apart, and this
    /// source's whole value is declining the second kind.
    /// The hostname starts here and everything after it is a small number or
    /// nothing — the model name plus the enumeration Apple appends.
    ///
    /// Apple's mDNS names are `MacBook-Pro`, `MacBook-Pro-3`, `iPhone-2`: the
    /// model, then digits. Restricting the tail to a short number is what
    /// separates that from `macbook-of-erik`, which a prefix alone cannot.
    /// The suffix is bounded because an owner's name can be numeric too; two
    /// digits is Apple's own longest default.
    Model(&'static str),
    /// The hostname starts here and the pattern is the whole name, as the
    /// generated conventions are.
    Generated(&'static str),
}

const fn model(text: &'static str) -> Pattern {
    Pattern::Model(text)
}

const fn generated(text: &'static str) -> Pattern {
    Pattern::Generated(text)
}

impl Pattern {
    fn matches(self, hostname: &str) -> bool {
        match self {
            Pattern::Model(text) => match hostname.strip_prefix(text) {
                Some("") | Some("-") => true,
                Some(rest) => match rest.strip_prefix('-') {
                    // A short run of digits: Apple appends at most a
                    // two-digit enumeration to the model name.
                    Some(digits) => digits.len() <= 2 && digits.bytes().all(|b| b.is_ascii_digit()),
                    None => false,
                },
                None => false,
            },
            Pattern::Generated(text) => hostname.starts_with(text),
        }
    }
}

/// What a host's name suggests it runs, if anything.
///
/// `None` — the common answer — when there is no hostname, or when the name is
/// not one an operating system generates by default. Declining is the point:
/// a person's hostname says what the person chose, not what the machine runs,
/// and a source that treated choice as evidence would be wrong about every
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
        family: (*family).to_string(),
        vendor: None,
        product: None,
        version: None,
        cpe: None,
        confidence: CONFIDENCE,
        evidence: format!("hostname {hostname}"),
    })
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗██████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████╗   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    fn family_of(hostname: Option<&str>) -> Option<String> {
        evidence_from(hostname).map(|evidence| evidence.family)
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
    /// them apart — the hardware address and the Darwin stack rules cannot,
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

    /// Below the reporting floor on its own, so agreement is what it is for —
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
            ("lgwebostv-1234", "webOS"),
        ];

        for (name, family) in cases {
            assert_eq!(
                family_of(Some(name)),
                Some(family.to_string()),
                "failed on {name}"
            );
        }
    }
}
