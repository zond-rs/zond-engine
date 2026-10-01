// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a service said about the machine underneath it
//!
//! A stack's shape says which family a host belongs to. A banner often says
//! which build: `SSH-2.0-OpenSSH_9.6p1 Debian` names a distribution, and
//! `Server: Microsoft-IIS/10.0` names a family.
//!
//! ## Limits
//!
//! A banner describes the *software*, which is not always the machine: a
//! container reports its base image, a reverse proxy reports itself, and an
//! appliance reports the vendor's firmware. So this source ranks below a stack
//! reading, and the two agreeing is worth more than either.
//!
//! ## Where it is read
//!
//! The imported SSH rules match the version string as it arrives. The imported
//! HTTP rules match a `Server` header value anchored at both ends
//! (`^Microsoft-IIS/4.0$`), so
//! [`HttpHeadersAnalyzer`](crate::fingerprint::HttpHeadersAnalyzer) extracts the
//! value and runs it through the signature set for operating-system metadata.
//!
//! ## Cost
//!
//! 2442 of the 4732 shipped rules carry `os.*` metadata, matched against text
//! the service pipeline already collects. No probe is added;
//! [`Signature`](super::super::matcher::Signature) keeps the metadata.
//!
//! ## Templates
//!
//! The imported rules do not hold literal values so much as instructions for
//! building them from what the pattern captured:
//!
//! ```text
//! os.product = "{capture:1}"
//! os.cpe23   = "cpe:/o:microsoft:windows_2000:{os.version}"
//! ```
//!
//! `{capture:N}` takes the Nth capture group. `{os.field}` takes a sibling field
//! of the same rule, so captures are resolved first; 205 rules build a CPE from
//! a captured version.
//!
//! A template naming something absent resolves to **nothing**, and the field is
//! dropped: a consumer would try to match `cpe:/o:microsoft:windows_2000:`.

use std::collections::HashMap;

use crate::model::host::OsEvidence;
use crate::model::host::OsSource;

/// What a matched service rule said about the operating system underneath it.
///
/// The `os.*` keys that name or qualify the machine. Edition and build number
/// are left out, since they distinguish ways of selling one system.
///
/// Boxed on signatures, since 2290 of 4732 rules have none.
///
/// Not [`Eq`]: [`certainty`](Self::certainty) is a float.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OsMetadata {
    /// The vendor, such as `"Microsoft"`.
    pub vendor: Option<String>,
    /// The family, such as `"Windows"`.
    pub family: Option<String>,
    /// The product, such as `"Windows Server 2003"`.
    pub product: Option<String>,
    /// The version or service pack.
    pub version: Option<String>,
    /// The kernel release, where a rule reads one.
    ///
    /// Separate from [`version`](Self::version): Debian 12 runs kernel 6.1, and
    /// filing the kernel as a version would make an SSH banner saying `12` and
    /// an SNMP agent saying `6.1.0` contradict each other.
    ///
    /// Read from `os.kernel`, this engine's own key; the imported corpus puts a
    /// kernel in `os.version`.
    pub kernel: Option<String>,
    /// A Common Platform Enumeration identifier.
    pub cpe23: Option<String>,
    /// The instruction set the system runs on: `x86_64`, `mips`, `armv7l`.
    ///
    /// `sysDescr` on a Unix host is `uname -a`, which ends with the machine type.
    /// About 170 shipped rules carry one.
    pub arch: Option<String>,
    /// What kind of box the rule says this is: `Printer`, `Switch`, `Router`.
    ///
    /// Read from `os.device`, falling back to `hw.device`, which is the same
    /// class written under the hardware namespace by rules that describe a
    /// device rather than the software on it.
    ///
    /// A rule stating a class describes hardware: its `product` is a model and its
    /// `vendor` a manufacturer; see [`evidence_from`].
    pub device: Option<String>,
    /// How sure the corpus itself says this rule is, `0.0..=1.0`.
    ///
    /// 353 imported rules carry it.
    pub certainty: Option<f32>,
}

impl OsMetadata {
    /// Reads the `os.*` keys out of a rule's metadata map, or `None` if it names
    /// no operating system at all.
    ///
    /// Called once per rule when the database is built, never per match.
    pub fn from_map(metadata: &HashMap<String, String>) -> Option<Self> {
        let get = |key: &str| metadata.get(key).filter(|v| !v.is_empty()).cloned();

        let found = Self {
            vendor: get("os.vendor"),
            family: get("os.family"),
            product: get("os.product"),
            version: get("os.version"),
            kernel: get("os.kernel"),
            cpe23: get("os.cpe23"),
            arch: get("os.arch"),
            device: get("os.device").or_else(|| get("hw.device")),
            certainty: get("os.certainty").and_then(|v| v.parse().ok()),
        };

        // Kept if it names only an instruction set (seven rules do), which is
        // collected rather than voted on; `evidence_from` declines it as a
        // reading.
        (found.family.is_some() || found.product.is_some() || found.arch.is_some()).then_some(found)
    }

    /// Resolves this rule's templates against what its pattern captured.
    ///
    /// `captures` is indexed as the pattern numbers its groups, index 0 being the
    /// whole match. A field whose template names a group that did not participate
    /// resolves to `None`.
    pub fn resolve(&self, captures: &[String]) -> Self {
        // Capture templates first: the sibling form below reads the results.
        let vendor = fill(self.vendor.as_deref(), captures);
        let family = fill(self.family.as_deref(), captures);
        let product = fill(self.product.as_deref(), captures);
        let version = fill(self.version.as_deref(), captures);
        let kernel = fill(self.kernel.as_deref(), captures);
        let device = fill(self.device.as_deref(), captures);
        let arch = fill(self.arch.as_deref(), captures);

        let siblings = [
            ("os.vendor", vendor.as_deref()),
            ("os.family", family.as_deref()),
            ("os.product", product.as_deref()),
            ("os.version", version.as_deref()),
            ("os.kernel", kernel.as_deref()),
        ];
        let cpe23 = fill(self.cpe23.as_deref(), captures)
            .and_then(|template| fill_siblings(&template, &siblings));

        Self {
            vendor,
            family,
            product,
            version,
            kernel,
            cpe23,
            arch,
            device,
            certainty: self.certainty,
        }
    }
}

/// Substitutes `{capture:N}` for the Nth capture group.
///
/// `None` when the template names a group that did not participate, or resolves
/// to an empty string.
pub(crate) fn fill(template: Option<&str>, captures: &[String]) -> Option<String> {
    let template = template?;
    if !template.contains("{capture:") {
        return Some(template.to_string());
    }

    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{capture:") {
        out.push_str(&rest[..start]);
        let after = &rest[start + "{capture:".len()..];
        let end = after.find('}')?;
        let index: usize = after[..end].parse().ok()?;
        let value = captures.get(index).filter(|value| !value.is_empty())?;
        out.push_str(value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);

    let out = out.trim().to_string();
    (!out.is_empty()).then_some(out)
}

/// Substitutes `{os.field}` for a sibling field already resolved.
fn fill_siblings(template: &str, siblings: &[(&str, Option<&str>)]) -> Option<String> {
    let mut out = template.to_string();
    for (name, value) in siblings {
        let token = format!("{{{name}}}");
        if out.contains(&token) {
            out = out.replace(&token, value.filter(|v| !v.is_empty())?);
        }
    }
    (!out.trim().is_empty()).then(|| out.trim().to_string())
}

/// The hardware a rule describes, where it describes any.
///
/// Read from the same map as [`OsMetadata::from_map`], but separately: a NETGEAR
/// ReadyNAS runs Linux, and the two are different facts. 536 shipped rules name
/// hardware and no operating system.
///
/// Templates resolve as the operating system's do.
pub fn hardware_from(
    metadata: &HashMap<String, String>,
    captures: &[String],
) -> Option<crate::model::host::HardwareInfo> {
    // The corpus's own certainty. Forty-six rules state zero, which disclaims
    // the attribution.
    let certainty: f32 = metadata
        .get("hw.certainty")
        .and_then(|value| value.parse().ok())
        .unwrap_or(1.0);
    if certainty <= 0.0 {
        return None;
    }

    let get = |key: &str| {
        metadata
            .get(key)
            .filter(|value| !value.is_empty())
            .and_then(|value| fill(Some(value.as_str()), captures))
    };

    // Captures first, since siblings read them: the label printers write
    // `hw.product` as `Thermal Label Printer {hw.model}`.
    let vendor = get("hw.vendor");
    let model = get("hw.model");
    let family = get("hw.family");
    let version = get("hw.version");
    let serial = get("hw.serial_number");

    let siblings = [
        ("hw.vendor", vendor.as_deref()),
        ("hw.model", model.as_deref()),
        ("hw.family", family.as_deref()),
        ("hw.version", version.as_deref()),
    ];
    let resolve = |value: Option<String>| {
        value.and_then(|template| match template.contains('{') {
            true => fill_siblings(&template, &siblings),
            false => Some(template),
        })
    };

    let product = resolve(get("hw.product"));
    let cpe23 = resolve(get("hw.cpe23"));

    crate::model::host::HardwareInfo::described(crate::model::host::HardwareDescription {
        vendor: vendor.as_deref(),
        product: product.as_deref(),
        family: family.as_deref(),
        cpe23: cpe23.as_deref(),
        model: model.as_deref(),
        version: version.as_deref(),
        serial_number: serial.as_deref(),
    })
}

/// What a matched service rule contributes to identifying the host, read as
/// `source` attests it.
///
/// `None` when the rule resolved to nothing usable.
///
/// # The family, and when a product may stand in for one
///
/// Most imported rules name no `os.family`; for operating systems `os.product`
/// (`Linux`, `AIX`, `Windows Server 2008 R2`) is read as the family. 362 rules
/// depend on that.
///
/// A rule naming a [device class](OsMetadata::device) is the exception: its
/// product is a model number. Read as a family, a Brother print server's
/// `NC-8700w` at 0.385 against `Network device` at 0.4 would leave 25% in
/// [`resolve`](super::resolve)'s vote, under the floor. Those 389 rules abstain
/// from the family vote.
pub fn evidence_from(
    metadata: &OsMetadata,
    captures: &[String],
    source: OsSource,
) -> Option<OsEvidence> {
    let resolved = metadata.resolve(captures);
    let family = match (&resolved.family, &resolved.device) {
        (Some(family), _) => Some(family.clone()),
        (None, Some(_)) => None,
        (None, None) => Some(resolved.product.clone()?),
    };

    // Absent means full strength; a stated certainty only lowers it.
    let certainty = resolved.certainty.unwrap_or(1.0).clamp(0.0, 1.0);

    // Forty-six rules state 0.0. At zero confidence the reading could only drag
    // a real answer down through the disagreement penalty.
    if certainty <= f32::EPSILON {
        return None;
    }

    let confidence = certainty * ceiling(source);

    let described = resolved
        .product
        .clone()
        .or_else(|| resolved.family.clone())
        .or_else(|| family.clone())
        .or_else(|| resolved.vendor.clone())
        .or_else(|| resolved.device.clone())?;

    let read = match source {
        OsSource::SnmpAgent => "snmp agent names",
        OsSource::MdnsResponder => "mdns responder names",
        _ => "service banner names",
    };

    Some(OsEvidence {
        source,
        family,
        device: resolved.device,
        vendor: resolved.vendor,
        product: resolved.product,
        version: resolved.version,
        kernel: resolved.kernel,
        arch: resolved.arch,
        cpe: resolved.cpe23,
        confidence,
        evidence: format!("{read} {described}"),
    })
}

/// Fills in what the corpus canonically knows about the operating system this
/// evidence names, where it names one that is recognised.
///
/// An SMB session setup's `Windows Server 2008 R2 Standard` has no family in it,
/// so [`evidence_from`] reads the product as the family, and two Windows
/// machines on different editions would disagree. `canonical` comes from the 59
/// corpus rules that name an operating system's canonical form, consulted
/// through [`canonical_os_name`](crate::fingerprint::SignatureDb).
///
/// # It may only add
///
/// Every field the first match stated is kept, since the canonical reading is
/// coarser (it would turn `Windows Server 2008 R2` into `Windows`). Only empty
/// fields are filled, plus the family where it merely repeats the product.
///
/// The confidence is unchanged: a canonical name is not a second observation.
pub fn canonicalise(evidence: OsEvidence, canonical: &OsEvidence) -> OsEvidence {
    /// The first match's value, or the canonical one where it had none.
    fn or(mine: Option<String>, theirs: &Option<String>) -> Option<String> {
        mine.or_else(|| theirs.clone())
    }

    // A family equal to the product is `evidence_from`'s fallback, replaced by
    // the canonical family. Rules stating both as the same word (Linux, AIX)
    // agree with the canonical reading anyway.
    let family = match (&evidence.family, &evidence.product, &canonical.family) {
        (Some(family), Some(product), Some(canonical)) if family == product => {
            Some(canonical.clone())
        }
        _ => or(evidence.family, &canonical.family),
    };

    OsEvidence {
        family,
        vendor: or(evidence.vendor, &canonical.vendor),
        version: or(evidence.version, &canonical.version),
        kernel: or(evidence.kernel, &canonical.kernel),
        arch: or(evidence.arch, &canonical.arch),
        cpe: or(evidence.cpe, &canonical.cpe),
        device: evidence.device.or_else(|| canonical.device.clone()),
        ..evidence
    }
}

/// The most a rule matched against `source`'s text may be worth, before the
/// corpus's own certainty scales it.
///
/// See [`BANNER_CEILING`] and [`AGENT_CEILING`].
pub fn ceiling(source: OsSource) -> f32 {
    match source {
        // The machine answering for itself, as SNMP is.
        OsSource::SnmpAgent | OsSource::MdnsResponder => AGENT_CEILING,
        _ => BANNER_CEILING,
    }
}

/// The most a banner is worth, before the corpus's own certainty scales it.
///
/// Enough to name a host on its own. Below a stack reading because a banner
/// describes the software, which may be a container's base image, a reverse
/// proxy, or an appliance's firmware.
///
/// One banner names a host at about 55, below the threshold that stops further
/// probing; agreeing with a stack reading it reaches the low eighties.
pub const BANNER_CEILING: f32 = 0.55;

/// The most a management agent's own description of its machine is worth.
///
/// Above [`BANNER_CEILING`]: net-snmp renders `sysDescr` from `uname -a` when
/// asked, so it is the running kernel, and on an appliance the firmware
/// reporting itself.
///
/// Below the 85 that
/// [`OsFingerprint::is_highly_confident`](crate::model::host::OsFingerprint::is_highly_confident)
/// reads, so settling a host still takes a second independent source.
pub const AGENT_CEILING: f32 = 0.8;

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

    fn metadata(pairs: &[(&str, &str)]) -> OsMetadata {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        OsMetadata::from_map(&map).expect("names an operating system")
    }

    fn hardware(
        pairs: &[(&str, &str)],
        captures: &[String],
    ) -> Option<crate::model::host::HardwareInfo> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        hardware_from(&map, captures)
    }

    /// A product written around a sibling field, as the label printers and many
    /// Cisco access points state it.
    #[test]
    fn a_product_written_around_a_sibling_field_is_completed_from_it() {
        let found = hardware(
            &[
                ("hw.vendor", "Cisco"),
                ("hw.model", "{capture:1}"),
                ("hw.product", "Aironet {hw.model}"),
            ],
            &["Aironet 1140".to_string(), "1140".to_string()],
        )
        .expect("it names something");

        assert_eq!(found.product(), Some("Aironet 1140"));
        assert_eq!(found.model(), Some("1140"));
    }

    /// `hw.certainty = 0.0` (forty-six rules) yields no hardware.
    #[test]
    fn a_rule_that_disclaims_its_own_attribution_produces_no_hardware() {
        assert!(hardware(&[("hw.certainty", "0.0"), ("hw.vendor", "Generic")], &[],).is_none());
    }

    /// The three fields a service states and an address block cannot reach.
    #[test]
    fn a_rule_that_names_a_unit_keeps_the_model_revision_and_serial() {
        let found = hardware(
            &[
                ("hw.vendor", "Xerox"),
                ("hw.product", "WorkCentre 4200"),
                ("hw.model", "4200"),
                ("hw.version", "2"),
                ("hw.serial_number", "{capture:1}"),
            ],
            &[
                "WorkCentre 4200 XRX9000123".to_string(),
                "XRX9000123".to_string(),
            ],
        )
        .expect("it names something");

        assert_eq!(found.model(), Some("4200"));
        assert_eq!(found.hardware_version(), Some("2"));
        assert_eq!(found.serial_number(), Some("XRX9000123"));
    }

    /// A rule verbatim from the imported corpus, templates in three fields.
    #[test]
    fn a_real_rule_builds_its_values_from_what_the_pattern_captured() {
        let rule = metadata(&[
            ("os.vendor", "Microsoft"),
            ("os.family", "Windows"),
            ("os.product", "{capture:1}"),
            ("os.edition", "{capture:2}"),
            ("os.version", "{capture:3}"),
        ]);

        let resolved = rule.resolve(&[
            "Windows Server 2003 Standard SP2".to_string(),
            "Windows Server 2003".to_string(),
            "Standard".to_string(),
            "SP2".to_string(),
        ]);

        assert_eq!(resolved.vendor.as_deref(), Some("Microsoft"));
        assert_eq!(resolved.family.as_deref(), Some("Windows"));
        assert_eq!(resolved.product.as_deref(), Some("Windows Server 2003"));
        assert_eq!(resolved.version.as_deref(), Some("SP2"));
    }

    /// The sibling form reads an already-resolved capture.
    #[test]
    fn a_platform_identifier_is_built_from_a_field_that_was_itself_captured() {
        let rule = metadata(&[
            ("os.family", "Windows"),
            ("os.product", "Windows 2000"),
            ("os.version", "{capture:2}"),
            ("os.cpe23", "cpe:/o:microsoft:windows_2000:{os.version}"),
        ]);

        let resolved = rule.resolve(&[
            "Windows 2000 Professional SP4".to_string(),
            "Professional".to_string(),
            "SP4".to_string(),
        ]);

        assert_eq!(
            resolved.cpe23.as_deref(),
            Some("cpe:/o:microsoft:windows_2000:SP4"),
            "the sibling template must see the resolved capture, not the template"
        );
    }

    /// A template naming a group that did not participate drops the field.
    #[test]
    fn a_template_over_an_absent_capture_drops_the_field_rather_than_half_building_it() {
        let rule = metadata(&[
            ("os.family", "Windows"),
            ("os.product", "Windows 2000"),
            ("os.version", "{capture:2}"),
            ("os.cpe23", "cpe:/o:microsoft:windows_2000:{os.version}"),
        ]);

        // An optional group that did not participate arrives as an empty string.
        let resolved = rule.resolve(&["Windows 2000".to_string(), String::new(), String::new()]);

        assert_eq!(resolved.version, None);
        assert_eq!(resolved.cpe23, None, "no dangling identifier");
        assert_eq!(
            resolved.product.as_deref(),
            Some("Windows 2000"),
            "and the fields that did resolve survive"
        );
    }

    /// A rule naming neither a family nor a product describes no operating
    /// system.
    #[test]
    fn metadata_that_names_no_system_is_not_a_reading() {
        let map: HashMap<String, String> = [("os.certainty".to_string(), "1.0".to_string())]
            .into_iter()
            .collect();
        assert!(OsMetadata::from_map(&map).is_none());
    }

    /// An architecture alone is kept, and is still not a reading.
    ///
    /// `from_map` keeps it; `evidence_from` declines it.
    #[test]
    fn an_architecture_alone_is_kept_but_is_not_a_reading() {
        let map: HashMap<String, String> = [("os.arch".to_string(), "mips".to_string())]
            .into_iter()
            .collect();

        let metadata = OsMetadata::from_map(&map).expect("the architecture survives");
        assert_eq!(metadata.arch.as_deref(), Some("mips"));

        assert!(
            evidence_from(&metadata, &[], OsSource::ServiceBanner).is_none(),
            "an architecture is a fact about the host, not a reading of its system"
        );
    }

    /// 362 rules name `Linux`, `AIX`, `FreeBSD` in `os.product` and no family.
    #[test]
    fn a_product_stands_in_for_a_family_nobody_stated() {
        let rule = metadata(&[("os.vendor", "Ubuntu"), ("os.product", "Linux")]);
        let found = evidence_from(&rule, &[], OsSource::ServiceBanner).expect("names a system");

        assert_eq!(found.family.as_deref(), Some("Linux"));
    }

    /// Except where a device class makes the product a model number (389 rules).
    #[test]
    fn a_model_number_never_stands_in_for_a_family() {
        let rule = metadata(&[
            ("os.vendor", "Brother"),
            ("os.product", "NC-8700w"),
            ("os.device", "Printer"),
        ]);
        let found = evidence_from(&rule, &[], OsSource::SnmpAgent).expect("names a system");

        assert_eq!(found.family, None);
        assert_eq!(found.product.as_deref(), Some("NC-8700w"));
        assert_eq!(found.device.as_deref(), Some("Printer"));
    }

    /// `os.device` and `hw.device` are the same fact.
    #[test]
    fn a_class_written_under_the_hardware_namespace_is_the_same_class() {
        let rule = metadata(&[("os.product", "Linux"), ("hw.device", "IP Camera")]);
        assert_eq!(rule.device.as_deref(), Some("IP Camera"));
    }

    /// A class can be captured; an empty template is dropped.
    #[test]
    fn a_captured_device_class_resolves_against_the_match() {
        let rule = metadata(&[("os.product", "VRP"), ("os.device", "{capture:2}")]);

        let captures = ["".to_string(), "".to_string(), "Switch".to_string()];
        assert_eq!(rule.resolve(&captures).device.as_deref(), Some("Switch"));
        assert_eq!(rule.resolve(&[]).device, None);
    }

    /// An agent is worth more than a banner.
    #[test]
    fn an_agent_outweighs_a_banner_saying_the_same_thing() {
        let rule = metadata(&[("os.family", "Linux"), ("os.kernel", "6.1.0")]);

        let by_agent = evidence_from(&rule, &[], OsSource::SnmpAgent).expect("names a system");
        let by_banner = evidence_from(&rule, &[], OsSource::ServiceBanner).expect("names a system");

        assert!(
            by_agent.confidence > by_banner.confidence,
            "an agent rendering `uname -a` on demand is closer to the machine \
             than a string a daemon carried from its build"
        );
        assert!(
            by_agent.confidence < 0.85,
            "and still not enough to settle a host on its own"
        );
    }

    /// A rule marked uncertain is worth less.
    #[test]
    fn the_corpus_own_hedging_lowers_what_a_rule_is_worth() {
        let confident = metadata(&[("os.family", "Linux"), ("os.product", "Ubuntu")]);
        let hedged = metadata(&[
            ("os.family", "Linux"),
            ("os.product", "Ubuntu"),
            ("os.certainty", "0.5"),
        ]);

        let confident =
            evidence_from(&confident, &[], OsSource::ServiceBanner).expect("names a system");
        let hedged = evidence_from(&hedged, &[], OsSource::ServiceBanner).expect("names a system");

        assert!(
            hedged.confidence < confident.confidence,
            "an unqualified rule is the ordinary case and must outrank a hedged one"
        );
    }

    /// A certainty of zero yields no evidence.
    #[test]
    fn a_rule_the_corpus_calls_worthless_produces_no_evidence() {
        let worthless = metadata(&[
            ("os.family", "Linux"),
            ("os.product", "Ubuntu"),
            ("os.certainty", "0.0"),
        ]);
        assert!(evidence_from(&worthless, &[], OsSource::ServiceBanner).is_none());
    }

    /// A banner names a host on its own, below the threshold that stops further
    /// probing.
    #[test]
    fn a_banner_alone_names_a_host_but_does_not_settle_it() {
        let rule = metadata(&[("os.family", "Linux"), ("os.product", "Ubuntu")]);
        let evidence = evidence_from(&rule, &[], OsSource::ServiceBanner).expect("names a system");
        assert!(evidence.confidence <= BANNER_CEILING);

        let alone = super::super::resolve(vec![evidence]).expect("a banner names a host");
        assert!(alone.accuracy >= 40, "reported rather than discarded");
        assert!(
            !alone.to_fingerprint().is_highly_confident(),
            "and not enough on its own to stop looking"
        );
    }

    /// A banner and a stack reading fail differently, so their agreement is worth
    /// more than either.
    #[test]
    fn a_banner_agreeing_with_the_wire_is_worth_more_than_either() {
        use super::super::OsVerdict;
        use crate::model::host::OsSource;

        let banner = evidence_from(
            &metadata(&[("os.family", "Linux"), ("os.product", "Ubuntu")]),
            &[],
            OsSource::ServiceBanner,
        )
        .expect("names a system");

        let stack = OsVerdict {
            family: Some("Linux".to_string()),
            device: None,
            vendor: None,
            product: None,
            version: None,
            kernel: None,
            arch: None,
            cpe: None,
            accuracy: 65,
            detail_accuracy: None,
            source: OsSource::TcpStack,
            evidence: "syn-ack opts=M,S,T,N,W".to_string(),
        }
        .as_evidence();

        let together = super::super::resolve(vec![stack, banner]).expect("named");
        assert!(
            together.accuracy > 65,
            "two independent sources agreeing must beat the better one alone"
        );
        assert_eq!(together.family.as_deref(), Some("Linux"));
    }

    /// An mDNS device-info record is worth what `sysDescr` is.
    #[test]
    fn a_responder_answering_for_the_machine_is_worth_what_an_agent_is() {
        assert_eq!(ceiling(OsSource::MdnsResponder), AGENT_CEILING);
        assert!(ceiling(OsSource::MdnsResponder) > ceiling(OsSource::ServiceBanner));
    }
}

#[cfg(test)]
mod against_the_shipped_corpus {
    use crate::fingerprint::SignatureDb;
    use crate::model::port::Protocol;

    /// A banner naming a release must yield that release.
    ///
    /// Both strings were read off a real host on 2026-08-21. The first maps to
    /// Debian 12 only if the software identifier is matched, not the whole line.
    ///
    /// The second names no release: the corpus has no OpenSSH 10 rule yet.
    #[test]
    fn a_banner_that_names_a_release_yields_the_release() {
        let db = SignatureDb::global();

        let debian_12 = db
            .identify(22, Protocol::Tcp, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10")
            .and_then(|found| found.os)
            .expect("a Debian OpenSSH banner names an operating system");

        assert_eq!(debian_12.family.as_deref(), Some("Linux"));
        assert_eq!(
            debian_12.version.as_deref(),
            Some("12"),
            "the release is the whole reason to read a banner: {debian_12:?}"
        );
        assert_eq!(
            debian_12.cpe.as_deref(),
            Some("cpe:/o:debian:debian_linux:12.0"),
            "the CPE keeps its registered form, which is a name in somebody \
             else's namespace rather than this engine's claim"
        );
        assert_eq!(debian_12.vendor.as_deref(), Some("Debian"));

        let debian_13 = db
            .identify(22, Protocol::Tcp, "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4")
            .and_then(|found| found.os)
            .expect("a Debian OpenSSH banner names an operating system");
        assert_eq!(debian_13.family.as_deref(), Some("Linux"));
        assert_eq!(
            debian_13.version.as_deref(),
            Some("13"),
            "read from the release Debian stamps into its own package version, so a \
             release the corpus has never seen still names itself: {debian_13:?}"
        );

        // A backport names the release it was built for.
        let backported = db
            .identify(22, Protocol::Tcp, "SSH-2.0-OpenSSH_9.7p1 Debian-1~bpo12+1")
            .and_then(|found| found.os)
            .expect("a backport names one too");
        assert_eq!(backported.version.as_deref(), Some("12"));

        // With `DebianBanner no` the suffix is gone and no release is named.
        let stripped = db
            .identify(22, Protocol::Tcp, "SSH-2.0-OpenSSH_10.0p2")
            .and_then(|found| found.os);
        assert!(
            stripped.is_none_or(|os| os.version.is_none()),
            "a stripped banner carries no release and must not invent one"
        );
    }

    /// A distribution with nothing in its banners to match.
    ///
    /// Arch ships OpenSSH unmarked; its kernel release is the only mark, and a
    /// rolling release has no version.
    ///
    /// Authored from the naming convention, not a captured host. `arch1` is a
    /// string only Arch produces, so a wrong guess only means no match.
    #[test]
    fn arch_is_named_by_its_kernel_because_nothing_else_names_it() {
        let db = SignatureDb::global();

        let found = db.identify(161, Protocol::Udp, "Linux host 6.12.1-arch1-1 #1 SMP PREEMPT_DYNAMIC Fri, 22 Nov 2024 12:00:00 +0000 x86_64",
        )
        .and_then(|found| found.os)
        .expect("an Arch kernel names Arch");

        assert_eq!(found.vendor.as_deref(), Some("Arch Linux"));
        assert_eq!(found.kernel.as_deref(), Some("6.12.1"));
        assert_eq!(
            found.version, None,
            "a rolling release has no version, and inventing one would be worse \
             than the silence it replaced"
        );

        // A bare `OpenSSH_10.0p2` could be Arch, Fedora, Gentoo or a source build.
        let by_ssh = db
            .identify(22, Protocol::Tcp, "SSH-2.0-OpenSSH_10.0p2")
            .and_then(|found| found.os);
        assert!(
            by_ssh.is_none_or(|os| os.vendor.is_none()),
            "an unmarked upstream banner must not be attributed to any distribution"
        );
    }

    /// The instruction set a `uname`-derived `sysDescr` ends with.
    ///
    /// 255 shipped rules carry `os.arch`.
    #[test]
    fn an_agent_that_states_its_machine_type_keeps_it() {
        let db = SignatureDb::global();

        let found = db
            .identify(
                161,
                Protocol::Udp,
                "FreeBSD freebsd-10-x64-ports-p 10.0-RELEASE-p4 FreeBSD 10.0-RELEASE-p4 #0: \
                 Tue Jun 3 13:14:57 UTC 2014 \
                 root@amd64-builder.daemonology.net:/usr/obj/usr/src/sys/GENERIC amd64",
            )
            .and_then(|found| found.os)
            .expect("a FreeBSD agent names FreeBSD");

        assert_eq!(found.family.as_deref(), Some("FreeBSD"));
        assert_eq!(found.version.as_deref(), Some("10.0-RELEASE-p4"));
        assert_eq!(found.arch.as_deref(), Some("amd64"));
    }

    /// A `sysDescr` that names hardware and no operating system.
    ///
    /// Read off a Brother NC-8700w print server on 2026-08-26. The rule carries a
    /// vendor, model, firmware and device class, and no family. The model stays
    /// under `product` and the class on its own axis.
    #[test]
    fn an_agent_that_names_only_hardware_names_hardware() {
        let db = SignatureDb::global();

        let found = db
            .identify(
                161,
                Protocol::Udp,
                "Brother NC-8700w, Firmware Ver.ZL  ,MID 8CE-823,FID 2",
            )
            .and_then(|found| found.os)
            .expect("a shipped rule reads this exact string");

        assert_eq!(found.vendor.as_deref(), Some("Brother"));
        assert_eq!(found.product.as_deref(), Some("NC-8700w"));
        assert_eq!(found.version.as_deref(), Some("ZL"));
        assert_eq!(found.device.as_deref(), Some("Printer"));
        assert_eq!(
            found.family, None,
            "a model number is not a family, and reading it as one is what put \
             `NC-8700w` on a ballot against `Network device`"
        );
    }

    /// The kernel survives from datagram to evidence.
    #[test]
    fn an_agent_that_names_a_kernel_names_a_kernel() {
        let db = SignatureDb::global();

        let found = db
            .identify(
                161,
                Protocol::Udp,
                "Linux zond 6.1.0-18-arm64 #1 SMP Debian 6.1.76-1 (2024-02-01) aarch64",
            )
            .and_then(|found| found.os)
            .expect("the kernel rule reads this");

        assert_eq!(found.family.as_deref(), Some("Linux"));
        assert_eq!(found.kernel.as_deref(), Some("6.1.0"));
        assert_eq!(found.source, crate::model::host::OsSource::SnmpAgent);
    }

    /// Releases nobody has a machine for.
    ///
    /// The generic Debian rule reads the release from the packaging stamp, so
    /// these need no live host (Debian 9 and 11 arm64 images do not boot under
    /// Apple's hypervisor).
    #[test]
    fn a_release_names_itself_without_a_machine_to_read_it_from() {
        let db = SignatureDb::global();
        for (banner, release) in [
            ("SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7", "9"),
            ("SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2", "10"),
            ("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3", "11"),
        ] {
            let found = db
                .identify(22, Protocol::Tcp, banner)
                .and_then(|found| found.os)
                .unwrap_or_else(|| panic!("{banner} names nothing"));

            assert_eq!(found.family.as_deref(), Some("Linux"));
            assert_eq!(found.vendor.as_deref(), Some("Debian"));
            assert_eq!(
                found.version.as_deref(),
                Some(release),
                "read from the stamp rather than from a table of known releases: {banner}"
            );
        }
    }

    /// The channel that answers the question no packet can.
    ///
    /// An SNMP agent's `sysDescr` states the kernel; 27 shipped rules read it.
    /// Matched through the analyzer's own entry point.
    #[test]
    fn an_snmp_agent_names_the_system_it_is_running() {
        let db = SignatureDb::global();
        let sys_descr = "Linux zond 6.1.0-18-arm64 #1 SMP Debian 6.1.76-1 (2024-02-01) aarch64";

        let found = db
            .identify(161, Protocol::Udp, sys_descr)
            .and_then(|found| found.os)
            .expect("a uname string names an operating system");

        assert_eq!(found.family.as_deref(), Some("Linux"));
        assert_eq!(
            found.kernel.as_deref(),
            Some("6.1.0"),
            "the kernel release is the whole reason to read this field: {found:?}"
        );
        assert_eq!(
            found.version, None,
            "a kernel is not a distribution release, and must not occupy its field \
             where it would contradict a banner that named one"
        );
        assert!(
            !found.evidence.to_ascii_lowercase().contains("zond"),
            "the nodename is somebody's hostname and must not travel with the finding"
        );
    }

    /// Real banners, matched by the shipped database, produce an operating
    /// system.
    #[test]
    fn real_banners_name_an_operating_system_through_the_shipped_signatures() {
        let db = SignatureDb::global();
        // The text the patterns are written against: for HTTP the `Server` value
        // (see the module docs).
        let cases = [
            (22u16, "SSH-2.0-OpenSSH_9.6p1 Debian-3"),
            (80, "Microsoft-IIS/4.0"),
        ];
        // Matched as the analyzer matches: the extracted field and the whole line.

        let mut named = 0usize;
        for (port, banner) in cases {
            // Port-linked set first, then global, as the matcher does.
            let found = db
                .identify(port, Protocol::Tcp, banner)
                .and_then(|found| found.os);

            if let Some(os) = found {
                assert!(
                    os.family.as_deref().is_none_or(|family| !family.is_empty()),
                    "a named family is not an empty one"
                );
                assert!(os.confidence > 0.0);
                named += 1;
            }
        }

        assert_eq!(
            named,
            cases.len(),
            "a shipped signature failed to name an operating system for text it was \
             written against, which is what it looks like when the imported metadata \
             stops reaching the matcher"
        );
    }
}
