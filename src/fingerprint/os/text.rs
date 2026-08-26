// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a service said about the machine underneath it
//!
//! A stack's shape says which family a host belongs to. A banner frequently says
//! which *build* — `SSH-2.0-OpenSSH_9.6p1 Debian` names a distribution outright,
//! and `Server: Microsoft-IIS/10.0` names a family with something close to
//! certainty. This is where that half is read.
//!
//! ## What a banner can and cannot say
//!
//! It names the host, modestly. What it actually describes is the *software*, and
//! the software is not always the machine: a container reports the base image it
//! was built from rather than the kernel it runs on, a reverse proxy reports
//! itself, and an appliance reports the vendor's firmware. That is why this
//! source sits below a stack reading, which is the machine answering for itself,
//! and why the two agreeing is worth more than either.
//!
//! ## Where it is joined up, and where it is not yet
//!
//! A rule matches the text it was written against, and that is not always the
//! whole banner. The imported SSH rules match a version string as it arrives, so
//! they work directly off what the transport read. The imported HTTP rules match
//! a `Server` header **value** — `^Microsoft-IIS/4.0$`, anchored at both ends —
//! so a full response never matches one, and reaching them means handing over the
//! extracted header rather than the banner.
//!
//! Extraction is [`HttpHeadersAnalyzer`](crate::fingerprint::HttpHeadersAnalyzer)'s
//! job and it already does it for service identification; running the extracted
//! value back through the signature set for *operating-system* metadata is not
//! wired up. So this source reaches SSH and the other line-oriented protocols
//! today, and the largest single family of OS-bearing rules in the corpus — the
//! web servers — is still on the other side of that seam.
//!
//! ## It costs nothing, which is the point
//!
//! Over half the shipped signature corpus — 2442 of 4732 rules — already carries
//! `os.*` metadata, matched against text the service pipeline already collects
//! from ports it has already opened. No probe here is new. The work is entirely
//! in *not throwing the metadata away*, which is what the runtime did before this
//! module existed: [`Signature`](crate::fingerprinting) kept a rule's service,
//! product, vendor and version, and dropped everything else on the floor.
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
//! Two forms, and they resolve in order. `{capture:N}` takes the Nth capture
//! group, and is why a match has to keep its groups at all. `{os.field}` takes a
//! *sibling* field of the same rule, which means the capture form has to be
//! resolved first — 205 rules in the corpus build a platform identifier out of a
//! version that was itself captured.
//!
//! A template naming something absent resolves to **nothing at all**, and the
//! field is dropped rather than emitted half-built. A platform identifier reading
//! `cpe:/o:microsoft:windows_2000:` is worse than no identifier: it is a string a
//! consumer will try to match on.

use std::collections::HashMap;

use super::evidence::OsEvidence;
use super::verdict::OsSource;

/// What a matched service rule said about the operating system underneath it.
///
/// A struct of the fields worth keeping rather than the rule's whole metadata
/// map. The corpus carries a dozen `os.*` keys and this holds the six that name
/// the machine; the rest — architecture, device class, build number — describe
/// the hardware or the packaging and belong to a different question than "what
/// operating system is this".
///
/// Stored behind a pointer on the signatures that have one, because 2290 of the
/// 4732 rules have none and a scan holds all of them at once.
/// Comparable but not [`Eq`]: [`certainty`](Self::certainty) is a float, and a
/// value nobody can write down exactly is not one two rules should be claimed to
/// share.
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
    /// **Not a finer [`version`](Self::version), and not a competitor to it.** A
    /// distribution release and the kernel it ships are two facts about one
    /// machine: Debian 12 runs kernel 6.1, and neither number is a better answer
    /// than the other. Filing the kernel as a version made an SSH banner naming
    /// `12` and an SNMP agent naming `6.1.0` look like a contradiction, and a
    /// host that had told this engine both was reported as neither.
    ///
    /// Read from the `os.kernel` key, which is this engine's own: the imported
    /// corpus has no notion of it and puts a kernel in `os.version` where it
    /// finds one.
    pub kernel: Option<String>,
    /// A Common Platform Enumeration identifier.
    pub cpe23: Option<String>,
    /// What kind of box the rule says this is — `Printer`, `Switch`, `Router`.
    ///
    /// Read from `os.device`, falling back to `hw.device`, which is the same
    /// class written under the hardware namespace by rules that describe a
    /// device rather than the software on it.
    ///
    /// **Its presence changes how the rest of the rule reads.** A rule stating a
    /// class is describing hardware, so its `product` is a model number and its
    /// `vendor` is a manufacturer — see [`evidence_from`].
    pub device: Option<String>,
    /// How sure the corpus itself says this rule is, `0.0..=1.0`.
    ///
    /// The imported rules carry their own hedging on 353 entries, and honouring
    /// it is free: a corpus that marks a rule uncertain has told us something we
    /// would otherwise have to guess.
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
            device: get("os.device").or_else(|| get("hw.device")),
            certainty: get("os.certainty").and_then(|v| v.parse().ok()),
        };

        // A rule naming neither a family nor a product says nothing this layer
        // can use, whatever else it carries.
        (found.family.is_some() || found.product.is_some()).then_some(found)
    }

    /// Resolves this rule's templates against what its pattern captured.
    ///
    /// `captures` is indexed as the pattern numbers its groups, index 0 being the
    /// whole match. A field whose template names a group that did not participate
    /// resolves to `None` and is dropped rather than emitted half-built. A
    /// platform identifier reading `cpe:/o:microsoft:windows_2000:` is worse than
    /// no identifier at all, because a consumer will try to match on it.
    pub fn resolve(&self, captures: &[String]) -> Self {
        // Capture templates first: the sibling form below reads the results.
        let vendor = fill(self.vendor.as_deref(), captures);
        let family = fill(self.family.as_deref(), captures);
        let product = fill(self.product.as_deref(), captures);
        let version = fill(self.version.as_deref(), captures);
        let kernel = fill(self.kernel.as_deref(), captures);
        let device = fill(self.device.as_deref(), captures);

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
            device,
            certainty: self.certainty,
        }
    }
}

/// Substitutes `{capture:N}` for the Nth capture group.
///
/// `None` when the template names a group that did not participate, or resolves
/// to nothing at all — an empty value is not a value.
fn fill(template: Option<&str>, captures: &[String]) -> Option<String> {
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

/// What a matched service rule contributes to identifying the host, read as
/// `source` attests it.
///
/// `None` when the rule resolved to nothing usable.
///
/// # The family, and when a product may stand in for one
///
/// Most imported rules name no `os.family`, and for the ones describing an
/// operating system the `os.product` is the family in all but name — `Linux`,
/// `AIX`, `Windows Server 2008 R2` — so it is read as one. 362 rules depend on
/// that.
///
/// **A rule that names a [device class](OsMetadata::device) is the exception,
/// and it is not a small one.** There the product is a model number and reading
/// it as a family puts `NC-8700w` on the ballot [`resolve`](super::resolve)
/// settles by vote, where it can only run against real families. Measured, on a
/// Brother print server: `NC-8700w` at 0.385 against `Network device` at 0.4
/// left 25%, under the floor, and a host that had answered three separate
/// probes was reported as unidentified. Those 389 rules state no family, keep
/// their model in `product` and their class in `device`, and abstain.
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

    // The corpus's own hedging where it gave any. Absent means the rule asserted
    // its attribution without qualification, which is the ordinary case — only
    // 353 of the shipped rules carry the field at all — so the default is full
    // strength and a stated certainty is a *downgrade*, never an upgrade.
    let certainty = resolved.certainty.unwrap_or(1.0).clamp(0.0, 1.0);

    // Forty-six rules state 0.0, which is the corpus saying in as many words that
    // this attribution is worth nothing. Emitting it at zero confidence would put
    // a family name into the resolver where it can only ever drag a real answer
    // down through the disagreement penalty. Declining is what the corpus asked
    // for.
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
        cpe: resolved.cpe23,
        confidence,
        evidence: format!("{read} {described}"),
    })
}

/// The most a rule matched against `source`'s text may be worth, before the
/// corpus's own certainty scales it.
///
/// One number per kind of text, because the kinds are not equally close to the
/// machine. See [`BANNER_CEILING`] and [`AGENT_CEILING`].
pub fn ceiling(source: OsSource) -> f32 {
    match source {
        OsSource::SnmpAgent => AGENT_CEILING,
        _ => BANNER_CEILING,
    }
}

/// The most a banner is worth, before the corpus's own certainty scales it.
///
/// Enough to name a host on its own, and not by much. `OpenSSH_9.6p1 Debian`
/// really does say Debian — a distribution's build of a daemon is running on that
/// distribution, and pretending otherwise would discard the most direct statement
/// a machine ever makes about itself.
///
/// Held below what a stack reading is worth for a reason that is not hedging.
/// **A banner describes the software, and the software is not always the host.**
/// A container reports the base image it was built from rather than the kernel it
/// runs on; a reverse proxy reports the proxy and not what is behind it; an
/// appliance reports the vendor's firmware while the box underneath runs
/// something else. The stack, by contrast, is the machine answering for itself.
///
/// So one banner names a host at around 55, which reports but does not reach the
/// threshold that stops further probing; a banner agreeing with a stack reading
/// reaches the low eighties, which is the point of having both.
pub const BANNER_CEILING: f32 = 0.55;

/// The most a management agent's own description of its machine is worth.
///
/// Above [`BANNER_CEILING`] for the reason that ceiling exists: a banner is a
/// string a daemon carries from its build, and the gap between the build and the
/// running machine is what holds the number down. `sysDescr` has no such gap. On
/// a Unix host net-snmp renders it from `uname -a` when the question is asked —
/// the kernel that is executing, at the moment of asking — and on an appliance it
/// is the firmware build reporting itself. The agent is part of the machine, not
/// software running on it.
///
/// Below the 85 that
/// [`OsFingerprint::is_highly_confident`](crate::model::host::OsFingerprint::is_highly_confident)
/// reads, so one agent still does not settle a host on its own. Reaching that
/// takes a second independent source, which is the rule everywhere else here and
/// there is no case for exempting this one.
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

    /// A rule taken verbatim from the imported corpus, with the capture groups
    /// its pattern would have produced. Templates in three fields at once, which
    /// is the ordinary shape rather than a corner case.
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

    /// The second template form, and the reason resolution is ordered: 205 rules
    /// in the corpus build a platform identifier out of a version that was itself
    /// captured, so the capture form has to be filled before the sibling form
    /// reads it.
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

    /// A template naming a group that did not participate resolves to nothing and
    /// the field is dropped. Emitting the half-built value would put
    /// `cpe:/o:microsoft:windows_2000:` into a report, which is worse than an
    /// absent identifier because a consumer will try to match on it.
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

    /// A rule naming neither a family nor a product describes no operating system
    /// this layer can use, whatever else it carries — several hundred rules in
    /// the corpus record only an architecture or a device class.
    #[test]
    fn metadata_that_names_no_system_is_not_kept() {
        let map: HashMap<String, String> = [("os.arch".to_string(), "mips".to_string())]
            .into_iter()
            .collect();
        assert!(OsMetadata::from_map(&map).is_none());
    }

    /// 362 rules name an operating system in `os.product` and no family at all —
    /// `Linux`, `AIX`, `FreeBSD` — and reading the product as the family is what
    /// makes them work.
    #[test]
    fn a_product_stands_in_for_a_family_nobody_stated() {
        let rule = metadata(&[("os.vendor", "Ubuntu"), ("os.product", "Linux")]);
        let found = evidence_from(&rule, &[], OsSource::ServiceBanner).expect("names a system");

        assert_eq!(found.family.as_deref(), Some("Linux"));
    }

    /// Except where a device class says the product is a model number. 389 rules
    /// are written that way, and reading `NC-8700w` as a family is what set a
    /// printer's model against the class of box a hop counter had established.
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

    /// The corpus writes the same class under two namespaces. Both are the same
    /// fact about the same box.
    #[test]
    fn a_class_written_under_the_hardware_namespace_is_the_same_class() {
        let rule = metadata(&[("os.product", "Linux"), ("hw.device", "IP Camera")]);
        assert_eq!(rule.device.as_deref(), Some("IP Camera"));
    }

    /// A class can be captured out of the text like anything else, and a
    /// template that resolves to nothing is dropped rather than emitted raw.
    #[test]
    fn a_captured_device_class_resolves_against_the_match() {
        let rule = metadata(&[("os.product", "VRP"), ("os.device", "{capture:2}")]);

        let captures = ["".to_string(), "".to_string(), "Switch".to_string()];
        assert_eq!(rule.resolve(&captures).device.as_deref(), Some("Switch"));
        assert_eq!(rule.resolve(&[]).device, None);
    }

    /// What an agent says is worth more than what a daemon was compiled with,
    /// and the gap is the whole reason the two are separate sources.
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

    /// The corpus hedges on 353 of its own rules and honouring that is free.
    /// A rule marked uncertain must not be worth what a confident one is.
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

    /// Forty-six rules in the corpus state a certainty of zero, which is it
    /// saying the attribution is worth nothing. Emitting that as evidence would
    /// put a family name in front of the resolver where it can only drag a real
    /// answer down through the disagreement penalty.
    #[test]
    fn a_rule_the_corpus_calls_worthless_produces_no_evidence() {
        let worthless = metadata(&[
            ("os.family", "Linux"),
            ("os.product", "Ubuntu"),
            ("os.certainty", "0.0"),
        ]);
        assert!(evidence_from(&worthless, &[], OsSource::ServiceBanner).is_none());
    }

    /// A banner names a host on its own — `OpenSSH_9.6p1 Debian` really does say
    /// Debian — but modestly, and below the threshold that would stop a caller
    /// probing further. The software is not always the host: a container reports
    /// its base image rather than the kernel underneath it.
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

    /// The reason for having two sources rather than a better single one. A
    /// banner and a stack reading are read from different places and fail in
    /// different ways, so agreement between them is worth more than either — and
    /// this is where a verdict legitimately passes what one packet could support.
    #[test]
    fn a_banner_agreeing_with_the_wire_is_worth_more_than_either() {
        use super::super::{OsSource, OsVerdict};

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
}

#[cfg(test)]
mod against_the_shipped_corpus {
    use crate::fingerprint::SignatureDb;
    use crate::model::port::Protocol;

    /// A banner naming a release must yield that release.
    ///
    /// Both of these are strings read off a real host on 2026-08-21, exactly as
    /// they arrive on the wire. The first is the case that was broken: the
    /// corpus held a rule mapping it to Debian 12 with a CPE, and the engine
    /// reported `Linux` — because the corpus anchors its patterns on the SSH
    /// software identifier and the whole identification line was being matched
    /// instead, so only a loose family rule could ever fire.
    ///
    /// The second names no release yet, and that is the corpus being short
    /// rather than the matcher being broken: it holds no OpenSSH 10 rule. It is
    /// here so that adding one is visible as this assertion getting stronger.
    #[test]
    fn a_banner_that_names_a_release_yields_the_release() {
        let db = SignatureDb::global();

        let debian_12 = crate::fingerprint::analyzer::os_from_banner(
            db,
            22,
            Protocol::Tcp,
            "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10",
        )
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

        let debian_13 = crate::fingerprint::analyzer::os_from_banner(
            db,
            22,
            Protocol::Tcp,
            "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4",
        )
        .expect("a Debian OpenSSH banner names an operating system");
        assert_eq!(debian_13.family.as_deref(), Some("Linux"));
        assert_eq!(
            debian_13.version.as_deref(),
            Some("13"),
            "read from the release Debian stamps into its own package version, so a \
             release the corpus has never seen still names itself: {debian_13:?}"
        );

        // A backport says which release it was built *for*, in the same place.
        let backported = crate::fingerprint::analyzer::os_from_banner(
            db,
            22,
            Protocol::Tcp,
            "SSH-2.0-OpenSSH_9.7p1 Debian-1~bpo12+1",
        )
        .expect("a backport names one too");
        assert_eq!(backported.version.as_deref(), Some("12"));

        // And a banner with the suffix stripped — `DebianBanner no` — names no
        // release, because there is none in it to name. Declining is right:
        // guessing a release from an OpenSSH version would attribute Debian's
        // packaging to every distribution that ships the same upstream.
        let stripped = crate::fingerprint::analyzer::os_from_banner(
            db,
            22,
            Protocol::Tcp,
            "SSH-2.0-OpenSSH_10.0p2",
        );
        assert!(
            stripped.is_none_or(|os| os.version.is_none()),
            "a stripped banner carries no release and must not invent one"
        );
    }

    /// A distribution with nothing in its banners to match.
    ///
    /// Arch ships OpenSSH unpatched and unmarked, so no banner rule can reach
    /// it — Recog carries none. Its kernel release is the one place its own
    /// packaging signs its work, and there is deliberately no version, because a
    /// rolling release has none to give.
    ///
    /// Authored from the naming convention rather than from a host this engine
    /// has read, which is safe here for one specific reason: the failure mode is
    /// silence. `arch1` in a kernel release is a string only Arch produces, so a
    /// wrong guess about the shape means the rule never fires — it cannot name
    /// somebody else's machine Arch.
    #[test]
    fn arch_is_named_by_its_kernel_because_nothing_else_names_it() {
        let db = SignatureDb::global();

        let found = crate::fingerprint::analyzer::os_from_banner(db, 161, Protocol::Udp,
            "Linux host 6.12.1-arch1-1 #1 SMP PREEMPT_DYNAMIC Fri, 22 Nov 2024 12:00:00 +0000 x86_64",
        )
        .expect("an Arch kernel names Arch");

        assert_eq!(found.vendor.as_deref(), Some("Arch Linux"));
        assert_eq!(found.kernel.as_deref(), Some("6.12.1"));
        assert_eq!(
            found.version, None,
            "a rolling release has no version, and inventing one would be worse \
             than the silence it replaced"
        );

        // And the banner it actually presents on port 22 names nothing, which is
        // the honest answer rather than a gap to be papered over: a bare
        // `OpenSSH_10.0p2` is Arch, Fedora, Gentoo or a source build alike.
        let by_ssh = crate::fingerprint::analyzer::os_from_banner(
            db,
            22,
            Protocol::Tcp,
            "SSH-2.0-OpenSSH_10.0p2",
        );
        assert!(
            by_ssh.is_none_or(|os| os.vendor.is_none()),
            "an unmarked upstream banner must not be attributed to any distribution"
        );
    }

    /// A `sysDescr` that names hardware and no operating system.
    ///
    /// Read off a Brother NC-8700w print server on 2026-08-26, exactly as its
    /// agent answered. The rule for it carries a vendor, a model, a firmware and
    /// a device class — and no family, because the box never said what it runs.
    ///
    /// Every field here was on the wire and none of it reached a report: the
    /// model was read as the *family*, put on the ballot against the `Network
    /// device` a hop counter of 255 had already established, and the two
    /// annihilated. What this asserts is that the reading survives to be
    /// reported, with the model under `product` where it belongs and the class
    /// on its own axis.
    #[test]
    fn an_agent_that_names_only_hardware_names_hardware() {
        let db = SignatureDb::global();

        let found = crate::fingerprint::analyzer::os_from_banner(
            db,
            161,
            Protocol::Udp,
            "Brother NC-8700w, Firmware Ver.ZL  ,MID 8CE-823,FID 2",
        )
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

    /// The kernel an agent reads out is the point of asking, and it survives the
    /// whole path from datagram to evidence.
    #[test]
    fn an_agent_that_names_a_kernel_names_a_kernel() {
        let db = SignatureDb::global();

        let found = crate::fingerprint::analyzer::os_from_banner(
            db,
            161,
            Protocol::Udp,
            "Linux zond 6.1.0-18-arm64 #1 SMP Debian 6.1.76-1 (2024-02-01) aarch64",
        )
        .expect("the kernel rule reads this");

        assert_eq!(found.family.as_deref(), Some("Linux"));
        assert_eq!(found.kernel.as_deref(), Some("6.1.0"));
        assert_eq!(found.source, super::super::OsSource::SnmpAgent);
    }

    /// Releases nobody has a machine for.
    ///
    /// The generic Debian rule reads the release out of the stamp its packaging
    /// writes, so a release this engine has never been pointed at names itself
    /// from a string alone. That is what makes these testable without booting
    /// anything — which matters, because the arm64 cloud images for Debian 9 and
    /// 11 do not boot under Apple's hypervisor at all.
    #[test]
    fn a_release_names_itself_without_a_machine_to_read_it_from() {
        let db = SignatureDb::global();
        for (banner, release) in [
            ("SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7", "9"),
            ("SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2", "10"),
            ("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3", "11"),
        ] {
            let found = crate::fingerprint::analyzer::os_from_banner(db, 22, Protocol::Tcp, banner)
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
    /// A TCP stack's shape names a family and cannot separate two kernels eleven
    /// releases apart — measured, on two labelled hosts. A service banner names
    /// a distribution release at best. An SNMP agent's `sysDescr` is the output
    /// of `uname -a`, so it states the kernel outright, and 27 shipped rules are
    /// written against it.
    ///
    /// Matched through the same entry point the analyzer uses, so this cannot
    /// pass while the engine feeds the matcher something else — which is exactly
    /// how the SSH release rules stayed unreachable.
    #[test]
    fn an_snmp_agent_names_the_system_it_is_running() {
        let db = SignatureDb::global();
        let sys_descr = "Linux zond 6.1.0-18-arm64 #1 SMP Debian 6.1.76-1 (2024-02-01) aarch64";

        let found = crate::fingerprint::analyzer::os_from_banner(db, 161, Protocol::Udp, sys_descr)
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

    /// The claim this module makes, checked against what actually ships rather
    /// than against a fixture: real banners, matched by the real signature
    /// database, produce an operating system.
    ///
    /// Each of these is a string a host genuinely sends. If the imported
    /// metadata stopped reaching the matcher — which is the state this module was
    /// written to end — every one would come back naming nothing, and no other
    /// test in the tree would notice.
    #[test]
    fn real_banners_name_an_operating_system_through_the_shipped_signatures() {
        let db = SignatureDb::global();
        // Each is the text the corpus's patterns are written against, which is
        // not always the whole banner: the imported HTTP rules match a `Server`
        // header *value* (`^Microsoft-IIS/...$`, anchored both ends), so feeding
        // them a full response can never match. Extracting that value is
        // `HttpHeadersAnalyzer`'s job and is where this evidence has to be joined
        // up for HTTP — see the note in the module docs.
        let cases = [
            (22u16, "SSH-2.0-OpenSSH_9.6p1 Debian-3"),
            (80, "Microsoft-IIS/4.0"),
        ];
        // Matched the way the analyzer matches them, which for a structured
        // banner is against the field the corpus anchors on as well as the whole
        // line. Feeding only the line is what this test used to do, and it is
        // why it passed while every release-naming SSH rule was unreachable.

        let mut named = 0usize;
        for (port, banner) in cases {
            // The port-linked set first, then the global one, exactly as the
            // matcher does.
            let found =
                crate::fingerprint::analyzer::os_from_banner(db, port, Protocol::Tcp, banner);

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
