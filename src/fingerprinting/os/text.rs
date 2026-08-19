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
//! Extraction is [`HttpHeadersAnalyzer`](crate::fingerprinting::HttpHeadersAnalyzer)'s
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
    /// A Common Platform Enumeration identifier.
    pub cpe23: Option<String>,
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
            cpe23: get("os.cpe23"),
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

        let siblings = [
            ("os.vendor", vendor.as_deref()),
            ("os.family", family.as_deref()),
            ("os.product", product.as_deref()),
            ("os.version", version.as_deref()),
        ];
        let cpe23 = fill(self.cpe23.as_deref(), captures)
            .and_then(|template| fill_siblings(&template, &siblings));

        Self {
            vendor,
            family,
            product,
            version,
            cpe23,
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

/// What a matched service rule contributes to identifying the host.
///
/// `None` when the rule resolved to nothing usable. The confidence is modest and
/// deliberately so: a banner says what the *service* was built against, which is
/// usually but not always what the machine runs — a container image reports its
/// own base distribution, not the host's kernel, and a proxy reports itself.
pub fn evidence_from(metadata: &OsMetadata, captures: &[String]) -> Option<OsEvidence> {
    let resolved = metadata.resolve(captures);
    let family = resolved
        .family
        .clone()
        .or_else(|| resolved.product.clone())?;

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

    // Scaled below what a stack reading is worth: the stack is the machine
    // answering for itself, where a banner is software describing what it was
    // compiled against.
    let confidence = certainty * BANNER_CEILING;

    let described = resolved
        .product
        .clone()
        .or_else(|| resolved.family.clone())
        .unwrap_or_else(|| family.clone());

    Some(OsEvidence {
        source: OsSource::ServiceBanner,
        family,
        vendor: resolved.vendor,
        product: resolved.product,
        version: resolved.version,
        cpe: resolved.cpe23,
        confidence,
        evidence: format!("service banner names {described}"),
    })
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
const BANNER_CEILING: f32 = 0.55;

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

        let confident = evidence_from(&confident, &[]).expect("names a system");
        let hedged = evidence_from(&hedged, &[]).expect("names a system");

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
        assert!(evidence_from(&worthless, &[]).is_none());
    }

    /// A banner names a host on its own — `OpenSSH_9.6p1 Debian` really does say
    /// Debian — but modestly, and below the threshold that would stop a caller
    /// probing further. The software is not always the host: a container reports
    /// its base image rather than the kernel underneath it.
    #[test]
    fn a_banner_alone_names_a_host_but_does_not_settle_it() {
        let rule = metadata(&[("os.family", "Linux"), ("os.product", "Ubuntu")]);
        let evidence = evidence_from(&rule, &[]).expect("names a system");
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
        )
        .expect("names a system");

        let stack = OsVerdict {
            family: "Linux".to_string(),
            vendor: None,
            product: None,
            version: None,
            cpe: None,
            accuracy: 65,
            source: OsSource::TcpStack,
            evidence: "syn-ack opts=M,S,T,N,W".to_string(),
        }
        .as_evidence();

        let together = super::super::resolve(vec![stack, banner]).expect("named");
        assert!(
            together.accuracy > 65,
            "two independent sources agreeing must beat the better one alone"
        );
        assert_eq!(together.family, "Linux");
    }
}

#[cfg(test)]
mod against_the_shipped_corpus {
    use crate::fingerprinting::SignatureDb;
    use crate::fingerprinting::prefilter::Prefilter;

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

        let mut named = 0usize;
        for (port, banner) in cases {
            // The port-linked set first, then the global one, exactly as the
            // matcher does.
            let found = db
                .signatures_for_port(port)
                .iter()
                .chain(db.prefilter().candidates(banner).iter())
                .filter_map(|&index| db.signature(index).identify(banner))
                .find_map(|matched| matched.os);

            if let Some(os) = found {
                assert!(!os.family.is_empty(), "a named family is not an empty one");
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
