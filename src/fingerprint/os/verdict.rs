// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Turning matched rules into an answer
//!
//! [`classify`] matches an observation against the rule database and returns
//! what can be said, which is sometimes nothing.
//!
//! ## One packet is one piece of evidence
//!
//! The hop counter, window, option layout and window scale of one reply all
//! follow from one stack build, so they are not independent. A whole
//! observation is matched jointly against a rule and yields **one** result.
//! Independence is assumed only between different sources (a stack, a service
//! banner, a hardware address, a DHCP option), which [`resolve`](super::resolve)
//! combines; [`OsVerdict`] carries a source and a confidence for that.
//!
//! ## The ceiling
//!
//! [`MAX_STACK_ACCURACY`] keeps stack evidence alone below the 85 that
//! [`OsFingerprint::is_highly_confident`](crate::model::host::OsFingerprint::is_highly_confident)
//! reads. Callers use that threshold to decide whether to stop probing, so it
//! must take corroboration from a second, independent source.
//!
//! ## Nothing is a valid answer
//!
//! Below [`MIN_REPORTABLE_ACCURACY`] no operating system is reported. A
//! confident wrong answer is believed; a missing one invites a second look.

use crate::model::host::OsFingerprint;
use crate::model::host::{OsEvidence, OsSource};

use super::db::RuleDb;
use super::observation::{StackObservation, StackReply};
use super::series::SeriesClasses;
use super::signature::{OsDefinition, Provenance};

/// The most a single reply's stack shape may claim on its own.
///
/// Below the 85 that marks high confidence; see the module documentation.
pub const MAX_STACK_ACCURACY: u8 = 70;

/// The least a finding may score and still be reported.
///
/// Under this, [`classify`] yields nothing rather than the least bad guess.
pub const MIN_REPORTABLE_ACCURACY: u8 = 40;

/// What a rule measured by this engine is worth before its own weight applies.
///
/// Several matches do not raise the score; see [`classify`].
const MEASURED_ACCURACY: f32 = 65.0;

/// What a rule taken from published stack characteristics is worth.
///
/// Lower because the rule has not been seen through this engine's own probe:
/// option negotiation is reciprocal, so a documented layout may not match what
/// this probe draws.
///
/// Above [`MIN_REPORTABLE_ACCURACY`], so such a rule still reports. Confirming
/// it on real hardware promotes it.
const PUBLISHED_ACCURACY: f32 = 50.0;

/// What the rules concluded about one observation.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct OsVerdict {
    /// The broad family, where anything could name one.
    ///
    /// `None` where every source abstained, such as an agent naming only make
    /// and model. See [`OsEvidence::family`](crate::model::host::OsEvidence::family).
    pub family: Option<String>,
    /// What kind of box this is, where a source said: `Printer`, `Switch`,
    /// `Router`. Independent of the family.
    pub device: Option<String>,
    /// The vendor, where a rule named one.
    pub vendor: Option<String>,
    /// The product, where a rule named one.
    pub product: Option<String>,
    /// The version, where a rule named one.
    pub version: Option<String>,
    /// A Common Platform Enumeration identifier, where a rule named one.
    pub cpe: Option<String>,
    /// The kernel release, where a source read one.
    ///
    /// Separate from [`version`](Self::version): a distribution release and its
    /// kernel are two facts.
    pub kernel: Option<String>,
    /// The instruction set, where a source read one.
    ///
    /// Never from a handshake; from text such as an SNMP `sysDescr`, which on a
    /// Unix host ends with the machine type.
    pub arch: Option<String>,
    /// How sure this is, on the `0..=100` scale
    /// [`OsFingerprint`] uses. Bounded by [`MAX_STACK_ACCURACY`].
    ///
    /// About the family, which is the part every source can speak to.
    pub accuracy: u8,
    /// How sure the parts *past* the family are, where this names any.
    ///
    /// Separate because a stack reading and a banner may agree on Linux while
    /// only the banner names the release. `None` where nothing finer than a
    /// family was named.
    pub detail_accuracy: Option<u8>,
    /// What produced it.
    pub source: OsSource,
    /// One line describing the observation this was read off, for a report to
    /// carry beside the conclusion. See
    /// [`StackObservation::summary`](super::StackObservation::summary).
    pub evidence: String,
}

impl OsVerdict {
    /// Presents this verdict as one item for [`resolve`](super::resolve) to fold
    /// against other sources.
    ///
    /// The accuracy becomes a probability, the scale the combining arithmetic
    /// uses. A whole reply is one item; see the module documentation.
    pub fn as_evidence(&self) -> OsEvidence {
        OsEvidence {
            source: self.source,
            family: self.family.clone(),
            device: self.device.clone(),
            vendor: self.vendor.clone(),
            product: self.product.clone(),
            version: self.version.clone(),
            kernel: self.kernel.clone(),
            arch: self.arch.clone(),
            cpe: self.cpe.clone(),
            confidence: f32::from(self.accuracy) / 100.0,
            evidence: self.evidence.clone(),
        }
    }

    /// The label a reader sees: the most specific thing the rules supported.
    ///
    /// Infallible, because [`resolve`](super::resolve) declines rather than
    /// return a verdict that names nothing.
    pub fn label(&self) -> String {
        // `product` equal to the family means no product; for a Linux
        // distribution the distribution is in `vendor` (993 rules), so Debian 12
        // reads `Debian 12`, not `Linux 12.0`.
        //
        // With no product at all, `vendor` is often a device maker (Ubiquiti,
        // AXIS, Crestron), and seventeen rules pair `Microsoft` with `Windows`;
        // those keep the family.
        match (&self.product, &self.vendor) {
            (Some(product), Some(vendor)) if Some(product.as_str()) == self.family.as_deref() => {
                vendor.clone()
            }
            // With a device class the product is a model, shown with its maker:
            // `Brother NC-8700w`.
            (Some(product), Some(vendor))
                if self.device.is_some() && !product.starts_with(vendor.as_str()) =>
            {
                format!("{vendor} {product}")
            }
            (Some(product), _) => product.clone(),
            (None, vendor) => self
                .family
                .clone()
                .or_else(|| vendor.clone())
                .unwrap_or_else(|| self.device.clone().unwrap_or_default()),
        }
    }

    /// Projects onto the model's [`OsFingerprint`].
    ///
    /// `OsFingerprint` ranks findings by accuracy and fills gaps on a tie.
    pub fn to_fingerprint(&self) -> OsFingerprint {
        let mut fingerprint =
            OsFingerprint::new(self.label(), self.accuracy).with_evidence(&*self.evidence);

        if let Some(family) = &self.family {
            fingerprint = fingerprint.with_family(&**family);
        }
        if let Some(device) = &self.device {
            fingerprint = fingerprint.with_device(&**device);
        }

        if let Some(vendor) = &self.vendor {
            fingerprint = fingerprint.with_vendor(&**vendor);
        }
        if let Some(version) = &self.version {
            fingerprint = fingerprint.with_generation(&**version);
        }
        if let Some(cpe) = &self.cpe {
            fingerprint.add_cpe(&**cpe);
        }
        if let Some(kernel) = &self.kernel {
            fingerprint = fingerprint.with_kernel(&**kernel);
        }
        if let Some(arch) = &self.arch {
            fingerprint = fingerprint.with_arch(&**arch);
        }
        if let Some(accuracy) = self.detail_accuracy {
            fingerprint = fingerprint.with_detail_accuracy(accuracy);
        }
        fingerprint
    }
}

/// Names the operating system behind `reply`, or nothing.
///
/// # How several matches are scored
///
/// Rules are overlapping claims:
///
/// - **One rule matched.** It scores its base worth times its weight.
/// - **Several matched and agree** on the identifying axes (family, device
///   class). The verdict keeps only the parts all of them agree on. The score
///   does not rise: rules written from the same measurements are one piece of
///   evidence.
/// - **Several matched and contradict** on family or device class. Reported as
///   nothing, since breaking the tie by weight would report an authoring
///   decision as a measurement.
///
/// A rule naming a family and one naming only a device class do not
/// contradict; the verdict carries both.
///
/// Returns `None` when no rule matched, when the matches contradict each other,
/// or when the result scores below [`MIN_REPORTABLE_ACCURACY`].
pub fn classify(db: &RuleDb, reply: &StackReply) -> Option<OsVerdict> {
    let matched: Vec<&OsDefinition> = db.matching(reply).collect();
    score(matched, reply.summary())
}

/// Names the operating system behind a host that was asked more than once.
///
/// The active counterpart of [`classify`]. Each reading is one reply paired with
/// its series classes; a host contributes one reading per kind of answer (a
/// SYN+ACK from an open port, a reset from a closed one). Rules are gathered
/// across all of them and scored together.
///
/// # One host, one verdict
///
/// All readings come from one stack, so the result is a single [`OsVerdict`];
/// several would be double-counted by [`resolve`](super::resolve)'s noisy-OR.
///
/// # Readings are kept apart
///
/// Resets and handshake answers come from different code paths (one host wrote
/// identifier zero on SYN+ACKs and a global counter on resets), so each reply
/// carries the series from replies of its own kind.
///
/// # Every reading is recorded
///
/// The evidence line includes every series, matched or not; the corpus has no
/// reset rules yet, and these readings are what one would be written from.
pub fn classify_series(db: &RuleDb, readings: &[(StackReply, SeriesClasses)]) -> Option<OsVerdict> {
    let matched: Vec<&OsDefinition> = readings
        .iter()
        .flat_map(|(reply, series)| db.matching_with_series(reply, series))
        .collect();

    let mut lines: Vec<String> = readings
        .iter()
        .map(|(reply, series)| format!("{} {}", reply.summary(), series.summary()))
        .collect();
    lines.sort_unstable();
    lines.dedup();

    score(matched, lines.join(" | "))
}

/// Two matched rules named one part differently.
///
/// Only stops the verdict on the two identifying axes; below them it is treated
/// as absence.
struct Contradiction;

/// The one value every rule that states `part` gives, or `None` where none
/// states it.
///
/// Silence abstains; dissent is an error. A family-level rule and a
/// version-level rule matching together are a refinement, not a disagreement.
fn consensus<'a>(
    matched: &[&'a OsDefinition],
    part: impl Fn(&'a OsDefinition) -> Option<&'a str>,
) -> Result<Option<String>, Contradiction> {
    let mut stated = matched.iter().copied().filter_map(part);
    let Some(candidate) = stated.next() else {
        return Ok(None);
    };
    match stated.all(|other| other == candidate) {
        true => Ok(Some(candidate.to_owned())),
        false => Err(Contradiction),
    }
}

/// Scores the rules that matched, whatever gathered them, into one verdict.
///
/// Shared by [`classify`] and [`classify_series`]. `evidence` is the rendered
/// line, since only the caller knows how many replies went into it.
fn score(matched: Vec<&OsDefinition>, evidence: String) -> Option<OsVerdict> {
    if matched.is_empty() {
        return None;
    }

    // The two identifying axes: dissent on either yields no verdict.
    let family = consensus(&matched, |rule| rule.os.family.as_deref()).ok()?;
    let device = consensus(&matched, |rule| rule.os.device.as_deref()).ok()?;
    if family.is_none() && device.is_none() {
        return None;
    }

    // Finer parts are kept where the rules that state them agree; otherwise
    // the part goes unreported.
    let agreed = |part: fn(&OsDefinition) -> Option<&str>| -> Option<String> {
        consensus(&matched, part).unwrap_or_default()
    };

    // The least confident match's weight.
    let weight = matched
        .iter()
        .map(|rule| rule.weight)
        .fold(f32::INFINITY, f32::min);

    // The least confident provenance, likewise.
    let base = if matched
        .iter()
        .all(|rule| rule.provenance == Provenance::Measured)
    {
        MEASURED_ACCURACY
    } else {
        PUBLISHED_ACCURACY
    };

    let accuracy = (base * weight).clamp(0.0, f32::from(MAX_STACK_ACCURACY)) as u8;
    if accuracy < MIN_REPORTABLE_ACCURACY {
        return None;
    }

    let (vendor, product, version, cpe) = (
        agreed(|rule| rule.os.vendor.as_deref()),
        agreed(|rule| rule.os.product.as_deref()),
        agreed(|rule| rule.os.version.as_deref()),
        agreed(|rule| rule.os.cpe.as_deref()),
    );

    Some(OsVerdict {
        family,
        device,
        // One rule asserts its whole identity, so the two figures are equal here;
        // they diverge only in `resolve`.
        detail_accuracy: (vendor.is_some()
            || product.is_some()
            || version.is_some()
            || cpe.is_some())
        .then_some(accuracy),
        vendor,
        product,
        version,
        // A handshake carries neither: one kernel build emits the same handshake
        // on every architecture.
        kernel: None,
        arch: None,
        cpe,
        accuracy,
        source: OsSource::TcpStack,
        evidence,
    })
}

/// Names the operating system behind a TCP reply, from bytes.
///
/// For a caller with a TCP segment and its IP header: builds the observation
/// and asks the shipped rules. Opens no socket.
pub fn classify_reply(
    ip: crate::model::capture::IpObservation,
    segment: &[u8],
) -> Option<OsVerdict> {
    let observed = StackObservation::from_tcp(ip, segment)?;
    classify(RuleDb::global(), &observed.into())
}

/// Names the operating system behind an echo reply, from bytes.
///
/// The counterpart of [`classify_reply`], for hosts with no open or closed
/// port. `sent_payload` is what the request carried.
pub fn classify_echo_reply(
    ip: crate::model::capture::IpObservation,
    message: &[u8],
    sent_payload: &[u8],
) -> Option<OsVerdict> {
    let observed = super::observation::EchoObservation::from_echo_reply(ip, message, sent_payload)?;
    classify(RuleDb::global(), &observed.into())
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
    use crate::model::capture::{IpObservation, Ipv4Observation};
    use crate::protocols::tcp::flags;

    /// The IP header a Linux host on this segment answered with.
    fn ip() -> IpObservation {
        IpObservation::V4(Ipv4Observation {
            ttl: 64,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            dscp: 0,
            ecn: 0,
        })
    }

    /// A TCP segment carrying `flags`, `window` and `options`, assembled from
    /// RFC 793 offsets rather than through this crate's own builder.
    fn segment(flag_byte: u8, window: u16, options: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 20 + options.len()];
        bytes[0..2].copy_from_slice(&80u16.to_be_bytes());
        bytes[2..4].copy_from_slice(&50_000u16.to_be_bytes());
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        bytes[12] = (((20 + options.len()) / 4) as u8) << 4;
        bytes[13] = flag_byte;
        bytes[14..16].copy_from_slice(&window.to_be_bytes());
        bytes[20..].copy_from_slice(options);
        bytes
    }

    /// The option bytes a single-board computer running Debian bookworm on
    /// kernel 6.12.47 answered a negotiating SYN with, recorded off the wire on
    /// 2026-08-18.
    const DEBIAN_BOOKWORM: [u8; 20] = [
        0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xad, 0x58, 0xa5, 0xa7, 0x64, 0x48, 0x96,
        0x12, 0x01, 0x03, 0x03, 0x07,
    ];

    /// From the bytes a real host of known operating system sent, to a name.
    #[test]
    fn a_recorded_linux_reply_is_named_linux() {
        let verdict = classify_reply(
            ip(),
            &segment(flags::SYN | flags::ACK, 65_160, &DEBIAN_BOOKWORM),
        )
        .expect("a labelled Linux host is identified");

        assert_eq!(verdict.family.as_deref(), Some("Linux"));
        assert_eq!(verdict.source, OsSource::TcpStack);

        let fingerprint = verdict.to_fingerprint();
        assert_eq!(fingerprint.name(), "Linux");
        assert_eq!(fingerprint.family(), Some("Linux"));
    }

    /// The weight bound is where the knob stops turning.
    ///
    /// Accuracy is base worth times weight, clamped at [`MAX_STACK_ACCURACY`];
    /// past the clamp, larger weights change nothing. Fails if the bound rises
    /// past where the arithmetic saturates.
    #[test]
    fn the_weight_bound_leaves_no_dead_range() {
        use super::super::MAX_RULE_WEIGHT;

        let saturates_at = f32::from(MAX_STACK_ACCURACY) / MEASURED_ACCURACY;
        assert!(
            saturates_at < MAX_RULE_WEIGHT,
            "a measured rule saturates at {saturates_at}, which is at or above the \
             bound of {MAX_RULE_WEIGHT}, so no weight reaches the ceiling"
        );

        // Not so far above that most of the range is inert.
        assert!(
            MAX_RULE_WEIGHT < saturates_at * 2.0,
            "weights from {saturates_at} to {MAX_RULE_WEIGHT} all produce the same \
             answer, so most of the range an author can reach for does nothing"
        );
    }

    /// One packet cannot reach the high-confidence threshold.
    #[test]
    fn stack_evidence_alone_never_reaches_high_confidence() {
        let verdict = classify_reply(
            ip(),
            &segment(flags::SYN | flags::ACK, 65_160, &DEBIAN_BOOKWORM),
        )
        .expect("a labelled Linux host is identified");

        assert!(verdict.accuracy <= MAX_STACK_ACCURACY);
        assert!(
            !verdict.to_fingerprint().is_highly_confident(),
            "one reply's shape is one observation, however many of its fields agree"
        );
    }

    /// An unknown host gets no answer rather than a guess.
    #[test]
    fn a_shape_no_rule_describes_is_reported_as_nothing() {
        // An option layout nothing emits: an MSS, an unknown kind, and padding.
        // The layout, not the window, since a tuned window is still Linux (see
        // the next test).
        let nothing_emits = [2, 4, 0x05, 0xb4, 99, 2, 1, 1];
        let verdict = classify_reply(
            ip(),
            &segment(flags::SYN | flags::ACK, 65_160, &nothing_emits),
        );
        assert!(verdict.is_none());
    }

    /// A tuned host still matches.
    ///
    /// Measured 2026-08-21: `sysctl -w net.ipv4.tcp_rmem=...` moves a Debian
    /// guest's window and window scale together. The hop counter, option layout
    /// and the two named capabilities survive tuning, and are what the rule tests.
    #[test]
    fn a_linux_host_with_tuned_receive_buffers_is_still_linux() {
        for window in [12_345u16, 29_200, 64_240, 65_160] {
            let verdict = classify_reply(
                ip(),
                &segment(flags::SYN | flags::ACK, window, &DEBIAN_BOOKWORM),
            )
            .unwrap_or_else(|| panic!("a Linux handshake advertising {window} names nothing"));
            assert_eq!(verdict.family.as_deref(), Some("Linux"));
        }
    }

    /// A distribution is named by its distribution, not by its kernel.
    ///
    /// 993 imported rules write a distribution as `vendor = "Debian"`,
    /// `product = "Linux"`, `family = "Linux"`.
    #[test]
    fn a_distribution_is_named_by_its_distribution() {
        let verdict = OsVerdict {
            family: Some("Linux".to_owned()),
            device: None,
            vendor: Some("Debian".to_owned()),
            product: Some("Linux".to_owned()),
            version: Some("12".to_owned()),
            kernel: None,
            arch: None,
            cpe: None,
            accuracy: 84,
            detail_accuracy: Some(55),
            source: OsSource::ServiceBanner,
            evidence: "service banner names Linux".to_owned(),
        };

        let fingerprint = verdict.to_fingerprint();
        assert_eq!(fingerprint.name(), "Debian");
        assert_eq!(fingerprint.family(), Some("Linux"));
        assert_eq!(
            fingerprint.to_string(),
            "Linux [84%] · Debian 12 [55%]",
            "the family carries what several sources agreed; the release carries \
             what the one source that named it was worth"
        );
    }

    /// With a device class the label is maker and model: `Brother NC-8700w`.
    #[test]
    fn a_model_number_is_labelled_with_the_maker_that_built_it() {
        let verdict = OsVerdict {
            family: Some("Network device".to_owned()),
            device: Some("Printer".to_owned()),
            vendor: Some("Brother".to_owned()),
            product: Some("NC-8700w".to_owned()),
            version: Some("ZL".to_owned()),
            kernel: None,
            arch: None,
            cpe: None,
            accuracy: 40,
            detail_accuracy: Some(56),
            source: OsSource::SnmpAgent,
            evidence: "snmp agent names NC-8700w".to_owned(),
        };

        let fingerprint = verdict.to_fingerprint();
        assert_eq!(fingerprint.name(), "Brother NC-8700w");
        assert_eq!(fingerprint.device(), Some("Printer"));
        assert_eq!(fingerprint.family(), Some("Network device"));

        // Not twice where the model already includes the maker.
        let spelled_out = OsVerdict {
            product: Some("Brother HL-1660e".to_owned()),
            ..verdict
        };
        assert_eq!(spelled_out.label(), "Brother HL-1660e");
    }

    /// A verdict with no family still has a label.
    #[test]
    fn a_verdict_without_a_family_is_still_named() {
        let verdict = OsVerdict {
            family: None,
            device: Some("Printer".to_owned()),
            vendor: Some("Brother".to_owned()),
            product: Some("NC-8700w".to_owned()),
            version: Some("ZL".to_owned()),
            kernel: None,
            arch: None,
            cpe: None,
            accuracy: 56,
            detail_accuracy: Some(56),
            source: OsSource::SnmpAgent,
            evidence: "snmp agent names NC-8700w".to_owned(),
        };

        let fingerprint = verdict.to_fingerprint();
        assert_eq!(fingerprint.name(), "Brother NC-8700w");
        assert_eq!(fingerprint.family(), None);
    }

    /// With no product, `Microsoft` + `Windows` (seventeen rules) stays `Windows`.
    #[test]
    fn a_vendor_without_a_product_does_not_replace_the_family() {
        let verdict = OsVerdict {
            family: Some("Windows".to_owned()),
            device: None,
            vendor: Some("Microsoft".to_owned()),
            product: None,
            version: Some("10".to_owned()),
            kernel: None,
            arch: None,
            cpe: None,
            accuracy: 60,
            detail_accuracy: Some(60),
            source: OsSource::ServiceBanner,
            evidence: "service banner names Windows".to_owned(),
        };

        assert_eq!(verdict.to_fingerprint().name(), "Windows");
    }

    /// The corpus holds no rule for a reset, so a reset names nothing.
    #[test]
    fn a_reset_names_nothing() {
        assert!(classify_reply(ip(), &segment(flags::RST | flags::ACK, 0, &[])).is_none());
    }

    /// Two rules disagreeing on the family yield no verdict.
    #[test]
    fn rules_that_contradict_each_other_name_nothing() {
        use super::super::signature::{
            MatchRule, OsDefinition, OsIdentity, Predicate, Provenance, ReplyKind,
        };

        let rule = |family: &str| OsDefinition {
            os: OsIdentity {
                family: Some(family.to_string()),
                device: None,
                vendor: None,
                product: None,
                version: None,
                cpe: None,
            },
            provenance: Provenance::Measured,
            notes: None,
            weight: 1.0,
            r#match: MatchRule {
                reply: ReplyKind::SynAck,
                initial_hops: Some(Predicate {
                    equals: Some(64),
                    ..Default::default()
                }),
                ..Default::default()
            },
            example: Vec::new(),
        };

        let db = RuleDb::try_from_rules(vec![rule("Linux"), rule("Windows")])
            .expect("the rules are well formed");
        let observed = StackObservation::from_tcp(
            ip(),
            &segment(flags::SYN | flags::ACK, 65_160, &DEBIAN_BOOKWORM),
        )
        .unwrap()
        .into();

        assert_eq!(db.matching(&observed).count(), 2, "both rules match");
        assert!(
            classify(&db, &observed).is_none(),
            "and the contradiction is reported as no answer, not as the heavier rule"
        );
    }
}

#[cfg(test)]
mod second_family {
    use super::*;
    use crate::model::capture::{IpObservation, Ipv4Observation};
    use crate::protocols::tcp::flags;

    /// The options a Mac answered with, rebuilt from the values measured off it:
    /// maximum segment size 1460, no-op, window scale 6, two no-ops, a
    /// timestamp, SACK-permitted, and the trailing end-of-list that no other
    /// family in the corpus writes.
    fn darwin_options() -> Vec<u8> {
        let mut options = vec![2, 4, 0x05, 0xb4]; // MSS 1460
        options.push(1); // NOP
        options.extend_from_slice(&[3, 3, 6]); // window scale 6
        options.push(1); // NOP
        options.push(1); // NOP
        options.extend_from_slice(&[8, 10]); // timestamp
        options.extend_from_slice(&0x1122_3344u32.to_be_bytes());
        options.extend_from_slice(&0x5566_7788u32.to_be_bytes());
        options.extend_from_slice(&[4, 2]); // SACK permitted
        options.push(0); // end of list
        options.push(0); // padding to a four-byte boundary
        options
    }

    fn segment(flag_byte: u8, window: u16, options: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 20 + options.len()];
        bytes[0..2].copy_from_slice(&22u16.to_be_bytes());
        bytes[2..4].copy_from_slice(&50_000u16.to_be_bytes());
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        bytes[12] = (((20 + options.len()) / 4) as u8) << 4;
        bytes[13] = flag_byte;
        bytes[14..16].copy_from_slice(&window.to_be_bytes());
        bytes[20..].copy_from_slice(options);
        bytes
    }

    fn ip() -> IpObservation {
        IpObservation::V4(Ipv4Observation {
            ttl: 64,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            dscp: 0,
            ecn: 0,
        })
    }

    /// A second hardware-confirmed family keeps the Linux rules falsifiable.
    /// Darwin shares Linux's hop counter; the option order separates them.
    #[tokio::test(flavor = "current_thread")]
    async fn a_measured_darwin_reply_is_named_macos_and_not_linux() {
        let observed = classify_reply(
            ip(),
            &segment(flags::SYN | flags::ACK, 65_535, &darwin_options()),
        )
        .expect("a labelled Mac is identified");

        assert_eq!(observed.family.as_deref(), Some("macOS"));
        assert_eq!(observed.vendor.as_deref(), Some("Apple"));

        // Hardware-confirmed: a measured rule.
        assert_eq!(observed.accuracy, MEASURED_ACCURACY as u8);
    }

    /// Linux counts its window in segments; Darwin announces the field's maximum
    /// whatever the path.
    #[test]
    fn a_flat_window_is_not_read_as_a_multiple() {
        let observed = StackObservation::from_tcp(
            ip(),
            &segment(flags::SYN | flags::ACK, 65_535, &darwin_options()),
        )
        .expect("the reply parses");

        assert_eq!(observed.window, 65_535);
        assert_eq!(observed.effective_mss(), Some(1448));
        assert_eq!(
            observed.window_in_units(),
            Some((45, 375)),
            "the derived figures exist, and describe the path rather than the sender"
        );
    }
}

#[cfg(test)]
mod series_backed {
    use super::*;
    use crate::fingerprint::os::series::{ClockClass, IdClass, IsnClass};
    use crate::model::capture::{IpObservation, Ipv4Observation};
    use crate::protocols::tcp::flags;

    use super::super::signature::{MatchRule, OsIdentity, Predicate, ReplyKind};

    fn ip() -> IpObservation {
        IpObservation::V4(Ipv4Observation {
            ttl: 64,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            dscp: 0,
            ecn: 0,
        })
    }

    /// A handshake answer, assembled from RFC 793's offsets.
    fn syn_ack() -> StackReply {
        let mut bytes = vec![0u8; 20];
        bytes[0..2].copy_from_slice(&22u16.to_be_bytes());
        bytes[2..4].copy_from_slice(&50_000u16.to_be_bytes());
        bytes[12] = 5 << 4;
        bytes[13] = flags::SYN | flags::ACK;
        bytes[14..16].copy_from_slice(&64_240u16.to_be_bytes());
        StackObservation::from_tcp(ip(), &bytes)
            .expect("a handshake answer")
            .into()
    }

    /// What several replies from a stack with a hashed generator look like once
    /// classified.
    fn hashed() -> SeriesClasses {
        SeriesClasses {
            identifiers: IdClass::Zero,
            sequences: IsnClass::Hashed,
            clock: ClockClass::Hertz(1000),
        }
    }

    /// An identity naming a family, and a release where the rule reaches one.
    ///
    /// `OsDefinition::validate` refuses a version without a product.
    fn named(family: &str, version: Option<&str>) -> OsIdentity {
        OsIdentity {
            family: Some(family.to_owned()),
            device: None,
            vendor: None,
            product: version.map(|_| "Debian".to_owned()),
            version: version.map(str::to_owned),
            cpe: None,
        }
    }

    fn rule(os: OsIdentity, r#match: MatchRule) -> OsDefinition {
        OsDefinition {
            os,
            provenance: Provenance::Measured,
            notes: None,
            weight: 1.0,
            r#match,
            example: Vec::new(),
        }
    }

    /// A predicate over the hop counter, which every rule here shares so that
    /// the series predicate is the only thing separating them.
    fn at_64() -> Option<Predicate<u8>> {
        Some(Predicate {
            equals: Some(64),
            ..Default::default()
        })
    }

    fn is(name: &str) -> Option<Predicate<String>> {
        Some(Predicate {
            equals: Some(name.to_owned()),
            ..Default::default()
        })
    }

    /// A series predicate cannot be satisfied by a single reply.
    #[test]
    fn a_series_rule_cannot_be_satisfied_by_one_reply() {
        let db = RuleDb::try_from_rules(vec![rule(
            named("Linux", Some("6.x")),
            MatchRule {
                reply: ReplyKind::SynAck,
                initial_hops: at_64(),
                sequence_class: is("hashed"),
                ..Default::default()
            },
        )])
        .expect("the rules are well formed");
        let reply = syn_ack();

        assert!(
            classify(&db, &reply).is_none(),
            "the passive path has no series, so a series rule must fail against it"
        );

        let verdict = classify_series(&db, &[(reply, hashed())])
            .expect("the same rule matches once the series is known");
        assert_eq!(verdict.family.as_deref(), Some("Linux"));
        assert_eq!(verdict.version.as_deref(), Some("6.x"));
    }

    /// The reason a version-level rule can exist at all.
    ///
    /// A release rule and its family rule both match; the family rule's silence
    /// on the version is not dissent.
    #[test]
    fn a_broader_rule_matching_beside_a_finer_one_does_not_erase_the_version() {
        let db = RuleDb::try_from_rules(vec![
            rule(
                named("Linux", None),
                MatchRule {
                    reply: ReplyKind::SynAck,
                    initial_hops: at_64(),
                    ..Default::default()
                },
            ),
            rule(
                named("Linux", Some("6.x")),
                MatchRule {
                    reply: ReplyKind::SynAck,
                    initial_hops: at_64(),
                    sequence_class: is("hashed"),
                    ..Default::default()
                },
            ),
        ])
        .expect("the rules are well formed");

        let reply = syn_ack();
        assert_eq!(
            db.matching_with_series(&reply, &hashed()).count(),
            2,
            "both rules describe this host"
        );

        let verdict =
            classify_series(&db, &[(reply, hashed())]).expect("a host both rules describe");
        assert_eq!(verdict.family.as_deref(), Some("Linux"));
        assert_eq!(
            verdict.version.as_deref(),
            Some("6.x"),
            "the finer rule states a version and the broader one abstains"
        );
    }

    /// Two rules naming different releases leave the release unreported.
    #[test]
    fn two_rules_naming_different_versions_keep_neither() {
        let with_version = |version: &str, class: &str| {
            rule(
                named("Linux", Some(version)),
                MatchRule {
                    reply: ReplyKind::SynAck,
                    initial_hops: at_64(),
                    sequence_class: is(class),
                    ..Default::default()
                },
            )
        };
        let db = RuleDb::try_from_rules(vec![
            with_version("6.x", "hashed"),
            with_version("7.x", "hashed"),
        ])
        .expect("the rules are well formed");

        let verdict = classify_series(&db, &[(syn_ack(), hashed())]).expect("the family is agreed");
        assert_eq!(verdict.family.as_deref(), Some("Linux"));
        assert!(
            verdict.version.is_none(),
            "a contradiction about the release is not a release"
        );
    }

    /// Several replies from one host yield one verdict.
    #[test]
    fn a_host_read_several_ways_still_yields_one_verdict() {
        let db = RuleDb::try_from_rules(vec![rule(
            named("Linux", None),
            MatchRule {
                reply: ReplyKind::SynAck,
                initial_hops: at_64(),
                ..Default::default()
            },
        )])
        .expect("the rules are well formed");

        let one = classify_series(&db, &[(syn_ack(), hashed())]).expect("one reading names it");
        let twice = classify_series(&db, &[(syn_ack(), hashed()), (syn_ack(), hashed())])
            .expect("two readings still name it");

        assert_eq!(one.family, twice.family);
        assert_eq!(
            one.accuracy, twice.accuracy,
            "reading one stack twice is not two pieces of evidence"
        );
    }
}
