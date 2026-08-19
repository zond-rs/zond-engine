// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Turning matched rules into an answer
//!
//! [`classify`] takes an observation, asks the rule database about it, and
//! returns what can honestly be said — which is sometimes nothing.
//!
//! ## One packet is one piece of evidence, not nine
//!
//! The hop counter, the window, the option layout and the window scale of a
//! single reply are not independent. They are consequences of one stack build,
//! chosen together by one set of authors, and a host that has one of them
//! usually has all of them. Scoring each as a separate vote triple-counts a
//! single observation and manufactures confidence out of nothing.
//!
//! So a whole observation is matched jointly against a rule and yields **one**
//! result. Independence is claimed only *between* genuinely different sources —
//! a stack, a service banner, a hardware address, a DHCP option — where it is
//! close enough to true to build on. That is phase 5's work and this module is
//! shaped to receive it: [`OsVerdict`] carries a source and a confidence rather
//! than a bare name.
//!
//! ## Why the ceiling is where it is
//!
//! [`MAX_STACK_ACCURACY`] caps what this evidence alone may claim, and it sits
//! deliberately below the 85 that
//! [`OsFingerprint::is_highly_confident`](crate::model::host::OsFingerprint::is_highly_confident)
//! reads. That threshold is what a caller uses to decide whether to stop and
//! accept an answer or send something more intrusive, so a number reachable from
//! one correlated packet would make it meaningless — every host with an open
//! port would look settled and no further probe would ever be justified.
//!
//! Reaching high confidence has to take corroboration from a second, genuinely
//! independent source. Today there is none, so nothing this module produces is
//! highly confident, and that is the honest state of the evidence rather than a
//! placeholder.
//!
//! ## Nothing is a valid answer
//!
//! Below [`MIN_REPORTABLE_ACCURACY`] this reports no operating system at all. A
//! wrong confident answer costs more than a missing one: a scan that says
//! nothing invites a second look, and one that says "Linux" about a Windows host
//! is believed. nmap's aggressive-guess mode is a wart, not a feature to copy.

use crate::model::host::OsFingerprint;

use super::db::RuleDb;
use super::observation::{StackObservation, StackReply};
use super::signature::{OsDefinition, Provenance};

/// The most a single reply's stack shape may claim on its own.
///
/// Below the 85 that marks high confidence, and for the reason given in the
/// module documentation: one packet's fields are one observation however many
/// of them agree.
pub const MAX_STACK_ACCURACY: u8 = 70;

/// The least a finding may score and still be reported.
///
/// Under this, [`classify`] yields nothing rather than the least bad guess.
pub const MIN_REPORTABLE_ACCURACY: u8 = 40;

/// What a rule measured by this engine is worth before its own weight applies.
///
/// A rule that matched said everything it tests is true of this host. What it
/// does *not* establish is that no other rule would have said the same, which is
/// why several matches do not raise the score — see [`classify`].
const MEASURED_ACCURACY: f32 = 65.0;

/// What a rule taken from published stack characteristics is worth.
///
/// Lower, and not because published defaults are unreliable — an initial hop
/// counter and an option order are ordinary engineering facts. Lower because the
/// rule has not been seen *through this engine's own probe on a real network*,
/// which is the gap that has already caught this project out once: option
/// negotiation is reciprocal, so a documented layout is documented against some
/// probe, and against a different one it is wrong while looking right.
///
/// Above [`MIN_REPORTABLE_ACCURACY`], so such a rule reports rather than hides —
/// a plausible answer that says how sure it is beats no answer. Confirming one
/// on real hardware is what promotes it.
const PUBLISHED_ACCURACY: f32 = 50.0;

/// Which evidence produced a verdict.
///
/// One variant today. It exists so that phase 5's sources arrive as variants
/// rather than as a rewrite, and so a report can say *why* a host was named
/// rather than only what it was named.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsSource {
    /// The shape of a single TCP reply.
    TcpStack,
    /// The vendor a host's hardware address is registered to.
    HardwareVendor,
    /// Text a service volunteered about the system it runs on.
    ServiceBanner,
}

/// What the rules concluded about one observation.
#[derive(Debug, Clone, PartialEq)]
pub struct OsVerdict {
    /// The identity, most specific part first in the sense that `family` is
    /// always present and the rest are filled in only where a rule supported
    /// them.
    pub family: String,
    /// The vendor, where a rule named one.
    pub vendor: Option<String>,
    /// The product, where a rule named one.
    pub product: Option<String>,
    /// The version, where a rule named one.
    pub version: Option<String>,
    /// A Common Platform Enumeration identifier, where a rule named one.
    pub cpe: Option<String>,
    /// How sure this is, on the `0..=100` scale
    /// [`OsFingerprint`] uses. Bounded by [`MAX_STACK_ACCURACY`].
    pub accuracy: u8,
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
    /// The accuracy becomes a probability, because that is the scale the
    /// combining arithmetic works on — a percentage summed against another
    /// percentage means nothing, where two probabilities for one hypothesis
    /// combine exactly.
    ///
    /// A whole reply is one item, never one per field. Its hop counter, window
    /// and option layout are consequences of one stack build and agree by
    /// construction; scoring them apart would count a single observation several
    /// times over and manufacture confidence out of nothing.
    pub fn as_evidence(&self) -> super::evidence::OsEvidence {
        super::evidence::OsEvidence {
            source: self.source,
            family: self.family.clone(),
            vendor: self.vendor.clone(),
            product: self.product.clone(),
            version: self.version.clone(),
            cpe: self.cpe.clone(),
            confidence: f32::from(self.accuracy) / 100.0,
            evidence: self.evidence.clone(),
        }
    }

    /// Projects onto the model's [`OsFingerprint`].
    ///
    /// The name is the most specific thing the rules supported: a product where
    /// one was named, the family otherwise. `OsFingerprint` ranks findings from
    /// different techniques by accuracy and fills gaps on a tie, so what is
    /// handed over here needs to be honest about how much it knows rather than
    /// as specific as possible.
    pub fn to_fingerprint(&self) -> OsFingerprint {
        let name = self.product.clone().unwrap_or_else(|| self.family.clone());
        let mut fingerprint = OsFingerprint::new(name, self.accuracy)
            .with_family(&*self.family)
            .with_evidence(&*self.evidence);

        if let Some(vendor) = &self.vendor {
            fingerprint = fingerprint.with_vendor(&**vendor);
        }
        if let Some(version) = &self.version {
            fingerprint = fingerprint.with_generation(&**version);
        }
        if let Some(cpe) = &self.cpe {
            fingerprint.add_cpe(&**cpe);
        }
        fingerprint
    }
}

/// Names the operating system behind `reply`, or nothing.
///
/// # How several matches are scored
///
/// Rules are not alternatives to be ranked; they are claims that overlap. Three
/// outcomes, and the middle one is the one worth explaining:
///
/// - **One rule matched.** It is the only thing that describes this host, and it
///   scores its base worth times its own weight.
/// - **Several matched and agree on the family.** They corroborate at the family
///   level and disagree, or say nothing, below it. The verdict is the family they
///   share, and it keeps only the finer parts *all* of them agree on — which is
///   usually none. The score does not rise for the agreement: two rules written
///   from the same measurements are not two pieces of evidence.
/// - **Several matched and disagree on the family.** The rules cannot both be
///   right and nothing here can say which is. Reported as nothing, deliberately:
///   a tie broken by weight would be reporting an authoring decision as a
///   measurement.
///
/// Returns `None` when no rule matched, when the matches contradict each other,
/// or when the result scores below [`MIN_REPORTABLE_ACCURACY`].
pub fn classify(db: &RuleDb, reply: &StackReply) -> Option<OsVerdict> {
    let matched: Vec<&OsDefinition> = db.matching(reply).collect();
    let (first, rest) = matched.split_first()?;

    // A family the matches do not share is a contradiction, not a ranking.
    if rest.iter().any(|rule| rule.os.family != first.os.family) {
        return None;
    }

    // Keep only the finer parts every match agrees on. `agreed` is `None` as
    // soon as any rule differs, including when one names a part and another
    // leaves it empty — "Ubuntu" and "unspecified" are not agreement.
    let agreed = |part: fn(&OsDefinition) -> &Option<String>| -> Option<String> {
        let candidate = part(first).as_ref()?;
        rest.iter()
            .all(|rule| part(rule).as_deref() == Some(candidate.as_str()))
            .then(|| candidate.clone())
    };

    // The weight of the least confident match, not the most: a set of rules is
    // only as good as its weakest member when they are all claiming the same
    // thing.
    let weight = matched
        .iter()
        .map(|rule| rule.weight)
        .fold(f32::INFINITY, f32::min);

    // The least confident provenance among the matches, for the same reason as
    // the weight: a set of rules claiming one thing is only as good as its
    // weakest member.
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

    Some(OsVerdict {
        family: first.os.family.clone(),
        vendor: agreed(|rule| &rule.os.vendor),
        product: agreed(|rule| &rule.os.product),
        version: agreed(|rule| &rule.os.version),
        cpe: agreed(|rule| &rule.os.cpe),
        accuracy,
        source: OsSource::TcpStack,
        evidence: reply.summary(),
    })
}

/// Names the operating system behind a TCP reply, from bytes.
///
/// The whole path in one call, for a caller who has a TCP segment and what its
/// IP header said: build the observation, ask the shipped rules, return what can
/// be said. Nothing here opens a socket or touches the scanner.
pub fn classify_reply(
    ip: crate::model::capture::IpObservation,
    segment: &[u8],
) -> Option<OsVerdict> {
    let observed = StackObservation::from_tcp(ip, segment)?;
    classify(RuleDb::global(), &observed.into())
}

/// Names the operating system behind an echo reply, from bytes.
///
/// The counterpart of [`classify_reply`] for the reply a host with no open and
/// no closed port can still give. `sent_payload` is what the request carried,
/// which is the only way to know whether what came back is what went out.
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

    /// The whole path, from the bytes a real labelled host sent to a name. This
    /// is the claim phase 4 makes, and the machine it is made about is one whose
    /// operating system is known independently of anything the engine says.
    #[test]
    fn a_recorded_linux_reply_is_named_linux() {
        let verdict = classify_reply(
            ip(),
            &segment(flags::SYN | flags::ACK, 65_160, &DEBIAN_BOOKWORM),
        )
        .expect("a labelled Linux host is identified");

        assert_eq!(verdict.family, "Linux");
        assert_eq!(verdict.source, OsSource::TcpStack);

        let fingerprint = verdict.to_fingerprint();
        assert_eq!(fingerprint.name(), "Linux");
        assert_eq!(fingerprint.family(), Some("Linux"));
    }

    /// The ceiling exists so that one correlated packet cannot satisfy the
    /// threshold a caller uses to stop probing. If stack evidence alone could
    /// reach high confidence, every host with an open port would look settled and
    /// no further probe would ever be justified.
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

    /// Silence about an unknown host beats a confident wrong answer: a scan that
    /// reports nothing invites a second look, and one that reports "Linux" about
    /// a Windows machine is believed.
    #[test]
    fn a_shape_no_rule_describes_is_reported_as_nothing() {
        // A plausible handshake that no measured host produced: the right layout
        // with a window belonging to neither shape in the corpus.
        let verdict = classify_reply(
            ip(),
            &segment(flags::SYN | flags::ACK, 12_345, &DEBIAN_BOOKWORM),
        );
        assert!(verdict.is_none());
    }

    /// A reset carries no options at all, and the corpus holds no rule written
    /// for one. Naming a host from a reset would mean matching a rule against a
    /// segment it was never written for.
    #[test]
    fn a_reset_names_nothing() {
        assert!(classify_reply(ip(), &segment(flags::RST | flags::ACK, 0, &[])).is_none());
    }

    /// Two rules that disagree about the family cannot both be right, and nothing
    /// in one reply can say which is. Breaking the tie by weight would report an
    /// authoring decision as a measurement.
    #[test]
    fn rules_that_contradict_each_other_name_nothing() {
        use super::super::signature::{
            MatchRule, OsDefinition, OsIdentity, Predicate, Provenance, ReplyKind,
        };

        let rule = |family: &str| OsDefinition {
            os: OsIdentity {
                family: family.to_string(),
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

        let db = RuleDb::from_rules(vec![rule("Linux"), rule("Windows")]);
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

    /// The corpus now holds a second family confirmed on hardware, which is what
    /// makes the Linux rules falsifiable: until there was something else for a
    /// reply to be named, "everything is Linux" and "the rules work" produced the
    /// same output.
    ///
    /// Darwin shares its hop counter with Linux, so nothing in the IP header
    /// separates them. The option order does, in every position.
    #[tokio::test(flavor = "current_thread")]
    async fn a_measured_darwin_reply_is_named_macos_and_not_linux() {
        let observed = classify_reply(
            ip(),
            &segment(flags::SYN | flags::ACK, 65_535, &darwin_options()),
        )
        .expect("a labelled Mac is identified");

        assert_eq!(observed.family, "macOS");
        assert_eq!(observed.vendor.as_deref(), Some("Apple"));

        // Confirmed against hardware, so it scores as a measured rule rather
        // than a published one.
        assert_eq!(observed.accuracy, MEASURED_ACCURACY as u8);
    }

    /// The window is where the two families differ in kind rather than in value.
    /// Linux counts its window in segments; Darwin announces the largest number
    /// the field holds, whatever the path. A rule that read the second as though
    /// it were the first would match one network and not the next.
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
