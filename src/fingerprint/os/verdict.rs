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
use crate::model::host::{OsEvidence, OsSource};

use super::db::RuleDb;
use super::observation::{StackObservation, StackReply};
use super::series::SeriesClasses;
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

/// What the rules concluded about one observation.
#[derive(Debug, Clone, PartialEq)]
pub struct OsVerdict {
    /// The broad family, where anything could name one.
    ///
    /// `None` where every source abstained — a host identified down to its make
    /// and model by an agent that never said what it runs. See
    /// [`OsEvidence::family`](crate::model::host::OsEvidence::family).
    pub family: Option<String>,
    /// What kind of box this is, where a source said: `Printer`, `Switch`,
    /// `Router`. Orthogonal to the family, never a substitute for it.
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
    /// Beside [`version`](Self::version) rather than instead of it: a
    /// distribution release and the kernel it ships are two facts about one
    /// machine, and a source that knows one may know nothing of the other.
    pub kernel: Option<String>,
    /// How sure this is, on the `0..=100` scale
    /// [`OsFingerprint`] uses. Bounded by [`MAX_STACK_ACCURACY`].
    ///
    /// **About the family**, which is the part every source can speak to.
    pub accuracy: u8,
    /// How sure the parts *past* the family are, where this names any.
    ///
    /// Separate because they are usually attested differently: a stack reading
    /// and a banner may agree that a host is Linux while only the banner can say
    /// which release, and one figure for both would report the weaker claim at
    /// the stronger claim's strength. `None` where nothing finer than a family
    /// was named.
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
    /// The accuracy becomes a probability, because that is the scale the
    /// combining arithmetic works on — a percentage summed against another
    /// percentage means nothing, where two probabilities for one hypothesis
    /// combine exactly.
    ///
    /// A whole reply is one item, never one per field. Its hop counter, window
    /// and option layout are consequences of one stack build and agree by
    /// construction; scoring them apart would count a single observation several
    /// times over and manufacture confidence out of nothing.
    pub fn as_evidence(&self) -> OsEvidence {
        OsEvidence {
            source: self.source,
            family: self.family.clone(),
            device: self.device.clone(),
            vendor: self.vendor.clone(),
            product: self.product.clone(),
            version: self.version.clone(),
            kernel: self.kernel.clone(),
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
        // A corpus that sets `product` to the family name is *declining* to name
        // a product, and for a Linux distribution it puts the distribution in
        // `vendor` — 993 shipped rules are written that way, which is why a host
        // running Debian 12 was reported as `Linux 12.0`: a version number no
        // Linux has ever had, attached to the wrong noun.
        //
        // A rule with **no** product at all is a different case and must not be
        // read the same way. There, `vendor` is often the maker of a device
        // rather than the publisher of an operating system — Ubiquiti, AXIS,
        // Crestron — and seventeen rules pair `Microsoft` with `Windows`, which
        // this would otherwise render as `Microsoft 10`. Those keep the family.
        match (&self.product, &self.vendor) {
            (Some(product), Some(vendor)) if Some(product.as_str()) == self.family.as_deref() => {
                vendor.clone()
            }
            // A device class means the product is a model number, and a model
            // number without its maker names nothing a reader can look up:
            // `NC-8700w` is a string, `Brother NC-8700w` is a printer.
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
    /// `OsFingerprint` ranks findings from different techniques by accuracy and
    /// fills gaps on a tie, so what is handed over here needs to be honest about
    /// how much it knows rather than as specific as possible.
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
    score(matched, reply.summary())
}

/// Names the operating system behind a host that was asked more than once.
///
/// The active counterpart of [`classify`]. Each reading is one reply paired with
/// what the series it belongs to turned out to be, and a host contributes as
/// many readings as it gave distinct kinds of answer — a SYN+ACK from an open
/// port, a reset from a closed one. Rules are gathered across all of them and
/// scored together.
///
/// # One host is one piece of evidence, however many packets it took
///
/// Every reading here came from one stack, so they are not independent and the
/// result is a single [`OsVerdict`] rather than one per reply. Returning several
/// would put them through [`resolve`](super::resolve)'s noisy-OR as though a
/// machine agreeing with itself were two sources agreeing with each other, which
/// is the same double-count [`classify`] avoids within a single reply.
///
/// # Why the readings are kept apart rather than pooled
///
/// A stack's resets and its handshake answers come from different code paths
/// that disagree about the same fields — measured, on one host: identifier zero
/// on the SYN+ACK path and a global counter on the reset path. So each reply
/// carries the series read from replies of *its own kind*, and a rule sees the
/// classes belonging to the segment it declares. Pooling them would compare a
/// host against itself under two policies at once.
///
/// # Every reading is recorded, including the ones nothing matched
///
/// The evidence line carries what each series turned out to be whether or not a
/// rule read it. That is deliberate and it is most of this function's value
/// today: the corpus holds no rule written for a reset, so a host's reset series
/// currently names nothing — and it is precisely the measurement somebody needs
/// in front of them to write the first one. A reading dropped for matching
/// nothing is a reading nobody can author from.
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

/// Scores the rules that matched, whatever gathered them, into one verdict.
///
/// The half [`classify`] and [`classify_series`] share: they differ in which
/// rules they ask about and what the resulting line says, and agree on
/// everything after. `evidence` is that line, already rendered, because only the
/// caller knows how many replies went into it.
fn score(matched: Vec<&OsDefinition>, evidence: String) -> Option<OsVerdict> {
    let (first, rest) = matched.split_first()?;

    // A family the matches do not share is a contradiction, not a ranking.
    if rest.iter().any(|rule| rule.os.family != first.os.family) {
        return None;
    }

    // Keep the finer parts of the path, where the rules that spoke to them
    // agree. A rule that leaves a part empty **abstains** rather than dissents:
    // a family-level rule and a version-level one that both matched are a
    // refinement, not a contradiction, and treating silence as disagreement
    // would mean every version a rule can name is erased by the broader rule
    // that necessarily matched beside it. Two rules naming *different* values is
    // still a contradiction and still yields nothing.
    let agreed = |part: fn(&OsDefinition) -> &Option<String>| -> Option<String> {
        let mut stated = matched.iter().filter_map(|rule| part(rule).as_deref());
        let candidate = stated.next()?;
        stated
            .all(|other| other == candidate)
            .then(|| candidate.to_owned())
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

    let (vendor, product, version, cpe) = (
        agreed(|rule| &rule.os.vendor),
        agreed(|rule| &rule.os.product),
        agreed(|rule| &rule.os.version),
        agreed(|rule| &rule.os.cpe),
    );

    Some(OsVerdict {
        family: Some(first.os.family.clone()),
        // A reply's shape says nothing about what kind of box sent it. The
        // classes that would be worth reading — printer, switch, camera — are
        // read off text, by rules that can name them.
        device: None,
        // A rule is one source, and it asserts its whole identity at once: the
        // release it names is worth exactly what the rule is worth. The two
        // figures only come apart once *several* sources are folded together,
        // which is `resolve`'s job rather than this one's.
        detail_accuracy: (vendor.is_some()
            || product.is_some()
            || version.is_some()
            || cpe.is_some())
        .then_some(accuracy),
        vendor,
        product,
        version,
        // A stack rule reads a reply's shape, which carries no kernel release.
        // Only a service that states one can supply it.
        kernel: None,
        cpe,
        accuracy,
        source: OsSource::TcpStack,
        evidence,
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

        assert_eq!(verdict.family.as_deref(), Some("Linux"));
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
        // An option layout nothing emits: a maximum segment size, an option kind
        // no stack writes, and padding. Well-formed, and belonging to no family
        // in the corpus.
        //
        // The *layout* rather than the window, deliberately — see the test
        // below. A window nothing has been measured at is an ordinary Linux host
        // whose owner tuned it, and naming that one nothing was the defect this
        // pair now guards from both sides.
        let nothing_emits = [2, 4, 0x05, 0xb4, 99, 2, 1, 1];
        let verdict = classify_reply(
            ip(),
            &segment(flags::SYN | flags::ACK, 65_160, &nothing_emits),
        );
        assert!(verdict.is_none());
    }

    /// And the other side of it: a host is not disqualified for having been
    /// tuned.
    ///
    /// Measured 2026-08-21 — one `sysctl -w net.ipv4.tcp_rmem=...` on an
    /// untouched kernel moved a Debian guest's window and window scale together,
    /// and the rule that pinned them stopped matching. A machine went from
    /// `Linux [65%]` to no operating system at all because somebody had raised
    /// their receive buffers, which is a rule describing a configuration while
    /// claiming to describe a system.
    ///
    /// The hop counter, the option layout and the two capabilities the peer
    /// named are what survive tuning, and they are what the rule now tests.
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
    /// The imported corpus writes a Linux distro as `vendor = "Debian"`,
    /// `product = "Linux"`, `family = "Linux"` — 993 rules set `product` to the
    /// family name like that — and reading `product` as the label reported a
    /// real Debian 12 host as `Linux 12.0`, a version number no Linux has ever
    /// carried.
    #[test]
    fn a_distribution_is_named_by_its_distribution() {
        let verdict = OsVerdict {
            family: Some("Linux".to_owned()),
            device: None,
            vendor: Some("Debian".to_owned()),
            product: Some("Linux".to_owned()),
            version: Some("12".to_owned()),
            kernel: None,
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

    /// A device class means the product is a model number, and a model number
    /// without its maker names nothing anybody can look up. `NC-8700w` is a
    /// string; `Brother NC-8700w` is a printer.
    #[test]
    fn a_model_number_is_labelled_with_the_maker_that_built_it() {
        let verdict = OsVerdict {
            family: Some("Network device".to_owned()),
            device: Some("Printer".to_owned()),
            vendor: Some("Brother".to_owned()),
            product: Some("NC-8700w".to_owned()),
            version: Some("ZL".to_owned()),
            kernel: None,
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

        // And not twice, where the corpus already wrote the maker into the model.
        let spelled_out = OsVerdict {
            product: Some("Brother HL-1660e".to_owned()),
            ..verdict
        };
        assert_eq!(spelled_out.label(), "Brother HL-1660e");
    }

    /// A verdict with no family at all — an agent that named a box outright and
    /// never said what it runs — still labels itself off what it did establish.
    #[test]
    fn a_verdict_without_a_family_is_still_named() {
        let verdict = OsVerdict {
            family: None,
            device: Some("Printer".to_owned()),
            vendor: Some("Brother".to_owned()),
            product: Some("NC-8700w".to_owned()),
            version: Some("ZL".to_owned()),
            kernel: None,
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

    /// And the case that rule must not break. A rule naming no product leaves
    /// `vendor` meaning whoever made the *machine* as often as whoever published
    /// the system — so `Microsoft` + `Windows`, of which the corpus holds
    /// seventeen, has to stay `Windows`.
    #[test]
    fn a_vendor_without_a_product_does_not_replace_the_family() {
        let verdict = OsVerdict {
            family: Some("Windows".to_owned()),
            device: None,
            vendor: Some("Microsoft".to_owned()),
            product: None,
            version: Some("10".to_owned()),
            kernel: None,
            cpe: None,
            accuracy: 60,
            detail_accuracy: Some(60),
            source: OsSource::ServiceBanner,
            evidence: "service banner names Windows".to_owned(),
        };

        assert_eq!(verdict.to_fingerprint().name(), "Windows");
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

        assert_eq!(observed.family.as_deref(), Some("macOS"));
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

    fn named(family: &str, version: Option<&str>) -> OsIdentity {
        OsIdentity {
            family: family.to_owned(),
            vendor: None,
            product: None,
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

    /// The guarantee that makes a series predicate safe to author: it cannot be
    /// satisfied by a single reply, because a single reply has no series to
    /// satisfy it with. A rule that says "this generator hashes" must never be
    /// matched by one sequence number, whatever that number is.
    #[test]
    fn a_series_rule_cannot_be_satisfied_by_one_reply() {
        let db = RuleDb::from_rules(vec![rule(
            named("Linux", Some("6.x")),
            MatchRule {
                reply: ReplyKind::SynAck,
                initial_hops: at_64(),
                sequence_class: is("hashed"),
                ..Default::default()
            },
        )]);
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
    /// A rule naming a release is necessarily *narrower* than the family rule
    /// that describes the same stack, so both match, every time. Treating the
    /// family rule's silence about the version as disagreement would erase the
    /// version on exactly the hosts the finer rule was written for — more
    /// evidence yielding a less specific answer.
    #[test]
    fn a_broader_rule_matching_beside_a_finer_one_does_not_erase_the_version() {
        let db = RuleDb::from_rules(vec![
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
        ]);

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

    /// Abstention is not agreement with anything: two rules naming *different*
    /// releases still cannot both be right, and nothing here can say which is.
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
        let db = RuleDb::from_rules(vec![
            with_version("6.x", "hashed"),
            with_version("7.x", "hashed"),
        ]);

        let verdict = classify_series(&db, &[(syn_ack(), hashed())]).expect("the family is agreed");
        assert_eq!(verdict.family.as_deref(), Some("Linux"));
        assert!(
            verdict.version.is_none(),
            "a contradiction about the release is not a release"
        );
    }

    /// Several replies from one host are one piece of evidence about one stack.
    /// The scanner that collects them hands them over together for exactly this
    /// reason: separately they would pass through the resolver's noisy-OR as
    /// though a machine agreeing with itself were two sources agreeing with each
    /// other.
    #[test]
    fn a_host_read_several_ways_still_yields_one_verdict() {
        let db = RuleDb::from_rules(vec![rule(
            named("Linux", None),
            MatchRule {
                reply: ReplyKind::SynAck,
                initial_hops: at_64(),
                ..Default::default()
            },
        )]);

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
