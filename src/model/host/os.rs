// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a host is running
//!
//! [`OsFingerprint`] is an operating system as one technique identified it,
//! carrying the accuracy that says how much to believe it.
//!
//! Several techniques answer the same question from different evidence — the
//! shape of a TCP/IP stack's replies, a service banner, an SNMP response — and
//! they disagree. The accuracy is what makes them combinable at all: it ranks
//! two findings without either one having to know how the other was reached.
//! [`OsFingerprint::merge`] is that rule.

use std::{collections::BTreeSet, sync::Arc};

/// The most CPE identifiers one fingerprint will have recorded against it.
///
/// A bound on what a single target can make this process allocate. The
/// identifiers are derived from what the target said and how its stack behaved,
/// neither of which this engine controls, and a host that produces a few
/// thousand plausible ones would otherwise have every one of them held.
///
/// [`MAX_CPES_PER_SERVICE`](crate::model::port::service::MAX_CPES_PER_SERVICE)
/// is the same bound for a service, where it matters more: a banner is text the
/// target chose outright.
pub const MAX_CPES_PER_OS: usize = 50;

/// A host's operating system as one technique identified it, and how sure that
/// technique was.
///
/// The accuracy is what makes several techniques combinable: a better-informed
/// finding replaces a worse one and equally-informed ones fill each other's
/// gaps. See [`merge`](Self::merge).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OsFingerprint {
    /// The operating system's name, such as `"Linux"` or `"Windows"`.
    ///
    /// Shared rather than owned because a scan of any size finds the same few
    /// names over and over, and the string is then one allocation across the
    /// whole result rather than one per host.
    name: Arc<str>,

    /// The broad family, such as `"Unix-like"` or `"Windows NT"`.
    family: Option<Arc<str>>,

    /// What kind of box this is, such as `"Printer"` or `"Switch"`.
    ///
    /// **A second axis, not a coarser name.** What a machine runs and what it is
    /// are separate facts, and a source often knows one without the other: a hop
    /// counter says infrastructure and never a vendor, an SNMP agent names a
    /// printer's firmware and never its kernel. Held apart, the two corroborate;
    /// folded into one field they contradicted, and a Brother print server that
    /// had answered ARP, ICMP, TCP and SNMP was reported as unidentified.
    device: Option<Arc<str>>,

    /// The version or generation, such as `"5.15.0"` or `"11"`.
    generation: Option<Arc<str>>,

    /// The vendor, such as `"Canonical"` or `"Microsoft"`.
    vendor: Option<Arc<str>>,

    /// How sure this identification is, as a percentage.
    ///
    /// Private because [`new`](Self::new) clamps it to 100 and
    /// [`merge`](Self::merge) ranks findings by it. A value above 100 would
    /// outrank a completed match and could never be displaced.
    accuracy: u8,

    /// The kernel release, where something read one.
    ///
    /// **Beside the generation, not a finer form of it.** A distribution release
    /// and the kernel it ships are two facts about one machine — Debian 12 runs
    /// kernel 6.1 — and neither is the better answer. Held as one field they
    /// contradicted: an SSH banner naming `12` and an SNMP agent naming `6.1.0`
    /// were read as two sources disagreeing, and a host that had told this engine
    /// both was reported as neither.
    ///
    /// It is also the single most actionable thing a scan can learn about a Unix
    /// host, because it is what a known-vulnerability lookup keys on.
    kernel: Option<Arc<str>>,

    /// How well supported everything *past* the family is, where the finding
    /// says more than a family at all.
    ///
    /// The family is what every source can speak to, and [`accuracy`] describes
    /// agreement about it. A release is usually named by exactly one source — a
    /// service banner — so reporting it under the family's figure launders one
    /// weaker claim through the agreement of several stronger ones. Measured, on
    /// a real host: two sources agreeing on Linux scored 84, the release came
    /// from a single banner worth 55, and `Debian 12.0 [84%]` claimed the second
    /// number was as well attested as the first.
    ///
    /// `None` where the finding stops at the family, and there is nothing extra
    /// to qualify.
    ///
    /// [`accuracy`]: Self::accuracy
    detail_accuracy: Option<u8>,

    /// A bounded set of Common Platform Enumeration (CPE) identifiers.
    cpe: BTreeSet<Arc<str>>,

    /// What this identification was read off, in one line.
    ///
    /// A verdict nobody can check is a verdict nobody can dispute, and a *wrong*
    /// confident one is exactly where checking matters. Carrying the evidence
    /// beside the conclusion means a false positive can be diagnosed, and turned
    /// into a corpus entry, without re-running the scan — where a scan that
    /// prints only its conclusion has to be repeated before it can be argued
    /// with.
    ///
    /// **Written for a person, not for a parser.** It is a rendering of whatever
    /// technique produced the finding, and different techniques render different
    /// things; nothing should try to read a value back out of it. The fields a
    /// consumer is meant to act on are the named ones beside it.
    evidence: Option<Arc<str>>,
}

impl OsFingerprint {
    /// Creates a new `OsFingerprint` with a name and a confidence score.
    ///
    /// Accuracy is strictly clamped to the range `[0, 100]`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use zond_engine::model::host::OsFingerprint;
    /// let os = OsFingerprint::new("Ubuntu Linux", 95);
    /// assert_eq!(os.accuracy(), 95);
    /// ```
    pub fn new(name: impl Into<Arc<str>>, accuracy: u8) -> Self {
        Self {
            name: name.into(),
            family: None,
            device: None,
            generation: None,
            vendor: None,
            accuracy: accuracy.min(100),
            kernel: None,
            detail_accuracy: None,
            cpe: BTreeSet::new(),
            evidence: None,
        }
    }

    /// The operating system's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The broad family, if one was identified.
    pub fn family(&self) -> Option<&str> {
        self.family.as_deref()
    }

    /// The version or generation, if one was identified.
    pub fn generation(&self) -> Option<&str> {
        self.generation.as_deref()
    }

    /// What kind of box this is, if anything named a class.
    pub fn device(&self) -> Option<&str> {
        self.device.as_deref()
    }

    /// Builder method to set the device class.
    #[must_use]
    pub fn with_device(mut self, device: impl Into<Arc<str>>) -> Self {
        self.device = Some(device.into());
        self
    }

    /// The vendor, if one was identified.
    pub fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    /// How sure this identification is, from 0 to 100.
    pub fn accuracy(&self) -> u8 {
        self.accuracy
    }

    /// The kernel release, where something read one.
    pub fn kernel(&self) -> Option<&str> {
        self.kernel.as_deref()
    }

    /// Records the kernel release.
    #[must_use]
    pub fn with_kernel(mut self, kernel: impl Into<Arc<str>>) -> Self {
        self.kernel = Some(kernel.into());
        self
    }

    /// How well supported everything past the family is, or `None` where the
    /// finding stops at the family.
    pub fn detail_accuracy(&self) -> Option<u8> {
        self.detail_accuracy
    }

    /// Records how well supported the finer parts of this identity are.
    pub fn with_detail_accuracy(mut self, accuracy: u8) -> Self {
        self.detail_accuracy = Some(accuracy.min(100));
        self
    }

    /// Builder method to set the broad family.
    pub fn with_family(mut self, family: impl Into<Arc<str>>) -> Self {
        self.family = Some(family.into());
        self
    }

    /// Builder method to set the version or generation.
    pub fn with_generation(mut self, generation: impl Into<Arc<str>>) -> Self {
        self.generation = Some(generation.into());
        self
    }

    /// Builder method to set the vendor.
    pub fn with_vendor(mut self, vendor: impl Into<Arc<str>>) -> Self {
        self.vendor = Some(vendor.into());
        self
    }

    /// Builder method to record what this identification was read off.
    pub fn with_evidence(mut self, evidence: impl Into<Arc<str>>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    /// What this identification was read off, if the technique recorded it.
    pub fn evidence(&self) -> Option<&str> {
        self.evidence.as_deref()
    }

    /// Adds a CPE identifier to the fingerprint, provided the internal limit
    /// ([`MAX_CPES_PER_OS`]) has not been reached.
    pub fn add_cpe(&mut self, cpe: impl Into<Arc<str>>) {
        if self.cpe.len() < MAX_CPES_PER_OS {
            self.cpe.insert(cpe.into());
        }
    }

    /// Returns a read-only view of all identified CPEs for this host.
    pub fn cpes(&self) -> &BTreeSet<Arc<str>> {
        &self.cpe
    }

    /// Returns `true` if the identification has high certainty (>= 85%).
    ///
    /// This threshold is often used by scanning engines to decide whether
    /// to terminate OS discovery or continue with more intrusive probes.
    pub fn is_highly_confident(&self) -> bool {
        self.accuracy >= 85
    }

    /// Folds another technique's identification of this host into this one.
    ///
    /// The identity — name, family, generation, vendor — comes from whichever
    /// record is more accurate, and a tie keeps what is already recorded.
    ///
    /// **CPEs are unioned whatever the accuracies are**, which is the one part
    /// that does not follow the ranking, and it matches
    /// [`Service::merge`](crate::model::port::Service::merge) next door. A CPE
    /// is not a claim about which operating system this is; it is a claim that
    /// this identifier applies, and a technique that was less sure of the name
    /// can still have extracted a valid one. Discarding them cost real findings:
    /// a low-accuracy pass that named three CPEs was erased entire by a
    /// higher-accuracy pass that named none.
    pub fn merge(&mut self, other: OsFingerprint) {
        let OsFingerprint {
            name,
            family,
            device,
            generation,
            vendor,
            accuracy,
            kernel,
            detail_accuracy,
            cpe,
            evidence,
        } = other;

        if accuracy > self.accuracy {
            self.name = name;
            self.accuracy = accuracy;
            self.family = family.or(self.family.take());
            // Kept across a losing merge, unlike the name: what the box *is* does
            // not stop being true because a stronger technique named what it
            // runs. The two answers are about different things.
            self.device = device.or(self.device.take());
            self.generation = generation.or(self.generation.take());
            self.vendor = vendor.or(self.vendor.take());
            self.kernel = kernel.or(self.kernel.take());
            // Travels with the parts it qualifies, never on its own: a figure
            // describing a release this finding no longer names would attach a
            // confidence to nothing.
            self.detail_accuracy = detail_accuracy.or(self.detail_accuracy.take());
            // The evidence follows the identity it explains. Keeping the losing
            // technique's line beside the winning technique's name would be a
            // rationale for a conclusion nobody reached.
            self.evidence = evidence.or(self.evidence.take());
        } else if accuracy == self.accuracy {
            // Two findings of equal strength about one host.
            //
            // Where they name the same system they are two *readings* of it and
            // both belong in the record. This is how the active series probe's
            // reading arrives: it corroborates the passive one exactly, so it
            // ties, and keeping only the first meant the one measurement that
            // says what the host's counters do — the whole reason the probe was
            // sent — was discarded before anybody saw it.
            //
            // Where they name different systems the loser's line is a rationale
            // for a conclusion nobody reached, and it goes, for the same reason
            // it does above.
            self.evidence = if self.name == name {
                join_evidence(self.evidence.take(), evidence)
            } else {
                self.evidence.take().or(evidence)
            };
            self.family = self.family.take().or(family);
            self.device = self.device.take().or(device);
            self.generation = self.generation.take().or(generation);
            self.vendor = self.vendor.take().or(vendor);
            self.kernel = self.kernel.take().or(kernel);
            self.detail_accuracy = self.detail_accuracy.take().or(detail_accuracy);
        }

        for cpe in cpe {
            if self.cpe.len() >= MAX_CPES_PER_OS {
                break;
            }
            self.cpe.insert(cpe);
        }
    }
}

/// What separates two readings in an evidence line.
///
/// The same separator [`resolve`](crate::fingerprint::os::resolve) folds its
/// sources with, so a person reading a report meets one convention rather than
/// two.
const SEPARATOR: &str = " | ";

/// The most evidence one fingerprint carries, in bytes.
///
/// Readings accumulate — a host read passively, then followed, then pinged
/// contributes three — and each is worth keeping. A caller running strategies in
/// a loop over one host is not, so this bounds the record at the point where it
/// stops describing a host and starts logging a session.
const MAX_EVIDENCE_LEN: usize = 512;

/// Joins two evidence lines, keeping each reading once and in the order it
/// arrived.
///
/// Truncates a whole reading rather than half of one: a line cut mid-value would
/// read as a measurement that says something it does not.
fn join_evidence(existing: Option<Arc<str>>, incoming: Option<Arc<str>>) -> Option<Arc<str>> {
    match (existing, incoming) {
        (Some(existing), Some(incoming)) => Some(join_readings(&existing, &incoming).into()),
        (existing, incoming) => existing.or(incoming),
    }
}

/// Joins two evidence lines, keeping each reading once and in the order it
/// arrived.
///
/// Shared with the evidence a host retains per source, so a reading that arrives
/// twice by two routes reads the same either way.
///
/// **A reading that another one extends is dropped.** The passive path and the
/// active one describe the same reply, and the active one appends what several
/// replies added up to — so its line begins with the passive line and continues.
/// Keeping both would print the same observation twice with the second copy
/// merely longer.
///
/// Truncates a whole reading rather than half of one: a line cut mid-value would
/// read as a measurement that says something it does not.
pub(super) fn join_readings(existing: &str, incoming: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();

    for part in existing.split(SEPARATOR).chain(incoming.split(SEPARATOR)) {
        // Already said, or already said at greater length.
        if parts.iter().any(|kept| kept.starts_with(part)) {
            continue;
        }
        // Says everything one already on record says, and more.
        parts.retain(|kept| !part.starts_with(kept));
        parts.push(part);
    }

    let mut length = 0usize;
    parts.retain(|part| {
        let cost = part.len() + if length == 0 { 0 } else { SEPARATOR.len() };
        let room = length + cost <= MAX_EVIDENCE_LEN;
        if room {
            length += cost;
        }
        room
    });

    parts.join(SEPARATOR)
}

impl std::fmt::Display for OsFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The family and its agreement first, because that is the part several
        // sources can vouch for. Anything finer follows with its own figure —
        // one source usually names a release, and printing it under the family's
        // number would claim it was as well attested as the family.
        let family = self.family.as_deref().unwrap_or(&self.name);
        write!(f, "{family} [{}%]", self.accuracy)?;

        // Then the distribution, where one was named. `·` separates facts of
        // different strengths rather than parts of one name.
        let names_a_release = &*self.name != family || self.generation.is_some();
        if names_a_release {
            write!(f, " · {}", self.name)?;
            if let Some(generation) = &self.generation {
                write!(f, " {generation}")?;
            }
            if let Some(accuracy) = self.detail_accuracy {
                write!(f, " [{accuracy}%]")?;
            }
        }

        // And the kernel last, labelled, because `Debian 12 · 6.1.0` reads as
        // two guesses at one number where `kernel 6.1.0` reads as what it is.
        if let Some(kernel) = &self.kernel {
            write!(f, " · kernel {kernel}")?;
            if let Some(accuracy) = self.detail_accuracy {
                write!(f, " [{accuracy}%]")?;
            }
        }

        Ok(())
    }
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

    /// The defect this exists to prevent, and it was a live one: the active
    /// series probe corroborates the passive reading exactly, so the two tie —
    /// and keeping only the first threw away the only line that says what the
    /// host's counters do, which is the whole reason the probe was sent.
    #[test]
    fn two_readings_of_one_system_are_both_kept() {
        let mut passive = OsFingerprint::new("Linux", 65)
            .with_evidence("syn-ack hops>=64 opts=M,S,T,N,W win=65160=45x1448 ws=7");
        passive.merge(OsFingerprint::new("Linux", 65).with_evidence(
            "syn-ack hops>=64 opts=M,S,T,N,W win=65160=45x1448 ws=7 \
                                id=zero isn=hashed ts=ticking",
        ));

        let evidence = passive.evidence().expect("evidence survives");
        assert!(
            evidence.contains("isn=hashed"),
            "the series reading is the one that cannot be got back: {evidence}"
        );
    }

    /// Three facts about one machine, each with what it is actually worth.
    ///
    /// The family is what several sources agreed on; the distribution release
    /// came from one banner; the kernel from one agent. Rendering them as one
    /// name — `Debian 12` — hid the kernel entirely, and rendering the kernel as
    /// a version made the two look like rival answers to one question.
    #[test]
    fn a_finding_shows_the_family_the_release_and_the_kernel_apart() {
        let os = OsFingerprint::new("Debian", 93)
            .with_family("Linux")
            .with_generation("12")
            .with_kernel("6.1.0")
            .with_detail_accuracy(69);

        assert_eq!(
            os.to_string(),
            "Linux [93%] · Debian 12 [69%] · kernel 6.1.0 [69%]"
        );
    }

    /// A finding that knows only a family says only that. The separators are for
    /// facts that exist.
    #[test]
    fn a_family_alone_renders_as_a_family_alone() {
        let os = OsFingerprint::new("Linux", 65).with_family("Linux");
        assert_eq!(os.to_string(), "Linux [65%]");
    }

    /// A kernel with no distribution behind it — an SNMP agent on a host with
    /// nothing else to say — still reports the kernel.
    #[test]
    fn a_kernel_without_a_release_is_still_reported() {
        let os = OsFingerprint::new("Linux", 84)
            .with_family("Linux")
            .with_kernel("6.1.0")
            .with_detail_accuracy(55);

        assert_eq!(os.to_string(), "Linux [84%] · kernel 6.1.0 [55%]");
    }

    /// Joining is for readings of the *same* system. A tie between two different
    /// names keeps the winner's line alone — the loser's is a rationale for a
    /// conclusion nobody reached.
    #[test]
    fn a_tie_between_two_names_does_not_borrow_the_losers_reasoning() {
        let mut linux = OsFingerprint::new("Linux", 65).with_evidence("a Linux-shaped reply");
        linux.merge(OsFingerprint::new("Windows", 65).with_evidence("a Windows-shaped reply"));

        assert_eq!(linux.name(), "Linux");
        assert_eq!(linux.evidence(), Some("a Linux-shaped reply"));
    }

    /// One reading, however many times it is filed. A scan that identifies a
    /// host twice by the same route has learned one thing.
    #[test]
    fn the_same_reading_twice_is_recorded_once() {
        let mut host = OsFingerprint::new("Linux", 65).with_evidence("syn-ack hops>=64");
        host.merge(OsFingerprint::new("Linux", 65).with_evidence("syn-ack hops>=64"));

        assert_eq!(host.evidence(), Some("syn-ack hops>=64"));
    }

    /// Readings accumulate, so the record needs a ceiling — and it has to fall
    /// between readings rather than inside one, because half a reading reads as
    /// a measurement claiming something it never said.
    #[test]
    fn a_long_accumulation_is_cut_between_readings_not_inside_one() {
        let reading = |n: usize| format!("reading {n} {}", "x".repeat(60));

        let mut host = OsFingerprint::new("Linux", 65).with_evidence(reading(0));
        for n in 1..40 {
            host.merge(OsFingerprint::new("Linux", 65).with_evidence(reading(n)));
        }

        let evidence = host.evidence().expect("evidence survives");
        assert!(evidence.len() <= MAX_EVIDENCE_LEN, "{}", evidence.len());
        for part in evidence.split(SEPARATOR) {
            assert!(
                part.starts_with("reading ") && part.ends_with('x'),
                "a reading was cut in half: {part:?}"
            );
        }
    }
    use super::*;

    /// Accuracy is what ranks two findings, so a value above 100 would outrank
    /// a completed match and could never afterwards be displaced. Clamping at
    /// construction is what keeps a caller computing a score from producing
    /// one.
    #[test]
    fn an_accuracy_above_100_is_clamped_rather_than_kept() {
        assert_eq!(OsFingerprint::new("Linux", 200).accuracy(), 100);
        assert_eq!(OsFingerprint::new("Linux", 100).accuracy(), 100);
    }

    /// The threshold a caller uses to stop fingerprinting, so where exactly it
    /// falls decides whether a further, more intrusive probe is sent.
    #[test]
    fn high_confidence_starts_at_85() {
        assert!(OsFingerprint::new("Linux", 85).is_highly_confident());
        assert!(!OsFingerprint::new("Linux", 84).is_highly_confident());
    }

    /// The surer technique names the host. Without this a scan reports whichever
    /// identification happened to finish last, and a stack fingerprint sure to
    /// 90% loses to a banner guess.
    #[test]
    fn the_more_accurate_finding_names_the_host() {
        let mut banner = OsFingerprint::new("Linux", 50);
        banner.merge(OsFingerprint::new("Ubuntu", 90));

        assert_eq!(banner.name(), "Ubuntu");
        assert_eq!(banner.accuracy(), 90);
    }

    /// Two equally accurate findings are equally good sources, so a tie keeps
    /// what is already recorded and fills only what is missing. Preferring the
    /// later one would make the report depend on which technique finished
    /// first.
    #[test]
    fn a_tie_keeps_the_incumbent_and_fills_only_its_gaps() {
        let mut first = OsFingerprint::new("Linux", 80).with_family("Unix-like");

        first.merge(
            OsFingerprint::new("Linux", 80)
                .with_family("Something else")
                .with_generation("5.15.0"),
        );

        assert_eq!(first.family(), Some("Unix-like"), "already recorded");
        assert_eq!(first.generation(), Some("5.15.0"), "a gap, so filled");
    }

    /// A CPE says "this identifier applies", not "this is the operating
    /// system", so it survives a merge that overrules the identity around it.
    /// Replacing the whole record on higher accuracy erased every identifier a
    /// less certain technique had extracted.
    #[test]
    fn a_more_accurate_finding_takes_the_identity_but_not_at_the_cost_of_cpes() {
        let mut banner = OsFingerprint::new("Linux", 40).with_vendor("Canonical");
        banner.add_cpe("cpe:/o:canonical:ubuntu_linux");

        let mut stack = OsFingerprint::new("Ubuntu 22.04", 90);
        stack.add_cpe("cpe:/o:canonical:ubuntu_linux:22.04");

        banner.merge(stack);

        assert_eq!(banner.name(), "Ubuntu 22.04", "the surer name wins");
        assert_eq!(banner.accuracy(), 90);
        assert_eq!(
            banner.vendor(),
            Some("Canonical"),
            "and a field the surer finding left empty is not erased"
        );
        assert_eq!(banner.cpes().len(), 2, "both identifiers still apply");
    }

    /// The identifiers come from what the target said and how its stack
    /// behaved, so their number is not this engine's to choose. Both the direct
    /// route and a merge have to respect the bound, or the merge is a way
    /// around it.
    #[test]
    fn the_cpe_list_is_bounded_by_both_routes_into_it() {
        let mut os = OsFingerprint::new("Windows", 100);
        for i in 0..MAX_CPES_PER_OS * 2 {
            os.add_cpe(format!("cpe:/o:ident:{i}"));
        }
        assert_eq!(os.cpes().len(), MAX_CPES_PER_OS);

        let mut other = OsFingerprint::new("Windows", 100);
        for i in 0..MAX_CPES_PER_OS {
            other.add_cpe(format!("cpe:/o:other:{i}"));
        }
        os.merge(other);
        assert_eq!(os.cpes().len(), MAX_CPES_PER_OS);
    }
}
