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
//! Several techniques answer the question from different evidence (a TCP/IP stack's
//! replies, a service banner, an SNMP response) and they disagree. The accuracy ranks
//! two findings regardless of how each was reached; [`OsFingerprint::merge`] applies
//! it.

use std::{collections::BTreeSet, sync::Arc};

/// The most CPE identifiers one fingerprint will have recorded against it.
///
/// Bounds what a single target can make this process allocate, since the identifiers
/// derive from what the target said and how its stack behaved.
///
/// [`MAX_CPES_PER_SERVICE`](crate::model::port::service::MAX_CPES_PER_SERVICE) reads
/// its number from here.
pub const MAX_CPES_PER_OS: usize = 50;

/// The accuracy at which [`OsFingerprint::is_highly_confident`] answers true.
///
/// Eighty-five is where a stack reading plus an agreeing second source lands, and
/// above what a single weakly scored source reaches.
pub const HIGH_CONFIDENCE_ACCURACY: u8 = 85;

/// A host's operating system as one technique identified it, and how sure that
/// technique was.
///
/// A better-informed finding replaces a worse one, and equally informed ones fill each
/// other's gaps. See [`merge`](Self::merge).
///
/// A rule can fill its names from a banner, so each is untrusted and can hold control
/// characters; escape before display. Its `Display` does.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OsFingerprint {
    /// The operating system's name, such as `"Linux"` or `"Windows"`.
    ///
    /// Shared, since a scan finds the same few names over and over.
    name: Arc<str>,

    /// The broad family, such as `"Unix-like"` or `"Windows NT"`.
    family: Option<Arc<str>>,

    /// What kind of box this is, such as `"Printer"` or `"Switch"`.
    ///
    /// A separate axis from the name: what a machine runs and what it is are separate
    /// facts, and a source often knows only one (a hop counter says infrastructure, an
    /// SNMP agent names a printer's firmware). Held apart, the two corroborate.
    device: Option<Arc<str>>,

    /// The version or generation, such as `"5.15.0"` or `"11"`.
    generation: Option<Arc<str>>,

    /// The vendor, such as `"Canonical"` or `"Microsoft"`.
    vendor: Option<Arc<str>>,

    /// How sure this identification is, as a percentage.
    ///
    /// Private because [`new`](Self::new) clamps it to 100; [`merge`](Self::merge)
    /// ranks by it, and a larger value could never be displaced.
    accuracy: u8,

    /// The kernel release, where something read one.
    ///
    /// Separate from the generation: Debian 12 runs kernel 6.1, and an SSH banner naming
    /// `12` and an SNMP agent naming `6.1.0` do not disagree.
    ///
    /// The most actionable thing a scan learns about a Unix host, since a
    /// known-vulnerability lookup keys on it.
    kernel: Option<Arc<str>>,

    /// The instruction set the system runs on, where something read one.
    ///
    /// A third axis: `mips` on a router and `x86_64` on a server are the same family on
    /// different silicon, and a vulnerability may need one. `sysDescr` on a Unix host is
    /// `uname -a`, which ends with the machine type.
    arch: Option<Arc<str>>,

    /// How well supported everything past the family is, where the finding says
    /// more than a family at all.
    ///
    /// [`accuracy`] describes agreement about the family. A release is usually named by
    /// one source, typically a banner, so it gets its own figure: on a real host two
    /// sources agreed on Linux at 84 while the release came from one banner worth 55.
    ///
    /// `None` where the finding stops at the family.
    ///
    /// [`accuracy`]: Self::accuracy
    detail_accuracy: Option<u8>,

    /// A bounded set of Common Platform Enumeration (CPE) identifiers.
    cpe: BTreeSet<Arc<str>>,

    /// What this identification was read off, in one line.
    ///
    /// Lets a false positive be diagnosed, and turned into a corpus entry, without
    /// re-running the scan.
    ///
    /// Written for a person; its format varies by technique, so do not parse it. Act on
    /// the named fields.
    evidence: Option<Arc<str>>,
}

impl OsFingerprint {
    /// Creates a new `OsFingerprint` with a name and a confidence score.
    ///
    /// Accuracy is clamped to `[0, 100]`.
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
            arch: None,
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
    pub fn with_kernel(mut self, kernel: impl Into<Arc<str>>) -> Self {
        self.kernel = Some(kernel.into());
        self
    }

    /// The instruction set, where something read one.
    pub fn arch(&self) -> Option<&str> {
        self.arch.as_deref()
    }

    /// Records the instruction set.
    pub fn with_arch(mut self, arch: impl Into<Arc<str>>) -> Self {
        self.arch = Some(arch.into());
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

    /// Whether the identification is sure enough to stop asking:
    /// [`HIGH_CONFIDENCE_ACCURACY`] or better.
    ///
    /// Read by `fingerprint::os`'s verdict and text passes, to decide whether a
    /// host needs a more intrusive probe than it has already answered.
    pub fn is_highly_confident(&self) -> bool {
        self.accuracy >= HIGH_CONFIDENCE_ACCURACY
    }

    /// Folds another technique's identification of this host into this one.
    ///
    /// The identity (name and every field beside it) comes from the more accurate
    /// record, a tie keeping what is recorded; the other fills gaps.
    ///
    /// CPEs are unioned regardless, as in
    /// [`Service::merge`](crate::model::port::Service::merge): a CPE says an identifier
    /// applies, and a less certain technique can still extract a valid one.
    pub fn merge(&mut self, other: OsFingerprint) {
        let OsFingerprint {
            name,
            family,
            device,
            generation,
            vendor,
            accuracy,
            kernel,
            arch,
            detail_accuracy,
            cpe,
            evidence,
        } = other;

        if accuracy > self.accuracy {
            self.name = name;
            self.accuracy = accuracy;
            self.family = family.or(self.family.take());
            // Kept across a losing merge: what the box *is* is a separate question
            // from what it runs.
            self.device = device.or(self.device.take());
            self.generation = generation.or(self.generation.take());
            self.vendor = vendor.or(self.vendor.take());
            self.kernel = kernel.or(self.kernel.take());
            self.arch = arch.or(self.arch.take());
            // Travels with the parts it qualifies.
            self.detail_accuracy = detail_accuracy.or(self.detail_accuracy.take());
            // The evidence follows the identity it explains.
            self.evidence = evidence.or(self.evidence.take());
        } else if accuracy == self.accuracy {
            // A tie. Naming the same system, both lines are readings worth keeping
            // (the active series probe ties with the passive reading and adds what
            // the counters do). Naming different systems, the loser's line goes.
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
            self.arch = self.arch.take().or(arch);
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
/// The same separator [`resolve`](crate::fingerprint::os::resolve) uses.
const SEPARATOR: &str = " | ";

/// The most evidence one fingerprint carries, in bytes.
///
/// A host read passively, then followed, then pinged contributes three readings; this
/// bounds a caller running strategies in a loop over one host.
const MAX_EVIDENCE_LEN: usize = 512;

/// Joins two evidence lines, keeping each reading once and in the order it
/// arrived.
///
/// Drops whole readings at the bound, never half of one.
fn join_evidence(existing: Option<Arc<str>>, incoming: Option<Arc<str>>) -> Option<Arc<str>> {
    match (existing, incoming) {
        (Some(existing), Some(incoming)) => Some(join_readings(&existing, &incoming).into()),
        (existing, incoming) => existing.or(incoming),
    }
}

/// Joins two evidence lines, keeping each reading once and in the order it
/// arrived.
///
/// Shared with the evidence a host keeps per source.
///
/// A reading another one extends is dropped: the active path's line begins with the
/// passive path's and continues.
///
/// Drops whole readings at the bound, never half of one.
pub(super) fn join_readings(existing: &str, incoming: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();

    for part in existing.split(SEPARATOR).chain(incoming.split(SEPARATOR)) {
        // Already said, possibly at greater length.
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

/// Text a server may have chosen, with every control character written as an
/// escape, so printing a fingerprint cannot drive the terminal it is printed to.
///
/// Escaped as the zond CLI escapes a field, so its output reads the same.
struct Printable<'a>(&'a str);

impl std::fmt::Display for Printable<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;

        for character in self.0.chars() {
            match character {
                '\t' => f.write_str("\\t")?,
                '\n' => f.write_str("\\n")?,
                '\r' => f.write_str("\\r")?,
                c if c.is_control() => write!(f, "\\x{:02x}", u32::from(c))?,
                c => f.write_char(c)?,
            }
        }
        Ok(())
    }
}

impl std::fmt::Display for OsFingerprint {
    // Each name is written `Printable`, since a rule can fill it from a banner.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The family and its agreement first; anything finer follows with its own
        // figure.
        let family = self.family.as_deref().unwrap_or(&self.name);
        write!(f, "{} [{}%]", Printable(family), self.accuracy)?;

        // Then the distribution. `·` separates facts of different strengths.
        let names_a_release = &*self.name != family || self.generation.is_some();
        if names_a_release {
            write!(f, " · {}", Printable(&self.name))?;
            if let Some(generation) = &self.generation {
                write!(f, " {}", Printable(generation))?;
            }
            if let Some(accuracy) = self.detail_accuracy {
                write!(f, " [{accuracy}%]")?;
            }
        }

        // The kernel last, labelled: `Debian 12 · 6.1.0` would read as two guesses.
        if let Some(kernel) = &self.kernel {
            write!(f, " · kernel {}", Printable(kernel))?;
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

    /// The active series probe ties with the passive reading, and both lines are kept.
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

    /// Family, release and kernel render as three facts, each with its own strength.
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

    /// A finding that knows only a family says only that.
    #[test]
    fn a_family_alone_renders_as_a_family_alone() {
        let os = OsFingerprint::new("Linux", 65).with_family("Linux");
        assert_eq!(os.to_string(), "Linux [65%]");
    }

    /// A kernel with no distribution still reports the kernel.
    #[test]
    fn a_kernel_without_a_release_is_still_reported() {
        let os = OsFingerprint::new("Linux", 84)
            .with_family("Linux")
            .with_kernel("6.1.0")
            .with_detail_accuracy(55);

        assert_eq!(os.to_string(), "Linux [84%] · kernel 6.1.0 [55%]");
    }

    /// A tie between two different names keeps only the winner's line.
    #[test]
    fn a_tie_between_two_names_does_not_borrow_the_losers_reasoning() {
        let mut linux = OsFingerprint::new("Linux", 65).with_evidence("a Linux-shaped reply");
        linux.merge(OsFingerprint::new("Windows", 65).with_evidence("a Windows-shaped reply"));

        assert_eq!(linux.name(), "Linux");
        assert_eq!(linux.evidence(), Some("a Linux-shaped reply"));
    }

    /// One reading, however many times it is filed.
    #[test]
    fn the_same_reading_twice_is_recorded_once() {
        let mut host = OsFingerprint::new("Linux", 65).with_evidence("syn-ack hops>=64");
        host.merge(OsFingerprint::new("Linux", 65).with_evidence("syn-ack hops>=64"));

        assert_eq!(host.evidence(), Some("syn-ack hops>=64"));
    }

    /// The ceiling falls between readings, never inside one.
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

    /// Accuracy is clamped at construction.
    #[test]
    fn an_accuracy_above_100_is_clamped_rather_than_kept() {
        assert_eq!(OsFingerprint::new("Linux", 200).accuracy(), 100);
        assert_eq!(OsFingerprint::new("Linux", 100).accuracy(), 100);
    }

    /// The threshold decides whether a more intrusive probe is sent.
    #[test]
    fn high_confidence_starts_at_85() {
        assert!(OsFingerprint::new("Linux", 85).is_highly_confident());
        assert!(!OsFingerprint::new("Linux", 84).is_highly_confident());
    }

    /// The surer technique names the host, whichever finished last.
    #[test]
    fn the_more_accurate_finding_names_the_host() {
        let mut banner = OsFingerprint::new("Linux", 50);
        banner.merge(OsFingerprint::new("Ubuntu", 90));

        assert_eq!(banner.name(), "Ubuntu");
        assert_eq!(banner.accuracy(), 90);
    }

    /// A tie keeps what is recorded and fills only what is missing.
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

    /// CPEs survive a merge that overrules the identity around them.
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

    /// Both adding and merging respect the CPE bound.
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

/// Which evidence produced a verdict.
///
/// Lets a report say *why* a host was named. The variants carry no ordering; what each
/// is worth is decided where the evidence is made.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OsSource {
    /// The shape of a single TCP reply.
    TcpStack,
    /// The vendor a host's hardware address is registered to.
    HardwareVendor,
    /// Text a service volunteered about the system it runs on.
    ServiceBanner,
    /// A management agent answering for the machine itself, such as `sysDescr`
    /// out of SNMP.
    ///
    /// Worth more than [`ServiceBanner`](Self::ServiceBanner): a banner is a string a
    /// daemon was *compiled* with, so a container reports its base image, while
    /// `sysDescr` on a Unix host is `uname -a` at the moment of asking, and on an
    /// appliance the firmware actually running. See
    /// [`ceiling`](crate::fingerprint::os::ceiling).
    SnmpAgent,
    /// A Bonjour responder answering for the machine itself: the mDNS
    /// device-info record it serves, and the `.local` name it announces.
    ///
    /// Worth the same as [`SnmpAgent`](Self::SnmpAgent): `model=Mac16,10` and
    /// `osxvers=25` are what the machine says when asked. It also separates macOS from
    /// iOS, which share a kernel and answer a stack probe identically.
    ///
    /// One source for both, since one daemon serves both and the record is asked for
    /// under the announced name. A default name heard this way counts once with the
    /// record.
    MdnsResponder,
    /// The host's own name, where it is one an operating system generates by
    /// default and something other than the host's own responder gave it: a
    /// resolver answering a reverse lookup, or the host's DHCP request.
    ///
    /// The weakest source, but sometimes the only one: a stock Windows desktop drops
    /// every probe and still names itself `DESKTOP-`. A `.local` name is filed as
    /// [`MdnsResponder`](Self::MdnsResponder).
    Hostname,
}

/// One source's opinion about one host.
///
/// The identity is a path like
/// [`OsVerdict`](crate::fingerprint::os::OsVerdict)'s, and the confidence is a
/// probability rather than a percentage, since the arithmetic that combines these
/// only makes sense on `0.0..=1.0`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct OsEvidence {
    /// What produced it.
    pub source: OsSource,
    /// The broad family, where this source can name one.
    ///
    /// `None` is an abstention. [`resolve`](crate::fingerprint::os::resolve) settles the
    /// family by vote, and an invented family would vote against the real ones. A rule
    /// reading `Brother NC-8700w` off an SNMP agent knows the make, model and firmware
    /// but not what the box runs.
    pub family: Option<String>,
    /// What kind of box this is, such as `Printer` or `Switch` or `Router`, where
    /// a source says.
    ///
    /// Independent of the family: a Linux print server is both.
    pub device: Option<String>,
    /// The vendor, where the source knew one.
    pub vendor: Option<String>,
    /// The product, where the source knew one.
    pub product: Option<String>,
    /// The version, where the source knew one.
    pub version: Option<String>,
    /// The kernel release, where the source read one.
    ///
    /// Separate from the version: a distribution release and its kernel are two facts.
    pub kernel: Option<String>,
    /// The instruction set, where the source read one: `x86_64`, `mips`.
    pub arch: Option<String>,
    /// A Common Platform Enumeration identifier, where one applies exactly.
    pub cpe: Option<String>,
    /// How much this source is worth on its own, from 0 to 1.
    ///
    /// What this source contributes on its own, which is also the most it can produce
    /// alone.
    pub confidence: f32,
    /// One line describing what was read, for the report to carry.
    pub evidence: String,
}
