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
            generation: None,
            vendor: None,
            accuracy: accuracy.min(100),
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

    /// The vendor, if one was identified.
    pub fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    /// How sure this identification is, from 0 to 100.
    pub fn accuracy(&self) -> u8 {
        self.accuracy
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
            generation,
            vendor,
            accuracy,
            cpe,
            evidence,
        } = other;

        if accuracy > self.accuracy {
            self.name = name;
            self.accuracy = accuracy;
            self.family = family.or(self.family.take());
            self.generation = generation.or(self.generation.take());
            self.vendor = vendor.or(self.vendor.take());
            // The evidence follows the identity it explains. Keeping the losing
            // technique's line beside the winning technique's name would be a
            // rationale for a conclusion nobody reached.
            self.evidence = evidence.or(self.evidence.take());
        } else if accuracy == self.accuracy {
            self.evidence = self.evidence.take().or(evidence);
            self.family = self.family.take().or(family);
            self.generation = self.generation.take().or(generation);
            self.vendor = self.vendor.take().or(vendor);
        }

        for cpe in cpe {
            if self.cpe.len() >= MAX_CPES_PER_OS {
                break;
            }
            self.cpe.insert(cpe);
        }
    }
}

impl std::fmt::Display for OsFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(ref generation) = self.generation {
            write!(f, " {}", generation)?;
        }
        write!(f, " [{}%]", self.accuracy)
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
