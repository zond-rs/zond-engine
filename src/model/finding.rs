// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What is wrong with what is running
//!
//! [`Evidence`](crate::fingerprint::Evidence) says *what is running* on a port;
//! a [`Finding`] says *what is wrong with it*. It is the model's second
//! vocabulary — the typed result a detection produces, whether that detection is
//! a signature, a declarative flow, a sandboxed module, or the built-in
//! CVE correlator, so that all of them compose without knowing about one another.
//!
//! A finding is a **positive claim, backed by evidence, about a subject the scan
//! already holds** — a vulnerable service on a port, a weakness inferred across a
//! host. It is carried by the thing it is about: a [`Host`](crate::model::host)
//! and a [`Port`](crate::model::port) each hold their own findings, the way they
//! already hold network roles and filtering conclusions. A finding that is *not*
//! present is never a claim that the subject is clean — it is a detection that
//! did not run, or ran and did not fire.
//!
//! ## Two axes, not one
//!
//! Every finding carries two independent judgements, and keeping them apart is
//! the whole reason a typed finding beats a printed string:
//!
//! - [`Severity`] — *how bad it is if true*.
//! - [`Confidence`] — *how sure it is true*,
//!   reused verbatim from the fingerprinting model so that one trust vocabulary
//!   covers the whole engine.
//!
//! A single "risk" number cannot say *Critical but unverified*, and that is
//! precisely the common case: a distribution backports a security fix without
//! moving the version string, so a version-matched CVE is genuinely severe and
//! genuinely unsure at once. The two axes say both; a fused one lies about one.
//!
//! ## Provenance is a first-class field
//!
//! A finding always names the [`DetectionId`] that produced it — an id, a
//! [`Version`], and the content hash of the detection body. The report records
//! that stamp, so a finding is reproducible and auditable long after the scan:
//! *which detection, which version, which bytes*. This is the field an
//! unstructured script blob never has, and it is what lets a detection be
//! accepted from a stranger and still answer for itself.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::model::confidence::Confidence;

/// The most justifying text a finding retains, in bytes.
///
/// The excerpt is target-controlled — it is bytes a scanned host chose to send —
/// and it travels into every export and every journal. Three things break
/// without a bound: a multi-megabyte banner becomes a denial-of-service on the
/// report; a journal that must let two runs write byte-identical files cannot
/// carry an unbounded string and stay comparable with itself; and the full
/// bytes already live in the journal's recorded exchange, of which this is only
/// the excerpt. Two kilobytes is past anything a person reads to see *why* a
/// finding fired and short of where the string stops being an excerpt.
pub const MAX_EXCERPT_BYTES: usize = 2048;

/// The most distinct findings one subject — a single host or a single port —
/// retains.
///
/// Findings deduplicate by claim, so this bounds *distinct* claims, not
/// repetitions: a detection that fires the same claim a thousand times still
/// occupies one slot. What it guards against is the other direction — a flooding
/// detection, or a correlation against a service with a vast CVE history, making
/// one subject allocate without limit. Past the finding count of any real
/// subject and short of where the map becomes a denial-of-service on the report
/// it feeds.
pub const MAX_FINDINGS_PER_SUBJECT: usize = 256;

/// How bad a [`Finding`] is if it is true.
///
/// Ordered weakest-to-strongest, so a set of findings ranks by an ordinary
/// comparison and the worst rises to the top of a report. This is the *impact*
/// axis and it is deliberately independent of [`Confidence`], which is the
/// *certainty* axis: a finding can be [`Critical`](Self::Critical) and only
/// [`Probable`](Confidence::Probable), and a report that fuses the two into one
/// number can no longer say so.
///
/// The enum is `#[non_exhaustive]` so that adding a level costs a recompile
/// rather than a major version; [`ALL`](Self::ALL) is the list to iterate.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum Severity {
    /// Not a weakness — a fact worth surfacing. An unencrypted service that is
    /// meant to be unencrypted, a version banner, a reachable management port.
    Info,
    /// A weakness of little consequence on its own: information disclosure a
    /// determined attacker gains anyway, a hardening step left undone.
    Low,
    /// A real weakness with a real precondition — exploitable given a foothold,
    /// a position, or a second flaw to chain from.
    Medium,
    /// Directly exploitable, or a disclosure that hands an attacker materially
    /// more than they had.
    High,
    /// Remote code execution, an authentication bypass, or a compromise that
    /// needs nothing the internet does not already have.
    Critical,
}

impl Severity {
    /// The human label, capitalised for a report a person reads.
    ///
    /// Kept separate from the wire name (which lives in
    /// [`record::wire`](crate::record::wire)) for the reason every model enum
    /// keeps them apart: the label may be reworded whenever it reads better, and
    /// the wire name may never change without breaking every file already
    /// written.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }

    /// Projects onto the `0..=100` scale, mirroring
    /// [`Confidence::as_score`](crate::model::confidence::Confidence::as_score) so a
    /// caller can put impact and certainty on one bar. The numbers are tunable;
    /// the ordering is the invariant.
    pub const fn as_score(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 25,
            Self::Medium => 50,
            Self::High => 75,
            Self::Critical => 100,
        }
    }

    /// Every severity, weakest-first, for a caller that iterates rather than
    /// writing the list out.
    pub const ALL: [Severity; 5] = [
        Self::Info,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Critical,
    ];
}

/// The intrusiveness a detection ran under, recorded on the finding it produced.
///
/// Not part of what the finding *claims* — the same weakness reached passively
/// and then confirmed by an exploit is one finding, corroborated, not two — but
/// a fact about *how it was learned*, so a report can say a finding was drawn by
/// observation versus by an exploit that fired. The class a detection declares is
/// exactly the set of capabilities the operator's envelope will serve it, which
/// is what makes it an enforced boundary rather than a self-assigned label:
/// [`Passive`](Self::Passive) is served no way to touch the network at all.
///
/// Ordered least-to-most intrusive, so a policy can compare against a ceiling.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum DetectionClass {
    /// Reads only what the scan already gathered. No new traffic.
    Passive,
    /// Exchanges bytes with the scanned socket, within a byte budget. Reads;
    /// changes nothing.
    ActiveBenign,
    /// Causes a state change on the target — a write, a login that is logged, a
    /// test record left behind.
    ActiveMutating,
    /// Attempts to trigger the weakness, not merely to detect it.
    Exploit,
    /// May degrade the target's service.
    Dos,
}

impl DetectionClass {
    /// How a class is written for a person to read.
    ///
    /// Lowercase, by the rule
    /// [`NetworkRole::label`](crate::model::host::NetworkRole::label) writes
    /// down: an acronym is capitals and a word is not, so `exploit` is an
    /// ordinary noun and `DoS` is a name in initials. [`Severity::label`] beside
    /// it is Title Case, which is its own deliberate choice, so a report showing
    /// both axes shows `Critical` and `active-benign`. Two conventions, one per
    /// axis, and neither is a slip.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::ActiveBenign => "active-benign",
            Self::ActiveMutating => "active-mutating",
            Self::Exploit => "exploit",
            Self::Dos => "DoS",
        }
    }

    /// Every class, least-intrusive-first.
    pub const ALL: [DetectionClass; 5] = [
        Self::Passive,
        Self::ActiveBenign,
        Self::ActiveMutating,
        Self::Exploit,
        Self::Dos,
    ];
}

/// A detection's version — a provenance stamp that needs to be *ordered*, not a
/// package resolver's input.
///
/// "The newer detection's verdict wins" (which is how two accounts of one claim
/// reconcile in a merge) needs a comparison, so this is a real type rather than a
/// string. It is deliberately the common `major.minor.patch` subset of semver and
/// nothing more — no pre-release grammar, no build metadata — because a detection
/// version answers "which of these two is newer", and that is all. Hand-rolled so
/// that no version-parsing dependency enters the model.
///
/// The `Ord` derive compares `major`, then `minor`, then `patch`, in field order,
/// which is exactly the intended precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// The leading component, and the one that settles a comparison whenever
    /// two versions differ in it.
    pub major: u16,
    /// Breaks a tie on `major`.
    pub minor: u16,
    /// The last word, reached only where `major` and `minor` both agree.
    pub patch: u16,
}

impl Version {
    /// A version from its three components.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

/// Why a string is not a detection version.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("'{input}' is not a version: expected three dot-separated numbers, as in `1.2.3`")]
pub struct VersionParseError {
    /// What the caller wrote.
    pub input: String,
}

impl FromStr for Version {
    type Err = VersionParseError;

    /// Reads `"major.minor.patch"`.
    ///
    /// Strict on purpose: exactly three dot-separated unsigned integers, each in
    /// range. A version that will not parse is not guessed at, and a caller
    /// reading one from a file substitutes the earliest, least-trusted value
    /// rather than inventing a middle one, which `unwrap_or` says in one line.
    ///
    /// A [`FromStr`] rather than the inherent `parse` this used to be, because
    /// every other type in the model that reads itself from text is one, and an
    /// inherent method of that name invites a reader to expect
    /// `"1.2.3".parse::<Version>()` to work.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let fail = || VersionParseError {
            input: text.to_string(),
        };

        let mut parts = text.split('.');
        let mut number = || parts.next().ok_or_else(fail)?.parse().map_err(|_| fail());

        let major = number()?;
        let minor = number()?;
        let patch = number()?;
        if parts.next().is_some() {
            return Err(fail());
        }
        Ok(Self::new(major, minor, patch))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// An external reference a finding points at.
///
/// The *kind* is typed because that is what a consumer switches on — an NVD entry
/// for a CVE, a MITRE definition for a CWE, a bare link otherwise — and typing it
/// costs nothing and buys the export, sorting, and deduplication behaviour. The
/// payloads differ by kind: a CVE is an opaque identifier this vocabulary never
/// computes over, a CWE *is* a number (its canonical MITRE URL is built from it),
/// and a URL is arbitrary and untrusted.
///
/// `Ord` so a finding's references live in a [`BTreeSet`] — deduplicated, and
/// written in a stable order so two runs produce the same file.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reference {
    /// A CVE identifier, e.g. `CVE-2021-44228`. Validated for shape at
    /// construction, never parsed into fields.
    Cve(String),
    /// A CWE weakness number, e.g. `79` for `CWE-79`. The bare number, because
    /// the identifier is a number and its link is built from it.
    Cwe(u32),
    /// Any other reference — an advisory, a vendor bulletin. Untrusted, and
    /// rendered as inert escaped text on export, never as a live link target.
    Url(String),
}

impl Reference {
    /// A CVE reference, if `id` has the shape `CVE-YYYY-N` (a four-digit year and
    /// at least one digit of sequence). Returns [`None`] otherwise — a
    /// malformed identifier is not a reference.
    pub fn cve(id: impl Into<String>) -> Option<Self> {
        let id = id.into();
        is_cve_shaped(&id).then_some(Self::Cve(id))
    }

    /// A CWE reference from its number.
    pub const fn cwe(number: u32) -> Self {
        Self::Cwe(number)
    }

    /// An arbitrary URL reference.
    pub fn url(url: impl Into<String>) -> Self {
        Self::Url(url.into())
    }
}

/// Whether `id` reads as `CVE-<4 digits>-<1+ digits>`.
///
/// A hand-rolled shape check rather than a regex, because the model has no
/// business pulling a regex engine in to recognise one fixed prefix.
fn is_cve_shaped(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, seq)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && !seq.is_empty()
        && seq.bytes().all(|b| b.is_ascii_digit())
}

/// The bytes that made a detection fire, bounded and safe to carry everywhere.
///
/// A newtype rather than a bare `String` so that the [`MAX_EXCERPT_BYTES`] bound
/// is enforced at the one place a value is made — [`Excerpt::new`] — and cannot
/// be bypassed by a rebuild from a file or a value handed back from a sandboxed
/// module. Over-length input is *truncated*, never rejected: dropping a real
/// finding because its evidence ran long would be the wrong failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Excerpt(String);

impl Excerpt {
    /// An excerpt from `text`, truncated to [`MAX_EXCERPT_BYTES`] on a character
    /// boundary so the result is always valid UTF-8.
    pub fn new(text: impl Into<String>) -> Self {
        let mut text = text.into();
        if text.len() > MAX_EXCERPT_BYTES {
            let mut end = MAX_EXCERPT_BYTES;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        Self(text)
    }

    /// The excerpt text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the excerpt carries nothing.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Which detection produced a [`Finding`], to which version, from which bytes.
///
/// The provenance stamp the report records so a finding can be reproduced and
/// audited: an author-chosen `id`, a [`Version`] that can be ordered, and the
/// content hash of the detection body. The hash is carried as an opaque string —
/// the model does not compute it, the detection subsystem does — the same way a
/// certificate fingerprint is carried as a string rather than a typed digest.
///
/// The `id` is **untrusted input**: an author chose it, and it reaches exported
/// reports, so a consumer escapes it exactly as it escapes a scanned host's own
/// banner. The reservation of the `zond:` prefix for the engine's own built-in
/// detections is enforced where detections are *authored* — `build.rs` for the
/// ones this project ships, [`detect::flow::validate`](crate::detect::flow) for
/// the ones an operator writes — and not here, because the built-in correlator's
/// own id lives in that namespace.
///
/// It is not enforced on a report read back either, and that is not a gap in the
/// reservation so much as a fact about the document: everything in an imported
/// report is the document's claim, the host list included. Checking one prefix
/// there would suggest the rest had been verified.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DetectionId {
    id: String,
    version: Version,
    content_hash: String,
}

impl DetectionId {
    /// A detection identity, or [`FindingError::EmptyId`] if `id` is blank.
    ///
    /// The content hash is opaque and may be empty (a detection under development
    /// need not have one yet); the id may not, because a finding that cannot say
    /// what produced it is the unstructured blob this whole vocabulary replaces.
    pub fn new(
        id: impl Into<String>,
        version: Version,
        content_hash: impl Into<String>,
    ) -> Result<Self, FindingError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(FindingError::EmptyId);
        }
        Ok(Self {
            id,
            version,
            content_hash: content_hash.into(),
        })
    }

    /// The author-chosen identifier. Untrusted; escape before display.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The detection's version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The content hash of the detection body, or an empty string if none was
    /// recorded.
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }
}

/// What makes two findings *the same finding*: the detection that asserts it and
/// the thing it asserts.
///
/// A key that deliberately excludes the version, the hash, the confidence, the
/// severity, and the excerpt — for the reason the host's own `OsClaim` key
/// excludes its confidence and evidence: those are *how sure*, *which build*, and
/// *why*, none of which change *what is being claimed*. Keying on any of them
/// would let one claim in under several spellings, so a detection version bump
/// would double every finding in a merge instead of updating it in place.
///
/// The `subject` distinguishes two claims from the *same* detection: the CVE
/// identifier for a CVE finding, and the finding's title otherwise. The host or
/// port a finding hangs off is the other half of its identity, supplied by the
/// container it lives in rather than by the finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimId {
    detection: String,
    subject: String,
}

impl ClaimId {
    /// The producing detection's author-chosen id. Untrusted; escape before
    /// display.
    pub fn detection(&self) -> &str {
        &self.detection
    }

    /// What the claim is about: the first CVE identifier the finding
    /// references, or its title where it references none. Untrusted; escape
    /// before display.
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

/// One thing wrong with a scanned subject: a typed, provenance-tagged claim.
///
/// Every finding names the [`DetectionId`] that produced it, carries two
/// independent judgements ([`Severity`] and [`Confidence`]), holds a bounded
/// [`Excerpt`] of the bytes that justify it, and points at zero or more typed
/// [`Reference`]s. It is built through [`Finding::new`] and refined with the
/// `with_*` builders, so every finding — scanned, rebuilt from a file, or handed
/// back from a module — has passed the same checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    detection: DetectionId,
    title: String,
    severity: Severity,
    confidence: Confidence,
    class: DetectionClass,
    excerpt: Excerpt,
    references: BTreeSet<Reference>,
    remediation: Option<String>,
}

impl Finding {
    /// A finding from its required parts, or [`FindingError::EmptyTitle`] if
    /// `title` is blank.
    ///
    /// The excerpt starts empty, the reference set empty, and remediation absent;
    /// each is added with a builder below. Severity and confidence are separate
    /// arguments precisely because they are separate axes — neither is derived
    /// from the other.
    pub fn new(
        detection: DetectionId,
        title: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        class: DetectionClass,
    ) -> Result<Self, FindingError> {
        let title = title.into();
        if title.trim().is_empty() {
            return Err(FindingError::EmptyTitle);
        }
        Ok(Self {
            detection,
            title,
            severity,
            confidence,
            class,
            excerpt: Excerpt::default(),
            references: BTreeSet::new(),
            remediation: None,
        })
    }

    /// Adds a reference. Duplicates fold away and the set stays ordered, so two
    /// runs that found the same references write the same file.
    #[must_use]
    pub fn with_reference(mut self, reference: Reference) -> Self {
        self.references.insert(reference);
        self
    }

    /// Sets the justifying excerpt. Already bounded by [`Excerpt::new`].
    #[must_use]
    pub fn with_excerpt(mut self, excerpt: Excerpt) -> Self {
        self.excerpt = excerpt;
        self
    }

    /// Sets the remediation advice.
    #[must_use]
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// The detection that produced this finding.
    pub fn detection(&self) -> &DetectionId {
        &self.detection
    }

    /// The one-line title. Untrusted; escape before display.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// How bad this finding is if true.
    pub fn severity(&self) -> Severity {
        self.severity
    }

    /// How sure this finding is true.
    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// The intrusiveness the producing detection ran under.
    pub fn class(&self) -> DetectionClass {
        self.class
    }

    /// The bytes that justify this finding.
    pub fn excerpt(&self) -> &Excerpt {
        &self.excerpt
    }

    /// The external references, in sorted order.
    pub fn references(&self) -> impl Iterator<Item = &Reference> {
        self.references.iter()
    }

    /// The remediation advice, if any. Untrusted; escape before display.
    pub fn remediation(&self) -> Option<&str> {
        self.remediation.as_deref()
    }

    /// The key that decides whether this finding and another are the same claim.
    ///
    /// The producing detection's id, paired with the subject it discriminates on:
    /// the first (lowest, hence stable) CVE identifier this finding references,
    /// or its title where it references no CVE.
    pub fn claim_id(&self) -> ClaimId {
        let subject = self
            .references
            .iter()
            .find_map(|r| match r {
                Reference::Cve(id) => Some(id.clone()),
                _ => None,
            })
            .unwrap_or_else(|| self.title.clone());
        ClaimId {
            detection: self.detection.id.clone(),
            subject,
        }
    }

    /// Folds another account of the same claim into this one, keeping the
    /// stronger reading, and reports whether anything changed.
    ///
    /// Called when a detection asserts a claim a subject already carries: the
    /// same producer, the same [`claim_id`](Self::claim_id). The caller is
    /// trusted to have matched the claims first; folding two different claims
    /// would be a caller's error, not this method's to police.
    ///
    /// **A superseded detection does not supply the verdict.** Severity, title
    /// and class are what a detection concluded, and the [`DetectionId`] beside
    /// them is the record of which one concluded it. Taking the verdict from
    /// whichever account arrived second while taking the stamp only from a newer
    /// one put the two out of step: folding a `1.0.0` reading of a claim into a
    /// `2.0.0` one left a finding that read `2.0.0` and `Low` where `2.0.0` had
    /// said `Critical`, which is the one thing a provenance stamp exists to make
    /// impossible. Two reports written by two builds are enough to reach it, and
    /// the direction that loses is the common one, since the record being folded
    /// in is usually the older.
    ///
    /// So an account at a lower version supplies nothing but what is missing.
    ///
    /// **An account at the same version supplies the verdict**, and that is not
    /// the same question. One detection grading one claim differently on two
    /// occasions has read different evidence, not changed its mind, so the
    /// reading to keep is the current one. Which is current is
    /// [`merge`](crate::merge)'s to know: it folds documents in the order their
    /// own clocks give, so the account arriving here second is the later scan's,
    /// and a cipher that was `Low` in January and `Critical` in June is
    /// `Critical`. Nothing is out of step either way, the stamps being equal.
    ///
    /// Two things never follow the version. **Certainty rises whatever reached
    /// it**, because [`Confidence`] says how sure the claim is rather than what
    /// the claim is, and a second account agreeing is worth something whichever
    /// build produced it. **References union**, for the same reason
    /// [`Service::merge`](crate::model::port::Service::merge) unions CPEs: a
    /// reference is a pointer that applies, not a verdict that competes.
    ///
    /// The excerpt and the remediation travel with the verdict where there is
    /// one to take, and fill a gap where there is not.
    pub fn corroborate(&mut self, other: Finding) -> bool {
        // Destructured rather than reached through `other.…`, so a field added
        // to this struct is a compile error here and not a value that quietly
        // stops being folded.
        let Finding {
            detection,
            title,
            severity,
            confidence,
            class,
            excerpt,
            references,
            remediation,
        } = other;

        let mut changed = false;

        let stronger = self.confidence.max(confidence);
        if stronger != self.confidence {
            self.confidence = stronger;
            changed = true;
        }

        // Same claim means the same detection id, so the version is what orders
        // the two accounts.
        if detection.version >= self.detection.version {
            // Only a strictly newer detection replaces the stamp, and it brings
            // its own content hash with it. At the same version the hashes are
            // the same detection's, so the incumbent's stands.
            if detection.version > self.detection.version {
                self.detection = detection;
                changed = true;
            }

            if severity != self.severity {
                self.severity = severity;
                changed = true;
            }
            if title != self.title {
                self.title = title;
                changed = true;
            }
            if class != self.class {
                self.class = class;
                changed = true;
            }
            if !excerpt.is_empty() && excerpt != self.excerpt {
                self.excerpt = excerpt;
                changed = true;
            }
            if remediation.is_some() && remediation != self.remediation {
                self.remediation = remediation;
                changed = true;
            }
        } else {
            // Superseded. What it justified itself with is still better than
            // nothing where nothing is recorded, and cannot displace what is.
            if self.excerpt.is_empty() && !excerpt.is_empty() {
                self.excerpt = excerpt;
                changed = true;
            }
            if self.remediation.is_none() && remediation.is_some() {
                self.remediation = remediation;
                changed = true;
            }
        }

        for reference in references {
            changed |= self.references.insert(reference);
        }

        changed
    }
}

/// Why a [`Finding`] or a [`DetectionId`] could not be constructed.
///
/// Both cases are an empty identifier or title — a finding must be able to say
/// what produced it and what it claims, and a blank string says neither.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FindingError {
    /// A [`DetectionId`] was given a blank `id`.
    #[error("a detection id cannot be empty")]
    EmptyId,
    /// A [`Finding`] was given a blank title.
    #[error("a finding title cannot be empty")]
    EmptyTitle,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detection() -> DetectionId {
        DetectionId::new("redis-unauth-access", Version::new(1, 0, 0), "abc123").unwrap()
    }

    fn finding() -> Finding {
        Finding::new(
            detection(),
            "Unauthenticated Redis access",
            Severity::High,
            Confidence::Certain,
            DetectionClass::ActiveBenign,
        )
        .unwrap()
    }

    #[test]
    fn severity_orders_weakest_to_strongest() {
        // The whole reason Severity is an enum and not a number: a report ranks
        // by this order. A mutant that reorders the variants is caught here.
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
        assert_eq!(Severity::ALL.iter().max(), Some(&Severity::Critical));
        assert_eq!(Severity::Critical.as_score(), 100);
        assert_eq!(Severity::Info.as_score(), 0);
    }

    #[test]
    fn an_empty_title_is_refused() {
        // A finding that cannot say what it claims is the blob this replaces.
        let err = Finding::new(
            detection(),
            "   ",
            Severity::High,
            Confidence::Certain,
            DetectionClass::ActiveBenign,
        );
        assert_eq!(err, Err(FindingError::EmptyTitle));
    }

    #[test]
    fn an_empty_detection_id_is_refused() {
        let err = DetectionId::new("", Version::new(1, 0, 0), "hash");
        assert_eq!(err, Err(FindingError::EmptyId));
    }

    #[test]
    fn an_over_length_excerpt_is_truncated_on_a_char_boundary() {
        // A multi-byte char straddling the cap must not be split into invalid
        // UTF-8, and the result must be within the bound. A mutant that truncates
        // by byte index alone would panic or produce a broken string.
        let big = "é".repeat(MAX_EXCERPT_BYTES); // two bytes each — 2x over the cap
        let excerpt = Excerpt::new(big);
        assert!(excerpt.as_str().len() <= MAX_EXCERPT_BYTES);
        // Still valid UTF-8: as_str returning at all proves it, but assert the
        // last char is whole by round-tripping through chars.
        assert!(excerpt.as_str().chars().all(|c| c == 'é'));
    }

    #[test]
    fn a_short_excerpt_is_kept_verbatim() {
        let excerpt = Excerpt::new("redis_version:7.2.4");
        assert_eq!(excerpt.as_str(), "redis_version:7.2.4");
    }

    #[test]
    fn references_dedup_and_sort() {
        // Held in a BTreeSet so two runs write the same file. A mutant using a
        // Vec would keep the duplicate and the insertion order.
        let f = finding()
            .with_reference(Reference::cwe(306))
            .with_reference(Reference::cwe(306))
            .with_reference(Reference::cve("CVE-2021-44228").unwrap());
        let refs: Vec<_> = f.references().cloned().collect();
        assert_eq!(refs.len(), 2, "the duplicate CWE must fold away");
        // Cve sorts before Cwe by variant order, so the CVE leads.
        assert_eq!(refs[0], Reference::Cve("CVE-2021-44228".to_string()));
    }

    #[test]
    fn a_malformed_cve_is_not_a_reference() {
        assert!(Reference::cve("CVE-2021-44228").is_some());
        assert!(Reference::cve("not-a-cve").is_none());
        assert!(Reference::cve("CVE-21-44228").is_none()); // year not four digits
        assert!(Reference::cve("CVE-2021-").is_none()); // no sequence
    }

    #[test]
    fn version_parses_and_orders_numerically() {
        assert_eq!("8.3.1".parse(), Ok(Version::new(8, 3, 1)));
        assert!("8.3".parse::<Version>().is_err());
        assert!("8.3.1.0".parse::<Version>().is_err());
        assert!("8.x.1".parse::<Version>().is_err());
        // The order is component-wise numeric, not lexicographic: 8.10 > 8.3.
        assert!(Version::new(8, 10, 0) > Version::new(8, 3, 1));
    }

    #[test]
    fn claim_id_keys_on_cve_when_present_else_title() {
        // Two versions of the same CVE detection are the same claim, so a merge
        // updates in place rather than doubling. The version is not in the key.
        let v1 = finding().with_reference(Reference::cve("CVE-2021-44228").unwrap());
        let newer = Finding::new(
            DetectionId::new("redis-unauth-access", Version::new(2, 0, 0), "def456").unwrap(),
            "A reworded title",
            Severity::Critical,
            Confidence::Strong,
            DetectionClass::ActiveBenign,
        )
        .unwrap()
        .with_reference(Reference::cve("CVE-2021-44228").unwrap());
        assert_eq!(v1.claim_id(), newer.claim_id());

        // With no CVE, the title is the discriminator instead.
        let by_title = finding();
        assert_eq!(
            by_title.claim_id(),
            ClaimId {
                detection: "redis-unauth-access".to_string(),
                subject: "Unauthenticated Redis access".to_string(),
            }
        );
    }

    #[test]
    fn corroborate_takes_the_stronger_and_newer_reading() {
        // The same claim, reached again by a newer version that re-scored the
        // severity up and carries a second reference. Certainty must only rise;
        // the newer verdict must win; the references must union.
        let mut base = finding() // High / Certain, v1.0.0
            .with_reference(Reference::cve("CVE-2022-0543").unwrap());
        let newer = Finding::new(
            DetectionId::new("redis-unauth-access", Version::new(1, 1, 0), "newhash").unwrap(),
            "Unauthenticated Redis access",
            Severity::Critical, // re-scored up
            Confidence::Strong, // weaker than Certain — must not lower it
            DetectionClass::ActiveBenign,
        )
        .unwrap()
        .with_reference(Reference::cve("CVE-2022-0543").unwrap()) // same claim
        .with_reference(Reference::cwe(306))
        .with_remediation("Require a password.");
        assert_eq!(base.claim_id(), newer.claim_id());

        assert!(base.corroborate(newer));
        assert_eq!(base.severity(), Severity::Critical, "newer severity wins");
        assert_eq!(
            base.confidence(),
            Confidence::Certain,
            "confidence only rises"
        );
        assert_eq!(base.detection().version(), Version::new(1, 1, 0));
        assert_eq!(base.remediation(), Some("Require a password."));
        let refs: Vec<_> = base.references().cloned().collect();
        assert_eq!(refs.len(), 2, "references union, not replace");
        assert!(refs.contains(&Reference::Cwe(306)));
    }

    /// The direction nothing was checking, and the one a merge usually takes.
    ///
    /// A record being folded in is normally the older of the two: a journal read
    /// back into a newer run, or a report written by an earlier build. The
    /// verdict was taken from whichever account arrived second and the stamp
    /// only from a newer one, so an older reading landed under a newer version's
    /// name. The finding then said `2.0.0` produced a `Low`, where `2.0.0` had
    /// said `Critical` and `1.0.0` had said `Low`, and nothing in the document
    /// showed which had happened.
    #[test]
    fn an_older_account_does_not_supply_a_newer_versions_verdict() {
        let account = |version: Version, severity: Severity, title: &str| {
            Finding::new(
                DetectionId::new("redis-unauth-access", version, "hash").unwrap(),
                title,
                severity,
                Confidence::Probable,
                DetectionClass::ActiveBenign,
            )
            .unwrap()
        };

        let mut current = account(
            Version::new(2, 0, 0),
            Severity::Critical,
            "Redis, wide open",
        );
        let superseded = account(Version::new(1, 0, 0), Severity::Low, "Redis reachable");

        current.corroborate(superseded);

        assert_eq!(current.detection().version(), Version::new(2, 0, 0));
        assert_eq!(
            current.severity(),
            Severity::Critical,
            "the stamp and the verdict have to name one version"
        );
        assert_eq!(current.title(), "Redis, wide open");
    }

    /// One detection at one version grading a claim two ways has read two lots
    /// of evidence, so the account arriving second stands.
    ///
    /// The counterpart of the test above and a different question from it. That
    /// one is about two *detections*, settled by which of them is superseded;
    /// this is about two *readings* by one detection, where nothing supersedes
    /// anything and the one to keep is the current one.
    ///
    /// Which is current is [`merge`](crate::merge)'s to know, and it folds
    /// documents in the order their own clocks give. `merge`'s
    /// `two_accounts_of_one_host_keep_every_claim_and_grade_it_as_the_newer_did`
    /// is this rule read from the other end: a cipher graded `Low` in January
    /// and `Critical` in June is `Critical`.
    #[test]
    fn an_account_at_the_same_version_supplies_the_current_reading() {
        let account = |severity: Severity| {
            Finding::new(
                DetectionId::new("tls-weak-cipher", Version::new(1, 0, 0), "hash").unwrap(),
                "a weak cipher is offered",
                severity,
                Confidence::Probable,
                DetectionClass::Passive,
            )
            .unwrap()
        };

        let mut january = account(Severity::Low);
        assert!(january.corroborate(account(Severity::Critical)));
        assert_eq!(january.severity(), Severity::Critical);

        // And a claim that was downgraded is downgraded. The later reading is
        // kept because it is later, not because it is worse.
        let mut worse_before = account(Severity::Critical);
        assert!(worse_before.corroborate(account(Severity::Low)));
        assert_eq!(worse_before.severity(), Severity::Low);

        // The stamp does not move, there being nothing newer to move it to.
        assert_eq!(january.detection().version(), Version::new(1, 0, 0));
    }

    /// A superseded account still justifies itself, and that is worth keeping
    /// where the record has nothing.
    #[test]
    fn an_older_account_fills_a_gap_it_cannot_overwrite() {
        let account = |version: Version| {
            Finding::new(
                DetectionId::new("redis-unauth-access", version, "hash").unwrap(),
                "Unauthenticated Redis access",
                Severity::High,
                Confidence::Probable,
                DetectionClass::ActiveBenign,
            )
            .unwrap()
        };

        let mut current = account(Version::new(2, 0, 0));
        let older = account(Version::new(1, 0, 0))
            .with_excerpt(Excerpt::new("-ERR unknown command"))
            .with_remediation("Require a password.");

        assert!(current.corroborate(older), "a gap was filled");
        assert_eq!(current.excerpt().as_str(), "-ERR unknown command");
        assert_eq!(current.remediation(), Some("Require a password."));

        // But it does not displace an excerpt the newer account already carried.
        let mut carrying = account(Version::new(2, 0, 0)).with_excerpt(Excerpt::new("READONLY"));
        carrying.corroborate(account(Version::new(1, 0, 0)).with_excerpt(Excerpt::new("older")));
        assert_eq!(carrying.excerpt().as_str(), "READONLY");
    }

    #[test]
    fn corroborate_reports_no_change_for_an_identical_refiring() {
        // A detection firing the same claim twice is not new information — the
        // signal a subject uses to know a finding was already recorded.
        let mut base = finding();
        assert!(!base.corroborate(finding()));
    }
}
