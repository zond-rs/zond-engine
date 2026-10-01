// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What is wrong with what is running
//!
//! [`Evidence`](crate::fingerprint::Evidence) says what is running on a port and a
//! [`Finding`] says what is wrong with it. Every kind of detection (a signature, a
//! declarative flow, a sandboxed module, the built-in CVE correlator) produces this one
//! type, so they compose without knowing about one another.
//!
//! A finding is a **positive claim, backed by evidence, about a subject the scan
//! already holds**: a vulnerable service on a port, a weakness inferred across a host.
//! The [`Host`](crate::model::host) or [`Port`](crate::model::port) it is about carries
//! it. An absent finding is not a claim that the subject is clean: the detection did not
//! run, or ran and did not fire.
//!
//! ## Two axes
//!
//! - [`Severity`]: how bad it is if true.
//! - [`Confidence`]: how sure it is true, the same trust vocabulary fingerprinting uses.
//!
//! A single "risk" number cannot say *Critical but unverified*, which is the common
//! case: a distribution backports a security fix without moving the version string, so
//! a version-matched CVE is severe and uncertain at once.
//!
//! ## Provenance
//!
//! A finding always names the [`DetectionId`] that produced it: an id, a [`Version`],
//! and the content hash of the detection body. The report records that stamp, so a
//! finding stays reproducible and auditable after the scan, and a detection from a
//! stranger can still answer for itself.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::model::confidence::Confidence;
use crate::model::port::Build;

/// The most justifying text a finding retains, in bytes.
///
/// The excerpt is target-controlled and travels into every export and journal, so it is
/// bounded: a multi-megabyte banner would be a denial of service on the report. The full
/// bytes live in the journal's recorded exchange. Two kilobytes is more than a person
/// reads to see why a finding fired.
pub const MAX_EXCERPT_BYTES: usize = 2048;

/// The most distinct findings one subject, meaning a single host or a single
/// port, retains.
///
/// Findings deduplicate by claim, so a claim fired a thousand times occupies one slot.
/// This bounds a flooding detection, or a correlation against a service with a vast CVE
/// history. Above the finding count of any real subject.
pub const MAX_FINDINGS_PER_SUBJECT: usize = 256;

/// How bad a [`Finding`] is if it is true.
///
/// Ordered weakest to strongest, so findings rank by ordinary comparison. Independent of
/// [`Confidence`]: a finding can be [`Critical`](Self::Critical) and only
/// [`Probable`](Confidence::Probable). [`ALL`](Self::ALL) is the list to iterate.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum Severity {
    /// A fact worth surfacing: an unencrypted service meant to be unencrypted, a
    /// version banner, a reachable management port.
    Info,
    /// A weakness of little consequence on its own: information disclosure a
    /// determined attacker gains anyway, a hardening step left undone.
    Low,
    /// A real weakness with a real precondition, exploitable given a foothold, a
    /// position, or a second flaw to chain from.
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
    /// Separate from the wire name in [`record::wire`](crate::record::wire): the label
    /// may be reworded, the wire name may not.
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

    /// Every severity, weakest first.
    pub const ALL: &'static [Self] = &[
        Self::Info,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Critical,
    ];
}

/// The intrusiveness a detection ran under, recorded on the finding it produced.
///
/// How the finding was learned, not part of its claim: a weakness seen passively and
/// then confirmed by an exploit is one finding. The class a detection declares is
/// exactly the set of capabilities the operator's envelope serves it, so it is
/// enforced: [`Passive`](Self::Passive) is given no way to touch the network.
///
/// Ordered least to most intrusive, so a policy can compare against a ceiling.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum DetectionClass {
    /// Reads only what the scan already gathered. No new traffic.
    Passive,
    /// Exchanges bytes with the scanned socket, within a byte budget. Reads;
    /// changes nothing.
    ActiveBenign,
    /// Causes a state change on the target: a write, a login that is logged, a
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
    /// Lowercase except acronyms, by the rule
    /// [`NetworkRole::label`](crate::model::host::NetworkRole::label) describes: so
    /// `exploit` and `DoS`. [`Severity::label`] is Title Case, so a report showing both
    /// axes shows `Critical` and `active-benign`.
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
    pub const ALL: &'static [Self] = &[
        Self::Passive,
        Self::ActiveBenign,
        Self::ActiveMutating,
        Self::Exploit,
        Self::Dos,
    ];
}

/// A detection's version, ordered so two accounts of one claim can reconcile in a merge
/// ("the newer detection's verdict wins").
///
/// The `major.minor.patch` subset of semver, with no pre-release or build metadata,
/// since it only has to say which of two is newer. `Ord` compares `major`, then
/// `minor`, then `patch`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// The leading component.
    pub major: u16,
    /// Breaks a tie on `major`.
    pub minor: u16,
    /// Breaks a tie on `major` and `minor`.
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
#[non_exhaustive]
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
    /// Strict: exactly three dot-separated unsigned integers, each in range. A caller
    /// reading one from a file substitutes the earliest, least-trusted value on
    /// failure.
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
/// Typed by kind, which is what a consumer switches on: an NVD entry for a CVE, a MITRE
/// definition for a CWE, or a bare link. A CVE is an opaque identifier, a CWE is a
/// number (its MITRE URL is built from it), and a URL is arbitrary and untrusted.
///
/// `Ord` because a claim key needs the lowest CVE a finding carries; see
/// [`Finding::claim_id`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reference {
    /// A CVE identifier, e.g. `CVE-2021-44228`. Validated for shape at
    /// construction, never parsed into fields.
    Cve(String),
    /// A CWE weakness number, e.g. `79` for `CWE-79`.
    Cwe(u32),
    /// Any other reference, such as an advisory or a vendor bulletin. Untrusted, and
    /// exported as inert escaped text, not a live link.
    Url(String),
}

impl Reference {
    /// A CVE reference, if `id` has the shape `CVE-YYYY-N` (a four-digit year and
    /// at least one digit of sequence). Returns [`None`] otherwise, since a
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
/// A hand-rolled shape check, so the model needs no regex engine.
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

/// What a finding is one of, where several detections cover one weakness
/// between them.
///
/// Four detections reading an SSH server's KEXINIT may each flag something different: a
/// cipher, a host key, a key exchange, a MAC. They stay four findings, each separately
/// true and separately fixed, but to a reader they are one sentence. A detection may
/// declare its group and how the group reads as a whole; what a front end does with
/// that is up to it, and nothing merges.
///
/// Both halves are author-chosen and untrusted, like the detection's id and title.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FindingGroup {
    id: String,
    summary: String,
}

impl FindingGroup {
    /// A group from its identity and how it reads, or
    /// [`FindingError::EmptyGroup`] if either is blank.
    ///
    /// The summary is a plural noun phrase a count can lead: `weak SSH algorithms
    /// offered`, so four read as *4 weak SSH algorithms offered*. This is not checked.
    pub fn new(id: impl Into<String>, summary: impl Into<String>) -> Result<Self, FindingError> {
        let id = id.into();
        let summary = summary.into();
        if id.trim().is_empty() || summary.trim().is_empty() {
            return Err(FindingError::EmptyGroup);
        }
        Ok(Self { id, summary })
    }

    /// The author-chosen identity every member shares. Untrusted; escape before
    /// display.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// How the group reads when its members are spoken of as one. Untrusted;
    /// escape before display.
    pub fn summary(&self) -> &str {
        &self.summary
    }
}

/// The bytes that made a detection fire, bounded and safe to carry everywhere.
///
/// A newtype, so the [`MAX_EXCERPT_BYTES`] bound is enforced at [`Excerpt::new`] and
/// cannot be bypassed by a rebuild from a file or a value from a sandboxed module.
/// Over-length input is truncated, so a real finding is never dropped for long
/// evidence.
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
/// The provenance stamp the report records: an author-chosen `id`, an ordered
/// [`Version`], and the content hash of the detection body. The hash is an opaque
/// string computed by the detection subsystem.
///
/// The `id` is **untrusted input** that reaches exported reports, so escape it like a
/// scanned host's banner. The `zond:` prefix is reserved for built-in detections,
/// enforced where detections are authored: by `build.rs` for those this project ships
/// and by [`detect::flow::validate`](crate::detect::flow) for an operator's. It is not
/// enforced here, since the built-in correlator's id lives in that namespace, nor on a
/// report read back, where everything is the document's own claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DetectionId {
    id: String,
    version: Version,
    content_hash: String,
}

impl DetectionId {
    /// A detection identity, or [`FindingError::EmptyId`] if `id` is blank.
    ///
    /// The content hash is opaque and may be empty (a detection under development need
    /// not have one); the id may not.
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

/// Which of a finding's vulnerabilities are known to be exploited in the wild,
/// and whose list says so.
///
/// Separate from the verdict: exploitation in the wild says nothing about whether this
/// host is affected ([`Confidence`]) or how bad it would be ([`Severity`]). It tells a
/// reader which claims to work through first, so it raises neither axis; a front end
/// marks and orders by it.
///
/// Stamped with the list that said so (CISA's by default), since that is someone
/// else's data on someone else's schedule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Exploitation {
    by: DetectionId,
    cves: Vec<String>,
}

impl Exploitation {
    /// The CVE identifiers among `cves` that `by` lists as exploited, in the
    /// order given and without repeats, or [`FindingError::NoExploitedCve`]
    /// where none of them is one.
    ///
    /// Anything not shaped like a CVE identifier is left out, as with
    /// [`Reference::cve`].
    pub fn new(
        by: DetectionId,
        cves: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, FindingError> {
        let mut kept: Vec<String> = Vec::new();
        for cve in cves {
            let cve = cve.into();
            if is_cve_shaped(&cve) && !kept.contains(&cve) {
                kept.push(cve);
            }
        }
        if kept.is_empty() {
            return Err(FindingError::NoExploitedCve);
        }
        Ok(Self { by, cves: kept })
    }

    /// The list that names them exploited: its identity, version and content
    /// hash. Untrusted; escape before display.
    pub fn by(&self) -> &DetectionId {
        &self.by
    }

    /// The finding's vulnerabilities the list names, in the order the finding
    /// cites them. Never empty.
    pub fn cves(&self) -> impl Iterator<Item = &str> {
        self.cves.iter().map(String::as_str)
    }
}

/// What makes two findings *the same finding*: the detection that asserts it and
/// the thing it asserts.
///
/// Excludes the version, hash, confidence, severity and excerpt (as the host's `OsClaim`
/// key excludes confidence and evidence): they say how sure, which build and why, not
/// what is claimed. Otherwise a detection version bump would double every finding in a
/// merge.
///
/// The `subject` distinguishes two claims from the *same* detection: the CVE identifier
/// for a CVE finding, the title otherwise. The host or port holding the finding is the
/// other half of its identity.
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
/// [`Reference`]s. Built through [`Finding::new`] and the `with_*` builders, so every
/// finding passes the same checks whether scanned, rebuilt from a file, or returned by
/// a module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    detection: DetectionId,
    title: String,
    severity: Severity,
    confidence: Confidence,
    class: DetectionClass,
    excerpt: Excerpt,
    /// In the order the detection added them, deduplicated.
    ///
    /// Order carries meaning: a vulnerability correlation cites the worst first, and a
    /// front end with room for three of forty-four wants those three. Two runs still
    /// write the same file, since the producer is deterministic.
    references: Vec<Reference>,
    remediation: Option<String>,
    /// The platform identifiers the finding was drawn from, for one a
    /// vulnerability correlation drew from a service's CPEs, ascending.
    ///
    /// A correlation rests on the identification it matched, and [`merge`](crate::merge)
    /// asks whether a newer scan still backs it before carrying the finding forward.
    /// The excerpt is for people, and the detection id names a catalogue, so this is
    /// a field.
    ///
    /// A set, because a service may carry two identifiers for one release (an
    /// imported document's URI form beside its 2.3 form), and the claim is backed
    /// while any of them is.
    cpes: BTreeSet<String>,
    /// What the claim is about, where the detection names it outright. See
    /// [`claim_id`](Self::claim_id).
    subject: Option<String>,
    /// The distribution build a correlation judged, for one drawn from a
    /// service that carried one.
    ///
    /// The claim rests on it, as on [`cpes`](Self::cpes). A distribution ships fixes as
    /// new package revisions of the same upstream version, so an upgrade moves only
    /// this, and [`merge`](crate::merge) has to see it move.
    build: Option<Build>,
    /// What this finding is one of, where its detection declared a
    /// [`FindingGroup`]. Most detections declare none.
    group: Option<FindingGroup>,
    /// The distributor's advisory data a correlation consulted, where it
    /// consulted any.
    ///
    /// A second stamp beside [`detection`](Self::detection). A verdict on a
    /// distribution's build uses two datasets: the catalogue says which
    /// vulnerabilities the upstream release has, and the distributor's data which of
    /// them its build still carries. This records which snapshot of the second was
    /// used.
    advised_by: Option<DetectionId>,
    /// Which of the vulnerabilities it cites are known to be exploited, where
    /// the correlation that drew it consulted a list naming any.
    exploitation: Option<Exploitation>,
}

impl Finding {
    /// A finding from its required parts, or [`FindingError::EmptyTitle`] if
    /// `title` is blank.
    ///
    /// The excerpt, references and remediation start empty and are added with the
    /// builders below.
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
            references: Vec::new(),
            remediation: None,
            cpes: BTreeSet::new(),
            subject: None,
            build: None,
            advised_by: None,
            exploitation: None,
            group: None,
        })
    }

    /// Adds a reference, keeping the order they arrive in. A duplicate folds
    /// away, so two runs that found the same references write the same file.
    #[must_use]
    pub fn with_reference(mut self, reference: Reference) -> Self {
        if !self.references.contains(&reference) {
            self.references.push(reference);
        }
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

    /// Adds a platform identifier the finding was drawn from.
    ///
    /// For a correlation, which draws a finding from a CPE a service carries. Adding
    /// one already named changes nothing.
    #[must_use]
    pub fn with_cpe(mut self, cpe: impl Into<String>) -> Self {
        self.cpes.insert(cpe.into());
        self
    }

    /// Names what the claim is about, which [`claim_id`](Self::claim_id)
    /// then keys on in place of the references.
    ///
    /// For a detection whose findings summarise a changing set of references, as a
    /// correlation's do, so the claim does not rename itself when the data changes.
    #[must_use]
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Records the distribution build a correlation judged.
    #[must_use]
    pub fn with_build(mut self, build: Build) -> Self {
        self.build = Some(build);
        self
    }

    /// Records the distributor's advisory data a correlation consulted.
    #[must_use]
    pub fn with_advised_by(mut self, advised_by: DetectionId) -> Self {
        self.advised_by = Some(advised_by);
        self
    }

    /// Records which of the vulnerabilities it cites are known to be
    /// exploited.
    #[must_use]
    pub fn with_exploitation(mut self, exploitation: Exploitation) -> Self {
        self.exploitation = Some(exploitation);
        self
    }

    /// Records which group of findings this one belongs to.
    #[must_use]
    pub fn with_group(mut self, group: FindingGroup) -> Self {
        self.group = Some(group);
        self
    }

    /// What this finding is one of, where its detection declared a group.
    pub fn group(&self) -> Option<&FindingGroup> {
        self.group.as_ref()
    }

    /// What the claim is about, where the detection named it. Untrusted.
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// The distribution build a correlation judged, if it judged one.
    pub fn build(&self) -> Option<&Build> {
        self.build.as_ref()
    }

    /// The distributor's advisory data a correlation consulted, if any.
    pub fn advised_by(&self) -> Option<&DetectionId> {
        self.advised_by.as_ref()
    }

    /// Which of the vulnerabilities it cites are known to be exploited, if a
    /// list consulted names any.
    pub fn exploitation(&self) -> Option<&Exploitation> {
        self.exploitation.as_ref()
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

    /// The external references, in the order the detection stated them, which is
    /// most-relevant-first where it had an order to state.
    pub fn references(&self) -> impl Iterator<Item = &Reference> {
        self.references.iter()
    }

    /// The remediation advice, if any. Untrusted; escape before display.
    pub fn remediation(&self) -> Option<&str> {
        self.remediation.as_deref()
    }

    /// The platform identifiers a correlation drew this finding from,
    /// ascending, and none for a finding drawn from anything else. Untrusted: a
    /// scanned host's banner chose them, so escape before display.
    ///
    /// Each draws the same claim, so it stands while any of them still identifies the
    /// endpoint.
    pub fn cpes(&self) -> impl Iterator<Item = &str> {
        self.cpes.iter().map(String::as_str)
    }

    /// Whether a correlation drew this finding, which is whether it names a
    /// platform identifier it rests on.
    pub(crate) fn is_correlation(&self) -> bool {
        !self.cpes.is_empty()
    }

    /// The key that decides whether this finding and another are the same claim.
    ///
    /// The producing detection's id, paired with the subject it discriminates on:
    /// the [`subject`](Self::subject) the detection named where it named one,
    /// otherwise the lowest CVE identifier this finding references, or its
    /// title where it references none.
    ///
    /// The lowest, not the first: a correlation states its worst first, which changes
    /// when the catalogue does, so keying on the first would rename the claim after a
    /// data refresh and a diff of an unchanged host would show one finding gone and
    /// another arrived.
    pub fn claim_id(&self) -> ClaimId {
        let subject = self.subject.clone().unwrap_or_else(|| {
            self.references
                .iter()
                .filter_map(|r| match r {
                    Reference::Cve(id) => Some(id.clone()),
                    _ => None,
                })
                .min()
                .unwrap_or_else(|| self.title.clone())
        });
        ClaimId {
            detection: self.detection.id.clone(),
            subject,
        }
    }

    /// Folds another account of the same claim into this one, keeping the
    /// stronger reading, and reports whether anything changed.
    ///
    /// Called when a detection asserts a claim a subject already carries: the same
    /// producer and [`claim_id`](Self::claim_id). The caller must have matched the
    /// claims.
    ///
    /// The verdict (severity, title, class) follows the version, so it stays in step
    /// with the [`DetectionId`] that records who concluded it:
    ///
    /// - An account at a **lower** version supplies only what is missing. Otherwise
    ///   folding a `1.0.0` reading into a `2.0.0` one would leave `2.0.0` stamped on
    ///   `1.0.0`'s `Low`. This is the common direction, since the record folded in is
    ///   usually the older.
    /// - An account at the **same** version supplies the verdict: one detection
    ///   grading a claim differently twice has read different evidence, and the later
    ///   reading wins. [`merge`](crate::merge) folds documents in the order their own
    ///   clocks give, so a cipher `Low` in January and `Critical` in June is `Critical`.
    /// - A **newer** version supplies the verdict and its own stamp.
    ///
    /// Regardless of version, **certainty only rises**, since a second agreeing account
    /// is worth something whichever build produced it, and **references and platform
    /// identifiers union**, as [`Service::merge`](crate::model::port::Service::merge)
    /// unions CPEs. Keeping one identifier would have a merge drop the claim once a
    /// newer scan backed only the other.
    ///
    /// **Except for correlations**, whose certainty and references are part of the
    /// verdict. A correlation is a computation over a service identification and the
    /// datasets behind it, and a later one that cites fewer vulnerabilities, or holds
    /// them less surely, has usually learned some do not apply to this build. Unioning
    /// would carry every vulnerability ever cited into every later report at the surest
    /// grade ever given. So an account of a correlation at the same version or newer
    /// replaces the certainty, references, build, advisory stamp and exploitation
    /// outright, and an older one supplies none of them.
    ///
    /// The excerpt and remediation travel with the verdict where one is taken, and
    /// otherwise fill a gap.
    pub fn corroborate(&mut self, other: Finding) -> bool {
        // Both must be correlations: a finding rebuilt from a file that lost its
        // identifiers is treated as the observation it looks like.
        let correlation = self.is_correlation() && other.is_correlation();

        // Destructured, so a new field fails to compile until it is folded.
        let Finding {
            detection,
            title,
            severity,
            confidence,
            class,
            excerpt,
            references,
            remediation,
            cpes,
            subject,
            build,
            advised_by,
            exploitation,
            group,
        } = other;

        let mut changed = false;
        let at_least_as_new = detection.version >= self.detection.version;

        if correlation {
            // A correlation's verdict comes whole from an account at least as new.
            if at_least_as_new {
                if confidence != self.confidence {
                    self.confidence = confidence;
                    changed = true;
                }
                if references != self.references {
                    self.references = references;
                    changed = true;
                }
                if build != self.build {
                    self.build = build;
                    changed = true;
                }
                if advised_by != self.advised_by {
                    self.advised_by = advised_by;
                    changed = true;
                }
                if exploitation != self.exploitation {
                    self.exploitation = exploitation;
                    changed = true;
                }
            }
        } else {
            let stronger = self.confidence.max(confidence);
            if stronger != self.confidence {
                self.confidence = stronger;
                changed = true;
            }
            for reference in references {
                if !self.references.contains(&reference) {
                    self.references.push(reference);
                    changed = true;
                }
            }
            if self.build.is_none() && build.is_some() {
                self.build = build;
                changed = true;
            }
            if self.advised_by.is_none() && advised_by.is_some() {
                self.advised_by = advised_by;
                changed = true;
            }
            if self.exploitation.is_none() && exploitation.is_some() {
                self.exploitation = exploitation;
                changed = true;
            }
        }

        // Both accounts share the subject; one that named it fills one that did not.
        if self.subject.is_none() && subject.is_some() {
            self.subject = subject;
            changed = true;
        }

        // The group belongs to the detection. A newer account carrying it moves a
        // finding recorded before the detection joined the group onto it.
        if at_least_as_new && group.is_some() && group != self.group {
            self.group = group;
            changed = true;
        }

        // Same claim means the same detection id, so the version orders them.
        if at_least_as_new {
            // Only a strictly newer detection replaces the stamp and content hash.
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
            // Superseded: its justification only fills a gap.
            if self.excerpt.is_empty() && !excerpt.is_empty() {
                self.excerpt = excerpt;
                changed = true;
            }
            if self.remediation.is_none() && remediation.is_some() {
                self.remediation = remediation;
                changed = true;
            }
        }

        for cpe in cpes {
            changed |= self.cpes.insert(cpe);
        }

        changed
    }
}

/// Where one account of a subject leaves a claim drawn from another account's
/// evidence.
///
/// Asked only of a finding a built-in derivation draws from evidence the report records
/// beside it, such as what a TLS endpoint accepts. For other findings, absence from a
/// later scan only means the detection did not fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Standing {
    /// The account draws the same claim from its own evidence.
    Upheld,
    /// The account settled everything the claim rests on and does not draw it.
    Overturned,
    /// The account left part of what the claim rests on unsettled, so it
    /// neither draws the claim nor refutes it.
    Unsettled,
}

/// Why a [`Finding`] or a [`DetectionId`] could not be constructed.
///
/// Every case is an empty identifier, title, phrase or list.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FindingError {
    /// A [`DetectionId`] was given a blank `id`.
    #[error("a detection id cannot be empty")]
    EmptyId,
    /// A [`Finding`] was given a blank title.
    #[error("a finding title cannot be empty")]
    EmptyTitle,
    /// A [`FindingGroup`] was given a blank id or a blank summary.
    #[error("a finding group needs both an id and a summary")]
    EmptyGroup,
    /// An [`Exploitation`] was given no CVE identifier.
    #[error("an exploitation needs at least one CVE identifier")]
    NoExploitedCve,
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

    /// A correlation at the same version or newer replaces the earlier one's verdict,
    /// certainty and citations included.
    #[test]
    fn a_correlations_later_account_replaces_its_certainty_and_citations() {
        let correlation = |version: u16, confidence: Confidence, cves: &[&str]| {
            let mut finding = Finding::new(
                DetectionId::new("zond:cve-kev", Version::new(0, version, 0), "h").unwrap(),
                "OpenSSH 6.6.1p1",
                Severity::Critical,
                confidence,
                DetectionClass::Passive,
            )
            .unwrap()
            .with_cpe("cpe:/a:openbsd:openssh:6.6.1p1")
            .with_subject("openbsd:openssh:6.6.1p1@ubuntu-14.04/build-unchecked");
            for cve in cves {
                finding = finding.with_reference(Reference::cve(*cve).unwrap());
            }
            finding
        };

        let mut held = correlation(
            3,
            Confidence::Probable,
            &["CVE-2016-1908", "CVE-2023-38408"],
        );
        assert!(held.corroborate(correlation(3, Confidence::Weak, &["CVE-2023-38408"])));
        assert_eq!(held.confidence(), Confidence::Weak);
        assert_eq!(held.references().count(), 1);

        // An older correlator's account gives nothing.
        held.corroborate(correlation(2, Confidence::Certain, &["CVE-2016-1908"]));
        assert_eq!(held.confidence(), Confidence::Weak);
        assert_eq!(held.references().count(), 1);

        // An observation still ratchets.
        let mut observed = finding();
        let mut weaker = finding();
        weaker.confidence = Confidence::Weak;
        observed.corroborate(weaker);
        assert_eq!(observed.confidence(), Confidence::Certain);
    }

    #[test]
    fn severity_orders_weakest_to_strongest() {
        // A report ranks by this order.
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
        // A finding must say what it claims.
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
        // A multi-byte char straddling the cap must not be split into invalid UTF-8,
        // and the result must be within the bound.
        let big = "é".repeat(MAX_EXCERPT_BYTES); // two bytes each, so twice the cap
        let excerpt = Excerpt::new(big);
        assert!(excerpt.as_str().len() <= MAX_EXCERPT_BYTES);
        // The last char is whole.
        assert!(excerpt.as_str().chars().all(|c| c == 'é'));
    }

    #[test]
    fn a_short_excerpt_is_kept_verbatim() {
        let excerpt = Excerpt::new("redis_version:7.2.4");
        assert_eq!(excerpt.as_str(), "redis_version:7.2.4");
    }

    /// A duplicate folds away and the rest keep the order they arrived in.
    ///
    /// A correlation cites its worst first, and that order is kept.
    #[test]
    fn references_dedup_and_keep_the_order_they_were_added_in() {
        let worst = Reference::cve("CVE-2024-6387").expect("a CVE");
        let older = Reference::cve("CVE-2015-5600").expect("a CVE");

        let f = finding()
            .with_reference(Reference::cwe(306))
            .with_reference(Reference::cwe(306))
            .with_reference(worst.clone())
            .with_reference(older.clone());

        let refs: Vec<_> = f.references().cloned().collect();
        assert_eq!(refs.len(), 3, "the duplicate CWE must fold away");
        assert_eq!(refs, vec![Reference::cwe(306), worst, older]);
    }

    /// The claim key takes the lowest CVE, not the first.
    ///
    /// The first reference changes when the dataset does; keying on it would rename
    /// the claim after a catalogue refresh.
    #[test]
    fn a_claim_is_keyed_on_the_lowest_cve_however_they_were_ordered() {
        let ranked = finding()
            .with_reference(Reference::cve("CVE-2024-6387").expect("a CVE"))
            .with_reference(Reference::cve("CVE-2015-5600").expect("a CVE"));
        let reordered = finding()
            .with_reference(Reference::cve("CVE-2015-5600").expect("a CVE"))
            .with_reference(Reference::cve("CVE-2024-6387").expect("a CVE"));

        assert_eq!(ranked.claim_id(), reordered.claim_id());
        assert_eq!(ranked.claim_id().subject(), "CVE-2015-5600");
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
        // Two versions of the same CVE detection are the same claim; the version is
        // not in the key.
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
            Confidence::Strong, // weaker than Certain, and must not lower it
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

    /// The usual direction: folding an older record (a journal read back into a newer
    /// run, a report from an earlier build) into a newer one keeps the newer verdict
    /// under the newer stamp.
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

    /// One detection at one version grading a claim two ways has read two lots of
    /// evidence, so the account arriving second stands. [`merge`](crate::merge) folds
    /// in clock order; see its
    /// `two_accounts_of_one_host_keep_every_claim_and_grade_it_as_the_newer_did`.
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

        // A downgrade is kept too: the later reading wins either way.
        let mut worse_before = account(Severity::Critical);
        assert!(worse_before.corroborate(account(Severity::Low)));
        assert_eq!(worse_before.severity(), Severity::Low);

        // The stamp does not move.
        assert_eq!(january.detection().version(), Version::new(1, 0, 0));
    }

    /// A superseded account's excerpt fills a gap.
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

        // It does not displace an excerpt the newer account already carried.
        let mut carrying = account(Version::new(2, 0, 0)).with_excerpt(Excerpt::new("READONLY"));
        carrying.corroborate(account(Version::new(1, 0, 0)).with_excerpt(Excerpt::new("older")));
        assert_eq!(carrying.excerpt().as_str(), "READONLY");
    }

    /// **A claim drawn from two identifiers names both**, whichever account is current
    /// and whichever catalogue version drew it.
    #[test]
    fn a_claim_drawn_from_two_identifiers_names_both() {
        let drawn = |version: Version, cpe: &str| {
            Finding::new(
                DetectionId::new("zond:cve-kev", version, "hash").unwrap(),
                "http_server 2.4.49 has 1 known vulnerability",
                Severity::Critical,
                Confidence::Probable,
                DetectionClass::Passive,
            )
            .unwrap()
            .with_reference(Reference::cve("CVE-2021-41773").unwrap())
            .with_cpe(cpe)
        };
        let uri = "cpe:/a:apache:http_server:2.4.49";
        let formatted = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*";

        for (current, other) in [
            (Version::new(1, 0, 0), Version::new(1, 0, 0)),
            (Version::new(2, 0, 0), Version::new(1, 0, 0)),
            (Version::new(1, 0, 0), Version::new(2, 0, 0)),
        ] {
            let mut claim = drawn(current, uri);
            assert!(claim.corroborate(drawn(other, formatted)));
            assert_eq!(
                claim.cpes().collect::<Vec<_>>(),
                [uri, formatted],
                "{current} corroborated by {other}"
            );
            assert!(
                !claim.corroborate(drawn(other, uri)),
                "an identifier already named is no news"
            );
        }
    }

    #[test]
    fn corroborate_reports_no_change_for_an_identical_refiring() {
        // The same claim twice is not new information.
        let mut base = finding();
        assert!(!base.corroborate(finding()));
    }
}
