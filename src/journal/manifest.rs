// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a journal is a journal *of*
//!
//! A cursor is a number. It means something only against the plan it was counted
//! in, so the plan has to travel with it — and a resumed scan has to be able to
//! prove the plan has not moved.
//!
//! ## Why a position is not self-describing
//!
//! [`Cursor`](super::cursor) records that position 4,001,927 is settled.
//! [`TargetMap::iter`](crate::model::target::TargetMap::iter) is what says which
//! target that is, and it answers differently if anything about the plan
//! changed: a port added to the list, a range widened, an exclusion policy
//! edited, a unit added. None of those are exotic — they are what happens when
//! somebody edits a settings file between two sittings.
//!
//! Resuming across such a change does not fail. It scans the wrong targets and
//! reports success, which is the same class of invisible wrongness
//! [`settle`](super::settle) exists to prevent, arriving by a different route.
//!
//! So the plan is fingerprinted when the journal is created and checked when it
//! is resumed, and **a mismatch is a refusal rather than a warning.** A caller
//! who genuinely wants the new plan is asking for a new scan, and that is a
//! different journal.
//!
//! ## Two shapes of plan
//!
//! The engine has two entry points and they count in different units.
//! [`discover`](crate::scanner::discover) walks addresses; [`scan`] walks
//! addresses paired with ports. Position 400 is the four-hundredth address of
//! one and the four-hundredth address-and-port pair of the other, so a journal
//! records which phase it holds and [`Plan`] is how a caller says.
//!
//! The phase goes into the fingerprint before anything else, which means a
//! sweep and a port scan over the same addresses can never be mistaken for each
//! other however alike the rest of them looks.
//!
//! [`scan`]: crate::scanner::scan
//!
//! ## What the fingerprint covers, and what it costs
//!
//! Not the enumeration — hashing sixteen billion targets to check a `/8` would
//! cost more than the scan. It covers the *structure that decides* the
//! enumeration: the canonical address ranges, each unit's port list in order,
//! the technique or the sweep flag, and the privilege level, plus the total as a
//! cheap cross-check.
//!
//! That is a few hundred bytes of hashing for any plan of any size, and it moves
//! whenever a position's meaning moves — which is the only property required of
//! it.
//!
//! ## Privilege is part of the plan, for the plans that probe
//!
//! A scan begun privileged and resumed unprivileged is not the same scan
//! continued. The connect fallback can only complete handshakes, so it answers a
//! different question than a raw technique does —
//! [`TcpScanTechnique`] makes exactly
//! this argument about not quietly substituting one for the other. Folding it
//! into the fingerprint means the refusal happens up front, rather than the
//! second sitting silently filling the first one's gaps with weaker evidence.
//!
//! **A watch has no such pair, so it is deliberately not covered.** A listener
//! sends nothing and has no fallback to be silently substituted: it either
//! opened a capture or did nothing at all, and it enumerated nothing either way,
//! so there is no position a privilege change could give a second meaning to.
//! Covering it refused a resume across `sudo` — an ordinary thing to do on a
//! machine that captures through `access_bpf` or `cap_net_raw` — and refused it
//! by reporting that recorded positions would name different targets, of which
//! such a journal has none.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::model::exclusion::Exclusions;
use crate::model::ip::scoped::Zone;
use crate::model::ip::set::IpSet;
use crate::model::target::TargetMap;
use crate::model::technique::TcpScanTechnique;
use crate::record::{PlanRecord, wire};
use crate::report::ScanKind;
use crate::system::privilege::Privilege;

/// What a scan will actually walk, in the shape the phase it belongs to counts.
///
/// The engine's two entry points are asked different questions and enumerate
/// different things: [`discover`](crate::scanner::discover) walks addresses and
/// [`scan`](crate::scanner::scan) walks addresses paired with ports. A position
/// means one or the other, never both, so a journal has to say which it holds.
///
/// # The exclusion policy is part of the plan
///
/// An excluded address is never probed, so it never settles. Numbering a plan
/// that still holds one stalls a resumed scan's watermark at the first
/// exclusion for the rest of the job, and counts a total the scan can never
/// reach.
///
/// Worse, the policy *decides the enumeration*: withhold the first half of a
/// range and every position after it names a different target. Two sittings
/// under different policies would then agree on a fingerprint and disagree on
/// what position 400 means, which is the silent-wrong-coverage failure
/// [`settle`](super::settle) exists to prevent, arriving by a different route.
///
/// So constructing a plan applies the policy, and a caller cannot hold one that
/// has not had it applied. Applying it again inside the scan costs nothing:
/// withholding what is already withheld removes nothing.
#[derive(Debug, Clone)]
pub struct Plan(Resolved);

/// A plan's two shapes. Private, which is what makes the constructors the only
/// way in — a variant a caller could fill in themselves would be a plan with no
/// exclusion policy applied, which is the thing this type exists to prevent.
#[derive(Debug, Clone)]
enum Resolved {
    /// Which hosts among these addresses are alive.
    Discovery { addresses: IpSet, sweep: bool },
    /// Which of these addresses' ports are open.
    PortScan {
        targets: TargetMap,
        technique: TcpScanTechnique,
    },
    /// What these links carry.
    ///
    /// The one plan that enumerates nothing. A listener is pointed at a link
    /// rather than at targets, so there is no set to walk, no position to
    /// settle, and no total to reach — see [`Plan::listen`].
    Listen { links: Vec<Zone> },
}

impl Plan {
    /// A sweep of `addresses`, less whatever `exclusions` withholds.
    pub fn discovery(addresses: &IpSet, exclusions: &Exclusions, sweep: bool) -> Self {
        let mut addresses = addresses.clone();
        exclusions.withhold(&mut addresses);
        addresses.canonicalize();

        Self(Resolved::Discovery { addresses, sweep })
    }

    /// A port scan of `targets`, less whatever `exclusions` withholds.
    pub fn port_scan(
        targets: &TargetMap,
        exclusions: &Exclusions,
        technique: TcpScanTechnique,
    ) -> Self {
        let mut targets = targets.clone();
        exclusions.withhold_targets(&mut targets);

        Self(Resolved::PortScan { targets, technique })
    }

    /// A watch of `links`.
    ///
    /// # The plan that counts nothing
    ///
    /// The other two enumerate: a sweep walks addresses and a port scan walks
    /// addresses paired with ports, and everything the journal does — the
    /// cursor, the watermark, the total — is arithmetic over that enumeration.
    /// A listener has none. It was pointed at a link, the link carries what it
    /// carries, and there is no set of things that could be finished.
    ///
    /// So a listen journal has no cursor, and **resuming one appends a sitting
    /// rather than skipping settled work**. There is nothing settled to skip.
    /// What the journal buys is the other half of what it buys the other two:
    /// the findings survive a listener that stopped, and the report describes
    /// the whole watch rather than its last sitting.
    ///
    /// # Why the exclusion policy is not applied here
    ///
    /// Because it has nothing to apply to. The other constructors narrow a set
    /// before it is numbered, since the policy decides the enumeration; a
    /// listener cannot narrow what a link carries and enforces its scope where
    /// findings are recorded instead. The policy is still in force — it is
    /// applied at the store, as it is for every phase — and it is simply not
    /// part of *this* plan's identity.
    ///
    /// # What identifies the job
    ///
    /// The links, by name. Not the recording scope: with nothing enumerated
    /// there is nothing a changed scope could renumber, and a sitting that
    /// recorded more or less than the last is still a sitting of the same watch
    /// from the same place. What each sitting covered is on its own phase.
    pub fn listen(links: Vec<Zone>) -> Self {
        Self(Resolved::Listen { links })
    }

    /// Which phase this plan belongs to.
    pub fn kind(&self) -> ScanKind {
        match self.0 {
            Resolved::Discovery { .. } => ScanKind::Discovery,
            Resolved::PortScan { .. } => ScanKind::PortScan,
            Resolved::Listen { .. } => ScanKind::Listen,
        }
    }

    /// The links a watch reads, or `None` for a phase that walks targets.
    pub fn links(&self) -> Option<&[Zone]> {
        match &self.0 {
            Resolved::Listen { links } => Some(links),
            _ => None,
        }
    }

    /// How many targets the plan holds, counted in the units its phase probes:
    /// addresses for a sweep, address-and-port pairs for a port scan.
    pub fn total_targets(&self) -> u128 {
        match &self.0 {
            Resolved::Discovery { addresses, .. } => addresses.len(),
            Resolved::PortScan { targets, .. } => targets.gross_targets().unwrap_or_default(),
            // Not "none were found": there is no unit a watch could be counted
            // in. See `Plan::listen`.
            Resolved::Listen { .. } => 0,
        }
    }

    /// The addresses a sweep will walk, or `None` for a port scan, which is
    /// counted in address-and-port pairs rather than addresses.
    pub fn addresses(&self) -> Option<&IpSet> {
        match &self.0 {
            Resolved::Discovery { addresses, .. } => Some(addresses),
            Resolved::PortScan { .. } | Resolved::Listen { .. } => None,
        }
    }

    /// The targets a port scan will walk, or `None` for a sweep, which has no
    /// ports.
    pub fn targets(&self) -> Option<&TargetMap> {
        match &self.0 {
            Resolved::PortScan { targets, .. } => Some(targets),
            Resolved::Discovery { .. } | Resolved::Listen { .. } => None,
        }
    }

    /// Which TCP segment a port scan's probes carry, or `None` for a sweep,
    /// which sends no segment of its choosing.
    pub fn technique(&self) -> Option<TcpScanTechnique> {
        match &self.0 {
            Resolved::PortScan { technique, .. } => Some(*technique),
            Resolved::Discovery { .. } | Resolved::Listen { .. } => None,
        }
    }

    /// Whether a sweep may go beyond the addresses it was given. False for a
    /// port scan, whose liveness pass is targeted by construction.
    pub fn sweeps_the_segment(&self) -> bool {
        matches!(self.0, Resolved::Discovery { sweep: true, .. })
    }

    /// The plan as a file holds it.
    pub fn record(&self) -> PlanRecord {
        match &self.0 {
            Resolved::Discovery { addresses, .. } => PlanRecord::from(addresses),
            Resolved::PortScan { targets, .. } => PlanRecord::from(targets),
            // A watch names links rather than targets, and those are recorded on
            // the manifest beside the technique and the sweep flag — the other
            // two fields that belong to one phase and not the others.
            Resolved::Listen { .. } => PlanRecord::default(),
        }
    }
}

/// A fingerprint of the plan a cursor's positions are counted in.
///
/// Compared, never interpreted. The value has no meaning beyond equality with
/// another one, and its derivation is free to change when
/// [`JOURNAL_VERSION`](super::format::JOURNAL_VERSION) does, which is what
/// refuses a journal written under an older derivation rather than reporting it
/// as a plan that moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlanFingerprint(u64);

impl PlanFingerprint {
    /// Fingerprints a resolved plan.
    ///
    /// `privilege` is what the scan could actually send, not what it asked for:
    /// what matters is which question the probes answered. **It is read for the
    /// two enumerating phases and ignored for a watch**, which sends no probe
    /// and so has no second question a privilege change could switch it to; see
    /// the `Listen` arm.
    ///
    /// It goes in as the boolean the manifest writes, because that is the shape
    /// the field has on disk and there is no reason for the two to differ.
    ///
    /// The digest walks each unit's canonical ranges and ports rather than its
    /// targets, so this is cheap on a plan of any size. Feeding each field's
    /// count before the fields themselves is what keeps two differently-shaped
    /// plans from colliding: without it, one unit of two ranges and two units of
    /// one would digest the same.
    ///
    /// Every enum reaches the digest as its wire name rather than as a derived
    /// hash, for the reason [`record::wire`](crate::record::wire) gives about
    /// names generally. A derived hash is a variant's position in a declaration,
    /// so inserting a technique anywhere but the end would silently invalidate
    /// every journal on disk, which is precisely the change
    /// [`JOURNAL_VERSION`](super::JOURNAL_VERSION) exists to announce.
    pub fn of(plan: &Plan, privilege: Privilege) -> Self {
        let mut digest = Digest::new();

        // The phase first, so a sweep and a port scan over the same addresses
        // can never agree. They count different things, and a position from one
        // read against the other names a target nobody probed.
        digest.text(wire::scan_kind_name(plan.kind()));

        match &plan.0 {
            Resolved::Discovery { addresses, sweep } => {
                // Privilege belongs to the enumerating phases and to them only.
                // A raw SYN and a connect attempt ask different questions of the
                // same port, so a journal half of each would be counting two
                // things — which is what this bit refuses.
                digest.flag(privilege.is_raw());
                digest.flag(*sweep);
                digest.addresses(addresses);
            }
            Resolved::Listen { links } => {
                // **And a watch has no such pair to tell apart**, so privilege
                // is deliberately not digested here. A listener has one way of
                // working and no fallback: it either opened a capture or it did
                // nothing at all, and either way it enumerated nothing and left
                // no position for a privilege change to invalidate.
                //
                // Hashing it refused a resume across `sudo`, which is a thing
                // people do — a machine that captures through `access_bpf` or
                // `cap_net_raw` records one sitting unprivileged and the next
                // one under `sudo` — and refused it with a message about
                // recorded positions this journal does not have.
                //
                // By name, and not by index. An interface's number is a fact
                // about a running kernel and changes across a reboot; the name
                // is what a person meant by the link and what two sittings of
                // one watch agree on.
                digest.count(links.len());
                for link in links {
                    digest.text(link.name());
                }
            }
            Resolved::PortScan { targets, technique } => {
                digest.flag(privilege.is_raw());
                digest.text(technique.name());
                digest.count(targets.units.len());

                for unit in &targets.units {
                    digest.addresses(unit.ips());

                    let ports = unit.ports().to_vec();
                    digest.count(ports.len());
                    for (port, protocol) in ports {
                        digest.number(u64::from(port));
                        digest.text(wire::protocol_name(protocol));
                    }
                }
            }
        }

        // A cheap cross-check on everything above. Cannot catch a change the
        // structure digest missed on its own, but it costs one call and it turns
        // a collision into a mismatch rather than a silent agreement.
        digest.wide(plan.total_targets());

        Self(digest.finish())
    }
}

/// The plan digest: FNV-1a over bytes this file chooses, and nothing borrowed
/// from a `Hash` implementation.
///
/// **A fingerprint that is written down cannot be built out of `Hash`.**
/// `DefaultHasher` was what this used, and the standard library says of it that
/// "the internal algorithm is not specified, and so it and its hashes should not
/// be relied upon over releases" — so upgrading the compiler moved the value,
/// every journal on disk stopped matching, and the refusal said the plan had
/// changed. The same caveat covers the `Hash` implementations of the types fed
/// to it, so the bytes are chosen here instead.
///
/// Non-cryptographic on purpose. Nothing here is defending against a chosen
/// collision: anyone who can edit a manifest can edit the fingerprint beside it.
/// What is required is that the value be a function of the plan and of nothing
/// else, which this is.
struct Digest(u64);

impl Digest {
    /// The FNV-1a 64-bit offset basis and prime, as the algorithm defines them.
    const BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    fn new() -> Self {
        Self(Self::BASIS)
    }

    fn bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }

    /// A string, length first, so that two adjacent fields cannot be run
    /// together into a third that digests the same.
    fn text(&mut self, text: &str) {
        self.number(text.len() as u64);
        self.bytes(text.as_bytes());
    }

    fn number(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }

    fn wide(&mut self, value: u128) {
        self.bytes(&value.to_le_bytes());
    }

    fn count(&mut self, value: usize) {
        self.number(value as u64);
    }

    fn flag(&mut self, value: bool) {
        self.bytes(&[u8::from(value)]);
    }

    /// One address set's canonical ranges.
    ///
    /// Each family's count goes in before its ranges. Without it, one set of two
    /// ranges and two sets of one would digest the same. The family tag goes in
    /// too, so a v4 range and a v6 range whose octets happen to coincide cannot.
    fn addresses(&mut self, ips: &IpSet) {
        self.count(ips.v4().len());
        for range in ips.v4() {
            self.bytes(&[4]);
            self.bytes(&range.start_addr().octets());
            self.bytes(&range.end_addr().octets());
        }

        self.count(ips.v6().len());
        for range in ips.v6() {
            self.bytes(&[6]);
            self.bytes(&range.start_addr().octets());
            self.bytes(&range.end_addr().octets());
            // The zone is part of the address for a link-local range: `fe80::1`
            // names a different machine on every segment. Absent and zero are
            // told apart, since zero is a scope id a kernel can report.
            match range.zone() {
                Some(zone) => {
                    self.bytes(&[1]);
                    self.number(u64::from(zone));
                }
                None => self.bytes(&[0]),
            }
        }
    }

    fn finish(self) -> u64 {
        self.0
    }
}

/// What a journal is a journal of.
///
/// Written once when the journal is created and never rewritten, which is what
/// makes it safe to read without a lock: nothing that reads a manifest can race
/// a writer changing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalManifest {
    /// The journal format this was written under, so a reader that predates it
    /// refuses rather than guessing. Mirrors the header on every journal file;
    /// carried here too because a manifest is the first thing read and should
    /// not depend on another file to be interpretable.
    pub journal_version: u32,
    /// The scan this journal belongs to.
    pub id: String,
    /// The engine build that created it, for diagnostics.
    pub engine_version: String,
    /// When the first sitting began.
    pub created_at: SystemTime,
    /// Which phase this is a journal of, by wire name.
    ///
    /// A sweep counts addresses and a port scan counts address-and-port pairs,
    /// so this decides what everything below is measured in. Absent in a
    /// journal written before sweeps were recorded, which read as port scans
    /// because that is all there was.
    #[serde(default)]
    pub kind: String,
    /// The plan every position in this journal is counted in.
    pub plan: PlanFingerprint,
    /// That plan itself, so a scan can be continued without being described
    /// again.
    ///
    /// A fingerprint can only check a plan somebody supplies; this is what gives
    /// one back. Ranges and port lists, so it stays small for a plan of any
    /// size.
    #[serde(default)]
    pub targets: PlanRecord,
    /// Which segment each TCP probe carried, by wire name. Part of the plan: a
    /// port's verdict means different things under different techniques. Empty
    /// for a sweep, which sends no TCP segment of its choosing.
    #[serde(default)]
    pub technique: String,
    /// Whether a sweep was allowed onto the segment beyond the addresses it was
    /// given. Part of the plan for the same reason the technique is: it decides
    /// what the scan covered. Always false for a port scan, whose liveness pass
    /// is targeted by construction.
    #[serde(default)]
    pub sweep: bool,
    /// The links a watch reads, by name. Part of the plan for the reason the
    /// technique and the sweep flag are: it is what the job *is*.
    ///
    /// By name and not by index, because an index is a fact about a running
    /// kernel and does not survive a reboot, where the name is what a person
    /// meant by the link. Empty for the two phases that walk targets.
    #[serde(default)]
    pub links: Vec<String>,
    /// What the scan was able to send.
    ///
    /// Recorded because a resume must run under the same answer. The connect
    /// fallback asks a different question than a raw technique does, and a
    /// journal half of each would be counting two things.
    #[serde(
        rename = "privileged",
        default = "wire_privilege::unrecorded",
        with = "wire_privilege"
    )]
    pub privilege: Privilege,
    /// How many targets that plan holds, so a caller can report progress without
    /// walking it.
    pub total_targets: u128,
    /// A human-readable summary of what was scanned, for a caller listing
    /// journals. **Not** load-bearing: nothing is decided from this text, which
    /// is why it is free to change shape between versions.
    pub summary: String,
}

/// The manifest's `privileged` field as it is written: a boolean, which is the
/// only shape it has ever had on disk.
///
/// The distinction is worth making in the type and not worth making twice.
/// Spelling it out in the file as well would change what every journal already
/// written says, and that is a
/// [`JOURNAL_VERSION`](crate::journal::JOURNAL_VERSION) bump for no reader's
/// benefit.
mod wire_privilege {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::system::privilege::Privilege;

    /// What a journal written before the field existed was scanning under.
    ///
    /// Connect, which is what the boolean's absence has always meant here.
    pub(super) fn unrecorded() -> Privilege {
        Privilege::Connect
    }

    pub(super) fn serialize<S: Serializer>(
        privilege: &Privilege,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        privilege.is_raw().serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Privilege, D::Error> {
        Ok(if bool::deserialize(deserializer)? {
            Privilege::Raw
        } else {
            Privilege::Connect
        })
    }
}

impl JournalManifest {
    /// Describes a scan about to start.
    pub fn new(
        id: impl Into<String>,
        plan: &Plan,
        privilege: Privilege,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            journal_version: super::JOURNAL_VERSION,
            id: id.into(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: SystemTime::now(),
            kind: wire::scan_kind_name(plan.kind()).to_owned(),
            plan: PlanFingerprint::of(plan, privilege),
            targets: plan.record(),
            technique: plan
                .technique()
                .map(|technique| technique.name().to_owned())
                .unwrap_or_default(),
            sweep: plan.sweeps_the_segment(),
            links: plan
                .links()
                .unwrap_or_default()
                .iter()
                .map(|link| link.name().to_owned())
                .collect(),
            privilege,
            total_targets: plan.total_targets(),
            summary: summary.into(),
        }
    }

    /// Which phase this journal records.
    ///
    /// A journal written before sweeps were recorded names no kind, and is a
    /// port scan, because that is all there was to record.
    pub fn kind(&self) -> ScanKind {
        wire::scan_kind(&self.kind).unwrap_or(ScanKind::PortScan)
    }

    /// The plan this journal was counted in, as it was recorded.
    ///
    /// What a resume scans, in the shape its phase counts in. Rebuilt from the
    /// ranges and ports written down rather than from anything a caller typed,
    /// so a hostname that has since moved does not quietly change what is being
    /// continued — and the exclusion policy is already in it, since it was
    /// applied before the plan was recorded.
    pub fn recorded(&self) -> Plan {
        // Built here rather than through the constructors: the policy was
        // applied before this was written down, and applying it again would be
        // a second subtraction against whatever policy happens to be in force
        // now.
        Plan(match self.kind() {
            ScanKind::Discovery => Resolved::Discovery {
                addresses: self.targets.addresses(),
                sweep: self.sweep,
            },
            // Unresolved zones, deliberately. The recorded plan is what *names*
            // the job and what a fingerprint is taken over, and a name is the
            // whole of that. A caller running the watch supplies links it looked
            // up against this machine, since an index read from a file was true
            // of some other boot.
            ScanKind::Listen => Resolved::Listen {
                links: self
                    .links
                    .iter()
                    .map(|name| Zone::unresolved(name.as_str()))
                    .collect(),
            },
            _ => Resolved::PortScan {
                targets: TargetMap::from(&self.targets),
                technique: self.technique(),
            },
        })
    }

    /// The technique the recorded plan ran under.
    ///
    /// Falls back to the default for a journal written before this was recorded,
    /// which the fingerprint then refuses if it was anything else.
    pub fn technique(&self) -> TcpScanTechnique {
        self.technique.parse().unwrap_or_default()
    }

    /// Whether `plan` under these conditions is the plan this journal was
    /// counted in.
    pub fn covers(&self, plan: &Plan, privilege: Privilege) -> Result<(), PlanChanged> {
        let found = PlanFingerprint::of(plan, privilege);
        if found == self.plan {
            return Ok(());
        }

        Err(PlanChanged {
            expected: self.plan,
            found,
            expected_targets: self.total_targets,
            found_targets: plan.total_targets(),
        })
    }
}

/// The plan a journal was counted in is not the plan now being resumed.
///
/// Carries both target counts because they are the half of the difference a
/// person can act on: "40,960 then, 81,920 now" points at the edit, where two
/// hashes do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanChanged {
    /// What the journal was written against.
    pub expected: PlanFingerprint,
    /// What was offered.
    pub found: PlanFingerprint,
    /// How many targets the original plan held.
    pub expected_targets: u128,
    /// How many the offered plan holds.
    pub found_targets: u128,
}

impl std::fmt::Display for PlanChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "this journal was written against a different plan, so its recorded \
             positions would name different targets"
        )?;

        if self.expected_targets != self.found_targets {
            write!(
                f,
                " ({} targets then, {} now)",
                self.expected_targets, self.found_targets
            )?;
        } else {
            write!(
                f,
                " (the same {} targets, differently arranged, or a different \
                 technique or privilege level)",
                self.expected_targets
            )?;
        }

        Ok(())
    }
}

impl std::error::Error for PlanChanged {}

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
    use crate::model::ip::set::IpSet;
    use crate::model::port::PortSet;
    use crate::model::target::TargetSet;

    fn plan(pairs: &[(&str, &str)]) -> TargetMap {
        let mut map = TargetMap::new();
        for (range, ports) in pairs {
            map.add_unit(TargetSet::new(
                range.parse::<IpSet>().expect("a range"),
                ports.parse::<PortSet>().expect("ports"),
            ));
        }
        map
    }

    fn ports(map: &TargetMap) -> Plan {
        Plan::port_scan(map, &Exclusions::none(), TcpScanTechnique::Syn)
    }

    fn print(map: &TargetMap) -> PlanFingerprint {
        PlanFingerprint::of(&ports(map), Privilege::Raw)
    }

    fn addresses(written: &str) -> IpSet {
        written.parse().expect("a range")
    }

    fn sweeping(ips: &IpSet, sweep: bool) -> Plan {
        Plan::discovery(ips, &Exclusions::none(), sweep)
    }

    /// The derivation is pinned to a value, not merely to itself.
    ///
    /// Every other test here asks whether two fingerprints agree, and every one
    /// of them passed while the derivation was `DefaultHasher` — whose output the
    /// standard library declines to keep stable across compiler releases, so the
    /// value moved when the toolchain did and every journal on disk was refused
    /// as a plan that had changed. A test comparing two fingerprints taken in one
    /// process cannot see that. This one can.
    ///
    /// **If this fails, the derivation moved.** That is allowed, and it is a
    /// [`JOURNAL_VERSION`](crate::journal::JOURNAL_VERSION) bump: every journal
    /// already written carries the old value and cannot be continued under the
    /// new one. Bump the version, update the number here, and check that
    /// `Journal::resume` still refuses the older format by name.
    #[test]
    fn the_derivation_is_pinned_to_a_value() {
        assert_eq!(
            print(&plan(&[("192.0.2.1-192.0.2.10", "80,443")])).0,
            0xa4d1_e087_ea5b_98c2,
            "the plan fingerprint derivation has moved"
        );
    }

    /// The same plan fingerprints the same, however many times it is asked. A
    /// hash that moved between two runs of one build would refuse every resume.
    #[test]
    fn the_same_plan_fingerprints_the_same() {
        let a = plan(&[("192.0.2.1-192.0.2.10", "80,443")]);
        let b = plan(&[("192.0.2.1-192.0.2.10", "80,443")]);

        assert_eq!(print(&a), print(&a), "not stable within one value");
        assert_eq!(print(&a), print(&b), "not stable across equal values");
    }

    /// Every edit that moves what a position means has to move the fingerprint.
    /// Each case here is a plausible thing to do between two sittings.
    #[test]
    fn any_change_that_renumbers_targets_changes_the_fingerprint() {
        let base = plan(&[("192.0.2.1-192.0.2.10", "80,443")]);
        let original = print(&base);

        for (what, changed) in [
            (
                "a port added",
                plan(&[("192.0.2.1-192.0.2.10", "80,443,8080")]),
            ),
            ("a port removed", plan(&[("192.0.2.1-192.0.2.10", "80")])),
            (
                "the range widened",
                plan(&[("192.0.2.1-192.0.2.20", "80,443")]),
            ),
            (
                "the range narrowed",
                plan(&[("192.0.2.1-192.0.2.5", "80,443")]),
            ),
            (
                "a unit added",
                plan(&[("192.0.2.1-192.0.2.10", "80,443"), ("198.51.100.1", "22")]),
            ),
        ] {
            assert_ne!(
                original,
                print(&changed),
                "{what} left the fingerprint alone"
            );
        }
    }

    /// Port *order* decides the enumeration, so two plans holding the same ports
    /// in a different order are different plans.
    #[test]
    fn the_order_of_the_ports_is_part_of_the_plan() {
        let ascending = plan(&[("192.0.2.1", "80,443")]);
        let descending = plan(&[("192.0.2.1", "443,80")]);

        // Only meaningful if the set actually preserves the written order; if it
        // canonicalises, the two are genuinely the same plan and must agree.
        let same_order =
            ascending.units[0].ports().to_vec() == descending.units[0].ports().to_vec();
        assert_eq!(
            print(&ascending) == print(&descending),
            same_order,
            "the fingerprint must follow the enumeration, whichever way the set orders it"
        );
    }

    /// Two units of one range must not hash as one unit of two: the shapes
    /// enumerate differently, and a length-free hash would collide them.
    #[test]
    fn the_shape_of_the_units_is_not_flattened_away() {
        let split = plan(&[
            ("192.0.2.1-192.0.2.5", "80"),
            ("192.0.2.6-192.0.2.10", "80"),
        ]);
        let joined = plan(&[("192.0.2.1-192.0.2.10", "80")]);

        assert_eq!(
            split.gross_targets().unwrap(),
            joined.gross_targets().unwrap(),
            "the same ten targets either way, which is what makes this the trap"
        );
        assert_ne!(
            print(&split),
            print(&joined),
            "two units enumerate differently from one"
        );
    }

    /// A scan begun privileged and resumed unprivileged is a different scan:
    /// the connect fallback can only complete handshakes, so it answers a
    /// different question. The refusal belongs up front.
    #[test]
    fn privilege_and_technique_are_part_of_the_plan() {
        let map = plan(&[("192.0.2.1-192.0.2.10", "80,443")]);

        assert_ne!(
            PlanFingerprint::of(&ports(&map), Privilege::Raw),
            PlanFingerprint::of(&ports(&map), Privilege::Connect),
            "privilege decides which question the probes answered"
        );
        assert_ne!(
            PlanFingerprint::of(&ports(&map), Privilege::Raw),
            PlanFingerprint::of(
                &Plan::port_scan(&map, &Exclusions::none(), TcpScanTechnique::Fin),
                Privilege::Raw
            ),
            "a technique decides what silence means"
        );
    }

    /// Privilege is a type in this build and a boolean in the file, and the
    /// boolean is the half that may not move.
    ///
    /// Every journal on disk was written with `"privileged": true` and
    /// fingerprinted from that byte. Spelling the variant out instead would
    /// refuse all of them without
    /// [`JOURNAL_VERSION`](super::super::JOURNAL_VERSION) having moved to say
    /// so, and the refusal would arrive as a plan that changed.
    #[cfg(feature = "journal-format")]
    #[test]
    fn privilege_is_written_as_the_boolean_the_format_promised() {
        let map = plan(&[("192.0.2.1", "80")]);
        let manifest = JournalManifest::new("01J8Z5Q7VN", &ports(&map), Privilege::Raw, "");

        let mut written = serde_json::to_value(&manifest).expect("a manifest serializes");
        assert_eq!(written["privileged"], serde_json::Value::Bool(true));

        let read: JournalManifest =
            serde_json::from_value(written.clone()).expect("and reads back");
        assert_eq!(read.privilege, Privilege::Raw);
        assert_eq!(read.plan, manifest.plan, "the same plan, still");

        written["privileged"] = serde_json::Value::Bool(false);
        let read: JournalManifest = serde_json::from_value(written).expect("a connect scan reads");
        assert_eq!(read.privilege, Privilege::Connect, "the polarity is intact");
    }

    /// A journal written before the field existed reads as a connect scan,
    /// which is what its absence has always meant here.
    #[cfg(feature = "journal-format")]
    #[test]
    fn a_manifest_that_records_no_privilege_reads_as_a_connect_scan() {
        let map = plan(&[("192.0.2.1", "80")]);
        let manifest = JournalManifest::new("01J8Z5Q7VN", &ports(&map), Privilege::Raw, "");

        let mut written = serde_json::to_value(&manifest).expect("a manifest serializes");
        written
            .as_object_mut()
            .expect("an object")
            .remove("privileged");

        let read: JournalManifest = serde_json::from_value(written).expect("an older manifest");
        assert_eq!(read.privilege, Privilege::Connect);
    }

    /// The manifest accepts the plan it was made from and refuses anything else,
    /// naming the counts so a person can see what moved.
    #[test]
    fn a_manifest_covers_its_own_plan_and_refuses_another() {
        let original = plan(&[("192.0.2.1-192.0.2.10", "80,443")]);
        let manifest = JournalManifest::new(
            "01J8Z5Q7VN",
            &ports(&original),
            Privilege::Raw,
            "192.0.2.1-192.0.2.10 on 2 ports",
        );

        assert_eq!(manifest.total_targets, 20);
        assert_eq!(manifest.kind(), ScanKind::PortScan);
        assert!(manifest.covers(&ports(&original), Privilege::Raw).is_ok());

        let widened = plan(&[("192.0.2.1-192.0.2.20", "80,443")]);
        let refused = manifest
            .covers(&ports(&widened), Privilege::Raw)
            .expect_err("a widened plan renumbers every position past the first host");

        assert_eq!(refused.expected_targets, 20);
        assert_eq!(refused.found_targets, 40);
        assert!(
            refused.to_string().contains("20 targets then, 40 now"),
            "{refused}"
        );
    }

    /// A sweep and a port scan count in different units, so a position from one
    /// names a different target under the other. The two must never fingerprint
    /// alike, however much the addresses they cover overlap.
    #[test]
    fn a_sweep_is_never_the_same_plan_as_a_port_scan() {
        let ips = addresses("192.0.2.1-192.0.2.10");
        let map = plan(&[("192.0.2.1-192.0.2.10", "80")]);

        assert_ne!(
            PlanFingerprint::of(&sweeping(&ips, false), Privilege::Raw),
            print(&map),
            "the same ten addresses, asked two different questions"
        );

        let manifest =
            JournalManifest::new("01J8Z5Q7VN", &sweeping(&ips, false), Privilege::Raw, "");
        assert_eq!(manifest.kind(), ScanKind::Discovery);
        assert_eq!(manifest.total_targets, 10, "a sweep counts addresses");
        assert!(
            manifest.covers(&ports(&map), Privilege::Raw).is_err(),
            "a sweep's journal must not accept a port scan's plan"
        );
    }

    /// Whether a sweep may go beyond its addresses decides what it covered, so
    /// the two are different plans.
    #[test]
    fn a_segment_sweep_is_not_a_targeted_pass() {
        let ips = addresses("192.0.2.1-192.0.2.10");

        assert_ne!(
            PlanFingerprint::of(&sweeping(&ips, true), Privilege::Raw),
            PlanFingerprint::of(&sweeping(&ips, false), Privilege::Raw)
        );
    }

    /// A sweep's addresses have to come back as they went in, since that is the
    /// whole of its plan.
    #[test]
    fn a_sweeps_addresses_survive_the_round_trip() {
        let ips = addresses("192.0.2.1-192.0.2.10,2001:db8::1");
        let manifest =
            JournalManifest::new("01J8Z5Q7VN", &sweeping(&ips, false), Privilege::Raw, "");

        assert_eq!(
            manifest.recorded().addresses().map(IpSet::len),
            Some(ips.len())
        );
        assert!(
            manifest
                .covers(
                    &sweeping(
                        &manifest.recorded().addresses().cloned().unwrap_or_default(),
                        false
                    ),
                    Privilege::Raw
                )
                .is_ok(),
            "a plan rebuilt from the record must fingerprint as the original"
        );
    }

    /// A link-local plan has to survive the round trip *in order*. The set
    /// sorts IPv6 by zone before address, so a record that came back with the
    /// interfaces in another order would enumerate differently — and every
    /// position an earlier sitting settled would name a different machine.
    #[test]
    fn a_link_local_plan_comes_back_in_the_order_it_was_counted() {
        let mut ips = IpSet::new();
        for (zone, last) in [(9u32, 4u16), (3, 6), (7, 2)] {
            ips.insert_range(crate::model::ip::range::IpRange::V6(
                crate::model::ip::range::Ipv6Range::scoped(
                    "fe80::1".parse().expect("an address"),
                    format!("fe80::{last}").parse().expect("an address"),
                    Some(zone),
                )
                .expect("a range"),
            ));
        }
        ips.canonicalize();

        let manifest =
            JournalManifest::new("01J8Z5Q7VN", &sweeping(&ips, false), Privilege::Raw, "");
        let recovered = manifest
            .recorded()
            .addresses()
            .cloned()
            .expect("a sweep's plan");

        assert_eq!(
            recovered.iter().collect::<Vec<_>>(),
            ips.iter().collect::<Vec<_>>(),
            "the same addresses in the same order, so positions still mean what they did"
        );
        assert!(
            manifest
                .covers(&sweeping(&recovered, false), Privilege::Raw)
                .is_ok(),
            "and the plan rebuilt from the record fingerprints as the original"
        );
    }

    /// A rearrangement holding the same number of targets still refuses, and the
    /// message must not claim a count changed when it did not.
    #[test]
    fn a_refusal_over_an_equal_count_says_so_rather_than_reporting_a_change() {
        let map = plan(&[("192.0.2.1-192.0.2.10", "80,443")]);
        let manifest = JournalManifest::new("01J8Z5Q7VN", &ports(&map), Privilege::Raw, "");

        let refused = manifest
            .covers(
                &Plan::port_scan(&map, &Exclusions::none(), TcpScanTechnique::Fin),
                Privilege::Raw,
            )
            .expect_err("a different technique is a different plan");

        assert_eq!(refused.expected_targets, refused.found_targets);
        let message = refused.to_string();
        assert!(message.contains("differently arranged"), "{message}");
        assert!(!message.contains("then,"), "{message}");
    }

    /// A watch names links; a sweep and a port scan name targets. The phase is
    /// hashed first, so no two of the three can ever agree — which is what keeps
    /// a journal of one from being continued as another.
    #[test]
    fn a_watch_never_shares_a_fingerprint_with_a_phase_that_walks_targets() {
        let listen = Plan::listen(vec![Zone::unresolved("en0")]);
        let mut ips = IpSet::new();
        ips.insert_range("10.0.0.0/24".parse().expect("a valid range"));

        assert_ne!(
            PlanFingerprint::of(&listen, Privilege::Raw),
            PlanFingerprint::of(&sweeping(&ips, true), Privilege::Raw),
        );
        assert_eq!(listen.kind(), ScanKind::Listen);
        assert_eq!(
            listen.total_targets(),
            0,
            "not `none were found`: there is no unit a watch is counted in"
        );
    }

    /// The links are what the job is, so a watch of a different link is a
    /// different job and may not be appended to this one's record.
    #[test]
    fn a_watch_of_another_link_is_another_job() {
        let one = Plan::listen(vec![Zone::unresolved("en0")]);
        let other = Plan::listen(vec![Zone::unresolved("en1")]);
        let both = Plan::listen(vec![Zone::unresolved("en0"), Zone::unresolved("en1")]);

        assert_ne!(
            PlanFingerprint::of(&one, Privilege::Raw),
            PlanFingerprint::of(&other, Privilege::Raw),
        );
        assert_ne!(
            PlanFingerprint::of(&one, Privilege::Raw),
            PlanFingerprint::of(&both, Privilege::Raw),
        );
    }

    /// A watch is the same watch whether or not this sitting is root, and the
    /// phases that probe still are not.
    ///
    /// The distinction is what the bit is *for*. A port scan begun with raw
    /// sockets and resumed without them fell back to completing handshakes,
    /// which answers a different question — so the second sitting would fill the
    /// first's gaps with weaker evidence and report success. A listener has no
    /// second way of working to fall back to: it opened a capture or it did
    /// nothing, and it enumerated nothing either way.
    ///
    /// Both halves are asserted together because the risk runs in both
    /// directions. Covering a watch refused a resume across `sudo` — ordinary on
    /// a machine that captures through `access_bpf` or `cap_net_raw` — and
    /// uncovering a port scan is the silent-wrong-coverage failure this whole
    /// module exists to prevent.
    #[test]
    fn privilege_decides_a_probing_plan_and_says_nothing_about_a_watch() {
        let watch = Plan::listen(vec![Zone::unresolved("en0")]);
        assert_eq!(
            PlanFingerprint::of(&watch, Privilege::Connect),
            PlanFingerprint::of(&watch, Privilege::Raw),
            "a watch under sudo is the same watch"
        );

        let ips = addresses("192.0.2.0/30");
        assert_ne!(
            PlanFingerprint::of(&sweeping(&ips, false), Privilege::Connect),
            PlanFingerprint::of(&sweeping(&ips, false), Privilege::Raw),
            "a sweep's probes are not the same probes"
        );

        let map = plan(&[("192.0.2.1-192.0.2.10", "80,443")]);
        assert_ne!(
            PlanFingerprint::of(&ports(&map), Privilege::Connect),
            PlanFingerprint::of(&ports(&map), Privilege::Raw),
            "and neither are a port scan's"
        );
    }

    /// By name and not by index. An interface's number is a fact about a running
    /// kernel; a watch resumed after a reboot is the same watch.
    #[test]
    fn a_link_is_the_same_link_whatever_number_the_kernel_gave_it_today() {
        let before = Plan::listen(vec![Zone::new(3, "en0")]);
        let after = Plan::listen(vec![Zone::new(11, "en0")]);

        assert_eq!(
            PlanFingerprint::of(&before, Privilege::Raw),
            PlanFingerprint::of(&after, Privilege::Raw),
        );
    }

    /// The recorded plan has to survive the round trip through a manifest, or a
    /// caller with nothing but a journal id cannot say what it was watching.
    #[test]
    fn a_watch_reads_back_as_the_links_it_was_written_with() {
        let plan = Plan::listen(vec![Zone::new(3, "en0"), Zone::new(4, "en1")]);
        let manifest = JournalManifest::new("id", &plan, Privilege::Raw, "listening");

        let recorded = manifest.recorded();
        assert_eq!(recorded.kind(), ScanKind::Listen);
        assert_eq!(
            recorded
                .links()
                .expect("a watch names links")
                .iter()
                .map(|link| link.name().to_owned())
                .collect::<Vec<_>>(),
            vec!["en0".to_owned(), "en1".to_owned()],
        );
        manifest
            .covers(&plan, Privilege::Raw)
            .expect("the plan it was written against still covers it");
    }
}
