// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a journal is a journal of
//!
//! A cursor is a number. It means something only against the plan it was counted
//! in, so the plan travels with it and a resumed scan can prove the plan has not
//! moved.
//!
//! ## Why a position is not self-describing
//!
//! [`Cursor`](super::cursor) records that position 4,001,927 is settled.
//! [`TargetMap::iter`](crate::model::target::TargetMap::iter) says which target
//! that is, and it answers differently if anything about the plan changed: a port
//! added to the list, a range widened, an exclusion policy edited, a unit added.
//! None of those are exotic; they are what happens when somebody edits a settings
//! file between two sittings.
//!
//! Resuming across such a change does not fail. It scans the wrong targets and
//! reports success, which is the invisible wrongness
//! [`settle`](super::settle) exists to prevent arriving by another route.
//!
//! So the plan is fingerprinted when the journal is created and checked when it
//! is resumed, and a mismatch is a refusal rather than a warning. A caller who
//! wants the new plan is asking for a new scan, which is a different journal.
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
//! Not the enumeration; hashing sixteen billion targets to check a `/8` would
//! cost more than the scan. It covers the structure that decides the enumeration:
//! the canonical address ranges, each unit's port list in order, the technique or
//! the sweep flag, and the privilege level, plus the total as a cheap
//! cross-check.
//!
//! That is a few hundred bytes of hashing for a plan of any size, and it moves
//! whenever a position's meaning moves, which is the only property required of
//! it.
//!
//! ## Privilege is part of the plan, for the plans that probe
//!
//! A scan begun privileged and resumed unprivileged is not the same scan
//! continued. The connect fallback can only complete handshakes, so it answers a
//! different question than a raw technique does, which is the argument
//! [`TcpScanTechnique`] makes about not substituting one for the other. Folding
//! it into the fingerprint puts the refusal up front, rather than letting the
//! second sitting fill the first one's gaps with weaker evidence.
//!
//! A watch has no such pair and is not covered. A listener sends nothing and has
//! no fallback to be substituted: it either opened a capture or did nothing, and
//! it enumerated nothing either way, so there is no position a privilege change
//! could give a second meaning to. Covering it refused a resume across `sudo`,
//! which is ordinary on a machine that captures through `access_bpf` or
//! `cap_net_raw`, and refused it by reporting that recorded positions would name
//! different targets, of which such a journal has none.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::config::ZondConfig;
use crate::evasion::EvasionProfile;
use crate::model::exclusion::Exclusions;
use crate::model::ip::scoped::Zone;
use crate::model::ip::set::IpSet;
use crate::model::port::PortSet;
use crate::model::target::TargetMap;
use crate::model::technique::TcpScanTechnique;
use crate::record::{PlanRecord, SettingsRecord, wire};
use crate::report::{ScanKind, ScanSettings};
use crate::system::privilege::Privilege;

/// What a scan will actually walk, in the shape the phase it belongs to counts.
///
/// The engine's two entry points enumerate different things:
/// [`discover`](crate::scanner::discover) walks addresses and
/// [`scan`](crate::scanner::scan) walks addresses paired with ports. A position
/// means one or the other, never both, so a journal says which it holds.
///
/// # The exclusion policy is part of the plan
///
/// An excluded address is never probed, so it never settles. Numbering a plan
/// that still holds one stalls a resumed scan's watermark at the first
/// exclusion for the rest of the job, and counts a total the scan can never
/// reach.
///
/// The policy also decides the enumeration: withhold the first half of a range
/// and every position after it names a different target. Two sittings under
/// different policies would agree on a fingerprint and disagree on what position
/// 400 means, which is the silent wrong coverage [`settle`](super::settle) exists
/// to prevent arriving by another route.
///
/// So constructing a plan applies the policy, and a caller cannot hold one that
/// has not had it applied. Applying it again inside the scan costs nothing:
/// withholding what is already withheld removes nothing.
#[derive(Debug, Clone)]
pub struct Plan(Resolved);

/// A plan's two shapes. Private, which makes the constructors the only way in: a
/// variant a caller could fill in themselves would be a plan with no exclusion
/// policy applied, which is what this type exists to prevent.
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
    /// rather than at targets, so there is no set to walk, no position to settle
    /// and no total to reach. See [`Plan::listen`].
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
    /// addresses paired with ports, and the cursor and the watermark and the
    /// total are all arithmetic over that enumeration. A listener has none. It
    /// was pointed at a link, the link carries what it carries, and there is no
    /// set of things that could be finished.
    ///
    /// So a listen journal has no cursor, and resuming one appends a sitting
    /// rather than skipping settled work, since there is nothing settled to skip.
    /// What it buys is the other half of what the journal buys the other two: the
    /// findings survive a listener that stopped, and the report describes the
    /// whole watch rather than its last sitting.
    ///
    /// # Why the exclusion policy is not applied here
    ///
    /// It has nothing to apply to. The other constructors narrow a set before it
    /// is numbered, since the policy decides the enumeration. A listener cannot
    /// narrow what a link carries and enforces its scope where findings are
    /// recorded instead. The policy is still in force, applied at the store as it
    /// is for every phase, and it is not part of this plan's identity.
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
            // A watch names links rather than targets, and those are recorded
            // on the manifest beside the technique and the sweep flag, the other
            // two fields belonging to one phase and not the others.
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
                // A raw SYN and a connect attempt ask different questions of
                // the same port, so a journal half of each would count two
                // things, which is what this bit refuses.
                digest.flag(privilege.is_raw());
                digest.flag(*sweep);
                digest.addresses(addresses);
            }
            Resolved::Listen { links } => {
                // A watch has no such pair to tell apart, so privilege is not
                // digested here. A listener has one way of working and no
                // fallback: it either opened a capture or it did nothing, and
                // either way it enumerated nothing and left no position for a
                // privilege change to invalidate.
                //
                // Hashing it refused a resume across `sudo`, which is ordinary
                // on a machine that captures through `access_bpf` or
                // `cap_net_raw`, and refused it with a message about recorded
                // positions this journal does not have.
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
/// A fingerprint that is written down cannot be built out of `Hash`.
/// `DefaultHasher` is not kept stable across releases of the standard library,
/// so upgrading the compiler would move the value, every journal on disk would
/// stop matching, and the refusal would say the plan had changed. The same
/// caveat covers the `Hash` implementations of the types fed to it, so the
/// bytes are chosen here instead.
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
///
/// `#[non_exhaustive]` because this type has grown six times and will grow
/// again: `kind`, `targets`, `technique`, `sweep`, `links` and `privilege` each
/// carry a `#[serde(default)]` recording a journal written before they existed,
/// and each addition would have broken a caller who built one by literal.
/// [`new`](Self::new) is how one is made, and reading is what everything else
/// does.
#[non_exhaustive]
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
    /// The key the order this journal's targets are asked in is a function of.
    ///
    /// Not part of the plan, and not part of [`PlanFingerprint`]: it decides the
    /// order the same targets are asked in and nothing about which targets those
    /// are, so a sitting resumed under a different one still covers the job. What it buys is that a resumed
    /// sitting does not have to. A scan that switched to a fresh order halfway
    /// through would emit a change of shape mid-run, which is a signature of its
    /// own; see [`Permutation`](crate::model::order::Permutation).
    ///
    /// [`None`] in a journal written before the order was keyed, which is
    /// resumed the way it was started: in plan order, shuffled within a batch.
    #[serde(default)]
    pub order_seed: Option<u64>,
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

    /// Writes a [`Privilege`] as the one bit a journal needs: whether the scan
    /// held raw sockets. The enum's other distinctions are about *why* it did
    /// not, which a resume cannot act on.
    pub(super) fn serialize<S: Serializer>(
        privilege: &Privilege,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        privilege.is_raw().serialize(serializer)
    }

    /// Reads the bit [`serialize`] wrote back into a [`Privilege`].
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
            // Drawn here because a journal is created once and the order is a
            // property of the job rather than of a sitting. Every sitting after
            // the first reads it back, which is what it is written down for.
            order_seed: Some(rand::random()),
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
    /// ranges and ports written down rather than from anything a caller typed, so
    /// a hostname that has since moved does not change what is being continued.
    /// The exclusion policy is already in it, having been applied before the plan
    /// was recorded.
    pub fn recorded(&self) -> Plan {
        // Built here rather than through the constructors. The policy was
        // applied before this was written down, and applying it again would
        // subtract a second time against whatever policy is in force now.
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
            ScanKind::PortScan => Resolved::PortScan {
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

/// The options a job runs under, as its journal records them.
///
/// A plan says which targets a job walks. This says how it asks them, so that a
/// later sitting given nothing but the journal asks the rest the way the first
/// sitting asked the start. Recorded by the engine when a journal's first
/// sitting starts, from the configuration that sitting runs under; see
/// [`Journal::options`](crate::journal::Journal::options).
///
/// # What is recorded, and what a later sitting may change
///
/// Five kinds of option, told apart by what changing one between two sittings
/// would do to the job.
///
/// **What the job asks, and what its answers mean.** The TCP and SCTP
/// techniques, the retry policy, whether a port scan asks first whether a host
/// is there, the passes beyond the port scan (operating system and service
/// identification, the detection ceiling, TLS enumeration, route tracing, filter
/// characterisation and the IP protocol pass), the ports held back from
/// probing, the evasion profile and an idle scan's zombie. A sitting under a
/// different one answers a different question, and its answers would stand in
/// one report beside the first sitting's as though they were answers to the
/// same one. These are restored, and a sitting that asks for a different one is
/// refused; see [`check`](Self::check).
///
/// **Which ports the job sends nothing.** The ports excluded outright. An
/// exclusion only narrows what a scan asks, and it is how a device that cannot
/// take a probe is kept from one, so a later sitting may exclude more than the
/// first did and may not exclude less: restored as the union of the recorded
/// set and the caller's, and a sitting that drops one is refused. The job's
/// plan stays numbered without the recorded set alone, since a numbering
/// without the added ports too would move every target after one of them to
/// another position. A sitting sends its added ones nothing, settling each
/// target at them it walks past as withheld, and drops them from the hosts it
/// restores, so no pass after its probes reaches one either; a target settled
/// so is owed to no later sitting, whatever that one excludes.
///
/// **Who each address is asked as.** The name a target gave an address, which
/// a web port is asked for by. Restored, so a sitting given nothing but the
/// journal asks for the sites the first asked for; not held to the record,
/// since a name is how an address is addressed rather than which question it
/// is asked, and a caller resolving the targets again may find them named
/// otherwise.
///
/// **How fast, for how long, and what else goes on the wire.** The probe-rate
/// ceiling and floor, the gap kept between probes at one host, the per-host and
/// per-sitting budgets, how raw probes are placed on the wire, and whether the
/// scan may send DNS queries of its own. These decide a sitting's pace and the
/// traffic beside its probes, not what a probe asks or what an answer means,
/// and each sitting's phase records the values it ran under. They are restored,
/// so a sitting given nothing runs as the first did, and a caller may set them
/// otherwise: a scan resumed after it upset a network is resumed slower.
///
/// **Not recorded.** Whether identifying detail is masked, and whether the
/// capture keeps ICMP errors a technique did not need, which decide what a
/// report shows rather than what the scan sends. The source addresses a scan
/// was pinned to, which name this machine's interfaces and belong to the
/// machine a sitting runs on. And the exclusion policy and the segment sweep,
/// which are the plan's and checked there.
///
/// A watch records none of them. It sends nothing, so nothing here decides
/// what it asks; see
/// [`listen_with_journal`](crate::scanner::listen_with_journal).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobOptions {
    /// Every setting a sitting's phase records, in the form a journal writes
    /// it. Carries both recorded kinds and the two that are not restored, since
    /// it is one record and splitting it would give it a second vocabulary.
    pub settings: SettingsRecord,
    /// Whether a port scan probed every target without asking first whether
    /// its host was there.
    #[serde(default)]
    pub assume_up: bool,
    /// The name each address was asked for by, where a target named a host;
    /// see [`ZondConfig::target_names`].
    #[serde(default)]
    pub target_names: BTreeMap<IpAddr, String>,
}

impl JobOptions {
    /// The options `cfg` runs a job under.
    pub fn of(cfg: &ZondConfig) -> Self {
        Self {
            settings: SettingsRecord::from(&ScanSettings::from(cfg)),
            assume_up: cfg.assume_up,
            target_names: cfg.target_names.clone(),
        }
    }

    /// Restores every recorded option onto `cfg`, leaving the ones that are not
    /// recorded as they are, and adding the recorded excluded ports to the ones
    /// `cfg` already excludes; see the type on why a sitting may exclude more.
    ///
    /// A caller continuing a job by its id starts from here, and lays whatever
    /// its user set for this sitting on top: what the job asks is then checked
    /// by [`check`](Self::check), and its pace is the user's to change.
    pub fn apply_to(&self, cfg: &mut ZondConfig) {
        let recorded = ScanSettings::from(&self.settings);

        cfg.assume_up = self.assume_up;
        cfg.target_names = self.target_names.clone();
        cfg.tcp_technique = recorded.tcp_technique;
        cfg.sctp_technique = recorded.sctp_technique;
        cfg.retry = recorded.retry;
        cfg.os_detection = recorded.os_detection;
        cfg.service_detection = recorded.service_detection;
        cfg.detection = recorded.detection;
        cfg.traceroute = recorded.traceroute;
        cfg.characterise = recorded.characterise;
        cfg.ip_protocols = recorded.ip_protocols.into_iter().collect();
        cfg.tls_enumeration = recorded.tls_enumeration;
        cfg.listen_only_ports = recorded.listen_only_ports.into_iter().collect();
        cfg.excluded_ports = recorded.excluded_ports.union(&cfg.excluded_ports);
        cfg.evasion = recorded
            .evasion
            .map(|evasion| EvasionProfile {
                source_port: evasion.source_port,
                ttl: evasion.ttl,
                padding: evasion.padding,
                bad_tcp_checksum: evasion.bad_tcp_checksum,
                spoof_mac: evasion.spoof_mac,
                fragment: evasion.fragment,
                decoys: evasion.decoys,
                flags: evasion.flags,
            })
            .unwrap_or_default();
        cfg.idle_scan = recorded.idle_scan;

        cfg.send_mode = recorded.send_mode;
        cfg.max_probe_rate = recorded.max_probe_rate;
        cfg.min_probe_rate = recorded.min_probe_rate;
        cfg.host_probe_interval = recorded.host_probe_interval;
        cfg.host_timeout = recorded.host_timeout;
        cfg.scan_timeout = recorded.scan_timeout;
        cfg.no_dns = !recorded.dns_enabled;
    }

    /// The ports the job's first sitting excluded outright, which its plan is
    /// numbered without; see the type on the ones a later sitting adds.
    pub(crate) fn excluded_ports(&self) -> PortSet {
        ScanSettings::from(&self.settings).excluded_ports
    }

    /// Whether a sitting under `cfg` asks what this job asks, naming the first
    /// option where it does not.
    ///
    /// Only the options that decide what the job asks and what its answers
    /// mean, and the ports it sends nothing, of which a sitting may exclude
    /// more; the type's documentation lists them, and why the others may move.
    /// Compared in the form the journal writes, so a value is the same value
    /// however it was read back.
    pub fn check(&self, cfg: &ZondConfig) -> Result<(), OptionChanged> {
        let recorded = &self.settings;
        let this = Self::of(cfg);
        let offered = &this.settings;

        let changed = [
            ("assume_up", self.assume_up != this.assume_up),
            (
                "tcp_technique",
                recorded.tcp_technique != offered.tcp_technique,
            ),
            (
                "sctp_technique",
                recorded.sctp_technique != offered.sctp_technique,
            ),
            (
                "retry.effort",
                recorded.retry_effort != offered.retry_effort,
            ),
            (
                "retry.max_attempts",
                recorded.retry_max_attempts != offered.retry_max_attempts,
            ),
            (
                "retry.timeout_scale",
                recorded.retry_timeout_scale != offered.retry_timeout_scale,
            ),
            (
                "retry.dampen_silent_hosts",
                recorded.retry_dampen_silent_hosts != offered.retry_dampen_silent_hosts,
            ),
            (
                "os_detection",
                recorded.os_detection != offered.os_detection,
            ),
            (
                "service_detection",
                recorded.service_detection != offered.service_detection,
            ),
            ("detection", recorded.detection != offered.detection),
            ("traceroute", recorded.traceroute != offered.traceroute),
            (
                "characterise",
                recorded.characterise != offered.characterise,
            ),
            (
                "ip_protocols",
                recorded.ip_protocols != offered.ip_protocols,
            ),
            (
                "tls_enumeration",
                recorded.tls_enumeration != offered.tls_enumeration,
            ),
            (
                "listen_only_ports",
                recorded.listen_only_ports != offered.listen_only_ports,
            ),
            (
                "excluded_ports",
                !self
                    .excluded_ports()
                    .difference(&cfg.excluded_ports)
                    .is_empty(),
            ),
            ("evasion", recorded.evasion != offered.evasion),
            ("idle_scan", recorded.idle_scan != offered.idle_scan),
        ];

        match changed.into_iter().find(|(_, changed)| *changed) {
            Some((option, _)) => Err(OptionChanged { option }),
            None => Ok(()),
        }
    }
}

/// A sitting asks for an option the job it continues did not run under.
///
/// Names the option, by the name of the
/// [`ZondConfig`] field that sets it, since that is what a caller changes to
/// continue the job as it was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionChanged {
    /// The option, as a [`ZondConfig`] field path: `assume_up`, `retry.effort`.
    pub option: &'static str,
}

impl std::fmt::Display for OptionChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "this sitting's {} is not the one the journal's scan ran under",
            self.option
        )
    }
}

impl std::error::Error for OptionChanged {}

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
    /// of them would pass with a derivation built on `DefaultHasher`, whose
    /// output the standard library declines to keep stable across compiler
    /// releases. Its value moves when the toolchain does, and every journal on
    /// disk would be refused as a plan that had changed. A test comparing two
    /// fingerprints taken in one process cannot see that. This one can.
    ///
    /// A failure here means the derivation moved. That is allowed, and it is a
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

    /// The order a journal's targets are asked in survives the round trip, and a
    /// journal written before the field existed reads as no order rather than as
    /// the one seed 0 names.
    ///
    /// The difference is what a sitting resuming an old journal gets: the walk
    /// that journal was written under, rather than a rearrangement it never used.
    #[cfg(feature = "journal-format")]
    #[test]
    fn a_manifest_that_records_no_order_asks_for_none() {
        let map = plan(&[("192.0.2.1", "80")]);
        let manifest = JournalManifest::new("01J8Z5Q7VN", &ports(&map), Privilege::Raw, "");
        assert!(manifest.order_seed.is_some(), "a fresh journal draws one");

        let mut written = serde_json::to_value(&manifest).expect("a manifest serializes");
        let read: JournalManifest =
            serde_json::from_value(written.clone()).expect("and reads back");
        assert_eq!(read.order_seed, manifest.order_seed);

        written
            .as_object_mut()
            .expect("an object")
            .remove("order_seed");
        let read: JournalManifest =
            serde_json::from_value(written).expect("an older journal reads");
        assert_eq!(read.order_seed, None);
    }

    /// Two journals of the same plan ask about it in different orders, so the
    /// seed is drawn per journal rather than derived from anything the plan says.
    #[cfg(feature = "journal-format")]
    #[test]
    fn two_journals_of_one_plan_ask_about_it_differently() {
        let map = plan(&[("192.0.2.0/24", "1-1024")]);
        let one = JournalManifest::new("01J8Z5Q7VN", &ports(&map), Privilege::Raw, "");
        let other = JournalManifest::new("01J8Z5Q7VP", &ports(&map), Privilege::Raw, "");

        assert_eq!(one.plan, other.plan, "the same plan");
        assert_ne!(one.order_seed, other.order_seed, "asked in its own order");
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

    /// A link-local plan has to survive the round trip in order. The set sorts
    /// IPv6 by zone before address, so a record coming back with the interfaces
    /// in another order would enumerate differently and every position an earlier
    /// sitting settled would name a different machine.
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

    /// A watch names links, where a sweep and a port scan name targets. The phase
    /// is hashed first, so no two of the three can agree and a journal of one
    /// cannot be continued as another.
    #[test]
    fn a_watch_never_shares_a_fingerprint_with_a_phase_that_walks_targets() {
        let listen = Plan::listen(vec![Zone::unresolved("en0")]);
        let mut ips = IpSet::new();
        ips.insert_range("192.0.2.0/24".parse().expect("a valid range"));

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
    /// A port scan begun with raw sockets and resumed without them falls back to
    /// completing handshakes, which answers a different question, so the second
    /// sitting would fill the first's gaps with weaker evidence and report
    /// success. A listener has no second way of working: it opened a capture or
    /// it did nothing, and it enumerated nothing either way.
    ///
    /// Both halves are asserted together because the risk runs both ways.
    /// Covering a watch refused a resume across `sudo`, which is ordinary on a
    /// machine that captures through `access_bpf` or `cap_net_raw`, and
    /// uncovering a port scan is the silent wrong coverage this module exists to
    /// prevent.
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

    /// A configuration that sets something of every recorded kind.
    fn set_apart() -> ZondConfig {
        let mut cfg = ZondConfig {
            assume_up: true,
            traceroute: true,
            tls_enumeration: true,
            characterise: true,
            no_dns: true,
            redact: true,
            icmp_evidence: true,
            tcp_technique: TcpScanTechnique::Fin,
            max_probe_rate: std::num::NonZeroU32::new(200),
            scan_timeout: Some(std::time::Duration::from_secs(60)),
            evasion: EvasionProfile::default().with_ttl(12).with_source_port(53),
            ..ZondConfig::default()
        };
        cfg.retry.effort = crate::config::ScanEffort::Thorough;
        cfg.ip_protocols = [1, 6].into_iter().collect();
        cfg.listen_only_ports.clear();
        cfg.excluded_ports = "22,u:161".try_into().expect("a port specification");
        cfg.target_names.insert(
            "192.0.2.1".parse().expect("an address"),
            "box.example".into(),
        );
        cfg
    }

    /// Restored onto a configuration that set none of them, a job's options
    /// ask what they asked, and hold its pace, and leave alone what a sitting
    /// decides for itself.
    #[test]
    fn a_jobs_options_restore_what_it_asked_and_its_pace() {
        let recorded = JobOptions::of(&set_apart());
        let mut restored = ZondConfig {
            redact: false,
            icmp_evidence: false,
            ..ZondConfig::default()
        };
        recorded.apply_to(&mut restored);

        assert_eq!(recorded.check(&restored), Ok(()));
        assert!(restored.assume_up);
        assert_eq!(restored.tcp_technique, TcpScanTechnique::Fin);
        assert_eq!(restored.evasion, set_apart().evasion);
        assert_eq!(restored.ip_protocols, set_apart().ip_protocols);
        assert!(restored.listen_only_ports.is_empty(), "print ports probed");
        assert_eq!(restored.excluded_ports, set_apart().excluded_ports);
        assert_eq!(restored.max_probe_rate, std::num::NonZeroU32::new(200));
        assert_eq!(
            restored.scan_timeout,
            Some(std::time::Duration::from_secs(60))
        );
        assert!(restored.no_dns);
        assert_eq!(restored.target_names, set_apart().target_names);

        assert!(!restored.redact, "masking is what this sitting shows");
        assert!(!restored.icmp_evidence, "and so is what the capture keeps");
    }

    /// Every option that decides what a job asks refuses a sitting that sets
    /// it otherwise, by name; its pace does not.
    #[test]
    fn a_sitting_asking_something_else_is_refused_by_the_option_it_changed() {
        let recorded = JobOptions::of(&ZondConfig::default());
        let changed = |change: fn(&mut ZondConfig)| {
            let mut cfg = ZondConfig::default();
            change(&mut cfg);
            recorded.check(&cfg).err().map(|changed| changed.option)
        };

        assert_eq!(changed(|cfg| cfg.assume_up = true), Some("assume_up"));
        assert_eq!(
            changed(|cfg| cfg.tcp_technique = TcpScanTechnique::Fin),
            Some("tcp_technique")
        );
        assert_eq!(
            changed(|cfg| cfg.retry.max_attempts = std::num::NonZeroU8::new(1)),
            Some("retry.max_attempts")
        );
        assert_eq!(changed(|cfg| cfg.traceroute = true), Some("traceroute"));
        assert_eq!(
            changed(|cfg| cfg.listen_only_ports.clear()),
            Some("listen_only_ports")
        );
        assert_eq!(
            changed(|cfg| cfg.evasion = EvasionProfile::default().with_ttl(3)),
            Some("evasion")
        );

        for pace in [
            (|cfg: &mut ZondConfig| cfg.max_probe_rate = std::num::NonZeroU32::new(10))
                as fn(&mut ZondConfig),
            |cfg| cfg.host_timeout = Some(std::time::Duration::from_secs(5)),
            |cfg| cfg.no_dns = true,
            |cfg| cfg.redact = true,
            |cfg| {
                cfg.target_names.insert(
                    "192.0.2.1".parse().expect("an address"),
                    "box.example".into(),
                );
            },
        ] {
            assert_eq!(changed(pace), None);
        }
    }

    /// A sitting may exclude ports the job did not, and is restored with the
    /// job's beside its own, but one that drops a port the job excluded is
    /// refused by that option.
    ///
    /// An exclusion keeps a device that cannot take a probe from one. Held to
    /// the record like the rest, a port added between sittings is either
    /// refused, costing the job, or overwritten by the record on restoring,
    /// and probed; dropped, a port the job promised to spare is asked.
    #[test]
    fn a_sitting_may_exclude_more_ports_than_its_job_and_never_fewer() {
        let excluding = |ports: &str| ZondConfig {
            excluded_ports: ports.try_into().expect("ports"),
            ..ZondConfig::default()
        };
        let recorded = JobOptions::of(&excluding("22"));

        let mut more = excluding("9100");
        recorded.apply_to(&mut more);
        assert_eq!(more.excluded_ports.to_string(), "22,9100");
        assert_eq!(recorded.check(&more), Ok(()));
        assert_eq!(recorded.excluded_ports().to_string(), "22");

        assert_eq!(
            recorded
                .check(&excluding("9100"))
                .err()
                .map(|changed| changed.option),
            Some("excluded_ports")
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
