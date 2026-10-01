// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a journal is a journal of
//!
//! A cursor is a number that means something only against the plan it was counted in,
//! so the plan travels with it and a resumed scan can prove the plan has not moved.
//!
//! ## Why a position is not self-describing
//!
//! [`Cursor`](super::cursor) records that position 4,001,927 is settled.
//! [`TargetMap::iter`](crate::model::target::TargetMap::iter) says which target that is, and
//! answers differently if anything about the plan changed: a port added, a range widened,
//! an exclusion policy edited, a unit added. That happens whenever somebody edits a settings
//! file between two sittings, and resuming across it would scan the wrong targets and
//! report success.
//!
//! So the plan is fingerprinted when the journal is created and checked when it is resumed,
//! and a mismatch is a refusal. A caller who wants the new plan is starting a new scan,
//! with a new journal.
//!
//! ## Two shapes of plan
//!
//! [`discover`](crate::scanner::discover) walks addresses; [`scan`] walks addresses paired
//! with ports. A journal records which phase it holds, and [`Plan`] is how a caller says.
//! The phase goes into the fingerprint first, so a sweep and a port scan over the same
//! addresses can never match.
//!
//! [`scan`]: crate::scanner::scan
//!
//! ## What the fingerprint covers
//!
//! Hashing the enumeration of a `/8` would cost more than the scan. The fingerprint covers
//! the structure that decides the enumeration: the canonical address ranges, each unit's
//! port list in order, the technique or the sweep flag, and the privilege level, plus the
//! total as a cross-check. That is a few hundred bytes of hashing for a plan of any size,
//! and it changes whenever a position's meaning changes.
//!
//! ## Privilege is part of the plan, for the plans that probe
//!
//! A scan begun privileged and resumed unprivileged is not the same scan continued: the
//! connect fallback can only complete handshakes, so it answers a different question than a
//! raw technique (see [`TcpScanTechnique`]). The fingerprint refuses that resume up front.
//!
//! A watch is not covered. A listener sends nothing, has no fallback and enumerates
//! nothing, so a privilege change cannot give any position a second meaning, and resuming
//! one across `sudo` is ordinary on a machine that captures through `access_bpf` or
//! `cap_net_raw`.

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
/// A position means an address for [`discover`](crate::scanner::discover) and an
/// address-and-port pair for [`scan`](crate::scanner::scan), so a journal says which it
/// holds.
///
/// # The exclusion policy is part of the plan
///
/// An excluded address is never probed, so it never settles. Numbering a plan that still
/// held one would stall a resumed scan's watermark at the first exclusion and count a total
/// the scan can never reach. The policy also decides the enumeration: withhold the first
/// half of a range and every later position names a different target.
///
/// So constructing a plan applies the policy, and a caller cannot hold a plan without it.
/// Applying it again inside the scan removes nothing.
#[derive(Debug, Clone)]
pub struct Plan(Resolved);

/// A plan's shapes. Private, so the constructors, which apply the exclusion policy,
/// are the only way in.
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
    /// The one plan that enumerates nothing: no set to walk, no position to settle, no
    /// total to reach. See [`Plan::listen`].
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
    /// A listener is pointed at a link, so there is no set of things that could be finished. A
    /// listen journal has no cursor, and resuming one appends a sitting. What the journal buys
    /// is that the findings survive a listener that stopped, and the report describes the whole
    /// watch.
    ///
    /// # Exclusions
    ///
    /// The exclusion policy is not applied here because there is no set to narrow. A listener
    /// enforces it where findings are recorded, as every phase does at the store, and it is not
    /// part of this plan's identity.
    ///
    /// # What identifies the job
    ///
    /// The links, by name. The recording scope is not included: with nothing enumerated, a
    /// changed scope renumbers nothing, and what each sitting covered is on its own phase.
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
            // There is no unit a watch could be counted in. See `Plan::listen`.
            Resolved::Listen { .. } => 0,
        }
    }

    /// How many targets the plan numbers: what a job's progress is drawn against, and
    /// what it has finished once each is settled.
    ///
    /// [`total_targets`](Self::total_targets) for a sweep. For a port scan, less what the port
    /// phase takes out before numbering: a link-local range naming no interface, an address two
    /// ranges name on two interfaces, and a range too wide to walk; see
    /// [`TargetMap::take_unprobeable`]. Those are refused in every sitting, so a total counting
    /// them would never be reached.
    ///
    /// `excluded_ports` are the job's excluded ports, which every sitting of a port scan
    /// numbers its plan without; see [`JobOptions`].
    pub(crate) fn numbered_targets(&self, excluded_ports: &PortSet) -> u128 {
        match &self.0 {
            Resolved::PortScan { targets, .. } => {
                let mut numbered = targets.clone();
                numbered.withhold_ports(excluded_ports);
                numbered.take_unprobeable(&[], crate::system::interface::is_enumerable);
                numbered.gross_targets().unwrap_or_default()
            }
            Resolved::Discovery { .. } | Resolved::Listen { .. } => self.total_targets(),
        }
    }

    /// The addresses a sweep will walk, or `None` for a port scan, which counts
    /// address-and-port pairs.
    pub fn addresses(&self) -> Option<&IpSet> {
        match &self.0 {
            Resolved::Discovery { addresses, .. } => Some(addresses),
            Resolved::PortScan { .. } | Resolved::Listen { .. } => None,
        }
    }

    /// The targets a port scan will walk, or `None` for a sweep.
    pub fn targets(&self) -> Option<&TargetMap> {
        match &self.0 {
            Resolved::PortScan { targets, .. } => Some(targets),
            Resolved::Discovery { .. } | Resolved::Listen { .. } => None,
        }
    }

    /// Which TCP segment a port scan's probes carry, or `None` for a sweep.
    pub fn technique(&self) -> Option<TcpScanTechnique> {
        match &self.0 {
            Resolved::PortScan { technique, .. } => Some(*technique),
            Resolved::Discovery { .. } | Resolved::Listen { .. } => None,
        }
    }

    /// Whether a sweep may go beyond the addresses it was given. False for a port scan,
    /// whose liveness pass is targeted.
    pub fn sweeps_the_segment(&self) -> bool {
        matches!(self.0, Resolved::Discovery { sweep: true, .. })
    }

    /// The plan as a file holds it.
    pub fn record(&self) -> PlanRecord {
        match &self.0 {
            Resolved::Discovery { addresses, .. } => PlanRecord::from(addresses),
            Resolved::PortScan { targets, .. } => PlanRecord::from(targets),
            // A watch's links are recorded on the manifest, beside the technique and the sweep
            // flag.
            Resolved::Listen { .. } => PlanRecord::default(),
        }
    }
}

/// A fingerprint of the plan a cursor's positions are counted in.
///
/// Compared, never interpreted. Its derivation belongs to the format and may change
/// only with [`JOURNAL_VERSION`](super::format::JOURNAL_VERSION).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlanFingerprint(u64);

impl PlanFingerprint {
    /// Fingerprints a resolved plan.
    ///
    /// `privilege` is what the scan could actually send, not what it asked for, since
    /// that decides which question the probes answered. It is ignored for a watch, which sends
    /// no probe. It goes in as the boolean the manifest writes.
    ///
    /// The digest walks each unit's canonical ranges and ports, so this is cheap on a plan of
    /// any size. Each field's count goes in before the field, so one unit of two ranges and two
    /// units of one do not digest the same.
    ///
    /// Every enum goes in as its wire name, not a derived hash: a derived hash is a variant's
    /// position in its declaration, so inserting a technique anywhere but the end would
    /// silently invalidate every journal on disk. See [`record::wire`](crate::record::wire).
    pub fn of(plan: &Plan, privilege: Privilege) -> Self {
        let mut digest = Digest::new();

        // The phase first: a position from a sweep read against a port scan names a
        // target nobody probed.
        digest.text(wire::scan_kind_name(plan.kind()));

        match &plan.0 {
            Resolved::Discovery { addresses, sweep } => {
                // A raw SYN and a connect attempt ask different questions of the same port, so
                // privilege is digested for the enumerating phases.
                digest.flag(privilege.is_raw());
                digest.flag(*sweep);
                digest.addresses(addresses);
            }
            Resolved::Listen { links } => {
                // Privilege is not digested for a watch: it enumerates nothing, so there is no
                // position a privilege change could invalidate.
                //
                // Links go in by name. An interface index changes across a reboot; the name is
                // what two sittings of one watch agree on.
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

        // A cheap cross-check that turns a collision in the structure digest into a
        // mismatch.
        digest.wide(plan.total_targets());

        Self(digest.finish())
    }
}

/// The plan digest: FNV-1a over bytes chosen here, borrowing nothing from a `Hash`
/// implementation.
///
/// `DefaultHasher` and the `Hash` impls of the fed types are not stable across releases, so
/// a compiler upgrade would move the value and every journal on disk would be refused as a
/// changed plan.
///
/// Non-cryptographic: anyone who can edit a manifest can edit the fingerprint beside it.
/// The value only has to be a function of the plan.
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

    /// A string, length first, so two adjacent fields cannot run together into a third
    /// that digests the same.
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
    /// Each family's count goes in before its ranges, so one set of two ranges and two
    /// sets of one differ. The family tag goes in too, so a v4 and a v6 range whose octets
    /// coincide differ.
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
            // The zone is part of a link-local address: `fe80::1` names a different machine on
            // every segment. Absent and zero are told apart, since zero is a valid scope id.
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
/// Written once when the journal is created and never rewritten, so it is safe to
/// read without a lock.
///
/// `#[non_exhaustive]`, with [`new`](Self::new) as the constructor, because fields keep
/// being added; each added field carries `#[serde(default)]` so older journals still
/// read.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalManifest {
    /// The journal format this was written under, so an older reader refuses it.
    /// Mirrors the header on every journal file, so the manifest can be read on its own.
    pub journal_version: u32,
    /// The scan this journal belongs to.
    pub id: String,
    /// The engine build that created it, for diagnostics.
    pub engine_version: String,
    /// When the first sitting began.
    pub created_at: SystemTime,
    /// Which phase this is a journal of, by wire name.
    ///
    /// A sweep counts addresses and a port scan counts address-and-port pairs, so this
    /// decides what everything below is measured in. Absent means a port scan.
    #[serde(default)]
    pub kind: String,
    /// The plan every position in this journal is counted in.
    pub plan: PlanFingerprint,
    /// The plan itself, so a scan can be continued without being described again.
    /// Ranges and port lists, so it stays small for a plan of any size.
    #[serde(default)]
    pub targets: PlanRecord,
    /// Which segment each TCP probe carried, by wire name. Part of the plan, since a
    /// port's verdict means different things under different techniques. Empty for a sweep.
    #[serde(default)]
    pub technique: String,
    /// Whether a sweep was allowed onto the segment beyond the addresses it was given.
    /// Part of the plan, since it decides what the scan covered. Always false for a port
    /// scan.
    #[serde(default)]
    pub sweep: bool,
    /// The links a watch reads, by name. Part of the plan. Names survive a reboot;
    /// interface indexes do not. Empty for the phases that walk targets.
    #[serde(default)]
    pub links: Vec<String>,
    /// What the scan was able to send.
    ///
    /// A resume must run under the same answer: the connect fallback asks a different
    /// question than a raw technique does.
    #[serde(
        rename = "privileged",
        default = "wire_privilege::unrecorded",
        with = "wire_privilege"
    )]
    pub privilege: Privilege,
    /// How many targets the plan numbers, so a caller can report progress without
    /// walking it: everything it holds except what a port scan refuses before numbering and the
    /// ports the job excludes. See [`Plan::total_targets`] for everything it holds.
    pub total_targets: u128,
    /// The key the order this journal's targets are asked in is derived from.
    ///
    /// Not part of the plan or the [`PlanFingerprint`]: it decides only the order, so a sitting
    /// resumed under a different one would still cover the job. Keeping it means a resumed
    /// sitting keeps the same order, since a scan that switched to a fresh order halfway would
    /// change shape mid-run, a signature of its own; see
    /// [`Permutation`](crate::model::order::Permutation).
    ///
    /// [`None`] in a journal written before the order was keyed, which is resumed in plan
    /// order, shuffled within a batch.
    #[serde(default)]
    pub order_seed: Option<u64>,
    /// A human-readable summary of what was scanned, for a caller listing journals.
    /// Nothing is decided from it, and its shape may change between versions.
    pub summary: String,
}

/// The manifest's `privileged` field as written: a boolean. Writing the full enum
/// would change every existing journal and need a
/// [`JOURNAL_VERSION`](crate::journal::JOURNAL_VERSION) bump.
mod wire_privilege {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::system::privilege::Privilege;

    /// What a journal written before the field existed was scanning under: connect.
    pub(super) fn unrecorded() -> Privilege {
        Privilege::Connect
    }

    /// Writes a [`Privilege`] as the one bit a journal needs: whether the scan held raw
    /// sockets. The other variants say why it did not, which a resume cannot act on.
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
            // The job's excluded ports are not known until its first sitting records its
            // options, which counts them out then; see `Journal::record_options`.
            total_targets: plan.numbered_targets(&PortSet::new()),
            // The order belongs to the job, so it is drawn once here and read back by every
            // later sitting.
            order_seed: Some(rand::random()),
            summary: summary.into(),
        }
    }

    /// Which phase this journal records.
    ///
    /// A journal that names no kind is a port scan.
    pub fn kind(&self) -> ScanKind {
        wire::scan_kind(&self.kind).unwrap_or(ScanKind::PortScan)
    }

    /// The plan this journal was counted in, as it was recorded.
    ///
    /// What a resume scans. Rebuilt from the recorded ranges and ports, so a hostname
    /// that has since moved does not change what is continued. The exclusion policy was already
    /// applied before recording.
    pub fn recorded(&self) -> Plan {
        // Built directly: running the constructors would apply whatever exclusion policy is
        // in force now a second time.
        Plan(match self.kind() {
            ScanKind::Discovery => Resolved::Discovery {
                addresses: self.targets.addresses(),
                sweep: self.sweep,
            },
            // Unresolved zones: the recorded plan names the job and is fingerprinted by name. A
            // caller running the watch supplies links looked up on this machine, since an index
            // read from a file belongs to another boot.
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
    /// Falls back to the default for a journal that did not record it, which the
    /// fingerprint then refuses if it was anything else.
    pub fn technique(&self) -> TcpScanTechnique {
        self.technique.parse().unwrap_or_default()
    }

    /// Whether `plan` under `privilege` is the plan this journal was counted in.
    pub fn covers(&self, plan: &Plan, privilege: Privilege) -> Result<(), PlanChanged> {
        let found = PlanFingerprint::of(plan, privilege);
        if found == self.plan {
            return Ok(());
        }

        Err(PlanChanged {
            expected: self.plan,
            found,
            expected_targets: self.total_targets,
            found_targets: plan.numbered_targets(&PortSet::new()),
        })
    }
}

/// The plan a journal was counted in is not the plan now being resumed.
///
/// Carries both target counts because a person can act on them: "40,960 then,
/// 81,920 now" points at the edit.
#[non_exhaustive]
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
/// A plan says which targets a job walks; this says how it asks them, so a later
/// sitting given only the journal asks the rest the way the first sitting asked the start.
/// Recorded when a journal's first sitting starts; see
/// [`Journal::options`](crate::journal::Journal::options).
///
/// # What is recorded, and what a later sitting may change
///
/// **What the job asks, and what its answers mean.** The TCP and SCTP techniques, the retry
/// policy, whether a port scan checks liveness first, the passes beyond the port scan
/// (operating system and service identification, the detection ceiling, TLS enumeration,
/// route tracing, filter characterisation and the IP protocol pass), the ports held back
/// from probing, the evasion profile and an idle scan's zombie. A sitting under a different
/// value answers a different question, and its answers would sit in one report beside the
/// first sitting's. Restored, and a sitting that asks for a different value is refused; see
/// [`check`](Self::check).
///
/// **Which ports the job sends nothing.** The excluded ports. An exclusion only narrows a
/// scan and is how a fragile device is protected, so a later sitting may exclude more but
/// not less: restored as the union of the recorded set and the caller's, and a sitting that
/// drops one is refused. The plan stays numbered without the recorded set alone, since
/// renumbering would move every later target. A sitting sends its added ports nothing,
/// settles each target at them as withheld, and drops them from the hosts it restores; a
/// target settled that way is owed to no later sitting.
///
/// **Who each address is asked as.** The name a target gave an address, which a web port
/// is asked for by. Restored, but not held to the record, since a caller resolving the
/// targets again may find them named otherwise.
///
/// **How fast, for how long, and what else goes on the wire.** The probe-rate ceiling and
/// floor, the per-host probe gap, the per-host and per-sitting budgets, raw probe placement
/// on the wire, and whether the scan may send its own DNS queries. These set pace and side
/// traffic, not what a probe asks, and each sitting's phase records its own values.
/// Restored, and a caller may change them: a scan that upset a network can resume slower.
///
/// **Not recorded.** Masking of identifying detail and keeping unneeded ICMP errors, which
/// decide what a report shows. Pinned source addresses, which belong to the machine a
/// sitting runs on. The exclusion policy and segment sweep, which are part of the plan.
///
/// A watch records none of them, since it sends nothing; see
/// [`listen_with_journal`](crate::scanner::listen_with_journal).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobOptions {
    /// Every setting a sitting's phase records, in journal form. Includes the settings
    /// that are not restored, to keep one record and one vocabulary.
    pub settings: SettingsRecord,
    /// Whether a port scan probed every target without checking liveness first.
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

    /// Restores every recorded option onto `cfg`, leaving unrecorded ones as they are,
    /// and adds the recorded excluded ports to those `cfg` already excludes.
    ///
    /// A caller continuing a job by its id starts here and lays its user's settings for this
    /// sitting on top. [`check`](Self::check) then verifies what the job asks; the pace is the
    /// user's to change.
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
        cfg.probe_interval = recorded.probe_interval;
        cfg.host_timeout = recorded.host_timeout;
        cfg.scan_timeout = recorded.scan_timeout;
        cfg.no_dns = !recorded.dns_enabled;
    }

    /// The ports the job's first sitting excluded outright, which its plan is numbered
    /// without.
    pub(crate) fn excluded_ports(&self) -> PortSet {
        ScanSettings::from(&self.settings).excluded_ports
    }

    /// Whether a sitting under `cfg` asks what this job asks, naming the first option
    /// where it does not.
    ///
    /// Checks only the options that decide what the job asks and what its answers mean, plus
    /// the excluded ports, of which a sitting may exclude more; see the type's documentation.
    /// Compared in journal form, so a value read back compares equal to itself.
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
/// Names the option by its [`ZondConfig`] field, which is what a caller changes to
/// continue the job as recorded.
#[non_exhaustive]
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
    /// The other tests compare two fingerprints from one process, and would all pass with a
    /// derivation built on `DefaultHasher`, whose output can change between compiler releases
    /// and would then refuse every journal on disk.
    ///
    /// A failure here means the derivation moved. That needs a
    /// [`JOURNAL_VERSION`](crate::journal::JOURNAL_VERSION) bump and an updated number here.
    #[test]
    fn the_derivation_is_pinned_to_a_value() {
        assert_eq!(
            print(&plan(&[("192.0.2.1-192.0.2.10", "80,443")])).0,
            0xa4d1_e087_ea5b_98c2,
            "the plan fingerprint derivation has moved"
        );
    }

    /// The same plan fingerprints the same every time.
    #[test]
    fn the_same_plan_fingerprints_the_same() {
        let a = plan(&[("192.0.2.1-192.0.2.10", "80,443")]);
        let b = plan(&[("192.0.2.1-192.0.2.10", "80,443")]);

        assert_eq!(print(&a), print(&a), "not stable within one value");
        assert_eq!(print(&a), print(&b), "not stable across equal values");
    }

    /// Every edit that changes what a position means changes the fingerprint.
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

    /// Port order decides the enumeration, so the same ports in a different order are
    /// a different plan.
    #[test]
    fn the_order_of_the_ports_is_part_of_the_plan() {
        let ascending = plan(&[("192.0.2.1", "80,443")]);
        let descending = plan(&[("192.0.2.1", "443,80")]);

        // If the set canonicalises the order, the two are the same plan and must agree.
        let same_order =
            ascending.units[0].ports().to_vec() == descending.units[0].ports().to_vec();
        assert_eq!(
            print(&ascending) == print(&descending),
            same_order,
            "the fingerprint must follow the enumeration, whichever way the set orders it"
        );
    }

    /// Two units of one range do not hash as one unit of two: they enumerate
    /// differently.
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

    /// Privilege and technique each change the fingerprint.
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

    /// Privilege is written as the boolean the format has always had. Every journal on
    /// disk was fingerprinted from `"privileged": true`, and changing the spelling would refuse
    /// them all without a [`JOURNAL_VERSION`](super::super::JOURNAL_VERSION) change.
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

    /// The order seed survives the round trip, and a journal without the field reads as
    /// no order (the walk it was written under), not as seed 0.
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

    /// Two journals of the same plan ask in different orders: the seed is drawn per
    /// journal.
    #[cfg(feature = "journal-format")]
    #[test]
    fn two_journals_of_one_plan_ask_about_it_differently() {
        let map = plan(&[("192.0.2.0/24", "1-1024")]);
        let one = JournalManifest::new("01J8Z5Q7VN", &ports(&map), Privilege::Raw, "");
        let other = JournalManifest::new("01J8Z5Q7VP", &ports(&map), Privilege::Raw, "");

        assert_eq!(one.plan, other.plan, "the same plan");
        assert_ne!(one.order_seed, other.order_seed, "asked in its own order");
    }

    /// A journal without the field reads as a connect scan.
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

    /// A port scan's total leaves out the targets its port phase withholds before
    /// numbering: a link-local range naming no interface, an address another range names on
    /// another interface, and a range too wide to walk. Counting them, a job that settled
    /// everything it could ask would stay resumable for good.
    #[test]
    fn a_port_scans_total_leaves_out_what_its_port_phase_withholds() {
        let named = plan(&[
            ("fe80::1-fe80::2", "80,443"),
            ("192.0.2.1", "80,443"),
            ("2001:db8::/64", "80"),
        ]);
        let manifest = JournalManifest::new("01J8Z5Q7VN", &ports(&named), Privilege::Raw, "");
        assert_eq!(manifest.total_targets, 2);
    }

    /// The manifest accepts the plan it was made from and refuses anything else,
    /// naming the counts.
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

    /// A sweep and a port scan count in different units, so they never fingerprint
    /// alike, however much their addresses overlap.
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

    /// Whether a sweep may go beyond its addresses makes a different plan.
    #[test]
    fn a_segment_sweep_is_not_a_targeted_pass() {
        let ips = addresses("192.0.2.1-192.0.2.10");

        assert_ne!(
            PlanFingerprint::of(&sweeping(&ips, true), Privilege::Raw),
            PlanFingerprint::of(&sweeping(&ips, false), Privilege::Raw)
        );
    }

    /// A sweep's addresses come back as they went in.
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

    /// A link-local plan survives the round trip in order. The set sorts IPv6 by zone
    /// before address, so interfaces coming back in another order would renumber every
    /// position.
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
    /// message does not claim a count changed.
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

    /// A watch, a sweep and a port scan never fingerprint alike, so a journal of one
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

    /// A watch of a different link is a different job.
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

    /// A watch is the same watch whether or not this sitting is root; the probing
    /// phases are not. Both halves are asserted because the risk runs both ways: covering a
    /// watch refuses an ordinary resume across `sudo`, and not covering a port scan lets a
    /// connect sitting fill a raw sitting's gaps with weaker evidence.
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

    /// Links are fingerprinted by name, so a watch resumed after a reboot is the same
    /// watch.
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

    /// Restored onto a configuration that set none of them, a job's options restore
    /// what it asks and its pace, and leave alone what a sitting decides for itself.
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

    /// Every option that decides what a job asks refuses a sitting that changes it, by
    /// name; its pace does not.
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

    /// A sitting may exclude ports the job did not, and is restored with the job's
    /// beside its own, but one that drops a port the job excluded is refused.
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

    /// The recorded plan survives the round trip through a manifest, so a caller with
    /// only a journal id can say what it was watching.
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
