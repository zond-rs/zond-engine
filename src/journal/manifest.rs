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
//! ## Privilege is part of the plan
//!
//! A scan begun privileged and resumed unprivileged is not the same scan
//! continued. The connect fallback can only complete handshakes, so it answers a
//! different question than a raw technique does —
//! [`TcpScanTechnique`](crate::model::technique::TcpScanTechnique) makes exactly
//! this argument about not quietly substituting one for the other. Folding it
//! into the fingerprint means the refusal happens up front, rather than the
//! second sitting silently filling the first one's gaps with weaker evidence.

use std::hash::{Hash, Hasher};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::model::exclusion::Exclusions;
use crate::model::ip::set::IpSet;
use crate::model::target::TargetMap;
use crate::model::technique::TcpScanTechnique;
use crate::record::{PlanRecord, wire};
use crate::scanner::report::ScanKind;

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

    /// Which phase this plan belongs to.
    pub fn kind(&self) -> ScanKind {
        match self.0 {
            Resolved::Discovery { .. } => ScanKind::Discovery,
            Resolved::PortScan { .. } => ScanKind::PortScan,
        }
    }

    /// How many targets the plan holds, counted in the units its phase probes:
    /// addresses for a sweep, address-and-port pairs for a port scan.
    pub fn total_targets(&self) -> u128 {
        match &self.0 {
            Resolved::Discovery { addresses, .. } => addresses.len(),
            Resolved::PortScan { targets, .. } => targets.gross_targets().unwrap_or_default(),
        }
    }

    /// The addresses a sweep will walk, or `None` for a port scan, which is
    /// counted in address-and-port pairs rather than addresses.
    pub fn addresses(&self) -> Option<&IpSet> {
        match &self.0 {
            Resolved::Discovery { addresses, .. } => Some(addresses),
            Resolved::PortScan { .. } => None,
        }
    }

    /// The targets a port scan will walk, or `None` for a sweep, which has no
    /// ports.
    pub fn targets(&self) -> Option<&TargetMap> {
        match &self.0 {
            Resolved::PortScan { targets, .. } => Some(targets),
            Resolved::Discovery { .. } => None,
        }
    }

    /// Which TCP segment a port scan's probes carry, or `None` for a sweep,
    /// which sends no segment of its choosing.
    pub fn technique(&self) -> Option<TcpScanTechnique> {
        match &self.0 {
            Resolved::PortScan { technique, .. } => Some(*technique),
            Resolved::Discovery { .. } => None,
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
        }
    }
}

/// A fingerprint of the plan a cursor's positions are counted in.
///
/// Compared, never interpreted. The value has no meaning beyond equality with
/// another one, and its derivation is free to change between journal versions
/// because [`JOURNAL_VERSION`](super::format::JOURNAL_VERSION) already refuses a
/// journal written by a build whose format this one does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlanFingerprint(u64);

impl PlanFingerprint {
    /// Fingerprints a resolved plan.
    ///
    /// `privileged` is whether the scan holds the privileges its raw strategies
    /// need, not whether it asked for them: what matters is which question the
    /// probes actually answered.
    ///
    /// The hash walks each unit's canonical ranges and ports rather than its
    /// targets, so this is cheap on a plan of any size. Feeding each field's
    /// count before the fields themselves is what keeps two differently-shaped
    /// plans from colliding — without it, one unit of two ranges and two units
    /// of one would hash the same.
    pub fn of(plan: &Plan, privileged: bool) -> Self {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();

        // The phase first, so a sweep and a port scan over the same addresses
        // can never agree. They count different things, and a position from one
        // read against the other names a target nobody probed.
        wire::scan_kind_name(plan.kind()).hash(&mut hasher);
        privileged.hash(&mut hasher);

        match &plan.0 {
            Resolved::Discovery { addresses, sweep } => {
                sweep.hash(&mut hasher);
                hash_addresses(addresses, &mut hasher);
            }
            Resolved::PortScan { targets, technique } => {
                technique.hash(&mut hasher);
                targets.units.len().hash(&mut hasher);

                for unit in &targets.units {
                    hash_addresses(unit.ips(), &mut hasher);

                    let ports = unit.ports().to_vec();
                    ports.len().hash(&mut hasher);
                    for (port, protocol) in ports {
                        port.hash(&mut hasher);
                        protocol.hash(&mut hasher);
                    }
                }
            }
        }

        // A cheap cross-check on everything above. Cannot catch a change the
        // structure hash missed on its own, but it costs one call and it turns a
        // hash collision into a mismatch rather than a silent agreement.
        plan.total_targets().hash(&mut hasher);

        Self(hasher.finish())
    }
}

/// Feeds one address set's canonical ranges into `hasher`.
///
/// Each family's count goes in before its ranges. Without it, one set of two
/// ranges and two sets of one would hash the same.
fn hash_addresses(ips: &IpSet, hasher: &mut impl Hasher) {
    ips.v4().len().hash(hasher);
    for range in ips.v4() {
        range.start_addr().hash(hasher);
        range.end_addr().hash(hasher);
    }

    ips.v6().len().hash(hasher);
    for range in ips.v6() {
        range.start_addr().hash(hasher);
        range.end_addr().hash(hasher);
        // The zone is part of the address for a link-local range: `fe80::1`
        // names a different machine on every segment.
        range.zone().hash(hasher);
    }
}

/// What a journal is a journal of.
///
/// Written once when the journal is created and never rewritten, which is what
/// makes it safe to read without a lock: nothing that reads a manifest can race
/// a writer changing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
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
    /// Whether the scan held the privileges its raw strategies need.
    ///
    /// Recorded because a resume must run under the same answer. The connect
    /// fallback asks a different question than a raw technique does, and a
    /// journal half of each would be counting two things.
    #[serde(default)]
    pub privileged: bool,
    /// How many targets that plan holds, so a caller can report progress without
    /// walking it.
    pub total_targets: u128,
    /// A human-readable summary of what was scanned, for a caller listing
    /// journals. **Not** load-bearing: nothing is decided from this text, which
    /// is why it is free to change shape between versions.
    pub summary: String,
}

impl Manifest {
    /// Describes a scan about to start.
    pub fn new(
        id: impl Into<String>,
        plan: &Plan,
        privileged: bool,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            journal_version: super::JOURNAL_VERSION,
            id: id.into(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: SystemTime::now(),
            kind: wire::scan_kind_name(plan.kind()).to_owned(),
            plan: PlanFingerprint::of(plan, privileged),
            targets: plan.record(),
            technique: plan
                .technique()
                .map(|technique| technique.name().to_owned())
                .unwrap_or_default(),
            sweep: plan.sweeps_the_segment(),
            privileged,
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
    pub fn covers(&self, plan: &Plan, privileged: bool) -> Result<(), PlanChanged> {
        let found = PlanFingerprint::of(plan, privileged);
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
// ║    ╚═╝   ╚═╝     ╚══════╝   ╚═╝   ╚══════╝ ║
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
        PlanFingerprint::of(&ports(map), true)
    }

    fn addresses(written: &str) -> IpSet {
        written.parse().expect("a range")
    }

    fn sweeping(ips: &IpSet, sweep: bool) -> Plan {
        Plan::discovery(ips, &Exclusions::none(), sweep)
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
            PlanFingerprint::of(&ports(&map), true),
            PlanFingerprint::of(&ports(&map), false),
            "privilege decides which question the probes answered"
        );
        assert_ne!(
            PlanFingerprint::of(&ports(&map), true),
            PlanFingerprint::of(
                &Plan::port_scan(&map, &Exclusions::none(), TcpScanTechnique::Fin),
                true
            ),
            "a technique decides what silence means"
        );
    }

    /// The manifest accepts the plan it was made from and refuses anything else,
    /// naming the counts so a person can see what moved.
    #[test]
    fn a_manifest_covers_its_own_plan_and_refuses_another() {
        let original = plan(&[("192.0.2.1-192.0.2.10", "80,443")]);
        let manifest = Manifest::new(
            "01J8Z5Q7VN",
            &ports(&original),
            true,
            "192.0.2.1-192.0.2.10 on 2 ports",
        );

        assert_eq!(manifest.total_targets, 20);
        assert_eq!(manifest.kind(), ScanKind::PortScan);
        assert!(manifest.covers(&ports(&original), true).is_ok());

        let widened = plan(&[("192.0.2.1-192.0.2.20", "80,443")]);
        let refused = manifest
            .covers(&ports(&widened), true)
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
            PlanFingerprint::of(&sweeping(&ips, false), true),
            print(&map),
            "the same ten addresses, asked two different questions"
        );

        let manifest = Manifest::new("01J8Z5Q7VN", &sweeping(&ips, false), true, "");
        assert_eq!(manifest.kind(), ScanKind::Discovery);
        assert_eq!(manifest.total_targets, 10, "a sweep counts addresses");
        assert!(
            manifest.covers(&ports(&map), true).is_err(),
            "a sweep's journal must not accept a port scan's plan"
        );
    }

    /// Whether a sweep may go beyond its addresses decides what it covered, so
    /// the two are different plans.
    #[test]
    fn a_segment_sweep_is_not_a_targeted_pass() {
        let ips = addresses("192.0.2.1-192.0.2.10");

        assert_ne!(
            PlanFingerprint::of(&sweeping(&ips, true), true),
            PlanFingerprint::of(&sweeping(&ips, false), true)
        );
    }

    /// A sweep's addresses have to come back as they went in, since that is the
    /// whole of its plan.
    #[test]
    fn a_sweeps_addresses_survive_the_round_trip() {
        let ips = addresses("192.0.2.1-192.0.2.10,2001:db8::1");
        let manifest = Manifest::new("01J8Z5Q7VN", &sweeping(&ips, false), true, "");

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
                    true
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

        let manifest = Manifest::new("01J8Z5Q7VN", &sweeping(&ips, false), true, "");
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
            manifest.covers(&sweeping(&recovered, false), true).is_ok(),
            "and the plan rebuilt from the record fingerprints as the original"
        );
    }

    /// A rearrangement holding the same number of targets still refuses, and the
    /// message must not claim a count changed when it did not.
    #[test]
    fn a_refusal_over_an_equal_count_says_so_rather_than_reporting_a_change() {
        let map = plan(&[("192.0.2.1-192.0.2.10", "80,443")]);
        let manifest = Manifest::new("01J8Z5Q7VN", &ports(&map), true, "");

        let refused = manifest
            .covers(
                &Plan::port_scan(&map, &Exclusions::none(), TcpScanTechnique::Fin),
                true,
            )
            .expect_err("a different technique is a different plan");

        assert_eq!(refused.expected_targets, refused.found_targets);
        let message = refused.to_string();
        assert!(message.contains("differently arranged"), "{message}");
        assert!(!message.contains("then,"), "{message}");
    }
}
