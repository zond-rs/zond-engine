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
//! ## What the fingerprint covers, and what it costs
//!
//! Not the enumeration — hashing sixteen billion targets to check a `/8` would
//! cost more than the scan. It covers the *structure that decides* the
//! enumeration: each unit's canonical address ranges and its port list, in
//! order, plus the technique and the privilege level, plus the total as a cheap
//! cross-check.
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

use crate::model::target::TargetMap;
use crate::model::technique::TcpScanTechnique;

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
    pub fn of(plan: &TargetMap, technique: TcpScanTechnique, privileged: bool) -> Self {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();

        technique.hash(&mut hasher);
        privileged.hash(&mut hasher);
        plan.units.len().hash(&mut hasher);

        for unit in &plan.units {
            let ips = unit.ips();

            ips.v4().len().hash(&mut hasher);
            for range in ips.v4() {
                range.start_addr().hash(&mut hasher);
                range.end_addr().hash(&mut hasher);
            }

            ips.v6().len().hash(&mut hasher);
            for range in ips.v6() {
                range.start_addr().hash(&mut hasher);
                range.end_addr().hash(&mut hasher);
                // The zone is part of the address for a link-local range:
                // `fe80::1` names a different machine on every segment.
                range.zone().hash(&mut hasher);
            }

            let ports = unit.ports().to_vec();
            ports.len().hash(&mut hasher);
            for (port, protocol) in ports {
                port.hash(&mut hasher);
                protocol.hash(&mut hasher);
            }
        }

        // A cheap cross-check on everything above. Cannot catch a change the
        // structure hash missed on its own, but it costs one call and it turns a
        // hash collision into a mismatch rather than a silent agreement.
        plan.gross_targets().unwrap_or_default().hash(&mut hasher);

        Self(hasher.finish())
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
    /// The plan every position in this journal is counted in.
    pub plan: PlanFingerprint,
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
        plan: &TargetMap,
        technique: TcpScanTechnique,
        privileged: bool,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            journal_version: super::JOURNAL_VERSION,
            id: id.into(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: SystemTime::now(),
            plan: PlanFingerprint::of(plan, technique, privileged),
            total_targets: plan.gross_targets().unwrap_or_default(),
            summary: summary.into(),
        }
    }

    /// Whether `plan` under these conditions is the plan this journal was
    /// counted in.
    pub fn covers(
        &self,
        plan: &TargetMap,
        technique: TcpScanTechnique,
        privileged: bool,
    ) -> Result<(), PlanChanged> {
        let found = PlanFingerprint::of(plan, technique, privileged);
        if found == self.plan {
            return Ok(());
        }

        Err(PlanChanged {
            expected: self.plan,
            found,
            expected_targets: self.total_targets,
            found_targets: plan.gross_targets().unwrap_or_default(),
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

    fn print(map: &TargetMap) -> PlanFingerprint {
        PlanFingerprint::of(map, TcpScanTechnique::Syn, true)
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
            PlanFingerprint::of(&map, TcpScanTechnique::Syn, true),
            PlanFingerprint::of(&map, TcpScanTechnique::Syn, false),
            "privilege decides which question the probes answered"
        );
        assert_ne!(
            PlanFingerprint::of(&map, TcpScanTechnique::Syn, true),
            PlanFingerprint::of(&map, TcpScanTechnique::Fin, true),
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
            &original,
            TcpScanTechnique::Syn,
            true,
            "192.0.2.1-192.0.2.10 on 2 ports",
        );

        assert_eq!(manifest.total_targets, 20);
        assert!(
            manifest
                .covers(&original, TcpScanTechnique::Syn, true)
                .is_ok()
        );

        let widened = plan(&[("192.0.2.1-192.0.2.20", "80,443")]);
        let refused = manifest
            .covers(&widened, TcpScanTechnique::Syn, true)
            .expect_err("a widened plan renumbers every position past the first host");

        assert_eq!(refused.expected_targets, 20);
        assert_eq!(refused.found_targets, 40);
        assert!(
            refused.to_string().contains("20 targets then, 40 now"),
            "{refused}"
        );
    }

    /// A rearrangement holding the same number of targets still refuses, and the
    /// message must not claim a count changed when it did not.
    #[test]
    fn a_refusal_over_an_equal_count_says_so_rather_than_reporting_a_change() {
        let map = plan(&[("192.0.2.1-192.0.2.10", "80,443")]);
        let manifest = Manifest::new("01J8Z5Q7VN", &map, TcpScanTechnique::Syn, true, "");

        let refused = manifest
            .covers(&map, TcpScanTechnique::Fin, true)
            .expect_err("a different technique is a different plan");

        assert_eq!(refused.expected_targets, refused.found_targets);
        let message = refused.to_string();
        assert!(message.contains("differently arranged"), "{message}");
        assert!(!message.contains("then,"), "{message}");
    }
}
