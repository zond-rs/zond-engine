// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The operating-system rule database
//!
//! The compiled artifact and the access over it.
//!
//! ## What it costs, measured
//!
//! Held flat and walked. That is a different shape from the service signatures
//! next door, and deliberately so: those carry thousands of regexes whose
//! *compilation* dominates everything, which is why they are compiled lazily,
//! cached, warmed in parallel, and narrowed by a port index and an Aho-Corasick
//! literal prefilter before any of it happens. A rule here compiles to nothing —
//! it is a handful of integer comparisons — so the same machinery would cost
//! more than it saves.
//!
//! Measured on this machine, one observation against a synthetic rule set:
//!
//! | rules | per host |
//! |---|---|
//! | 2 (what ships) | 0.8 µs |
//! | 1 000 | 33 µs |
//! | 10 000 | 278 µs |
//!
//! Linear, with a small constant. At the two rules that ship it is not
//! measurable against anything else a scan does; at ten thousand — which is what
//! translating a public corpus would bring — it is 18 seconds of CPU across a
//! `/16`, which is real but not disqualifying.
//!
//! Getting there took one fix worth naming, because it is the mistake this shape
//! invites. Rendering the option layout allocates, and doing it inside the
//! per-rule test cost **3.2 ms per host** at ten thousand rules — 210 seconds
//! across a `/16`, essentially all of it spent building the same short string
//! ten thousand times over. [`rules::matching`](super::rules) now works the
//! derived values out once for the whole set and orders the cheap integer
//! comparisons ahead of the string one, which is 11.5x at ten thousand rules and
//! 1.7x at two.
//!
//! ## Where the index goes, when it is needed
//!
//! [`RuleDb::matching`] is the seam, and nothing above it would change. The
//! natural narrowing is the direct analogue of the service side's port index: key
//! rules by reply kind and by an exactly-specified option layout, keep the rules
//! that state neither in a set that is always checked, and the walk goes from
//! every rule to a handful. It is not built, because two rules do not need it and
//! an index nobody can measure the benefit of is a guess.
//!
//! ## Where the artifact comes from
//!
//! Today it is the `bincode` blob `build.rs` compiles from
//! `assets/fingerprinting/os/`. [`RuleDb::global`] is the single place a
//! disk-loaded database will slot in later, which is what makes it possible to
//! use a corpus this crate can never ship: the largest and best operating-system
//! fingerprint database in existence is nmap's, and its licence is incompatible
//! with this one, so it can only ever be something a user brings and translates
//! on their own machine. The translator is the deliverable there; the corpus is
//! not.

use std::sync::OnceLock;

use super::observation::StackObservation;
use super::rules;
use super::signature::OsDefinition;

/// The rules compiled from `assets/fingerprinting/os/` by `build.rs`.
const EMBEDDED_RULES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/os_rules.bin"));

static DB: OnceLock<RuleDb> = OnceLock::new();

/// Runtime view over the operating-system rules.
pub struct RuleDb {
    rules: Vec<OsDefinition>,
}

impl RuleDb {
    /// The process-wide database. The first call deserializes the embedded
    /// rules; later calls are a pointer read.
    pub fn global() -> &'static RuleDb {
        DB.get_or_init(|| {
            let rules: Vec<OsDefinition> = bincode::deserialize(EMBEDDED_RULES)
                .expect("the embedded OS rule database failed to deserialize");
            RuleDb { rules }
        })
    }

    /// Builds a database from rules given directly, for a caller supplying their
    /// own corpus and for the tests.
    pub fn from_rules(rules: Vec<OsDefinition>) -> Self {
        Self { rules }
    }

    /// Every rule, in the order the build compiled them.
    pub fn rules(&self) -> &[OsDefinition] {
        &self.rules
    }

    /// Every rule that describes `observed`.
    ///
    /// Returns all of them rather than the best one. Which of several matching
    /// rules should name the host is a question about weights and about the other
    /// evidence in hand, and it is not this layer's to answer — two rules
    /// agreeing on a family and disagreeing on a version is a *result*, not a
    /// tie to be broken here.
    pub fn matching<'a>(
        &'a self,
        observed: &'a StackObservation,
    ) -> impl Iterator<Item = &'a OsDefinition> {
        rules::matching(&self.rules, observed)
    }
}
