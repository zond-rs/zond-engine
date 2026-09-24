// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The exclusion policy's sending promise, as an invariant over a plan
//!
//! No probe is *addressed* to an excluded address: `withhold` and
//! `withhold_targets` keep that before anything is opened. A sweep can break it
//! without going near either: `seed_from_neighbor_table` takes candidates from
//! the host's own neighbour table into the target set, and taken in *after*
//! withholding, a swept segment would send a unicast solicitation to an address
//! somebody had been told would not be probed — and because the recording gate
//! still drops the finding, the report would stay clean and the packet
//! invisible.
//!
//! The recording promise, that no excluded address appears in the report, is
//! lexical and gets a census in the hygiene tier, `tests/hygiene/exclusions.rs`.
//! This one is not: there is no honest grep for "this address will be probed".
//! So it gets the stronger thing instead: an invariant over what a plan actually
//! contains. Whatever a sweep discovers, and however it discovers it, no step it
//! produces may carry an excluded address. That catches a path nobody thought to
//! add to a list, which is the kind of path an exclusion defect comes through.
//!
//! A plan cannot hold everything a scan sends. A sweep takes leads off the wire
//! while it runs, from mDNS records and unsolicited advertisements, and asks each
//! one directly; those addresses never pass through a plan, so this invariant
//! cannot see them. The simulated tier guards that path on the wire, in
//! `lan_discovery.rs`'s `an_excluded_address_learned_mid_sweep_is_not_asked_about`.
//!
//! It sits in this tier because it builds a plan through the library, reading
//! this host's interface table and opening nothing.

use std::net::IpAddr;

use zond_engine::model::exclusion::Exclusions;
use zond_engine::model::parse::ip::to_set;
use zond_engine::scanner::plan::{DiscoveryPlan, DiscoveryStep};
use zond_engine::scanner::strategy::local::Scope;

/// Every address a step would probe.
fn addresses_of(step: &DiscoveryStep) -> Vec<IpAddr> {
    match step {
        DiscoveryStep::Local { targets, .. } | DiscoveryStep::Connect { targets, .. } => {
            targets.iter().collect()
        }
        DiscoveryStep::Routed { targets, .. } | DiscoveryStep::RoutedSctp { targets, .. } => {
            targets.iter().map(|routed| routed.target).collect()
        }
        // `DiscoveryStep` is `#[non_exhaustive]`, so a new kind of step lands
        // here. Failing is the point: a step this function cannot read is a step
        // the invariant below silently stops covering, which is worse than no
        // invariant because it reads as one.
        other => panic!(
            "a {:?} step is not read by addresses_of, so the exclusion invariant \
             would skip it. Teach this function to enumerate its targets.",
            other.kind()
        ),
    }
}

/// **No plan carries an address the exclusions forbid.**
///
/// The end-to-end shape of the send-side promise: whatever a plan ends up
/// holding, no step may name an address the operator ruled out.
///
/// **What this covers, and what it cannot.** It exercises the *list* source
/// end to end — withholding runs, the plan is built, every step is walked. It
/// cannot exercise the *discovered* source, because `DiscoveryPlan::build` reads
/// the running host's own neighbour table and an integration test has nowhere to
/// put a synthetic one. That path is asserted where the table can be injected,
/// in `plan.rs`'s own
/// `a_swept_plan_does_not_take_an_excluded_neighbour_as_a_candidate`, which is
/// the test that fails if that filter goes.
///
/// Saying so matters. Removing the neighbour-table filter leaves this test
/// passing, and a test that passes for a reason it does not name is a defect,
/// the kind a COOKIE-ECHO test that quotes an INIT is, or an escaping test that
/// never sees the most hostile strings. The assertions below on the fixture
/// itself are what stop this one being one: if withholding stops removing
/// anything, or the plan stops having steps, the test fails rather than quietly
/// covering nothing.
#[test]
fn no_plan_step_carries_an_excluded_address() {
    let forbidden =
        to_set(&["192.0.2.64/26", "198.51.100.0/24"], None, None).expect("a parseable range");
    let exclusions = Exclusions::new(forbidden);

    for scope in [Scope::Sweep, Scope::Targeted] {
        let mut targets =
            to_set(&["192.0.2.0/24", "198.51.100.0/24"], None, None).expect("a parseable range");
        let before = targets.len();

        // What a caller does before building a plan, and the whole of the
        // send-side guarantee as the module states it.
        let withheld = exclusions.withhold(&mut targets);

        assert!(
            withheld > 0 && targets.len() < before,
            "the fixture has to give withholding something to do, or this test \
             covers a list that was never in scope"
        );

        // No forced source: the routing table chooses, as it does for a scan
        // that names none.
        let plan = DiscoveryPlan::build(targets, scope, &exclusions, &[]);

        let mut walked = 0usize;
        for step in plan.steps() {
            for address in addresses_of(step) {
                walked += 1;
                assert!(
                    !exclusions.excludes(&address),
                    "a {scope:?} plan's {:?} step would probe {address}, which is excluded",
                    step.kind()
                );
            }
        }

        assert!(
            walked > 0,
            "a {scope:?} plan over a /24 has to name addresses, or this test walked nothing"
        );
    }
}
