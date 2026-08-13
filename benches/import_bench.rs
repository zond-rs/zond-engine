// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What does grouping targets by port specification actually buy?
//!
//! `TargetMapBuilder` puts every target sharing a port specification into one
//! [`TargetSet`], where the old `to_target_map` emitted one unit per input
//! token. The claim made when that landed was that a 65 536-line target file
//! becomes one unit instead of 65 536. That is true by construction and it is
//! not the question: **the user-visible number is the wall clock from handing
//! the engine a file to having a scannable `TargetMap`, and then to having
//! walked it.** The unit count is a proxy, and this measures both so the proxy
//! is never reported on its own.
//!
//! ```text
//! cargo run --release --example import_bench
//! ```
//!
//! ## Predictions, written before the first run
//!
//! Recorded here rather than in a commit message so that a later reader can see
//! which of them the numbers contradicted.
//!
//! 1. **Grouping collapses contiguous input.** A file listing a contiguous
//!    block one address per line ends as one unit holding one range. Certain -
//!    it follows from `IpSet` merging adjacent ranges - and it is the premise
//!    the rest rests on rather than a finding.
//! 2. **Grouped *building* is slower**, by something like 1.3x to 2x. Grouping
//!    pays one `O(n log n)` sort-and-merge over every range; the ungrouped path
//!    pushes `n` one-range sets and never sorts anything. The claimed win cannot
//!    be in this phase.
//! 3. **Grouped *iteration* is much faster on contiguous input**, because
//!    walking one range of 65 536 addresses beats walking 65 536 sets of one.
//!    Enough to pay for prediction 2 several times over.
//! 4. **On scattered input the advantage mostly disappears.** Addresses that
//!    cannot merge leave the same number of ranges either way, so all grouping
//!    saves is the `Vec<TargetSet>` overhead. If predictions 3 and 4 are both
//!    right, the honest claim is narrower than the one phase 1 made: grouping
//!    helps *contiguous* target files, which is most of them, and not all of
//!    them.
//! 5. **The import path is quadratic in file length**, and this is a defect
//!    rather than a design. `TargetCollector::accept` checks the address budget
//!    by calling `TargetMapBuilder::gross_address_count`, which walks every
//!    range in every group - `O(n)` per token, so `O(n²)` per file. If this is
//!    right, quadrupling the line count roughly sixteen-times the import time
//!    instead of quadrupling it, and the scaling arm below will show it
//!    immediately.
//!
//! Prediction 5 is the reason this example measures the same shape at four
//! sizes rather than measuring one big file once. A single size cannot tell a
//! slow constant from the wrong complexity.
//!
//! ## What the first run said
//!
//! On an M-series Mac, release build, 65 536 lines. Two predictions were wrong
//! and one of the wrong ones was the interesting result.
//!
//! **Prediction 5 held, and was the whole story of the import path.** The
//! scaling ratios came out 9.2x, 11.2x, 15.9x - converging on 16, which is
//! quadratic exactly as feared. A 65 536-line file took **3 240 ms** to import
//! against **6.9 ms** to build directly, a 470x tax paid entirely by the budget
//! check. Fixed by keeping the gross address count as a running total instead of
//! recomputing it per line: **3 240 ms became 10.3 ms**, and the ratios became
//! 3.4x, 3.4x, 2.4x. Linear.
//!
//! **Prediction 4 was wrong, and grouping is better than was claimed for it.**
//! Scattered input - every fourth address, so nothing can merge - came out
//! *marginally faster* than contiguous input, 1.61x against 1.59x. So the win
//! has nothing to do with range merging. It is that each [`TargetSet`]
//! canonicalizes itself and allocates a port vector when walked, and 65 536
//! units means 65 536 of each. The claim in phase 1 named the wrong mechanism
//! and was, by accident, too narrow.
//!
//! **Prediction 1 was right about the engine and wrong about the instrument.**
//! The first run reported 65 536 ranges for contiguous input, which looked like
//! a failure to merge and was really this example reading the range count before
//! canonicalization - the merge is lazy. Contiguous and scattered reported
//! identical figures, which was the instrument agreeing with itself. Counting
//! after canonicalizing gives 1 range and 65 536 respectively.
//!
//! Predictions 2 and 3 held: building grouped costs 1.38x (6.6 ms against
//! 4.8 ms) and walking it costs a twentieth (0.3 ms against 6.0 ms).
//!
//! **Unpredicted, and the honest cost:** a file naming a distinct port
//! specification on every line makes grouping *lose*, 0.65x - 24.6 ms against
//! 16.1 ms. There is nothing to group, and the index and the per-group
//! machinery are paid for anyway. Nobody writes that file, but it is the shape
//! that would make this the wrong design if they did.

use std::io::Cursor;
use std::time::{Duration, Instant};

use zond_engine::core::models::ip::set::IpSet;
use zond_engine::core::models::port::PortSet;
use zond_engine::core::models::target::{TargetMap, TargetSet};
use zond_engine::core::parse::ip::insert_expression;
use zond_engine::import::target::TargetExpr;
use zond_engine::import::{ImportFormat, ImportLimits, ImportOptions};

/// How many times each arm runs. The median is reported, so a scheduling hiccup
/// in one run cannot become the finding.
const RUNS: usize = 3;

fn main() {
    println!("import_bench — what grouping by port specification costs and buys\n");

    scaling();
    shapes();
}

// ---------------------------------------------------------------------------
// Prediction 5: is the import path quadratic?
// ---------------------------------------------------------------------------

/// The same file shape at four sizes.
///
/// A single measurement cannot distinguish a slow constant from the wrong
/// complexity. Four sizes each four times the last can: linear work shows a
/// ratio near 4, quadratic work shows a ratio near 16.
fn scaling() {
    println!("== Scaling: the same shape at four sizes ==");
    println!("A ratio near 4 is linear. A ratio near 16 is quadratic.\n");
    println!(
        "{:>9}  {:>12}  {:>8}  {:>12}  {:>8}",
        "lines", "import", "vs 1/4", "ungrouped", "vs 1/4"
    );

    let mut previous: Option<(Duration, Duration)> = None;

    for lines in [1_024usize, 4_096, 16_384, 65_536] {
        let text = contiguous(lines);
        let ports = PortSet::try_from("80").expect("ports");

        let imported = median(|| {
            let start = Instant::now();
            let out = import(&text, &ports);
            let elapsed = start.elapsed();
            std::hint::black_box(out);
            elapsed
        });

        let ungrouped = median(|| {
            let start = Instant::now();
            let out = build_ungrouped(&text, &ports);
            let elapsed = start.elapsed();
            std::hint::black_box(out);
            elapsed
        });

        let ratio = |now: Duration, before: Option<Duration>| match before {
            Some(before) if !before.is_zero() => {
                format!("{:.1}x", now.as_secs_f64() / before.as_secs_f64())
            }
            _ => "-".to_string(),
        };

        println!(
            "{lines:>9}  {:>12}  {:>8}  {:>12}  {:>8}",
            millis(imported),
            ratio(imported, previous.map(|(i, _)| i)),
            millis(ungrouped),
            ratio(ungrouped, previous.map(|(_, u)| u)),
        );

        previous = Some((imported, ungrouped));
    }

    println!();
}

// ---------------------------------------------------------------------------
// Predictions 1 to 4: what grouping costs to build and saves to walk
// ---------------------------------------------------------------------------

/// One arm's worth of input.
struct Shape {
    name: &'static str,
    text: String,
    note: &'static str,
}

fn shapes() {
    let lines = 65_536usize;
    let ports = PortSet::try_from("80").expect("ports");

    let shapes = [
        Shape {
            name: "contiguous",
            text: contiguous(lines),
            note: "10.0.0.0 upwards, one per line",
        },
        Shape {
            name: "scattered",
            text: scattered(lines),
            note: "every fourth address, so nothing merges",
        },
        Shape {
            name: "eight port specs",
            text: rotating_ports(lines, 8),
            note: "contiguous, port spec rotating over 8",
        },
        Shape {
            name: "unique port specs",
            text: unique_ports(lines),
            note: "a distinct port on every line",
        },
    ];

    println!("== Shapes: {lines} lines each ==\n");
    println!(
        "{:<18} {:>9} {:>8} {:>10} {:>10} {:>10} {:>10}",
        "shape", "units", "ranges", "build", "walk", "total", "vs naive"
    );

    for shape in shapes {
        let grouped_build = median(|| {
            let start = Instant::now();
            let out = build_grouped(&shape.text, &ports);
            let elapsed = start.elapsed();
            std::hint::black_box(out);
            elapsed
        });
        let naive_build = median(|| {
            let start = Instant::now();
            let out = build_ungrouped(&shape.text, &ports);
            let elapsed = start.elapsed();
            std::hint::black_box(out);
            elapsed
        });

        let grouped_walk = median(|| {
            let map = build_grouped(&shape.text, &ports);
            let start = Instant::now();
            let count = map.iter().count();
            let elapsed = start.elapsed();
            std::hint::black_box(count);
            elapsed
        });
        let naive_walk = median(|| {
            let map = build_ungrouped(&shape.text, &ports);
            let start = Instant::now();
            let count = map.iter().count();
            let elapsed = start.elapsed();
            std::hint::black_box(count);
            elapsed
        });

        let map = build_grouped(&shape.text, &ports);
        let units = map.units.len();
        // No canonicalize call, and none possible: a `TargetSet` merges its
        // addresses when it is built, so there is no longer a moment at which
        // this could count ranges *inserted* rather than ranges held. That was
        // a real reading once — a contiguous file and a deliberately unmergeable
        // one reported identical figures, the instrument agreeing with itself
        // rather than measuring anything.
        let ranges: usize = map
            .units
            .iter()
            .map(|unit| unit.ips().v4().len() + unit.ips().v6().len())
            .sum();

        let grouped_total = grouped_build + grouped_walk;
        let naive_total = naive_build + naive_walk;
        let speedup = naive_total.as_secs_f64() / grouped_total.as_secs_f64();

        println!(
            "{:<18} {units:>9} {ranges:>8} {:>10} {:>10} {:>10} {:>9.2}x",
            shape.name,
            millis(grouped_build),
            millis(grouped_walk),
            millis(grouped_total),
            speedup,
        );
        println!(
            "{:<18} {:>9} {:>8} {:>10} {:>10} {:>10}",
            format!("  naive: {}", shape.note),
            lines,
            lines,
            millis(naive_build),
            millis(naive_walk),
            millis(naive_total),
        );
    }

    println!();
}

// ---------------------------------------------------------------------------
// The two builders
// ---------------------------------------------------------------------------

/// The whole import path: what a caller actually invokes, limits and all.
fn import(text: &str, ports: &PortSet) -> TargetMap {
    let options = ImportOptions::new(ports.clone()).with_limits(ImportLimits::none());
    ImportFormat::List
        .read(&mut Cursor::new(text), &options)
        .expect("the generated file imports")
        .map
}

/// The builder on its own, without the collector's bookkeeping.
///
/// Separated from [`import`] so that the cost of grouping can be told apart
/// from the cost of the budget check that wraps it - which is the whole of
/// prediction 5.
fn build_grouped(text: &str, ports: &PortSet) -> TargetMap {
    let context = zond_engine::import::TargetContext::new();
    let mut builder = zond_engine::import::TargetMapBuilder::new(ports.clone());
    for token in text.split_whitespace() {
        builder
            .push(token, &context)
            .expect("generated targets parse");
    }
    builder.build()
}

/// What `to_target_map` did before phase 1: one unit per input token.
///
/// Rebuilt here rather than measured from history, so both arms run in the same
/// process against the same input and neither can inherit an advantage from the
/// machine it was measured on.
fn build_ungrouped(text: &str, default_ports: &PortSet) -> TargetMap {
    let mut map = TargetMap::new();

    for token in text.split_whitespace() {
        let expr = TargetExpr::parse(token).expect("generated targets parse");
        let ports = match expr.ports {
            Some(spec) => PortSet::try_from(spec).expect("generated ports parse"),
            None => default_ports.clone(),
        };

        let mut ips = IpSet::new();
        for address in expr.addresses() {
            insert_expression(address, &mut ips, None, None).expect("generated addresses parse");
        }
        map.add_unit(TargetSet::new(ips, ports));
    }

    map
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// A contiguous block, one address per line. The shape a target file usually
/// has, and the one grouping is supposed to help most.
fn contiguous(lines: usize) -> String {
    let mut text = String::with_capacity(lines * 12);
    for index in 0..lines {
        text.push_str(&address(index as u32));
        text.push('\n');
    }
    text
}

/// Every fourth address, so no two are adjacent and nothing merges. The arm
/// that can disprove the claim.
fn scattered(lines: usize) -> String {
    let mut text = String::with_capacity(lines * 12);
    for index in 0..lines {
        text.push_str(&address(index as u32 * 4));
        text.push('\n');
    }
    text
}

/// Contiguous addresses over a small set of port specifications.
fn rotating_ports(lines: usize, specs: usize) -> String {
    let mut text = String::with_capacity(lines * 18);
    for index in 0..lines {
        text.push_str(&address(index as u32));
        text.push(':');
        text.push_str(&(1000 + index % specs).to_string());
        text.push('\n');
    }
    text
}

/// A distinct port specification on every line: as many groups as there are
/// lines, which is the worst case for the builder's index.
fn unique_ports(lines: usize) -> String {
    let mut text = String::with_capacity(lines * 18);
    for index in 0..lines {
        text.push_str(&address(index as u32));
        text.push(':');
        text.push_str(&(1 + (index % 65_535)).to_string());
        text.push('\n');
    }
    text
}

/// `10.a.b.c` for an index, so a run of indices is a run of addresses.
fn address(index: u32) -> String {
    let octets = index.to_be_bytes();
    format!("10.{}.{}.{}", octets[1], octets[2], octets[3])
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

/// Runs a measurement [`RUNS`] times and returns the median.
fn median(mut measure: impl FnMut() -> Duration) -> Duration {
    let mut samples: Vec<Duration> = (0..RUNS).map(|_| measure()).collect();
    samples.sort();
    samples[RUNS / 2]
}

fn millis(duration: Duration) -> String {
    format!("{:.1} ms", duration.as_secs_f64() * 1000.0)
}
