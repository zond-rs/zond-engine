// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Repeatable measurement of host discovery, so changes to it can be judged
//! against a number instead of an impression.
//!
//! A discovery sweep is a probabilistic thing: it finds what answered in time,
//! and one run tells you almost nothing. What matters is the distribution and,
//! more than that, the *stability* — a sweep that reports 187 hosts on one run
//! and 96 on the next is not 60% accurate, it is unreliable, and the two failure
//! modes have different fixes. So this runs the same sweep repeatedly and
//! reports:
//!
//! - how many hosts each run found and how long it took,
//! - the union across every run, which is the best evidence available of how
//!   many hosts are really there,
//! - the intersection, which is the part of the answer that is dependable,
//! - and the count of devices found by some runs but not others, which is the
//!   number that has to go to zero.
//!
//! Devices are counted by [`identity`], not by store key, so a neighbour that
//! keys differently between runs is not mistaken for an unreliable one.
//!
//! Each run also prints the scanner's own audit line (see
//! [`scanner::audit`](../src/scanner/audit.rs)), which says whether a shortfall
//! came from packets that went missing, a deadline that fired too early, or
//! replies that arrived and were not recognized.
//!
//! Raw sockets and `libpcap` both need root:
//!
//! ```text
//! sudo -E cargo run --release --example discovery_bench -- <targets> [runs] [effort] [flags]
//! sudo -E cargo run --release --example discovery_bench -- 1.1.1.0/24 5
//! sudo -E cargo run --release --example discovery_bench -- 1.1.1.0/22 5 thorough
//! ```
//!
//! `--rate N` caps how fast routed discovery emits probes, in probes per
//! second. It is the one knob that changes what the network sees rather than
//! how long we wait for it: sweeping it maps the rate at which a path starts
//! dropping probes, which is the number the retry budget has been compensating
//! for.
//!
//! `--attempts N` and `--timeout-scale F` override the effort's own numbers.
//! An effort level moves both at once, which is convenient for choosing one and
//! useless for attributing a result to either; these separate them. The pair
//! that matters most is `--attempts 1 --timeout-scale 8`, one probe per target
//! and the patience to wait for it: whatever that finds was never a question of
//! retransmission.
//!
//! Compare against, on the same network and at the same time of day:
//!
//! ```text
//! sudo nmap -sn -n --max-retries 2 1.1.1.0/24
//! ```

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

use zond_engine::core::config::ZondConfig;
use zond_engine::core::models::host::Host;
use zond_engine::core::models::retry::{RetryConfig, ScanEffort};
use zond_engine::core::parse::to_ipset;
use zond_engine::scanner;

/// What counts as "the same thing found twice".
///
/// Not the store key, which is whichever address happened to answer first. A
/// neighbour that replies to ARP is keyed by its IPv4 address and one that
/// replies to the all-nodes solicitation by its link-local, so the *same*
/// device can key differently between runs while being found just as reliably
/// on each. Counting keys reports that as instability, which is a statement
/// about this program rather than about the scan.
///
/// A MAC address is the identity where one is known, which on a local segment
/// is everywhere. Off-link there is none, and the address is all there is.
type Device = String;

fn identity(host: &Host) -> Device {
    match host.mac() {
        Some(mac) => format!("mac {mac}"),
        None => format!("ip {}", host.primary_ip()),
    }
}

/// The retry profile the sweep runs under, so one range can be measured at more
/// than one effort without rebuilding.
///
/// This is what makes attempt budget a variable rather than a constant of the
/// experiment. A range that falls short at `balanced` and completes at
/// `thorough` is short of attempts or of patience; one that lands in the same
/// place at both is losing packets somewhere repetition does not reach, and
/// `single` says how much of that loss the very first pass already suffered.
fn effort_from(name: &str) -> Option<ScanEffort> {
    match name {
        "single" => Some(ScanEffort::Single),
        "fast" => Some(ScanEffort::Fast),
        "balanced" => Some(ScanEffort::Balanced),
        "thorough" => Some(ScanEffort::Thorough),
        _ => None,
    }
}

/// The value of `--name`, if it was given.
///
/// A flag present but unparseable ends the run. Silently ignoring it would
/// report the default configuration's numbers under a label describing the one
/// that was asked for, which is worse than no measurement at all.
fn flag<T: std::str::FromStr>(args: &[String], name: &str) -> Option<T> {
    let position = args.iter().position(|arg| arg == name)?;
    match args.get(position + 1).and_then(|value| value.parse().ok()) {
        Some(value) => Some(value),
        None => fail(&format!("{name} needs a value")),
    }
}

/// Names the overrides in the run header, so a scrollback of results says which
/// configuration produced each one.
fn describe_overrides(
    max_attempts: Option<u8>,
    timeout_scale: Option<f64>,
    max_probe_rate: Option<u32>,
) -> String {
    let mut out = String::new();
    if let Some(attempts) = max_attempts {
        out.push_str(&format!(", attempts {attempts}"));
    }
    if let Some(scale) = timeout_scale {
        out.push_str(&format!(", timeouts x{scale}"));
    }
    if let Some(rate) = max_probe_rate {
        out.push_str(&format!(", rate {rate}/s"));
    }
    out
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let positional: Vec<&String> = args
        .iter()
        .take_while(|arg| !arg.starts_with("--"))
        .collect();

    let targets = positional
        .first()
        .map(|arg| arg.to_string())
        .unwrap_or_else(|| "1.1.1.0/24".to_string());
    let runs: usize = positional
        .get(1)
        .and_then(|n| n.parse().ok())
        .unwrap_or(5)
        .max(1);
    let effort = match positional.get(2) {
        Some(name) => match effort_from(name) {
            Some(effort) => effort,
            // Defaulting on a name that was meant to change the experiment
            // would report the wrong effort's numbers under the right label.
            None => fail(&format!(
                "unknown effort `{name}`: expected single, fast, balanced, or thorough"
            )),
        },
        None => ScanEffort::default(),
    };

    let max_attempts: Option<u8> = flag(&args, "--attempts");
    let timeout_scale: Option<f64> = flag(&args, "--timeout-scale");
    let max_probe_rate: Option<u32> = flag(&args, "--rate");

    let ips = to_ipset(&[targets.as_str()], None).expect("target expression parses");
    let total = ips.len();

    // No DNS: a reverse lookup would add latency that has nothing to do with
    // what is being measured, and the nmap run compared against uses -n.
    let cfg = ZondConfig {
        no_banner: true,
        no_dns: true,
        disable_input: true,
        max_probe_rate,
        retry: RetryConfig {
            effort,
            max_attempts,
            timeout_scale,
            ..Default::default()
        },
        ..Default::default()
    };

    println!(
        "\ndiscovery benchmark: {targets} ({total} addresses), {runs} runs, effort {effort:?}{overrides}\n",
        overrides = describe_overrides(max_attempts, timeout_scale, max_probe_rate),
    );

    let mut results: Vec<(usize, Duration)> = Vec::with_capacity(runs);
    // How many runs each device was found in, which is what separates one that
    // is reliably discovered from one that is discovered by luck.
    let mut seen_in: HashMap<Device, usize> = HashMap::new();

    for run in 1..=runs {
        let started = Instant::now();
        let (session, task) = scanner::discover(ips.clone(), &cfg)
            .await
            .expect("discovery starts");
        let report = task.await.expect("discovery finishes");
        let elapsed = started.elapsed();

        // The bench keeps timing the run itself, so its numbers stay comparable
        // with every baseline recorded before reports existed. What the report
        // adds is the reason a run came back short: a strategy that never
        // started reads as a quiet network in the host count alone.
        for failure in report.failures() {
            println!("  run {run:>2}: DEGRADED - {failure}");
        }

        let found: BTreeSet<Device> = session.store.iter().map(|entry| identity(&entry)).collect();
        for device in &found {
            *seen_in.entry(device.clone()).or_insert(0) += 1;
        }

        println!(
            "  run {run:>2}: {:>4}/{total} hosts in {elapsed:.2?}",
            found.len()
        );
        results.push((found.len(), elapsed));
    }

    summarize(total, runs, &results, &seen_in);
}

fn summarize(
    total: u128,
    runs: usize,
    results: &[(usize, Duration)],
    seen_in: &HashMap<Device, usize>,
) {
    let mut counts: Vec<usize> = results.iter().map(|(found, _)| *found).collect();
    let mut times: Vec<Duration> = results.iter().map(|(_, elapsed)| *elapsed).collect();
    counts.sort_unstable();
    times.sort_unstable();

    let union = seen_in.len();
    let stable = seen_in.values().filter(|seen| **seen == runs).count();
    let flaky = union - stable;

    println!(
        "\n  hosts   min {} / median {} / max {} (of {total})",
        counts[0],
        counts[counts.len() / 2],
        counts[counts.len() - 1],
    );
    println!(
        "  time    min {:.2?} / median {:.2?} / max {:.2?}",
        times[0],
        times[times.len() / 2],
        times[times.len() - 1],
    );
    println!("  union   {union} devices answered at least once");
    println!("  stable  {stable} answered in every run");
    println!(
        "  flaky   {flaky} answered in some runs but not others{}",
        if flaky == 0 {
            "  <- what has to reach zero"
        } else {
            ""
        }
    );

    // The honest headline: the worst run is what a user actually experiences,
    // measured against the best evidence of what is really out there.
    if union > 0 {
        println!(
            "\n  worst run saw {:.0}% of everything that ever answered\n",
            (counts[0] as f64 / union as f64) * 100.0
        );
    }
}
