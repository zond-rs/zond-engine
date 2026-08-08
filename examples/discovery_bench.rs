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
//! sudo -E cargo run --release --example discovery_bench -- 1.1.1.0/24 5
//! ```
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();

    let mut args = std::env::args().skip(1);
    let targets = args.next().unwrap_or_else(|| "1.1.1.0/24".to_string());
    let runs: usize = args
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(5)
        .max(1);

    let ips = to_ipset(&[targets.as_str()], None).expect("target expression parses");
    let total = ips.len();

    // No DNS: a reverse lookup would add latency that has nothing to do with
    // what is being measured, and the nmap run compared against uses -n.
    let cfg = ZondConfig {
        no_banner: true,
        no_dns: true,
        disable_input: true,
        ..Default::default()
    };

    println!("\ndiscovery benchmark: {targets} ({total} addresses), {runs} runs\n");

    let mut results: Vec<(usize, Duration)> = Vec::with_capacity(runs);
    // How many runs each device was found in, which is what separates one that
    // is reliably discovered from one that is discovered by luck.
    let mut seen_in: HashMap<Device, usize> = HashMap::new();

    for run in 1..=runs {
        let started = Instant::now();
        let (session, task) = scanner::discover(ips.clone(), &cfg)
            .await
            .expect("discovery starts");
        task.await.expect("discovery finishes");
        let elapsed = started.elapsed();

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

    println!("\n  hosts   min {} / median {} / max {} (of {total})",
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
