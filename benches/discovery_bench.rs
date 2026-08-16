// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
//! ## Address family and evidence
//!
//! Two devices found is not two devices found *the same way*, and a total alone
//! cannot say whether the IPv6 half of a scan contributes anything. So the
//! summary also splits the union by address family - how many devices were seen
//! at an IPv6 address, and how many were seen at *only* an IPv6 address, which
//! is the set no IPv4 sweep would have reported at all - and tallies which
//! probe proved each device alive.
//!
//! That tally is what makes an IPv6 change measurable. A device credited to
//! `arp` was found by the IPv4 path whatever else also saw it; one credited to
//! `icmp_echo` or `ndp` was found by the IPv6 path and by nothing else. A change
//! that moves the host total by nothing and moves this breakdown is still a
//! change, and one that claims to add IPv6 coverage while every device stays
//! credited to `arp` has added none.
//!
//! Each run also prints the scanner's own audit line (see
//! [`scanner::audit`](../src/scanner/audit.rs)), which says whether a shortfall
//! came from packets that went missing, a deadline that fired too early, or
//! replies that arrived and were not recognized.
//!
//! Those lines are then **summarised across runs**, per scanner, which is the
//! only form in which they answer anything. One run's `found-at` histogram on a
//! segment of sleeping wireless devices is noise; five runs' is a distribution,
//! and a deadline can be argued about against a distribution.
//!
//! The line to read is `tail`: what share of each run happened *after* its last
//! reply. Near zero means the scan was cut off with answers still arriving and
//! more patience buys more hosts. Near one means the answer was complete long
//! before the run ended and the deadline is spending time rather than finding
//! anything. **Both produce the same host count and the same stop reason**, so
//! nothing else in this output distinguishes them - and they call for opposite
//! changes.
//!
//! Raw sockets and `libpcap` both need root:
//!
//! ```text
//! cargo bench --no-run --bench discovery_bench
//! sudo -E target/release/deps/discovery_bench-<hash> <targets> [runs] [effort] [flags]
//! sudo -E target/release/deps/discovery_bench-<hash> 1.1.1.0/24 5
//! sudo -E target/release/deps/discovery_bench-<hash> 1.1.1.0/22 5 thorough
//! ```//!
//! Built with `--no-run` and invoked directly, for the reason `verify_scan`
//! gives: cargo passes its own arguments through to a `harness = false` target,
//! and this one reads argv.
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
//! `--roster` prints every device the union contains, with its addresses and
//! the evidence for it. That is the output to compare against something outside
//! this engine, which is the only comparison that can catch an error the engine
//! and its tests both make.
//!
//! Compare against, on the same network and at the same time of day:
//!
//! ```text
//! sudo nmap -sn -n --max-retries 2 1.1.1.0/24
//! sudo nmap -6 -sn -n fe80::/64            # what nmap finds over IPv6
//! ndp -an                                  # macOS: the host's own neighbours
//! ip -6 neigh show                         # Linux: the same
//! ```
//!
//! The neighbour table is the strongest external reference available for the
//! IPv6 half: every entry in it is a device that has spoken IPv6 on this segment
//! recently, keyed by the same MAC this program keys by, and it is populated by
//! the operating system rather than by anything under test here.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use zond_engine::config::ZondConfig;
use zond_engine::config::{RetryConfig, ScanEffort};
use zond_engine::export::schema::status_protocol_name;
use zond_engine::model::host::Host;
use zond_engine::model::parse::ip::to_set_with as to_ipset_with;
use zond_engine::model::parse::ip::{Keyword, names_keyword};
use zond_engine::scanner;
use zond_engine::scanner::report::{BUCKET_BOUNDS_MS, ProbeStats};
use zond_engine::system::interface;

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

/// Everything known about one device across every run: how often it was found,
/// where it answered, and what proved it was there.
///
/// Accumulated across runs rather than per run, because that is the question
/// being asked. A device answering ARP on one run and the all-nodes
/// solicitation on the next was found by both mechanisms, and a per-run view
/// would report it as two half-reliable findings instead of one device with two
/// independent proofs.
#[derive(Default)]
struct DeviceRecord {
    runs: usize,
    addresses: BTreeSet<IpAddr>,
    evidence: BTreeSet<String>,
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
    let roster = args.iter().any(|arg| arg == "--roster");

    // The keyword resolver is what turns `lan` into this host's own segment. It
    // has to be supplied here rather than defaulted inside the parser, because
    // resolving a keyword means reading the host's interfaces and the parser is
    // deliberately free of that dependency - so a caller that omits it gets an
    // error rather than a silently different target set.
    let ips = to_ipset_with(
        &[targets.as_str()],
        Some(interface::resolve_keyword),
        Some(interface::resolve_zone),
    )
    .unwrap_or_else(|e| fail(&format!("target expression `{targets}`: {e}")));
    let total = ips.len();

    // No DNS: a reverse lookup would add latency that has nothing to do with
    // what is being measured, and the nmap run compared against uses -n.
    // A sweep is what `lan` means. Without this the benchmark measures a
    // targeted run of the IPv4 range the keyword expanded to, with no all-nodes
    // echo and no neighbour-table candidates, and reports the missing IPv6 half
    // as a network with nothing on it. A front end has to make the same
    // connection; see `ZondConfig::segment_sweep`.
    let segment_sweep = names_keyword(&[targets.as_str()], Keyword::Lan);

    let cfg = ZondConfig {
        segment_sweep,
        no_dns: true,
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

    // Said out loud, because the alternative is a run that looks complete and
    // is not. Given a local range spelled out rather than the `lan` keyword,
    // this measures a *targeted* run: no all-nodes echo, no neighbour-table
    // candidates, and therefore no IPv6 at all - which prints as
    // `family 0 answered at an IPv6 address` and reads exactly like an IPv6
    // half that has regressed.
    if !segment_sweep {
        println!(
            "  note  targeted run: no all-nodes echo and no neighbour-table\n\
             \x20       candidates, so the IPv6 half is not measured here.\n\
             \x20       Use `lan` as the target expression to sweep the segment.\n"
        );
    }

    let mut results: Vec<(usize, Duration)> = Vec::with_capacity(runs);
    // What every run learned about each device. The run count is what separates
    // one that is reliably discovered from one that is discovered by luck; the
    // addresses and evidence are what say which half of the engine found it.
    let mut devices: HashMap<Device, DeviceRecord> = HashMap::new();
    // What each instrumented scanner filed, kept per run and per scanner. One
    // run's audit line answers nothing on a segment this variable, and mixing a
    // local sweep's timings with a routed one's answers worse than nothing.
    let mut audits: Vec<(String, ProbeStats, Duration)> = Vec::new();

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

        let mut found: BTreeSet<Device> = BTreeSet::new();
        for host in session.hosts().snapshot() {
            let device = identity(&host);
            let record = devices.entry(device.clone()).or_default();
            // Counted once per run however many store entries a device has: two
            // keys for one device is a fact about the store, not a second
            // sighting.
            if found.insert(device) {
                record.runs += 1;
            }
            record.addresses.extend(host.ips().iter().copied());
            record.evidence.extend(
                host.reasons()
                    .iter()
                    .map(|reason| status_protocol_name(&reason.protocol).into_owned()),
            );
        }

        for phase in report.phases() {
            for stats in phase.probe_stats() {
                audits.push((
                    format!("{:?}", stats.scanner()).to_lowercase(),
                    stats.clone(),
                    stats.elapsed(),
                ));
            }
        }

        println!(
            "  run {run:>2}: {:>4}/{total} hosts in {elapsed:.2?}",
            found.len()
        );
        results.push((found.len(), elapsed));
    }

    summarize(total, runs, &results, &devices);
    summarize_audit(&audits);
    if roster {
        print_roster(&devices);
    }
}

fn summarize(
    total: u128,
    runs: usize,
    results: &[(usize, Duration)],
    devices: &HashMap<Device, DeviceRecord>,
) {
    let mut counts: Vec<usize> = results.iter().map(|(found, _)| *found).collect();
    let mut times: Vec<Duration> = results.iter().map(|(_, elapsed)| *elapsed).collect();
    counts.sort_unstable();
    times.sort_unstable();

    let union = devices.len();
    let stable = devices
        .values()
        .filter(|record| record.runs == runs)
        .count();
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

    summarize_families(devices);
    summarize_evidence(devices);

    // The honest headline: the worst run is what a user actually experiences,
    // measured against the best evidence of what is really out there.
    if union > 0 {
        println!(
            "\n  worst run saw {:.0}% of everything that ever answered\n",
            (counts[0] as f64 / union as f64) * 100.0
        );
    }
}

/// Splits the union by the address families a device answered at.
///
/// `v6 only` is the line that matters. Those are devices no IPv4 sweep would
/// have reported at all, so it is the direct measure of what the IPv6 half of
/// discovery contributes - and, run before a change to that half, the number
/// that change has to move.
fn summarize_families(devices: &HashMap<Device, DeviceRecord>) {
    let mut v4 = 0;
    let mut v6 = 0;
    let mut v6_only = 0;

    for record in devices.values() {
        let has_v4 = record.addresses.iter().any(IpAddr::is_ipv4);
        let has_v6 = record.addresses.iter().any(IpAddr::is_ipv6);
        v4 += usize::from(has_v4);
        v6 += usize::from(has_v6);
        v6_only += usize::from(has_v6 && !has_v4);
    }

    println!("  family  {v4} answered at an IPv4 address, {v6} at an IPv6 address");
    println!("          {v6_only} answered only over IPv6");
}

/// Tallies how many devices each protocol proved alive.
///
/// A device can appear under more than one protocol, and that is the useful
/// case rather than a defect in the count: it means two independent mechanisms
/// found it, and removing either would still leave it discovered. The protocols
/// nothing is credited to are the ones contributing nothing.
fn summarize_evidence(devices: &HashMap<Device, DeviceRecord>) {
    let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
    for record in devices.values() {
        for protocol in &record.evidence {
            *tally.entry(protocol.as_str()).or_insert(0) += 1;
        }
    }

    let rendered: Vec<String> = tally
        .iter()
        .map(|(protocol, count)| format!("{protocol} {count}"))
        .collect();

    println!(
        "  proof   {}",
        if rendered.is_empty() {
            "nothing recorded any evidence".to_string()
        } else {
            rendered.join(", ")
        }
    );
}

/// Prints every device the union holds, for comparison against a source outside
/// this engine - `ndp -an`, `arp -an`, or an nmap run.
///
/// Keyed by MAC wherever one is known, which is what makes the comparison
/// possible: the neighbour table and this program then agree on what a device
/// is, and a device present in one and absent from the other is a real
/// difference rather than two names for the same box.
fn print_roster(devices: &HashMap<Device, DeviceRecord>) {
    let sorted: BTreeMap<&Device, &DeviceRecord> = devices.iter().collect();

    println!("  roster");
    for (device, record) in sorted {
        let addresses: Vec<String> = record.addresses.iter().map(|ip| ip.to_string()).collect();
        let evidence: Vec<&str> = record.evidence.iter().map(String::as_str).collect();
        println!(
            "    {device:<24} seen {:>2}x  {:<48} [{}]",
            record.runs,
            addresses.join(", "),
            evidence.join(", ")
        );
    }
    println!();
}

/// What the instrumented scanners said about their own runs, gathered across
/// every run rather than left one line at a time in the log.
///
/// **The line that matters is `tail`.** A sweep that stops while answers are
/// still arriving and a sweep that waits two seconds for nothing produce the
/// same host count and the same stop reason, and the only thing separating them
/// is how long the run continued after its last finding. Read one run at a time
/// that number is noise; read across five it is the difference between a
/// deadline that is too short and one that is too long, which are opposite
/// changes.
///
/// Split per scanner, because a local sweep answers in single-digit
/// milliseconds and a routed one in hundreds. Averaged together they describe
/// neither.
fn summarize_audit(audits: &[(String, ProbeStats, Duration)]) {
    if audits.is_empty() {
        return;
    }

    let mut scanners: BTreeSet<&str> = BTreeSet::new();
    for (name, _, _) in audits {
        scanners.insert(name.as_str());
    }

    for scanner in scanners {
        let filed: Vec<&(String, ProbeStats, Duration)> = audits
            .iter()
            .filter(|(name, _, _)| name == scanner)
            .collect();

        println!("  audit   {scanner}, {} run(s)", filed.len());

        // Stop reasons, in descending order of how often each happened. A
        // single reason across every run is itself the finding: a sweep that
        // always stops the same way is never finishing for its own reasons.
        let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
        for (_, stats, _) in &filed {
            *reasons
                .entry(format!("{:?}", stats.stop_reason()))
                .or_default() += 1;
        }
        let reasons: Vec<String> = reasons
            .iter()
            .map(|(reason, count)| format!("{reason} {count}"))
            .collect();
        println!("    stopped   {}", reasons.join(", "));

        let attempted: u64 = filed.iter().map(|(_, s, _)| s.sends_attempted()).sum();
        let failed: u64 = filed.iter().map(|(_, s, _)| s.sends_failed()).sum();
        println!(
            "    sends     {attempted} attempted, {failed} failed{}",
            if failed > 0 {
                "  <- frames that never reached the segment"
            } else {
                ""
            }
        );

        summarize_found_at(&filed);
        summarize_tail(&filed);
    }
    println!();
}

/// When hosts were credited, summed over every run.
///
/// Printed cumulatively because the question is never "how many landed in this
/// bucket" but "how much of the answer was already in by here" - which is what a
/// deadline has to be set against.
fn summarize_found_at(filed: &[&(String, ProbeStats, Duration)]) {
    let mut totals = vec![0u64; BUCKET_BOUNDS_MS.len() + 1];
    for (_, stats, _) in filed {
        for (slot, count) in stats.found_at().iter().enumerate() {
            totals[slot] += count;
        }
    }

    let found: u64 = totals.iter().sum();
    if found == 0 {
        println!("    found-at  nothing was credited");
        return;
    }

    let mut running = 0u64;
    let mut cells = Vec::new();
    for (slot, count) in totals.iter().enumerate() {
        running += count;
        if *count == 0 {
            continue;
        }
        let label = match BUCKET_BOUNDS_MS.get(slot) {
            Some(bound) => format!("<={bound}ms"),
            None => ">1s".to_string(),
        };
        cells.push(format!(
            "{label} {count} ({:.0}%)",
            (running as f64 / found as f64) * 100.0
        ));
    }
    println!("    found-at  {}", cells.join("  "));
}

/// How much of each run happened after its last finding.
///
/// Reported as a share of the run rather than as a duration, because the
/// absolute number is meaningless across scanners: a connect probe of loopback
/// finishes in microseconds and a segment sweep takes seconds, and the same
/// millisecond gap means opposite things in the two.
///
/// Near zero means the scan was cut off with answers still arriving, and every
/// millisecond added to the deadline buys another host. Near one means the
/// opposite - the answer was complete long before the run ended, and the
/// deadline is spending time rather than finding anything. Both produce the same
/// host count and the same stop reason, which is the whole reason this is here.
fn summarize_tail(filed: &[&(String, ProbeStats, Duration)]) {
    let mut shares: Vec<(f64, Duration, Duration)> = filed
        .iter()
        .filter_map(|(_, stats, elapsed)| {
            let last = stats.last_reply()?;
            let gap = elapsed.saturating_sub(last);
            (elapsed.as_secs_f64() > 0.0)
                .then(|| (gap.as_secs_f64() / elapsed.as_secs_f64(), gap, *elapsed))
        })
        .collect();

    if shares.is_empty() {
        println!("    tail      no run recorded a reply");
        return;
    }

    shares.sort_by(|a, b| a.0.total_cmp(&b.0));
    let (median, gap, elapsed) = shares[shares.len() / 2];
    let (lowest, _, _) = shares[0];

    println!(
        "    tail      median {:.0}% of the run happened after its last reply \
({gap:.2?} of {elapsed:.2?})",
        median * 100.0
    );

    // Stated as what the number rules out rather than as a verdict. One sitting
    // on one segment cannot decide a deadline, and an instrument that announces
    // a conclusion is the one nobody re-checks.
    let reading = if lowest < 0.05 {
        "at least one run was still being answered when it stopped"
    } else if median > 0.5 {
        "no run was cut off while it was still being answered"
    } else {
        "runs stopped neither immediately after an answer nor long after one"
    };
    println!("              {reading}");

    // Deliberately not "so the deadline is not the constraint", which this
    // cannot show. It measures the gap after the last *credited* reply, and a
    // device found by overhearing an advertisement is credited whenever it
    // happens to speak - so a longer run has more chances to overhear one even
    // though nothing was in flight when the shorter run ended. Ruling out "cut
    // off mid-answer" is not the same as ruling out "more time finds more", and
    // only varying the deadline and watching the union answers the second.
    if median > 0.5 {
        println!(
            "              (whether a longer run would find more is a different \
question: vary the deadline and watch the union)"
        );
    }
}
