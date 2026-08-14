// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runs every TCP scan technique against the same target and prints what each
//! one concluded, side by side.
//!
//! This is the only instrument that puts the flag probes on a real wire. The
//! simulated network in `tests/probe_classification.rs` decides how to answer
//! from the probe's flags and the RFC, which is the right way to build a
//! simulator and still leaves one thing untestable: whether a **real** stack
//! echoes a probe's nonce back where the engine goes looking for it. If it does
//! not, every reset is discarded and the whole range reads open-filtered - a
//! result indistinguishable, from the inside, from a well-firewalled host.
//!
//! So the table this prints is read column by column against a target whose
//! ports are already known from a SYN scan:
//!
//! * a column of `open_filtered` and nothing else means correlation failed, not
//!   that the host is silent,
//! * `closed` on the flag probes where SYN says closed means it worked,
//! * `closed` on the flag probes where SYN says **open** means the target is one
//!   of the stacks that resets everything, and the technique is useless against
//!   it - which is a finding about the target, not about the engine.
//!
//! Each technique runs as its own scan, sequentially. Running them at once
//! would have them share the target's ICMP rate limit and make every verdict
//! about the others' traffic.
//!
//! ```text
//! cargo bench --no-run --bench technique_sweep
//! sudo -E target/release/deps/technique_sweep-<hash> 192.168.0.1 22,80,443 3
//! ```//!
//! Built with `--no-run` and invoked directly, for the reason `verify_scan`
//! gives: cargo passes its own arguments through to a `harness = false` target,
//! and this one reads argv.
//!
//! The third argument is how many times to repeat the whole sweep. Every run is
//! printed rather than averaged: a technique that answers differently between
//! two runs is telling you something an average would hide.

use std::net::IpAddr;
use std::time::Instant;

use zond_engine::config::ZondConfig;
use zond_engine::export::schema::port_state_name;
use zond_engine::model::parse::ip::to_set;
use zond_engine::model::port::{PortSet, PortState, Protocol};
use zond_engine::model::target::{TargetMap, TargetSet};
use zond_engine::model::technique::TcpScanTechnique;
use zond_engine::scanner;

/// The ports of the reference host, chosen to cover one of each state a SYN
/// scan can reach. Override on the command line for anything else.
const DEFAULT_PORTS: &str = "22,80,443,445,3389";

#[tokio::main]
async fn main() {
    // The engine emits its audit line per strategy at INFO. Without a subscriber
    // installed it goes nowhere, and this instrument would be measuring a scan
    // while discarding the one record of how that scan went.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();

    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| {
        eprintln!("usage: technique_sweep <target> [ports] [repeats]");
        std::process::exit(2);
    });
    let ports = args.next().unwrap_or_else(|| DEFAULT_PORTS.to_string());
    let repeats: usize = args
        .next()
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(1)
        .max(1);

    // A hostname cannot be resolved here: `to_set` takes an optional resolver
    // and this instrument supplies none, deliberately - a benchmark that
    // silently scanned whatever DNS answered with would be measuring a moving
    // target. Reported rather than panicked, because an unparseable argument is
    // a typo and not a bug.
    let addresses = match to_set(&[target.as_str()], None) {
        Ok(addresses) => addresses,
        Err(e) => {
            eprintln!("target `{target}`: {e}");
            eprintln!("give an address or a CIDR range; hostnames are not resolved here");
            std::process::exit(2);
        }
    };
    let port_set = match PortSet::try_from(ports.as_str()) {
        Ok(ports) => ports,
        Err(e) => {
            eprintln!("ports `{ports}`: {e}");
            std::process::exit(2);
        }
    };
    let numbers: Vec<u16> = port_set
        .iter()
        .filter(|(_, protocol)| *protocol == Protocol::Tcp)
        .map(|(port, _)| port)
        .collect();

    println!("target: {target}   ports: {ports}   repeats: {repeats}\n");

    for run in 1..=repeats {
        if repeats > 1 {
            println!("── run {run} ─────────────────────────────────────────");
        }
        print_header(&numbers);

        for technique in TcpScanTechnique::ALL {
            let target_map = {
                let mut map = TargetMap::new();
                map.add_unit(TargetSet::new(addresses.clone(), port_set.clone()));
                map
            };

            let cfg = ZondConfig {
                tcp_technique: technique,
                ..Default::default()
            };

            let started = Instant::now();
            let (session, task) = scanner::scan(target_map, &cfg).await.expect("scan starts");
            let report = task.await.expect("scan finishes");
            let elapsed = started.elapsed();

            // Printed before the verdicts, because a strategy that never ran
            // reports the same silence a firewall does. A row under a failure
            // line is not a measurement.
            for failure in report.failures() {
                println!("  !! {failure}");
            }

            let host: Option<IpAddr> = session.hosts().snapshot().first().map(|h| h.primary_ip());
            let states: Vec<&str> = numbers
                .iter()
                .map(
                    |port| match host.and_then(|ip| state_of(&session, ip, *port)) {
                        Some(state) => port_state_name(state),
                        None => "-",
                    },
                )
                .collect();

            let status = host
                .and_then(|ip| {
                    session
                        .hosts()
                        .get(&ip)
                        .map(|h| format!("{:?}", h.status()))
                })
                .unwrap_or_else(|| "no host".to_string());

            print!("{:<8}", technique.name());
            for state in &states {
                print!("{state:<16}");
            }
            println!("{:>8.0?}  {status}", elapsed);
        }
        println!();
    }
}

fn print_header(ports: &[u16]) {
    print!("{:<8}", "");
    for port in ports {
        print!("{:<16}", format!("{port}/tcp"));
    }
    println!("{:>8}  host", "elapsed");
}

fn state_of(
    session: &zond_engine::scanner::session::ScanSession,
    ip: IpAddr,
    port: u16,
) -> Option<PortState> {
    session
        .hosts()
        .get(&ip)
        .and_then(|host| host.ports().find(|p| p.number() == port).map(|p| p.state()))
}
