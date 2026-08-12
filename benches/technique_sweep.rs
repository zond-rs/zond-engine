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
//! sudo -E cargo run --example technique_sweep -- 192.168.0.1 22,80,443 3
//! ```
//!
//! The third argument is how many times to repeat the whole sweep. Every run is
//! printed rather than averaged: a technique that answers differently between
//! two runs is telling you something an average would hide.

use std::net::IpAddr;
use std::time::Instant;

use zond_engine::core::config::ZondConfig;
use zond_engine::core::models::port::{PortSet, PortState, Protocol};
use zond_engine::core::models::target::{TargetMap, TargetSet};
use zond_engine::core::models::technique::TcpScanTechnique;
use zond_engine::core::parse::ip::to_set;
use zond_engine::export::schema::port_state_name;
use zond_engine::scanner;

/// The ports of the reference host, chosen to cover one of each state a SYN
/// scan can reach. Override on the command line for anything else.
const DEFAULT_PORTS: &str = "22,80,443,445,3389";

#[tokio::main]
async fn main() {
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

    let addresses = to_set(&[target.as_str()], None).expect("target parses");
    let port_set = PortSet::try_from(ports.as_str()).expect("ports parse");
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

            let host: Option<IpAddr> = session.store.iter().next().map(|entry| *entry.key());
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
                .and_then(|ip| session.store.get(&ip).map(|h| format!("{:?}", h.status())))
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
    session: &zond_engine::core::session::ScanSession,
    ip: IpAddr,
    port: u16,
) -> Option<PortState> {
    session
        .store
        .get(&ip)
        .and_then(|host| host.ports().find(|p| p.number() == port).map(|p| p.state()))
}
