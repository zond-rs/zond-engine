// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runs a real scan and prints everything it learned about each host.
//!
//! The companion to `os_observe`, and a different instrument for a different
//! question. `os_observe` drives the transport directly and prints what came off
//! the wire, which is what rules are *authored* from. This drives
//! [`scanner::scan`] — the same entry point a front end calls — and prints what
//! the shipped rules made of it, which is what a user would actually see. A
//! difference between the two is a defect in everything between them.
//!
//! ## The ordinary way is the CLI
//!
//! `zond scan <target> --os-detection active -v` runs the same phases through
//! the same entry point and shows the finding with the working under it. Reach
//! for that first. This exists for the case the CLI deliberately does not serve:
//! seeing the **whole** [`Host`] record, every field the engine populated,
//! which is what says whether a value is missing because nothing found it or
//! because nothing carried it through.
//!
//! ```text
//! cargo bench --no-run --bench os_detect
//! sudo -E <binary> <target> [ports] [off|passive|active|aggressive] [--all]
//! ```
//!
//! `cargo bench` is deliberately not used to *run* it: this wants root, and
//! `sudo cargo` would build as root and leave `target/` owned by it.
//!
//! ### Finding the binary you just built
//!
//! A `harness = false` bench builds to a hashed name, several accumulate across
//! rebuilds, and nothing warns you that the one you ran is not the one you
//! built. **Select by newest, and select executables:**
//!
//! ```text
//! # fish
//! set bin (command ls -t (path filter -fx target/release/deps/os_detect-*))[1]
//! test -x "$bin"; and sudo -E $bin 192.168.64.0/24 22,80,443 active
//!
//! # bash / zsh
//! bin=$(find target/release/deps -name 'os_detect-*' -type f -perm -u+x -print0 \
//!       | xargs -0 ls -t 2>/dev/null | head -1)
//! [ -x "$bin" ] && sudo -E "$bin" 192.168.64.0/24 22,80,443 active
//! ```
//!
//! Guard the result before running it. Unguarded on a tree that has not been
//! built, `xargs ls -t` receives no input and lists the current directory
//! instead, so `sudo` is handed the first entry in the repository as a command.
//!
//! ## Reading it
//!
//! One block per host that answered something, carrying the whole [`Host`]: the
//! verdict and its evidence line, the status and what proved it, the hostname,
//! the hardware vendor, the RTT summary, and every port state. `-` in the `os`
//! field is the ordinary case, not a failure — the corpus holds rules only for
//! what has been measured, and a wrong answer costs more than a missing one.
//!
//! Addresses that answered nothing are skipped: a `/24` with four live hosts
//! would otherwise print two hundred and fifty-two identical blocks saying so.
//! `--all` includes them.
//!
//! The last argument sets the detection level, so the same scan can be run with
//! it off to confirm the difference is the reading and not the probing: at
//! `passive` — the default — the traffic is byte-identical to `off`.
//!
//! At `active` two more things happen. Every host with an open or closed TCP
//! port is **followed**: asked the same question several times, from a fresh
//! source port each time, so that the policies behind its counters become
//! visible. Those show up on the `evidence` line as `id=`, `isn=` and `ts=`, and
//! they are the only features a rule naming a *release* rather than a family can
//! predicate on. Every host that answered no TCP probe at all is additionally
//! pinged, which is the one route left to it.
//!
//! At `aggressive` the same probes are sent, twice as many samples per host, and
//! at every host rather than only the unsettled ones — which is what to run when
//! *measuring* a machine whose operating system is already known from outside,
//! because that is how a rule gets authored.
//!
//! [`Host`]: zond_engine::model::host::Host

use std::collections::BTreeMap;
use std::net::IpAddr;

use zond_engine::config::{OsDetection, ZondConfig};
use zond_engine::model::host::Host;
use zond_engine::model::parse::ip::to_set;
use zond_engine::model::port::{PortSet, PortState};
use zond_engine::model::target::{TargetMap, TargetSet};
use zond_engine::scanner;

/// Ports to probe, chosen for being the ones most likely to be open on a home or
/// office segment. Only one has to answer for a host to be identifiable.
const DEFAULT_PORTS: &str = "22,80,443,445,3389,8080";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let show_all = args.iter().any(|arg| arg == "--all");
    let positional: Vec<&String> = args.iter().filter(|arg| *arg != "--all").collect();

    let Some(target) = positional.first() else {
        eprintln!("usage: os_detect <target> [ports] [off|passive|active|aggressive] [--all]");
        eprintln!("  ports default to {DEFAULT_PORTS}");
        std::process::exit(2);
    };
    let ports = positional
        .get(1)
        .map_or(DEFAULT_PORTS.to_string(), |ports| {
            if ports.is_empty() {
                DEFAULT_PORTS.to_string()
            } else {
                (*ports).clone()
            }
        });
    let detection = match positional.get(2) {
        Some(level) => level.parse().unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(2);
        }),
        None => OsDetection::default(),
    };

    // No resolver, deliberately: an instrument that silently followed whatever
    // DNS answered with would be measuring a moving target.
    let addresses = match to_set(&[target.as_str()], None, None) {
        Ok(addresses) => addresses,
        Err(e) => {
            eprintln!("cannot read target `{target}`: {e}");
            std::process::exit(2);
        }
    };
    let Ok(ports) = PortSet::try_from(ports.as_str()) else {
        eprintln!("cannot read the port list");
        std::process::exit(2);
    };

    let mut target_map = TargetMap::new();
    target_map.add_unit(TargetSet::new(addresses, ports));

    let cfg = ZondConfig {
        os_detection: detection,
        ..ZondConfig::default()
    };

    println!(
        "scanning with os detection {} (level {}), which sends {} of its own\n",
        detection,
        detection.level(),
        if detection.is_active() {
            "probes"
        } else {
            "nothing"
        }
    );

    let (session, task) = match scanner::scan(target_map, &cfg).await {
        Ok(started) => started,
        Err(e) => {
            eprintln!("the scan could not start: {e}");
            eprintln!("this needs root: it opens raw sockets and a capture.");
            std::process::exit(1);
        }
    };
    let _report = task.await.expect("the scan finishes");

    // Sorted by address so two runs of the same range are diffable.
    let hosts: BTreeMap<IpAddr, Host> = session
        .hosts()
        .snapshot()
        .into_iter()
        .map(|host| (host.primary_ip(), host))
        .collect();

    if hosts.is_empty() {
        println!("nothing answered.");
        return;
    }

    let mut named = 0usize;
    let mut open_somewhere = 0usize;
    let mut silent = 0usize;
    let mut printed = 0usize;
    for (address, host) in &hosts {
        let answered = host.status() != zond_engine::model::host::HostStatus::Unknown;
        if !answered && !show_all {
            continue;
        }
        if printed > 0 {
            println!();
        }
        print_host(address, host);
        printed += 1;

        if host.os().is_some() {
            named += 1;
        }
        if host.ports().any(|p| p.state() == PortState::Open) {
            open_somewhere += 1;
        } else if host.status().is_up() {
            silent += 1;
        }
    }

    let skipped = hosts.len() - printed;
    let skipped_note = if skipped > 0 {
        format!(" ({skipped} that answered nothing skipped; --all shows them)")
    } else {
        String::new()
    };
    println!(
        "\n{named} of {} host(s) named; {open_somewhere} with an open port, {silent} up with none{skipped_note}.",
        hosts.len()
    );

    if !detection.is_enabled() {
        println!("  Detection was off, so nothing was read and nothing could be named.");
        println!("  Re-run at `passive` to see what these replies say - it sends no extra packet.");
        return;
    }

    if named < open_somewhere && detection.is_active() {
        println!(
            "  A host with an open port and no name answered with a stack shape no rule\n  \
             describes. That is the corpus being honest rather than the classifier failing:\n  \
             rules exist only for what has been measured with an open port. Run `os_observe`\n  \
             against it to see the shape, and add it once its operating system is known\n  \
             from outside."
        );
    }
    if silent > 0 && !detection.is_active() {
        println!(
            "  A host up with no open port has no TCP options to read — a reset carries\n  \
             none — so nothing here can name it. Re-run at `active` to ask it by echo,\n  \
             which is the packet such a host still answers."
        );
    }
    if !detection.is_active() {
        println!(
            "  Nothing here is release-level: the identifier policy, the sequence\n  \
             generator and the timestamp clock are only visible across several replies,\n  \
             and this level sent one. Re-run at `active` to follow each host and read\n  \
             them; the `evidence` line then carries `id=`, `isn=` and `ts=`."
        );
    }
}

/// Everything the scan knows about one host, one field per line.
///
/// `Host`'s own `Display` renders a single summary row; this prints the whole
/// record because the point of the instrument is to see what a front end would
/// have to work with, and to spot the field that is set wrongly or not at all.
fn print_host(address: &IpAddr, host: &Host) {
    let os = match host.os() {
        Some(os) => format!(
            "{} [{}%]{}{}{}",
            os.name(),
            os.accuracy(),
            os.family()
                .map(|family| format!(" family={family}"))
                .unwrap_or_default(),
            // The part a series rule exists to supply. Printed even though it
            // is usually absent, because "no version" and "a version nothing
            // showed me" are the two outcomes this instrument is run to tell
            // apart.
            os.generation()
                .map(|version| format!(" version={version}"))
                .unwrap_or_default(),
            os.vendor()
                .map(|vendor| format!(" vendor={vendor}"))
                .unwrap_or_default(),
        ),
        None => "-".to_string(),
    };
    println!("{address}  {os}");

    println!(
        "  status {:?} ({})",
        host.status(),
        if host.is_alive() {
            "alive"
        } else {
            "not confirmed alive"
        }
    );

    if let Some(hostname) = host.hostname() {
        println!("  hostname {hostname}");
    }
    if let Some(hardware) = host.hardware() {
        println!(
            "  hardware {}{}",
            hardware
                .most_recent_mac()
                .map(|mac| mac.to_string())
                .unwrap_or_default(),
            hardware
                .vendor()
                .map(|vendor| format!(" vendor={vendor}"))
                .unwrap_or_default(),
        );
    }
    if let Some(median) = host.median_rtt() {
        println!(
            "  rtt median {median:?} (min {:?}, max {:?})",
            host.min_rtt().unwrap_or_default(),
            host.max_rtt().unwrap_or_default()
        );
    }
    for reason in host.reasons() {
        let from = reason
            .source
            .map(|source| format!(" (reported by {source})"))
            .unwrap_or_default();
        println!(
            "  why {:?}: {}{from}",
            reason.protocol,
            reason.details.as_deref().unwrap_or("-")
        );
    }
    if let Some(os) = host.os()
        && let Some(evidence) = os.evidence()
    {
        println!("  evidence {evidence}");
    }
    if let Some(os) = host.os() {
        for cpe in os.cpes() {
            println!("  cpe {cpe}");
        }
    }

    let ports: Vec<String> = host
        .ports()
        .map(|port| format!("{}/{:?}={:?}", port.number(), port.protocol(), port.state()))
        .collect();
    if !ports.is_empty() {
        println!("  ports {}", ports.join(" "));
    }
}
