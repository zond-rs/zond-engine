// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runs a real scan and prints what it concluded about each host's operating
//! system.
//!
//! The companion to `os_observe`, and a different instrument for a different
//! question. `os_observe` drives the transport directly and prints what came off
//! the wire, which is what rules are *authored* from. This drives
//! [`scanner::scan`] — the same entry point a front end calls — and prints what
//! the shipped rules made of it, which is what a user would actually see. A
//! difference between the two is a defect in everything between them.
//!
//! ```text
//! cargo bench --no-run --bench os_detect
//! sudo -E <binary> <target> [ports] [off|passive|active|aggressive|0|1|2|3]
//! ```
//!
//! Built with `--no-run` and invoked directly rather than through `cargo bench`,
//! because it wants root and `sudo cargo` would build as root and leave
//! `target/` owned by it. Select the binary carefully — several accumulate under
//! a hashed name and nothing warns you the one you ran is not the one you built:
//!
//! ```text
//! # fish
//! set bin (command ls -t (path filter -fx target/release/deps/os_detect-*))[1]
//! test -x "$bin"; and sudo -E $bin 192.0.2.0/24
//!
//! # bash / zsh
//! bin=$(find target/release/deps -name 'os_detect-*' -type f -perm -u+x -print0 \
//!       | xargs -0 ls -t 2>/dev/null | head -1)
//! [ -x "$bin" ] && sudo -E "$bin" 192.0.2.0/24 || echo "not built yet"
//! ```
//!
//! ## Reading it
//!
//! One row per host that answered. `os` is what the rules concluded and `why` is
//! the evidence line the report carries — the observation the verdict was read
//! off, so a wrong answer can be argued with without running the scan again.
//!
//! **`-` in the `os` column is the ordinary case, not a failure.** The corpus
//! holds rules only for what has been measured with an open port, which today is
//! Linux and nothing else. A host with no open port has no options to read; a
//! host running an unmeasured system has no rule to match. Both report nothing,
//! deliberately, because a confident wrong answer costs more than a missing one.
//!
//! The last argument sets the detection level, so the same scan can be run with
//! it off to confirm the difference is the reading and not the probing: at
//! `passive` — the default — the traffic is byte-identical to `off`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use zond_engine::config::{OsDetection, ZondConfig};
use zond_engine::model::parse::ip::to_set;
use zond_engine::model::port::{PortSet, PortState};
use zond_engine::model::target::{TargetMap, TargetSet};
use zond_engine::scanner;

/// Ports to probe, chosen for being the ones most likely to be open on a home or
/// office segment. Only one has to answer for a host to be identifiable.
const DEFAULT_PORTS: &str = "22,80,443,445,3389,8080";

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| {
        eprintln!("usage: os_detect <target> [ports] [off|passive|active|aggressive]");
        std::process::exit(2);
    });
    let ports = args.next().unwrap_or_else(|| DEFAULT_PORTS.to_string());
    let detection = match args.next() {
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
    let hosts: BTreeMap<IpAddr, _> = session
        .hosts()
        .snapshot()
        .into_iter()
        .map(|host| (host.primary_ip(), host))
        .collect();

    if hosts.is_empty() {
        println!("nothing answered.");
        return;
    }

    println!(
        "{:<40} {:<10} {:<7} {:<22} {:>4}  why",
        "address", "status", "open", "os", "acc"
    );

    let mut named = 0usize;
    let mut open_somewhere = 0usize;
    for (address, host) in &hosts {
        let open: Vec<u16> = host
            .ports()
            .filter(|port| port.state() == PortState::Open)
            .map(|port| port.number())
            .collect();
        if !open.is_empty() {
            open_somewhere += 1;
        }

        let (os, accuracy, why) = match host.os() {
            Some(os) => {
                named += 1;
                // `name()` rather than the `Display`, which appends the
                // accuracy the next column already carries.
                (
                    os.name().to_string(),
                    os.accuracy().to_string(),
                    os.evidence().unwrap_or("-").to_string(),
                )
            }
            None => ("-".to_string(), "-".to_string(), String::new()),
        };

        println!(
            "{:<40} {:<10} {:<7} {:<22} {:>4}  {why}",
            address.to_string(),
            format!("{:?}", host.status()).to_lowercase(),
            if open.is_empty() {
                "-".to_string()
            } else {
                open.iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            },
            os,
            accuracy,
        );
    }

    println!(
        "\n{named} of {} host(s) named, {open_somewhere} had an open port.",
        hosts.len()
    );

    // Nothing below applies when nothing looked. A host unnamed because
    // detection was off and a host unnamed because no rule described it are
    // completely different findings, and saying the second about the first sends
    // somebody measuring a shape that was never read.
    if !detection.is_enabled() {
        println!("  Detection was off, so nothing was read and nothing could be named.");
        println!("  Re-run at `passive` to see what these replies say - it sends no extra packet.");
        return;
    }

    if named < open_somewhere {
        println!(
            "  A host with an open port and no name answered with a stack shape no rule\n  \
             describes. That is the corpus being honest rather than the classifier failing:\n  \
             rules exist only for what has been measured with an open port. Run `os_observe`\n  \
             against it to see the shape, and add it once its operating system is known\n  \
             from outside."
        );
    }
    if open_somewhere < hosts.len() {
        println!(
            "  A host with no open port has no TCP options to read at all — a reset carries\n  \
             none — so nothing here can name it. That needs a banner, a name or a hardware\n  \
             address instead."
        );
    }
}
