// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! End-to-end check for the Layer-2 / pcap probe transport.
//!
//! Before the pcap receive path, macOS classified *every* port as Filtered
//! because raw sockets never delivered the replies. This exercises all three
//! outcomes deterministically:
//!
//! * an **Open** port  - a real listener this example binds,
//! * a **Closed** port - a free loopback port with nothing behind it (the
//!   kernel answers our SYN with a RST),
//! * an external **Open** port on 1.1.1.1, to cover the off-link/VPN send path
//!   in addition to loopback.
//!
//! The loopback targets also cover the `DLT_NULL` link-layer parse, distinct
//! from Ethernet.
//!
//! Run as root (raw socket + pcap both require it):
//!
//! ```text
//! sudo -E cargo run --example verify_scan
//! ```

use std::net::{IpAddr, Ipv4Addr, TcpListener};

use zond_engine::core::models::ip::set::IpSet;
use zond_engine::core::models::port::{PortSet, PortState};
use zond_engine::core::models::target::{TargetMap, TargetSet};
use zond_engine::scanner;

#[tokio::main]
async fn main() {
    // A real listener on loopback: a guaranteed-Open port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind open port");
    let open_port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        // Keep accepting so the port stays open for the duration of the scan.
        for stream in listener.incoming() {
            drop(stream);
        }
    });

    // A free loopback port we bind then immediately release: nothing listens,
    // so the kernel RSTs a SYN to it -> guaranteed Closed.
    let closed_port = {
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind closed port");
        probe.local_addr().unwrap().port()
    };

    let localhost: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let external: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

    println!(
        "Loopback 127.0.0.1: port {open_port} should be Open, port {closed_port} should be Closed."
    );
    println!("External 1.1.1.1: port 443 should be Open (off-link / VPN send path).\n");

    let mut target_map = TargetMap::new();

    let mut local_ips = IpSet::new();
    local_ips.insert(localhost);
    let local_ports = PortSet::try_from(format!("{open_port}, {closed_port}").as_str()).unwrap();
    target_map.add_unit(TargetSet::new(local_ips, local_ports));

    let mut ext_ips = IpSet::new();
    ext_ips.insert(external);
    target_map.add_unit(TargetSet::new(ext_ips, PortSet::try_from("443").unwrap()));

    let (session, task) = scanner::scan(target_map).await.expect("scan started");
    task.await.expect("scan finished");

    let state_of = |ip: IpAddr, port: u16| -> Option<PortState> {
        session
            .store
            .get(&ip)
            .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
    };

    let open = state_of(localhost, open_port);
    let closed = state_of(localhost, closed_port);
    let external_open = state_of(external, 443);

    println!("Results:");
    println!("  127.0.0.1:{open_port:<5} -> {open:?}   (want Open)");
    println!("  127.0.0.1:{closed_port:<5} -> {closed:?}   (want Closed)");
    println!("  1.1.1.1:443     -> {external_open:?}   (want Open)\n");

    let pass = open == Some(PortState::Open)
        && closed == Some(PortState::Closed)
        && external_open == Some(PortState::Open);

    if pass {
        println!("PASS: Open, Closed, and off-link Open all classified correctly.");
    } else {
        println!("FAIL: at least one port did not classify as expected (see above).");
        std::process::exit(1);
    }
}
