// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
//!   in addition to loopback,
//! * the same **Open** and **Closed** pair over **IPv6** on `[::1]`.
//!
//! The loopback targets also cover the `DLT_NULL` link-layer parse, distinct
//! from Ethernet.
//!
//! The IPv6 pair is the only check anywhere that puts a real SYN on a real
//! socket over IPv6 and reads a port state back. `tests/probe_classification.rs`
//! covers the same classifications deterministically, but against a simulated
//! network that replaces the whole `ProbeTransport` — so it never exercises the
//! v6 socket, the route, or the capture. Loopback keeps this half dependency
//! free: no IPv6 connectivity and no router required.
//!
//! Run as root (raw socket + pcap both require it):
//!
//! ```text
//! sudo -E cargo run --example verify_scan
//! ```

use std::net::{IpAddr, Ipv4Addr, TcpListener};

use zond_engine::core::config::{SendMode, ZondConfig};
use zond_engine::core::models::ip::set::IpSet;
use zond_engine::core::models::port::{PortSet, PortState};
use zond_engine::core::models::target::{TargetMap, TargetSet};
use zond_engine::scanner;

#[tokio::main]
async fn main() {
    // `cargo run --example verify_scan -- ethernet` forces the Layer-2 send
    // backend (host-stack bypass); otherwise the platform default is used.
    // Note: Ethernet mode can't reach loopback, so only the 1.1.1.1 check is
    // meaningful there.
    let send_mode = match std::env::args().nth(1).as_deref() {
        Some("ethernet") => SendMode::Ethernet,
        Some("raw") => SendMode::RawSocket,
        _ => SendMode::Auto,
    };
    println!("Send mode: {send_mode:?}\n");

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

    // The IPv6 twin of the pair above. This is the only check anywhere that
    // puts a real SYN on a real socket over IPv6 and reads a port state back:
    // the simulated-network tests replace the whole `ProbeTransport`, so they
    // exercise probe construction and classification but never the v6 socket,
    // the route, or the capture. Loopback keeps it dependency-free — no IPv6
    // connectivity, no router, nothing outside this machine.
    let open_v6 = TcpListener::bind("[::1]:0").ok().map(|listener| {
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                drop(stream);
            }
        });
        port
    });
    let closed_v6 = TcpListener::bind("[::1]:0")
        .ok()
        .map(|probe| probe.local_addr().unwrap().port());

    let localhost: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let localhost_v6: IpAddr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
    let external: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

    // Ethernet mode builds frames itself and can't reach loopback (no
    // Ethernet interface to ARP), so loopback is skipped there. Off-link
    // 1.1.1.1 uses the gateway MAC read from the OS; the on-link gateway
    // probe below is what exercises the *active* ARP path.
    let ethernet = send_mode == SendMode::Ethernet;
    let gateway = if ethernet { default_gateway() } else { None };

    let mut target_map = TargetMap::new();

    if !ethernet {
        let mut local_ips = IpSet::new();
        local_ips.insert(localhost);
        let local_ports =
            PortSet::try_from(format!("{open_port}, {closed_port}").as_str()).unwrap();
        target_map.add_unit(TargetSet::new(local_ips, local_ports));
    }

    if !ethernet && let (Some(open), Some(closed)) = (open_v6, closed_v6) {
        let mut v6_ips = IpSet::new();
        v6_ips.insert(localhost_v6);
        let v6_ports = PortSet::try_from(format!("{open}, {closed}").as_str()).unwrap();
        target_map.add_unit(TargetSet::new(v6_ips, v6_ports));
    }

    let mut ext_ips = IpSet::new();
    ext_ips.insert(external);
    target_map.add_unit(TargetSet::new(ext_ips, PortSet::try_from("443").unwrap()));

    if let Some(gw) = gateway {
        let mut gw_ips = IpSet::new();
        gw_ips.insert(gw);
        // Port 80 is a report-only probe: whatever it returns (Open or
        // Closed), a non-Filtered result proves the on-link ARP round trip.
        target_map.add_unit(TargetSet::new(gw_ips, PortSet::try_from("80").unwrap()));
    }

    let cfg = ZondConfig {
        send_mode,
        ..Default::default()
    };
    let (session, task) = scanner::scan(target_map, &cfg).await.expect("scan started");
    let report = task.await.expect("scan finished");

    // A verification run that lost a scanner would otherwise print the same
    // "Filtered" as a genuinely filtered port.
    for failure in report.failures() {
        println!("  !! {failure}");
    }

    let state_of = |ip: IpAddr, port: u16| -> Option<PortState> {
        session
            .store
            .get(&ip)
            .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
    };

    let external_open = state_of(external, 443);
    println!("Results:");
    if !ethernet {
        println!(
            "  127.0.0.1:{open_port:<5} -> {:?}   (want Open)",
            state_of(localhost, open_port)
        );
        println!(
            "  127.0.0.1:{closed_port:<5} -> {:?}   (want Closed)",
            state_of(localhost, closed_port)
        );
        match (open_v6, closed_v6) {
            (Some(open), Some(closed)) => {
                println!(
                    "  [::1]:{open:<9} -> {:?}   (want Open)",
                    state_of(localhost_v6, open)
                );
                println!(
                    "  [::1]:{closed:<9} -> {:?}   (want Closed)",
                    state_of(localhost_v6, closed)
                );
            }
            _ => println!("  [::1]           -> skipped (no IPv6 loopback)"),
        }
    }
    println!("  1.1.1.1:443     -> {external_open:?}   (want Open)");
    if let Some(gw) = gateway {
        let gw_state = state_of(gw, 80);
        let arp_ok = matches!(gw_state, Some(PortState::Open | PortState::Closed));
        println!(
            "  gateway {gw}:80 -> {gw_state:?}   (active ARP round trip: {})",
            if arp_ok {
                "OK"
            } else {
                "inconclusive (dropped)"
            }
        );
    }
    println!();

    // The off-link Open classification is the universal success signal. In
    // non-Ethernet modes the deterministic loopback Open/Closed are required
    // too; in Ethernet mode loopback is out of scope.
    let mut pass = external_open == Some(PortState::Open);
    if !ethernet {
        pass &= state_of(localhost, open_port) == Some(PortState::Open)
            && state_of(localhost, closed_port) == Some(PortState::Closed);

        // Required on the same terms as the IPv4 pair, and skipped only where
        // the host genuinely has no IPv6 loopback. Reporting the v6 result
        // without letting it decide the verdict would be a check nobody reads.
        if let (Some(open), Some(closed)) = (open_v6, closed_v6) {
            pass &= state_of(localhost_v6, open) == Some(PortState::Open)
                && state_of(localhost_v6, closed) == Some(PortState::Closed);
        }
    }

    if pass {
        println!("PASS: reply classification is correct for {send_mode:?} mode.");
    } else {
        println!("FAIL: at least one required port did not classify as expected (see above).");
        std::process::exit(1);
    }
}

/// The default IPv4 gateway, if the OS reports one - an on-link host we can
/// ARP to exercise the Layer-2 active-resolution path.
fn default_gateway() -> Option<IpAddr> {
    netdev::get_default_interface()
        .ok()?
        .gateway?
        .ipv4
        .first()
        .copied()
        .map(IpAddr::V4)
}
