// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Does the ICMP transport reach a host, and does a routed one answer?
//!
//! A functional check, not a study. Phase 6 of `docs/os-fingerprinting.md` needs
//! to ask a host something its TCP stack cannot be made to answer — a machine
//! with no open and no closed port still answers a ping — and until this work
//! there was no way to send one anywhere but the local segment: the echo
//! builders in `protocols::icmp` produce whole Ethernet frames, which need a
//! destination hardware address.
//!
//! So the question here is yes or no. Send an echo to each target over the raw
//! ICMP socket, print what came back, and say whether the reply crossed a
//! router. The request carries [`ECHO_PROBE_CODE`] rather than a conformant
//! zero, because that is what the fingerprinting probe sends and a path that
//! drops one is worth finding out about here rather than later — the code that
//! comes back is printed, and it is itself a discriminator. If the routed line
//! stays empty the ICMP half of phase 6 does not work and nothing built on it
//! will either.
//!
//! [`ECHO_PROBE_CODE`]: zond_engine::protocols::icmp::ECHO_PROBE_CODE
//!
//! ```text
//! cargo bench --no-run --bench icmp_reach
//! sudo -E <binary> 192.168.0.1 1.1.1.1 8.8.8.8
//! ```
//!
//! Finding the binary: a `harness = false` bench builds to a hashed name and
//! several accumulate, so select the newest **executable** rather than the first
//! match, and guard it before handing it to `sudo`.
//!
//! ```text
//! set bin (command ls -t (path filter -fx target/release/deps/icmp_reach-*))[1]
//! test -x "$bin"; and sudo -E $bin 1.1.1.1
//! ```

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use tokio::time::timeout;

use zond_engine::model::capture::IpObservation;
use zond_engine::model::parse::ip::to_set;
use zond_engine::protocols::icmp::{self, EchoReply};
use zond_engine::system::interface::SourceResolver;
use zond_engine::transport::probe::{ProbeKind, ProbeTransport};

/// How long to keep reading after the last request goes out.
const LISTEN_FOR: Duration = Duration::from_secs(3);

/// How long to block on the receive channel before checking the clock.
const RECV_TICK: Duration = Duration::from_millis(50);

/// The payload every request carries.
///
/// Non-empty on purpose: a conformant responder echoes it back (RFC 792,
/// RFC 4443 §4.2), so a reply that comes back short has said something about the
/// stack that sent it, and a reply that comes back whole confirms the request
/// arrived intact rather than merely arriving.
const PAYLOAD: &[u8] = b"zond-engine icmp reach check";

/// The initial hop counters a reply's remaining hops are read against. A reply
/// arriving at one of these exactly crossed no router.
const COMMON_INITIAL_HOPS: [u8; 4] = [32, 64, 128, 255];

#[tokio::main]
async fn main() {
    let targets: Vec<String> = std::env::args().skip(1).collect();
    if targets.is_empty() {
        eprintln!("usage: icmp_reach <target> [target ...]");
        eprintln!("  give at least one on-link and one routed address.");
        std::process::exit(2);
    }
    let addresses = match to_set(&targets, None, None) {
        Ok(addresses) => addresses,
        Err(e) => {
            eprintln!("cannot read the targets: {e}");
            std::process::exit(2);
        }
    };

    let identifier: u16 = rand::random();
    let mut transport = match ProbeTransport::open(ProbeKind::IcmpEcho { identifier }) {
        Ok(transport) => transport,
        Err(e) => {
            eprintln!("cannot open an ICMP probe transport: {e}");
            eprintln!("this needs root: it opens a raw socket and a capture.");
            std::process::exit(1);
        }
    };
    let mut resolver = SourceResolver::from_system();

    // Sequence number to the address it was sent to. The identifier says the
    // reply is this run's; the sequence says which request it answers, which is
    // what lets one run ask several hosts at once.
    let mut sent: BTreeMap<u16, IpAddr> = BTreeMap::new();
    for (sequence, address) in addresses.iter().enumerate() {
        let Ok(sequence) = u16::try_from(sequence) else {
            eprintln!("more targets than an echo sequence number can name");
            break;
        };
        let Some(source) = resolver.resolve(address) else {
            println!("{address}: no source address reaches it");
            continue;
        };
        let message = match icmp::create_echo_request_message(
            source,
            address,
            icmp::ECHO_PROBE_CODE,
            identifier,
            sequence,
            PAYLOAD,
        ) {
            Ok(message) => message,
            Err(e) => {
                println!("{address}: cannot build an echo request: {e}");
                continue;
            }
        };
        match transport.tx.send(&message, source, address) {
            Ok(()) => {
                sent.insert(sequence, address);
            }
            Err(e) => println!("{address}: the host would not send it: {e}"),
        }
    }

    if sent.is_empty() {
        println!("\nnothing went out. The transport is the thing to look at, not the network.");
        std::process::exit(1);
    }
    println!(
        "\n{} request(s) away, listening for {LISTEN_FOR:?}",
        sent.len()
    );

    let mut answered: BTreeMap<IpAddr, String> = BTreeMap::new();
    let until = Instant::now() + LISTEN_FOR;
    while Instant::now() < until {
        let Ok(Some(reply)) = timeout(RECV_TICK, transport.rx.recv()).await else {
            continue;
        };
        if reply.protocol != IpNextHeaderProtocols::Icmp
            && reply.protocol != IpNextHeaderProtocols::Icmpv6
        {
            continue;
        }
        // The family the reply arrived under decides how to read its type. An
        // ICMP message does not say which numbering it belongs to.
        let over_ipv6 = reply.source.is_ipv6();
        let EchoReply::Ours { sequence } =
            icmp::classify_echo_reply(&reply.bytes, identifier, over_ipv6)
        else {
            continue;
        };
        let Some(&asked) = sent.get(&sequence) else {
            continue;
        };

        let code = reply.bytes.get(1).copied().unwrap_or_default();
        let echoed = reply.bytes.len().saturating_sub(8);
        let intact = reply.bytes.get(8..).is_some_and(|tail| tail == PAYLOAD);
        let hops = reply
            .observation
            .map_or("unknown".to_string(), |observation: IpObservation| {
                let left = observation.remaining_hops();
                if COMMON_INITIAL_HOPS.contains(&left) {
                    format!("{left}, so no router was crossed")
                } else {
                    format!("{left}, so it crossed at least one router")
                }
            });
        let from = if reply.source == asked {
            String::new()
        } else {
            format!(" (answered by {})", reply.source)
        };
        answered.insert(
            asked,
            format!(
                "hops left {hops}; code {code} back; {echoed} payload byte(s) back, {}{from}",
                if intact { "intact" } else { "CHANGED" },
            ),
        );
    }

    println!();
    let mut routed = 0usize;
    for address in sent.values() {
        match answered.get(address) {
            Some(line) => {
                if line.contains("crossed at least one router") {
                    routed += 1;
                }
                println!("  {address}: {line}");
            }
            None => println!("  {address}: no reply"),
        }
    }

    println!();
    if routed > 0 {
        println!(
            "{routed} routed host(s) answered. The ICMP transport reaches past the \
             local segment, which is the whole point of it."
        );
    } else {
        println!(
            "No reply crossed a router. Either nothing routed was asked, or the ICMP \
             transport does not reach past the segment — and the ICMP half of phase 6 \
             rests on it, so find out which before building on it."
        );
    }
}
