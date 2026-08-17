// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How fast does an IPv6 neighbour answer a solicitation?
//!
//! The measurement the whole NDP retry schedule rests on, taken outside the
//! scanner so it cannot inherit the scanner's assumptions.
//!
//! Every attempt to time an IPv6 neighbour has run into the same wall: the
//! answer arrives after the probe has been sent a second time, and two
//! solicitations for one address are identical on the wire, so Karn's rule
//! discards the sample. A packet capture of a real sweep (`scan.pcapng`) showed
//! why the second attempt is the one that gets answered — of 27 solicitations,
//! the two emitted on their own were both answered, and the 25 emitted
//! back-to-back at the scanner's 1 ms send interval were answered by nobody.
//! Byte-identical re-sends a second later were answered, two of them within
//! 6 ms by hosts that had ignored the first.
//!
//! That capture cannot say whether the burst is lost on the way out or ignored
//! on arrival, and it cannot say what spacing is enough, because the scan only
//! ever ran at one spacing. This does: it sends **exactly one** solicitation per
//! address at a chosen interval and waits. One attempt per address means every
//! advertisement is unambiguously an answer to it, so the round trip printed
//! here is a measurement rather than an inference.
//!
//! Run the same target set at several intervals and compare how many first
//! attempts are answered:
//!
//! ```text
//! cargo bench --no-run --bench ndp_pace
//! sudo -E target/release/deps/ndp_pace-<hash> 1
//! sudo -E target/release/deps/ndp_pace-<hash> 20
//! sudo -E target/release/deps/ndp_pace-<hash> 100
//! ```
//!
//! Built with `--no-run` and invoked directly, for the reason `verify_scan`
//! gives: cargo passes its own arguments through to a `harness = false` target,
//! and this one reads argv.
//!
//! If the answered count climbs with the interval, the scanner's burst is the
//! cause and solicitation needs its own pacing. If it does not, the burst is
//! innocent and these devices simply answer on a schedule of their own, which
//! is an argument about timeouts instead.
//!
//! Targets come from this host's IPv6 neighbour table, the same source the
//! sweep seeds from, so the two runs ask about the same addresses. Note that a
//! stale entry names an address nobody holds any more; those are silent here
//! however they are paced, which is why the roster is printed in full rather
//! than only as a count.
//!
//! ```text
//! sudo -E target/release/deps/ndp_pace-<hash> [interval_ms] [flags]
//!
//!   --window MS      how long to keep listening after the last solicitation
//!                    (default 4000)
//!   --interface NAME probe from this interface instead of the best-ranked one
//!   --target ADDR    ask about this address instead of the neighbour table;
//!                    repeatable
//!   --flood MS       also broadcast an ARP request every MS milliseconds for
//!                    the whole run, reproducing the channel load an IPv4 sweep
//!                    puts on the segment while it solicits
//! ```
//!
//! `--flood` is the control that keeps this honest. Solicitation in the scanner
//! never happens on a quiet segment: it happens beside an IPv4 sweep emitting
//! broadcast at a thousand frames a second. A pacing that works here and not
//! there would be an instrument measuring conditions the engine never meets.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use zond_engine::protocols::{arp, ndp};
use zond_engine::system::interface::{NetworkInterfaceExtension, get_prioritized_interfaces};
use zond_engine::system::neighbors;
use zond_engine::transport::channel;

/// How long to listen after the last solicitation goes out.
///
/// Sized from what a capture of a live segment showed rather than from what a
/// LAN round trip suggests: advertisements arrived up to 2.2 seconds after the
/// solicitation that provoked them, from devices asleep on wifi that answer
/// when they next wake. A window that closes earlier would report a slow
/// neighbour as a silent one, which is the distinction this exists to draw.
const DEFAULT_WINDOW: Duration = Duration::from_millis(4_000);

/// The interval used when none is given: the scanner's own send interval, so
/// the default run reproduces the conditions being questioned.
const DEFAULT_INTERVAL: Duration = Duration::from_millis(1);

/// One address asked about once.
struct Probe {
    target: Ipv6Addr,
    sent_at: Instant,
    /// When the advertisement naming this address arrived, if one did.
    answered_at: Option<Instant>,
}

impl Probe {
    fn rtt(&self) -> Option<Duration> {
        self.answered_at
            .map(|at| at.saturating_duration_since(self.sent_at))
    }
}

fn fail(message: &str) -> ! {
    eprintln!("ndp_pace: {message}");
    std::process::exit(1);
}

/// The value of a `--name VALUE` flag, if it was given.
///
/// A flag that is present but unparseable ends the run: an interval silently
/// falling back to the default would produce a second arm identical to the
/// first and no sign that it had.
fn flag<T: std::str::FromStr>(args: &[String], name: &str) -> Option<T> {
    let position = args.iter().position(|arg| arg == name)?;
    match args.get(position + 1).and_then(|value| value.parse().ok()) {
        Some(value) => Some(value),
        None => fail(&format!("`{name}` needs a value it can parse")),
    }
}

/// Every value given to a repeatable `--name VALUE` flag.
fn flags<T: std::str::FromStr>(args: &[String], name: &str) -> Vec<T> {
    args.iter()
        .enumerate()
        .filter(|(_, arg)| arg.as_str() == name)
        .map(
            |(position, _)| match args.get(position + 1).and_then(|v| v.parse().ok()) {
                Some(value) => value,
                None => fail(&format!("`{name}` needs a value it can parse")),
            },
        )
        .collect()
}

/// The interface to probe from: the one named, or the best-ranked one that has
/// a link-local address to solicit from.
fn choose_interface(name: Option<String>) -> NetworkInterface {
    let interfaces = get_prioritized_interfaces(usize::MAX)
        .unwrap_or_else(|e| fail(&format!("interfaces: {e}")));

    match name {
        Some(name) => interfaces
            .into_iter()
            .find(|intf| intf.name == name)
            .unwrap_or_else(|| fail(&format!("no interface named `{name}`"))),
        None => interfaces
            .into_iter()
            .find(|intf| link_local_of(intf).is_some())
            .unwrap_or_else(|| fail("no interface has a link-local IPv6 address")),
    }
}

/// The IPv4 address the flood's requests claim to come from, and the /24 they
/// ask about.
fn ipv4_of(intf: &NetworkInterface) -> Option<Ipv4Addr> {
    intf.ips
        .iter()
        .filter_map(|net| match net.ip() {
            IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
            _ => None,
        })
        .next()
}

fn link_local_of(intf: &NetworkInterface) -> Option<Ipv6Addr> {
    intf.get_ipv6_nets()
        .into_iter()
        .map(|net| net.ip())
        .find(Ipv6Addr::is_unicast_link_local)
}

/// The addresses to ask about, in the order they will be asked.
///
/// Deduplicated, because the neighbour table may hold one address against more
/// than one entry and asking twice would forfeit the attribution this whole
/// measurement depends on.
fn targets(intf: &NetworkInterface, explicit: Vec<Ipv6Addr>) -> Vec<Ipv6Addr> {
    if !explicit.is_empty() {
        return explicit;
    }

    let mut seen = Vec::new();
    for neighbor in neighbors::ipv6_neighbors() {
        let IpAddr::V6(address) = neighbor.ip else {
            continue;
        };
        if neighbor.interface_index == intf.index && !seen.contains(&address) {
            seen.push(address);
        }
    }
    seen
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let interval = args
        .first()
        .filter(|arg| !arg.starts_with("--"))
        .map(|arg| match arg.parse::<u64>() {
            Ok(ms) => Duration::from_millis(ms),
            Err(_) => fail("the interval is a whole number of milliseconds"),
        })
        .unwrap_or(DEFAULT_INTERVAL);
    let window = flag::<u64>(&args, "--window")
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_WINDOW);
    let flood = flag::<u64>(&args, "--flood").map(Duration::from_millis);

    let intf = choose_interface(flag(&args, "--interface"));
    let Some(source) = link_local_of(&intf) else {
        fail(&format!("{} has no link-local IPv6 address", intf.name));
    };
    let Some(mac) = intf.mac else {
        fail(&format!("{} has no mac address", intf.name));
    };

    let targets = targets(&intf, flags(&args, "--target"));
    if targets.is_empty() {
        fail(&format!(
            "no IPv6 neighbours known on {} - pass --target to name one",
            intf.name
        ));
    }

    // Resolved before the run so a flood that cannot be sent is an error rather
    // than an arm that silently ran without the load it was named for.
    let flood_source = flood.map(|_| {
        ipv4_of(&intf)
            .unwrap_or_else(|| fail(&format!("{} has no IPv4 address to flood from", intf.name)))
    });

    println!(
        "\nndp_pace: {} targets on {} ({source}), one solicitation each, {} ms apart, \
         listening {} ms after the last{}\n",
        targets.len(),
        intf.name,
        interval.as_millis(),
        window.as_millis(),
        match (flood, flood_source) {
            (Some(every), Some(from)) => format!(
                ", under a broadcast ARP flood from {from} every {} ms",
                every.as_millis()
            ),
            _ => String::new(),
        },
    );

    let mut handle = channel::start_capture(&intf)
        .unwrap_or_else(|e| fail(&format!("opening {}: {e}", intf.name)));

    let mut probes: Vec<Probe> = Vec::with_capacity(targets.len());
    let mut index_of: HashMap<Ipv6Addr, usize> = HashMap::with_capacity(targets.len());
    let mut pending = targets.into_iter();
    let mut unasked: Vec<Ipv6Addr> = Vec::new();

    // One ticker for both phases: it paces the sends, and once they are done it
    // simply wakes the loop often enough to notice the window has closed.
    let mut ticker = tokio::time::interval(interval.max(Duration::from_millis(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Runs for the whole measurement, listening window included: a sweep is
    // still emitting ARP while it waits for advertisements, so an arm whose
    // flood stopped at the last solicitation would not be reproducing it.
    let mut flood_ticker = tokio::time::interval(
        flood
            .unwrap_or(Duration::from_secs(3_600))
            .max(Duration::from_millis(1)),
    );
    flood_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut flood_host: u8 = 0;
    // Per-address, so the ARP half is a measurement rather than background
    // noise: the sweep it reproduces asks each address once, and whether that
    // one request is answered is the same question being asked of solicitation.
    let mut arp_probes: Vec<(Ipv4Addr, Instant, Option<Instant>)> = Vec::new();
    let mut arp_index: HashMap<Ipv4Addr, usize> = HashMap::new();

    let mut last_sent_at = Instant::now();
    let mut sending = true;

    loop {
        if !sending && Instant::now() >= last_sent_at + window {
            break;
        }

        tokio::select! {
            frame = handle.rx.recv() => {
                let Some(bytes) = frame else { break };
                let now = Instant::now();
                let Some(frame) = EthernetPacket::new(&bytes) else { continue };
                if let Some(sender) = arp_reply_sender(&frame)
                    && let Some(probe) = arp_index.get(&sender).map(|i| &mut arp_probes[*i])
                    && probe.2.is_none() {
                    probe.2 = Some(now);
                    continue;
                }

                let Some(target) = ndp::advertised_target(&frame) else { continue };

                // Only the first advertisement counts. A neighbour may repeat
                // one, and a later copy would overwrite a real round trip with
                // the time the neighbour happened to say it again.
                if let Some(probe) = index_of.get(&target).map(|i| &mut probes[*i])
                    && probe.answered_at.is_none() {
                    probe.answered_at = Some(now);
                }
            }

            _ = ticker.tick(), if sending => {
                let Some(target) = pending.next() else {
                    sending = false;
                    continue;
                };

                let packet = ndp::create_neighbor_solicitation(&mac, &source, target);
                let now = Instant::now();

                // Recorded only if the frame actually left. A probe the channel
                // refused is not evidence about pacing either way, and counting
                // it would report an address as silent that was never asked -
                // which is the one direction this instrument must not err in,
                // since it would make every arm look worse the busier the link
                // was.
                if !left_the_host(handle.tx.send_to(&packet, None)) {
                    unasked.push(target);
                    continue;
                }

                index_of.insert(target, probes.len());
                probes.push(Probe { target, sent_at: now, answered_at: None });
                last_sent_at = now;
            }

            _ = flood_ticker.tick(), if flood_source.is_some() && flood_host < 254 => {
                let Some(from) = flood_source else { continue };
                // One request per address across the /24, once, exactly as the
                // sweep emits them - so "answered" here means answered on the
                // first attempt, the only attempt a round trip can come from.
                flood_host += 1;
                let octets = from.octets();
                let target = Ipv4Addr::new(octets[0], octets[1], octets[2], flood_host);
                if target == from {
                    continue;
                }
                let packet = arp::create_request(&mac, &from, target);
                let now = Instant::now();

                // Same rule as the solicitation above: a request that never
                // left is not one the segment declined to answer.
                if !left_the_host(handle.tx.send_to(&packet, None)) {
                    continue;
                }

                arp_index.insert(target, arp_probes.len());
                arp_probes.push((target, now, None));
            }

            _ = tokio::time::sleep(Duration::from_millis(50)), if !sending => {}
        }
    }

    report(&probes, &unasked, interval, &arp_probes, flood);
}

/// Whether a frame handed to the channel actually reached the wire.
///
/// `send_to` reports `None` when the channel had no buffer to write into and
/// `Some(Err(..))` when the write itself failed, and both mean the frame never
/// left. Reading only whether the packet *built* is how a measurement comes to
/// count probes that were never sent.
fn left_the_host(outcome: Option<std::io::Result<()>>) -> bool {
    match outcome {
        Some(Ok(())) => true,
        Some(Err(e)) => {
            eprintln!("ndp_pace: a frame could not be sent: {e}");
            false
        }
        None => {
            eprintln!("ndp_pace: the link-layer channel accepted no frame");
            false
        }
    }
}

/// The sender address of an ARP reply, or `None` for any other frame.
fn arp_reply_sender(frame: &EthernetPacket) -> Option<Ipv4Addr> {
    if frame.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(frame.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    Some(arp.get_sender_proto_addr())
}

fn report(
    probes: &[Probe],
    unasked: &[Ipv6Addr],
    interval: Duration,
    arp_probes: &[(Ipv4Addr, Instant, Option<Instant>)],
    arp_interval: Option<Duration>,
) {
    println!("{:<46} answered", "address");
    println!("{}", "─".repeat(60));
    for probe in probes {
        match probe.rtt() {
            Some(rtt) => println!("{:<46} {:>7.1} ms", probe.target.to_string(), millis(rtt)),
            None => println!("{:<46} {:>10}", probe.target.to_string(), "silent"),
        }
    }
    // Addresses whose solicitation never reached the wire. Listed apart from
    // the silent ones because they are a fault in this host rather than an
    // answer from the segment, and folding them together would understate
    // every arm they appear in.
    for target in unasked {
        println!("{:<46} {:>10}", target.to_string(), "not sent");
    }

    let mut rtts: Vec<Duration> = probes.iter().filter_map(Probe::rtt).collect();
    rtts.sort_unstable();

    println!("{}", "─".repeat(60));
    println!(
        "ndp  {:>4} ms apart: {} of {} first solicitations answered",
        interval.as_millis(),
        rtts.len(),
        probes.len(),
    );
    if let (Some(fastest), Some(slowest)) = (rtts.first(), rtts.last()) {
        println!(
            "     round trips: min {:.1} ms, median {:.1} ms, max {:.1} ms",
            millis(*fastest),
            millis(rtts[rtts.len() / 2]),
            millis(*slowest),
        );
    }

    // The IPv4 half of the same question. The sweep asks each address once at
    // this spacing, so a request that goes unanswered here is a host the scan
    // would have to retry for - and a retry is a round trip it cannot report.
    if let Some(arp_interval) = arp_interval {
        let mut arp_rtts: Vec<Duration> = arp_probes
            .iter()
            .filter_map(|(_, sent, answered)| {
                answered.map(|at| at.saturating_duration_since(*sent))
            })
            .collect();
        arp_rtts.sort_unstable();

        println!(
            "arp  {:>4} ms apart: {} of {} first requests answered",
            arp_interval.as_millis(),
            arp_rtts.len(),
            arp_probes.len(),
        );
        if let (Some(fastest), Some(slowest)) = (arp_rtts.first(), arp_rtts.last()) {
            println!(
                "     round trips: min {:.1} ms, median {:.1} ms, max {:.1} ms",
                millis(*fastest),
                millis(arp_rtts[arp_rtts.len() / 2]),
                millis(*slowest),
            );
        }
    }
    println!();
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}
