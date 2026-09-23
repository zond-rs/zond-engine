// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Layer-2 (Ethernet) Send Backend
//!
//! A [`ProbeSender`] that builds and
//! emits complete Ethernet frames itself, rather than handing a segment to a
//! raw socket and letting the kernel route it.
//!
//! Two situations need this:
//!
//! - **Windows**, where the OS blocks raw-socket TCP sends outright, so the
//!   only way to emit a SYN probe is to write the frame at the link layer.
//! - **Deliberate host-stack bypass**: crafting the frame end to end (source
//!   MAC included) sidesteps the local firewall and connection-tracking that
//!   a raw-socket send still traverses.
//!
//! It leans on [`NeighborResolver`] to decide, per packet, which interface to
//! send from and what the next-hop MAC is: the interface holding the packet's
//! source address, the gateway the OS names for it for off-link targets, and an
//! active, cached ARP exchange for on-link ones. A packet whose source only a
//! tunnel holds has no Ethernet route, and is refused rather than framed onto a
//! physical link the tunnel was meant to carry it past.
//!
//! On portability: on-link IPv6 currently returns an error rather than performing
//! NDP neighbor solicitation, while off-link IPv6 works since the gateway's MAC
//! comes from the OS. Wiring up NDP is the remaining gap.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use pnet_base::MacAddr;
use pnet_packet::Packet;
use pnet_packet::arp::{ArpOperations, ArpPacket};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};

use crate::protocols::arp;
use crate::transport::capture::{self, FrameSink};
use crate::transport::frame;
use crate::transport::neighbor::{LinkRoute, NeighborResolver};
use crate::transport::probe::{Emission, IpProtocols, ProbeSender, SendError};

/// How long to wait for an ARP reply before giving up on an on-link target.
const ARP_TIMEOUT: Duration = Duration::from_millis(500);

/// How many ARP requests one resolution sends, spread evenly across
/// [`ARP_TIMEOUT`]: at its start, a third of the way in, and two thirds.
///
/// More than one because a single request is a single chance, and a lost
/// request or a lost reply is not rare. ARP is broadcast, and a switch under
/// load drops broadcast before anything else. One lost frame costs far more
/// than the resolution: the neighbour is then remembered as unanswered for
/// [`NEIGHBOR_UNREACHABLE_TTL`], so a live host's every port goes unasked for
/// that long on the strength of one dropped packet. The kernel covers the same
/// risk the same way, with several solicitations before it gives a neighbour
/// up.
///
/// Three, and spaced a third of the timeout apart, because a neighbour on the
/// same segment that is going to answer does so in well under a millisecond.
/// A request unanswered after a sixth of a second was lost rather than slow, so
/// asking again then is not impatience, and the spacing is wide enough that a
/// burst which dropped one request has usually passed before the next. The
/// local sweep asks three times on much the same schedule, for the same
/// reason. A dead address still costs exactly [`ARP_TIMEOUT`]: the requests
/// share the wait rather than each bringing one of their own.
const ARP_REQUESTS: u32 = 3;

/// How long a neighbour that did not answer its address resolution is left
/// unasked before the sender tries it again.
///
/// A dead on-link address, or a gateway that never answered, would otherwise
/// pay [`ARP_TIMEOUT`] afresh on every probe: each port, and each retry within
/// a port, re-runs the exchange and blocks for the full timeout because nothing
/// records that the last one went unanswered. One dead `(host, port)` pair
/// across a three-attempt sweep costs three timeouts, and a range of dead
/// addresses across a port list multiplies that by every port. Remembering the
/// failure collapses the whole of it to a single timeout per address: the first
/// probe waits, and every probe behind it is turned away at once.
///
/// The memory ages out rather than standing for the sender's life so a host that
/// was down when first probed and has since come up is found on a later sweep of
/// a long-running scan, and so a MAC learned after a transient failure is not
/// shadowed by a verdict nothing revisits. It is long enough that a single
/// scan's repeated probes to one address, and the retries behind them, all reuse
/// the one failure it records rather than each re-timing the dead neighbour.
const NEIGHBOR_UNREACHABLE_TTL: Duration = Duration::from_secs(30);

/// Per-interface datalink read timeout, so the ARP receive loop wakes often
/// enough to honor [`ARP_TIMEOUT`] instead of blocking indefinitely.
const CHANNEL_READ_TIMEOUT: Duration = Duration::from_millis(50);

/// The open link-layer channel for one interface, plus the source MAC to
/// stamp on frames leaving it.
struct InterfaceChannel {
    channel: capture::FrameChannel,
}

/// The neighbours whose address resolution last went unanswered, so the sender
/// can decline to ask again until the record ages out. Keyed by
/// `(interface, next-hop IP)`, the same key the resolver's learned-MAC cache
/// uses, so a next hop is either known to answer or known not to, never both
/// consulted at once.
///
/// This is the negative half of that cache: it holds not a MAC but the instant
/// an exchange for one timed out. See [`NEIGHBOR_UNREACHABLE_TTL`] for why an
/// entry expires. The clock is a parameter rather than read inside so the policy
/// is a pure function of time and can be tested without waiting on one.
#[derive(Default)]
struct UnansweredNeighbors {
    seen: HashMap<(String, IpAddr), Instant>,
}

impl UnansweredNeighbors {
    /// Records that resolution for `next_hop` on `interface` went unanswered at
    /// `at`.
    fn note(&mut self, interface: &str, next_hop: IpAddr, at: Instant) {
        self.seen.insert((interface.to_string(), next_hop), at);
    }

    /// Forgets any record for `next_hop` on `interface`: a neighbour that has
    /// since answered is not one to skip.
    fn clear(&mut self, interface: &str, next_hop: IpAddr) {
        self.seen.remove(&(interface.to_string(), next_hop));
    }

    /// Whether `next_hop` on `interface` went unanswered within `ttl` of `now`,
    /// so the sender should decline to resolve it again yet.
    fn is_fresh(&self, interface: &str, next_hop: IpAddr, now: Instant, ttl: Duration) -> bool {
        self.seen
            .get(&(interface.to_string(), next_hop))
            .is_some_and(|at| now.saturating_duration_since(*at) < ttl)
    }
}

/// A Layer-2 send backend. Interfaces' channels are opened lazily on first
/// use and reused thereafter.
pub struct EthernetSender {
    resolver: Mutex<NeighborResolver>,
    channels: Mutex<HashMap<String, InterfaceChannel>>,
    /// Next hops whose last resolution went unanswered, so a dead address is
    /// asked once rather than once per probe. See [`UnansweredNeighbors`] and
    /// [`NEIGHBOR_UNREACHABLE_TTL`].
    unanswered: Mutex<UnansweredNeighbors>,
    /// The IP protocol numbers to stamp into the headers this sender builds,
    /// one per address family. Fixed per sender because a transport carries one
    /// kind of probe; see [`EthernetSender::from_system`].
    protocols: IpProtocols,
}

impl EthernetSender {
    /// Builds a sender over the system's Ethernet-capable interfaces, emitting
    /// segments as `protocols` says for the family being addressed.
    ///
    /// Unlike the raw-socket sender, this one writes the IP header itself, so
    /// nothing else can tell it what it is carrying: the segment is opaque
    /// bytes by the time it arrives. The protocols are fixed at construction
    /// rather than passed per send because a transport is opened for one
    /// `ProbeKind` and carries only that kind's probes. They are a pair because a
    /// kind carrying ICMP carries two different protocol numbers and only the
    /// destination says which. A wrong number here is invisible
    /// locally and fatal remotely: the datagram arrives and is handed to the
    /// wrong protocol handler, so it is simply never answered.
    ///
    /// Returns `None` if the host has no Ethernet-capable interface (only
    /// tunnels or loopback), so the caller can fall back to the raw-IP path
    /// rather than stand up a backend that can never send.
    pub fn from_system(protocols: IpProtocols) -> Option<Self> {
        let resolver = NeighborResolver::from_system();
        if !resolver.has_ethernet() {
            return None;
        }
        Some(Self {
            resolver: Mutex::new(resolver),
            channels: Mutex::new(HashMap::new()),
            unanswered: Mutex::new(UnansweredNeighbors::default()),
            protocols,
        })
    }

    /// Determines the next-hop MAC for `route`, performing (and caching) an
    /// ARP exchange for a next hop whose MAC is not already known: an on-link
    /// target not yet learned, or a gateway the OS gave no hardware address for.
    ///
    /// A next hop that went unanswered on a recent exchange is not asked again
    /// until that record ages out; see [`UnansweredNeighbors`]. Without it every
    /// probe to a dead address pays [`ARP_TIMEOUT`] over, since nothing else
    /// remembers that the last attempt heard nothing.
    fn next_hop_mac(&self, route: &LinkRoute) -> Result<MacAddr, SendError> {
        if let Some(mac) = route.next_hop_mac {
            return Ok(mac);
        }

        let target_v4 = match route.next_hop {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(SendError::Unsupported(
                    "IPv6 next-hop resolution (NDP) is not yet implemented",
                ));
            }
        };
        let src_v4 = match route.src_ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(SendError::Unsupported(
                    "an IPv4 target cannot be reached from an IPv6 source",
                ));
            }
        };

        let mac =
            ask_unless_unanswered(&self.unanswered, &route.interface, route.next_hop, || {
                self.arp_resolve(&route.interface, route.src_mac, src_v4, target_v4)
            })?;
        self.resolver
            .lock()
            .map_err(|_| poisoned("route resolver"))?
            .remember(&route.interface, route.next_hop, mac);
        Ok(mac)
    }

    /// Asks for `target`'s hardware address and waits for the reply, returning
    /// the target's MAC. Runs synchronously against the interface's datalink
    /// channel, bounded by [`ARP_TIMEOUT`], with the requests [`ARP_REQUESTS`]
    /// describes.
    fn arp_resolve(
        &self,
        interface: &str,
        src_mac: MacAddr,
        src_ip: Ipv4Addr,
        target: Ipv4Addr,
    ) -> Result<MacAddr, SendError> {
        let mut channels = self
            .channels
            .lock()
            .map_err(|_| poisoned("datalink channel"))?;
        let channel = self.channel_for(&mut channels, interface)?;

        let request = arp::build_request(src_mac, src_ip, target);
        resolve_over(&mut channel.channel, &request, target)
            .map_err(|reason| SendError::Refused(format!("sending an ARP request: {reason}")))?
            .ok_or_else(|| unanswered_neighbor(IpAddr::V4(target), interface))
    }

    /// Returns the datalink channel for `interface`, opening it on first use.
    fn channel_for<'a>(
        &self,
        channels: &'a mut HashMap<String, InterfaceChannel>,
        interface: &str,
    ) -> Result<&'a mut InterfaceChannel, SendError> {
        if !channels.contains_key(interface) {
            // ARP alone: this channel exists to resolve a next hop, and every
            // other frame on the segment is somebody else's business.
            let channel = capture::FrameChannel::open(interface, "arp", CHANNEL_READ_TIMEOUT)
                .map_err(|error| {
                    SendError::Refused(format!("no datalink channel on {interface}: {error}"))
                })?;
            channels.insert(interface.to_string(), InterfaceChannel { channel });
        }
        Ok(channels.get_mut(interface).unwrap())
    }
}

impl ProbeSender for EthernetSender {
    /// The zone is unused here. A frame this sender builds leaves on the
    /// interface its own route names, and the destination it can reach that way
    /// is IPv4: `next_hop_mac` has no NDP to resolve an IPv6 neighbour with.
    fn send(
        &self,
        segment: &[u8],
        src: IpAddr,
        dst: IpAddr,
        _zone: Option<u32>,
        emission: Emission,
    ) -> Result<(), SendError> {
        // Every step here can fail for a reason outside this process - no route,
        // a neighbour that never answered our ARP, an interface that went down
        // mid-scan - so they are all refusals carrying the cause, not claims
        // that the transport is incapable.
        (|| -> Result<(), SendError> {
            let route = self
                .resolver
                .lock()
                .map_err(|_| poisoned("route resolver"))?
                .resolve_from(src, dst)
                .ok_or_else(|| {
                    SendError::Unroutable(format!("no Ethernet route from {src} to {dst}"))
                })?;

            let dst_mac = self.next_hop_mac(&route)?;
            let src_mac = spoofed_source_mac(route.src_mac, emission.source_mac);
            let protocol = self.protocols.for_destination(dst);

            // One frame, or several if the caller asked to fragment. A packet
            // that already fits the requested MTU comes back as a single frame,
            // so the fragmenting path is not a second code path for the ordinary
            // case.
            let spec = frame::FrameSpec {
                src_mac,
                dst_mac,
                src,
                dst,
                protocol,
                hop_limit: emission.hop_limit,
            };
            // A packet this transport cannot express, as against a network that
            // would not take it: the caller asked for something the framing
            // cannot carry, and asking again changes nothing.
            let frames = match emission.fragment {
                Some(mtu) => frame::build_fragmented_ethernet_frames(&spec, segment, mtu),
                None => frame::build_ethernet_frame(&spec, segment).map(|frame| vec![frame]),
            }
            .map_err(|error| {
                SendError::Refused(format!("the frame could not be built: {error}"))
            })?;

            let mut channels = self
                .channels
                .lock()
                .map_err(|_| poisoned("datalink channel"))?;
            let channel = self.channel_for(&mut channels, &route.interface)?;
            for frame in &frames {
                channel.channel.send_frame(frame).map_err(|reason| {
                    SendError::Refused(format!("the frame could not be sent: {reason}"))
                })?;
            }
            Ok(())
        })()
    }
}

/// A link an address resolution runs over: somewhere to put a request, and
/// the frames that come back.
///
/// The seam between [`resolve_over`] and the capture it runs on, so that the
/// schedule of requests can be shown against a neighbour that answers only
/// some of them, which a real segment offers only by chance.
trait ResolutionLink: FrameSink {
    /// The next frame the link's filter admitted, or `None` once its read
    /// timeout passes with nothing.
    fn next_frame(&mut self) -> Option<&[u8]>;
}

impl ResolutionLink for capture::FrameChannel {
    fn next_frame(&mut self) -> Option<&[u8]> {
        capture::FrameChannel::next_frame(self)
    }
}

/// Runs one address resolution for `target` over `link`: `request` sent as
/// [`ARP_REQUESTS`] schedules it, and the replies read until one answers or
/// [`ARP_TIMEOUT`] passes.
///
/// `Ok(None)` is a neighbour that never answered; an `Err` is a request that
/// could not be sent, which says nothing about the neighbour at all.
fn resolve_over(
    link: &mut impl ResolutionLink,
    request: &[u8],
    target: Ipv4Addr,
) -> Result<Option<MacAddr>, String> {
    let started = Instant::now();
    let spacing = ARP_TIMEOUT / ARP_REQUESTS;
    let mut sent = 0;

    loop {
        let elapsed = started.elapsed();
        if elapsed >= ARP_TIMEOUT {
            return Ok(None);
        }
        // The next request goes out once its share of the wait has begun.
        // Reads end on the channel's own timeout, so a request is at most
        // that late.
        if sent < ARP_REQUESTS && elapsed >= spacing * sent {
            link.send_frame(request)?;
            sent += 1;
        }

        let Some(frame) = link.next_frame() else {
            continue; // read timeout; keep waiting until the deadline
        };
        if let Some(mac) = parse_arp_reply(frame, target) {
            return Ok(Some(mac));
        }
    }
}

/// A poisoned lock, carried as a refusal rather than taken as a panic.
///
/// Reachable only when another thread panicked while holding the lock, which no
/// critical section in this module can do: each is a few statements over data it
/// owns. It is carried anyway because this is a library. `unwrap` here would
/// turn one thread's panic into a permanent failure of the consumer's send path,
/// with every later probe panicking and nothing they could catch, retry, or read
/// a cause from.
fn poisoned(what: &str) -> SendError {
    SendError::Refused(format!(
        "the {what} lock was poisoned by another thread's panic"
    ))
}

/// Runs `exchange`, the address resolution for `next_hop` on `interface`,
/// unless an exchange for it went unanswered within
/// [`NEIGHBOR_UNREACHABLE_TTL`], and records how it went.
///
/// A timeout is remembered, so the probes behind it are turned away at once
/// rather than waiting the same timeout again. An answer clears any record, so
/// a neighbour that has come up is not skipped. A refusal, a channel that would
/// not open, is not a fact about the neighbour and is not remembered as one.
///
/// The record is not held locked while `exchange` waits, since the wait is the
/// whole of what this exists to avoid paying twice.
fn ask_unless_unanswered(
    unanswered: &Mutex<UnansweredNeighbors>,
    interface: &str,
    next_hop: IpAddr,
    exchange: impl FnOnce() -> Result<MacAddr, SendError>,
) -> Result<MacAddr, SendError> {
    let record = || {
        unanswered
            .lock()
            .map_err(|_| poisoned("unanswered neighbours"))
    };

    if record()?.is_fresh(
        interface,
        next_hop,
        Instant::now(),
        NEIGHBOR_UNREACHABLE_TTL,
    ) {
        return Err(unanswered_neighbor(next_hop, interface));
    }
    let outcome = exchange();
    match &outcome {
        Ok(_) => record()?.clear(interface, next_hop),
        Err(SendError::Unresolved(_)) => record()?.note(interface, next_hop, Instant::now()),
        Err(_) => {}
    }
    outcome
}

/// The refusal for a next hop that did not answer its address resolution,
/// whether the exchange just timed out or a recent one already did.
///
/// An [`Unresolved`](SendError::Unresolved) rather than a
/// [`Refused`](SendError::Refused), because
/// it is a fact about that address and not about this sender: the neighbour is
/// not answering, so the address was asked about and not covered. A scan reads
/// it as it reads no route, and it is the class the raw-socket path reports for
/// the same case where the kernel says so, as macOS does with `EHOSTDOWN`, so a
/// dead on-link host reads the same whichever backend a scan uses.
///
/// Not [`Unroutable`](SendError::Unroutable), which a transport holding the raw
/// socket behind this sender reads as a reason to try the socket. This one is
/// the answer, and asking the kernel the same question again is what would turn
/// one dead host into ports that disagree about it.
fn unanswered_neighbor(next_hop: IpAddr, interface: &str) -> SendError {
    SendError::Unresolved(format!(
        "{next_hop} did not answer address resolution on {interface}"
    ))
}

/// The source hardware address a frame should carry: the caller's spoofed one
/// when set, otherwise the sending interface's own.
///
/// The evasion profile speaks [`model::MacAddr`](crate::model::mac::MacAddr) and
/// the frame builder speaks pnet's, so this is the one place they meet.
fn spoofed_source_mac(interface: MacAddr, spoofed: Option<crate::model::mac::MacAddr>) -> MacAddr {
    match spoofed {
        Some(mac) => {
            let octets: [u8; 6] = mac.into();
            MacAddr::new(
                octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
            )
        }
        None => interface,
    }
}

/// Parses an Ethernet frame as an ARP reply from `target`, returning the
/// sender's hardware address if it matches.
fn parse_arp_reply(frame: &[u8], target: Ipv4Addr) -> Option<MacAddr> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() == ArpOperations::Reply && arp.get_sender_proto_addr() == target {
        Some(arp.get_sender_hw_addr())
    } else {
        None
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
    use pnet_packet::ethernet::MutableEthernetPacket;

    /// Builds an Ethernet-framed ARP reply from `sender_ip`/`sender_mac`.
    fn arp_reply(sender_ip: Ipv4Addr, sender_mac: MacAddr) -> Vec<u8> {
        let mut buf = vec![0u8; 42];
        {
            let mut eth = MutableEthernetPacket::new(&mut buf[..14]).unwrap();
            eth.set_ethertype(EtherTypes::Arp);
            eth.set_source(sender_mac);
            eth.set_destination(MacAddr::broadcast());
        }
        {
            let mut a = MutableArpPacket::new(&mut buf[14..]).unwrap();
            a.set_hardware_type(ArpHardwareTypes::Ethernet);
            a.set_protocol_type(EtherTypes::Ipv4);
            a.set_hw_addr_len(6);
            a.set_proto_addr_len(4);
            a.set_operation(ArpOperations::Reply);
            a.set_sender_hw_addr(sender_mac);
            a.set_sender_proto_addr(sender_ip);
            a.set_target_proto_addr(Ipv4Addr::new(192, 0, 2, 50));
        }
        buf
    }

    /// A neighbour on a segment that loses frames: it answers the request
    /// numbered `answers` and none before it, as it would if the earlier ones
    /// or their replies were dropped, and waits out each read the way a quiet
    /// capture does.
    struct LossyNeighbour {
        reply: Vec<u8>,
        answers: u32,
        requests: u32,
        replied: bool,
    }

    impl LossyNeighbour {
        fn answering(answers: u32, ip: Ipv4Addr, mac: MacAddr) -> Self {
            Self {
                reply: arp_reply(ip, mac),
                answers,
                requests: 0,
                replied: false,
            }
        }
    }

    impl FrameSink for LossyNeighbour {
        fn send_frame(&mut self, _frame: &[u8]) -> Result<(), String> {
            self.requests += 1;
            Ok(())
        }
    }

    impl ResolutionLink for LossyNeighbour {
        fn next_frame(&mut self) -> Option<&[u8]> {
            if self.requests >= self.answers && !self.replied {
                self.replied = true;
                return Some(&self.reply);
            }
            std::thread::sleep(CHANNEL_READ_TIMEOUT / 10);
            None
        }
    }

    /// A neighbour whose first request was lost is still resolved, by the next.
    ///
    /// One request per resolution made a single dropped broadcast final: the
    /// neighbour read as unanswered, and the memory of that turned a live
    /// host's every port away for the next half-minute.
    #[test]
    fn a_neighbour_answering_only_a_later_request_is_resolved() {
        let ip = Ipv4Addr::new(192, 0, 2, 200);
        let mac = MacAddr::new(0x02, 0, 0, 0, 0, 0xc8);

        // At least the second, so a schedule of one request cannot pass by
        // having no later request to test.
        for answers in 2..=ARP_REQUESTS.max(2) {
            let mut neighbour = LossyNeighbour::answering(answers, ip, mac);
            let resolved = resolve_over(&mut neighbour, b"request", ip);

            assert_eq!(resolved, Ok(Some(mac)), "answering request {answers}");
            assert_eq!(neighbour.requests, answers, "and asked no further");
        }
    }

    /// A neighbour that never answers is asked every scheduled time, and given
    /// up after the one timeout the requests share.
    #[test]
    fn a_neighbour_that_never_answers_costs_one_timeout_across_every_request() {
        let ip = Ipv4Addr::new(192, 0, 2, 200);
        let mut neighbour =
            LossyNeighbour::answering(u32::MAX, ip, MacAddr::new(0x02, 0, 0, 0, 0, 1));

        let started = Instant::now();
        assert_eq!(resolve_over(&mut neighbour, b"request", ip), Ok(None));
        let waited = started.elapsed();

        assert_eq!(neighbour.requests, ARP_REQUESTS);
        assert!(
            waited >= ARP_TIMEOUT && waited < ARP_TIMEOUT + CHANNEL_READ_TIMEOUT * 2,
            "a dead neighbour cost {waited:?}"
        );
    }

    #[test]
    fn parses_matching_arp_reply() {
        let ip = Ipv4Addr::new(192, 0, 2, 200);
        let mac = MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        assert_eq!(parse_arp_reply(&arp_reply(ip, mac), ip), Some(mac));
    }

    #[test]
    fn a_spoofed_source_mac_replaces_the_interface_and_converts_faithfully() {
        let interface = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

        // No spoof: the interface's own address is used.
        assert_eq!(spoofed_source_mac(interface, None), interface);

        // Spoofed: the caller's address is used, octet for octet across the
        // model/pnet boundary. A mutant that dropped the octets or kept the
        // interface's address would send an unspoofed frame while the scan
        // reported a spoof.
        let spoofed = crate::model::mac::MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        assert_eq!(
            spoofed_source_mac(interface, Some(spoofed)),
            MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01)
        );
    }

    #[test]
    fn ignores_arp_reply_from_other_ip() {
        let mac = MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        let reply = arp_reply(Ipv4Addr::new(192, 0, 2, 201), mac);
        assert_eq!(parse_arp_reply(&reply, Ipv4Addr::new(192, 0, 2, 200)), None);
    }

    #[test]
    fn ignores_non_arp_frame() {
        let mut buf = vec![0u8; 42];
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_ethertype(EtherTypes::Ipv4);
        assert_eq!(parse_arp_reply(&buf, Ipv4Addr::new(192, 0, 2, 200)), None);
    }

    const DEAD: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));

    /// A neighbour that never answers is asked once, not on every probe behind
    /// the first.
    ///
    /// The record of the failed exchange stands while it is fresh, so the sender
    /// turns away every later probe to that address at once rather than waiting
    /// the whole [`ARP_TIMEOUT`] again. This is the difference between a dead
    /// address costing one timeout and its costing one per port per attempt.
    #[test]
    fn a_neighbour_that_never_answers_is_asked_once() {
        let mut unanswered = UnansweredNeighbors::default();
        let t0 = Instant::now();
        let ttl = NEIGHBOR_UNREACHABLE_TTL;

        // Nothing is skipped until a failure is on record.
        assert!(!unanswered.is_fresh("en0", DEAD, t0, ttl));

        unanswered.note("en0", DEAD, t0);
        // The probe right behind the timeout, and the next, are turned away.
        assert!(unanswered.is_fresh("en0", DEAD, t0, ttl));
        assert!(unanswered.is_fresh("en0", DEAD, t0 + Duration::from_secs(1), ttl));
    }

    /// The record is a next hop's, on its own interface: another address, and
    /// the same address on another link, are unaffected.
    #[test]
    fn a_failure_is_remembered_per_next_hop_and_interface() {
        let mut unanswered = UnansweredNeighbors::default();
        let t0 = Instant::now();
        let ttl = NEIGHBOR_UNREACHABLE_TTL;
        let other: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 201));

        unanswered.note("en0", DEAD, t0);
        assert!(
            !unanswered.is_fresh("en0", other, t0, ttl),
            "a different next hop"
        );
        assert!(
            !unanswered.is_fresh("en1", DEAD, t0, ttl),
            "the same next hop, another link"
        );
    }

    /// The record ages out, so a host that was down when first probed and has
    /// since come up is resolved again on a later sweep rather than shadowed for
    /// the sender's whole life.
    #[test]
    fn an_aged_out_failure_is_asked_again() {
        let mut unanswered = UnansweredNeighbors::default();
        let t0 = Instant::now();
        let ttl = NEIGHBOR_UNREACHABLE_TTL;

        unanswered.note("en0", DEAD, t0);
        assert!(
            !unanswered.is_fresh("en0", DEAD, t0 + ttl, ttl),
            "at the horizon"
        );
        assert!(
            !unanswered.is_fresh("en0", DEAD, t0 + ttl + Duration::from_secs(1), ttl),
            "past it"
        );
    }

    /// The sender's own path, not only the record: a dead neighbour's exchange
    /// runs once, and every later probe inside the window is refused without
    /// running it, with the same error the timeout gave.
    #[test]
    fn a_dead_neighbour_is_resolved_once_and_refused_after() {
        let unanswered = Mutex::new(UnansweredNeighbors::default());
        let exchanges = std::cell::Cell::new(0);
        let timing_out = || {
            exchanges.set(exchanges.get() + 1);
            Err(unanswered_neighbor(DEAD, "en0"))
        };

        for _ in 0..5 {
            assert!(matches!(
                ask_unless_unanswered(&unanswered, "en0", DEAD, timing_out),
                Err(SendError::Unresolved(_))
            ));
        }
        assert_eq!(exchanges.get(), 1, "one exchange for five probes");
    }

    /// Only a timeout is a fact about the neighbour. A channel that would not
    /// open says nothing about it, so the next probe asks again; and an answer
    /// clears an earlier timeout.
    #[test]
    fn only_an_unanswered_exchange_is_remembered() {
        let unanswered = Mutex::new(UnansweredNeighbors::default());
        let mac = MacAddr::new(0x02, 0, 0, 0, 0, 0x20);
        let exchanges = std::cell::Cell::new(0);
        let count = |result: Result<MacAddr, SendError>| {
            exchanges.set(exchanges.get() + 1);
            result
        };

        let refused = || count(Err(SendError::Refused("no channel".into())));
        assert!(ask_unless_unanswered(&unanswered, "en0", DEAD, refused).is_err());
        assert!(ask_unless_unanswered(&unanswered, "en0", DEAD, refused).is_err());
        assert_eq!(exchanges.get(), 2, "a refusal is asked again");

        // A timeout that has aged out is asked again, and this time answered.
        let expired = Instant::now()
            .checked_sub(NEIGHBOR_UNREACHABLE_TTL + Duration::from_secs(1))
            .expect("a monotonic clock that has run past the window");
        unanswered.lock().unwrap().note("en0", DEAD, expired);
        let answering = || count(Ok(mac));
        assert_eq!(
            ask_unless_unanswered(&unanswered, "en0", DEAD, answering).ok(),
            Some(mac)
        );
        assert!(
            unanswered.lock().unwrap().seen.is_empty(),
            "an answer leaves no record behind"
        );
    }

    /// A neighbour that answers after an earlier timeout is no longer skipped:
    /// its record is cleared, so the learned MAC governs from then on.
    #[test]
    fn a_neighbour_that_answers_is_no_longer_skipped() {
        let mut unanswered = UnansweredNeighbors::default();
        let t0 = Instant::now();
        let ttl = NEIGHBOR_UNREACHABLE_TTL;

        unanswered.note("en0", DEAD, t0);
        assert!(unanswered.is_fresh("en0", DEAD, t0, ttl));

        unanswered.clear("en0", DEAD);
        assert!(!unanswered.is_fresh("en0", DEAD, t0, ttl));
    }
}
