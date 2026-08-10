// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A simulated local segment for [`LocalScanner`], the link-layer companion to
//! [`fake_net`](super::fake_net).
//!
//! Local discovery works one layer below everything else in the engine. It does
//! not send segments and read replies, it builds whole Ethernet frames, puts
//! them on an interface, and identifies a neighbour by the source MAC of what
//! comes back. That is why it holds an
//! [`EthernetHandle`](zond_engine::network::channel::EthernetHandle) rather than
//! a probe transport, and why it needs a simulator of its own: a capture-fed
//! transport has already discarded the MAC address by the time a scanner sees
//! the bytes.
//!
//! [`FakeLan`] plugs into `EthernetHandle::from_parts`. It reads the frames the
//! scanner emits, answers ARP requests and the ICMPv6 all-nodes solicitation on
//! behalf of whichever hosts the test declared, and pushes the replies back as
//! though they had been captured off the interface. Nothing is bound, nothing is
//! opened, and no privileges are involved.
//!
//! Loss, delay and seeding work exactly as they do in
//! [`fake_net`](super::fake_net), whose [`Loss`] and generator this module
//! reuses so that both tiers reproduce from a seed the same way.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pnet::datalink::{DataLinkSender, MacAddr, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::icmpv6::echo_reply::{Icmpv6Codes, MutableEchoReplyPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use tokio::sync::mpsc::{self, UnboundedSender};

use zond_engine::network::channel::EthernetHandle;
use zond_engine::protocols::{ethernet, ip};

use super::fake_net::{Loss, SplitMix64};

/// An ARP payload is 28 bytes for IPv4 over Ethernet, and an Ethernet frame is
/// padded out to 60 bytes before the frame check sequence. Real ARP is always
/// padded, so the simulated replies are too.
const ARP_LEN: usize = 28;
const MIN_ETH_FRAME: usize = 60;

/// An ICMPv6 echo header: type, code, checksum, identifier, sequence number.
const ICMPV6_ECHO_LEN: usize = 8;

/// The default seed, so a segment built with [`FakeLan::new`] still reproduces.
const DEFAULT_SEED: u64 = 0x1A9E_5EED_1A9E_5EED;

/// A host sitting on the simulated segment.
///
/// A host answers whatever probe suits the address it is declared under: an ARP
/// request if that address is IPv4, the all-nodes solicitation if it is IPv6.
/// Addresses with no host declared simply never answer, which is what an empty
/// stretch of a real segment does.
#[derive(Debug, Clone, Copy)]
pub struct LanHost {
    mac: MacAddr,
    loss: Loss,
    delay: Duration,
}

impl LanHost {
    /// A host that answers immediately from `mac`.
    pub fn at(mac: MacAddr) -> Self {
        Self {
            mac,
            loss: Loss::None,
            delay: Duration::ZERO,
        }
    }

    /// Swallows the first `n` probes to this host. On a real segment ARP is
    /// lossy far more often than people expect, and a discovery sweep that never
    /// retries simply reports the host as absent.
    pub fn drop_first(mut self, n: u32) -> Self {
        self.loss = Loss::First(n);
        self
    }

    /// Swallows each probe to this host with probability `p`.
    ///
    /// Panics unless `p` is a probability, so a test cannot quietly claim to
    /// cover a loss level it never applied.
    pub fn loss_rate(mut self, p: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&p),
            "loss rate must be a probability, got {p}"
        );
        self.loss = Loss::Rate(p);
        self
    }

    /// Holds this host's reply back for `delay`.
    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

/// One probe the segment saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanProbe {
    /// An ARP request for one address. Seeing more than one for the same
    /// address means the scanner retried.
    Arp {
        target: Ipv4Addr,
        at: Instant,
        /// True when no reply was produced, whether because the link swallowed
        /// the request or because no host was declared at that address. The two
        /// are deliberately not distinguished: they are indistinguishable to the
        /// scanner too, which is the property being tested.
        dropped: bool,
    },
    /// An ICMPv6 all-nodes solicitation. Put to the whole segment rather than
    /// to one address, so it is logged on its own terms: seeing several is a
    /// sweep repeating the question, not a sweep retrying a target.
    Solicitation { at: Instant },
}

/// A simulated Ethernet segment a [`LocalScanner`] can be pointed at.
///
/// Declare the hosts, hand the scanner a [`handle`](Self::handle), run it, then
/// assert on the discovered hosts and on the [`probes`](Self::probes) the
/// segment saw.
pub struct FakeLan {
    hosts: HashMap<IpAddr, LanHost>,
    seed: u64,
    state: Arc<Mutex<State>>,
}

/// The segment's mutable half.
struct State {
    rng: SplitMix64,
    /// Probes seen per address, which is what [`Loss::First`] counts against.
    attempts: HashMap<IpAddr, u32>,
    log: Vec<LanProbe>,
}

impl FakeLan {
    /// An empty segment, seeded reproducibly.
    pub fn new() -> Self {
        Self::seeded(DEFAULT_SEED)
    }

    /// [`new`](Self::new) with an explicit seed for the probabilistic policies.
    pub fn seeded(seed: u64) -> Self {
        Self {
            hosts: HashMap::new(),
            seed,
            state: Arc::new(Mutex::new(State {
                rng: SplitMix64::new(seed),
                attempts: HashMap::new(),
                log: Vec::new(),
            })),
        }
    }

    /// Puts `host` on the segment at `ip`.
    pub fn host(mut self, ip: IpAddr, host: LanHost) -> Self {
        self.hosts.insert(ip, host);
        self
    }

    /// The seed this segment's probabilistic policies draw from. Print it from
    /// a failing test so the run can be reproduced.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// An Ethernet handle carrying this segment, ready to hand to
    /// [`LocalScanner::with_handle`].
    pub fn handle(&self) -> EthernetHandle {
        let (frames, rx) = mpsc::unbounded_channel();
        let link = FakeSegment {
            hosts: self.hosts.clone(),
            state: Arc::clone(&self.state),
            frames,
        };
        EthernetHandle::from_parts(Box::new(link), rx)
    }

    /// Every probe this segment received, in arrival order.
    pub fn probes(&self) -> Vec<LanProbe> {
        self.state.lock().expect("fake lan state").log.clone()
    }

    /// How many ARP requests reached the segment for `ip`, answered or dropped.
    /// Greater than one means the scanner retried.
    pub fn arp_count(&self, ip: Ipv4Addr) -> usize {
        self.state
            .lock()
            .expect("fake lan state")
            .log
            .iter()
            .filter(|p| matches!(p, LanProbe::Arp { target, .. } if *target == ip))
            .count()
    }
}

impl Default for FakeLan {
    fn default() -> Self {
        Self::new()
    }
}

/// The send half of a [`FakeLan`]: the scanner's view of the wire.
struct FakeSegment {
    hosts: HashMap<IpAddr, LanHost>,
    state: Arc<Mutex<State>>,
    frames: UnboundedSender<Vec<u8>>,
}

impl DataLinkSender for FakeSegment {
    /// Carries one frame onto the simulated segment.
    ///
    /// Always reports success. A frame that no host answers is indistinguishable
    /// from one that was lost, which is the whole point: reporting a send error
    /// would hand the scanner a signal a real segment never gives it.
    fn send_to(
        &mut self,
        packet: &[u8],
        _dst: Option<NetworkInterface>,
    ) -> Option<std::io::Result<()>> {
        let Some(frame) = EthernetPacket::new(packet) else {
            return Some(Ok(()));
        };

        match frame.get_ethertype() {
            EtherTypes::Arp => self.answer_arp(&frame),
            EtherTypes::Ipv6 => self.answer_solicitation(&frame),
            // Nothing else is a discovery probe, so nothing else is answered.
            _ => {}
        }

        Some(Ok(()))
    }

    /// Builds `num_packets` frames in place and sends each one.
    ///
    /// `LocalScanner` does not use this path, but the trait requires it and a
    /// silent no-op would turn a future caller's probes into an unexplained
    /// silence. Routing it through [`send_to`](Self::send_to) keeps one
    /// behaviour for both.
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<std::io::Result<()>> {
        for _ in 0..num_packets {
            let mut buffer = vec![0u8; packet_size];
            func(&mut buffer);
            self.send_to(&buffer, None)?.ok()?;
        }
        Some(Ok(()))
    }
}

impl FakeSegment {
    /// Answers an ARP request, if the address it asks about has a host on it.
    fn answer_arp(&mut self, frame: &EthernetPacket) {
        let Some(request) = ArpPacket::new(frame.payload()) else {
            return;
        };

        let target = request.get_target_proto_addr();
        let at = Instant::now();
        let host = self.hosts.get(&IpAddr::V4(target)).copied();

        // An address with no host still gets logged. A test asserting on retry
        // counts cares just as much about probes that went unanswered.
        let dropped = match host {
            Some(host) => self.admit(IpAddr::V4(target), host.loss),
            None => true,
        };
        self.log(LanProbe::Arp {
            target,
            at,
            dropped,
        });

        let Some(host) = host.filter(|_| !dropped) else {
            return;
        };

        let scanner_mac = request.get_sender_hw_addr();
        let scanner_ip = request.get_sender_proto_addr();
        if let Some(reply) = arp_reply(host.mac, target, scanner_mac, scanner_ip) {
            self.deliver(reply, host.delay);
        }
    }

    /// Answers the ICMPv6 all-nodes solicitation on behalf of every IPv6 host
    /// declared on the segment.
    ///
    /// Unlike ARP this probe is not sent per target: one multicast goes out and
    /// any neighbour may answer, so every declared IPv6 host gets the chance to.
    fn answer_solicitation(&mut self, frame: &EthernetPacket) {
        let Ok(scanner_ip) = ip::get_ipv6_src_addr_from_eth(frame) else {
            return;
        };
        let scanner_mac = frame.get_source();
        self.log(LanProbe::Solicitation { at: Instant::now() });

        let v6_hosts: Vec<(Ipv6Addr, LanHost)> = self
            .hosts
            .iter()
            .filter_map(|(ip, host)| match ip {
                IpAddr::V6(v6) => Some((*v6, *host)),
                IpAddr::V4(_) => None,
            })
            .collect();

        for (host_ip, host) in v6_hosts {
            if self.admit(IpAddr::V6(host_ip), host.loss) {
                continue;
            }
            if let Some(reply) = icmpv6_echo_reply(host.mac, host_ip, scanner_mac, scanner_ip) {
                self.deliver(reply, host.delay);
            }
        }
    }

    /// Counts one probe against `ip` and decides whether the segment swallowed
    /// it, returning true if it did.
    fn admit(&self, ip: IpAddr, loss: Loss) -> bool {
        let mut state = self.state.lock().expect("fake lan state");

        let attempts = state.attempts.entry(ip).or_insert(0);
        *attempts += 1;
        let attempt = *attempts;

        match loss {
            Loss::None => false,
            Loss::First(n) => attempt <= n,
            Loss::Rate(p) => state.rng.next_unit() < p,
        }
    }

    fn log(&self, probe: LanProbe) {
        self.state.lock().expect("fake lan state").log.push(probe);
    }

    /// Hands a reply frame back to the scanner, honouring the host's delay.
    ///
    /// A delayed reply is spawned rather than awaited, because this is called
    /// synchronously from inside the scanner's own send loop and blocking here
    /// would stall the loop the delay is meant to race against.
    fn deliver(&self, frame: Vec<u8>, delay: Duration) {
        if delay.is_zero() {
            let _ = self.frames.send(frame);
            return;
        }

        let frames = self.frames.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            // The receiver is gone once the sweep ends, which is the normal way
            // a reply that arrived too late is discarded.
            let _ = frames.send(frame);
        });
    }
}

/// An ARP reply frame from `host_mac`/`host_ip` back to the scanner.
fn arp_reply(
    host_mac: MacAddr,
    host_ip: Ipv4Addr,
    scanner_mac: MacAddr,
    scanner_ip: Ipv4Addr,
) -> Option<Vec<u8>> {
    let header = ethernet::make_header(host_mac, scanner_mac, EtherTypes::Arp).ok()?;

    let mut payload = [0u8; ARP_LEN];
    {
        let mut arp = MutableArpPacket::new(&mut payload)?;
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Reply);
        arp.set_sender_hw_addr(host_mac);
        arp.set_sender_proto_addr(host_ip);
        arp.set_target_hw_addr(scanner_mac);
        arp.set_target_proto_addr(scanner_ip);
    }

    let mut frame = Vec::with_capacity(MIN_ETH_FRAME);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&payload);
    frame.resize(MIN_ETH_FRAME, 0);
    Some(frame)
}

/// An ICMPv6 echo reply from `host_mac`/`host_ip` to the scanner's link-local
/// address: what a neighbour actually sends back when it answers the all-nodes
/// echo request.
///
/// The body is built rather than omitted, and that is the whole point of this
/// function. A frame carrying only an IPv6 header with nothing after it is not
/// an echo reply, not a neighbor advertisement, and not any message a neighbour
/// would ever emit - so a simulation that sent one could only ever be answered
/// by a scanner that had stopped reading at the IP header. The engine did, this
/// fake did, and between them they agreed on a reply neither had inspected.
fn icmpv6_echo_reply(
    host_mac: MacAddr,
    host_ip: Ipv6Addr,
    scanner_mac: MacAddr,
    scanner_ip: Ipv6Addr,
) -> Option<Vec<u8>> {
    let mut body = vec![0u8; ICMPV6_ECHO_LEN];
    {
        let mut echo = MutableEchoReplyPacket::new(&mut body)?;
        echo.set_icmpv6_type(Icmpv6Types::EchoReply);
        echo.set_icmpv6_code(Icmpv6Codes::NoCode);
        echo.set_identifier(0);
        echo.set_sequence_number(0);
    }

    let header = ethernet::make_header(host_mac, scanner_mac, EtherTypes::Ipv6).ok()?;
    let ipv6 = ip::create_ipv6_header(
        host_ip,
        scanner_ip,
        body.len() as u16,
        IpNextHeaderProtocols::Icmpv6,
        ip::HOP_LIMIT_ON_LINK,
    )
    .ok()?;

    let mut frame = Vec::with_capacity(MIN_ETH_FRAME);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&ipv6);
    frame.extend_from_slice(&body);
    frame.resize(MIN_ETH_FRAME, 0);
    Some(frame)
}
