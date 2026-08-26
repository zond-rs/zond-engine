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
//! [`EthernetHandle`](zond_engine::transport::channel::EthernetHandle) rather than
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
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::icmpv6::echo_reply::{Icmpv6Codes, MutableEchoReplyPacket};
use pnet::packet::icmpv6::ndp::{MutableNeighborAdvertPacket, NeighborSolicitPacket};
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::{MutableUdpPacket, ipv6_checksum as udp_ipv6_checksum};
use tokio::sync::mpsc::{self, Sender};

use zond_engine::model::ip::scoped::Zone;
use zond_engine::protocols::ethernet::Frame;
use zond_engine::protocols::{craft, ethernet, ip};
use zond_engine::transport::capture::CapturedFrame;
use zond_engine::transport::channel::EthernetHandle;
use zond_engine::transport::frame::LinkType;

use std::time::SystemTime;

use super::fake_net::{Loss, SplitMix64};

/// An ARP payload is 28 bytes for IPv4 over Ethernet, and an Ethernet frame is
/// padded out to 60 bytes before the frame check sequence. Real ARP is always
/// padded, so the simulated replies are too.
const ARP_LEN: usize = 28;
const MIN_ETH_FRAME: usize = 60;

/// How many frames this segment may hold for a scanner that has not read them
/// yet.
///
/// The real capture bounds its queue and stalls its reader thread when the
/// consumer falls behind; a simulated segment has no reader thread to stall, so
/// it drops instead. Sized well above any fixture — a `/24` where every host
/// answers is a few hundred frames — so that hitting it means a test built more
/// traffic than a segment holds rather than that the scanner was briefly busy.
const FAKE_QUEUE_DEPTH: usize = 4096;

/// The link this segment presents itself as, matching the interface
/// [`super::scanner_interface`] gives the scanner.
///
/// They have to agree: a frame is stamped with the link it came off, and a
/// fixture whose frames name a different one from the scanner's own interface
/// would be simulating two segments.
fn simulated_zone() -> Zone {
    let intf = super::scanner_interface();
    Zone::new(intf.index, intf.name)
}

/// Source port, destination port, length, checksum.
const UDP_HDR_LEN: usize = 8;

/// The port multicast DNS is spoken on.
const MDNS_PORT: u16 = 5353;

/// Where a DHCP server listens, and where its answer is addressed back to.
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

/// Pads `frame` out to the minimum Ethernet payload, leaving anything already
/// longer alone.
///
/// `Vec::resize` is the obvious call here and it is wrong in one direction: it
/// sets the length rather than raising it, so a frame longer than the minimum is
/// *truncated*. An ARP reply is 42 bytes and gets padded, which is why that went
/// unnoticed; a neighbor advertisement is 78 and was being cut to 60, leaving
/// six bytes where a 24-byte message should be. The scanner then read it as no
/// advertisement at all — a reply the simulated host had sent and the simulated
/// wire destroyed.
fn pad_to_min_frame(frame: &mut Vec<u8>) {
    if frame.len() < MIN_ETH_FRAME {
        frame.resize(MIN_ETH_FRAME, 0);
    }
}

/// An ICMPv6 echo header: type, code, checksum, identifier, sequence number.
const ICMPV6_ECHO_LEN: usize = 8;

/// A neighbor advertisement without options: type, code, checksum, flags and
/// reserved, then the 16-byte target address.
const NDP_ADVERT_LEN: usize = 24;

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
    /// How long before answering the all-nodes echo, when that differs from
    /// [`delay`](Self::delay). See [`echo_delay`](Self::echo_delay).
    echo_delay: Option<Duration>,
    answers_from: Option<Ipv6Addr>,
}

impl LanHost {
    /// A host that answers immediately from `mac`.
    pub fn at(mac: MacAddr) -> Self {
        Self {
            mac,
            loss: Loss::None,
            delay: Duration::ZERO,
            echo_delay: None,
            answers_from: None,
        }
    }

    /// Answers a neighbor solicitation from `address` rather than from the one
    /// that was asked about.
    ///
    /// Not perverse: a host with several IPv6 addresses answers from whichever
    /// its stack prefers, and on a real segment a phone solicited at
    /// `2a02:…::21e9` answered from `2a02:…:14f0:ca99:5818:74ee`. The
    /// advertisement still names the address it is about in its target field,
    /// which is the only thing tying the reply to the question.
    pub fn answering_from(mut self, address: Ipv6Addr) -> Self {
        self.answers_from = Some(address);
        self
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

    /// Waits `delay` before answering the all-nodes echo specifically, however
    /// fast this host answers a question addressed to it.
    ///
    /// The difference is real and it is large. A node answering a probe put to
    /// the whole segment holds its reply back so the segment does not answer at
    /// once, and a device asleep on wifi answers when it next wakes — an order
    /// of magnitude slower than the same device answers a question addressed to
    /// it alone. A fake with one delay for both cannot express that host, and it
    /// is the one the ranking in `HostTelemetry` exists for.
    pub fn echo_delay(mut self, delay: Duration) -> Self {
        self.echo_delay = Some(delay);
        self
    }

    /// How long this host waits before answering the all-nodes echo.
    fn echo_wait(&self) -> Duration {
        self.echo_delay.unwrap_or(self.delay)
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
    /// A neighbor solicitation for one address. The IPv6 counterpart of
    /// [`LanProbe::Arp`], and counted the same way: more than one for an address
    /// means the scanner retried.
    Solicit { target: Ipv6Addr, at: Instant },
    /// A router solicitation, put to every router on the segment at once.
    RouterSolicit { at: Instant },
    /// A `DHCPINFORM`, broadcast at the segment.
    DhcpInform { at: Instant },
}

/// A simulated Ethernet segment a [`LocalScanner`] can be pointed at.
///
/// Declare the hosts, hand the scanner a [`handle`](Self::handle), run it, then
/// assert on the discovered hosts and on the [`probes`](Self::probes) the
/// segment saw.
pub struct FakeLan {
    hosts: HashMap<IpAddr, LanHost>,
    /// Addresses that advertise themselves without being asked.
    ///
    /// A real segment is full of this — neighbours resolving each other,
    /// announcing a new address, answering somebody else's solicitation — and a
    /// promiscuous capture sees all of it. Without a way to express it here the
    /// harness could only produce neighbours that answer our own probes, which
    /// is the minority of what a real sweep actually finds.
    unsolicited: Vec<Ipv6Addr>,
    /// Names announced over mDNS, as `(hostname, address, announcer)`. A real
    /// segment shouts these constantly, and they name addresses no probe of
    /// ours has ever been answered for.
    announcements: Vec<(String, Ipv6Addr, MacAddr)>,
    /// The segment's DHCP server, which answers an inform and nothing else.
    dhcp: Option<Server>,
    /// The segment's IPv6 router, which answers a router solicitation.
    router: Option<Router>,
    /// The switch this segment is wired through, which announces itself
    /// unprompted the way a managed one does.
    switch: Option<Switch>,
    seed: u64,
    state: Arc<Mutex<State>>,
}

/// A DHCP server on the segment.
#[derive(Debug, Clone, Copy)]
struct Server {
    mac: MacAddr,
    /// The address the reply comes *from*.
    address: Ipv4Addr,
    /// The address it names as the server in the message (option 54), which is
    /// a different machine wherever a relay agent is forwarding.
    identifier: Ipv4Addr,
}

/// An IPv6 router on the segment.
#[derive(Debug, Clone, Copy)]
struct Router {
    mac: MacAddr,
    address: Ipv6Addr,
}

/// The switch the scanner is plugged into.
///
/// It answers nothing. A managed switch announces itself on its own timer,
/// which is what makes the finding unlike everything else on this segment: no
/// probe draws it, and the fixture emits it the moment the scanner puts
/// anything on the wire.
#[derive(Debug, Clone, Copy)]
struct Switch {
    mac: MacAddr,
    /// What the switch calls itself.
    name: &'static str,
    /// What it calls the port the scanner is plugged into.
    port: &'static str,
    /// The VLAN untagged traffic on that port lands in.
    native_vlan: u16,
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
            unsolicited: Vec::new(),
            announcements: Vec::new(),
            dhcp: None,
            router: None,
            switch: None,
            seed,
            state: Arc::new(Mutex::new(State {
                rng: SplitMix64::new(seed),
                attempts: HashMap::new(),
                log: Vec::new(),
            })),
        }
    }

    /// Puts `host` on the segment at `ip`.
    /// Puts a DHCP server at `address`, answering informs as itself.
    pub fn serving_dhcp(self, address: Ipv4Addr, mac: MacAddr) -> Self {
        self.serving_dhcp_as(address, address, mac)
    }

    /// The same, answering *from* `address` while naming `identifier` as the
    /// server — which is what a relay agent forwarding for a server on another
    /// segment produces.
    pub fn serving_dhcp_as(
        mut self,
        address: Ipv4Addr,
        identifier: Ipv4Addr,
        mac: MacAddr,
    ) -> Self {
        self.dhcp = Some(Server {
            mac,
            address,
            identifier,
        });
        self
    }

    /// Puts an IPv6 router at `address`, answering router solicitations.
    pub fn routing(mut self, address: Ipv6Addr, mac: MacAddr) -> Self {
        self.router = Some(Router { mac, address });
        self
    }

    /// Puts `host` on the segment at `ip`.
    /// Wires this segment through a managed switch that announces itself over
    /// LLDP, naming itself, the port the scanner is on, and that port's VLAN.
    pub fn wired_through(
        mut self,
        mac: MacAddr,
        name: &'static str,
        port: &'static str,
        native_vlan: u16,
    ) -> Self {
        self.switch = Some(Switch {
            mac,
            name,
            port,
            native_vlan,
        });
        self
    }

    pub fn host(mut self, ip: IpAddr, host: LanHost) -> Self {
        self.hosts.insert(ip, host);
        self
    }

    /// Makes `address` advertise itself once, unprompted, as soon as the
    /// scanner puts anything on the wire.
    pub fn advertising_unsolicited(mut self, address: IpAddr) -> Self {
        if let IpAddr::V6(v6) = address {
            self.unsolicited.push(v6);
        }
        self
    }

    /// Makes `announcer` shout `hostname` and `address` over mDNS once, as soon
    /// as the scanner puts anything on the wire.
    ///
    /// The address need not belong to the announcer and need not be a declared
    /// host: that is the case worth covering, since a responder answers with
    /// whatever else it knows and the record is a claim rather than a reply.
    pub fn announcing_over_mdns(
        mut self,
        hostname: &str,
        address: Ipv6Addr,
        announcer: MacAddr,
    ) -> Self {
        self.announcements
            .push((hostname.to_string(), address, announcer));
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
        let (frames, rx) = mpsc::channel(FAKE_QUEUE_DEPTH);
        let link = FakeSegment {
            hosts: self.hosts.clone(),
            unsolicited: self.unsolicited.clone(),
            announcements: self.announcements.clone(),
            dhcp: self.dhcp,
            router: self.router,
            switch: self.switch,
            state: Arc::clone(&self.state),
            frames,
            zone: simulated_zone(),
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
    dhcp: Option<Server>,
    router: Option<Router>,
    switch: Option<Switch>,
    /// Addresses that advertise themselves once, unprompted, the first time the
    /// scanner sends anything.
    unsolicited: Vec<Ipv6Addr>,
    /// Names announced over mDNS, as `(hostname, address, announcer)`.
    announcements: Vec<(String, Ipv6Addr, MacAddr)>,
    state: Arc<Mutex<State>>,
    frames: Sender<CapturedFrame>,
    /// The link every frame this segment delivers is stamped with, matching
    /// the interface [`super::scanner_interface`] hands the scanner.
    zone: Zone,
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
        let Ok(frame) = ethernet::parse(packet) else {
            return Some(Ok(()));
        };

        self.emit_unsolicited(&frame);
        self.emit_announcements(&frame);
        self.emit_switch_announcement();

        match frame.ethertype() {
            EtherTypes::Arp => self.answer_arp(&frame),
            EtherTypes::Ipv4 => self.answer_dhcp(&frame),
            // The two IPv6 probes are told apart by their ICMPv6 type, not by
            // the frame: one asks the whole segment, the other asks about one
            // address, and answering them identically is what let the engine
            // credit an echo reply to neighbour discovery for as long as it did.
            EtherTypes::Ipv6 => match ip::icmpv6_type(&frame) {
                Some(Icmpv6Types::NeighborSolicit) => self.answer_neighbor_solicit(&frame),
                Some(Icmpv6Types::EchoRequest) => self.answer_all_nodes_echo(&frame),
                Some(Icmpv6Types::RouterSolicit) => self.answer_router_solicit(&frame),
                _ => {}
            },
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
    /// Answers a `DHCPINFORM` on behalf of the segment's server, if one was
    /// declared and the frame is one.
    ///
    /// Every other IPv4 frame reaching here is left alone: this segment carries
    /// whatever the scanner puts on it, and only DHCP has an answer.
    fn answer_dhcp(&mut self, frame: &Frame<'_>) {
        let Some(message) = dhcp_message(frame) else {
            return;
        };
        // The message type option, which is what tells an inform from the
        // discovers and requests a real segment is full of.
        if message.first() != Some(&1) || !message.windows(3).any(|w| w == [53, 1, 8]) {
            return;
        }

        self.log(LanProbe::DhcpInform { at: Instant::now() });

        let Some(server) = self.dhcp else {
            return;
        };
        let scanner_mac = frame.source();
        let Ok(scanner_ip) = ip::ipv4_source(frame) else {
            return;
        };

        if let Some(reply) = dhcp_ack(server, scanner_mac, scanner_ip) {
            self.deliver(reply, Duration::ZERO);
        }
    }

    /// Answers a router solicitation with an advertisement, if a router was
    /// declared.
    fn answer_router_solicit(&mut self, frame: &Frame<'_>) {
        self.log(LanProbe::RouterSolicit { at: Instant::now() });

        let Some(router) = self.router else {
            return;
        };
        let scanner_mac = frame.source();

        if let Some(advert) = router_advertisement(router, scanner_mac) {
            self.deliver(advert, Duration::ZERO);
        }
    }

    /// Answers an ARP request, if the address it asks about has a host on it.
    fn answer_arp(&mut self, frame: &Frame<'_>) {
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

    /// Emits each declared unsolicited advertisement once, as soon as the
    /// scanner has put a frame on the wire and named an address to send it to.
    fn emit_unsolicited(&mut self, frame: &Frame<'_>) {
        if self.unsolicited.is_empty() || frame.ethertype() != EtherTypes::Ipv6 {
            return;
        }
        let Ok(scanner_ip) = ip::ipv6_source(frame) else {
            return;
        };
        let scanner_mac = frame.source();

        for address in std::mem::take(&mut self.unsolicited) {
            let Some(host) = self.hosts.get(&IpAddr::V6(address)).copied() else {
                continue;
            };
            if let Some(advert) =
                neighbor_advertisement(host.mac, address, address, scanner_mac, scanner_ip)
            {
                self.deliver(advert, host.delay);
            }
        }
    }

    /// Emits the switch's own announcement once, as soon as the scanner has put
    /// anything on the wire.
    ///
    /// Unlike everything else here it answers nothing — a managed switch
    /// announces itself on a timer, and the scanner's first frame is only the
    /// moment this fixture has to hang it on.
    fn emit_switch_announcement(&mut self) {
        let Some(switch) = self.switch.take() else {
            return;
        };
        self.deliver(lldp_advertisement(switch), Duration::ZERO);
    }

    /// Emits each declared mDNS announcement once, as soon as the scanner has
    /// put a frame on the wire.
    fn emit_announcements(&mut self, frame: &Frame<'_>) {
        if self.announcements.is_empty() || frame.ethertype() != EtherTypes::Ipv6 {
            return;
        }
        let Ok(scanner_ip) = ip::ipv6_source(frame) else {
            return;
        };
        let scanner_mac = frame.source();

        for (hostname, address, announcer) in std::mem::take(&mut self.announcements) {
            if let Some(message) =
                mdns_response(announcer, scanner_mac, scanner_ip, &hostname, address)
            {
                self.deliver(message, Duration::ZERO);
            }
        }
    }

    /// Answers a neighbor solicitation, if the address it asks about is one of
    /// this segment's declared hosts.
    ///
    /// Unlike the all-nodes echo, exactly one host can answer: the message names
    /// the address it is about. A host declared here answers whatever it thinks
    /// of being scanned, which is the property that makes solicitation worth
    /// sending — replying is not optional in the way replying to a multicast
    /// echo is.
    fn answer_neighbor_solicit(&mut self, frame: &Frame<'_>) {
        let Ok(scanner_ip) = ip::ipv6_source(frame) else {
            return;
        };
        let Some(target) = solicited_target(frame) else {
            return;
        };
        let scanner_mac = frame.source();

        self.log(LanProbe::Solicit {
            target,
            at: Instant::now(),
        });

        let Some(host) = self.hosts.get(&IpAddr::V6(target)).copied() else {
            return;
        };
        if self.admit(IpAddr::V6(target), host.loss) {
            return;
        }
        let from = host.answers_from.unwrap_or(target);
        if let Some(reply) = neighbor_advertisement(host.mac, target, from, scanner_mac, scanner_ip)
        {
            self.deliver(reply, host.delay);
        }
    }

    /// Answers the ICMPv6 all-nodes solicitation on behalf of every IPv6 host
    /// declared on the segment.
    ///
    /// Unlike ARP this probe is not sent per target: one multicast goes out and
    /// any neighbour may answer, so every declared IPv6 host gets the chance to.
    fn answer_all_nodes_echo(&mut self, frame: &Frame<'_>) {
        let Ok(scanner_ip) = ip::ipv6_source(frame) else {
            return;
        };
        // Read off the request rather than assumed, so a neighbour answers the
        // question it was actually asked and the scanner can tell which.
        let Some((identifier, sequence)) = echo_request_token(frame) else {
            return;
        };
        let scanner_mac = frame.source();
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
            if let Some(reply) = icmpv6_echo_reply(
                host.mac,
                host_ip,
                scanner_mac,
                scanner_ip,
                identifier,
                sequence,
            ) {
                self.deliver(reply, host.echo_wait());
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
        let captured = self.capture(frame);

        if delay.is_zero() {
            // `try_send` rather than a blocking or awaited send: this runs
            // synchronously inside the scanner's own send loop, on the runtime
            // thread, so waiting for room here would stall the very loop that
            // drains the queue. The depth is sized so that a full queue means a
            // test wrote more traffic than any real segment would.
            let _ = self.frames.try_send(captured);
            return;
        }

        let frames = self.frames.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            // The receiver is gone once the sweep ends, which is the normal way
            // a reply that arrived too late is discarded.
            let _ = frames.send(captured).await;
        });
    }

    /// Wraps a built frame as though a capture had lifted it off this segment.
    fn capture(&self, bytes: Vec<u8>) -> CapturedFrame {
        CapturedFrame {
            zone: self.zone.clone(),
            link: LinkType::Ethernet,
            bytes,
            observed_at: SystemTime::now(),
        }
    }
}

/// One LLDP type-length-value record: seven bits of type, nine of length.
fn lldp_tlv(kind: u8, value: &[u8]) -> Vec<u8> {
    let length = value.len();
    let mut bytes = vec![
        (kind << 1) | u8::try_from(length >> 8).expect("one bit of length"),
        u8::try_from(length & 0xFF).expect("eight bits of length"),
    ];
    bytes.extend_from_slice(value);
    bytes
}

/// The advertisement a managed switch sends to the port the scanner is on.
fn lldp_advertisement(switch: Switch) -> Vec<u8> {
    const NEAREST_BRIDGE: MacAddr = MacAddr(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E);
    // Chassis subtype 4 is a hardware address; port subtype 5 is an interface
    // name. The two identifiers are numbered by different tables, which is the
    // detail worth stating in a fixture somebody will copy.
    const CHASSIS_SUBTYPE_MAC: u8 = 4;
    const PORT_SUBTYPE_INTERFACE_NAME: u8 = 5;

    let mut chassis = vec![CHASSIS_SUBTYPE_MAC];
    chassis.extend_from_slice(&[
        switch.mac.0,
        switch.mac.1,
        switch.mac.2,
        switch.mac.3,
        switch.mac.4,
        switch.mac.5,
    ]);

    let mut port = vec![PORT_SUBTYPE_INTERFACE_NAME];
    port.extend_from_slice(switch.port.as_bytes());

    // Bridging enabled, routing supported but not enabled — the distinction a
    // reader has to keep, and one a real access switch actually reports.
    const BRIDGE: u16 = 1 << 2;
    const ROUTER: u16 = 1 << 4;
    let mut capabilities = (BRIDGE | ROUTER).to_be_bytes().to_vec();
    capabilities.extend_from_slice(&BRIDGE.to_be_bytes());

    let mut vlan = vec![0x00, 0x80, 0xC2, 0x01];
    vlan.extend_from_slice(&switch.native_vlan.to_be_bytes());

    let mut frame = ethernet::create_header(
        switch.mac,
        NEAREST_BRIDGE,
        zond_engine::protocols::lldp::ETHERTYPE,
    );
    frame.extend(lldp_tlv(1, &chassis));
    frame.extend(lldp_tlv(2, &port));
    frame.extend(lldp_tlv(3, &120u16.to_be_bytes()));
    frame.extend(lldp_tlv(5, switch.name.as_bytes()));
    frame.extend(lldp_tlv(7, &capabilities));
    frame.extend(lldp_tlv(127, &vlan));
    frame.extend(lldp_tlv(0, &[]));
    frame
}

/// An ARP reply frame from `host_mac`/`host_ip` back to the scanner.
fn arp_reply(
    host_mac: MacAddr,
    host_ip: Ipv4Addr,
    scanner_mac: MacAddr,
    scanner_ip: Ipv4Addr,
) -> Option<Vec<u8>> {
    let header = ethernet::create_header(host_mac, scanner_mac, EtherTypes::Arp);

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
    pad_to_min_frame(&mut frame);
    Some(frame)
}

/// The address a neighbor solicitation asks about.
fn solicited_target(frame: &Frame<'_>) -> Option<Ipv6Addr> {
    let packet = pnet::packet::ipv6::Ipv6Packet::new(frame.payload())?;
    Some(NeighborSolicitPacket::new(packet.payload())?.get_target_addr())
}

/// A neighbor advertisement from `host_mac` announcing `target`, addressed back
/// to the scanner that asked.
fn neighbor_advertisement(
    host_mac: MacAddr,
    target: Ipv6Addr,
    from: Ipv6Addr,
    scanner_mac: MacAddr,
    scanner_ip: Ipv6Addr,
) -> Option<Vec<u8>> {
    let mut body = vec![0u8; NDP_ADVERT_LEN];
    {
        let mut advert = MutableNeighborAdvertPacket::new(&mut body)?;
        advert.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
        advert.set_icmpv6_code(Icmpv6Code(0));
        // Solicited and override, which is what an answer to a solicitation
        // carries.
        advert.set_flags(0x60);
        advert.set_target_addr(target);
    }

    let header = ethernet::create_header(host_mac, scanner_mac, EtherTypes::Ipv6);
    let ipv6 = ip::create_ipv6_header(
        from,
        scanner_ip,
        body.len() as u16,
        IpNextHeaderProtocols::Icmpv6,
        ip::HOP_LIMIT_NDP,
    );

    let mut frame = Vec::with_capacity(MIN_ETH_FRAME);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&ipv6);
    frame.extend_from_slice(&body);
    pad_to_min_frame(&mut frame);
    Some(frame)
}

/// An mDNS response announcing `hostname` at `address`, framed as it arrives on
/// the wire: Ethernet, IPv6, UDP from port 5353, then a DNS message carrying one
/// AAAA answer.
///
/// Built rather than hand-waved for the reason every other frame here is: a
/// simulator that emits what the parser happens to accept proves only that the
/// parser accepts it. The UDP checksum is computed, even though nothing in the
/// engine currently reads it, so this stays a message a real responder could
/// have sent.
fn mdns_response(
    announcer: MacAddr,
    scanner_mac: MacAddr,
    scanner_ip: Ipv6Addr,
    hostname: &str,
    address: Ipv6Addr,
) -> Option<Vec<u8>> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&0u16.to_be_bytes()); // id: zero in an mDNS response
    dns.extend_from_slice(&0x8400u16.to_be_bytes()); // response, authoritative
    dns.extend_from_slice(&0u16.to_be_bytes()); // questions
    dns.extend_from_slice(&1u16.to_be_bytes()); // answers
    dns.extend_from_slice(&0u16.to_be_bytes()); // authority
    dns.extend_from_slice(&0u16.to_be_bytes()); // additional

    for label in hostname.split('.') {
        dns.push(u8::try_from(label.len()).ok()?);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0); // root label
    dns.extend_from_slice(&28u16.to_be_bytes()); // AAAA
    dns.extend_from_slice(&1u16.to_be_bytes()); // IN
    dns.extend_from_slice(&120u32.to_be_bytes()); // ttl
    dns.extend_from_slice(&16u16.to_be_bytes()); // rdlength
    dns.extend_from_slice(&address.octets());

    // Multicast DNS goes to ff02::fb, but this segment hands frames straight to
    // the scanner's capture, which is promiscuous and sees them either way.
    let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xFF);
    let mut udp = vec![0u8; UDP_HDR_LEN + dns.len()];
    {
        let mut datagram = MutableUdpPacket::new(&mut udp)?;
        datagram.set_source(MDNS_PORT);
        datagram.set_destination(MDNS_PORT);
        datagram.set_length(u16::try_from(UDP_HDR_LEN + dns.len()).ok()?);
        datagram.set_payload(&dns);
        let sum = udp_ipv6_checksum(&datagram.to_immutable(), &source, &scanner_ip);
        datagram.set_checksum(sum);
    }

    let header = ethernet::create_header(announcer, scanner_mac, EtherTypes::Ipv6);
    let ipv6 = ip::create_ipv6_header(
        source,
        scanner_ip,
        u16::try_from(udp.len()).ok()?,
        IpNextHeaderProtocols::Udp,
        ip::HOP_LIMIT_ON_LINK,
    );

    let mut frame = Vec::with_capacity(MIN_ETH_FRAME);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&ipv6);
    frame.extend_from_slice(&udp);
    pad_to_min_frame(&mut frame);
    Some(frame)
}

/// The identifier and sequence number an echo *request* carries, which the
/// reply has to return unchanged.
fn echo_request_token(frame: &Frame<'_>) -> Option<(u16, u16)> {
    let packet = pnet::packet::ipv6::Ipv6Packet::new(frame.payload())?;
    let request = pnet::packet::icmpv6::echo_request::EchoRequestPacket::new(packet.payload())?;
    Some((request.get_identifier(), request.get_sequence_number()))
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
///
/// `identifier` and `sequence` come from the request being answered, which RFC
/// 4443 requires and which a scanner needs in order to time the reply. A fake
/// that returned zeros would have every neighbour answering a request nobody
/// sent - untimed here, and no way to tell that from a real segment where the
/// timing works.
fn icmpv6_echo_reply(
    host_mac: MacAddr,
    host_ip: Ipv6Addr,
    scanner_mac: MacAddr,
    scanner_ip: Ipv6Addr,
    identifier: u16,
    sequence: u16,
) -> Option<Vec<u8>> {
    let mut body = vec![0u8; ICMPV6_ECHO_LEN];
    {
        let mut echo = MutableEchoReplyPacket::new(&mut body)?;
        echo.set_icmpv6_type(Icmpv6Types::EchoReply);
        echo.set_icmpv6_code(Icmpv6Codes::NoCode);
        echo.set_identifier(identifier);
        echo.set_sequence_number(sequence);
    }

    let header = ethernet::create_header(host_mac, scanner_mac, EtherTypes::Ipv6);
    let ipv6 = ip::create_ipv6_header(
        host_ip,
        scanner_ip,
        body.len() as u16,
        IpNextHeaderProtocols::Icmpv6,
        ip::HOP_LIMIT_ON_LINK,
    );

    let mut frame = Vec::with_capacity(MIN_ETH_FRAME);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&ipv6);
    frame.extend_from_slice(&body);
    pad_to_min_frame(&mut frame);
    Some(frame)
}

/// The BOOTP message inside `frame`, if it is a DHCP datagram at all.
fn dhcp_message<'a>(frame: &Frame<'a>) -> Option<Vec<u8>> {
    let packet = pnet::packet::ipv4::Ipv4Packet::new(frame.payload())?;
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }

    let datagram = pnet::packet::udp::UdpPacket::new(packet.payload())?;
    (datagram.get_destination() == DHCP_SERVER_PORT).then(|| datagram.payload().to_vec())
}

/// A `DHCPACK` from `server`, unicast back to the scanner as RFC 2131 §4.3.5
/// requires for an inform.
fn dhcp_ack(server: Server, scanner_mac: MacAddr, scanner_ip: Ipv4Addr) -> Option<Vec<u8>> {
    /// op, htype, hlen, hops, xid, secs, flags, and the four addresses through
    /// `chaddr`, `sname` and `file`.
    const BOOTP_FIXED_LEN: usize = 236;

    let mut message = vec![0u8; BOOTP_FIXED_LEN];
    message[0] = 2; // BOOTREPLY
    message[1] = 1; // Ethernet
    message[2] = 6;
    message.extend_from_slice(&[99, 130, 83, 99]); // magic cookie
    message.extend_from_slice(&[53, 1, 5]); // DHCPACK
    message.push(54); // server identifier
    message.push(4);
    message.extend_from_slice(&server.identifier.octets());
    message.push(255); // end

    let datagram = craft::Packet::new()
        .push(craft::Ipv4::new(server.address, scanner_ip))
        .push(craft::Udp::new(DHCP_SERVER_PORT, DHCP_CLIENT_PORT).with_payload(message))
        .build()
        .ok()?;

    let mut frame = ethernet::create_header(server.mac, scanner_mac, EtherTypes::Ipv4);
    frame.extend_from_slice(&datagram);
    pad_to_min_frame(&mut frame);
    Some(frame)
}

/// A router advertisement from `router`, addressed to the all-nodes group as a
/// real one is.
///
/// Carries the hop limit RFC 4861 §6.1.2 requires a receiver to check, because
/// the engine checks it: an advertisement built with anything less is one a
/// conformant listener discards, and a fake that sent one would be testing the
/// wrong half of the rule.
fn router_advertisement(router: Router, scanner_mac: MacAddr) -> Option<Vec<u8>> {
    /// Reachable time and retransmission timer, both left as "unspecified".
    const RA_BODY_LEN: usize = 8;

    let message = craft::Icmpv6 {
        icmp_type: Icmpv6Types::RouterAdvert.0,
        code: 0,
        checksum: craft::Field::Computed,
        // Current hop limit, flags, then a router lifetime of 1800 seconds —
        // the field that would be zero if this router were declining to be a
        // default one.
        rest_of_header: [64, 0, 0x07, 0x08],
        payload: vec![0u8; RA_BODY_LEN],
    };

    let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    let packet = craft::Packet::new()
        .push(craft::Ipv6::new(router.address, all_nodes).with_hop_limit(ip::HOP_LIMIT_NDP))
        .push(message)
        .build()
        .ok()?;

    let mut frame = ethernet::create_header(router.mac, scanner_mac, EtherTypes::Ipv6);
    frame.extend_from_slice(&packet);
    pad_to_min_frame(&mut frame);
    Some(frame)
}
