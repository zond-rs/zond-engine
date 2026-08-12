// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A simulated network for the raw scanners (Tier 2).
//!
//! The portable tests alongside this module drive the public API against real
//! loopback servers, which is honest but can only produce the handful of
//! outcomes a cooperative kernel is willing to produce: open and closed. The
//! behaviour that actually distinguishes a scanner - what it does when probes
//! are lost, answered late, answered twice, or never answered at all - needs a
//! network that misbehaves on demand.
//!
//! [`FakeNet`] is that network. It plugs into
//! [`ProbeTransport::from_parts`](zond_engine::network::probe::ProbeTransport::from_parts):
//! it receives the Layer-4 segments a scanner emits, decides per target how
//! (and whether) to answer, and pushes synthesized replies back onto the
//! scanner's receive stream exactly as a capture would. No sockets, no
//! privileges, no interfaces - so these tests run unchanged on every platform
//! CI covers, in milliseconds, with no dependence on the machine's network.
//!
//! # Determinism
//!
//! Probabilistic policies draw from a seeded generator owned by the net, so a
//! given seed always produces the same sequence of drops. A failure found in CI
//! reproduces locally from the seed alone. The generator is implemented here
//! rather than taken from `rand`, whose output is explicitly not stable across
//! versions - a dependency bump would otherwise silently change which packets
//! a "reproducible" test drops.
//!
//! # What this deliberately cannot model
//!
//! The seam sits *above* IP: a scanner hands down a finished Layer-4 segment
//! and gets Layer-4 segments back, with the IP layer already peeled off by the
//! capture. Anything whose behaviour lives at or below IP - path MTU,
//! fragmentation and reassembly, real queueing delay, ARP - is therefore
//! invisible here and cannot be faked convincingly. Those belong to the
//! privileged Linux tier, where a real kernel carries real packets across a
//! real (if virtual) link. [`Reply::Truncated`] is the one nod in that
//! direction, and it tests only that a scanner survives a reply it cannot
//! parse.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pnet::packet::icmp::destination_unreachable::{
    DestinationUnreachablePacket, IcmpCodes, MutableDestinationUnreachablePacket,
};
use pnet::packet::icmp::{IcmpCode, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::udp::UdpPacket;
use tokio::sync::mpsc::{self, UnboundedSender};

use zond_engine::network::capture::CapturedSegment;
use zond_engine::network::probe::{ProbeSender, ProbeTransport, SendError};
use zond_engine::protocols::{ip, udp};

/// TCP header length used for synthesized replies: the 20-byte minimum, with
/// no options. Real stacks usually attach options to a SYN+ACK, but nothing in
/// the classification path reads them.
const TCP_HDR_LEN: usize = 20;
const TCP_HDR_WORDS: u8 = (TCP_HDR_LEN / 4) as u8;

const FIN: u8 = 1;
const SYN: u8 = 1 << 1;
const RST: u8 = 1 << 2;
const ACK: u8 = 1 << 4;

/// The four unused bytes that precede the quoted datagram in an ICMPv6
/// Destination Unreachable message (RFC 4443 §3.1).
const ICMPV6_UNUSED_LEN: usize = 4;

/// How many bytes a [`Reply::Truncated`] reply is cut down to - short enough
/// that no Layer-4 parser can make a header out of it.
const TRUNCATED_LEN: usize = 4;

/// Hop limit for synthesized IPv6 replies. Immaterial here - the seam sits
/// above IP and nothing under test reads it - but it has to be some value.
const HOP_LIMIT: u8 = 64;

/// Which protocol the scanner under test speaks, and therefore how [`FakeNet`]
/// must read its probes and shape its answers.
///
/// A bare Layer-4 segment does not say what it is, and TCP and UDP headers are
/// not distinguishable by inspection, so this has to be declared up front -
/// exactly as the real transport declares a
/// [`ProbeKind`](zond_engine::network::probe::ProbeKind) when it compiles its
/// capture filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer4 {
    /// TCP SYN probes, answered with SYN+ACK or RST.
    Tcp,
    /// UDP probes, answered with a datagram or an ICMP error.
    Udp,
}

/// How a virtual host's TCP implementation behaves, where implementations
/// genuinely disagree.
///
/// Only the flag probes are affected. A SYN is answered the same way by
/// everything that speaks TCP, which is exactly why a SYN scan works against
/// every stack and these do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Stack {
    /// RFC 793 §3.4 to the letter: a closed port resets anything that is not a
    /// reset, and a port in LISTEN ignores a segment carrying neither SYN, ACK
    /// nor RST - but *does* reset one carrying ACK.
    ///
    /// The last clause is why a Maimon scan distinguishes nothing here, and why
    /// an ACK scan never reports a port open: both probes carry ACK, so both are
    /// answered identically by open and closed ports alike.
    #[default]
    Conformant,
    /// BSD-derived: as [`Conformant`](Self::Conformant), except that an open
    /// port drops a `FIN ACK` instead of resetting it. Uriel Maimon's finding,
    /// and the only stack family against which that technique tells you
    /// anything.
    BsdDerived,
    /// Answers every flag probe with a RST whatever the port state, as Windows,
    /// many Cisco devices, BSDI and IBM OS/400 do.
    ///
    /// Against this a FIN, NULL, Xmas or Maimon scan reports every port closed -
    /// not merely useless but confidently wrong - which is a documented property
    /// of those techniques and therefore something to pin rather than to fix.
    AlwaysResets,
}

/// What a virtual host says back when a probe reaches it.
///
/// This is the answer the host *would* give; whether the probe survives the
/// link to elicit it is [`Loss`]'s decision, applied first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// A listening port. TCP answers SYN+ACK, UDP answers with a datagram from
    /// the probed port. Either should classify as `Open`.
    Open,
    /// A port with nothing behind it. TCP answers RST, UDP answers ICMP port
    /// unreachable. Either should classify as `Closed`.
    Closed,
    /// No answer, ever. This is what a firewall configured to `DROP` rather
    /// than `REJECT` looks like from outside, and the only way to reach the
    /// `Filtered` classification: the scanner has to conclude it from silence
    /// and its own deadline, since nothing on the wire tells it.
    Silent,
    /// A specific ICMP Destination Unreachable reason, for the distinctions the
    /// blanket [`Closed`](Self::Closed) hides - an administratively prohibited
    /// message means filtered, not closed.
    ///
    /// A TCP probe draws one of these only where the scanner asked its capture
    /// for ICMP, which the SYN technique does not: for it, this is silence, as
    /// it would be on a real network where the kernel filter never let the error
    /// through.
    Unreachable(Unreachable),
    /// A reply cut short mid-header, which no parser can read. Nothing should
    /// be classified from it and nothing should panic on it - the probe stays
    /// outstanding as though the reply had never arrived.
    Truncated,
    /// A bare ACK: traffic from an established connection to this host, not an
    /// answer to any probe.
    ///
    /// This exists because the kernel filter no longer keeps it out. libpcap
    /// cannot narrow TCP by flags over IPv6, so the SYN transport admits every
    /// IPv6 TCP segment on every captured interface, and a scan of an address
    /// the host is already talking to will see its traffic. Over IPv4 the
    /// kernel drops it and this reply never reaches a scanner at all - which is
    /// the asymmetry worth testing, since the two families must still conclude
    /// the same thing.
    Established,
}

/// Why a Destination Unreachable message was sent, named by meaning rather
/// than by code number.
///
/// ICMPv4 and ICMPv6 number these differently, and the same reason carries
/// different numbers in each: "port unreachable" is code 3 over v4 and code 4
/// over v6. Naming the reason and resolving the number per address family keeps
/// a test from asserting on a v4 code that would be a different message
/// entirely on v6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreachable {
    /// Nothing is bound to the port. The one unambiguous "closed" signal a UDP
    /// scan gets.
    Port,
    /// A filtering device refused to forward the probe. Means filtered, and
    /// misreading it as closed is the classic UDP-scan error.
    AdminProhibited,
    /// The host itself could not be reached, which says nothing about the port.
    ///
    /// The two families genuinely disagree on what this means for a scan, and
    /// the harness does not paper over it: v4's host-unreachable is an explicit
    /// delivery failure and reads as filtered, while v6's address-unreachable
    /// is deliberately left unclassified and leaves the probe to time out. A
    /// test using this variant should expect the family's own behaviour.
    Host,
}

impl Unreachable {
    /// The ICMPv4 code for this reason (RFC 792, RFC 1812 §5.2.7.1).
    fn v4(self) -> IcmpCode {
        match self {
            Self::Port => IcmpCodes::DestinationPortUnreachable,
            Self::AdminProhibited => IcmpCodes::CommunicationAdministrativelyProhibited,
            Self::Host => IcmpCodes::DestinationHostUnreachable,
        }
    }

    /// The ICMPv6 code for this reason (RFC 4443 §3.1).
    fn v6(self) -> Icmpv6Code {
        match self {
            Self::Port => Icmpv6Code(4),
            Self::AdminProhibited => Icmpv6Code(1),
            Self::Host => Icmpv6Code(3),
        }
    }
}

/// What the link does to a probe on its way to the host.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Loss {
    /// Every probe arrives.
    None,
    /// Swallow the first `n` probes to a target, deliver the rest.
    ///
    /// This is the shape of the retransmission test: a scanner that gives up
    /// after one unanswered probe reports the target as filtered, while one
    /// that retries discovers its true state. Because the cutoff is a count and
    /// not a coin flip, the expected outcome is exact - the test asserts a
    /// classification, not a success rate.
    First(u32),
    /// Swallow each probe with probability `p`, drawn from the net's seeded
    /// generator. Models a genuinely lossy link, where the interesting property
    /// is statistical: over many targets, how much does the scan's accuracy
    /// degrade, and does it ever degrade into a *false* answer rather than a
    /// missing one.
    Rate(f64),
}

/// How one virtual `(host, port)` behaves: what it answers, what the link
/// between here and there does to the probe, and how long the round trip takes.
///
/// Built by starting from the reply and layering conditions on:
///
/// ```ignore
/// Policy::open().drop_first(1).delay(Duration::from_millis(40))
/// Policy::closed()
/// Policy::silent()
/// Policy::open().loss_rate(0.3).duplicated()
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    reply: Reply,
    loss: Loss,
    delay: Duration,
    /// Deliver the reply twice. A duplicate is normal on a real network (the
    /// host retransmits because our ACK never came) and must not be counted as
    /// a second observation or credited as a second round-trip sample.
    duplicated: bool,
}

impl Policy {
    /// A port that is open and answers immediately.
    pub fn open() -> Self {
        Self::answering(Reply::Open)
    }

    /// A port that is closed and refuses immediately.
    pub fn closed() -> Self {
        Self::answering(Reply::Closed)
    }

    /// A port behind a silent drop, which never answers at all.
    pub fn silent() -> Self {
        Self::answering(Reply::Silent)
    }

    /// A port answered by a specific ICMP Destination Unreachable reason. See
    /// [`Reply::Unreachable`].
    pub fn unreachable(reason: Unreachable) -> Self {
        Self::answering(Reply::Unreachable(reason))
    }

    /// A port administratively prohibited by a filtering router, the common
    /// case that must not be read as `Closed`.
    pub fn admin_prohibited() -> Self {
        Self::unreachable(Unreachable::AdminProhibited)
    }

    /// A port whose reply arrives unparseable. See [`Reply::Truncated`].
    pub fn truncated() -> Self {
        Self::answering(Reply::Truncated)
    }

    /// A host that sends a bare ACK rather than answering the probe. See
    /// [`Reply::Established`].
    pub fn established() -> Self {
        Self::answering(Reply::Established)
    }

    fn answering(reply: Reply) -> Self {
        Self {
            reply,
            loss: Loss::None,
            delay: Duration::ZERO,
            duplicated: false,
        }
    }

    /// Swallows the first `n` probes to this target. See [`Loss::First`].
    pub fn drop_first(mut self, n: u32) -> Self {
        self.loss = Loss::First(n);
        self
    }

    /// Swallows each probe with probability `p`. See [`Loss::Rate`].
    ///
    /// Panics unless `p` is a probability, since a silently clamped rate would
    /// make a test claim to cover a loss level it never applied.
    pub fn loss_rate(mut self, p: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&p),
            "loss rate must be a probability, got {p}"
        );
        self.loss = Loss::Rate(p);
        self
    }

    /// Holds the reply back for `delay` before delivering it.
    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Delivers the reply twice. See [`Policy::duplicated`].
    pub fn duplicated(mut self) -> Self {
        self.duplicated = true;
        self
    }
}

/// One probe as the network saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// The host it was addressed to.
    pub target: IpAddr,
    /// The port on that host.
    pub port: u16,
    /// When it was sent, for asserting on retry spacing and backoff.
    pub at: Instant,
    /// Whether the link swallowed it instead of delivering it.
    pub dropped: bool,
}

/// A simulated network the raw scanners can be pointed at.
///
/// Describe the hosts, hand the scanner a [`transport`](Self::transport), run
/// it, then assert on both the scan's results and the [`probes`](Self::probes)
/// this net observed - the second half is what makes retransmission testable,
/// since retrying is visible only in the probe log.
pub struct FakeNet {
    layer4: Layer4,
    /// How the virtual hosts' TCP implementations behave where implementations
    /// disagree. Per net rather than per host: a test about a stack quirk is
    /// about the whole machine it is scanning.
    stack: Stack,
    policies: HashMap<(IpAddr, u16), Policy>,
    /// Applied to any target no explicit policy names. Silence is the right
    /// default: it is what the vast majority of the address space does, and it
    /// means a test that forgets to declare a host gets a plausible answer
    /// rather than an accidental `Open`.
    fallback: Policy,
    seed: u64,
    /// Shared with every transport handed out, so the probe log and the
    /// generator survive in one place and can be read back after the scan.
    state: Arc<Mutex<State>>,
}

/// The net's mutable half: everything a send has to read or advance.
struct State {
    rng: SplitMix64,
    /// Probes seen per target, which is what [`Loss::First`] counts against.
    attempts: HashMap<(IpAddr, u16), u32>,
    log: Vec<Probe>,
}

impl FakeNet {
    /// An all-silent network speaking `layer4`, seeded reproducibly.
    pub fn new(layer4: Layer4) -> Self {
        Self::seeded(layer4, DEFAULT_SEED)
    }

    /// [`new`](Self::new) with an explicit seed for the probabilistic policies.
    /// Vary it to sweep a test across many loss patterns; record it to
    /// reproduce one.
    pub fn seeded(layer4: Layer4, seed: u64) -> Self {
        Self {
            layer4,
            stack: Stack::default(),
            policies: HashMap::new(),
            fallback: Policy::silent(),
            seed,
            state: Arc::new(Mutex::new(State {
                rng: SplitMix64::new(seed),
                attempts: HashMap::new(),
                log: Vec::new(),
            })),
        }
    }

    /// Gives every host on this network the TCP behaviour `stack` describes.
    pub fn stack(mut self, stack: Stack) -> Self {
        self.stack = stack;
        self
    }

    /// Gives `ip:port` the behaviour `policy` describes.
    pub fn host(mut self, ip: IpAddr, port: u16, policy: Policy) -> Self {
        self.policies.insert((ip, port), policy);
        self
    }

    /// Applies `policy` to every port `ip` is probed on that no
    /// [`host`](Self::host) call named, so a scan over a wide port range can be
    /// described in one line.
    pub fn host_default(mut self, policy: Policy) -> Self {
        self.fallback = policy;
        self
    }

    /// The seed this net's probabilistic policies draw from. Print it from a
    /// failing test so the run can be reproduced.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// A transport carrying this network, ready to hand to a scanner's
    /// `with_transport` constructor.
    ///
    /// Each call builds an independent reply stream but shares the probe log
    /// and generator, so two scanners on one net are still jointly
    /// reproducible.
    pub fn transport(&self) -> ProbeTransport {
        let (replies, rx) = mpsc::unbounded_channel();
        let link = FakeLink {
            layer4: self.layer4,
            stack: self.stack,
            policies: self.policies.clone(),
            fallback: self.fallback,
            state: Arc::clone(&self.state),
            replies,
        };
        ProbeTransport::from_parts(Box::new(link), rx)
    }

    /// Every probe this network received, in the order it received them.
    pub fn probes(&self) -> Vec<Probe> {
        self.state.lock().expect("fake net state").log.clone()
    }

    /// How many probes reached this network for `ip:port`, delivered or
    /// dropped. Greater than one means the scanner retransmitted.
    pub fn probe_count(&self, ip: IpAddr, port: u16) -> usize {
        self.state
            .lock()
            .expect("fake net state")
            .log
            .iter()
            .filter(|p| p.target == ip && p.port == port)
            .count()
    }
}

/// The send half of a [`FakeNet`]: the scanner's view of the wire.
struct FakeLink {
    layer4: Layer4,
    stack: Stack,
    policies: HashMap<(IpAddr, u16), Policy>,
    fallback: Policy,
    state: Arc<Mutex<State>>,
    replies: UnboundedSender<CapturedSegment>,
}

impl ProbeSender for FakeLink {
    /// Carries one probe across the simulated link.
    ///
    /// Sending never fails. A dropped packet is not a send error - the whole
    /// point is that the scanner cannot tell the difference between a probe
    /// that was lost and one that was ignored, and reporting an error here
    /// would hand it exactly the signal a real network withholds.
    fn send(&self, segment: &[u8], src: IpAddr, dst: IpAddr) -> Result<(), SendError> {
        let Some(probe) = self.parse(segment) else {
            return Err(SendError::Refused(format!(
                "fake net received a segment it could not parse as {:?}",
                self.layer4
            )));
        };

        let policy = self
            .policies
            .get(&(dst, probe.port))
            .copied()
            .unwrap_or(self.fallback);

        let dropped = self.admit(dst, probe.port, policy.loss);
        if dropped {
            return Ok(());
        }

        for reply in self.replies_to(&probe, policy.reply, src, dst) {
            self.deliver(reply, policy);
        }

        Ok(())
    }
}

/// The fields of an outgoing probe that decide how it is answered.
struct ParsedProbe {
    /// The port on the target the probe is aimed at.
    port: u16,
    /// The port the scanner sent from, which its replies must come back to.
    reply_port: u16,
    /// The TCP sequence number. Zero for UDP, which correlates by port instead.
    seq: u32,
    /// The TCP acknowledgement number, which a reset answering a probe that
    /// carried ACK takes as its own sequence number.
    ack: u32,
    /// The TCP flags, which decide both how a host answers the probe and how
    /// its answer has to be shaped. Zero for UDP.
    flags: u8,
    /// The probe as sent, kept whole because an ICMP error has to quote it.
    bytes: Vec<u8>,
}

impl FakeLink {
    /// Reads the fields that decide how a probe is answered out of its header.
    fn parse(&self, segment: &[u8]) -> Option<ParsedProbe> {
        let bytes = segment.to_vec();
        match self.layer4 {
            Layer4::Tcp => {
                let tcp = TcpPacket::new(segment)?;
                Some(ParsedProbe {
                    port: tcp.get_destination(),
                    reply_port: tcp.get_source(),
                    seq: tcp.get_sequence(),
                    ack: tcp.get_acknowledgement(),
                    flags: tcp.get_flags(),
                    bytes,
                })
            }
            Layer4::Udp => {
                let datagram = UdpPacket::new(segment)?;
                Some(ParsedProbe {
                    port: datagram.get_destination(),
                    reply_port: datagram.get_source(),
                    seq: 0,
                    ack: 0,
                    flags: 0,
                    bytes,
                })
            }
        }
    }

    /// Records the probe and decides whether the link swallows it, returning
    /// true if it did.
    ///
    /// Counting and the coin flip happen together under one lock, so probes
    /// racing in from a concurrent scan still consume the generator in a single
    /// well-defined order.
    fn admit(&self, target: IpAddr, port: u16, loss: Loss) -> bool {
        let mut state = self.state.lock().expect("fake net state");

        let attempts = state.attempts.entry((target, port)).or_insert(0);
        *attempts += 1;
        let attempt = *attempts;

        let dropped = match loss {
            Loss::None => false,
            Loss::First(n) => attempt <= n,
            Loss::Rate(p) => state.rng.next_unit() < p,
        };

        state.log.push(Probe {
            target,
            port,
            at: Instant::now(),
            dropped,
        });

        dropped
    }

    /// The segments a host answers `probe` with, empty when it stays silent.
    fn replies_to(
        &self,
        probe: &ParsedProbe,
        reply: Reply,
        scanner: IpAddr,
        target: IpAddr,
    ) -> Vec<CapturedSegment> {
        let segment = match (self.layer4, reply) {
            (_, Reply::Silent) => None,
            // UDP has no connection to be established on, so there is no
            // equivalent segment to send and the probe simply goes unanswered.
            (Layer4::Udp, Reply::Established) => None,

            (Layer4::Tcp, Reply::Open) => self.tcp_answer(probe, scanner, target, true),
            (Layer4::Tcp, Reply::Closed) => self.tcp_answer(probe, scanner, target, false),
            (Layer4::Tcp, Reply::Established) => self.tcp_reply(probe, scanner, target, ACK),
            (Layer4::Tcp, Reply::Unreachable(reason)) => {
                self.icmp_reply(probe, scanner, target, reason)
            }

            (Layer4::Udp, Reply::Open) => self.udp_reply(probe, scanner, target),
            (Layer4::Udp, Reply::Closed) => {
                self.icmp_reply(probe, scanner, target, Unreachable::Port)
            }
            (Layer4::Udp, Reply::Unreachable(reason)) => {
                self.icmp_reply(probe, scanner, target, reason)
            }

            (layer4, Reply::Truncated) => {
                // Truncate whatever this protocol's open reply would have been,
                // so the bytes are a plausible prefix rather than noise.
                let full = match layer4 {
                    Layer4::Tcp => self.tcp_answer(probe, scanner, target, true),
                    Layer4::Udp => self.udp_reply(probe, scanner, target),
                };
                full.map(|mut s| {
                    s.bytes.truncate(TRUNCATED_LEN);
                    s
                })
            }
        };

        segment.into_iter().collect()
    }

    /// What this net's TCP stack sends back when `probe` reaches a port that is
    /// `listening`, or nothing where the stack is required to stay silent.
    ///
    /// This is RFC 793 §3.4 and §3.9 applied to the probe as it arrived, not a
    /// table of what each scan technique expects. The distinction matters: a
    /// simulator built from the scanner's expectations agrees with the scanner
    /// even when both are wrong, and this file has produced exactly that
    /// mistake before.
    ///
    /// - A **SYN** is a connection attempt: a listener accepts with SYN+ACK, a
    ///   closed port refuses with RST+ACK.
    /// - A segment **carrying ACK** claims to belong to a connection that does
    ///   not exist, so the stack resets it - whether or not anything is
    ///   listening. That single clause is why an ACK scan cannot find open
    ///   ports and why a Maimon scan tells you nothing about a conformant host.
    /// - A segment carrying **neither SYN nor ACK nor RST** is ignored by a
    ///   listener and reset by a closed port, which is the whole basis of the
    ///   FIN, NULL and Xmas techniques.
    fn tcp_answer(
        &self,
        probe: &ParsedProbe,
        scanner: IpAddr,
        target: IpAddr,
        listening: bool,
    ) -> Option<CapturedSegment> {
        let carries = |flag: u8| probe.flags & flag != 0;

        if carries(SYN) {
            let flags = if listening { SYN | ACK } else { RST | ACK };
            return self.tcp_reply(probe, scanner, target, flags);
        }

        // The quirk this exists to model, and the whole of the Maimon finding:
        // BSD-derived stacks drop a FIN+ACK aimed at an open port where the RFC
        // has them reset it.
        if self.stack == Stack::BsdDerived && listening && carries(FIN) && carries(ACK) {
            return None;
        }

        let resets = match self.stack {
            Stack::AlwaysResets => true,
            _ => !listening || carries(ACK),
        };

        resets.then(|| self.tcp_reset(probe, scanner, target))?
    }

    /// The reset a stack sends in answer to a segment for a port it is not
    /// holding open, shaped as RFC 793 §3.4 requires.
    ///
    /// > If the incoming segment has an ACK field, the reset takes its sequence
    /// > number from the ACK field of the segment; otherwise the reset has
    /// > sequence number zero and the ACK field is set to the sum of the
    /// > sequence number and segment length of the incoming segment.
    ///
    /// Written out from the RFC rather than from anything the engine does with
    /// it. A scanner that reads the wrong field, or that forgets a FIN occupies
    /// an octet of sequence space where a flagless segment does not, must fail
    /// here rather than be agreed with.
    fn tcp_reset(
        &self,
        probe: &ParsedProbe,
        scanner: IpAddr,
        target: IpAddr,
    ) -> Option<CapturedSegment> {
        if probe.flags & ACK != 0 {
            return self.tcp_segment(probe, scanner, target, RST, probe.ack, 0);
        }

        let segment_len = u32::from(probe.flags & SYN != 0) + u32::from(probe.flags & FIN != 0);
        self.tcp_segment(
            probe,
            scanner,
            target,
            RST | ACK,
            0,
            probe.seq.wrapping_add(segment_len),
        )
    }

    /// A TCP segment from the probed port back to the scanner, acknowledging
    /// the probe's sequence number the way an answer to a SYN does.
    fn tcp_reply(
        &self,
        probe: &ParsedProbe,
        scanner: IpAddr,
        target: IpAddr,
        flags: u8,
    ) -> Option<CapturedSegment> {
        self.tcp_segment(
            probe,
            scanner,
            target,
            flags,
            self.next_u32(),
            probe.seq.wrapping_add(1),
        )
    }

    /// One TCP segment from the probed port back to the scanner's source port,
    /// carrying the sequence and acknowledgement numbers the caller worked out.
    fn tcp_segment(
        &self,
        probe: &ParsedProbe,
        scanner: IpAddr,
        target: IpAddr,
        flags: u8,
        sequence: u32,
        acknowledgement: u32,
    ) -> Option<CapturedSegment> {
        let mut buffer = vec![0u8; TCP_HDR_LEN];
        {
            let mut tcp = MutableTcpPacket::new(&mut buffer)?;
            tcp.set_source(probe.port);
            tcp.set_destination(probe.reply_port);
            tcp.set_data_offset(TCP_HDR_WORDS);
            tcp.set_sequence(sequence);
            tcp.set_acknowledgement(acknowledgement);
            tcp.set_flags(flags);
            tcp.set_window(65_535);
            tcp.set_checksum(0);

            let checksum = match (target, scanner) {
                (IpAddr::V4(s), IpAddr::V4(d)) => {
                    pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &s, &d)
                }
                (IpAddr::V6(s), IpAddr::V6(d)) => {
                    pnet::packet::tcp::ipv6_checksum(&tcp.to_immutable(), &s, &d)
                }
                _ => return None,
            };
            tcp.set_checksum(checksum);
        }

        Some(CapturedSegment {
            source: target,
            protocol: IpNextHeaderProtocols::Tcp,
            bytes: buffer,
        })
    }

    /// A UDP datagram from the probed port back to the scanner's source port,
    /// which is the only thing that marks a UDP port as definitely open.
    fn udp_reply(
        &self,
        probe: &ParsedProbe,
        scanner: IpAddr,
        target: IpAddr,
    ) -> Option<CapturedSegment> {
        let bytes =
            udp::create_packet(&target, &scanner, probe.port, probe.reply_port, Vec::new()).ok()?;

        Some(CapturedSegment {
            source: target,
            protocol: IpNextHeaderProtocols::Udp,
            bytes,
        })
    }

    /// An ICMP Destination Unreachable quoting the probe.
    ///
    /// The quotation is the probe's own bytes under a freshly built IP header,
    /// which is what a router would have echoed back. Building it from the real
    /// segment rather than a hand-written fixture means the scanner's check
    /// that the quoted datagram is *its* probe is exercised for real.
    fn icmp_reply(
        &self,
        probe: &ParsedProbe,
        scanner: IpAddr,
        target: IpAddr,
        reason: Unreachable,
    ) -> Option<CapturedSegment> {
        let quoted = quote(scanner, target, &probe.bytes, self.layer4)?;

        match target {
            IpAddr::V4(_) => {
                let mut buffer =
                    vec![0u8; DestinationUnreachablePacket::minimum_packet_size() + quoted.len()];
                let mut icmp = MutableDestinationUnreachablePacket::new(&mut buffer)?;
                icmp.set_icmp_type(IcmpTypes::DestinationUnreachable);
                icmp.set_icmp_code(reason.v4());
                icmp.set_payload(&quoted);

                Some(CapturedSegment {
                    source: target,
                    protocol: IpNextHeaderProtocols::Icmp,
                    bytes: buffer,
                })
            }
            IpAddr::V6(_) => {
                let mut payload = vec![0u8; ICMPV6_UNUSED_LEN];
                payload.extend_from_slice(&quoted);

                let mut buffer = vec![0u8; Icmpv6Packet::minimum_packet_size() + payload.len()];
                let mut icmp = MutableIcmpv6Packet::new(&mut buffer)?;
                icmp.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
                icmp.set_icmpv6_code(reason.v6());
                icmp.set_payload(&payload);

                Some(CapturedSegment {
                    source: target,
                    protocol: IpNextHeaderProtocols::Icmpv6,
                    bytes: buffer,
                })
            }
        }
    }

    /// Hands a reply to the scanner, honouring the policy's delay and
    /// duplication.
    ///
    /// A delayed reply is spawned rather than awaited: `send` is synchronous
    /// and is called from inside the scanner's own send loop, so blocking here
    /// would stall the very loop the delay is meant to race against.
    fn deliver(&self, segment: CapturedSegment, policy: Policy) {
        let copies = if policy.duplicated { 2 } else { 1 };

        if policy.delay.is_zero() {
            for _ in 0..copies {
                let _ = self.replies.send(segment.clone());
            }
            return;
        }

        let replies = self.replies.clone();
        let delay = policy.delay;
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            for _ in 0..copies {
                // The receiver is gone once the scan ends, which is the normal
                // way a delayed reply that arrived too late is discarded.
                let _ = replies.send(segment.clone());
            }
        });
    }

    fn next_u32(&self) -> u32 {
        (self.state.lock().expect("fake net state").rng.next_u64() >> 32) as u32
    }
}

/// The probe as an ICMP error would quote it: its IP header followed by the
/// datagram itself.
///
/// The header names the protocol the quoted probe actually is. A scanner checks
/// that field before believing a word of the quotation, so announcing a TCP
/// probe as UDP would have every error silently ignored - a simulator bug that
/// looks exactly like a firewall.
fn quote(scanner: IpAddr, target: IpAddr, probe: &[u8], layer4: Layer4) -> Option<Vec<u8>> {
    let len = probe.len() as u16;
    let protocol = match layer4 {
        Layer4::Tcp => IpNextHeaderProtocols::Tcp,
        Layer4::Udp => IpNextHeaderProtocols::Udp,
    };
    let header = match (scanner, target) {
        (IpAddr::V4(s), IpAddr::V4(d)) => ip::create_ipv4_header(s, d, len, protocol).ok()?,
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            ip::create_ipv6_header(s, d, len, protocol, HOP_LIMIT).ok()?
        }
        _ => return None,
    };

    Some(header.into_iter().chain(probe.iter().copied()).collect())
}

/// The default seed, so a net built with [`FakeNet::new`] is still
/// reproducible. Arbitrary; any fixed value would do.
const DEFAULT_SEED: u64 = 0x5EED_1234_5EED_1234;

/// SplitMix64: a small, fast generator with a fixed, documented output
/// sequence. Shared with the link-layer simulator in
/// [`fake_lan`](super::fake_lan), so both tiers reproduce the same way.
///
/// Owned here rather than pulled from `rand` on purpose. `rand` does not
/// promise the same seed yields the same stream across releases, so a
/// dependency bump would quietly change which packets a "reproducible" test
/// drops - and a test whose seed no longer reproduces its failure is worse than
/// no test. Ten lines of arithmetic buys permanent stability.
/// A transport whose send half refuses every probe, standing in for a host that
/// cannot put packets on the wire at all.
///
/// Deliberately not a [`FakeNet`] policy. Every policy there is a statement
/// about the *network* - what a host answers, what the link drops - and
/// [`FakeLink::send`] never fails on purpose, because a scanner must not be
/// able to tell a dropped probe from an ignored one. This is the opposite
/// situation: the probe never reached a network to be dropped by, and the
/// scanner not only may know but has to say so.
///
/// The receive half is a channel nobody ever sends on, which is what a scan with
/// no probes on the wire would hear.
pub fn unsendable_transport(reason: &'static str) -> ProbeTransport {
    /// Holds the receive channel's sending half for as long as the transport
    /// lives. Dropping it would close the stream, and a scanner reads that as
    /// its capture dying and stops - before it has tried to send anything, so
    /// the very failure this exists to produce would never happen. A real
    /// capture is kept alive by its reader threads.
    struct Refuses(&'static str, UnboundedSender<CapturedSegment>);

    impl ProbeSender for Refuses {
        fn send(&self, _segment: &[u8], _src: IpAddr, dst: IpAddr) -> Result<(), SendError> {
            Err(SendError::Refused(format!(
                "failed to send to {dst}: {}",
                self.0
            )))
        }
    }

    let (tx, rx) = mpsc::unbounded_channel();
    ProbeTransport::from_parts(Box::new(Refuses(reason, tx)), rx)
}

pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform draw from `[0, 1)`, using the 53 bits an `f64` represents
    /// exactly.
    pub fn next_unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}
