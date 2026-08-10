// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Probe Transport
//!
//! One handle the raw scanners send probes through and receive replies from,
//! independent of *how* those packets reach the wire.
//!
//! Sending and receiving are deliberately split across two mechanisms,
//! because the constraints differ by direction and by OS:
//!
//! - **Receiving** always goes through a `libpcap` capture
//!   ([`crate::network::capture`]). A raw Layer-4 socket receives replies on
//!   Linux but *not* on macOS/BSD, whose kernels never hand TCP/UDP to raw
//!   sockets; capturing at the link layer is the one path that works
//!   everywhere.
//! - **Sending** goes through a [`ProbeSender`]. The default
//!   [`RawIpSender`] emits segments over a raw Layer-4 socket, which *sends*
//!   fine on every supported Unix (only receiving that way is broken) and
//!   lets the kernel handle routing, ARP/NDP, and fragmentation. A future
//!   Ethernet [`ProbeSender`] can build frames itself for Windows - where
//!   raw TCP sends are blocked - or for deliberately bypassing the host
//!   stack, without any scanner having to know the difference.
//!
//! The trait is what makes that swappable: [`ProbeTransport`] owns a
//! `Box<dyn ProbeSender>` and a capture-fed receive stream, and every scanner
//! depends only on those two things.

use std::net::IpAddr;

use anyhow::Context;
use pnet::datalink;
use pnet::packet::Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};

use crate::core::config::SendMode;
use crate::network::capture::{self, CaptureCounts, CaptureGuard, CaptureStream};
use crate::network::ethernet::EthernetSender;
use crate::network::transport::{self, TransportSenderHandle, TransportType};

/// Which kind of raw probe traffic a [`ProbeTransport`] carries. Determines
/// both the raw socket(s) opened for sending and the kernel BPF filter that
/// decides which captured frames are worth copying to userspace.
#[derive(Debug, Clone, Copy)]
pub enum ProbeKind {
    /// TCP SYN probes and their SYN+ACK / RST replies, over IPv4 and IPv6.
    TcpSyn,
    /// UDP service probes (DNS / mDNS) and their replies, over IPv4.
    UdpResolve,
    /// UDP port probes and their ICMP unreachable / direct UDP replies.
    UdpProbe {
        /// The source port every probe in the scan is sent from, and so the
        /// destination port its direct replies come back to. Sending from one
        /// fixed port is what lets the kernel filter the UDP half down to this
        /// scan's own traffic; without it the only expressible filter is "all
        /// UDP", which on a busy host is mostly other people's packets.
        reply_port: u16,
    },
}

impl ProbeKind {
    /// The raw-socket transport type used for the send half.
    fn transport_type(self) -> TransportType {
        match self {
            ProbeKind::TcpSyn => TransportType::TcpLayer4,
            ProbeKind::UdpResolve | ProbeKind::UdpProbe { .. } => TransportType::UdpLayer4,
        }
    }

    /// The IP protocol number this kind's probes are, for a sender that writes
    /// the IP header itself.
    ///
    /// The raw-socket path never needs this - the kernel derives it from the
    /// socket's protocol - but a Layer-2 sender builds the header by hand and
    /// has nothing else to read it from. A wrong number here is invisible
    /// locally and fatal remotely: the datagram arrives and is handed to the
    /// wrong protocol handler, so it is simply never answered.
    fn ip_protocol(self) -> IpNextHeaderProtocol {
        match self {
            ProbeKind::TcpSyn => IpNextHeaderProtocols::Tcp,
            ProbeKind::UdpResolve | ProbeKind::UdpProbe { .. } => IpNextHeaderProtocols::Udp,
        }
    }

    /// The `libpcap`/`tcpdump` filter expression compiled into a kernel BPF
    /// program for the receive half. Narrow by design: only the replies a
    /// scan can act on ever reach userspace.
    fn filter(self) -> String {
        match self {
            // SYN+ACK (open) and RST (closed) both set at least one of the
            // SYN/RST flag bits; nothing else a SYN probe can elicit does.
            ProbeKind::TcpSyn => "tcp and (tcp[tcpflags] & (tcp-syn|tcp-rst)) != 0".to_string(),
            // DNS (53) and mDNS (5353) responses, by source port.
            ProbeKind::UdpResolve => "udp and (src port 53 or src port 5353)".to_string(),
            // A UDP probe draws two kinds of answer. A direct UDP reply comes
            // back to the port the scan sent from, so it narrows to exactly
            // this scan. An ICMP error carries no ports of its own - the probe
            // it refers to is quoted in its payload - so ICMP cannot be
            // narrowed here and is matched in userspace instead.
            ProbeKind::UdpProbe { reply_port } => {
                format!("icmp or icmp6 or (udp and dst port {reply_port})")
            }
        }
    }
}

/// Sends an already-built Layer-4 `segment` to `dst`.
///
/// `src` is the source address the segment's checksum was computed against;
/// a raw-socket sender lets the kernel stamp it into the IP header, while a
/// link-layer sender uses it to build the header itself. Implementations must
/// be safe to share across threads.
pub trait ProbeSender: Send + Sync {
    fn send(&self, segment: &[u8], src: IpAddr, dst: IpAddr) -> anyhow::Result<()>;
}

/// A borrowed Layer-4 segment presented as a `pnet` packet, so raw bytes can
/// be handed straight to a `TransportSender` without a copy or a typed
/// wrapper. The whole slice is the packet; it has no distinct payload of its
/// own as far as the transport is concerned.
struct RawSegment<'a>(&'a [u8]);

impl Packet for RawSegment<'_> {
    fn packet(&self) -> &[u8] {
        self.0
    }
    fn payload(&self) -> &[u8] {
        &[]
    }
}

/// The default sender: emits segments over a raw Layer-4 socket and lets the
/// kernel route them. Correct on Linux and macOS alike, for both on-link and
/// off-link destinations, with no ARP/NDP or gateway bookkeeping of its own.
pub struct RawIpSender {
    handle: TransportSenderHandle,
}

impl RawIpSender {
    fn open(kind: ProbeKind) -> anyhow::Result<Self> {
        Ok(Self {
            handle: transport::open_sender(kind.transport_type())?,
        })
    }
}

impl ProbeSender for RawIpSender {
    fn send(&self, segment: &[u8], _src: IpAddr, dst: IpAddr) -> anyhow::Result<()> {
        self.handle.send_to(RawSegment(segment), dst).map(|_| ())
    }
}

/// A sender that refuses to send. Paired with a capture for receive-only
/// transports (the DNS/mDNS resolver only listens), so no raw send socket is
/// opened just to be thrown away - and a stray send attempt fails loudly
/// rather than silently doing nothing.
struct NoopSender;

impl ProbeSender for NoopSender {
    fn send(&self, _segment: &[u8], _src: IpAddr, _dst: IpAddr) -> anyhow::Result<()> {
        anyhow::bail!("this transport is receive-only and cannot send")
    }
}

/// A probe transport: a swappable sender paired with a capture-fed receive
/// stream. Scanners hold one of these and depend only on [`ProbeTransport::tx`]
/// and [`ProbeTransport::rx`], never on how either is realized.
pub struct ProbeTransport {
    /// The send half. Boxed so the backend (raw socket today, Ethernet later)
    /// can vary without touching callers.
    pub tx: Box<dyn ProbeSender>,
    /// Parsed replies ([`capture::CapturedSegment`]), merged across every
    /// captured interface.
    pub rx: CaptureStream,
    /// Keeps the capture threads alive for this transport's lifetime, and holds
    /// the counters they publish.
    capture: CaptureGuard,
}

impl ProbeTransport {
    /// What the receive path's kernel buffers have done so far, summed over
    /// every interface this transport captures on.
    ///
    /// A scanner reports this alongside its own counters because the two answer
    /// different halves of the same question. The scanner knows how many replies
    /// it saw; only this knows how many arrived and were thrown away before it
    /// could. `None` for a transport with no capture behind it, so a synthetic
    /// receive stream never reports a clean receive path it never had.
    pub fn capture_counts(&self) -> Option<CaptureCounts> {
        self.capture.counts()
    }
    /// Opens a transport for `kind` with the platform-default send backend
    /// ([`SendMode::Auto`]).
    pub fn open(kind: ProbeKind) -> anyhow::Result<Self> {
        Self::open_with(kind, SendMode::Auto)
    }

    /// Opens a transport for `kind`, choosing the send backend per `mode`.
    ///
    /// All modes pair with a filtered `libpcap` capture on every currently-up
    /// interface. Capturing on all of them (loopback included) means a reply
    /// is caught whichever interface the kernel routed the probe out of - the
    /// egress path can differ per destination, especially with a VPN in play,
    /// so binding to a single guessed interface would silently miss replies.
    pub fn open_with(kind: ProbeKind, mode: SendMode) -> anyhow::Result<Self> {
        match mode {
            SendMode::Ethernet => Self::open_ethernet(kind),
            SendMode::RawSocket => Self::open_on(kind, &capturable_interfaces()),
            // On Windows raw-socket TCP sends are blocked, so Layer-2 is the
            // only path; everywhere else the raw socket is simplest and works
            // through tunnels without ARP.
            SendMode::Auto => {
                #[cfg(windows)]
                {
                    Self::open_ethernet(kind)
                }
                #[cfg(not(windows))]
                {
                    Self::open_on(kind, &capturable_interfaces())
                }
            }
        }
    }

    /// [`open`](Self::open) against an explicit interface-name list.
    pub fn open_on(kind: ProbeKind, interfaces: &[String]) -> anyhow::Result<Self> {
        let (rx, capture) = capture::start(interfaces, &kind.filter())?;
        let tx: Box<dyn ProbeSender> = Box::new(RawIpSender::open(kind)?);
        Ok(Self { tx, rx, capture })
    }

    /// Opens a transport whose send half builds and emits Ethernet frames
    /// directly ([`EthernetSender`]) instead of using a raw socket.
    ///
    /// For Windows (where raw TCP sends are blocked) and for deliberately
    /// bypassing the host stack. Fails if the host has no Ethernet-capable
    /// interface - only a tunnel or loopback - in which case the raw-IP
    /// transport from [`open`](Self::open) is the correct choice.
    pub fn open_ethernet(kind: ProbeKind) -> anyhow::Result<Self> {
        let sender = EthernetSender::from_system(kind.ip_protocol())
            .context("no Ethernet-capable interface for Layer-2 send")?;
        let (rx, capture) = capture::start(&capturable_interfaces(), &kind.filter())?;
        Ok(Self {
            tx: Box::new(sender),
            rx,
            capture,
        })
    }

    /// Opens a receive-only transport: a filtered capture on every up
    /// interface, with a sender that refuses to send.
    ///
    /// For consumers that only listen - the passive DNS/mDNS resolver never
    /// emits raw packets - so no raw send socket is opened. That drops an
    /// unnecessary privilege requirement and failure mode (a host that blocks
    /// raw sockets can still resolve hostnames).
    pub fn open_receiver(kind: ProbeKind) -> anyhow::Result<Self> {
        let (rx, capture) = capture::start(&capturable_interfaces(), &kind.filter())?;
        Ok(Self {
            tx: Box::new(NoopSender),
            rx,
            capture,
        })
    }

    /// Builds a transport from an explicit sender and receive stream, opening
    /// no socket and no capture.
    ///
    /// This is the seam that lets a test stand a scanner up against a synthetic
    /// network: `tx` observes the probes the scanner emits, and whatever is
    /// pushed onto the sending half of `rx` arrives as though it had been
    /// captured off the wire. Because no capture threads exist, the transport
    /// holds an inert [`CaptureGuard`] and dropping it stops nothing.
    ///
    /// Requires the `test-support` feature outside this crate.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_parts(tx: Box<dyn ProbeSender>, rx: CaptureStream) -> Self {
        Self {
            tx,
            rx,
            capture: CaptureGuard::noop(),
        }
    }
}

/// The interfaces a capture should listen on: every interface that's up.
/// Loopback is intentionally included so localhost probes are still heard.
fn capturable_interfaces() -> Vec<String> {
    datalink::interfaces()
        .into_iter()
        .filter(|iface| iface.is_up())
        .map(|iface| iface.name)
        .collect()
}

/// A record of one recorded send: `(segment, source, destination)`.
#[cfg(test)]
pub type SentProbe = (Vec<u8>, IpAddr, IpAddr);

/// A [`ProbeSender`] that records what it was asked to send instead of
/// touching a socket, so transport wiring and scanner logic can be exercised
/// without root. Available crate-wide under `cfg(test)`.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct MockSender {
    pub sent: std::sync::Arc<std::sync::Mutex<Vec<SentProbe>>>,
}

#[cfg(test)]
impl ProbeSender for MockSender {
    fn send(&self, segment: &[u8], src: IpAddr, dst: IpAddr) -> anyhow::Result<()> {
        self.sent.lock().unwrap().push((segment.to_vec(), src, dst));
        Ok(())
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

    #[tokio::test]
    async fn transport_forwards_sends_and_delivers_replies() {
        use crate::network::capture::CapturedSegment;
        use std::net::Ipv4Addr;

        let mock = MockSender::default();
        let recorded = mock.sent.clone();
        let (reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut transport = ProbeTransport::from_parts(Box::new(mock), reply_rx);

        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let dst = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        transport.tx.send(&[0xAA, 0xBB], src, dst).unwrap();

        let sent = recorded.lock().unwrap().clone();
        assert_eq!(sent, vec![(vec![0xAA, 0xBB], src, dst)]);

        // A reply pushed onto the capture stream is observed on rx unchanged.
        let reply = CapturedSegment {
            source: dst,
            protocol: pnet::packet::ip::IpNextHeaderProtocols::Udp,
            bytes: vec![1, 2, 3],
        };
        reply_tx.send(reply.clone()).unwrap();
        assert_eq!(transport.rx.recv().await, Some(reply));
    }

    /// A Layer-2 sender writes the IP header itself and has nothing but this to
    /// read the protocol number from. Announcing a UDP probe as TCP is
    /// invisible locally and fatal remotely - the target's stack hands it to
    /// the wrong protocol handler, so it is simply never answered.
    #[test]
    fn every_probe_kind_carries_its_own_ip_protocol() {
        assert_eq!(ProbeKind::TcpSyn.ip_protocol(), IpNextHeaderProtocols::Tcp);
        assert_eq!(
            ProbeKind::UdpResolve.ip_protocol(),
            IpNextHeaderProtocols::Udp
        );
        assert_eq!(
            ProbeKind::UdpProbe { reply_port: 40_000 }.ip_protocol(),
            IpNextHeaderProtocols::Udp
        );
    }

    /// The UDP filter must narrow direct replies to the scan's own source port,
    /// while leaving ICMP unnarrowed - an ICMP error carries no port to match on.
    #[test]
    fn udp_probe_filter_narrows_replies_to_the_scan_source_port() {
        let filter = ProbeKind::UdpProbe { reply_port: 54_321 }.filter();
        assert_eq!(filter, "icmp or icmp6 or (udp and dst port 54321)");
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Filter conformance
// ══════════════════════════════════════════════════════════════════════════════

/// What each [`ProbeKind`]'s filter actually admits, judged by `libpcap` rather
/// than by reading the expression.
///
/// These are the only tests in the crate that exercise the receive path's real
/// gatekeeper. Every scanner test drives a synthetic transport through
/// [`ProbeTransport::from_parts`], which opens no capture and therefore compiles
/// no filter: a reply pushed onto that stream arrives whatever the filter would
/// have done with it. So a scanner test can pass against a simulated network
/// while the same scan on a real one sees nothing at all, and the only way to
/// tell is to compile the expression and put a frame through it.
///
/// The evaluation is `libpcap`'s own `pcap_offline_filter` running the compiled
/// program - the same program the kernel is handed - over a frame built by this
/// crate's own packet builders. Nothing here re-implements a filter or a parser,
/// which is the point: an instrument that made the same assumptions as the code
/// it measures would confirm whatever the code already believed.
#[cfg(test)]
mod filter_conformance {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Types, MutableIcmpv6Packet};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::tcp::MutableTcpPacket;
    use pnet::util::MacAddr;

    use super::ProbeKind;
    use crate::network::frame::build_ethernet_frame;
    use crate::protocols::udp;

    const SRC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    const DST_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
    const SRC_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10));
    const DST_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x20));

    const SYN: u8 = 1 << 1;
    const RST: u8 = 1 << 2;
    const ACK: u8 = 1 << 4;

    const TCP_HDR_LEN: usize = 20;
    const ICMPV6_UNUSED_LEN: usize = 4;

    /// Whether `filter`, compiled for an Ethernet link, admits `frame`.
    ///
    /// A dead capture is a compiler with no interface behind it, so this needs
    /// neither privileges nor a network.
    fn admits(filter: &str, frame: &[u8]) -> bool {
        let capture = pcap::Capture::dead(pcap::Linktype::ETHERNET)
            .expect("opening a dead capture for the Ethernet link type");
        let program = capture
            .compile(filter, true)
            .unwrap_or_else(|e| panic!("compiling `{filter}`: {e}"));
        program.filter(frame)
    }

    /// An Ethernet-framed TCP segment carrying `flags`, over whichever family
    /// `src` and `dst` are.
    fn tcp_frame(src: IpAddr, dst: IpAddr, flags: u8) -> Vec<u8> {
        let mut segment = vec![0u8; TCP_HDR_LEN];
        {
            let mut tcp = MutableTcpPacket::new(&mut segment).expect("TCP header buffer");
            tcp.set_source(443);
            tcp.set_destination(50_000);
            tcp.set_data_offset((TCP_HDR_LEN / 4) as u8);
            tcp.set_flags(flags);
            tcp.set_window(1024);
        }
        frame(src, dst, IpNextHeaderProtocols::Tcp, &segment)
    }

    /// An Ethernet-framed UDP datagram between the given ports.
    fn udp_frame(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16) -> Vec<u8> {
        let segment = udp::create_packet(&src, &dst, src_port, dst_port, vec![0u8; 4])
            .expect("building a UDP datagram");
        frame(src, dst, IpNextHeaderProtocols::Udp, &segment)
    }

    /// An Ethernet-framed ICMPv6 destination-unreachable, the shape a UDP probe
    /// draws from a closed port over IPv6.
    fn icmpv6_error_frame(src: IpAddr, dst: IpAddr) -> Vec<u8> {
        let mut segment = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ICMPV6_UNUSED_LEN];
        {
            let mut icmp = MutableIcmpv6Packet::new(&mut segment).expect("ICMPv6 header buffer");
            icmp.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
            icmp.set_icmpv6_code(Icmpv6Code(4));
        }
        frame(src, dst, IpNextHeaderProtocols::Icmpv6, &segment)
    }

    fn frame(
        src: IpAddr,
        dst: IpAddr,
        protocol: pnet::packet::ip::IpNextHeaderProtocol,
        segment: &[u8],
    ) -> Vec<u8> {
        build_ethernet_frame(
            MacAddr::new(0x02, 0, 0, 0, 0, 0x02),
            MacAddr::new(0x02, 0, 0, 0, 0, 0x01),
            src,
            dst,
            protocol,
            segment,
        )
        .expect("building an Ethernet frame")
    }

    // ─── TCP SYN ─────────────────────────────────────────────────────────────

    #[test]
    fn the_syn_filter_admits_the_two_answers_a_syn_probe_draws_over_ipv4() {
        let filter = ProbeKind::TcpSyn.filter();

        assert!(
            admits(&filter, &tcp_frame(SRC_V4, DST_V4, SYN | ACK)),
            "a SYN+ACK is an open port and must reach the scanner"
        );
        assert!(
            admits(&filter, &tcp_frame(SRC_V4, DST_V4, RST | ACK)),
            "a RST is a closed port and must reach the scanner"
        );
    }

    /// The filter exists to keep unrelated traffic out of userspace, so an
    /// established connection's segments must not reach the scanner.
    #[test]
    fn the_syn_filter_rejects_established_traffic_over_ipv4() {
        assert!(!admits(
            &ProbeKind::TcpSyn.filter(),
            &tcp_frame(SRC_V4, DST_V4, ACK)
        ));
    }

    /// The gap this module was written to expose.
    ///
    /// `tcp[tcpflags]` is `proto[x]` indexing, which `libpcap` cannot compile
    /// over IPv6 - the next-header chain makes the offset non-constant. It does
    /// not report that; it silently narrows the whole expression to IPv4, and
    /// the compiled program jumps straight to `ret #0` on EtherType `0x86dd`.
    /// Since the capture is the only receive path, routed IPv6 discovery and
    /// IPv6 SYN port scanning currently see no replies whatsoever.
    ///
    /// Ignored rather than deleted: the assertion is what the fix has to make
    /// true, and a filter that admits IPv6 is the whole of phase 1 in
    /// `docs/ipv6.md`.
    #[test]
    #[ignore = "known gap: the SYN filter is IPv4-only; see docs/ipv6.md phase 1"]
    fn the_syn_filter_admits_the_same_answers_over_ipv6() {
        let filter = ProbeKind::TcpSyn.filter();

        assert!(admits(&filter, &tcp_frame(SRC_V6, DST_V6, SYN | ACK)));
        assert!(admits(&filter, &tcp_frame(SRC_V6, DST_V6, RST | ACK)));
    }

    /// Why the test above cannot be fixed by asking for IPv6 explicitly, and
    /// the constraint any replacement expression has to work around.
    ///
    /// This is the standing record of a `libpcap` limitation the engine has to
    /// design around rather than a choice it made. Should a future `libpcap`
    /// learn to index into IPv6, this test is what notices.
    #[test]
    fn libpcap_cannot_narrow_tcp_flags_over_ipv6() {
        let narrowed = "ip6 and tcp and (tcp[tcpflags] & (tcp-syn|tcp-rst)) != 0";
        let capture = pcap::Capture::dead(pcap::Linktype::ETHERNET).expect("dead capture");

        let admits_a_syn_ack = capture
            .compile(narrowed, true)
            .map(|program| program.filter(&tcp_frame(SRC_V6, DST_V6, SYN | ACK)))
            .unwrap_or(false);

        assert!(
            !admits_a_syn_ack,
            "libpcap now narrows TCP flags over IPv6; the split filter is no longer needed"
        );
    }

    // ─── UDP ─────────────────────────────────────────────────────────────────

    /// The resolver's filter is family-agnostic, and has to stay that way: a
    /// DNS or mDNS answer over IPv6 names hosts just as well as one over IPv4.
    #[test]
    fn the_resolve_filter_admits_dns_answers_over_both_families() {
        let filter = ProbeKind::UdpResolve.filter();

        assert!(admits(&filter, &udp_frame(SRC_V4, DST_V4, 53, 40_000)));
        assert!(admits(&filter, &udp_frame(SRC_V6, DST_V6, 53, 40_000)));
        assert!(admits(&filter, &udp_frame(SRC_V6, DST_V6, 5353, 5353)));
        assert!(
            !admits(&filter, &udp_frame(SRC_V6, DST_V6, 12_345, 40_000)),
            "traffic from an unrelated source port is not an answer to anything"
        );
    }

    /// Both answers a UDP probe can draw, over both families. `icmp6` is what
    /// carries the IPv6 half here, and it is the reason UDP port scanning is the
    /// one raw path that already works over IPv6.
    #[test]
    fn the_udp_probe_filter_admits_direct_replies_and_icmp_errors_over_both_families() {
        const REPLY_PORT: u16 = 40_000;
        let filter = ProbeKind::UdpProbe {
            reply_port: REPLY_PORT,
        }
        .filter();

        assert!(admits(&filter, &udp_frame(SRC_V4, DST_V4, 53, REPLY_PORT)));
        assert!(admits(&filter, &udp_frame(SRC_V6, DST_V6, 53, REPLY_PORT)));
        assert!(admits(&filter, &icmpv6_error_frame(SRC_V6, DST_V6)));
        assert!(
            !admits(&filter, &udp_frame(SRC_V6, DST_V6, 53, REPLY_PORT + 1)),
            "a datagram to a port this scan never sent from is somebody else's"
        );
    }
}
