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
//!   ([`crate::transport::capture`]). A raw Layer-4 socket receives replies on
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

use pnet_packet::Packet;
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};

use crate::config::SendMode;
use crate::model::capture::CaptureCounts;
use crate::model::ip::scoped::Zone;
use crate::transport::capture::{self, CaptureGuard, CaptureOptions, CaptureStream};
use crate::transport::link::EthernetSender;
use crate::transport::raw::{self, TransportSenderHandle, TransportType};

/// Which kind of raw probe traffic a [`ProbeTransport`] carries. Determines
/// both the raw socket(s) opened for sending and the kernel BPF filter that
/// decides which captured frames are worth copying to userspace.
#[derive(Debug, Clone, Copy)]
pub enum ProbeKind {
    /// TCP SYN probes and their SYN+ACK / RST replies, over IPv4 and IPv6,
    /// where the sender picks a fresh source port per probe.
    TcpSyn,
    /// TCP port probes and their replies, for a scan that sends every probe
    /// from one source port.
    TcpProbe {
        /// The port every probe in the scan leaves from, and so the port its
        /// replies come back to. One fixed port is what makes the TCP half of
        /// this filter expressible for **both** address families: `dst port`
        /// compiles over IPv6 where the flag test in [`ProbeKind::TcpSyn`]
        /// cannot, so a scan using this kind sees only its own answers instead
        /// of every IPv6 TCP segment on the host.
        reply_port: u16,
        /// Whether ICMP destination-unreachable messages are wanted as well.
        ///
        /// They are how a probe learns it was stopped in the path rather than
        /// answered, but an ICMP error carries no ports of its own - the probe
        /// it refers to is quoted in its payload - so admitting them means
        /// admitting *all* ICMP on every captured interface and matching it in
        /// userspace. Only a scan whose verdicts actually change on that
        /// evidence should pay for it.
        icmp_errors: bool,
    },
    /// UDP service probes (DNS / mDNS) and their replies, over IPv4.
    UdpResolve,
    /// ICMP echo requests and the replies and errors they draw, over both
    /// address families.
    ///
    /// The kind a scan uses to ask a host something its TCP stack cannot be made
    /// to answer — a host with no open and no closed port still answers a ping,
    /// and what it puts in the reply is a property of the same stack.
    IcmpEcho {
        /// The identifier every echo in the scan carries, and so the one its
        /// replies carry back.
        ///
        /// RFC 792 and RFC 4443 §4.2 both require a reply to echo the
        /// identifier and sequence back unchanged, which is the only thing that
        /// separates this scan's answers from every other ping on the host —
        /// and unlike a port, it cannot be expressed in a kernel filter, since
        /// it sits past a header whose length is not fixed over IPv6. So it is
        /// matched in userspace and this field is what a caller matches against.
        identifier: u16,
    },
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
            ProbeKind::TcpSyn | ProbeKind::TcpProbe { .. } => TransportType::TcpLayer4,
            ProbeKind::UdpResolve | ProbeKind::UdpProbe { .. } => TransportType::UdpLayer4,
            ProbeKind::IcmpEcho { .. } => TransportType::IcmpLayer4,
        }
    }

    /// The IP protocol numbers this kind's probes are, one per address family,
    /// for a sender that writes the IP header itself.
    ///
    /// The raw-socket path never needs this - the kernel derives it from the
    /// socket's protocol - but a Layer-2 sender builds the header by hand and
    /// has nothing else to read it from. A wrong number here is invisible
    /// locally and fatal remotely: the datagram arrives and is handed to the
    /// wrong protocol handler, so it is simply never answered.
    fn ip_protocols(self) -> IpProtocols {
        match self {
            ProbeKind::TcpSyn | ProbeKind::TcpProbe { .. } => {
                IpProtocols::same(IpNextHeaderProtocols::Tcp)
            }
            ProbeKind::UdpResolve | ProbeKind::UdpProbe { .. } => {
                IpProtocols::same(IpNextHeaderProtocols::Udp)
            }
            // The one kind whose two families are different protocols rather
            // than one protocol over two address sizes.
            ProbeKind::IcmpEcho { .. } => IpProtocols {
                v4: IpNextHeaderProtocols::Icmp,
                v6: IpNextHeaderProtocols::Icmpv6,
            },
        }
    }

    /// The `libpcap`/`tcpdump` filter expression compiled into a kernel BPF
    /// program for the receive half. Narrow by design: only the replies a
    /// scan can act on ever reach userspace.
    fn filter(self) -> String {
        match self {
            // SYN+ACK (open) and RST (closed) both set at least one of the
            // SYN/RST flag bits; nothing else a SYN probe can elicit does.
            //
            // The two families are narrowed differently because only one of
            // them can be. `tcp[tcpflags]` is `proto[x]` indexing, and an IPv6
            // next-header chain puts the transport header at no fixed offset,
            // so libpcap cannot compile it - and does not say so. Written as one
            // unqualified `tcp`, the expression is silently restricted to IPv4
            // and every IPv6 frame is rejected at the EtherType, which is what
            // made routed IPv6 discovery and IPv6 SYN port scanning find nothing
            // whatsoever. Writing `ip6` in front of the same test does not help;
            // it fails to compile outright.
            //
            // So the IPv6 half is admitted unnarrowed and the flags are checked
            // in userspace instead. The cost is that every IPv6 TCP segment on
            // every captured interface is copied up, not only the two a probe
            // can draw: on a host with live IPv6 connections that is real
            // traffic, and it lands in the audit's `off-target` count where it
            // can be seen. It buys the only IPv6 receive path there is.
            ProbeKind::TcpSyn => {
                "(ip and tcp and (tcp[tcpflags] & (tcp-syn|tcp-rst)) != 0) or (ip6 and tcp)"
                    .to_string()
            }
            // Every reply to a probe of this kind is addressed back to the one
            // port the scan sends from, so that is the whole narrowing - and it
            // is a narrowing both families get, which the flag test above is
            // not. What reaches userspace is this scan's own traffic rather
            // than every segment that happens to carry a SYN or RST bit.
            //
            // The flags are checked in userspace instead. That is not a
            // concession: a segment answering the right port still has to be
            // one of the two answers a probe can draw, and has to carry back
            // the value the probe went out with.
            ProbeKind::TcpProbe {
                reply_port,
                icmp_errors,
            } => {
                let tcp = format!("tcp and dst port {reply_port}");
                // An ICMP error names no ports of its own; the probe it refers
                // to is quoted in its payload, so this half cannot be narrowed
                // here and is matched in userspace.
                if icmp_errors {
                    format!("icmp or icmp6 or ({tcp})")
                } else {
                    tcp
                }
            }
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
            // Unnarrowed, and it has to be. The identifier that separates this
            // scan's replies from every other ping on the host sits four bytes
            // into the ICMP message, which is `proto[x]` indexing — expressible
            // over IPv4 and not over IPv6, whose next-header chain puts the
            // message at no fixed offset. Narrowing one family and not the other
            // would make the IPv6 half of every scan silently different from the
            // IPv4 half, which is the shape of defect that cost this crate its
            // whole IPv6 receive path once already. So both halves come up whole
            // and the identifier is matched in userspace.
            //
            // The errors are wanted as well as the replies: a host that answers
            // an echo with "administratively prohibited" has told you something,
            // and it did not come from the host's own stack.
            ProbeKind::IcmpEcho { .. } => "icmp or icmp6".to_string(),
        }
    }
}

/// Why one probe could not be put on the wire.
///
/// Two variants, because two things are worth telling apart and nothing else is.
/// [`Unsupported`](Self::Unsupported) is a fact about this transport that will
/// be just as true for the next probe — retrying is pointless and a scan should
/// give up on the path. [`Refused`](Self::Refused) came from outside and may not
/// hold next time: a full send buffer clears, a route appears.
///
/// The refusal carries the operating system's own words rather than a
/// classification of them. "No route to host" and "Permission denied" call for
/// completely different responses from whoever is reading the report, and no
/// enum this crate could write would keep pace with what a kernel actually says.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// This host has no route to that address.
    ///
    /// Separated from [`Refused`](Self::Refused) because it is a fact about the
    /// *destination* rather than about this scanner or its socket, and the two
    /// call for opposite responses. A send path that will not work is a strategy
    /// that did not run, and a caller has to be told the scan covered less than
    /// it was asked to. An address with no route is ordinary: a dual-stack name
    /// on an IPv4-only network resolves to an AAAA nobody here can reach, and
    /// reporting that as a broken scan makes every such scan look partial.
    ///
    /// Still an error, and still reported — the address was asked about and not
    /// covered — but as something known about that address.
    #[error("{0}")]
    Unroutable(String),

    /// The host would not send the packet, in its own words.
    #[error("{0}")]
    Refused(String),

    /// This transport cannot express the probe it was handed, and will not be
    /// able to next time either.
    #[error("this transport cannot send that probe: {0}")]
    Unsupported(&'static str),
}

impl SendError {
    /// Classifies a failure from a lower layer, keeping its whole cause chain.
    ///
    /// `{e:#}` rather than `{e}`: the outer message says which probe failed and
    /// the chain is the operating system's own explanation, which is the half
    /// that says what to do about it.
    ///
    /// Reads the operating system's own error kind rather than matching on the
    /// text of its message, which differs per platform and per locale. Only the
    /// two unreachable kinds are singled out; everything else stays a refusal,
    /// including the ones that look similar — a full send buffer or a permission
    /// failure says nothing about whether the destination exists.
    pub(crate) fn from_io(error: anyhow::Error) -> Self {
        let unroutable = error.chain().any(|cause| {
            cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
                matches!(
                    io.kind(),
                    std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NetworkUnreachable
                )
            })
        });

        if unroutable {
            Self::Unroutable(format!("{error:#}"))
        } else {
            Self::Refused(format!("{error:#}"))
        }
    }

    /// Whether this failure is about the destination rather than about the
    /// sending host.
    ///
    /// What separates "the scan could not run" from "that address is not
    /// reachable from here", which are reported differently and should be.
    pub fn is_unroutable(&self) -> bool {
        matches!(self, Self::Unroutable(_))
    }
}

/// What a caller decides about the IP header carrying a probe, as opposed to
/// what the packet itself decides.
///
/// Addresses, protocol number, lengths and checksums all follow from the probe
/// and its destination, so a sender derives them. What is left is the handful of
/// header fields nothing downstream can infer, and today that is exactly one:
/// how far the probe may travel.
///
/// It is a value rather than a bare `u8` because it is the seam every remaining
/// per-probe header choice arrives through — fragmentation, IP options, a
/// deliberately wrong checksum — and each of those should widen this struct
/// rather than the signature of every sender in the crate a second time.
///
/// Both backends can honour it, by different means: the link-layer sender is
/// already building the header and simply writes the field, while the raw-socket
/// sender sets it on the socket before the send, under the lock that serialises
/// sends anyway. See [`raw::TransportSenderHandle::send_to`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Emission {
    /// How many hops the probe may cross before a router discards it and
    /// reports having done so.
    pub hop_limit: u8,
}

impl Emission {
    /// What an ordinary probe wants: far enough for any path on the public
    /// internet. See [`ip::HOP_LIMIT_ROUTED`](crate::protocols::ip::HOP_LIMIT_ROUTED).
    pub const fn routed() -> Self {
        Self {
            hop_limit: crate::protocols::ip::HOP_LIMIT_ROUTED,
        }
    }

    /// A probe built to die `hops` routers away, so that the router which
    /// discards it names itself in the error it must send back.
    ///
    /// The whole of how a path is measured. A hop limit of zero would be
    /// discarded by this host's own stack before it reached a wire, so it is
    /// raised to one — the first router — rather than silently sending nothing.
    pub const fn at_hop(hops: u8) -> Self {
        Self {
            hop_limit: if hops == 0 { 1 } else { hops },
        }
    }
}

impl Default for Emission {
    fn default() -> Self {
        Self::routed()
    }
}

/// Sends an already-built Layer-4 `segment` to `dst`.
///
/// `src` is the source address the segment's checksum was computed against;
/// a raw-socket sender lets the kernel stamp it into the IP header, while a
/// link-layer sender uses it to build the header itself. `emission` is what the
/// caller decides about that header; see [`Emission`]. Implementations must be
/// safe to share across threads.
pub trait ProbeSender: Send + Sync {
    fn send(
        &self,
        segment: &[u8],
        src: IpAddr,
        dst: IpAddr,
        emission: Emission,
    ) -> Result<(), SendError>;
}

/// The IP protocol number a kind's probes carry, per address family.
///
/// A pair rather than one value because [`ProbeKind::IcmpEcho`] is two
/// protocols: ICMP is next-header 1 and ICMPv6 is 58. Every other kind names the
/// same protocol twice, which [`same`](Self::same) says out loud rather than
/// leaving to a reader to notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpProtocols {
    /// What an IPv4 header carrying this kind's probes says it carries.
    pub v4: IpNextHeaderProtocol,
    /// What an IPv6 header carrying this kind's probes says it carries.
    pub v6: IpNextHeaderProtocol,
}

impl IpProtocols {
    /// One protocol under both families.
    pub const fn same(protocol: IpNextHeaderProtocol) -> Self {
        Self {
            v4: protocol,
            v6: protocol,
        }
    }

    /// The number to stamp into a header addressed to `destination`.
    pub const fn for_destination(self, destination: IpAddr) -> IpNextHeaderProtocol {
        match destination {
            IpAddr::V4(_) => self.v4,
            IpAddr::V6(_) => self.v6,
        }
    }
}

/// Why a probe transport could not be opened.
///
/// Named by the half that failed, because the two halves fail for different
/// reasons and only one of them has an alternative. A scan that cannot capture
/// has nowhere to hear an answer and is over; a scan that cannot open its send
/// socket may still have a link-layer path, which is what [`SendMode`] selects.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The receive half could not be started.
    #[error("the reply capture could not be started: {0}")]
    Capture(#[from] capture::CaptureError),

    /// The raw send socket could not be opened. Needs root, and on Windows raw
    /// TCP sends are blocked outright whatever the privileges.
    #[error("the raw send socket could not be opened: {0}")]
    RawSocket(String),

    /// Layer-2 sending was asked for and this host has nothing to send from —
    /// only tunnels or loopback. The raw-socket path is the one that works here.
    #[error("no Ethernet-capable interface for Layer-2 send: {0}")]
    NoEthernetInterface(String),
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
    fn open(kind: ProbeKind) -> Result<Self, TransportError> {
        raw::open_sender(kind.transport_type())
            .map(|handle| Self { handle })
            .map_err(|e| TransportError::RawSocket(format!("{e:#}")))
    }
}

impl ProbeSender for RawIpSender {
    fn send(
        &self,
        segment: &[u8],
        _src: IpAddr,
        dst: IpAddr,
        emission: Emission,
    ) -> Result<(), SendError> {
        self.handle
            .send_to(RawSegment(segment), dst, emission.hop_limit)
            .map(|_| ())
            .map_err(SendError::from_io)
    }
}

/// A sender that refuses to send. Paired with a capture for receive-only
/// transports (the DNS/mDNS resolver only listens), so no raw send socket is
/// opened just to be thrown away - and a stray send attempt fails loudly
/// rather than silently doing nothing.
struct NoopSender;

impl ProbeSender for NoopSender {
    fn send(
        &self,
        _segment: &[u8],
        _src: IpAddr,
        _dst: IpAddr,
        _emission: Emission,
    ) -> Result<(), SendError> {
        Err(SendError::Unsupported("it is receive-only"))
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
    pub fn open(kind: ProbeKind) -> Result<Self, TransportError> {
        Self::open_with(kind, SendMode::Auto)
    }

    /// Opens a transport for `kind`, choosing the send backend per `mode`.
    ///
    /// All modes pair with a filtered `libpcap` capture on every currently-up
    /// interface. Capturing on all of them (loopback included) means a reply
    /// is caught whichever interface the kernel routed the probe out of - the
    /// egress path can differ per destination, especially with a VPN in play,
    /// so binding to a single guessed interface would silently miss replies.
    pub fn open_with(kind: ProbeKind, mode: SendMode) -> Result<Self, TransportError> {
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

    /// [`open`](Self::open) against an explicit list of links.
    pub fn open_on(kind: ProbeKind, links: &[Zone]) -> Result<Self, TransportError> {
        let (rx, capture) = capture::segments(links, &CaptureOptions::for_replies(kind.filter()))?;
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
    pub fn open_ethernet(kind: ProbeKind) -> Result<Self, TransportError> {
        let sender = EthernetSender::from_system(kind.ip_protocols()).ok_or_else(|| {
            TransportError::NoEthernetInterface(
                "the host has only tunnel or loopback interfaces".to_string(),
            )
        })?;
        let (rx, capture) = capture::segments(
            &capturable_interfaces(),
            &CaptureOptions::for_replies(kind.filter()),
        )?;
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
    pub fn open_receiver(kind: ProbeKind) -> Result<Self, TransportError> {
        let (rx, capture) = capture::segments(
            &capturable_interfaces(),
            &CaptureOptions::for_replies(kind.filter()),
        )?;
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
///
/// Each is named as a [`Zone`], carrying the index alongside the name. The
/// index costs nothing to keep here — the interface table was already read to
/// find the name — and it is what a finding scoped to a link needs, since a
/// link-local address names a different machine on every one of them.
fn capturable_interfaces() -> Vec<Zone> {
    crate::system::interface::interfaces()
        .into_iter()
        .filter(crate::system::interface::Link::is_up)
        .map(|link| link.zone())
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
    fn send(
        &self,
        segment: &[u8],
        src: IpAddr,
        dst: IpAddr,
        _emission: Emission,
    ) -> Result<(), SendError> {
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
        use crate::transport::capture::CapturedSegment;
        use std::net::Ipv4Addr;

        let mock = MockSender::default();
        let recorded = mock.sent.clone();
        let (reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut transport = ProbeTransport::from_parts(Box::new(mock), reply_rx);

        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let dst = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        transport
            .tx
            .send(&[0xAA, 0xBB], src, dst, Emission::routed())
            .unwrap();

        let sent = recorded.lock().unwrap().clone();
        assert_eq!(sent, vec![(vec![0xAA, 0xBB], src, dst)]);

        // A reply pushed onto the capture stream is observed on rx unchanged.
        let reply = CapturedSegment::synthetic(
            dst,
            pnet_packet::ip::IpNextHeaderProtocols::Udp,
            vec![1, 2, 3],
        );
        reply_tx.send(reply.clone()).unwrap();
        assert_eq!(transport.rx.recv().await, Some(reply));
    }

    /// A Layer-2 sender writes the IP header itself and has nothing but this to
    /// read the protocol number from. Announcing a UDP probe as TCP is
    /// invisible locally and fatal remotely - the target's stack hands it to
    /// the wrong protocol handler, so it is simply never answered.
    #[test]
    fn every_probe_kind_carries_its_own_ip_protocol() {
        assert_eq!(
            ProbeKind::TcpSyn.ip_protocols(),
            IpProtocols::same(IpNextHeaderProtocols::Tcp)
        );
        assert_eq!(
            ProbeKind::TcpProbe {
                reply_port: 50_000,
                icmp_errors: true,
            }
            .ip_protocols(),
            IpProtocols::same(IpNextHeaderProtocols::Tcp)
        );
        assert_eq!(
            ProbeKind::UdpResolve.ip_protocols(),
            IpProtocols::same(IpNextHeaderProtocols::Udp)
        );
        assert_eq!(
            ProbeKind::UdpProbe { reply_port: 40_000 }.ip_protocols(),
            IpProtocols::same(IpNextHeaderProtocols::Udp)
        );
    }

    /// ICMP is the one kind whose families are different protocols, and the
    /// number is chosen by the destination rather than by the kind.
    ///
    /// Pinned because getting it wrong is silent: an ICMPv6 message announced as
    /// protocol 1 is delivered to a handler that will not recognise it, and the
    /// probe simply goes unanswered. A scan reading that as "the host did not
    /// reply" is wrong about the host.
    #[test]
    fn an_icmp_probe_names_a_different_protocol_per_family() {
        let protocols = ProbeKind::IcmpEcho { identifier: 1 }.ip_protocols();
        assert_eq!(protocols.v4, IpNextHeaderProtocols::Icmp);
        assert_eq!(protocols.v6, IpNextHeaderProtocols::Icmpv6);
        assert_eq!(
            protocols.for_destination(IpAddr::from([192, 0, 2, 1])),
            IpNextHeaderProtocols::Icmp
        );
        assert_eq!(
            protocols.for_destination("2001:db8::1".parse().unwrap()),
            IpNextHeaderProtocols::Icmpv6
        );
    }

    /// The ICMP filter admits both families whole.
    ///
    /// The echo identifier is what separates this scan's replies from every
    /// other ping on the host, and it cannot be expressed here: it sits past a
    /// header whose length is not fixed over IPv6. Narrowing the IPv4 half alone
    /// would leave the two families behaving differently for no reason a reader
    /// could see, which is exactly how this crate lost its IPv6 receive path
    /// once before.
    #[test]
    fn the_icmp_filter_admits_both_families() {
        assert_eq!(
            ProbeKind::IcmpEcho { identifier: 4242 }.filter(),
            "icmp or icmp6"
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

    use pnet_base::MacAddr;
    use pnet_packet::icmpv6::{Icmpv6Code, Icmpv6Types, MutableIcmpv6Packet};
    use pnet_packet::ip::IpNextHeaderProtocols;
    use pnet_packet::tcp::MutableTcpPacket;

    use super::ProbeKind;
    use crate::protocols::udp;
    use crate::transport::frame::build_ethernet_frame;

    const SRC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    const DST_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
    const SRC_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10));
    const DST_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x20));

    const SYN: u8 = 1 << 1;
    const RST: u8 = 1 << 2;
    const ACK: u8 = 1 << 4;

    const TCP_HDR_LEN: usize = 20;
    const ICMPV6_UNUSED_LEN: usize = 4;

    /// The single port a [`ProbeKind::TcpProbe`] scan sends from, and so the
    /// port its answers come back to.
    const SCAN_PORT: u16 = 50_000;

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
    /// `src` and `dst` are, addressed back to the port a scan sent from.
    fn tcp_frame(src: IpAddr, dst: IpAddr, flags: u8) -> Vec<u8> {
        tcp_frame_to(src, dst, flags, SCAN_PORT)
    }

    /// [`tcp_frame`] addressed to an explicit port, for the filters that narrow
    /// on one.
    fn tcp_frame_to(src: IpAddr, dst: IpAddr, flags: u8, dst_port: u16) -> Vec<u8> {
        let mut segment = vec![0u8; TCP_HDR_LEN];
        {
            let mut tcp = MutableTcpPacket::new(&mut segment).expect("TCP header buffer");
            tcp.set_source(443);
            tcp.set_destination(dst_port);
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
        protocol: pnet_packet::ip::IpNextHeaderProtocol,
        segment: &[u8],
    ) -> Vec<u8> {
        build_ethernet_frame(
            MacAddr::new(0x02, 0, 0, 0, 0, 0x02),
            MacAddr::new(0x02, 0, 0, 0, 0, 0x01),
            src,
            dst,
            protocol,
            segment,
            crate::protocols::ip::HOP_LIMIT_ROUTED,
        )
        .expect("building an Ethernet frame")
    }

    /// The two send failures that call for opposite responses are told apart by
    /// the operating system's error kind, not by its wording.
    ///
    /// A message's text differs per platform and per locale, and matching on it
    /// is how a classification silently stops working on somebody else's
    /// machine. Only the two unreachable kinds are singled out: a full buffer or
    /// a permission failure says nothing about whether the destination exists,
    /// and treating either as unroutable would hide a scan that genuinely could
    /// not run.
    #[test]
    fn a_destination_with_no_route_is_not_a_broken_send_path() {
        use super::SendError;
        use std::io::{Error, ErrorKind};

        for kind in [ErrorKind::HostUnreachable, ErrorKind::NetworkUnreachable] {
            let error = SendError::from_io(
                anyhow::Error::new(Error::new(kind, "No route to host"))
                    .context("failed to send to 2001:db8::1"),
            );
            assert!(error.is_unroutable(), "{kind:?} is about the destination");
            assert!(
                error.to_string().contains("2001:db8::1"),
                "the address survives the classification: {error}"
            );
        }

        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::WouldBlock,
            ErrorKind::BrokenPipe,
        ] {
            let error = SendError::from_io(anyhow::Error::new(Error::new(kind, "nope")));
            assert!(
                !error.is_unroutable(),
                "{kind:?} is about this host, not the destination"
            );
        }
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

    /// The gap this module was written to expose, and the assertion that says
    /// it is closed.
    ///
    /// `tcp[tcpflags]` is `proto[x]` indexing, which `libpcap` cannot compile
    /// over IPv6 - the next-header chain makes the offset non-constant. It does
    /// not report that; written unqualified it silently narrows the whole
    /// expression to IPv4, and the compiled program jumps straight to `ret #0`
    /// on EtherType `0x86dd`. Since the capture is the only receive path, that
    /// left routed IPv6 discovery and IPv6 SYN port scanning seeing no replies
    /// whatsoever.
    #[test]
    fn the_syn_filter_admits_the_same_answers_over_ipv6() {
        let filter = ProbeKind::TcpSyn.filter();

        assert!(admits(&filter, &tcp_frame(SRC_V6, DST_V6, SYN | ACK)));
        assert!(admits(&filter, &tcp_frame(SRC_V6, DST_V6, RST | ACK)));
    }

    /// What admitting the IPv6 half unnarrowed actually costs, stated as a
    /// property rather than discovered later in a packet count.
    ///
    /// An established IPv6 connection's segments reach userspace, where the
    /// IPv4 equivalent is dropped by the kernel. Nothing can be done about that
    /// at the filter - see [`libpcap_cannot_narrow_tcp_flags_over_ipv6`] - so
    /// the scanners re-check the flags themselves, and this test exists so that
    /// asymmetry is written down where the filter is, not inferred from a
    /// scanner three modules away.
    #[test]
    fn the_ipv6_half_of_the_syn_filter_is_not_narrowed_to_probe_replies() {
        let filter = ProbeKind::TcpSyn.filter();

        assert!(
            !admits(&filter, &tcp_frame(SRC_V4, DST_V4, ACK)),
            "the IPv4 half is narrowed by the kernel"
        );
        assert!(
            admits(&filter, &tcp_frame(SRC_V6, DST_V6, ACK)),
            "the IPv6 half cannot be, so userspace has to do it"
        );
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

    // ─── TCP port probes ─────────────────────────────────────────────────────

    fn tcp_probe_filter(icmp_errors: bool) -> String {
        ProbeKind::TcpProbe {
            reply_port: SCAN_PORT,
            icmp_errors,
        }
        .filter()
    }

    /// Both answers a port probe can draw, over both families.
    #[test]
    fn the_tcp_probe_filter_admits_answers_addressed_to_the_scan() {
        let filter = tcp_probe_filter(false);

        for (src, dst) in [(SRC_V4, DST_V4), (SRC_V6, DST_V6)] {
            assert!(
                admits(&filter, &tcp_frame(src, dst, SYN | ACK)),
                "a SYN+ACK is an open port and must reach the scanner"
            );
            assert!(
                admits(&filter, &tcp_frame(src, dst, RST | ACK)),
                "a RST is an answer and must reach the scanner"
            );
        }
    }

    /// What narrowing on the scan's own port buys over narrowing on flags, and
    /// the reason a TCP port scan sends every probe from one port.
    ///
    /// A flag test cannot be compiled over IPv6 (see
    /// [`libpcap_cannot_narrow_tcp_flags_over_ipv6`]), so
    /// [`ProbeKind::TcpSyn`] admits every IPv6 TCP segment on every captured
    /// interface and sorts them out in userspace. A destination port compiles
    /// for both families, so this filter rejects the host's other conversations
    /// in the kernel over IPv6 exactly as it does over IPv4.
    #[test]
    fn the_tcp_probe_filter_rejects_traffic_addressed_elsewhere_over_both_families() {
        let filter = tcp_probe_filter(false);
        let elsewhere = SCAN_PORT + 1;

        for (src, dst) in [(SRC_V4, DST_V4), (SRC_V6, DST_V6)] {
            assert!(
                !admits(&filter, &tcp_frame_to(src, dst, RST | ACK, elsewhere)),
                "a segment to a port this scan never sent from is somebody else's"
            );
        }
    }

    /// What this filter narrows on is the conversation, not the flags, so a
    /// segment carrying neither of the two answers a probe can draw still
    /// reaches userspace if it is addressed to the scan's port.
    ///
    /// Stated here rather than left to be discovered in a packet count. The
    /// scan's port is drawn from the high ephemeral range precisely so nothing
    /// else on the host is holding a conversation on it, and the scanner
    /// re-checks the flags itself either way - so this costs a check per
    /// segment, not a wrong verdict.
    #[test]
    fn the_tcp_probe_filter_narrows_on_the_conversation_rather_than_the_flags() {
        let filter = tcp_probe_filter(false);

        assert!(admits(&filter, &tcp_frame(SRC_V4, DST_V4, ACK)));
        assert!(admits(&filter, &tcp_frame(SRC_V6, DST_V6, ACK)));
    }

    /// ICMP is admitted only when a technique's verdicts actually turn on it,
    /// because an ICMP error names no ports and so cannot be narrowed at all:
    /// asking for it means every ICMP packet on every captured interface is
    /// copied to userspace.
    #[test]
    fn the_tcp_probe_filter_admits_icmp_errors_only_when_asked() {
        let error = icmpv6_error_frame(SRC_V6, DST_V6);

        assert!(!admits(&tcp_probe_filter(false), &error));
        assert!(admits(&tcp_probe_filter(true), &error));
    }

    /// Asking for ICMP must not cost the answers the scan is actually waiting
    /// for, nor widen what it accepts on the TCP half.
    #[test]
    fn asking_for_icmp_changes_nothing_about_the_tcp_half() {
        let filter = tcp_probe_filter(true);

        assert!(admits(&filter, &tcp_frame(SRC_V6, DST_V6, RST | ACK)));
        assert!(!admits(
            &filter,
            &tcp_frame_to(SRC_V6, DST_V6, RST | ACK, SCAN_PORT + 1)
        ));
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
