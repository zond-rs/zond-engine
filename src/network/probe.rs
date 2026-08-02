// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

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

use crate::network::capture::{self, CaptureGuard, CaptureStream};
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
}

impl ProbeKind {
    /// The raw-socket transport type used for the send half.
    fn transport_type(self) -> TransportType {
        match self {
            ProbeKind::TcpSyn => TransportType::TcpLayer4,
            ProbeKind::UdpResolve => TransportType::UdpLayer4,
        }
    }

    /// The `libpcap`/`tcpdump` filter expression compiled into a kernel BPF
    /// program for the receive half. Narrow by design: only the replies a
    /// scan can act on ever reach userspace.
    fn filter(self) -> &'static str {
        match self {
            // SYN+ACK (open) and RST (closed) both set at least one of the
            // SYN/RST flag bits; nothing else a SYN probe can elicit does.
            ProbeKind::TcpSyn => "tcp and (tcp[tcpflags] & (tcp-syn|tcp-rst)) != 0",
            // DNS (53) and mDNS (5353) responses, by source port.
            ProbeKind::UdpResolve => "udp and (src port 53 or src port 5353)",
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
    /// Parsed `(segment, source_ip)` replies, merged across every captured
    /// interface.
    pub rx: CaptureStream,
    /// Keeps the capture threads alive for this transport's lifetime.
    _capture: CaptureGuard,
}

impl ProbeTransport {
    /// Opens a transport for `kind` using the send backend appropriate to the
    /// platform: a raw-socket sender on Unix, and the Layer-2 Ethernet sender
    /// on Windows, where the OS blocks raw-socket TCP sends outright. Both
    /// pair with a filtered `libpcap` capture on every currently-up interface.
    ///
    /// Capturing on all up interfaces (loopback included) means a reply is
    /// caught whichever interface the kernel routed the probe out of - the
    /// egress path can differ per destination, especially with a VPN in play,
    /// so binding to a single guessed interface would silently miss replies.
    pub fn open(kind: ProbeKind) -> anyhow::Result<Self> {
        #[cfg(windows)]
        {
            Self::open_ethernet(kind)
        }
        #[cfg(not(windows))]
        {
            Self::open_on(kind, &capturable_interfaces())
        }
    }

    /// [`open`](Self::open) against an explicit interface-name list.
    pub fn open_on(kind: ProbeKind, interfaces: &[String]) -> anyhow::Result<Self> {
        let (rx, capture) = capture::start(interfaces, kind.filter())?;
        let tx: Box<dyn ProbeSender> = Box::new(RawIpSender::open(kind)?);
        Ok(Self {
            tx,
            rx,
            _capture: capture,
        })
    }

    /// Opens a transport whose send half builds and emits Ethernet frames
    /// directly ([`EthernetSender`]) instead of using a raw socket.
    ///
    /// For Windows (where raw TCP sends are blocked) and for deliberately
    /// bypassing the host stack. Fails if the host has no Ethernet-capable
    /// interface - only a tunnel or loopback - in which case the raw-IP
    /// transport from [`open`](Self::open) is the correct choice.
    pub fn open_ethernet(kind: ProbeKind) -> anyhow::Result<Self> {
        let sender = EthernetSender::from_system()
            .context("no Ethernet-capable interface for Layer-2 send")?;
        let (rx, capture) = capture::start(&capturable_interfaces(), kind.filter())?;
        Ok(Self {
            tx: Box::new(sender),
            rx,
            _capture: capture,
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
        let (rx, capture) = capture::start(&capturable_interfaces(), kind.filter())?;
        Ok(Self {
            tx: Box::new(NoopSender),
            rx,
            _capture: capture,
        })
    }

    /// Builds a transport from an explicit sender and receive stream, without
    /// opening any socket or capture. For tests that drive scanner logic with
    /// synthesized replies.
    #[cfg(test)]
    pub fn from_parts(tx: Box<dyn ProbeSender>, rx: CaptureStream, capture: CaptureGuard) -> Self {
        Self {
            tx,
            rx,
            _capture: capture,
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

/// A [`ProbeSender`] that records what it was asked to send instead of
/// touching a socket, so transport wiring and scanner logic can be exercised
/// without root. Available crate-wide under `cfg(test)`.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct MockSender {
    pub sent: std::sync::Arc<std::sync::Mutex<Vec<(Vec<u8>, IpAddr, IpAddr)>>>,
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
        use crate::network::capture::CaptureGuard;
        use std::net::Ipv4Addr;

        let mock = MockSender::default();
        let recorded = mock.sent.clone();
        let (reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut transport =
            ProbeTransport::from_parts(Box::new(mock), reply_rx, CaptureGuard::noop());

        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let dst = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        transport.tx.send(&[0xAA, 0xBB], src, dst).unwrap();

        let sent = recorded.lock().unwrap().clone();
        assert_eq!(sent, vec![(vec![0xAA, 0xBB], src, dst)]);

        // A reply pushed onto the capture stream is observed on rx unchanged.
        reply_tx.send((vec![1, 2, 3], dst)).unwrap();
        assert_eq!(transport.rx.recv().await, Some((vec![1, 2, 3], dst)));
    }
}
