// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Raw Transport-Layer Sockets (Send Path)
//!
//! Wraps `pnet`'s raw transport-layer (Layer 4) sockets for *sending* probes,
//! so async scanning code never touches the blocking socket API directly.
//!
//! This module deliberately opens no receiver. Receiving TCP/UDP over a raw
//! socket works on Linux but is silently dead on macOS/BSD, whose kernels
//! never deliver those protocols to raw sockets - so replies are captured at
//! the link layer via [`crate::transport::capture`] instead, and every scanner
//! pairs this send-only handle with that capture through
//! [`crate::transport::probe::ProbeTransport`].
//!
//! A raw socket is bound to one address family: an IPv4 socket can neither
//! send to nor receive from an IPv6 destination, and vice versa. TCP scanning
//! needs both, since targets can be either, so [`open_sender`] opens one
//! socket per address family for [`TransportType::TcpLayer4`].
//! [`TransportType::UdpLayer4`] stays IPv4-only, since nothing in this crate
//! currently needs UDP over IPv6. [`TransportType::SctpLayer4`] and
//! [`TransportType::IcmpLayer4`] open both, and the ICMP one is
//! is the only way this crate can put an ICMP message on the wire for a host it
//! cannot reach at the link layer: the echo builders in
//! [`crate::protocols::icmp`] emit whole Ethernet frames and so need a
//! neighbour.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use pnet_packet::{Packet, ip::IpNextHeaderProtocols};
use pnet_transport::{
    self as transport, TransportChannelType, TransportProtocol, TransportReceiver, TransportSender,
};

const TRANSPORT_BUFFER_SIZE: usize = 4096;
const CHANNEL_TYPE_UDP_V4: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp));
const CHANNEL_TYPE_TCP_V4: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
const CHANNEL_TYPE_TCP_V6: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp));
const CHANNEL_TYPE_ICMP_V4: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
const CHANNEL_TYPE_ICMP_V6: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6));
const CHANNEL_TYPE_SCTP_V4: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Sctp));
const CHANNEL_TYPE_SCTP_V6: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Sctp));

/// Which transport-layer protocol, and address family coverage, to open a capture for.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum TransportType {
    /// Raw TCP segments, over both IPv4 and IPv6 where available.
    TcpLayer4,
    /// Raw UDP datagrams, over IPv4 only.
    UdpLayer4,
    /// Raw ICMP messages, over both IPv4 and IPv6 where available.
    ///
    /// The two families are different protocols rather than one protocol over two
    /// address sizes: ICMP is next-header 1 and ICMPv6 is 58, they number their
    /// message types differently, and ICMPv6 checksums cover a pseudo-header
    /// while ICMPv4 checksums cover the message alone. A caller therefore builds
    /// a different message per family, and this opens a socket for each.
    ///
    /// This is the only path by which this crate can send an ICMP message to a
    /// host that is not on the local segment. The echo builders in
    /// [`protocols::icmp`] produce whole Ethernet frames, which need a
    /// destination hardware address and so only reach an on-link neighbour.
    ///
    /// [`protocols::icmp`]: crate::protocols::icmp
    IcmpLayer4,
    /// Raw SCTP packets, over both IPv4 and IPv6 where available.
    ///
    /// The socket carries the packet and nothing more: an SCTP checksum is a
    /// CRC32c over the packet alone, so unlike TCP and UDP there is no
    /// pseudo-header for the kernel or the builder to agree about, and the same
    /// bytes go out over either family.
    ///
    /// Opening it needs no SCTP stack in the kernel, only the privilege every
    /// raw socket needs. A host that cannot itself hold an association can still
    /// send an INIT and read what comes back, which is the whole of what a scan
    /// does with one.
    SctpLayer4,
}

/// Routes an outgoing packet to whichever underlying raw socket matches its
/// destination's address family.
///
/// A [`TransportType::UdpLayer4`] handle only ever has an IPv4 sender, so
/// sending to an IPv6 destination through it fails with a clear error rather
/// than silently doing nothing.
pub struct TransportSenderHandle {
    v4: Option<Arc<Mutex<Socket>>>,
    v6: Option<Arc<Mutex<Socket>>>,
}

/// One raw socket, and the hop limit currently set on it.
///
/// The two travel under one lock because they have to be changed together: a
/// hop limit is socket state, not packet state, so setting it and sending are
/// one operation and a second thread must not send in between.
struct Socket {
    sender: TransportSender,
    /// What `IP_TTL` (or `IPV6_UNICAST_HOPS`) was last set to on this socket,
    /// or `None` before anything set it.
    ///
    /// Tracked so that a scan sending millions of probes at one hop limit pays
    /// for one `setsockopt` rather than one per probe. It starts as `None`
    /// rather than as this engine's default, so the first send states the value
    /// explicitly instead of trusting a kernel default that is only usually 64. A
    /// host tuned otherwise would send probes that expire early, and an expired
    /// probe is indistinguishable from a host that did not answer.
    hop_limit: Option<u8>,
}

impl Socket {
    fn new(sender: TransportSender) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            sender,
            hop_limit: None,
        }))
    }
}

/// Why a raw socket could not be opened, or a write through one failed.
///
/// Every variant here is an answer from the operating system rather than a
/// mistake in what was asked, [`NoSocket`](Self::NoSocket) aside. That matters
/// for what a caller does next: a scan meeting [`Open`](Self::Open) has no raw
/// path at all and falls back, and one meeting [`Send`](Self::Send) has a
/// transport that works and a destination that did not.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum RawSocketError {
    /// A raw socket could not be opened.
    ///
    /// Almost always a privilege refusal. `CAP_NET_RAW` on Linux, root
    /// elsewhere; see [`can_send_raw`](crate::system::privilege::can_send_raw),
    /// which asks this question by asking for the socket.
    #[error("a raw socket could not be opened: {source}")]
    Open {
        /// What the operating system said.
        #[source]
        source: std::io::Error,
    },

    /// No socket is open for the address family a destination named.
    ///
    /// A handle opens what it can, and a host with IPv6 raw sockets disabled
    /// gets an IPv4-only one rather than nothing. This is what a v6 destination
    /// then meets, and it is a narrower transport rather than a broken one.
    #[error(
        "no open raw socket for {destination}, whose address family this handle does not carry"
    )]
    NoSocket {
        /// The destination that had nowhere to go.
        destination: IpAddr,
    },

    /// The hop limit could not be set on the socket.
    #[error("a hop limit of {hop_limit} could not be set: {source}")]
    HopLimit {
        /// The hop limit that was asked for.
        hop_limit: u8,
        /// What the operating system said.
        #[source]
        source: std::io::Error,
    },

    /// The packet could not be written.
    #[error("sending to {destination} failed: {source}")]
    Send {
        /// Where it was going.
        destination: IpAddr,
        /// What the operating system said.
        #[source]
        source: std::io::Error,
    },

    /// The socket's lock was poisoned by another thread's panic.
    ///
    /// One socket is shared across a scan's senders, so a panic while it was
    /// held leaves it unusable rather than merely unlocked. Named rather than
    /// unwrapped, because this happened in the caller's process and taking it
    /// down twice helps nobody.
    #[error("the raw socket lock was poisoned by another thread's panic")]
    Poisoned,
}

impl TransportSenderHandle {
    /// Sends `packet` to `destination`, expiring after `hop_limit` routers.
    ///
    /// The hop limit is applied to the socket rather than written into the
    /// packet, because a Layer-4 socket has the kernel build the IP header and
    /// there is no header here to write it into. That makes it *sticky*, which
    /// is why the value in force is tracked alongside the socket: what a caller
    /// asks for is what goes out, whatever the previous send asked for.
    pub fn send_to<T: Packet>(
        &self,
        packet: T,
        destination: IpAddr,
        hop_limit: u8,
    ) -> Result<usize, RawSocketError> {
        let socket = match destination {
            IpAddr::V4(_) => self.v4.as_ref(),
            IpAddr::V6(_) => self.v6.as_ref(),
        }
        .ok_or(RawSocketError::NoSocket { destination })?;

        let mut socket = socket.lock().map_err(|_| RawSocketError::Poisoned)?;

        if socket.hop_limit != Some(hop_limit) {
            socket
                .sender
                .set_ttl(hop_limit)
                .map_err(|source| RawSocketError::HopLimit { hop_limit, source })?;
            socket.hop_limit = Some(hop_limit);
        }

        socket
            .sender
            .send_to(packet, destination)
            .map_err(|source| RawSocketError::Send {
                destination,
                source,
            })
    }
}

/// Opens only the outgoing half of a raw transport capture: the raw
/// socket(s) needed to *send* segments, with no receiver threads.
///
/// Sending over a raw Layer-4 socket works on every supported OS - it's only
/// *receiving* TCP/UDP this way that BSD-derived kernels refuse - so the
/// [`RawIpSender`](crate::transport::probe::RawIpSender) pairs this send-only
/// handle with a `libpcap` capture for replies instead of the (silently dead
/// on macOS) raw-socket receiver.
pub fn open_sender(transport_type: TransportType) -> Result<TransportSenderHandle, RawSocketError> {
    match transport_type {
        TransportType::TcpLayer4 => {
            let (v4_tx, _v4_rx) = open_channel(CHANNEL_TYPE_TCP_V4)?;
            // IPv6 raw sockets aren't available on every host; TCP scanning
            // still works over IPv4 alone, so a failure here isn't fatal.
            let v6 = open_channel(CHANNEL_TYPE_TCP_V6)
                .ok()
                .map(|(v6_tx, _v6_rx)| Socket::new(v6_tx));
            Ok(TransportSenderHandle {
                v4: Some(Socket::new(v4_tx)),
                v6,
            })
        }
        TransportType::UdpLayer4 => {
            let (v4_tx, _v4_rx) = open_channel(CHANNEL_TYPE_UDP_V4)?;
            Ok(TransportSenderHandle {
                v4: Some(Socket::new(v4_tx)),
                v6: None,
            })
        }
        TransportType::SctpLayer4 => {
            let (v4_tx, _v4_rx) = open_channel(CHANNEL_TYPE_SCTP_V4)?;
            // As for TCP: a host without IPv6 raw sockets still scans SCTP over
            // IPv4, so a failure here narrows the transport rather than ending
            // it.
            let v6 = open_channel(CHANNEL_TYPE_SCTP_V6)
                .ok()
                .map(|(v6_tx, _v6_rx)| Socket::new(v6_tx));
            Ok(TransportSenderHandle {
                v4: Some(Socket::new(v4_tx)),
                v6,
            })
        }
        TransportType::IcmpLayer4 => {
            let (v4_tx, _v4_rx) = open_channel(CHANNEL_TYPE_ICMP_V4)?;
            // Same reasoning as TCP: a host without IPv6 raw sockets can still
            // be probed over IPv4, so a failure here is a narrower transport
            // rather than no transport.
            let v6 = open_channel(CHANNEL_TYPE_ICMP_V6)
                .ok()
                .map(|(v6_tx, _v6_rx)| Socket::new(v6_tx));
            Ok(TransportSenderHandle {
                v4: Some(Socket::new(v4_tx)),
                v6,
            })
        }
    }
}

fn open_channel(
    channel_type: TransportChannelType,
) -> Result<(TransportSender, TransportReceiver), RawSocketError> {
    transport::transport_channel(TRANSPORT_BUFFER_SIZE, channel_type)
        .map_err(|source| RawSocketError::Open { source })
}
