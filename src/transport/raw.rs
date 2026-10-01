// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Raw Transport-Layer Sockets (Send Path)
//!
//! Wraps `pnet`'s raw transport-layer (Layer 4) sockets for *sending* probes, so async
//! scanning code never touches the blocking socket API.
//!
//! This module opens no receiver. Receiving TCP/UDP over a raw socket works on Linux
//! but macOS and the BSDs never deliver those protocols to raw sockets, so replies are
//! captured at the link layer via [`crate::transport::capture`], and every scanner
//! pairs this send-only handle with that capture through
//! [`crate::transport::probe::ProbeTransport`].
//!
//! A raw socket is bound to one address family, so [`open_sender`] opens one socket
//! per family for each [`TransportType`]. The ICMP sockets are the only way this crate
//! can send an ICMP message to a host it cannot reach at the link layer: the echo
//! builders in [`crate::protocols::icmp`] emit whole Ethernet frames and so need a
//! neighbour.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use pnet_packet::{
    Packet,
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
};
use pnet_transport::{
    self as transport, TransportChannelType, TransportProtocol, TransportReceiver, TransportSender,
};

const TRANSPORT_BUFFER_SIZE: usize = 4096;
const CHANNEL_TYPE_UDP_V4: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp));
const CHANNEL_TYPE_UDP_V6: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Udp));
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
    /// Raw UDP datagrams, over both IPv4 and IPv6 where available.
    UdpLayer4,
    /// Raw ICMP messages, over both IPv4 and IPv6 where available.
    ///
    /// ICMP (next-header 1) and ICMPv6 (58) are different protocols: they number
    /// their message types differently, and the ICMPv6 checksum covers a
    /// pseudo-header while ICMPv4's covers the message alone. A caller builds a
    /// different message per family.
    ///
    /// The only way this crate can send an ICMP message to a host off the local
    /// segment. The echo builders in [`protocols::icmp`] produce whole Ethernet
    /// frames, which only reach an on-link neighbour.
    ///
    /// [`protocols::icmp`]: crate::protocols::icmp
    IcmpLayer4,
    /// Raw SCTP packets, over both IPv4 and IPv6 where available.
    ///
    /// The SCTP checksum is a CRC32c over the packet alone, with no pseudo-header,
    /// so the same bytes go out over either family.
    ///
    /// Needs no SCTP support in the kernel, only raw-socket privilege. A host that
    /// cannot hold an association can still send an INIT and read the answer, which
    /// is all a scan does.
    SctpLayer4,
    /// Datagrams of one arbitrary IP protocol, over both families where available.
    ///
    /// Carries a protocol number and speaks nothing. This is what an
    /// [IP protocol scan](crate::scanner::strategy::protocols) sends: a header under a
    /// chosen next-header value, to learn whether the host's stack accepts it.
    ///
    /// One socket per number, because the kernel takes a Layer-4 socket's next-header
    /// value from the socket. A pass over a dozen protocols opens a dozen sockets;
    /// writing the IP header here would mean routing the packet here too.
    IpProtocol(u8),
}

/// Routes an outgoing packet to the raw socket matching its destination's address
/// family and its source.
///
/// A handle opens what the host allows: on a host with IPv6 raw sockets disabled it
/// carries IPv4 alone, and a send to an IPv6 destination fails with an error.
///
/// **The kernel chooses a Layer-4 socket's source**, but the segment's checksum is
/// computed over the source the scan chose. They agree when the scan took its source
/// from the routing table, and disagree when it was forced (`send_source`, to leave by
/// a LAN interface past a VPN's default route) or picked where the kernel had no
/// route; then every target drops the packet. So [`send_from`](Self::send_from) sends
/// such a packet through a socket pinned to its source: bound to the address, so the
/// kernel stamps that one, and to the interface holding it, so the packet leaves where
/// the source belongs.
pub struct TransportSenderHandle {
    v4: Option<Family>,
    v6: Option<Family>,
    /// The source the routing table picks per destination, remembered, since every
    /// port of a host asks the same question. Cleared when it grows past
    /// [`ROUTE_MEMO_LIMIT`].
    routes: Mutex<HashMap<IpAddr, Option<IpAddr>>>,
}

/// The most destinations whose kernel-chosen source is remembered at once.
const ROUTE_MEMO_LIMIT: usize = 1 << 16;

/// One address family's sockets: the ordinary one, and those pinned to a source.
struct Family {
    socket: Arc<Mutex<Socket>>,
    /// What the family's sockets are opened as, for opening a pinned one.
    channel: TransportChannelType,
    /// A socket per source the kernel would not have chosen, opened on first use
    /// and kept for the handle's life. A scan forces one or two.
    pinned: Mutex<HashMap<IpAddr, Arc<Mutex<Socket>>>>,
}

impl Family {
    fn new(sender: TransportSender, channel: TransportChannelType) -> Self {
        Self {
            socket: Socket::new(sender),
            channel,
            pinned: Mutex::new(HashMap::new()),
        }
    }

    /// The socket pinned to `source`, opened and pinned on first use.
    fn pinned(&self, source: IpAddr) -> Result<Arc<Mutex<Socket>>, RawSocketError> {
        let mut pinned = self.pinned.lock().map_err(|_| RawSocketError::Poisoned)?;
        if let Some(socket) = pinned.get(&source) {
            return Ok(socket.clone());
        }
        let (sender, _receiver) = open_channel(self.channel)?;
        pin(&sender, source)?;
        let socket = Socket::new(sender);
        pinned.insert(source, socket.clone());
        Ok(socket)
    }
}

/// One raw socket, and the hop limit currently set on it.
///
/// One lock covers both: the hop limit is socket state, so setting it and sending
/// must happen with no other thread sending in between.
struct Socket {
    sender: TransportSender,
    /// What `IP_TTL` (or `IPV6_UNICAST_HOPS`) was last set to on this socket, or
    /// `None` before anything set it.
    ///
    /// Tracked so a scan sending millions of probes at one hop limit makes one
    /// `setsockopt`. Starts as `None` so the first send sets the value explicitly: the
    /// kernel default is only usually 64, and a probe that expires early looks like a
    /// host that did not answer.
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
/// Apart from [`NoSocket`](Self::NoSocket), every variant is an answer from the
/// operating system. A scan meeting [`Open`](Self::Open) has no raw path and falls
/// back; one meeting [`Send`](Self::Send) has a working transport and a destination
/// that failed.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum RawSocketError {
    /// A raw socket could not be opened.
    ///
    /// Almost always a privilege refusal: `CAP_NET_RAW` on Linux, root elsewhere. See
    /// [`can_send_raw`](crate::system::privilege::can_send_raw).
    #[error("a raw socket could not be opened: {source}")]
    Open {
        /// What the operating system said.
        #[source]
        source: std::io::Error,
    },

    /// No socket is open for the destination's address family.
    ///
    /// A host with IPv6 raw sockets disabled gets an IPv4-only handle, and a v6
    /// destination then meets this.
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

    /// A packet was to be sent from an address this host does not hold.
    ///
    /// The kernel writes a Layer-4 socket's header and only with the host's own
    /// addresses. A probe that needs a spoofed source must be framed whole.
    #[error("{address} is not an address this host holds, so no raw socket can send from it")]
    #[cfg_attr(
        not(unix),
        expect(dead_code, reason = "a raw socket is pinned to a source on Unix alone")
    )]
    NotHeld {
        /// The source that was asked for.
        address: IpAddr,
    },

    /// A socket could not be bound to a source address or its interface.
    #[error("a raw socket could not be pinned to {address}: {source}")]
    Pin {
        /// The source it was being pinned to.
        address: IpAddr,
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
    /// One socket is shared across a scan's senders, so a panic while it was held
    /// leaves it unusable. Returned as an error so the caller's process is not taken
    /// down a second time.
    #[error("the raw socket lock was poisoned by another thread's panic")]
    Poisoned,
}

impl TransportSenderHandle {
    /// Sends `packet` to `destination` from whichever address the kernel chooses,
    /// expiring after `hop_limit` routers.
    ///
    /// For a packet whose bytes do not depend on its source. A segment whose checksum
    /// covers a pseudo-header, as TCP and UDP do, goes through
    /// [`send_from`](Self::send_from).
    ///
    /// The hop limit is set on the socket, since the kernel builds the IP header. That
    /// makes it sticky, so the value in force is tracked and changed whenever a send
    /// asks for a different one.
    ///
    /// `zone` is the interface a link-local destination is valid on. A `SocketAddrV6`
    /// with a zero scope id cannot reach `fe80::1`, and `pnet`'s send builds one, so a
    /// scoped destination goes through its own `sendto`.
    pub fn send_to<T: Packet>(
        &self,
        packet: T,
        destination: IpAddr,
        zone: Option<u32>,
        hop_limit: u8,
    ) -> Result<usize, RawSocketError> {
        let family = self.family(destination)?;
        send_on(&family.socket, packet, destination, zone, hop_limit)
    }

    /// Sends `packet` to `destination` from `source`, otherwise as
    /// [`send_to`](Self::send_to).
    ///
    /// Uses the family's ordinary socket where the routing table would pick `source`
    /// for `destination` anyway, and one pinned to `source` where it would not or has
    /// no route. See the type's documentation.
    pub fn send_from<T: Packet>(
        &self,
        packet: T,
        source: IpAddr,
        destination: IpAddr,
        zone: Option<u32>,
        hop_limit: u8,
    ) -> Result<usize, RawSocketError> {
        let family = self.family(destination)?;
        let socket = if self.kernel_source(destination) == Some(source) {
            family.socket.clone()
        } else {
            family.pinned(source)?
        };
        send_on(&socket, packet, destination, zone, hop_limit)
    }

    /// The family's sockets for `destination`.
    fn family(&self, destination: IpAddr) -> Result<&Family, RawSocketError> {
        match destination {
            IpAddr::V4(_) => self.v4.as_ref(),
            IpAddr::V6(_) => self.v6.as_ref(),
        }
        .ok_or(RawSocketError::NoSocket { destination })
    }

    /// The source the routing table picks for `destination`, remembered.
    ///
    /// Asked by connecting a UDP socket, which sends nothing. A poisoned memo asks
    /// afresh and the send goes ahead.
    fn kernel_source(&self, destination: IpAddr) -> Option<IpAddr> {
        let ask = || crate::system::interface::probe_route_source(destination);
        let Ok(mut routes) = self.routes.lock() else {
            return ask();
        };
        if let Some(known) = routes.get(&destination) {
            return *known;
        }
        if routes.len() >= ROUTE_MEMO_LIMIT {
            routes.clear();
        }
        let source = ask();
        routes.insert(destination, source);
        source
    }
}

/// Sends `packet` through `socket`, setting its hop limit first where it
/// differs. See [`TransportSenderHandle::send_to`].
fn send_on<T: Packet>(
    socket: &Mutex<Socket>,
    packet: T,
    destination: IpAddr,
    zone: Option<u32>,
    hop_limit: u8,
) -> Result<usize, RawSocketError> {
    let mut socket = socket.lock().map_err(|_| RawSocketError::Poisoned)?;

    if socket.hop_limit != Some(hop_limit) {
        socket
            .sender
            .set_ttl(hop_limit)
            .map_err(|source| RawSocketError::HopLimit { hop_limit, source })?;
        socket.hop_limit = Some(hop_limit);
    }

    match (destination, zone) {
        (IpAddr::V6(v6), Some(zone)) => {
            send_scoped(socket.sender.socket.fd, packet.packet(), v6, 0, zone)
        }
        _ => socket.sender.send_to(packet, destination),
    }
    .map_err(|source| RawSocketError::Send {
        destination,
        source,
    })
}

/// Binds `sender`'s socket to `source` and to the interface holding it.
///
/// The address makes the kernel write `source` into the header, matching the
/// checksum. The interface makes the packet leave by the link `source` belongs to,
/// whatever the default route says, which is also the only place a reply to that
/// address comes back. A link-local source is bound with its interface as its scope.
#[cfg(unix)]
fn pin(sender: &TransportSender, source: IpAddr) -> Result<(), RawSocketError> {
    use std::os::fd::BorrowedFd;

    let failed = |error| RawSocketError::Pin {
        address: source,
        source: error,
    };
    let link = crate::system::interface::interfaces()
        .map_err(failed)?
        .into_iter()
        .find(|link| link.addresses().iter().any(|held| held.address() == source))
        .ok_or(RawSocketError::NotHeld { address: source })?;

    // SAFETY: the descriptor belongs to `sender`, which outlives this borrow, and is
    // open: `pnet` closes it only when the sender is dropped.
    let fd = unsafe { BorrowedFd::borrow_raw(sender.socket.fd) };
    let socket = socket2::SockRef::from(&fd);

    let address = match source {
        IpAddr::V4(v4) => std::net::SocketAddr::from((v4, 0)),
        IpAddr::V6(v6) => {
            let scope = if v6.is_unicast_link_local() {
                link.index()
            } else {
                0
            };
            std::net::SocketAddr::V6(std::net::SocketAddrV6::new(v6, 0, 0, scope))
        }
    };
    socket.bind(&address.into()).map_err(failed)?;

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    {
        let index = std::num::NonZeroU32::new(link.index());
        match source {
            IpAddr::V4(_) => socket.bind_device_by_index_v4(index),
            IpAddr::V6(_) => socket.bind_device_by_index_v6(index),
        }
        .map_err(failed)?;
    }

    Ok(())
}

/// No pinning where raw sockets are not the scan's send path.
///
/// Windows refuses raw TCP, and a scan there frames its probes whole, source address
/// and all; see [`crate::transport::link`].
#[cfg(not(unix))]
fn pin(_sender: &TransportSender, source: IpAddr) -> Result<(), RawSocketError> {
    Err(RawSocketError::Pin {
        address: source,
        source: std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "a raw socket is not pinned to a source on this platform",
        ),
    })
}

/// Writes `bytes` to a destination that names the interface it is valid on.
///
/// `pnet`'s send builds its destination from an `IpAddr` alone, leaving
/// `sin6_scope_id` zero, and the kernel refuses a link-local address with no scope id.
///
/// `port` is zero for a raw socket, which reads the port from the segment. It is a
/// parameter because a datagram socket does read one, and refuses zero, which lets
/// this be tested without raw-socket privilege.
#[cfg(unix)]
fn send_scoped(
    fd: std::os::fd::RawFd,
    bytes: &[u8],
    destination: Ipv6Addr,
    port: u16,
    zone: u32,
) -> std::io::Result<usize> {
    let address = socket2::SockAddr::from(std::net::SocketAddrV6::new(destination, port, 0, zone));

    // SAFETY: the socket outlives the call, `bytes` is a live slice for its length,
    // and the address and its length come from the same `SockAddr`.
    let written = unsafe {
        libc::sendto(
            fd,
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
            address.as_ptr().cast(),
            address.len(),
        )
    };

    match written {
        -1 => Err(std::io::Error::last_os_error()),
        written => Ok(written as usize),
    }
}

/// Refuses a scoped send on a platform with no `sendto`.
///
/// Windows blocks raw TCP sends, so a scan reaching here has already fallen back to
/// a connected socket, which carries its own scope id.
#[cfg(not(unix))]
fn send_scoped(
    // `pnet`'s socket type: the same handle as `std::os::windows::io::RawSocket`, but
    // a `usize` where that is a `u64`. Unread; named to match the call site.
    _fd: usize,
    _bytes: &[u8],
    _destination: Ipv6Addr,
    _port: u16,
    _zone: u32,
) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "a scoped raw send is not built on this platform",
    ))
}

/// Opens only the sending half of a raw transport channel: the raw sockets needed to
/// send segments, with no receiver threads.
///
/// Sending over a raw Layer-4 socket works on every supported OS; BSD-derived
/// kernels refuse only *receiving* TCP/UDP this way. So
/// [`RawIpSender`](crate::transport::probe::RawIpSender) pairs this handle with a
/// `libpcap` capture for replies.
pub fn open_sender(transport_type: TransportType) -> Result<TransportSenderHandle, RawSocketError> {
    match transport_type {
        TransportType::TcpLayer4 => both(CHANNEL_TYPE_TCP_V4, CHANNEL_TYPE_TCP_V6),
        TransportType::UdpLayer4 => both(CHANNEL_TYPE_UDP_V4, CHANNEL_TYPE_UDP_V6),
        TransportType::SctpLayer4 => both(CHANNEL_TYPE_SCTP_V4, CHANNEL_TYPE_SCTP_V6),
        TransportType::IcmpLayer4 => both(CHANNEL_TYPE_ICMP_V4, CHANNEL_TYPE_ICMP_V6),
        TransportType::IpProtocol(number) => {
            let protocol = IpNextHeaderProtocol(number);
            both(
                TransportChannelType::Layer4(TransportProtocol::Ipv4(protocol)),
                TransportChannelType::Layer4(TransportProtocol::Ipv6(protocol)),
            )
        }
    }
}

/// A handle over an IPv4 socket, and an IPv6 one where the host allows it.
///
/// A host that refuses IPv6 raw sockets, or one protocol's socket, still probes over
/// IPv4: an IPv6 failure narrows the transport. An IPv4 failure is the privilege
/// refusal and ends it.
fn both(
    v4: TransportChannelType,
    v6: TransportChannelType,
) -> Result<TransportSenderHandle, RawSocketError> {
    let (v4_tx, _v4_rx) = open_channel(v4)?;
    let v6_tx = open_channel(v6).ok().map(|(v6_tx, _v6_rx)| v6_tx);
    Ok(TransportSenderHandle {
        v4: Some(Family::new(v4_tx, v4)),
        v6: v6_tx.map(|tx| Family::new(tx, v6)),
        routes: Mutex::new(HashMap::new()),
    })
}

/// Opens one raw transport channel, mapping `pnet`'s error to this crate's.
fn open_channel(
    channel_type: TransportChannelType,
) -> Result<(TransportSender, TransportReceiver), RawSocketError> {
    transport::transport_channel(TRANSPORT_BUFFER_SIZE, channel_type)
        .map_err(|source| RawSocketError::Open { source })
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    /// A datagram to a link-local neighbour, sent through the scoped path on an
    /// ordinary UDP socket.
    ///
    /// The raw socket needs privilege, and the syscall is the same either way: the
    /// check is that the destination reaches the kernel with its scope id. Sent to
    /// this host's own link-local address on a discard port, so nothing leaves the
    /// machine or reaches a listener.
    ///
    /// Skipped on a host with no link-local address.
    const DISCARD: u16 = 9;

    #[test]
    fn a_scoped_send_reaches_the_kernel_with_its_interface_on_it() {
        // A real broadcast interface, lowest index first, so the pick is stable.
        let mut links: Vec<_> = crate::system::interface::interfaces()
            .expect("this machine's interfaces")
            .into_iter()
            .filter(|link| link.is_up() && !link.is_loopback() && !link.is_point_to_point())
            .collect();
        links.sort_by_key(crate::system::interface::Link::index);
        let Some((address, zone)) = links.iter().find_map(|link| {
            link.addresses()
                .iter()
                .map(|held| held.address())
                .find_map(|address| match address {
                    IpAddr::V6(v6) if v6.is_unicast_link_local() => Some((v6, link.index())),
                    _ => None,
                })
        }) else {
            return;
        };

        // Only the positive is asserted. Whether the kernel rejects a zero-scope send
        // to a link-local address is not portable: a host with one such interface
        // infers the scope and accepts it, as the GitHub Linux runners do.
        let socket = UdpSocket::bind("[::]:0").expect("an unprivileged socket");
        let sent = send_scoped(socket.as_raw_fd(), b"zond", address, DISCARD, zone);
        assert!(
            sent.is_ok(),
            "a scoped destination is deliverable: {}",
            sent.unwrap_err()
        );
    }
}
