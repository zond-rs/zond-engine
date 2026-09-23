// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The sockets the engine opens towards a target
//!
//! Everything that talks to a scanned host through the operating system's own
//! TCP and UDP, rather than through a raw socket or a self-built frame, opens
//! its socket here: the connect scan and its sweep, the service pass, the
//! fingerprint engine's second connections and its analyzers, a TLS
//! enumeration, a detection's exchange, and the single datagrams asked of mDNS
//! and SNMP agents.
//!
//! One place because what a socket has to carry before it connects is not a
//! property of the caller. Windows resends a refused SYN until its SYN
//! retransmissions run out, which outlasts every connect budget this engine
//! sets, so on Windows every TCP socket needs its retransmissions limited
//! before the connect, whoever is connecting and whatever it wants to learn;
//! see [`syn_retries`]. A caller that opened its own socket would be the one
//! that forgot.
//!
//! What a caller does choose is [`Shaping`]: a source port and a hop limit,
//! which only the connect scanner's probes carry. With nothing chosen, and on a
//! platform that needs nothing set, a connect is exactly a plain
//! [`TcpStream::connect`] and a datagram socket a plain ephemeral bind, so the
//! kernel sees what it would have seen from any other program.
//!
//! `tests/hygiene/dialling.rs` holds the rest of the crate to this: a TCP or
//! UDP socket opened anywhere else has to say why it is not a connection to a
//! target.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use socket2::{Domain, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

#[cfg(any(windows, test))]
mod syn_retries;

/// What a caller has chosen about a socket beyond where it is going: a source
/// port to leave from and a hop limit to carry.
///
/// Both are ordinary socket options that need no privilege. They are what an
/// evasion profile can ask of a connection the kernel builds; the rest of a
/// profile, a spoofed address, fragments, decoys, a padded or mangled segment,
/// needs a segment this process writes itself, and there is none here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Shaping {
    /// The source port the socket binds to, or `None` to let the OS choose one.
    pub(crate) source_port: Option<u16>,
    /// The hop limit the socket carries, or `None` to leave the OS default.
    pub(crate) hop_limit: Option<u8>,
}

impl Shaping {
    /// Whether either field departs from what the OS would pick, so a plain
    /// socket can be taken when it does not.
    pub(crate) fn is_active(self) -> bool {
        self.source_port.is_some() || self.hop_limit.is_some()
    }
}

/// Connects to `addr` as any other program would.
pub(crate) async fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
    connect_shaped(addr, Shaping::default()).await
}

/// Connects to `addr`, honouring `shaping`.
///
/// With inert shaping on Unix this is exactly [`TcpStream::connect`], so a
/// connection that chose nothing sends the SYN it always would, byte for byte.
/// Windows needs an option on every TCP socket before it connects, so there
/// the socket is always built.
pub(crate) async fn connect_shaped(addr: SocketAddr, shaping: Shaping) -> io::Result<TcpStream> {
    if tcp_is_plain(shaping) {
        return TcpStream::connect(addr).await;
    }
    let socket = socket(addr.ip(), Protocol::Tcp, shaping)?;
    socket.set_nonblocking(true)?;
    TcpSocket::from_std_stream(std::net::TcpStream::from(socket))
        .connect(addr)
        .await
}

/// Connects to `addr` on the calling thread, giving up after `timeout`.
///
/// For a caller that holds a blocking socket, which is a detection running on
/// the blocking pool. The same socket [`connect`] would build, connected the
/// way [`std::net::TcpStream::connect_timeout`] connects one.
pub(crate) fn connect_within(
    addr: SocketAddr,
    timeout: Duration,
) -> io::Result<std::net::TcpStream> {
    if tcp_is_plain(Shaping::default()) {
        return std::net::TcpStream::connect_timeout(&addr, timeout);
    }
    let socket = socket(addr.ip(), Protocol::Tcp, Shaping::default())?;
    socket.connect_timeout(&addr.into(), timeout)?;
    Ok(socket.into())
}

/// A UDP socket bound to an ephemeral port of `peer`'s address family, ready
/// to be connected to it.
pub(crate) async fn udp(peer: IpAddr) -> io::Result<UdpSocket> {
    udp_shaped(peer, Shaping::default()).await
}

/// A UDP socket for `peer`'s address family honouring `shaping`, ready to be
/// connected to it.
///
/// With inert shaping this is the plain ephemeral bind. Otherwise the socket
/// carries the chosen hop limit and binds the chosen source port, or an
/// ephemeral one, so a hop-limit-only socket still has somewhere to send from.
pub(crate) async fn udp_shaped(peer: IpAddr, shaping: Shaping) -> io::Result<UdpSocket> {
    if !shaping.is_active() {
        return UdpSocket::bind(wildcard(peer, 0)).await;
    }
    let socket = socket(peer, Protocol::Udp, shaping)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(std::net::UdpSocket::from(socket))
}

/// [`udp`], for a caller holding a blocking socket.
pub(crate) fn udp_blocking(peer: IpAddr) -> io::Result<std::net::UdpSocket> {
    std::net::UdpSocket::bind(wildcard(peer, 0))
}

/// The two transports a socket here speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Tcp,
    Udp,
}

/// Whether a TCP socket carrying `shaping` can be left to
/// [`TcpStream::connect`] to open, because nothing has to be set on it first.
///
/// Never on Windows, where every TCP socket carries the SYN retransmission
/// limit.
fn tcp_is_plain(shaping: Shaping) -> bool {
    !shaping.is_active() && cfg!(not(windows))
}

/// Opens a socket towards `target` and sets on it everything that has to be in
/// force before its first packet: `shaping`, and on Windows, for TCP, the SYN
/// retransmission limit.
///
/// Bound where something about its source was chosen, since TCP binds only to
/// pin a port and UDP must bind before it can send at all. Left blocking; an
/// async caller switches it before handing it to the runtime.
///
/// The hop limit goes on with the option the address family uses (`IP_TTL` or
/// `IPV6_UNICAST_HOPS`). Address reuse is what lets the many probes a scan
/// runs at once each bind one pinned source port: every one still carries a
/// distinct four-tuple through its destination, so the kernel keeps their
/// replies apart.
fn socket(target: IpAddr, protocol: Protocol, shaping: Shaping) -> io::Result<Socket> {
    let domain = match target {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let socket = match protocol {
        Protocol::Tcp => Socket::new(domain, Type::STREAM, Some(socket2::Protocol::TCP))?,
        Protocol::Udp => Socket::new(domain, Type::DGRAM, Some(socket2::Protocol::UDP))?,
    };

    if let Some(hops) = shaping.hop_limit {
        match target {
            IpAddr::V4(_) => socket.set_ttl_v4(hops.into())?,
            IpAddr::V6(_) => socket.set_unicast_hops_v6(hops.into())?,
        }
    }
    if shaping.source_port.is_some() {
        socket.set_reuse_address(true)?;
        // Unix only, and both supported platforms are: without it a second
        // socket on the pinned port is refused rather than bound alongside.
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
    }

    #[cfg(windows)]
    if protocol == Protocol::Tcp {
        syn_retries::limit(&socket, target);
    }

    if protocol == Protocol::Udp || shaping.source_port.is_some() {
        let port = shaping.source_port.unwrap_or(0);
        socket.bind(&wildcard(target, port).into())?;
    }
    Ok(socket)
}

/// The unspecified address of `family`'s address family, carrying `port`
/// (`0` lets the OS pick one).
///
/// A socket bound to `0.0.0.0` cannot reach an IPv6 destination, the connect
/// fails outright, so binding the family the target belongs to is what makes a
/// v6 target reachable at all rather than silently unprobed.
fn wildcard(family: IpAddr, port: u16) -> SocketAddr {
    match family {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
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

    #[test]
    fn a_socket_binds_the_family_of_its_target() {
        assert!(wildcard(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).is_ipv4());
        assert!(wildcard(IpAddr::V6(Ipv6Addr::LOCALHOST), 0).is_ipv6());
    }

    /// A connection that chose nothing is the kernel's own, so a scan that
    /// asked for no evasion sends what any other program would. Windows is the
    /// exception, and the reason this module exists.
    #[test]
    fn an_unshaped_connect_is_left_to_the_kernel_except_on_windows() {
        assert_eq!(tcp_is_plain(Shaping::default()), cfg!(not(windows)));
        assert!(!tcp_is_plain(Shaping {
            source_port: Some(53),
            hop_limit: None,
        }));
        assert!(!tcp_is_plain(Shaping {
            source_port: None,
            hop_limit: Some(12),
        }));
    }

    /// A shaped connect leaves from the chosen source port and carries the
    /// chosen hop limit: proven where it counts, on the wire, against a peer
    /// that reads both back.
    ///
    /// The peer's view of the source port is the bind end to end. A version
    /// that ignored the source port would show an ephemeral one here; one that
    /// skipped the hop limit would show the OS default, not `9`.
    #[tokio::test]
    async fn a_shaped_connect_pins_its_source_port_and_hop_limit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener");
        let addr = listener.local_addr().expect("its address");

        const PINNED: u16 = 40_517;
        const HOPS: u8 = 9;
        let shaping = Shaping {
            source_port: Some(PINNED),
            hop_limit: Some(HOPS),
        };

        let accept = tokio::spawn(async move { listener.accept().await });
        let stream = connect_shaped(addr, shaping)
            .await
            .expect("the shaped connect completes");
        let (_accepted, peer) = accept
            .await
            .expect("the accept task joins")
            .expect("an accept");

        assert_eq!(
            peer.port(),
            PINNED,
            "the SYN left from the pinned source port"
        );
        assert_eq!(
            stream.ttl().expect("the socket's hop limit"),
            u32::from(HOPS),
            "the SYN carried the chosen hop limit"
        );
    }

    /// A shaped UDP socket leaves from the chosen source port, read back off
    /// the datagram the far side receives.
    ///
    /// The UDP socket is built by its own path, so it earns its own guard: one
    /// that bound an ephemeral port instead of the pinned one would show a
    /// different source port to the receiver.
    #[tokio::test]
    async fn a_shaped_udp_socket_pins_its_source_port() {
        let server = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a loopback server");
        let server_addr = server.local_addr().expect("its address");

        const PINNED: u16 = 40_619;
        let shaping = Shaping {
            source_port: Some(PINNED),
            hop_limit: None,
        };
        let socket = udp_shaped(IpAddr::V4(Ipv4Addr::LOCALHOST), shaping)
            .await
            .expect("a shaped UDP socket");
        socket
            .connect(server_addr)
            .await
            .expect("addressing the peer");
        socket.send(b"probe").await.expect("sending the probe");

        let mut buf = [0u8; 8];
        let (_read, from) = server
            .recv_from(&mut buf)
            .await
            .expect("the datagram arrives");
        assert_eq!(
            from.port(),
            PINNED,
            "the datagram left from the pinned source port"
        );
    }

    /// The blocking connect a detection makes reaches a listener in either
    /// family, through the same socket the async one would build.
    #[test]
    fn a_blocking_connect_reaches_a_listener_in_either_family() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let listener = std::net::TcpListener::bind((ip, 0)).expect("a loopback listener");
            let addr = listener.local_addr().expect("its address");
            let stream =
                connect_within(addr, Duration::from_secs(1)).expect("the connect completes");
            assert_eq!(stream.peer_addr().expect("a peer"), addr, "{ip}");
        }
    }
}
