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
//! property of the caller, and there are two such things.
//!
//! **Where it leaves from.** A scan forced to a source, to leave by a LAN
//! interface when a VPN holds the default route, has its raw probes sent from
//! that source and by the link that holds it. Its connections have to leave
//! the same way, or the probe finds a port by one link and every conversation
//! that follows goes out by the other, from another address, through the
//! tunnel the scan was pinned out of. Which connections that applies to is an
//! [`Egress`], decided per destination by the scan's [`ForcedSources`].
//!
//! **What Windows needs set.** Windows resends a refused SYN until its SYN
//! retransmissions run out, which outlasts every connect budget this engine
//! sets, so on Windows every TCP socket needs its retransmissions limited
//! before the connect, whoever is connecting and whatever it wants to learn;
//! see `dial/syn_retries.rs`, compiled for Windows and for the tests only.
//!
//! A third thing is not the caller's either: a socket refused because the
//! process's descriptor table is full says nothing about the target, so it is
//! asked for again for a while rather than handed back as the connection's
//! outcome; see [`descriptors`]. How many sockets a scan holds at once is not
//! decided here. Each pass takes its share of the process's budget for the
//! connections it makes.
//!
//! A caller that opened its own socket would be the one that forgot any of
//! these.
//! What a caller does choose is [`Shaping`]: a source port and a hop limit,
//! which only the connect scanner's probes carry, since an evasion profile
//! shapes a scan's probes and not the conversations that follow them; see
//! [`crate::evasion`] for why the source port rules out the rest. With nothing
//! forced, nothing
//! chosen, and on a platform that needs nothing set, a connect is exactly a
//! plain [`TcpStream::connect`] and a datagram socket a plain ephemeral bind,
//! so the kernel sees what it would have seen from any other program.
//!
//! `tests/hygiene/dialling.rs` holds the rest of the crate to this: a TCP or
//! UDP socket opened anywhere else has to say why it is not a connection to a
//! target.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::num::NonZeroU32;
use std::time::Duration;

use socket2::{Domain, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::logging::info;
use crate::system::descriptors;
use crate::system::interface::{Link, LinkAddress};

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

/// The sources a scan forced, and what they apply to.
///
/// A forced source is for a target the routing table would send out by the
/// wrong link. So it applies where the scan's plan applies it (see
/// `map_ips_to_interfaces_forced`), and nowhere else: not to loopback or this
/// host's own addresses, which no link reaches; not to an IPv4 address written
/// inside IPv6, which no wire carries; not to a link-local address, which is
/// on the link its zone names; and not to a target inside a prefix a link here
/// holds, which that link reaches directly, a segment by its neighbours and a
/// tunnel's prefix through the tunnel. A connection to any of those is the
/// routing table's, as the probe before it was.
///
/// One source per family, and a source speaks for its own family only. A
/// target of a family the scan forced nothing for is left to the routing table
/// here as it is in the plan, since a v4 source cannot carry a v6 connection,
/// and refusing the target would make a connection behave differently from
/// the probe it follows.
///
/// Read from the host once, when the scan starts, as the plan is. Empty, which
/// is every scan that forced nothing, it reads nothing at all and every
/// connection is the routing table's.
#[derive(Debug, Clone, Default)]
pub(crate) struct ForcedSources {
    /// One pin per family the scan forced a source for.
    pins: Vec<Pin>,
    /// Every address a link that could carry a connection holds, whose prefixes
    /// are reached directly and never by a forced source.
    held: Vec<LinkAddress>,
}

impl ForcedSources {
    /// The sources in `forced`, one per family at most, as they apply to the
    /// links this host has now.
    pub(crate) fn new(forced: &[IpAddr]) -> Self {
        if forced.is_empty() {
            return Self::default();
        }
        let sources = Self::with_links(forced, &crate::system::interface::interfaces());
        for pin in &sources.pins {
            match pin.interface {
                Some(index) => info!(
                    verbosity = 1,
                    "connections to routed targets leave from {} on interface {index}", pin.source
                ),
                None => info!(
                    verbosity = 1,
                    "no interface holds {}, so connections forced to it will fail", pin.source
                ),
            }
        }
        sources
    }

    /// [`new`](Self::new) against an interface table the caller supplies.
    fn with_links(forced: &[IpAddr], links: &[Link]) -> Self {
        let mut pins: Vec<Pin> = Vec::new();
        for &source in forced {
            if pins
                .iter()
                .any(|pin| pin.source.is_ipv4() == source.is_ipv4())
            {
                continue;
            }
            let interface = links
                .iter()
                .find(|link| link.addresses().iter().any(|held| held.address() == source))
                .and_then(|link| NonZeroU32::new(link.index()));
            pins.push(Pin { source, interface });
        }

        // The links the plan classifies against: up, not loopback, and holding
        // an address. A prefix on a link that is down reaches nothing.
        let held = links
            .iter()
            .filter(|link| link.is_up() && !link.is_loopback())
            .flat_map(|link| link.addresses().iter().copied())
            .collect();

        Self { pins, held }
    }

    /// Where a connection to `target` leaves from.
    pub(crate) fn toward(&self, target: IpAddr) -> Egress {
        let Some(pin) = self
            .pins
            .iter()
            .find(|pin| pin.source.is_ipv4() == target.is_ipv4())
        else {
            return Egress::KERNEL;
        };
        let reached_directly = target.is_loopback()
            || matches!(target, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()
                || v6.is_unicast_link_local())
            || self.held.iter().any(|held| held.contains(&target));
        if reached_directly {
            return Egress::KERNEL;
        }
        Egress { pin: Some(*pin) }
    }
}

/// Where one connection leaves from: where the routing table says, or pinned
/// to a forced source.
///
/// A pinned socket is bound to the source address, so the kernel writes that
/// address into every packet, and to the interface holding it, so the packets
/// leave by that link whatever the default route says. The address alone is
/// not enough on Linux or macOS, which pick the outgoing link by destination
/// and would send a packet carrying the LAN address down the tunnel. Windows
/// picks the link from the source address, so there the address is all it
/// takes. Bound to an interface, Linux and macOS look the route up among that
/// link's routes alone, which finds the LAN's own gateway: a VPN that takes
/// the default route over leaves that one beneath its own.
///
/// Copied into every phase that dials, so the choice made once for a
/// destination travels with it to every connection made there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Egress {
    pin: Option<Pin>,
}

/// A forced source, and the interface that holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pin {
    source: IpAddr,
    /// `None` where no interface here holds the source, which leaves the bind
    /// to fail and the connection to be reported as one this host could not
    /// make, rather than made from somewhere else.
    interface: Option<NonZeroU32>,
}

impl Egress {
    /// Wherever the routing table sends it.
    pub(crate) const KERNEL: Self = Self { pin: None };

    /// Connects to `addr`, waiting out a full descriptor table first, and
    /// giving the connection itself `timeout`.
    ///
    /// A socket refused because the process holds too many is asked for again
    /// for up to [`descriptors::PATIENCE`] rather than returned as a failed
    /// connection, which a caller would read as something the target did; see
    /// [`descriptors::patiently`]. Past that the refusal is returned, and
    /// [`descriptors::exhausted`] names it.
    ///
    /// The budget is the connection's and not the wait's: each attempt is
    /// timed on its own, and one refused a socket is refused before its clock
    /// has run. A connection that outlasts it comes back as
    /// [`ErrorKind::TimedOut`](io::ErrorKind::TimedOut), the stack giving up
    /// first and the budget running out being the same outcome, a SYN out and
    /// nothing back.
    pub(crate) async fn connect_timed(
        self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> io::Result<TcpStream> {
        descriptors::patiently(descriptors::PATIENCE, || async move {
            tokio::time::timeout(timeout, self.connect_shaped(addr, Shaping::default()))
                .await
                .unwrap_or_else(|_elapsed| Err(io::ErrorKind::TimedOut.into()))
        })
        .await
    }

    /// Connects to `addr` once, honouring `shaping`.
    ///
    /// One attempt, a refusal of a socket included, for the connect scanner,
    /// which waits out a full table itself because it gives its descriptor back
    /// between attempts and answers to the scan's stop while it waits, and for
    /// a caller that has to know which of its attempts a full table refused.
    /// Every other caller takes [`connect_timed`](Self::connect_timed).
    ///
    /// Unpinned, unshaped and on Unix this is exactly [`TcpStream::connect`],
    /// so a connection that chose nothing sends the SYN it always would, byte
    /// for byte. Windows needs an option on every TCP socket before it
    /// connects, so there the socket is always built.
    pub(crate) async fn connect_shaped(
        self,
        addr: SocketAddr,
        shaping: Shaping,
    ) -> io::Result<TcpStream> {
        if self.tcp_is_plain(shaping) {
            return TcpStream::connect(addr).await;
        }
        let socket = self.socket(addr.ip(), Protocol::Tcp, shaping)?;
        socket.set_nonblocking(true)?;
        TcpSocket::from_std_stream(std::net::TcpStream::from(socket))
            .connect(addr)
            .await
    }

    /// Starts a connect to `addr`, honouring `shaping`, and returns once its
    /// SYN is the kernel's to send.
    ///
    /// [`connect_shaped`](Self::connect_shaped) in two halves, for the connect
    /// scanner, because the two fail for different reasons and the reason is
    /// the port's verdict. An error from here is this machine refusing before
    /// anything left it: no socket, no route, no source, no local port. An
    /// error from [`Connecting::finish`] came after the SYN was handed over: a
    /// refusal, an ICMP error the kernel matched to the connection, or nothing
    /// back at all. The operating system names both halves with the same
    /// codes, `EHOSTUNREACH` for a missing route here as for a firewall's
    /// rejection on the far side, so only where an error surfaces tells them
    /// apart.
    ///
    /// The socket carries nothing the caller did not choose, as
    /// [`connect_shaped`](Self::connect_shaped)'s does, so an unshaped connect
    /// sends the SYN any other program would.
    ///
    /// A connect that met itself is refused here on the platforms that refuse
    /// one outright, and comes back from [`Connecting::finish`] on the ones
    /// that complete it; [`met_itself`] names it either way.
    pub(crate) fn start_connect(
        self,
        addr: SocketAddr,
        shaping: Shaping,
    ) -> io::Result<Connecting> {
        let socket = self.socket(addr.ip(), Protocol::Tcp, shaping)?;
        socket.set_nonblocking(true)?;
        match socket.connect(&addr.into()) {
            Ok(()) => {}
            #[cfg(unix)]
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            // macOS refuses a connect given the target's own port as its
            // source, with `EINVAL` over IPv4 and `EADDRINUSE` over IPv6 from
            // a wildcard bind, and leaves that port bound to say so.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::InvalidInput | io::ErrorKind::AddrInUse
                ) && socket
                    .local_addr()
                    .ok()
                    .and_then(|local| local.as_socket())
                    .is_some_and(|local| local.port() == addr.port()) =>
            {
                return Err(io::Error::other(MetItself));
            }
            // The bind above let the pinned port be shared, so a refusal here
            // is the whole four-tuple taken: macOS says it is in use, Linux
            // that it is not available. What holds it is almost always this
            // same connection made a moment ago, still closing.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::AddrNotAvailable
                ) && shaping.source_port.is_some() =>
            {
                return Err(SourcePortHeld::error(shaping, e, Holder::Closing));
            }
            // Linux refuses a connect by the type of the route that matched,
            // and names each type by its own code: no route, or an
            // `unreachable` one, as a network or host it cannot reach, a
            // `prohibit` route as permission denied and a `blackhole` route as
            // an invalid argument. The last two are routes somebody wrote to
            // say nothing goes there, as much a fact about the destination as
            // the first, so they are handed on as the host this machine cannot
            // reach, in the kernel's own words. A security module denying the
            // connect is read the same way, and is the same fact from where
            // this process stands: nothing it sends may go there.
            #[cfg(target_os = "linux")]
            Err(e) if matches!(e.raw_os_error(), Some(libc::EACCES | libc::EINVAL)) => {
                return Err(io::Error::new(io::ErrorKind::HostUnreachable, e));
            }
            Err(e) => return Err(e),
        }
        Ok(Connecting {
            stream: TcpStream::from_std(std::net::TcpStream::from(socket))?,
        })
    }

    /// Connects to `addr` on the calling thread, giving the connection
    /// `timeout` and a full descriptor table `patience`.
    ///
    /// For a caller that holds a blocking socket, which is a detection running
    /// on the blocking pool. The same socket [`connect_timed`](Self::connect_timed) would
    /// build, connected the way [`std::net::TcpStream::connect_timeout`]
    /// connects one, and a full descriptor table waited out the same way
    /// before it, outside `timeout`. The patience is the caller's, because a
    /// detection's exchange has a clock of its own that a wait for a socket
    /// cannot outlast.
    pub(crate) fn connect_within(
        self,
        addr: SocketAddr,
        timeout: Duration,
        patience: Duration,
    ) -> io::Result<std::net::TcpStream> {
        descriptors::patiently_blocking(patience, || {
            if self.tcp_is_plain(Shaping::default()) {
                return std::net::TcpStream::connect_timeout(&addr, timeout);
            }
            let socket = self.socket(addr.ip(), Protocol::Tcp, Shaping::default())?;
            socket.connect_timeout(&addr.into(), timeout)?;
            Ok(socket.into())
        })
    }

    /// A UDP socket bound for `peer`, ready to be connected to it, with a full
    /// descriptor table waited out for `patience`, as
    /// [`connect_timed`](Self::connect_timed) waits it out for
    /// [`PATIENCE`](descriptors::PATIENCE).
    pub(crate) async fn udp(self, peer: IpAddr, patience: Duration) -> io::Result<UdpSocket> {
        descriptors::patiently(patience, || self.udp_shaped(peer, Shaping::default())).await
    }

    /// A UDP socket bound for `peer` and honouring `shaping`, ready to be
    /// connected to it.
    ///
    /// One attempt, for the connect scanner's own wait; see
    /// [`connect_shaped`](Self::connect_shaped).
    ///
    /// Unpinned and unshaped, this is the plain ephemeral bind. Otherwise the
    /// socket carries its pin, the chosen hop limit, and the chosen source port
    /// or an ephemeral one.
    pub(crate) async fn udp_shaped(self, peer: IpAddr, shaping: Shaping) -> io::Result<UdpSocket> {
        if self.pin.is_none() && !shaping.is_active() {
            return UdpSocket::bind(wildcard(peer, 0)).await;
        }
        let socket = self.socket(peer, Protocol::Udp, shaping)?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(std::net::UdpSocket::from(socket))
    }

    /// [`udp`](Self::udp), for a caller holding a blocking socket, waiting
    /// out a full descriptor table for `patience`; see
    /// [`connect_within`](Self::connect_within).
    pub(crate) fn udp_blocking(
        self,
        peer: IpAddr,
        patience: Duration,
    ) -> io::Result<std::net::UdpSocket> {
        descriptors::patiently_blocking(patience, || {
            if self.pin.is_none() {
                return std::net::UdpSocket::bind(wildcard(peer, 0));
            }
            Ok(self.socket(peer, Protocol::Udp, Shaping::default())?.into())
        })
    }

    /// Whether a TCP socket carrying `shaping` can be left to
    /// [`TcpStream::connect`] to open, because nothing has to be set on it
    /// first.
    ///
    /// Never on Windows, where every TCP socket carries the SYN retransmission
    /// limit.
    fn tcp_is_plain(self, shaping: Shaping) -> bool {
        self.pin.is_none() && !shaping.is_active() && cfg!(not(windows))
    }

    /// Opens a socket towards `target` and sets on it everything that has to
    /// be in force before its first packet: the pin, `shaping`, and on
    /// Windows, for TCP, the SYN retransmission limit.
    ///
    /// Bound where something about its source was chosen, since TCP binds only
    /// to pin an address or a port and UDP must bind before it can send at
    /// all. Left blocking; an async caller switches it before handing it to
    /// the runtime.
    ///
    /// The hop limit goes on with the option the address family uses (`IP_TTL`
    /// or `IPV6_UNICAST_HOPS`). Address reuse is what lets the many probes a
    /// scan runs at once each bind one pinned source port: every one still
    /// carries a distinct four-tuple through its destination, so the kernel
    /// keeps their replies apart.
    fn socket(self, target: IpAddr, protocol: Protocol, shaping: Shaping) -> io::Result<Socket> {
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

        let port = shaping.source_port.unwrap_or(0);
        let bound = match self.pin {
            Some(pin) => pin.bind(&socket, target, port),
            None if protocol == Protocol::Udp || shaping.source_port.is_some() => {
                socket.bind(&wildcard(target, port).into())
            }
            None => Ok(()),
        };
        match bound {
            // Refused although this socket shares the port, so another holds
            // it without sharing.
            Err(e) if e.kind() == io::ErrorKind::AddrInUse && shaping.source_port.is_some() => {
                Err(SourcePortHeld::error(shaping, e, Holder::Socket))
            }
            Err(e) => Err(e),
            Ok(()) => Ok(socket),
        }
    }
}

/// A connection or datagram refused its pinned source port, because something
/// on this machine already held it.
///
/// Named apart from every other refusal because the remedy is the caller's and
/// specific. A port pinned for every probe is taken by each of them in turn,
/// and a connection keeps its four-tuple in `TIME_WAIT` after it ends, a
/// minute on Linux and half that on macOS, so the same port asked again inside
/// that wait from the same pinned port is refused. Nothing is sent, the port
/// is left unasked, and a scan run again once the wait is over asks it.
/// Waiting it out here would stall the scan on every such port, and ending
/// each connection with a reset to skip the wait would change what every
/// pinned probe puts on the wire.
#[derive(Debug)]
pub(crate) struct SourcePortHeld {
    /// The pinned port.
    pub(crate) port: u16,
    /// What held it.
    pub(crate) holder: Holder,
    /// The operating system's own error.
    cause: io::Error,
}

/// What held a pinned source port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Holder {
    /// A connection from the port to the same destination, as a rule this
    /// scan's own, still in its closing wait.
    Closing,
    /// Another socket on this machine, bound to the port without sharing it.
    Socket,
}

impl SourcePortHeld {
    /// The refusal `cause`, of `shaping`'s pinned port, as an error that says
    /// so.
    fn error(shaping: Shaping, cause: io::Error, holder: Holder) -> io::Error {
        let kind = cause.kind();
        io::Error::new(
            kind,
            Self {
                port: shaping.source_port.unwrap_or_default(),
                holder,
                cause,
            },
        )
    }

    /// The refusal `error` is, where it is a pinned source port held.
    pub(crate) fn of(error: &io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref::<Self>()
    }
}

impl std::fmt::Display for SourcePortHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "source port {} in use: {}", self.port, self.cause)
    }
}

impl std::error::Error for SourcePortHeld {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// A connect whose SYN is the kernel's to send, waiting on what comes back.
///
/// See [`Egress::start_connect`] for why a connect is made in two halves.
#[derive(Debug)]
pub(crate) struct Connecting {
    /// The socket, registered with the runtime while its handshake is under
    /// way, so its readiness is what says the handshake is over.
    stream: TcpStream,
}

impl Connecting {
    /// Waits for the handshake to finish, and returns the connection or what
    /// ended it.
    ///
    /// Unbounded, as a connect is; the caller holds the clock. Every error
    /// here came after the SYN was handed to the kernel, so it is something
    /// that happened on the way to the target or at it: a reset, an ICMP error
    /// the kernel matched to the connection, the stack giving up. A connection
    /// that met itself comes back as an error [`met_itself`] names, and is
    /// closed as it is dropped.
    pub(crate) async fn finish(self) -> io::Result<TcpStream> {
        self.stream.writable().await?;
        if let Some(error) = self.stream.take_error()? {
            return Err(error);
        }
        if self.stream.local_addr()? == self.stream.peer_addr()? {
            return Err(io::Error::other(MetItself));
        }
        Ok(self.stream)
    }
}

/// A connect that reached its own socket rather than anything listening.
///
/// A connect to one of this machine's own addresses can be given the port it
/// is aimed at as its own ephemeral source, when nothing holds that port, and
/// then its SYN arrives at the socket that sent it. Linux completes the
/// handshake as a simultaneous open, as macOS does over IPv6 from a socket
/// bound to the address; macOS otherwise refuses the connect. A full-range
/// scan of loopback meets it once or twice a run, at whichever ports the
/// kernel happens to draw.
///
/// Neither outcome is an answer about the port. The completed one is a
/// conversation with nobody, which read as a handshake would file a port with
/// no listener as open and identify its service by the scanner's own
/// questions echoed back; the refused one was never sent. What it does prove
/// is that nothing held the port when the kernel chose it, which is why a
/// fresh socket, given another source, is the way to the verdict.
#[derive(Debug)]
struct MetItself;

impl std::fmt::Display for MetItself {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the connect was given its target's port as its source and reached itself")
    }
}

impl std::error::Error for MetItself {}

/// Whether `error` is a connect that reached its own socket rather than
/// anything listening; see [`Egress::start_connect`].
pub(crate) fn met_itself(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<MetItself>())
}

impl Pin {
    /// Binds `socket`, about to reach `target`, to this pin's source and
    /// `port`, and to the interface holding the source.
    ///
    /// A link-local source is bound with its interface as its scope, the only
    /// way a bare `fe80::` names one address.
    fn bind(self, socket: &Socket, target: IpAddr, port: u16) -> io::Result<()> {
        if self.source.is_ipv4() != target.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a connection to {target} cannot leave from {}", self.source),
            ));
        }

        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        match self.source {
            IpAddr::V4(_) => socket.bind_device_by_index_v4(self.interface)?,
            IpAddr::V6(_) => socket.bind_device_by_index_v6(self.interface)?,
        }

        let address = match self.source {
            IpAddr::V4(v4) => SocketAddr::from((v4, port)),
            IpAddr::V6(v6) => {
                let scope = match (v6.is_unicast_link_local(), self.interface) {
                    (true, Some(index)) => index.get(),
                    _ => 0,
                };
                SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope))
            }
        };
        socket.bind(&address.into())
    }
}

/// The two transports a socket here speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Tcp,
    Udp,
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
        assert_eq!(
            Egress::KERNEL.tcp_is_plain(Shaping::default()),
            cfg!(not(windows))
        );
        assert!(!Egress::KERNEL.tcp_is_plain(Shaping {
            source_port: Some(53),
            hop_limit: None,
        }));
        assert!(!Egress::KERNEL.tcp_is_plain(Shaping {
            source_port: None,
            hop_limit: Some(12),
        }));
        let pinned = Egress {
            pin: Some(Pin {
                source: v4(192, 0, 2, 10),
                interface: NonZeroU32::new(2),
            }),
        };
        assert!(
            !pinned.tcp_is_plain(Shaping::default()),
            "a pinned connection was left to the kernel, which would source it"
        );
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
        let stream = Egress::KERNEL
            .connect_shaped(addr, shaping)
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
        let socket = Egress::KERNEL
            .udp_shaped(IpAddr::V4(Ipv4Addr::LOCALHOST), shaping)
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
            let stream = Egress::KERNEL
                .connect_within(addr, Duration::from_secs(1), descriptors::PATIENCE)
                .expect("the connect completes");
            assert_eq!(stream.peer_addr().expect("a peer"), addr, "{ip}");
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(text: &str) -> IpAddr {
        text.parse().expect("an IPv6 literal")
    }

    fn pinned(source: IpAddr, interface: u32) -> Egress {
        Egress {
            pin: Some(Pin {
                source,
                interface: NonZeroU32::new(interface),
            }),
        }
    }

    /// A laptop on a LAN, a WireGuard tunnel up beside it, a loopback, and a
    /// link that is down.
    fn laptop() -> Vec<Link> {
        use crate::system::interface::LinkKind;
        vec![
            Link::new("lo", 1)
                .with_kind(LinkKind::Loopback)
                .with_link_up(true)
                .with_addresses(vec![LinkAddress::new(v4(127, 0, 0, 1), 8)]),
            Link::new("eth0", 2).with_link_up(true).with_addresses(vec![
                LinkAddress::new(v4(192, 0, 2, 10), 24),
                LinkAddress::new(v6("2001:db8:1::10"), 64),
            ]),
            Link::new("wg0", 5)
                .with_link_up(true)
                .with_addresses(vec![LinkAddress::new(v4(198, 51, 100, 2), 24)]),
            Link::new("eth9", 9).with_addresses(vec![LinkAddress::new(v4(203, 0, 113, 1), 24)]),
        ]
    }

    /// A forced source carries a connection to a target only the routing table
    /// could have sent the wrong way, and leaves every other to it, as the plan
    /// leaves the probes before them.
    ///
    /// Each case is a way to get this wrong: pinning a neighbour on the LAN to
    /// the LAN is harmless, but pinning a tunnel peer to the LAN takes it off
    /// the only link that reaches it, and pinning loopback to a LAN interface
    /// reaches nothing.
    #[test]
    fn a_forced_source_carries_only_what_no_link_here_reaches_directly() {
        let sources =
            ForcedSources::with_links(&[v4(192, 0, 2, 10), v6("2001:db8:1::10")], &laptop());
        let lan_v4 = pinned(v4(192, 0, 2, 10), 2);
        let lan_v6 = pinned(v6("2001:db8:1::10"), 2);

        for (target, expected, why) in [
            (v4(198, 18, 0, 1), lan_v4, "a routed target"),
            (v6("2001:db8:ffff::1"), lan_v6, "a routed IPv6 target"),
            (
                v4(203, 0, 113, 50),
                lan_v4,
                "a target in the prefix of a link that is down",
            ),
            (v4(192, 0, 2, 77), Egress::KERNEL, "a neighbour on the LAN"),
            (v4(192, 0, 2, 10), Egress::KERNEL, "this host's own address"),
            (
                v4(198, 51, 100, 1),
                Egress::KERNEL,
                "a peer inside the tunnel",
            ),
            (v4(127, 0, 0, 1), Egress::KERNEL, "IPv4 loopback"),
            (v6("::1"), Egress::KERNEL, "IPv6 loopback"),
            (
                v6("::ffff:198.18.0.1"),
                Egress::KERNEL,
                "an IPv4 host written inside IPv6",
            ),
            (v6("fe80::1"), Egress::KERNEL, "a link-local neighbour"),
        ] {
            assert_eq!(sources.toward(target), expected, "{why}: {target}");
        }
    }

    /// A source speaks for its own family, and a scan that forced none for a
    /// family leaves that family's connections where the plan leaves its
    /// probes: to the routing table.
    #[test]
    fn a_forced_source_speaks_for_its_own_family_only() {
        let only_v4 = ForcedSources::with_links(&[v4(192, 0, 2, 10)], &laptop());
        assert_eq!(only_v4.toward(v6("2001:db8:ffff::1")), Egress::KERNEL);

        let only_v6 = ForcedSources::with_links(&[v6("2001:db8:1::10")], &laptop());
        assert_eq!(only_v6.toward(v4(198, 18, 0, 1)), Egress::KERNEL);

        // One per family: the first named is the one used.
        let two = ForcedSources::with_links(&[v4(192, 0, 2, 10), v4(198, 51, 100, 2)], &laptop());
        assert_eq!(two.toward(v4(198, 18, 0, 1)), pinned(v4(192, 0, 2, 10), 2));

        assert_eq!(
            ForcedSources::with_links(&[], &laptop()).toward(v4(198, 18, 0, 1)),
            Egress::KERNEL
        );
    }

    /// The same rule the probes were planned by, asked of this machine's own
    /// interfaces: a connection is pinned exactly where the plan paired its
    /// target with the forced source.
    ///
    /// The rule is written twice, there in the classifier and here, and this
    /// is what keeps the two from drifting. Skipped on a host holding no IPv4
    /// address outside loopback, which has nothing to force.
    #[test]
    fn a_connection_is_pinned_exactly_where_the_plan_pinned_its_probe() {
        use crate::model::ip::set::IpSet;
        use crate::system::interface::{interfaces, map_ips_to_interfaces_forced};

        let Some(held) = interfaces()
            .into_iter()
            .filter(|link| link.is_up() && !link.is_loopback())
            .flat_map(|link| link.addresses().to_vec())
            .find(|held| {
                matches!(held.address(), IpAddr::V4(a) if !a.is_loopback() && !a.is_link_local())
                    && held.prefix() <= 30
            })
        else {
            return;
        };
        let forced = held.address();
        let IpAddr::V4(own) = forced else {
            unreachable!("filtered to IPv4 above");
        };
        let neighbour = [1u32, 2]
            .into_iter()
            .map(|offset| {
                let network = u32::from(own) & (u32::MAX << (32 - held.prefix()));
                IpAddr::V4(Ipv4Addr::from(network + offset))
            })
            .find(|candidate| *candidate != forced)
            .expect("a /30 or wider holds a second address");

        let sources = ForcedSources::new(&[forced]);
        for target in [
            v4(198, 18, 0, 1),
            v4(127, 0, 0, 1),
            forced,
            neighbour,
            v6("::ffff:198.18.0.1"),
        ] {
            let mut set = IpSet::new();
            set.insert(target);
            let planned = map_ips_to_interfaces_forced(set, &[forced])
                .routed
                .iter()
                .any(|routed| routed.target == target && routed.source == forced);
            assert_eq!(
                sources.toward(target).pin.is_some(),
                planned,
                "{target}: the plan {} its probe to {forced}",
                if planned { "pinned" } else { "did not pin" }
            );
        }
    }

    /// A source no interface here holds is kept as asked, and the connection
    /// fails to bind rather than going out from an address the routing table
    /// picked instead.
    #[tokio::test]
    async fn a_source_this_host_does_not_hold_fails_the_connection_rather_than_moving_it() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener");
        let addr = listener.local_addr().expect("its address");

        let sources = ForcedSources::with_links(&[v4(192, 0, 2, 99)], &laptop());
        let egress = sources.toward(v4(198, 18, 0, 1));
        assert_eq!(egress, pinned(v4(192, 0, 2, 99), 0));

        assert!(
            egress
                .connect_timed(addr, crate::config::limits::CONNECT_PROBE_TIMEOUT)
                .await
                .is_err(),
            "a connection forced to an address this host does not hold went out anyway"
        );
    }

    /// The loopback interface, and an address on it to leave from that the
    /// routing table would not have picked for a connection to `127.0.0.1`,
    /// where the host has one.
    ///
    /// Linux answers for the whole of `127.0.0.0/8`. macOS holds `127.0.0.1`
    /// alone unless somebody added an alias, and there the source is the
    /// kernel's own choice and only the interface can be told apart.
    fn loopback_pin() -> (Egress, u32) {
        let lo = crate::system::interface::interfaces()
            .into_iter()
            .find(Link::is_loopback)
            .expect("a loopback interface");
        let second = lo
            .addresses()
            .iter()
            .map(LinkAddress::address)
            .find(|address| address.is_ipv4() && *address != v4(127, 0, 0, 1));
        let source = if cfg!(target_os = "linux") {
            v4(127, 0, 0, 2)
        } else {
            second.unwrap_or(v4(127, 0, 0, 1))
        };
        (pinned(source, lo.index()), lo.index())
    }

    /// A pinned connection leaves from its source and is bound to its
    /// interface, read back where each is visible: the source off the peer's
    /// accept, the interface off the socket itself.
    ///
    /// The unpinned connection beside it is the control. Where the host has a
    /// second loopback address the two sources differ, so the pin is what
    /// moved it; everywhere, only the pinned socket is bound to a device.
    #[tokio::test]
    async fn a_pinned_connection_leaves_from_its_source_and_by_its_interface() {
        let (egress, index) = loopback_pin();
        let source = egress.pin.expect("a pin").source;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener");
        let addr = listener.local_addr().expect("its address");

        let accept = tokio::spawn(async move {
            let (_, first) = listener.accept().await.expect("the pinned connection");
            let (_, second) = listener.accept().await.expect("the plain connection");
            (first, second)
        });
        let within = crate::config::limits::CONNECT_PROBE_TIMEOUT;
        let pinned = egress
            .connect_timed(addr, within)
            .await
            .expect("the pinned connect");
        let plain = Egress::KERNEL
            .connect_timed(addr, within)
            .await
            .expect("the plain connect");
        let (first, second) = accept.await.expect("the accept task joins");

        assert_eq!(first.ip(), source, "the pinned connection's source");
        assert_eq!(
            second.ip(),
            v4(127, 0, 0, 1),
            "the plain connection's source"
        );

        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        {
            let bound = |stream: &TcpStream| {
                socket2::SockRef::from(stream)
                    .device_index_v4()
                    .expect("the socket's interface")
            };
            assert_eq!(bound(&pinned), NonZeroU32::new(index));
            assert_eq!(bound(&plain), None);
        }
        // Elsewhere the interface a socket is bound to cannot be read back.
        #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
        let _ = (pinned, plain, index);
    }

    /// The datagram and the blocking connection are built by their own paths,
    /// so each earns its own guard: one that skipped the pin would show the
    /// kernel's source to the peer.
    #[tokio::test]
    async fn a_pinned_datagram_and_blocking_connection_leave_from_the_source() {
        let (egress, _) = loopback_pin();
        let source = egress.pin.expect("a pin").source;

        let server = UdpSocket::bind("127.0.0.1:0").await.expect("a UDP server");
        let server_addr = server.local_addr().expect("its address");
        let socket = egress
            .udp(server_addr.ip(), descriptors::PATIENCE)
            .await
            .expect("a pinned socket");
        socket
            .connect(server_addr)
            .await
            .expect("addressing the peer");
        socket.send(b"probe").await.expect("sending");
        let mut buf = [0u8; 8];
        let (_, from) = server.recv_from(&mut buf).await.expect("the datagram");
        assert_eq!(from.ip(), source, "the datagram's source");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let addr = listener.local_addr().expect("its address");
        // The accepted stream is handed back rather than dropped with the
        // thread: closed at once, it can reach the connecting side as a hang-up
        // before the connect has seen its handshake finish, which macOS reports
        // as a failed connect.
        let handle = std::thread::spawn(move || listener.accept());
        let _stream = egress
            .connect_within(addr, Duration::from_secs(1), descriptors::PATIENCE)
            .expect("the blocking connect");
        let (_accepted, from) = handle.join().expect("the accept joins").expect("an accept");
        assert_eq!(from.ip(), source, "the blocking connection's source");
    }
}
