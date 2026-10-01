// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The sockets the engine opens towards a target
//!
//! Everything that talks to a scanned host through the operating system's own TCP and
//! UDP opens its socket here: the connect scan and its sweep, the service pass, the
//! fingerprint engine's second connections and its analyzers, a TLS enumeration, a
//! detection's exchange, and the single datagrams sent to mDNS and SNMP agents.
//!
//! One place, because three things a socket must carry before it connects do not
//! depend on the caller.
//!
//! **Where it leaves from.** A scan forced to a source, to leave by a LAN interface
//! while a VPN holds the default route, sends its raw probes from that source by the
//! link that holds it. Its connections must leave the same way, or the probe finds a
//! port by one link and every conversation after it goes out by the other, from
//! another address, through the tunnel the scan was pinned out of. Which connections
//! that applies to is an [`Egress`], decided per destination by the scan's
//! [`ForcedSources`].
//!
//! **What Windows needs set.** Windows resends a refused SYN until its SYN
//! retransmissions run out, which outlasts every connect budget this engine sets, so
//! every TCP socket there needs its retransmissions limited before the connect; see
//! `dial/syn_retries.rs`, compiled for Windows and for the tests only.
//!
//! **When it may leave.** A scan that keeps a gap between its probes keeps it between
//! these too: every socket here is opened with the [`Slot`] one probe was given, which
//! the scan's egress hands out only once the gap allows. See [`pacing`].
//!
//! A socket refused because the process's descriptor table is full says nothing about
//! the target, so it is asked for again for a while before the refusal is returned as
//! the outcome; see [`descriptors`]. How many sockets a scan holds at once is decided
//! elsewhere: each pass takes its share of the process's budget.
//!
//! How long a conversation over one of these sockets waits is the caller's choice, set
//! for a path that costs nothing. What a measured path adds to each wait is a
//! [`PathAllowance`], sized as the port scans size their own probes.
//!
//! What a caller does choose is [`Shaping`]: a source port and a hop limit, carried
//! only by the connect scanner's probes, since an evasion profile shapes a scan's
//! probes and not the conversations after them; see [`crate::evasion`] for why the
//! source port rules out the rest. With nothing forced, nothing chosen, and on a
//! platform that needs nothing set, a connect is a plain [`TcpStream::connect`] and a
//! datagram socket a plain ephemeral bind, so the kernel sees what any other program
//! would send.
//!
//! `tests/hygiene/dialling.rs` enforces this: a TCP or UDP socket opened anywhere else
//! has to say why it is not a connection to a target.

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

mod allowance;
pub(crate) use allowance::PathAllowance;
#[cfg(test)]
pub(crate) use allowance::UNMEASURED_PATH_WAIT;

pub(crate) mod pacing;
pub(crate) use pacing::Slot;

/// How many TCP connections this process has begun to each destination, for tests
/// that must know a pass sent a port nothing.
///
/// Counted here, where every connection to a target begins, because no other process
/// can move this count. A loopback service tells this process's connections by their
/// far end, and a connection closed before the service accepted it has no far end left:
/// a connect scan's closes at once, and so does another scanner's sweep of loopback. A
/// connection counts as it begins, so a refused one, or one closed the moment it
/// completed, counts too.
#[cfg(test)]
pub(crate) mod dialled {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{LazyLock, Mutex};
    use std::time::Instant;

    /// When each connection to an address was begun, in order.
    static DIALLED: LazyLock<Mutex<HashMap<SocketAddr, Vec<Instant>>>> =
        LazyLock::new(Mutex::default);

    /// Counts a connection begun to `addr`, now.
    pub(super) fn note(addr: SocketAddr) {
        DIALLED
            .lock()
            .unwrap()
            .entry(addr)
            .or_default()
            .push(Instant::now());
    }

    /// How many connections this process has begun to `addr`, since a
    /// [`SilentPort`](crate::testing::loopback::SilentPort) last opened there.
    pub(crate) fn to(addr: SocketAddr) -> usize {
        times(addr).len()
    }

    /// When this process began each of its connections to `addr`, for tests that
    /// must know how far apart they left. An accept may never see a connection that
    /// closed the moment it completed.
    ///
    /// Only those since a [`SilentPort`](crate::testing::loopback::SilentPort) last
    /// opened at `addr`, which were to that port.
    pub(crate) fn times(addr: SocketAddr) -> Vec<Instant> {
        let since = crate::testing::loopback::opened_at(addr);
        DIALLED
            .lock()
            .unwrap()
            .get(&addr)
            .into_iter()
            .flatten()
            .copied()
            .filter(|&begun| since.is_none_or(|opened| begun >= opened))
            .collect()
    }

    /// The error each connection begun to an address is refused with, and how many
    /// more are.
    static REFUSED: LazyLock<Mutex<HashMap<SocketAddr, (i32, usize)>>> =
        LazyLock::new(Mutex::default);

    /// Makes the next `times` connections begun to `addr` fail before anything leaves
    /// with the operating system's error `code`, for kernel refusals a test cannot
    /// arrange, such as a neighbour hold-down.
    #[cfg(unix)]
    pub(crate) fn refuse(addr: SocketAddr, code: i32, times: usize) {
        REFUSED.lock().unwrap().insert(addr, (code, times));
    }

    /// The refusal the next connection to `addr` meets, if one is due.
    pub(super) fn refusal(addr: SocketAddr) -> Option<std::io::Error> {
        let mut refused = REFUSED.lock().unwrap();
        let (code, times) = refused.get_mut(&addr).filter(|(_, times)| *times > 0)?;
        *times -= 1;
        Some(std::io::Error::from_raw_os_error(*code))
    }
}

/// What a caller has chosen about a socket beyond where it is going: a source port to
/// leave from and a hop limit to carry.
///
/// Both are ordinary socket options needing no privilege, and the only parts of an
/// evasion profile a kernel-built connection can carry. The rest (a spoofed address,
/// fragments, decoys, a padded or mangled segment) needs a segment this process writes
/// itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Shaping {
    /// The source port the socket binds to, or `None` to let the OS choose one.
    pub(crate) source_port: Option<u16>,
    /// The hop limit the socket carries, or `None` to leave the OS default.
    pub(crate) hop_limit: Option<u8>,
}

impl Shaping {
    /// Whether either field departs from what the OS would pick; when neither does, a
    /// plain socket is used.
    pub(crate) fn is_active(self) -> bool {
        self.source_port.is_some() || self.hop_limit.is_some()
    }
}

/// The sources a scan forced, and what they apply to.
///
/// A forced source is for a target the routing table would send out by the wrong link,
/// so it applies exactly where the scan's plan applies it (see
/// `map_ips_to_interfaces_forced`). It does not apply to loopback or this host's own
/// addresses, which no link reaches; to an IPv4 address embedded in IPv6, which no wire
/// carries; to a link-local address, which is on the link its zone names; or to a
/// target inside a prefix a local link holds, which that link reaches directly (a
/// segment by its neighbours, a tunnel's prefix through the tunnel). Connections to
/// those follow the routing table, as their probes did.
///
/// One source per family, each speaking for its own family only. A target of a family
/// with no forced source is left to the routing table, as in the plan, since a v4
/// source cannot carry a v6 connection.
///
/// Read from the host once, when the scan starts, as the plan is. When empty it reads
/// nothing and every connection follows the routing table.
#[derive(Debug, Clone, Default)]
pub(crate) struct ForcedSources {
    /// One pin per family the scan forced a source for.
    pins: Vec<Pin>,
    /// Every address held by a link that could carry a connection; their prefixes are
    /// reached directly, never by a forced source.
    held: Vec<LinkAddress>,
}

impl ForcedSources {
    /// The sources in `forced`, at most one per family, as they apply to the links
    /// this host has now.
    pub(crate) fn new(forced: &[IpAddr]) -> Self {
        if forced.is_empty() {
            return Self::default();
        }
        let sources = Self::with_links(forced, &crate::system::interface::interfaces_or_none());
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

        // The links the plan classifies against: up, not loopback, and holding an
        // address. A prefix on a down link reaches nothing.
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
        Egress {
            pin: Some(*pin),
            gate: None,
        }
    }
}

/// Where one connection leaves from: where the routing table says, or pinned to a
/// forced source.
///
/// A pinned socket is bound to the source address, so the kernel writes it into every
/// packet, and to the interface holding it, so packets leave by that link whatever the
/// default route says. The address alone is not enough on Linux or macOS, which pick
/// the outgoing link by destination and would send a packet carrying the LAN address
/// down the tunnel. Windows picks the link from the source address, so the address is
/// enough there. Bound to an interface, Linux and macOS look up the route among that
/// link's routes alone, which finds the LAN's own gateway beneath a VPN's default
/// route.
///
/// Cloned into every phase that dials, so the choice made once for a destination
/// applies to every connection made there.
///
/// It also carries the scan's pacing, where the scan keeps a gap between probes: every
/// socket method here takes the [`Slot`] one probe was given, which only
/// [`slot`](Self::slot) hands out, once the scan's gate lets the probe leave. See
/// [`pacing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Egress {
    pin: Option<Pin>,
    /// The scan whose gaps this egress's probes keep, or `None` for a scan that keeps
    /// none and for a connection made outside a scan.
    gate: Option<pacing::Gate>,
}

/// A forced source, and the interface that holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pin {
    source: IpAddr,
    /// `None` where no interface here holds the source. The bind then fails and the
    /// connection is reported as one this host could not make.
    interface: Option<NonZeroU32>,
}

impl Egress {
    /// Wherever the routing table sends it, and whenever the caller likes.
    pub(crate) const KERNEL: Self = Self {
        pin: None,
        gate: None,
    };

    /// The same egress, its probes held to the gaps `gate` keeps, or to none where
    /// there is no gate.
    ///
    /// A scan that keeps no gap gives none, and its slots are free.
    pub(crate) fn paced_by(mut self, gate: Option<pacing::Gate>) -> Self {
        self.gate = gate;
        self
    }

    /// Connects to `addr` for the probe `slot` was given, waiting out a full
    /// descriptor table first, and giving the connection itself `timeout`.
    ///
    /// A socket refused because the process holds too many is retried for up to
    /// [`descriptors::patience`], since a caller would read a failed connection as
    /// something the target did; see [`descriptors::patiently`]. Past that the refusal
    /// is returned, and [`descriptors::exhausted`] names it. All attempts are the one
    /// probe, since none before the last left this machine, and the slot is given back
    /// if the last did not either; see [`Slot::settle`].
    ///
    /// `timeout` is per attempt; a socket refusal comes before the clock starts. A
    /// connection that outlasts it comes back as
    /// [`ErrorKind::TimedOut`](io::ErrorKind::TimedOut), the same outcome as the stack
    /// giving up first: a SYN out and nothing back.
    pub(crate) async fn connect_timed(
        &self,
        slot: Slot,
        addr: SocketAddr,
        timeout: Duration,
    ) -> io::Result<TcpStream> {
        debug_assert!(slot.is_for(addr.ip()), "a slot claimed for another host");
        let connected = descriptors::patiently(descriptors::patience(), || async move {
            tokio::time::timeout(timeout, self.connect_once(addr, Shaping::default()))
                .await
                .unwrap_or_else(|_elapsed| Err(io::ErrorKind::TimedOut.into()))
        })
        .await;
        slot.settle(&connected);
        connected
    }

    /// Connects to `addr` once, honouring `shaping`, for the probe `slot` was given.
    ///
    /// One attempt, socket refusal included, for a caller that waits out a full table
    /// itself or must know which attempt a full table refused. The slot stays the
    /// caller's, since a socket refusal leaves the probe unsent and the next attempt is
    /// the same probe; the caller settles it with the last outcome. Other callers use
    /// [`connect_timed`](Self::connect_timed).
    ///
    /// Unpinned, unshaped and on Unix this is exactly [`TcpStream::connect`], so the
    /// SYN is byte for byte the default one. Windows needs an option on every TCP
    /// socket before it connects, so there the socket is always built.
    pub(crate) async fn connect_shaped(
        &self,
        slot: &Slot,
        addr: SocketAddr,
        shaping: Shaping,
    ) -> io::Result<TcpStream> {
        debug_assert!(slot.is_for(addr.ip()), "a slot claimed for another host");
        self.connect_once(addr, shaping).await
    }

    /// [`connect_shaped`](Self::connect_shaped) for a caller in this module that holds
    /// the slot itself.
    async fn connect_once(&self, addr: SocketAddr, shaping: Shaping) -> io::Result<TcpStream> {
        #[cfg(test)]
        dialled::note(addr);
        if self.tcp_is_plain(shaping) {
            return TcpStream::connect(addr).await;
        }
        let socket = self.socket(addr.ip(), Protocol::Tcp, shaping)?;
        socket.set_nonblocking(true)?;
        TcpSocket::from_std_stream(std::net::TcpStream::from(socket))
            .connect(addr)
            .await
    }

    /// Starts a connect to `addr`, honouring `shaping`, and returns once its SYN is the
    /// kernel's to send.
    ///
    /// [`connect_shaped`](Self::connect_shaped) in two halves, for the connect scanner,
    /// because which half fails decides the port's verdict. An error from here is this
    /// machine refusing before anything left: no socket, no route, no source, no local
    /// port. An error from [`Connecting::finish`] came after the SYN was handed over: a
    /// refusal, an ICMP error the kernel matched to the connection, or nothing back.
    /// The operating system uses the same codes for both (`EHOSTUNREACH` for a missing
    /// route here and for a firewall's rejection on the far side), so only where the
    /// error surfaces tells them apart.
    ///
    /// Like [`connect_shaped`](Self::connect_shaped), the socket carries only what the
    /// caller chose, so an unshaped connect sends the SYN any other program would.
    ///
    /// A connect that met itself is refused here on platforms that refuse it outright,
    /// and comes back from [`Connecting::finish`] on those that complete it;
    /// [`met_itself`] names it either way.
    ///
    /// The slot stays the caller's, and no error here spends it.
    pub(crate) fn start_connect(
        &self,
        slot: &Slot,
        addr: SocketAddr,
        shaping: Shaping,
    ) -> io::Result<Connecting> {
        debug_assert!(slot.is_for(addr.ip()), "a slot claimed for another host");
        #[cfg(test)]
        {
            dialled::note(addr);
            if let Some(refused) = dialled::refusal(addr) {
                return Err(refused);
            }
        }
        let socket = self.socket(addr.ip(), Protocol::Tcp, shaping)?;
        socket.set_nonblocking(true)?;
        match socket.connect(&addr.into()) {
            Ok(()) => {}
            #[cfg(unix)]
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            // macOS refuses a connect whose source is the target's own port, with
            // `EINVAL` over IPv4 and `EADDRINUSE` over IPv6 from a wildcard bind, and
            // leaves that port bound.
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
            // The bind above let the pinned port be shared, so a refusal here means
            // the whole four-tuple is taken: macOS says in use, Linux not available.
            // Almost always it is this same connection made a moment ago, still
            // closing.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::AddrNotAvailable
                ) && shaping.source_port.is_some() =>
            {
                return Err(SourcePortHeld::error(shaping, e, Holder::Closing));
            }
            // Linux refuses a connect by the type of the matched route, each with its
            // own code: no route or an `unreachable` one as network or host
            // unreachable, a `prohibit` route as permission denied, a `blackhole`
            // route as an invalid argument. The last two are routes someone wrote to
            // say nothing goes there, so they are passed on as an unreachable host, in
            // the kernel's own words. A security module denying the connect means the
            // same thing from this process's view.
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

    /// Connects to `addr` on the calling thread for the probe `slot` was given,
    /// giving the connection `timeout` and a full descriptor table `patience`.
    ///
    /// For a caller holding a blocking socket, such as a detection on the blocking
    /// pool. Builds the same socket as [`connect_timed`](Self::connect_timed), connects
    /// it as [`std::net::TcpStream::connect_timeout`] does, waits out a full descriptor
    /// table the same way beforehand (outside `timeout`) and settles the slot the same
    /// way after. The patience is the caller's, because a detection's exchange has its
    /// own clock that a wait for a socket cannot outlast.
    pub(crate) fn connect_within(
        &self,
        slot: Slot,
        addr: SocketAddr,
        timeout: Duration,
        patience: Duration,
    ) -> io::Result<std::net::TcpStream> {
        debug_assert!(slot.is_for(addr.ip()), "a slot claimed for another host");
        let connected = descriptors::patiently_blocking(patience, || {
            #[cfg(test)]
            dialled::note(addr);
            if self.tcp_is_plain(Shaping::default()) {
                return std::net::TcpStream::connect_timeout(&addr, timeout);
            }
            let socket = self.socket(addr.ip(), Protocol::Tcp, Shaping::default())?;
            socket.connect_timeout(&addr.into(), timeout)?;
            Ok(socket.into())
        });
        slot.settle(&connected);
        connected
    }

    /// A UDP socket bound for `peer`, ready to be connected to it, for the exchange
    /// `slot` was given, with a full descriptor table waited out for `patience` (as
    /// [`connect_timed`](Self::connect_timed) waits for
    /// [`PATIENCE`](descriptors::PATIENCE)).
    ///
    /// The slot stays the caller's: the probe leaves with the first datagram the caller
    /// sends, and the caller settles it after a refused socket or send.
    pub(crate) async fn udp(
        &self,
        slot: &Slot,
        peer: IpAddr,
        patience: Duration,
    ) -> io::Result<UdpSocket> {
        descriptors::patiently(patience, || {
            std::future::ready(self.udp_shaped(slot, peer, Shaping::default()))
        })
        .await
    }

    /// A UDP socket bound for `peer` and honouring `shaping`, ready to be connected to
    /// it, for the exchange `slot` was given.
    ///
    /// One attempt, for the connect scanner's own wait; see
    /// [`connect_shaped`](Self::connect_shaped).
    ///
    /// Unpinned and unshaped, this is the plain ephemeral bind. Otherwise the socket
    /// carries its pin, the chosen hop limit, and the chosen or an ephemeral source
    /// port. Bound on the calling task, since a bind never waits, and registered with
    /// the current runtime.
    pub(crate) fn udp_shaped(
        &self,
        slot: &Slot,
        peer: IpAddr,
        shaping: Shaping,
    ) -> io::Result<UdpSocket> {
        debug_assert!(slot.is_for(peer), "a slot claimed for another host");
        let socket = match self.pin.is_none() && !shaping.is_active() {
            true => std::net::UdpSocket::bind(wildcard(peer, 0))?,
            false => self.socket(peer, Protocol::Udp, shaping)?.into(),
        };
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    }

    /// [`udp`](Self::udp) for a caller holding a blocking socket, waiting out a full
    /// descriptor table for `patience`; see [`connect_within`](Self::connect_within).
    pub(crate) fn udp_blocking(
        &self,
        slot: &Slot,
        peer: IpAddr,
        patience: Duration,
    ) -> io::Result<std::net::UdpSocket> {
        debug_assert!(slot.is_for(peer), "a slot claimed for another host");
        descriptors::patiently_blocking(patience, || {
            if self.pin.is_none() {
                return std::net::UdpSocket::bind(wildcard(peer, 0));
            }
            Ok(self.socket(peer, Protocol::Udp, Shaping::default())?.into())
        })
    }

    /// Whether a TCP socket carrying `shaping` can be opened by
    /// [`TcpStream::connect`], because nothing must be set on it first.
    ///
    /// Never on Windows, where every TCP socket carries the SYN retransmission limit.
    fn tcp_is_plain(&self, shaping: Shaping) -> bool {
        self.pin.is_none() && !shaping.is_active() && cfg!(not(windows))
    }

    /// Opens a socket towards `target` and sets everything that must be in force before
    /// its first packet: the pin, `shaping`, and on Windows, for TCP, the SYN
    /// retransmission limit.
    ///
    /// Bound where something about its source was chosen, since TCP binds only to pin
    /// an address or a port and UDP must bind before it can send. Left blocking; an
    /// async caller switches it before handing it to the runtime.
    ///
    /// The hop limit uses the family's option (`IP_TTL` or `IPV6_UNICAST_HOPS`).
    /// Address reuse lets the many concurrent probes of a scan each bind one pinned
    /// source port: each still has a distinct four-tuple through its destination, so
    /// the kernel keeps their replies apart.
    fn socket(&self, target: IpAddr, protocol: Protocol, shaping: Shaping) -> io::Result<Socket> {
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
            // Unix only, as both supported platforms are: without it a second socket
            // on the pinned port is refused.
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
            // Refused although this socket shares the port, so another holds it
            // without sharing.
            Err(e) if e.kind() == io::ErrorKind::AddrInUse && shaping.source_port.is_some() => {
                Err(SourcePortHeld::error(shaping, e, Holder::Socket))
            }
            Err(e) => Err(e),
            Ok(()) => Ok(socket),
        }
    }
}

/// A connection or datagram was refused its pinned source port because something on
/// this machine already held it.
///
/// A separate error because the remedy is the caller's. A port pinned for every probe
/// is taken by each in turn, and a connection keeps its four-tuple in `TIME_WAIT`
/// after it ends (a minute on Linux, half that on macOS), so asking the same port again
/// from the same pinned port within that wait is refused. Nothing is sent and the port
/// is left unasked; a later run asks it. Waiting here would stall the scan on every
/// such port, and ending each connection with a reset would change what every pinned
/// probe puts on the wire.
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
    /// A connection from the port to the same destination, usually this scan's own,
    /// still in its closing wait.
    Closing,
    /// Another socket on this machine, bound to the port without sharing it.
    Socket,
}

impl SourcePortHeld {
    /// The refusal `cause` of `shaping`'s pinned port, as an error that says so.
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
    /// The socket, registered with the runtime while its handshake is under way, so
    /// its readiness signals the end of the handshake.
    stream: TcpStream,
}

impl Connecting {
    /// Waits for the handshake to finish, and returns the connection or what ended it.
    ///
    /// Unbounded, as a connect is; the caller holds the clock. Every error here came
    /// after the SYN was handed to the kernel, so it happened on the way to the target
    /// or at it: a reset, an ICMP error the kernel matched to the connection, the stack
    /// giving up. A connection that met itself comes back as an error [`met_itself`]
    /// names, and is closed when dropped.
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

/// A connect that reached its own socket.
///
/// A connect to one of this machine's own addresses can be given the target port as
/// its ephemeral source when nothing holds that port, and its SYN then arrives at the
/// socket that sent it. Linux completes the handshake as a simultaneous open, as macOS
/// does over IPv6 from a socket bound to the address; macOS otherwise refuses the
/// connect. A full-range scan of loopback meets it once or twice a run.
///
/// Neither outcome answers anything about the port. The completed one is a
/// conversation with nobody: read as a handshake, it would file a port with no listener
/// as open and identify its service from the scanner's own questions echoed back. The
/// refused one was never sent. It does prove nothing held the port when the kernel
/// chose it, so a fresh socket with another source gets the verdict.
#[derive(Debug)]
struct MetItself;

impl std::fmt::Display for MetItself {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the connect was given its target's port as its source and reached itself")
    }
}

impl std::error::Error for MetItself {}

/// Whether `error` is a connect that reached its own socket; see
/// [`Egress::start_connect`].
pub(crate) fn met_itself(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<MetItself>())
}

impl Pin {
    /// Binds `socket`, about to reach `target`, to this pin's source and `port`, and to
    /// the interface holding the source.
    ///
    /// A link-local source is bound with its interface as its scope, the only way a
    /// bare `fe80::` address names one address.
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

/// The unspecified address of `family`, carrying `port` (`0` lets the OS pick one).
///
/// A socket bound to `0.0.0.0` cannot connect to an IPv6 destination, so binding the
/// target's family is what makes a v6 target reachable.
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
    use crate::testing::loopback::{accept_from_this_process, from_this_process};

    /// Where [`connect_once_and_close`] connects, in the process it runs in.
    #[cfg(unix)]
    const CONNECT_TO: &str = "ZOND_TEST_CONNECT_TO";

    /// The count a test reads to know a pass sent a port nothing moves for every
    /// connection this process begins to the port, however soon it closes, and for none
    /// another process opens.
    ///
    /// Another scanner on the machine can sweep loopback at any moment, and its
    /// connections close as soon as they complete. A count kept at the port cannot tell
    /// whose they were and would charge them to the test's pass.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_dial_count_moves_for_this_processs_connections_alone() {
        let silent = crate::testing::loopback::SilentPort::open();
        let addr = silent.addr();

        let path = format!(
            "{}::connect_once_and_close",
            module_path!().split_once("::").expect("a crate path").1
        );
        let elsewhere = std::process::Command::new(std::env::current_exe().unwrap())
            .args([path.as_str(), "--exact", "--ignored", "--test-threads=1"])
            .env(CONNECT_TO, addr.to_string())
            .output()
            .expect("another process runs");
        let said = String::from_utf8_lossy(&elsewhere.stdout);
        assert!(
            elsewhere.status.success() && said.contains("1 passed"),
            "the other process connected to nothing:\n{said}"
        );
        assert_eq!(
            dialled::to(addr),
            0,
            "another process's connection was counted"
        );

        let connected = Egress::KERNEL
            .connect_timed(Slot::unpaced(), addr, Duration::from_secs(30))
            .await
            .expect("connects to loopback");
        drop(connected);
        assert_eq!(
            dialled::to(addr),
            1,
            "a connection this process closed at once was not counted"
        );
    }

    /// A port opened where an earlier connection went is charged none of it.
    ///
    /// Tests share one process, and a port an earlier test connected to,
    /// listening or closed, is free for the next to bind. Its count would then
    /// read as the later test's pass having asked the port.
    #[tokio::test]
    async fn a_port_opened_afresh_is_charged_no_earlier_connection() {
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("binds loopback")
            .local_addr()
            .expect("a local address");
        // Refused, since the listener is gone, and counted all the same.
        let _ = Egress::KERNEL
            .connect_timed(Slot::unpaced(), addr, Duration::from_secs(30))
            .await;
        assert_eq!(
            dialled::to(addr),
            1,
            "the earlier connection was not counted"
        );

        let reopened = crate::testing::loopback::SilentPort::open_at(addr);

        assert_eq!(
            dialled::to(reopened.addr()),
            0,
            "a connection begun before the port opened was charged to it"
        );
    }

    /// Not a check of its own: the other process
    /// [`the_dial_count_moves_for_this_processs_connections_alone`] needs, connecting
    /// once where [`CONNECT_TO`] says and closing at once.
    #[cfg(unix)]
    #[test]
    #[ignore = "the connector another test runs in a process of its own"]
    fn connect_once_and_close() {
        if let Ok(to) = std::env::var(CONNECT_TO) {
            let to: SocketAddr = to.parse().expect("an address");
            drop(std::net::TcpStream::connect(to).expect("connects to loopback"));
        }
    }

    #[test]
    fn a_socket_binds_the_family_of_its_target() {
        assert!(wildcard(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).is_ipv4());
        assert!(wildcard(IpAddr::V6(Ipv6Addr::LOCALHOST), 0).is_ipv6());
    }

    /// A connection that chose nothing is the kernel's own, so a scan with no evasion
    /// sends what any other program would. Windows is the exception.
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
            gate: None,
        };
        assert!(
            !pinned.tcp_is_plain(Shaping::default()),
            "a pinned connection was left to the kernel, which would source it"
        );
    }

    /// A shaped connect leaves from the chosen source port and carries the chosen hop
    /// limit, checked on the wire against a peer that reads both back.
    ///
    /// Ignoring the source port would show an ephemeral one here; skipping the hop
    /// limit would show the OS default instead of `9`.
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

        let accept = tokio::spawn(async move {
            let accepted = accept_from_this_process(&listener).await?;
            let peer = accepted.peer_addr()?;
            std::io::Result::Ok((accepted, peer))
        });
        let stream = Egress::KERNEL
            .connect_shaped(&Slot::unpaced(), addr, shaping)
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

    /// A shaped UDP socket leaves from the chosen source port, read back off the
    /// datagram the far side receives.
    ///
    /// The UDP socket is built by its own path, so it gets its own test.
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
            .udp_shaped(&Slot::unpaced(), IpAddr::V4(Ipv4Addr::LOCALHOST), shaping)
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

    /// The blocking connect a detection makes reaches a listener in either family,
    /// through the same socket the async one would build.
    #[test]
    fn a_blocking_connect_reaches_a_listener_in_either_family() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let listener = std::net::TcpListener::bind((ip, 0)).expect("a loopback listener");
            let addr = listener.local_addr().expect("its address");
            let stream = Egress::KERNEL
                .connect_within(
                    Slot::unpaced(),
                    addr,
                    Duration::from_secs(1),
                    descriptors::PATIENCE,
                )
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
            gate: None,
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

    /// A forced source carries a connection only to a target the routing table could
    /// send the wrong way, and leaves every other to it, as the plan does for probes.
    ///
    /// Pinning a LAN neighbour to the LAN is harmless; pinning a tunnel peer to the LAN
    /// takes it off the only link that reaches it, and pinning loopback to a LAN
    /// interface reaches nothing.
    #[test]
    fn a_forced_source_carries_only_what_no_link_here_reaches_directly() {
        let sources =
            ForcedSources::with_links(&[v4(192, 0, 2, 10), v6("2001:db8:1::10")], &laptop());
        let lan_v4 = pinned(v4(192, 0, 2, 10), 2);
        let lan_v6 = pinned(v6("2001:db8:1::10"), 2);

        for (target, expected, why) in [
            (v4(198, 18, 0, 1), lan_v4.clone(), "a routed target"),
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

    /// A source speaks for its own family, and a family with no forced source leaves
    /// its connections to the routing table, as the plan does its probes.
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

    /// The rule the probes were planned by, applied to this machine's own interfaces: a
    /// connection is pinned exactly where the plan paired its target with the forced
    /// source.
    ///
    /// The rule is written twice, in the classifier and here, and this keeps the two
    /// in step. Skipped on a host with no IPv4 address outside loopback.
    #[test]
    fn a_connection_is_pinned_exactly_where_the_plan_pinned_its_probe() {
        use crate::model::ip::set::IpSet;
        use crate::system::interface::{interfaces, map_ips_to_interfaces_forced};

        let Some(held) = interfaces()
            .expect("this machine's interfaces")
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

    /// A source no interface here holds is kept as asked, and the connection fails to
    /// bind instead of going out from an address the routing table picked.
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
                .connect_timed(
                    Slot::unpaced(),
                    addr,
                    crate::config::limits::CONNECT_PROBE_TIMEOUT
                )
                .await
                .is_err(),
            "a connection forced to an address this host does not hold went out anyway"
        );
    }

    /// The loopback interface, and an address on it to leave from that the routing
    /// table would not pick for a connection to `127.0.0.1`, where the host has one.
    ///
    /// Linux answers for the whole of `127.0.0.0/8`. macOS holds `127.0.0.1` alone
    /// unless an alias was added, and there the source is the kernel's choice and only
    /// the interface can be told apart.
    fn loopback_pin() -> (Egress, u32) {
        let lo = crate::system::interface::interfaces()
            .expect("this machine's interfaces")
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

    /// A pinned connection leaves from its source and is bound to its interface, read
    /// back where each is visible: the source off the peer's accept, the interface off
    /// the socket.
    ///
    /// The unpinned connection beside it is the control. Where the host has a second
    /// loopback address the two sources differ; everywhere, only the pinned socket is
    /// bound to a device.
    #[tokio::test]
    async fn a_pinned_connection_leaves_from_its_source_and_by_its_interface() {
        let (egress, index) = loopback_pin();
        let source = egress.pin.expect("a pin").source;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener");
        let addr = listener.local_addr().expect("its address");

        let accept = tokio::spawn(async move {
            let from = async || {
                let accepted = accept_from_this_process(&listener).await?;
                accepted.peer_addr()
            };
            let first = from().await.expect("the pinned connection");
            let second = from().await.expect("the plain connection");
            (first, second)
        });
        let within = crate::config::limits::CONNECT_PROBE_TIMEOUT;
        let pinned = egress
            .connect_timed(Slot::unpaced(), addr, within)
            .await
            .expect("the pinned connect");
        let plain = Egress::KERNEL
            .connect_timed(Slot::unpaced(), addr, within)
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

    /// The datagram and the blocking connection are built by their own paths, so each
    /// gets its own test: skipping the pin would show the kernel's source to the peer.
    #[tokio::test]
    async fn a_pinned_datagram_and_blocking_connection_leave_from_the_source() {
        let (egress, _) = loopback_pin();
        let source = egress.pin.expect("a pin").source;

        let server = UdpSocket::bind("127.0.0.1:0").await.expect("a UDP server");
        let server_addr = server.local_addr().expect("its address");
        let socket = egress
            .udp(&Slot::unpaced(), server_addr.ip(), descriptors::PATIENCE)
            .await
            .expect("a pinned socket");
        socket
            .connect(server_addr)
            .await
            .expect("addressing the peer");
        socket.send(b"probe").await.expect("sending");
        let mut buf = [0u8; 8];
        let (_, from) = crate::testing::loopback::recv_from_this_process(&server, &mut buf)
            .await
            .expect("the datagram");
        assert_eq!(from.ip(), source, "the datagram's source");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let addr = listener.local_addr().expect("its address");
        // Return the accepted stream instead of dropping it with the thread: closed at
        // once, it can reach the connecting side as a hang-up before the connect has
        // seen its handshake finish, which macOS reports as a failed connect.
        let handle = std::thread::spawn(move || {
            let accepted = from_this_process(&listener).next().expect("an accept");
            let peer = accepted.peer_addr()?;
            std::io::Result::Ok((accepted, peer))
        });
        let _stream = egress
            .connect_within(
                Slot::unpaced(),
                addr,
                Duration::from_secs(1),
                descriptors::PATIENCE,
            )
            .expect("the blocking connect");
        let (_accepted, from) = handle.join().expect("the accept joins").expect("an accept");
        assert_eq!(from.ip(), source, "the blocking connection's source");
    }
}
