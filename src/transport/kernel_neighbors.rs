// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Where the kernel's own address resolution stands
//!
//! A raw socket hands a probe to the kernel, and for an on-link destination the
//! kernel has to learn the neighbour's hardware address before anything leaves.
//! Linux says nothing to the socket about how that goes. A write to a
//! neighbour it is still asking for is accepted and queued on the neighbour;
//! when the asking fails, three unanswered requests a second apart, the queue
//! is thrown away and the only word of it is an ICMP host unreachable the
//! kernel addresses to itself. The next write starts the asking over, so a
//! neighbour that never answers accepts every probe a scan sends it and
//! delivers none.
//!
//! Two things follow for a scan, and both are wrong without this module. The
//! probes to a dead neighbour read as silence, which is what a firewall
//! produces, where the truth is that none of them left. And every queued write
//! is charged to the socket that made it until the queue is thrown away, so a
//! scan that keeps writing to a few dead neighbours fills its own send buffer
//! and the kernel refuses the socket's writes to every host with `ENOBUFS`,
//! the live ones included.
//!
//! The kernel does keep the state it will not report to the socket: the
//! neighbour table holds each entry's resolution state, and rtnetlink reads it.
//! [`KernelNeighbors`] is that read, taken as a whole-table snapshot and
//! remembered, since the question is asked of many addresses at once and a
//! table is small. A host behind a gateway has no entry of its own, and its
//! writes queue on the gateway's, so it is read through the gateway the
//! routing table names for it, asked of rtnetlink the same way.
//!
//! Linux only. macOS refuses a write to a neighbour it gave up on with
//! `EHOSTDOWN`, which the send path already reads, and the frame path runs its
//! own resolution and remembers it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// Where the resolution of one neighbour's hardware address stands, as the
/// kernel's neighbour table says or as a frame sender's own resolution does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum NeighborState {
    /// The address was asked for and nobody answered (the kernel's
    /// `FAILED`). A write to it on Linux starts the asking over and is queued
    /// behind it.
    Failed,
    /// The address is being asked for and nobody has answered yet (the
    /// kernel's `INCOMPLETE`). A write to it on Linux is queued, not sent.
    Resolving,
    /// A hardware address is held for it, confirmed lately or not. A write to
    /// it leaves.
    Resolved,
}

impl NeighborState {
    /// Whether a write to a neighbour in this state is held by the kernel
    /// rather than sent.
    pub(crate) fn is_unresolved(self) -> bool {
        self != Self::Resolved
    }
}

/// The kernel's neighbour table as of one read.
pub(crate) type NeighborTable = HashMap<IpAddr, NeighborState>;

/// Reads the whole table. The seam a test replaces.
type Reader = Box<dyn Fn() -> std::io::Result<NeighborTable> + Send + Sync>;

/// Asks the routing table for the neighbour a write to an address is framed
/// to: the route's gateway, the address itself on a route with none, or
/// `None` where no ordinary route leads anywhere a neighbour could stand. The
/// seam a test replaces.
type Router = Box<dyn Fn(IpAddr) -> std::io::Result<Option<IpAddr>> + Send + Sync>;

/// The kernel's neighbour table, read on demand and remembered until a caller
/// needs a later one, and the next hop the kernel sends each address through.
pub(crate) struct KernelNeighbors {
    read: Reader,
    snapshot: Mutex<Option<(Instant, NeighborTable)>>,
    route: Router,
    /// Each address's next hop as the routing table gave it, asked once per
    /// address. A scan's routes do not move under it, and one asked about
    /// thousands of hosts behind one gateway would otherwise ask the kernel
    /// thousands of times for the same answer.
    next_hops: Mutex<HashMap<IpAddr, Option<IpAddr>>>,
}

impl KernelNeighbors {
    /// The running kernel's table, where this platform has one to read.
    pub(crate) fn from_system() -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            Some(Self::with_reader(Box::new(linux::dump)).routing(Box::new(linux::next_hop)))
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// A table served by `read`: the kernel's, or a test's. No address has a
    /// next hop until [`routing`](Self::routing) says how to find one.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn with_reader(read: Reader) -> Self {
        Self {
            read,
            snapshot: Mutex::new(None),
            route: Box::new(|_| Ok(None)),
            next_hops: Mutex::new(HashMap::new()),
        }
    }

    /// This table, finding each address's next hop with `route`.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn routing(mut self, route: Router) -> Self {
        self.route = route;
        self
    }

    /// The neighbour a write to `address` waits on the resolution of: the
    /// gateway the kernel routes it through, or `address` itself where the
    /// route has none.
    ///
    /// What makes a host behind a gateway readable at all. It has no entry of
    /// its own in the neighbour table, and its writes queue on the gateway's
    /// as an on-link host's queue on its own: a gateway that never answers
    /// takes every probe routed through it, charged to the socket, and throws
    /// them away three seconds later.
    ///
    /// `None` where the routing table names no ordinary route for `address`,
    /// one to this host's own address among them, or could not be read:
    /// either way no neighbour stands between a write and the wire.
    pub(crate) fn next_hop(&self, address: IpAddr) -> Option<IpAddr> {
        let mut next_hops = self.next_hops.lock().ok()?;
        *next_hops
            .entry(address)
            .or_insert_with(|| (self.route)(address).ok().flatten())
    }

    /// What the table says about `address`, as read no earlier than `since`.
    ///
    /// The remembered snapshot answers when it was taken at or after `since`,
    /// and the table is read afresh otherwise. So a caller asking about a
    /// neighbour its own write created passes the instant of that write, and
    /// is never answered from a table read before the entry existed.
    ///
    /// `None` when the table holds no entry for `address`, which is every
    /// destination reached through a gateway, and also when it could not be
    /// read: either way there is nothing to go on. An address held on more than
    /// one interface, as a link-local one can be, reads as its most resolved
    /// entry, so a doubt about one link never makes a reachable address read
    /// dead.
    pub(crate) fn state(&self, address: IpAddr, since: Instant) -> Option<NeighborState> {
        let mut snapshot = self.snapshot.lock().ok()?;
        let fresh = snapshot.as_ref().is_some_and(|(taken, _)| *taken >= since);
        if !fresh {
            let taken = Instant::now();
            let table = (self.read)().ok()?;
            *snapshot = Some((taken, table));
        }
        snapshot.as_ref()?.1.get(&address).copied()
    }
}

// ---------------------------------------------------------------------------
// The rtnetlink messages, read as bytes
// ---------------------------------------------------------------------------
//
// Parsed by hand rather than through the kernel's structs, so the reading is a
// pure function a test on any platform can feed. The numbers are the kernel's
// ABI and do not move.

#[cfg(any(target_os = "linux", test))]
mod wire {
    use super::{NeighborState, NeighborTable};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// `RTM_NEWNEIGH`: what a neighbour dump answers with, one per entry.
    pub(super) const RTM_NEWNEIGH: u16 = 28;
    /// `NLMSG_ERROR`.
    pub(super) const NLMSG_ERROR: u16 = 2;
    /// `NLMSG_DONE`: the end of a dump.
    pub(super) const NLMSG_DONE: u16 = 3;
    /// `NDA_DST`: the attribute carrying the neighbour's address.
    pub(super) const NDA_DST: u16 = 1;
    /// `NUD_INCOMPLETE`.
    pub(super) const NUD_INCOMPLETE: u16 = 0x01;
    /// `NUD_FAILED`.
    pub(super) const NUD_FAILED: u16 = 0x20;
    /// `NUD_NONE`: an entry with no state yet, which says nothing either way.
    pub(super) const NUD_NONE: u16 = 0x00;
    /// The length of `struct nlmsghdr`.
    pub(super) const NLMSG_HEADER: usize = 16;
    /// The length of `struct ndmsg`.
    pub(super) const NDMSG: usize = 12;

    /// `RTM_NEWROUTE`: what a route lookup answers with.
    pub(super) const RTM_NEWROUTE: u16 = 24;
    /// `RTA_DST`: the attribute carrying the address a lookup asks about.
    pub(super) const RTA_DST: u16 = 1;
    /// `RTA_GATEWAY`: the attribute carrying a route's gateway.
    pub(super) const RTA_GATEWAY: u16 = 5;
    /// `RTN_UNICAST`: an ordinary route, the one kind a write leaves by
    /// through a neighbour.
    pub(super) const RTN_UNICAST: u8 = 1;
    /// The length of `struct rtmsg`.
    pub(super) const RTMSG: usize = 12;

    /// Rounds `len` up to the four-byte boundary netlink pads every message and
    /// attribute to.
    pub(super) fn align(len: usize) -> usize {
        (len + 3) & !3
    }

    /// What one batch of a dump's messages held.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub(super) struct Batch {
        /// The dump's end was in this batch.
        pub(super) done: bool,
        /// The kernel reported an error, as a negative errno.
        pub(super) error: Option<i32>,
    }

    /// Reads one buffer of netlink messages into `table`.
    ///
    /// Every length here is the kernel's and is bounds-checked anyway: a message
    /// claiming more than remains ends the walk, and one claiming less than its
    /// own header does too, so no buffer can walk it off the end or into a loop.
    pub(super) fn parse(buffer: &[u8], table: &mut NeighborTable) -> Batch {
        let mut batch = Batch::default();
        let mut offset = 0;
        while offset + NLMSG_HEADER <= buffer.len() {
            let header = &buffer[offset..];
            let len = u32::from_ne_bytes(header[0..4].try_into().expect("four bytes")) as usize;
            let kind = u16::from_ne_bytes(header[4..6].try_into().expect("two bytes"));
            if len < NLMSG_HEADER || offset + len > buffer.len() {
                break;
            }
            let body = &buffer[offset + NLMSG_HEADER..offset + len];
            match kind {
                NLMSG_DONE => {
                    batch.done = true;
                    break;
                }
                NLMSG_ERROR => {
                    let errno = body
                        .get(0..4)
                        .map(|bytes| i32::from_ne_bytes(bytes.try_into().expect("four bytes")));
                    // An error of zero is an acknowledgement, not a failure.
                    if let Some(errno) = errno.filter(|errno| *errno != 0) {
                        batch.error = Some(errno);
                        batch.done = true;
                        break;
                    }
                }
                RTM_NEWNEIGH => {
                    if let Some((address, state)) = entry(body) {
                        let known = table.entry(address).or_insert(state);
                        *known = (*known).max(state);
                    }
                }
                _ => {}
            }
            offset += align(len);
        }
        batch
    }

    /// What a route lookup answered.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Route {
        /// An ordinary route through this gateway.
        Via(IpAddr),
        /// An ordinary route with no gateway: the address is on a link of this
        /// host's.
        Direct,
        /// Anything else: this host's own address, a route that discards, a
        /// refusal as a negative errno, or nothing readable.
        Elsewhere(Option<i32>),
    }

    /// Reads the answer to one `RTM_GETROUTE`.
    ///
    /// Bounds-checked as [`parse`] is, so no buffer can walk it off the end.
    pub(super) fn parse_route(buffer: &[u8]) -> Route {
        let mut offset = 0;
        while offset + NLMSG_HEADER <= buffer.len() {
            let header = &buffer[offset..];
            let len = u32::from_ne_bytes(header[0..4].try_into().expect("four bytes")) as usize;
            let kind = u16::from_ne_bytes(header[4..6].try_into().expect("two bytes"));
            if len < NLMSG_HEADER || offset + len > buffer.len() {
                break;
            }
            let body = &buffer[offset + NLMSG_HEADER..offset + len];
            match kind {
                NLMSG_ERROR => {
                    let errno = body
                        .get(0..4)
                        .map(|bytes| i32::from_ne_bytes(bytes.try_into().expect("four bytes")));
                    if errno.is_some_and(|errno| errno != 0) {
                        return Route::Elsewhere(errno);
                    }
                }
                RTM_NEWROUTE => return route(body),
                _ => {}
            }
            offset += align(len);
        }
        Route::Elsewhere(None)
    }

    /// One route's gateway, or that it has none.
    fn route(body: &[u8]) -> Route {
        if body.len() < RTMSG || body[7] != RTN_UNICAST {
            return Route::Elsewhere(None);
        }
        let mut attributes = &body[RTMSG..];
        while attributes.len() >= 4 {
            let len = usize::from(u16::from_ne_bytes(
                attributes[0..2].try_into().expect("two bytes"),
            ));
            let kind = u16::from_ne_bytes(attributes[2..4].try_into().expect("two bytes"));
            if len < 4 || len > attributes.len() {
                return Route::Elsewhere(None);
            }
            if kind == RTA_GATEWAY {
                return match address(&attributes[4..len]) {
                    Some(gateway) => Route::Via(gateway),
                    None => Route::Elsewhere(None),
                };
            }
            attributes = attributes.get(align(len)..).unwrap_or(&[]);
        }
        Route::Direct
    }

    /// An address attribute's value, four bytes or sixteen.
    fn address(value: &[u8]) -> Option<IpAddr> {
        match value.len() {
            4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(value).ok()?))),
            16 => Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(value).ok()?,
            ))),
            _ => None,
        }
    }

    /// One neighbour entry's address and state, when it names both.
    fn entry(body: &[u8]) -> Option<(IpAddr, NeighborState)> {
        if body.len() < NDMSG {
            return None;
        }
        let state = match u16::from_ne_bytes(body[8..10].try_into().expect("two bytes")) {
            NUD_NONE => return None,
            NUD_INCOMPLETE => NeighborState::Resolving,
            NUD_FAILED => NeighborState::Failed,
            _ => NeighborState::Resolved,
        };

        let mut attributes = &body[NDMSG..];
        while attributes.len() >= 4 {
            let len = usize::from(u16::from_ne_bytes(
                attributes[0..2].try_into().expect("two bytes"),
            ));
            let kind = u16::from_ne_bytes(attributes[2..4].try_into().expect("two bytes"));
            if len < 4 || len > attributes.len() {
                return None;
            }
            if kind == NDA_DST {
                return Some((address(&attributes[4..len])?, state));
            }
            attributes = attributes.get(align(len)..).unwrap_or(&[]);
        }
        None
    }
}
#[cfg(any(target_os = "linux", test))]
use wire::*;

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use std::net::IpAddr;

    use super::{
        NDMSG, NLMSG_HEADER, NeighborTable, RTA_DST, RTMSG, Route, align, parse, parse_route,
    };

    /// How much of a dump one read takes. The kernel sizes each batch to the
    /// reader's buffer, and a page's worth of entries per read is plenty.
    const READ_BUFFER: usize = 32 * 1024;

    /// The whole neighbour table, both families, over a netlink socket opened
    /// for the one dump.
    pub(super) fn dump() -> std::io::Result<NeighborTable> {
        // One `nlmsghdr` asking for a dump of `RTM_GETNEIGH`, and an `ndmsg`
        // of all zeroes: every family, every interface.
        let len = NLMSG_HEADER + NDMSG;
        let mut request = vec![0u8; len];
        request[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
        request[4..6].copy_from_slice(&libc::RTM_GETNEIGH.to_ne_bytes());
        let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
        request[6..8].copy_from_slice(&flags.to_ne_bytes());
        request[8..12].copy_from_slice(&1u32.to_ne_bytes());
        let socket = ask(&request)?;

        let mut table = NeighborTable::new();
        let mut buffer = vec![0u8; READ_BUFFER];
        loop {
            // SAFETY: `buffer` is `READ_BUFFER` bytes and that is the length
            // passed, so the kernel writes no more than was allocated.
            let read = unsafe {
                libc::recv(
                    socket.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if read < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if read == 0 {
                return Ok(table);
            }
            let batch = parse(&buffer[..read as usize], &mut table);
            if let Some(errno) = batch.error {
                return Err(std::io::Error::from_raw_os_error(-errno));
            }
            if batch.done {
                return Ok(table);
            }
        }
    }

    /// The neighbour a write to `address` is framed to, as a route lookup
    /// names it: see [`KernelNeighbors::next_hop`](super::KernelNeighbors::next_hop).
    pub(super) fn next_hop(address: IpAddr) -> std::io::Result<Option<IpAddr>> {
        // One `nlmsghdr` asking for `RTM_GETROUTE`, an `rtmsg` naming the
        // family and a full-length destination, and the destination itself as
        // `RTA_DST`: the lookup `ip route get` makes, rules and all.
        let (family, octets) = match address {
            IpAddr::V4(v4) => (libc::AF_INET, v4.octets().to_vec()),
            IpAddr::V6(v6) => (libc::AF_INET6, v6.octets().to_vec()),
        };
        let attribute = 4 + octets.len();
        let len = NLMSG_HEADER + RTMSG + align(attribute);
        let mut request = vec![0u8; len];
        request[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
        request[4..6].copy_from_slice(&libc::RTM_GETROUTE.to_ne_bytes());
        request[6..8].copy_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
        request[8..12].copy_from_slice(&1u32.to_ne_bytes());
        request[NLMSG_HEADER] = family as u8;
        request[NLMSG_HEADER + 1] = (octets.len() * 8) as u8;
        let at = NLMSG_HEADER + RTMSG;
        request[at..at + 2].copy_from_slice(&(attribute as u16).to_ne_bytes());
        request[at + 2..at + 4].copy_from_slice(&RTA_DST.to_ne_bytes());
        request[at + 4..at + 4 + octets.len()].copy_from_slice(&octets);
        let socket = ask(&request)?;

        let mut buffer = vec![0u8; READ_BUFFER];
        let read = loop {
            // SAFETY: `buffer` is `READ_BUFFER` bytes and that is the length
            // passed, so the kernel writes no more than was allocated.
            let read = unsafe {
                libc::recv(
                    socket.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if read >= 0 {
                break read as usize;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        };
        Ok(match parse_route(&buffer[..read]) {
            Route::Via(gateway) => Some(gateway),
            Route::Direct => Some(address),
            Route::Elsewhere(_) => None,
        })
    }

    /// Opens a netlink socket to the kernel and sends it `request`, handing
    /// back the socket its answer is read from.
    fn ask(request: &[u8]) -> std::io::Result<OwnedFd> {
        // SAFETY: plain socket creation; the descriptor is owned at once so
        // every return path below closes it.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned open by `socket` and is owned by
        // nothing else.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };

        // SAFETY: a zeroed `sockaddr_nl` with its family set addresses the
        // kernel, and the lengths passed are the buffers' own.
        let sent = unsafe {
            let mut kernel: libc::sockaddr_nl = std::mem::zeroed();
            kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            libc::sendto(
                socket.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&raw const kernel).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(socket)
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
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    const ON_LINK: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

    /// One `RTM_NEWNEIGH` message naming `address` in `state`, as the kernel
    /// lays it out.
    fn neighbour(address: IpAddr, state: u16) -> Vec<u8> {
        let octets = match address {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        let attribute_len = 4 + octets.len();
        let len = NLMSG_HEADER + NDMSG + align(attribute_len);
        let mut message = vec![0u8; len];
        message[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
        message[4..6].copy_from_slice(&RTM_NEWNEIGH.to_ne_bytes());
        let body = NLMSG_HEADER;
        message[body + 8..body + 10].copy_from_slice(&state.to_ne_bytes());
        let attribute = body + NDMSG;
        message[attribute..attribute + 2].copy_from_slice(&(attribute_len as u16).to_ne_bytes());
        message[attribute + 2..attribute + 4].copy_from_slice(&NDA_DST.to_ne_bytes());
        message[attribute + 4..attribute + 4 + octets.len()].copy_from_slice(&octets);
        message
    }

    /// One `RTM_NEWROUTE` message of route type `kind`, through `gateway`
    /// where one is given, as the kernel answers a route lookup.
    fn route_reply(kind: u8, gateway: Option<IpAddr>) -> Vec<u8> {
        let mut attributes = Vec::new();
        if let Some(gateway) = gateway {
            let octets = match gateway {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            // An attribute the reader passes over on the way, as the kernel
            // puts the destination and the table first.
            attributes.extend_from_slice(&8u16.to_ne_bytes());
            attributes.extend_from_slice(&RTA_DST.to_ne_bytes());
            attributes.extend_from_slice(&[198, 51, 100, 7]);
            let len = 4 + octets.len();
            attributes.extend_from_slice(&(len as u16).to_ne_bytes());
            attributes.extend_from_slice(&RTA_GATEWAY.to_ne_bytes());
            attributes.extend_from_slice(&octets);
            attributes.resize(align(attributes.len()), 0);
        }
        let len = NLMSG_HEADER + RTMSG + attributes.len();
        let mut message = vec![0u8; NLMSG_HEADER + RTMSG];
        message[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
        message[4..6].copy_from_slice(&RTM_NEWROUTE.to_ne_bytes());
        message[NLMSG_HEADER + 7] = kind;
        message.extend(attributes);
        message
    }

    /// A route lookup's answer names the gateway a write is framed to, or says
    /// the address is on a link of this host's; any other answer names no
    /// neighbour, since nothing a write waits on stands there.
    #[test]
    fn a_route_lookup_names_the_gateway_or_the_link() {
        let v4: IpAddr = "192.0.2.254".parse().expect("an address");
        let v6: IpAddr = "fe80::1".parse().expect("an address");
        assert_eq!(
            parse_route(&route_reply(RTN_UNICAST, Some(v4))),
            Route::Via(v4)
        );
        assert_eq!(
            parse_route(&route_reply(RTN_UNICAST, Some(v6))),
            Route::Via(v6)
        );
        assert_eq!(parse_route(&route_reply(RTN_UNICAST, None)), Route::Direct);
        // RTN_LOCAL: this host's own address.
        assert_eq!(parse_route(&route_reply(2, None)), Route::Elsewhere(None));

        let mut refused = vec![0u8; NLMSG_HEADER + 4];
        refused[0..4].copy_from_slice(&((NLMSG_HEADER + 4) as u32).to_ne_bytes());
        refused[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        refused[NLMSG_HEADER..].copy_from_slice(&(-101i32).to_ne_bytes());
        assert_eq!(parse_route(&refused), Route::Elsewhere(Some(-101)));
    }

    /// Each address's next hop is asked of the routing table once, however
    /// many probes to it want it: a scan asks about thousands of hosts behind
    /// one gateway.
    #[test]
    fn a_next_hop_is_asked_for_once_per_address() {
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&asked);
        let gateway: IpAddr = "192.0.2.254".parse().expect("an address");
        let routed: IpAddr = "198.51.100.7".parse().expect("an address");
        let neighbours = KernelNeighbors::with_reader(Box::new(|| Ok(NeighborTable::new())))
            .routing(Box::new(move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(Some(gateway))
            }));

        for _ in 0..3 {
            assert_eq!(neighbours.next_hop(routed), Some(gateway));
        }
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }

    fn done() -> Vec<u8> {
        let mut message = vec![0u8; NLMSG_HEADER + 4];
        message[0..4].copy_from_slice(&((NLMSG_HEADER + 4) as u32).to_ne_bytes());
        message[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        message
    }

    /// The two states a scan acts on are told apart from each other and from
    /// every state in which a write leaves, over both families.
    #[test]
    fn a_dump_reads_each_neighbours_resolution_state() {
        let v6: IpAddr = "2001:db8::7".parse().expect("an address");
        let resolved: IpAddr = "192.0.2.8".parse().expect("an address");
        let stale: IpAddr = "192.0.2.9".parse().expect("an address");
        let mut buffer = neighbour(ON_LINK, NUD_INCOMPLETE);
        buffer.extend(neighbour(v6, NUD_FAILED));
        buffer.extend(neighbour(resolved, 0x02)); // NUD_REACHABLE
        buffer.extend(neighbour(stale, 0x04)); // NUD_STALE
        buffer.extend(done());

        let mut table = NeighborTable::new();
        let batch = parse(&buffer, &mut table);

        assert!(batch.done, "the dump's end was read");
        assert_eq!(table.get(&ON_LINK), Some(&NeighborState::Resolving));
        assert_eq!(table.get(&v6), Some(&NeighborState::Failed));
        assert_eq!(table.get(&resolved), Some(&NeighborState::Resolved));
        assert_eq!(table.get(&stale), Some(&NeighborState::Resolved));
    }

    /// An address held on two links reads as its most resolved entry: a doubt
    /// about one link is not evidence the address is dead.
    #[test]
    fn an_address_on_two_links_reads_as_its_most_resolved_entry() {
        let mut buffer = neighbour(ON_LINK, NUD_FAILED);
        buffer.extend(neighbour(ON_LINK, 0x02));
        buffer.extend(neighbour(ON_LINK, NUD_INCOMPLETE));

        let mut table = NeighborTable::new();
        parse(&buffer, &mut table);

        assert_eq!(table.get(&ON_LINK), Some(&NeighborState::Resolved));
    }

    /// The walk ends inside any buffer, whatever its lengths claim, which is
    /// the property reading the kernel's bytes leans on.
    #[test]
    fn the_walk_survives_any_buffer() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = (next() % 256) as usize;
            let buffer: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
            parse(&buffer, &mut NeighborTable::new());
        }
        for _ in 0..20_000 {
            let mut buffer = neighbour(ON_LINK, NUD_INCOMPLETE);
            let at = (next() as usize) % buffer.len();
            buffer[at] = (next() & 0xFF) as u8;
            buffer.truncate((next() as usize) % (buffer.len() + 1));
            parse(&buffer, &mut NeighborTable::new());
        }
        for _ in 0..20_000 {
            let mut buffer = route_reply(RTN_UNICAST, Some(ON_LINK));
            let at = (next() as usize) % buffer.len();
            buffer[at] = (next() & 0xFF) as u8;
            buffer.truncate((next() as usize) % (buffer.len() + 1));
            parse_route(&buffer);
        }
    }

    /// A question about a neighbour this process just wrote to is answered
    /// from a table read after the write, never from one read before its
    /// entry existed; a question that allows an older reading shares it.
    #[test]
    fn a_reading_older_than_the_question_is_read_again() {
        let reads = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&reads);
        let neighbours = KernelNeighbors::with_reader(Box::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(NeighborTable::from([(ON_LINK, NeighborState::Resolving)]))
        }));

        let before = Instant::now();
        assert_eq!(
            neighbours.state(ON_LINK, before),
            Some(NeighborState::Resolving)
        );
        assert_eq!(
            neighbours.state(ON_LINK, before),
            Some(NeighborState::Resolving)
        );
        assert_eq!(reads.load(Ordering::SeqCst), 1, "the reading was shared");

        let later = Instant::now() + Duration::from_millis(1);
        std::thread::sleep(Duration::from_millis(2));
        neighbours.state(ON_LINK, later);
        assert_eq!(
            reads.load(Ordering::SeqCst),
            2,
            "a later question read again"
        );
    }

    /// The running kernel's table reads without error where there is one.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_running_kernels_table_can_be_read() {
        linux::dump().expect("rtnetlink answers a neighbour dump");
    }

    /// The running kernel's routing table answers a lookup where there is
    /// one: this host's own loopback address, which no neighbour stands in
    /// front of.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_running_kernels_routes_can_be_asked() {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            linux::next_hop(loopback).expect("rtnetlink answers a route lookup"),
            None
        );
    }
}
