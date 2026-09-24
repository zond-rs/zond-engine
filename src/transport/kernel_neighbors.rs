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
//! table is small.
//!
//! Linux only. macOS refuses a write to a neighbour it gave up on with
//! `EHOSTDOWN`, which the send path already reads, and the frame path runs its
//! own resolution and remembers it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// What the kernel's neighbour table says about one address.
///
/// Read only where there is a table to read, so elsewhere the two unresolved
/// states are named by the scan that acts on them and built by nothing.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum NeighborState {
    /// The kernel asked for the address and gave up (`FAILED`). A write to it
    /// starts the asking over and is queued behind it.
    Failed,
    /// The kernel is asking and has heard nothing yet (`INCOMPLETE`). A write
    /// to it is queued, not sent.
    Resolving,
    /// The kernel holds a hardware address for it, confirmed lately or not. A
    /// write to it leaves.
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

/// The kernel's neighbour table, read on demand and remembered until a caller
/// needs a later one.
pub(crate) struct KernelNeighbors {
    read: Reader,
    snapshot: Mutex<Option<(Instant, NeighborTable)>>,
}

impl KernelNeighbors {
    /// The running kernel's table, where this platform has one to read.
    pub(crate) fn from_system() -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            Some(Self::with_reader(Box::new(linux::dump)))
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// A table served by `read`: the kernel's, or a test's.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn with_reader(read: Reader) -> Self {
        Self {
            read,
            snapshot: Mutex::new(None),
        }
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
                let value = &attributes[4..len];
                let address = match value.len() {
                    4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(value).ok()?)),
                    16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(value).ok()?)),
                    _ => return None,
                };
                return Some((address, state));
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

    use super::{NDMSG, NLMSG_HEADER, NeighborTable, parse};

    /// How much of a dump one read takes. The kernel sizes each batch to the
    /// reader's buffer, and a page's worth of entries per read is plenty.
    const READ_BUFFER: usize = 32 * 1024;

    /// The whole neighbour table, both families, over a netlink socket opened
    /// for the one dump.
    pub(super) fn dump() -> std::io::Result<NeighborTable> {
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

        // One `nlmsghdr` asking for a dump of `RTM_GETNEIGH`, and an `ndmsg`
        // of all zeroes: every family, every interface.
        let len = NLMSG_HEADER + NDMSG;
        let mut request = vec![0u8; len];
        request[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
        request[4..6].copy_from_slice(&libc::RTM_GETNEIGH.to_ne_bytes());
        let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
        request[6..8].copy_from_slice(&flags.to_ne_bytes());
        request[8..12].copy_from_slice(&1u32.to_ne_bytes());

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
}
