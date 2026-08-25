// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The Host's Own Neighbour Table
//!
//! The cheapest source of addresses a scanner has, and the one the engine spent
//! its whole life ignoring.
//!
//! The operating system has been performing neighbour discovery all along. Every
//! address it has spoken to on a local segment recently is sitting in its
//! neighbour cache, already resolved to a MAC, obtained for no packets and no
//! waiting. On the segment this was written against, that table names twelve
//! devices over IPv6 — against thirteen in the ARP table — and fourteen of its
//! addresses are global or unique-local ones the engine could not otherwise
//! learn at all, because the only IPv6 probe it sends is sourced from a
//! link-local address and so draws only link-local answers.
//!
//! ## Why this matters more for IPv6 than for IPv4
//!
//! An IPv4 segment can be swept: a `/24` is 256 ARP requests. An IPv6 segment
//! cannot — a `/64` holds 2^64 addresses — and the one probe that does reach a
//! whole IPv6 segment, the all-nodes echo, is optional to answer. A neighbor
//! solicitation is *not* optional, but it can only be aimed at an address
//! somebody already has.
//!
//! This is where those addresses come from. The table supplies candidates and
//! solicitation confirms them, which is the only combination that finds a host
//! that both ignores multicast echo and has never been named by a user.
//!
//! ## What it is not
//!
//! Not a census. The table holds neighbours *this host* has had reason to talk
//! to recently, so it is biased toward whatever this machine uses and says
//! nothing about the rest of the segment. Entries also go stale: an address in
//! the table is one that answered once, not one that is answering now. Both are
//! reasons to treat an entry as a lead to be confirmed rather than as a
//! discovered host — nothing here writes to the store.

use std::net::IpAddr;

use pnet::util::MacAddr;

/// One entry from the host's neighbour cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    /// The neighbour's address.
    pub ip: IpAddr,
    /// Its link-layer address, when the entry is resolved.
    ///
    /// `None` for an entry the operating system created but has not completed —
    /// an address it is currently asking about. Those are still worth having:
    /// something on this host had a reason to look the address up, which is
    /// evidence it exists even though the neighbour has not answered yet.
    pub mac: Option<MacAddr>,
    /// The interface the entry belongs to, as a scope id.
    ///
    /// Required rather than incidental for IPv6: a link-local address from this
    /// table is meaningless without it, exactly as it is everywhere else in the
    /// engine. See [`ScopedIp`](crate::model::ip::scoped::ScopedIp).
    pub interface_index: u32,
}

/// Every IPv6 neighbour this host currently knows of.
///
/// Empty rather than an error when the table cannot be read: a scan that cannot
/// consult this source is a scan with fewer leads, not a failed one, and every
/// address it would have supplied is still reachable by the probes that do not
/// depend on it.
pub fn ipv6_neighbors() -> Vec<Neighbor> {
    platform::ipv6_neighbors()
}

// ══════════════════════════════════════════════════════════════════════════════
// macOS and BSD
// ══════════════════════════════════════════════════════════════════════════════

/// On BSD-derived systems the IPv6 neighbour cache *is* the routing table: each
/// entry is a host route carrying the `RTF_LLINFO` flag, whose gateway is a
/// link-layer address rather than another IP. That is precisely what `ndp -an`
/// reads, and it is reached through `sysctl` rather than through a socket.
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
mod platform {
    use std::mem;
    use std::net::{IpAddr, Ipv6Addr};

    use libc::{
        AF_INET6, AF_LINK, CTL_NET, NET_RT_FLAGS, PF_ROUTE, RTA_DST, RTA_GATEWAY, RTF_LLINFO,
        c_int, c_void, rt_msghdr, size_t, sockaddr, sockaddr_dl, sockaddr_in6,
    };
    use pnet::util::MacAddr;

    use super::Neighbor;
    use crate::warn;

    /// Socket addresses in a routing message are padded to a four-byte boundary,
    /// and a zero-length one still occupies that much.
    const SA_ALIGN: usize = mem::size_of::<u32>();

    fn roundup(len: usize) -> usize {
        if len == 0 {
            SA_ALIGN
        } else {
            (len + (SA_ALIGN - 1)) & !(SA_ALIGN - 1)
        }
    }

    pub(super) fn ipv6_neighbors() -> Vec<Neighbor> {
        let mut mib: [c_int; 6] = [
            CTL_NET,
            PF_ROUTE,
            0,
            AF_INET6,
            NET_RT_FLAGS,
            RTF_LLINFO as c_int,
        ];

        let buffer = match dump(&mut mib) {
            Ok(buffer) => buffer,
            Err(e) => {
                warn!(
                    verbosity = 1,
                    "could not read the IPv6 neighbour table: {e}"
                );
                return Vec::new();
            }
        };

        parse(&buffer)
    }

    /// Reads a sysctl of unknown size: ask for the length, allocate, read.
    ///
    /// The two calls race against a table that changes between them, so a short
    /// read is retried once with the length the kernel reported the second time.
    /// A table that keeps growing faster than it can be read is reported rather
    /// than looped on.
    fn dump(mib: &mut [c_int]) -> std::io::Result<Vec<u8>> {
        for _ in 0..2 {
            let mut len: size_t = 0;
            // SAFETY: `mib` is a valid slice of the length passed alongside it,
            // and a null `oldp` with a non-null `oldlenp` is the documented way
            // to ask only for the size.
            let sized = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as u32,
                    std::ptr::null_mut(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if sized < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if len == 0 {
                return Ok(Vec::new());
            }

            let mut buffer = vec![0u8; len];
            // SAFETY: `buffer` is `len` bytes and `len` is passed by pointer, so
            // the kernel writes no more than was allocated and reports how much
            // it used.
            let read = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as u32,
                    buffer.as_mut_ptr() as *mut c_void,
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if read < 0 {
                let err = std::io::Error::last_os_error();
                // The table grew between the two calls; ask again.
                if err.raw_os_error() == Some(libc::ENOMEM) {
                    continue;
                }
                return Err(err);
            }

            buffer.truncate(len);
            return Ok(buffer);
        }

        Err(std::io::Error::other(
            "the neighbour table kept growing while it was being read",
        ))
    }

    /// Walks the routing messages in `buffer`, yielding one neighbour per entry.
    ///
    /// Every length here comes from the kernel and is bounds-checked anyway. The
    /// buffer is trusted, but a message claiming to be longer than what remains
    /// would walk off the end, and a zero-length one would loop forever.
    fn parse(buffer: &[u8]) -> Vec<Neighbor> {
        let mut neighbors = Vec::new();
        let mut offset = 0usize;

        while offset + mem::size_of::<rt_msghdr>() <= buffer.len() {
            // SAFETY: the bounds check above guarantees a whole header is
            // present, and `rt_msghdr` is a plain repr(C) struct.
            let header: rt_msghdr =
                unsafe { std::ptr::read_unaligned(buffer[offset..].as_ptr() as *const rt_msghdr) };

            let message_len = header.rtm_msglen as usize;
            if message_len == 0 || offset + message_len > buffer.len() {
                break;
            }

            if let Some(neighbor) = entry(
                &buffer[offset + mem::size_of::<rt_msghdr>()..offset + message_len],
                header.rtm_addrs,
                header.rtm_index as u32,
            ) {
                neighbors.push(neighbor);
            }

            offset += message_len;
        }

        neighbors
    }

    /// Reads one message's address block: a sequence of `sockaddr`s, present or
    /// absent according to the bits in `addrs`, in a fixed order.
    ///
    /// The destination is the neighbour's address and the gateway is its
    /// link-layer address. Anything else in the block is skipped by its own
    /// length, which is why the whole sequence has to be walked even to read
    /// only two of them.
    fn entry(mut block: &[u8], addrs: c_int, interface_index: u32) -> Option<Neighbor> {
        let mut ip: Option<IpAddr> = None;
        let mut mac: Option<MacAddr> = None;

        for bit in 0..8 {
            let flag = 1 << bit;
            if addrs & flag == 0 {
                continue;
            }
            if block.len() < mem::size_of::<sockaddr>() {
                break;
            }

            // SAFETY: a whole `sockaddr` is present per the check above; its
            // `sa_len` then says how much of the block this one occupies.
            let sa: sockaddr =
                unsafe { std::ptr::read_unaligned(block.as_ptr() as *const sockaddr) };
            let sa_len = roundup(sa.sa_len as usize);
            if sa_len == 0 || sa_len > block.len() {
                break;
            }

            match (flag, c_int::from(sa.sa_family)) {
                (RTA_DST, AF_INET6) => ip = read_ipv6(&block[..sa_len]),
                (RTA_GATEWAY, AF_LINK) => mac = read_mac(&block[..sa_len]),
                _ => {}
            }

            block = &block[sa_len..];
        }

        ip.map(|ip| Neighbor {
            ip,
            mac,
            interface_index,
        })
    }

    fn read_ipv6(bytes: &[u8]) -> Option<IpAddr> {
        if bytes.len() < mem::size_of::<sockaddr_in6>() {
            return None;
        }
        // SAFETY: the length check guarantees a whole `sockaddr_in6`.
        let sin6: sockaddr_in6 =
            unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const sockaddr_in6) };
        let mut octets = sin6.sin6_addr.s6_addr;

        // BSD stores a link-local address's scope in bytes 2 and 3 of the
        // address itself rather than in the `sin6_scope_id` field, which is a
        // representation no other part of the engine uses and which would
        // otherwise be reported as part of the address. The interface is carried
        // separately, so the embedded copy is cleared.
        if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
            octets[2] = 0;
            octets[3] = 0;
        }

        Some(IpAddr::V6(Ipv6Addr::from(octets)))
    }

    fn read_mac(bytes: &[u8]) -> Option<MacAddr> {
        if bytes.len() < mem::size_of::<sockaddr_dl>() {
            return None;
        }
        // SAFETY: the length check guarantees a whole `sockaddr_dl`.
        let sdl: sockaddr_dl =
            unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const sockaddr_dl) };

        // The address lives inside a variable-length trailer after the interface
        // name, and is only a MAC when it is six bytes long.
        const ETHER_ADDR_LEN: usize = 6;
        if sdl.sdl_alen as usize != ETHER_ADDR_LEN {
            return None;
        }

        let start = sdl.sdl_nlen as usize;
        let data = &sdl.sdl_data;
        let end = start + ETHER_ADDR_LEN;
        if end > data.len() {
            return None;
        }

        let octets: Vec<u8> = data[start..end].iter().map(|b| *b as u8).collect();
        Some(MacAddr::new(
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
        ))
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Everywhere else
// ══════════════════════════════════════════════════════════════════════════════

/// Platforms whose neighbour table this does not read yet.
///
/// Reported once rather than silently returning nothing, because an empty table
/// and an unread one lead to the same host count and mean entirely different
/// things — the distinction this whole engine is built to preserve.
///
/// Linux keeps its table behind netlink (`RTM_GETNEIGH`) and Windows behind
/// `GetIpNetTable2`; both are a self-contained piece of work against an
/// interface neither shares with the other.
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
mod platform {
    use super::Neighbor;
    use crate::warn;

    pub(super) fn ipv6_neighbors() -> Vec<Neighbor> {
        warn!(
            verbosity = 1,
            "reading the IPv6 neighbour table is not implemented on this platform; \
             discovery will not use it as a source of candidate addresses"
        );
        Vec::new()
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

    /// Reading the table must not panic, whatever the host looks like, and must
    /// answer with something usable rather than an error a caller has to handle.
    ///
    /// Deliberately not an assertion about *contents*: a machine with no IPv6
    /// neighbours is a perfectly ordinary machine, and a test demanding some
    /// would fail in CI for a reason having nothing to do with this code.
    #[test]
    fn reading_the_table_is_infallible() {
        let neighbors = ipv6_neighbors();

        for neighbor in &neighbors {
            assert!(
                neighbor.ip.is_ipv6(),
                "the IPv6 table yielded {}",
                neighbor.ip
            );
        }
    }

    /// Every entry the table yields has to be something a probe can be aimed at.
    ///
    /// A link-local address without its interface is the one shape this must
    /// never produce, since it is exactly what the rest of the engine refuses to
    /// act on.
    #[test]
    fn every_link_local_entry_names_its_interface() {
        for neighbor in ipv6_neighbors() {
            let IpAddr::V6(v6) = neighbor.ip else {
                continue;
            };
            if v6.is_unicast_link_local() {
                assert_ne!(
                    neighbor.interface_index, 0,
                    "{v6} came back with no interface, so nothing could probe it"
                );
            }
        }
    }
}
