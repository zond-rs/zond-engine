// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Multicast resolution over the wire
//!
//! Sends the forward query [`crate::protocols::mdns`] builds and reads the
//! addresses out of whatever answers. This is the socket half of resolving a
//! `.local` name; the packet half knows nothing about sockets.
//!
//! ## Why it joins the group, and not just listens on an ephemeral port
//!
//! A `.local` name is resolved by asking the link, not a server: the query goes
//! to the multicast group `224.0.0.251:5353` and every responder on the segment
//! may answer. The tempting shortcut is to send from an ephemeral port and read
//! the reply there, on the strength of RFC 6762 §6.7, which says a responder
//! seeing a query from a port other than 5353 must answer it as unicast. In
//! practice that reply does not reliably arrive: a responder that has an answer
//! ready — the host's own responder answering for `mac.local`, most of all —
//! sends it to the multicast group, and a socket listening only on its own
//! ephemeral port never sees it.
//!
//! So this speaks mDNS the way the responders expect to be spoken to. It binds
//! port 5353, joins the group, and reads the multicast answers directly.
//! Port 5353 already belongs to the host's own responder (`mDNSResponder` on
//! macOS, `avahi` on Linux), so the bind sets `SO_REUSEADDR` and `SO_REUSEPORT`
//! to sit alongside it rather than displace it — multicast datagrams are
//! delivered to every socket joined to the group, so both receive them.
//! Multicast loopback is left on, which is what lets the host hear its *own*
//! responder: the `mac.local` case resolves for exactly this reason.
//!
//! The query goes out over the IPv4 group only. That still learns a host's IPv6
//! addresses: a responder answers with every address it holds for the name, so
//! the AAAA records ride back in the same reply as the A records. The one host
//! this cannot reach is one with no IPv4 address at all, which on a home or
//! office segment is rare enough to leave to a later IPv6-group pass.
//!
//! ## Every interface, because the default one is wrong
//!
//! A multicast group is joined on *an* interface, and the query egresses *an*
//! interface, and leaving the host to pick which is the mistake this makes a
//! point of not making. On a machine with a VPN up, the kernel's default
//! multicast interface is routinely the tunnel — measured on the machine this
//! was written on, where an unspecified-interface join bound to a `utun` and the
//! LAN's own responder was never heard. So the query is put out, and the group
//! joined, on *every* non-loopback interface holding an IPv4 address, one socket
//! each, and every answer that comes back on any of them is gathered.
//!
//! An interface with no IPv4 address of its own is skipped, since it cannot
//! carry a query to the v4 group. The one host that leaves unreachable is one on
//! a v6-only segment, the same gap the v4-only query already has.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket};
use std::time::Duration;

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout};

use crate::protocols::mdns::{self, PORT};
use crate::warn;

/// The IPv4 multicast group every mDNS responder on the segment listens to.
const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// The IP TTL an mDNS message is sent with. Fixed at 255 by RFC 6762 §11 so a
/// receiver can reject any mDNS packet that arrives with a lower one as having
/// crossed a router it should never have crossed.
const MULTICAST_TTL: u32 = 255;

/// The largest reply worth reading. RFC 6762 permits an mDNS message up to
/// roughly 9000 bytes when the path allows it, and a response carrying a host's
/// A, AAAA and the service records it volunteers alongside them can approach
/// that. A short buffer would truncate the answer into something unparseable
/// rather than merely incomplete.
const MAX_DATAGRAM: usize = 9000;

/// Resolves the addresses of a `.local` `name`, listening for `timeout`.
///
/// Every responder that answers within the window contributes; a name no
/// responder claims comes back as an empty vector, which is not an error but the
/// ordinary "nobody here answers to that" outcome. A socket that will not bind
/// or a group that cannot be reached is logged and also yields nothing, on the
/// principle that a name that could not be looked up and a name that resolved to
/// nothing are the same target — missing — to the caller.
pub async fn resolve(name: &str, timeout_after: Duration) -> Vec<IpAddr> {
    match query(name, timeout_after).await {
        Ok(addresses) => addresses,
        Err(e) => {
            warn!("mDNS lookup of {name} failed: {e}");
            Vec::new()
        }
    }
}

/// Puts the query on every usable interface and gathers matching addresses from
/// all of them until the window closes.
///
/// Each interface gets its own socket, its own send, and its own listening task;
/// the tasks run for the whole window and their finds are unioned. An interface
/// whose socket will not open, or whose send fails, is logged and dropped rather
/// than failing the lookup — another interface may still carry it. Only a run in
/// which no interface could be queried at all is an error.
async fn query(name: &str, timeout_after: Duration) -> Result<Vec<IpAddr>> {
    let interfaces = multicast_interfaces();
    if interfaces.is_empty() {
        anyhow::bail!("no interface holds an IPv4 address to query the mDNS group on");
    }

    let packet = mdns::build_query(name)?;
    let wanted = name.trim_end_matches('.').to_string();
    let deadline = Instant::now() + timeout_after;
    let target = SocketAddr::V4(SocketAddrV4::new(GROUP_V4, PORT));

    let mut listeners: JoinSet<Vec<IpAddr>> = JoinSet::new();
    for iface in interfaces {
        let socket = match open_group_socket(iface) {
            Ok(socket) => socket,
            Err(e) => {
                warn!("mDNS: could not join the group on {iface}: {e}");
                continue;
            }
        };
        if let Err(e) = socket.send_to(&packet, target).await {
            warn!("mDNS: could not query the group on {iface}: {e}");
            continue;
        }

        let wanted = wanted.clone();
        listeners.spawn(listen(socket, wanted, deadline));
    }

    if listeners.is_empty() {
        anyhow::bail!("no interface accepted the mDNS query");
    }

    let mut found = Vec::new();
    while let Some(joined) = listeners.join_next().await {
        if let Ok(addresses) = joined {
            for ip in addresses {
                if !found.contains(&ip) {
                    found.push(ip);
                }
            }
        }
    }

    Ok(found)
}

/// Reads `socket` until `deadline`, returning the addresses it hears for
/// `wanted`.
///
/// The window closing with replies still possibly in flight is the ordinary way
/// this ends, not a failure: a responder is under no obligation to answer, and a
/// name with no host answers exactly as a name whose host is slow to. A read
/// error ends this interface's listening without ending the lookup, since the
/// others are still going.
async fn listen(socket: UdpSocket, wanted: String, deadline: Instant) -> Vec<IpAddr> {
    let mut found = Vec::new();
    let mut buf = [0u8; MAX_DATAGRAM];

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _from))) => collect_matching(&buf[..len], &wanted, &mut found),
            _ => break,
        }
    }

    found
}

/// Opens one socket bound to port 5353 on `interface`, joined to the mDNS group
/// there.
///
/// The options that let this coexist with the host's own responder — reusing the
/// address and the port — must be set before the bind, which `std` cannot
/// express, so the socket is built through `socket2` and configured here. The
/// multicast interface is pinned so the query egresses `interface` rather than
/// whichever one the host would otherwise default to, and the group is joined on
/// the same interface so the answers arriving there are delivered. Once bound and
/// joined it is an ordinary UDP socket, handed to tokio for the send and receive.
fn open_group_socket(interface: Ipv4Addr) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("creating the mDNS socket")?;

    socket.set_reuse_address(true)?;
    // Unix only, and both supported platforms are: without it a second socket on
    // 5353 — the host's own responder is the first — is refused rather than bound
    // alongside.
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_multicast_ttl_v4(MULTICAST_TTL)?;
    socket.set_multicast_if_v4(&interface)?;

    let bind_addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT));
    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("binding {bind_addr} for {interface}"))?;
    socket
        .join_multicast_v4(&GROUP_V4, &interface)
        .with_context(|| format!("joining the mDNS group on {interface}"))?;

    socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(StdUdpSocket::from(socket))?)
}

/// One IPv4 address per interface worth sending an mDNS query from: up, not
/// loopback, and holding an address of its own to pin the send and the join to.
///
/// One address per interface rather than all of them, since a second address on
/// the same interface would only open a second socket onto the same segment. An
/// interface with no IPv4 address is not here, because it cannot reach the v4
/// group.
fn multicast_interfaces() -> Vec<Ipv4Addr> {
    crate::system::interface::interfaces()
        .into_iter()
        .filter(|link| link.is_up() && !link.is_loopback())
        .filter_map(|link| link.ipv4().map(|(v4, _)| v4).find(|v4| !v4.is_loopback()))
        .collect()
}

/// Reads one datagram and appends the addresses it gives for `wanted`.
///
/// A datagram that will not parse is skipped in silence: the group carries every
/// responder's traffic, including announcements and other queriers' answers, so
/// a message about a different host — or no host — is not this lookup's to
/// complain about. Names are matched without regard to case, since a responder
/// may echo the owner name in whatever case it stores it. Addresses already seen
/// are not repeated, so two responders naming the same host do not double it.
fn collect_matching(datagram: &[u8], wanted: &str, found: &mut Vec<IpAddr>) {
    let Ok(hosts) = mdns::extract_hosts(datagram) else {
        return;
    };

    for host in hosts {
        if !host.hostname.eq_ignore_ascii_case(wanted) {
            continue;
        }
        for ip in host.ips {
            if !found.contains(&ip) {
                found.push(ip);
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

    /// Assembles an mDNS response the way the wire carries one, so a test drives
    /// the matcher with bytes a responder would actually emit rather than with
    /// whatever the parser happens to accept. Mirrors the builder the
    /// `protocols::mdns` tests use for the same reason.
    fn response(records: &[(&str, IpAddr)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes()); // ID
        bytes.extend_from_slice(&0x8400u16.to_be_bytes()); // response, authoritative
        bytes.extend_from_slice(&0u16.to_be_bytes()); // questions
        bytes.extend_from_slice(&(records.len() as u16).to_be_bytes()); // answers
        bytes.extend_from_slice(&0u16.to_be_bytes()); // authority
        bytes.extend_from_slice(&0u16.to_be_bytes()); // additional

        for (owner, ip) in records {
            for label in owner.split('.') {
                bytes.push(label.len() as u8);
                bytes.extend_from_slice(label.as_bytes());
            }
            bytes.push(0);

            let (rtype, rdata): (u16, Vec<u8>) = match ip {
                IpAddr::V4(v4) => (1, v4.octets().to_vec()),
                IpAddr::V6(v6) => (28, v6.octets().to_vec()),
            };
            bytes.extend_from_slice(&rtype.to_be_bytes());
            bytes.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            bytes.extend_from_slice(&120u32.to_be_bytes()); // TTL
            bytes.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&rdata);
        }

        bytes
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("a valid address")
    }

    /// The answer's A and AAAA records for the queried name are both kept, so
    /// one exchange learns a host in both families.
    #[test]
    fn both_families_of_the_named_host_are_collected() {
        let datagram = response(&[
            ("raspberrypi.local", ip("192.168.0.150")),
            ("raspberrypi.local", ip("fe80::1")),
        ]);

        let mut found = Vec::new();
        collect_matching(&datagram, "raspberrypi.local", &mut found);

        assert!(found.contains(&ip("192.168.0.150")));
        assert!(found.contains(&ip("fe80::1")));
        assert_eq!(found.len(), 2);
    }

    /// A responder volunteers what else it knows, so a reply routinely names
    /// hosts the query did not ask about. Those addresses belong to other
    /// machines and must not be handed back as this name's.
    #[test]
    fn a_reply_naming_other_hosts_contributes_only_the_match() {
        let datagram = response(&[
            ("appletv.local", ip("192.168.0.40")),
            ("raspberrypi.local", ip("192.168.0.150")),
            ("printer.local", ip("192.168.0.30")),
        ]);

        let mut found = Vec::new();
        collect_matching(&datagram, "raspberrypi.local", &mut found);

        assert_eq!(found, vec![ip("192.168.0.150")]);
    }

    /// A responder may store and echo the owner name in any case, so matching
    /// has to ignore it or a host answers and is discarded.
    #[test]
    fn the_name_is_matched_without_regard_to_case() {
        let datagram = response(&[("Raspberrypi.local", ip("192.168.0.150"))]);

        let mut found = Vec::new();
        collect_matching(&datagram, "raspberrypi.local", &mut found);

        assert_eq!(found, vec![ip("192.168.0.150")]);
    }

    /// The group carries every responder's traffic; a datagram that is not a DNS
    /// message at all is background noise, not a lookup failure.
    #[test]
    fn a_datagram_that_is_not_dns_is_ignored() {
        let mut found = Vec::new();
        collect_matching(b"not a dns message", "raspberrypi.local", &mut found);
        assert!(found.is_empty());
    }

    /// Two responders naming the same host — a Pi that answers on two
    /// interfaces, say — must not make it appear twice.
    #[test]
    fn an_address_two_responders_agree_on_is_recorded_once() {
        let datagram = response(&[("nas.local", ip("192.168.0.5"))]);

        let mut found = vec![ip("192.168.0.5")];
        collect_matching(&datagram, "nas.local", &mut found);

        assert_eq!(found, vec![ip("192.168.0.5")]);
    }
}
