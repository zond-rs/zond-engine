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
//! addresses out of whatever answers: the socket half of resolving a `.local`
//! name.
//!
//! ## Joining the group
//!
//! The query goes to the multicast group `224.0.0.251:5353`, and every responder
//! on the segment may answer. RFC 6762 §6.7 says a responder seeing a query from
//! a port other than 5353 must answer by unicast, but in practice that reply does
//! not reliably arrive: a responder with an answer ready, above all the host's
//! own responder answering for `mac.local`, sends it to the group, which a socket
//! on an ephemeral port never sees.
//!
//! So this binds port 5353, joins the group, and reads the multicast answers.
//! The port already belongs to the host's own responder (`mDNSResponder` on
//! macOS, `avahi` on Linux), so the bind sets `SO_REUSEADDR` and `SO_REUSEPORT`
//! to sit alongside it; multicast datagrams reach every socket joined to the
//! group. Multicast loopback is left on so the host hears its own responder,
//! which is how `mac.local` resolves.
//!
//! The query goes out over the IPv4 group only. A responder answers with every
//! address it holds for the name, so AAAA records come back in the same reply
//! as A records. A host with no IPv4 address at all is out of reach until an
//! IPv6-group pass exists.
//!
//! ## Every interface
//!
//! On a machine with a VPN up, the kernel's default multicast interface is
//! often the tunnel: a join with no interface given has been seen to bind to a
//! `utun`, and the LAN's responders went unheard. So the query is sent, and the
//! group joined, on every non-loopback interface holding an IPv4 address, one
//! socket each, and answers from all of them are gathered. An interface with no
//! IPv4 address is skipped, since it cannot reach the v4 group.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout};

use crate::protocols::mdns::{self, PORT};
use crate::warn;

/// The IPv4 multicast group every mDNS responder on the segment listens to.
const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// The IP TTL an mDNS message is sent with. Fixed at 255 by RFC 6762 §11 so a
/// receiver can reject a packet with a lower one as having crossed a router.
const MULTICAST_TTL: u32 = 255;

/// The largest reply read. RFC 6762 permits an mDNS message up to roughly 9000
/// bytes when the path allows it, and a response carrying a host's A, AAAA and
/// volunteered service records can approach that. A truncated answer does not
/// parse at all.
const MAX_DATAGRAM: usize = 9000;

/// Resolves the addresses of a `.local` `name`, listening for `timeout`.
///
/// Every responder that answers within the window contributes. A name no
/// responder claims gives an empty vector. A socket that will not bind or a
/// group that cannot be reached is logged and also gives an empty vector, since
/// to the caller both are the same missing target.
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
/// Each interface gets its own socket, send and listening task; the tasks run
/// for the whole window and their finds are merged. An interface whose socket
/// will not open, or whose send fails, is logged and dropped. It is an error
/// only when no interface could be queried.
async fn query(name: &str, timeout_after: Duration) -> std::io::Result<Vec<IpAddr>> {
    let interfaces = multicast_interfaces();
    if interfaces.is_empty() {
        return Err(std::io::Error::other(
            "no interface holds an IPv4 address to query the mDNS group on",
        ));
    }

    let packet = mdns::build_query(name).map_err(std::io::Error::other)?;
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
        return Err(std::io::Error::other(
            "no interface accepted the mDNS query",
        ));
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
/// Ends when the window closes, or on a read error, which stops only this
/// interface's listener.
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
/// Address and port reuse, which let this coexist with the host's own
/// responder, must be set before the bind, which `std` cannot express, so the
/// socket is built through `socket2`. The multicast interface is pinned so the
/// query leaves by `interface`, and the group is joined on the same interface so
/// answers arriving there are delivered. The result is handed to tokio.
fn open_group_socket(interface: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    // Without it, binding 5353 next to the host's own responder is refused.
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_multicast_ttl_v4(MULTICAST_TTL)?;
    socket.set_multicast_if_v4(&interface)?;

    let bind_addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT));
    socket.bind(&bind_addr.into()).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("binding {bind_addr} for {interface}: {error}"),
        )
    })?;
    socket
        .join_multicast_v4(&GROUP_V4, &interface)
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("joining the mDNS group on {interface}: {error}"),
            )
        })?;

    socket.set_nonblocking(true)?;
    UdpSocket::from_std(StdUdpSocket::from(socket))
}

/// One IPv4 address per interface worth sending an mDNS query from: up, not
/// loopback, and holding an address of its own to pin the send and the join to.
///
/// One address per interface, since a second would only open a second socket
/// onto the same segment.
fn multicast_interfaces() -> Vec<Ipv4Addr> {
    crate::system::interface::interfaces_or_none()
        .into_iter()
        .filter(|link| link.is_up() && !link.is_loopback())
        .filter_map(|link| link.ipv4().map(|(v4, _)| v4).find(|v4| !v4.is_loopback()))
        .collect()
}

/// Reads one datagram and appends the addresses it gives for `wanted`.
///
/// A datagram that will not parse is skipped silently, since the group carries
/// every responder's traffic. Names are matched case-insensitively, since a
/// responder may echo the owner name in whatever case it stores it. Addresses
/// already in `found` are not added again.
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

    /// Assembles an mDNS response as the wire carries one, so the matcher is
    /// driven with bytes a responder would emit. Mirrors the builder in the
    /// `protocols::mdns` tests.
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
            ("raspberrypi.local", ip("192.0.2.150")),
            ("raspberrypi.local", ip("fe80::1")),
        ]);

        let mut found = Vec::new();
        collect_matching(&datagram, "raspberrypi.local", &mut found);

        assert!(found.contains(&ip("192.0.2.150")));
        assert!(found.contains(&ip("fe80::1")));
        assert_eq!(found.len(), 2);
    }

    /// A responder volunteers what else it knows, so a reply often names hosts
    /// the query did not ask about. Their addresses are not this name's.
    #[test]
    fn a_reply_naming_other_hosts_contributes_only_the_match() {
        let datagram = response(&[
            ("appletv.local", ip("192.0.2.40")),
            ("raspberrypi.local", ip("192.0.2.150")),
            ("printer.local", ip("192.0.2.30")),
        ]);

        let mut found = Vec::new();
        collect_matching(&datagram, "raspberrypi.local", &mut found);

        assert_eq!(found, vec![ip("192.0.2.150")]);
    }

    /// A responder may echo the owner name in any case.
    #[test]
    fn the_name_is_matched_without_regard_to_case() {
        let datagram = response(&[("Raspberrypi.local", ip("192.0.2.150"))]);

        let mut found = Vec::new();
        collect_matching(&datagram, "raspberrypi.local", &mut found);

        assert_eq!(found, vec![ip("192.0.2.150")]);
    }

    /// The group carries every responder's traffic, so a datagram that is not
    /// DNS is ignored.
    #[test]
    fn a_datagram_that_is_not_dns_is_ignored() {
        let mut found = Vec::new();
        collect_matching(b"not a dns message", "raspberrypi.local", &mut found);
        assert!(found.is_empty());
    }

    /// Two responders naming the same host, such as a Pi answering on two
    /// interfaces, record it once.
    #[test]
    fn an_address_two_responders_agree_on_is_recorded_once() {
        let datagram = response(&[("nas.local", ip("192.0.2.5"))]);

        let mut found = vec![ip("192.0.2.5")];
        collect_matching(&datagram, "nas.local", &mut found);

        assert_eq!(found, vec![ip("192.0.2.5")]);
    }
}
