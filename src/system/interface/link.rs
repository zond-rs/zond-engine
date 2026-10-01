// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What this machine is plugged into, as this engine needs it
//!
//! One type, [`Link`], owned by this crate so the public API does not carry the
//! enumerating library's type or its platform defects. Where the facts come from
//! is [`from_netdev`](Link::from_netdev)'s business alone.
//!
//! It carries only what the engine reads: speed, MTU, DNS servers and statistics
//! are left out.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::ip::range::{IpRange, cidr_range};
use crate::model::ip::scoped::Zone;
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;

/// One address an interface holds, and how much of it names the network.
///
/// The address is what a probe goes out *from*, and the network decides whether
/// a target is on this link or beyond it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkAddress {
    address: IpAddr,
    prefix: u8,
}

impl LinkAddress {
    /// An address and the length of its prefix.
    ///
    /// The prefix is clamped to what the family allows. A value past the end is
    /// the platform reporting something impossible, and the address is still
    /// worth having.
    pub fn new(address: IpAddr, prefix: u8) -> Self {
        let ceiling = if address.is_ipv4() { 32 } else { 128 };
        Self {
            address,
            prefix: prefix.min(ceiling),
        }
    }

    /// The address itself.
    pub fn address(&self) -> IpAddr {
        self.address
    }

    /// How many leading bits name the network.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Every address this prefix covers, network and broadcast included.
    ///
    /// This is what the link carries, as an on-link test needs; whether either
    /// end is worth probing is the sweeper's decision.
    pub fn network(&self) -> IpRange {
        // `new` clamped the prefix to its family, the only way this could fail.
        cidr_range(self.address, self.prefix).expect("a prefix clamped to its family")
    }

    /// Whether `ip` is on the same network as this address.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.network().contains(ip)
    }
}

/// What kind of thing a link is.
///
/// The engine asks only three questions of it: can it carry a link-layer probe,
/// is it wireless (a pacing question), and is it the machine talking to itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LinkKind {
    /// Something a frame can be put on the wire of: Ethernet at any speed, and
    /// the wired families that look like it from here.
    Wired,
    /// 802.11. Told apart from [`Wired`](Self::Wired) because a wireless link
    /// answers slower and less predictably.
    Wireless,
    /// The machine talking to itself.
    Loopback,
    /// A tunnel, a virtual adapter, or anything else with no physical port
    /// behind it. Capable of carrying IP and not of carrying a neighbour.
    Virtual,
}

/// A network interface on this machine.
///
/// Built from the host's interface table by `from_netdev`, or by hand in a test.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Link {
    name: String,
    friendly_name: Option<String>,
    index: u32,
    mac: Option<MacAddr>,
    addresses: Vec<LinkAddress>,
    kind: LinkKind,
    up: bool,
    addressing: Addressing,
    physical: bool,
    default_route: bool,
    gateway: bool,
}

impl Link {
    /// A link with nothing on it but a name and a number.
    ///
    /// The starting point for a test, or for a caller describing a link this
    /// machine cannot be asked about. Everything else is added through the
    /// builders below.
    pub fn new(name: impl Into<String>, index: u32) -> Self {
        Self {
            name: name.into(),
            friendly_name: None,
            index,
            mac: None,
            addresses: Vec::new(),
            kind: LinkKind::Virtual,
            up: false,
            addressing: Addressing::Neither,
            physical: false,
            default_route: false,
            gateway: false,
        }
    }

    /// The hardware address this link answers at.
    #[must_use]
    pub fn with_mac(mut self, mac: MacAddr) -> Self {
        self.mac = Some(mac);
        self
    }

    /// The addresses it holds.
    #[must_use]
    pub fn with_addresses(mut self, addresses: Vec<LinkAddress>) -> Self {
        self.addresses = addresses;
        self
    }

    /// What kind of link it is.
    #[must_use]
    pub fn with_kind(mut self, kind: LinkKind) -> Self {
        self.kind = kind;
        self
    }

    /// Whether the operating system reports it as up.
    #[must_use]
    pub fn with_link_up(mut self, up: bool) -> Self {
        self.up = up;
        self
    }

    /// How addresses on this link reach anything.
    #[must_use]
    pub fn with_addressing(mut self, addressing: Addressing) -> Self {
        self.addressing = addressing;
        self
    }

    /// Whether there is real hardware behind it.
    #[must_use]
    pub fn with_physical(mut self, physical: bool) -> Self {
        self.physical = physical;
        self
    }

    /// Whether this machine's default route leaves by it.
    #[must_use]
    pub fn with_default_route(mut self, carries: bool) -> Self {
        self.default_route = carries;
        self
    }

    /// Whether a router is configured on the link.
    #[must_use]
    pub fn with_gateway(mut self, has: bool) -> Self {
        self.gateway = has;
        self
    }

    /// What the interface is called here.
    ///
    /// The platform's name, which every other call in this crate is keyed by.
    /// On Windows it is the adapter's GUID.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What a person calls the interface, for a message addressed to one.
    ///
    /// The name the system settings show where the platform keeps one apart
    /// from [`name`](Self::name): `Wi-Fi` or `vEthernet (WSL)` on Windows, where
    /// the name is a GUID nobody recognises, and the display name on macOS.
    /// Otherwise the name itself, which on Linux is what a person writes.
    pub(crate) fn display_name(&self) -> &str {
        self.friendly_name.as_deref().unwrap_or(&self.name)
    }

    /// Its number in this kernel's interface table.
    ///
    /// Valid for this boot only, so nothing durable is keyed by it. See [`Zone`].
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The hardware address, where it has one.
    ///
    /// `None` for a link with no link layer to have one on: a tunnel, and
    /// loopback on most platforms.
    pub fn mac(&self) -> Option<MacAddr> {
        self.mac
    }

    /// Every address this link holds.
    pub fn addresses(&self) -> &[LinkAddress] {
        &self.addresses
    }

    /// The IPv4 addresses among them.
    pub fn ipv4(&self) -> impl Iterator<Item = (Ipv4Addr, u8)> + '_ {
        self.addresses.iter().filter_map(|held| match held.address {
            IpAddr::V4(v4) => Some((v4, held.prefix)),
            IpAddr::V6(_) => None,
        })
    }

    /// The IPv6 addresses among them.
    pub fn ipv6(&self) -> impl Iterator<Item = (Ipv6Addr, u8)> + '_ {
        self.addresses.iter().filter_map(|held| match held.address {
            IpAddr::V6(v6) => Some((v6, held.prefix)),
            IpAddr::V4(_) => None,
        })
    }

    /// This link as a zone, for scoping a link-local address to it.
    pub fn zone(&self) -> Zone {
        Zone::new(self.index, self.name.clone())
    }

    /// What kind of link it is.
    pub fn kind(&self) -> LinkKind {
        self.kind
    }

    /// Whether the operating system reports it as up.
    pub fn is_up(&self) -> bool {
        self.up
    }

    /// Whether this is the machine talking to itself.
    pub fn is_loopback(&self) -> bool {
        self.kind == LinkKind::Loopback
    }

    /// Whether it is 802.11.
    pub fn is_wireless(&self) -> bool {
        self.kind == LinkKind::Wireless
    }

    /// Whether there is a physical port behind it.
    ///
    /// False for a tunnel, a hypervisor's virtual switch, and a VPN, none of
    /// which has a neighbour to ARP for.
    pub fn is_physical(&self) -> bool {
        self.physical
    }

    /// Whether it can carry a broadcast.
    pub fn is_broadcast(&self) -> bool {
        self.addressing == Addressing::Broadcast
    }

    /// Whether it is a point-to-point link, which has one peer and no segment.
    pub fn is_point_to_point(&self) -> bool {
        self.addressing == Addressing::PointToPoint
    }

    /// Whether this machine's default route leaves by this link.
    ///
    /// The closest thing there is to "which network am I on", answerable the
    /// same way on every platform. Hardware fields cannot tell: macOS presents
    /// `awdl0` (AirDrop) and `llw0` as ordinary wired Ethernet.
    pub fn carries_default_route(&self) -> bool {
        self.default_route
    }

    /// Whether a router is configured on this link. True of a real LAN, false of
    /// a host-only virtualisation bridge, which is what tells them apart when a
    /// VPN owns the global default route.
    pub fn has_gateway(&self) -> bool {
        self.gateway
    }

    /// Whether it is a physical link that is not wireless.
    ///
    /// The one to prefer when there is a choice: a wired segment answers faster
    /// and more consistently than 802.11.
    pub fn is_wired(&self) -> bool {
        self.kind == LinkKind::Wired
    }

    /// Whether a link-layer probe can be put on it.
    ///
    /// ARP and neighbour discovery need a segment with somebody else on it and
    /// a hardware address to send from. A point-to-point link has a peer and no
    /// segment, loopback has neither, and a link with no hardware address has
    /// nothing to put in the frame.
    pub fn carries_frames(&self) -> bool {
        !self.is_point_to_point() && !self.is_loopback() && self.mac.is_some()
    }
}

/// How addresses on a link reach anything, which decides what a scan may send
/// out of it.
///
/// One value, since the platform's two flags are not independent.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Addressing {
    /// A shared segment: one frame sent to the broadcast address reaches every
    /// host on the link, which is what a sweep of a local network needs.
    Broadcast,

    /// Exactly one peer at the far end, and no broadcast address to reach it
    /// by. A tunnel or a dial-up link. Sweeping it means probing one host.
    PointToPoint,

    /// Neither. Loopback carries nothing to another machine at all, and some
    /// virtual interfaces present the same way.
    Neither,
}

impl Addressing {
    /// What a platform's two flags amount to.
    ///
    /// A link reporting both `IFF_BROADCAST` and `IFF_POINTOPOINT` (which no
    /// operating system does) is read as point-to-point, since broadcasting onto
    /// something that is not a broadcast domain is the more expensive mistake.
    pub(crate) fn of(broadcast: bool, point_to_point: bool) -> Self {
        match (broadcast, point_to_point) {
            (_, true) => Self::PointToPoint,
            (true, false) => Self::Broadcast,
            (false, false) => Self::Neither,
        }
    }
}

/// Every interface this machine has.
///
/// The one place the host is asked. Everything else in this crate takes
/// [`Link`]s from a caller or from here, so a scan against a stated set of links
/// and a scan against the real machine share a code path.
///
/// # Errors
///
/// When the host cannot be asked because the process has no descriptor free:
/// `EMFILE`, or, where no shortage can be found, an error saying the table came
/// back empty. Every host has a loopback interface, so an empty table means a
/// read failed silently.
///
/// On macOS the first read in a process with no descriptor free is refused,
/// because the system framework it goes through would segfault. Once one read
/// has succeeded, later ones need no descriptor.
pub fn interfaces() -> io::Result<Vec<Link>> {
    Ok(host_table()?.into_iter().map(Link::from_netdev).collect())
}

/// [`interfaces`], or none where the host cannot be asked, for a reader with no
/// error of its own to give.
///
/// The table is unreadable only in a process with no descriptor free, where
/// nothing a reader would do with a link could open a socket either. A scan is
/// refused before it starts in such a table; see
/// [`too_few`](crate::system::descriptors::too_few).
pub(crate) fn interfaces_or_none() -> Vec<Link> {
    interfaces().unwrap_or_default()
}

/// The host's interface table as `netdev` reads it, with the one fact it reads
/// wrong put right.
///
/// Every part of the crate that needs something [`Link`] does not carry, such as
/// a gateway's hardware address, reads the table through here, so the correction
/// and the refusal below hold everywhere. A census in
/// `tests/hygiene/architecture.rs` enforces this.
///
/// The correction is to a point-to-point link's own address on Linux. `netdev`
/// keeps the first of a netlink message's `IFA_ADDRESS` and `IFA_LOCAL`, which
/// are one address on most links. On a point-to-point link configured with a
/// peer (every pppd link, OpenVPN's p2p and net30 topologies) the kernel sends
/// `IFA_ADDRESS` first and it names the far end. Uncorrected, the VPN's gateway
/// would be reported as this machine, and the tunnel's real address would be
/// missing as a source.
///
/// The refusal is of a read that would end the process; see [`asked_safely`].
/// `netdev` returns an empty table on failure, with no usable error number. The
/// one known cause is a process with no descriptor free, so a descriptor is
/// opened and closed and its `EMFILE` is the error given. Only a table empty with
/// a descriptor to spare is reported as merely empty.
pub(crate) fn host_table() -> io::Result<Vec<netdev::Interface>> {
    let mut table = asked_safely(netdev::get_interfaces)?;
    if table.is_empty() {
        descriptor_free()?;
        return Err(io::Error::other(
            "the interface table came back empty, which no host's is",
        ));
    }
    let peers = point_to_point_peers();
    if !peers.is_empty() {
        for interface in &mut table {
            own_addresses_for_peers(interface, &peers);
        }
    }
    Ok(table)
}

/// Runs `read` where it cannot end the process, or refuses it.
///
/// On macOS `netdev` reads each interface's kind and display name from
/// SystemConfiguration, which opens a descriptor the first time a process asks.
/// With none free, the framework dereferences what it failed to open and the
/// process segfaults. Once loaded, it needs no descriptor again.
///
/// So until one read has succeeded, a read is let through only after a
/// descriptor has been opened and closed, and is refused with the system's error
/// otherwise. Reads are serialised while this holds, so two cannot count on the
/// same free descriptor. Another thread can still take it between the check and
/// the read; the engine's own connections never take a table's last few (see
/// [`OPENED_WHILE_RUNNING`](crate::system::descriptors::OPENED_WHILE_RUNNING)).
#[cfg(target_os = "macos")]
fn asked_safely<T>(read: impl FnOnce() -> T) -> io::Result<T> {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    static LOADED: AtomicBool = AtomicBool::new(false);
    static FIRST: Mutex<()> = Mutex::new(());

    if LOADED.load(Ordering::Acquire) {
        return Ok(read());
    }
    let _first = FIRST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !LOADED.load(Ordering::Acquire) {
        descriptor_free()?;
    }
    let answer = read();
    LOADED.store(true, Ordering::Release);
    Ok(answer)
}

/// Opens a descriptor and closes it again, or gives the system's reason it
/// could not: `EMFILE` in a process with none free.
fn descriptor_free() -> io::Result<()> {
    #[cfg(unix)]
    drop(std::fs::File::open("/dev/null")?);
    #[cfg(windows)]
    drop(std::fs::File::open("NUL")?);
    Ok(())
}

/// Elsewhere the read fails without harm where it has no descriptor, and the
/// empty table it returns is refused by [`host_table`].
#[cfg(not(target_os = "macos"))]
fn asked_safely<T>(read: impl FnOnce() -> T) -> io::Result<T> {
    Ok(read())
}

/// A point-to-point link's peer, paired with the address this host holds on
/// that link.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerAddress {
    /// The link's name, which is what `netdev` and the C library both key it by.
    link: String,
    /// The far end, as `IFA_ADDRESS` names it.
    peer: IpAddr,
    /// This host's own address on the link, `IFA_LOCAL`.
    local: IpAddr,
}

/// Puts this host's own address wherever `interface` lists a peer in its place.
///
/// Each prefix is kept: the kernel reports one prefix for the pair.
fn own_addresses_for_peers(interface: &mut netdev::Interface, peers: &[PeerAddress]) {
    let local_for = |peer: IpAddr| {
        peers
            .iter()
            .find(|pair| pair.link == interface.name && pair.peer == peer)
            .map(|pair| pair.local)
    };

    let replaced_v4: Vec<_> = interface
        .ipv4
        .iter()
        .map(|net| match local_for(IpAddr::V4(net.addr())) {
            Some(IpAddr::V4(local)) => {
                netdev::ipnet::Ipv4Net::new(local, net.prefix_len()).unwrap_or(*net)
            }
            _ => *net,
        })
        .collect();
    let replaced_v6: Vec<_> = interface
        .ipv6
        .iter()
        .map(|net| match local_for(IpAddr::V6(net.addr())) {
            Some(IpAddr::V6(local)) => {
                netdev::ipnet::Ipv6Net::new(local, net.prefix_len()).unwrap_or(*net)
            }
            _ => *net,
        })
        .collect();
    interface.ipv4 = replaced_v4;
    interface.ipv6 = replaced_v6;
}

/// Every point-to-point link's peer and the address this host holds opposite
/// it, from the C library's `getifaddrs`.
///
/// On Linux glibc and musl both fill `getifaddrs` the right way round:
/// `IFA_LOCAL` as the interface's address and `IFA_ADDRESS` as its destination.
/// Only pairs where the two differ are returned, which is the set `netdev` reads
/// wrong.
#[cfg(target_os = "linux")]
fn point_to_point_peers() -> Vec<PeerAddress> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` writes a list head into the pointer it is handed
    // and returns non-zero without touching it on failure.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Vec::new();
    }

    let mut pairs = Vec::new();
    let mut entry = head;
    while !entry.is_null() {
        // SAFETY: `entry` is a node of the list `getifaddrs` returned, which
        // stays valid until `freeifaddrs` below.
        let node = unsafe { &*entry };
        entry = node.ifa_next;

        if node.ifa_flags & libc::IFF_POINTOPOINT as u32 == 0 {
            continue;
        }
        // SAFETY: both are null or point at a socket address whose family says
        // how much of it may be read; `ip_of` reads no further than that.
        let (Some(local), Some(peer)) = (unsafe { ip_of(node.ifa_addr) }, unsafe {
            ip_of(node.ifa_ifu)
        }) else {
            continue;
        };
        if local == peer {
            continue;
        }
        // SAFETY: `ifa_name` is a NUL-terminated string owned by the list.
        let link = unsafe { std::ffi::CStr::from_ptr(node.ifa_name) }
            .to_string_lossy()
            .into_owned();
        pairs.push(PeerAddress { link, peer, local });
    }

    // SAFETY: `head` came from `getifaddrs` and is freed exactly once, after
    // the last read of any node.
    unsafe { libc::freeifaddrs(head) };
    pairs
}

/// Elsewhere `netdev` reads `getifaddrs` itself, and there is nothing to put
/// right.
#[cfg(not(target_os = "linux"))]
fn point_to_point_peers() -> Vec<PeerAddress> {
    Vec::new()
}

/// The address in a socket address of either IP family.
///
/// # Safety
///
/// `address` must be null or point at a socket address at least as large as
/// its family's structure.
#[cfg(target_os = "linux")]
unsafe fn ip_of(address: *const libc::sockaddr) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    // SAFETY: non-null, and every socket address starts with its family.
    match i32::from(unsafe { (*address).sa_family }) {
        libc::AF_INET => {
            // SAFETY: the family says this is a `sockaddr_in`.
            let v4 = unsafe { &*address.cast::<libc::sockaddr_in>() };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr))))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says this is a `sockaddr_in6`.
            let v6 = unsafe { &*address.cast::<libc::sockaddr_in6>() };
            Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

impl Link {
    /// Reads one interface out of the host's table.
    ///
    /// The crate's whole dependency on how that table is read; every fact is
    /// copied out.
    ///
    /// Reads `oper_state` because Windows publishes an operational state
    /// (through `GetAdaptersAddresses`) and no flags word.
    pub(crate) fn from_netdev(interface: netdev::Interface) -> Self {
        use netdev::interface::types::InterfaceType;

        let kind = if interface.is_loopback() {
            LinkKind::Loopback
        } else if interface.if_type == InterfaceType::Wireless80211 {
            LinkKind::Wireless
        } else if interface.is_physical() {
            LinkKind::Wired
        } else {
            LinkKind::Virtual
        };

        let addresses = interface
            .ipv4
            .iter()
            .map(|net| LinkAddress::new(IpAddr::V4(net.addr()), net.prefix_len()))
            .chain(
                interface
                    .ipv6
                    .iter()
                    .map(|net| LinkAddress::new(IpAddr::V6(net.addr()), net.prefix_len())),
            )
            .collect();

        Self {
            mac: interface.mac_addr.map(|mac| MacAddr::from(mac.octets())),
            addresses,
            kind,
            up: carries_traffic(
                interface.is_up(),
                interface.oper_state(),
                interface.is_running(),
            ),
            addressing: Addressing::of(interface.is_broadcast(), interface.is_point_to_point()),
            physical: interface.is_physical(),
            default_route: interface.default,
            gateway: interface
                .gateway
                .as_ref()
                .is_some_and(|g| !g.ipv4.is_empty() || !g.ipv6.is_empty()),
            // Kept only where it says something the name does not.
            friendly_name: interface
                .friendly_name
                .filter(|friendly| !friendly.is_empty() && *friendly != interface.name),
            name: interface.name,
            index: interface.index,
        }
    }
}

/// Whether a link-layer probe can be put on this link.
///
/// The free-function form of [`Link::carries_frames`].
pub fn is_layer_2_capable(link: &Link) -> bool {
    link.carries_frames()
}

/// Whether every target in `ips` is on the same segment as `link`.
///
/// Every range, wholly, in both families. A range straddling the edge of the
/// link's network is not on-link, since a sweep would wait out a timeout for
/// every address past the boundary.
///
/// An empty set is on-link.
pub fn is_on_link(link: &Link, ips: &IpSet) -> bool {
    let within = |start: IpAddr, end: IpAddr| {
        link.addresses()
            .iter()
            .any(|held| held.contains(&start) && held.contains(&end))
    };

    ips.v4()
        .iter()
        .all(|range| within(range.start_addr().into(), range.end_addr().into()))
        && ips
            .v6()
            .iter()
            .all(|range| within(range.start_addr().into(), range.end_addr().into()))
}

/// Whether an interface with this administrative state, operational state and
/// running flag can carry a probe or a reply.
///
/// Both states must be up: a cable can be plugged into an interface nobody has
/// brought up, and an interface can be administratively up with nothing on the
/// other end.
///
/// **An operational state of `unknown` is read from the running flag.** Drivers
/// that keep no operational state report `unknown`, and the kernel documentation
/// says to treat such an interface as usable. Linux reports it for every tun,
/// WireGuard and ppp device, so read as down, a VPN tunnel would be left out of
/// source selection and capture. Such a driver sets the running flag once
/// something is attached, so a tunnel nobody has opened stays out.
fn carries_traffic(
    admin_up: bool,
    oper: netdev::interface::state::OperState,
    running: bool,
) -> bool {
    use netdev::interface::state::OperState;

    admin_up
        && match oper {
            OperState::Up => true,
            OperState::Unknown => running,
            OperState::NotPresent
            | OperState::Down
            | OperState::LowerLayerDown
            | OperState::Testing
            | OperState::Dormant => false,
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
    use crate::model::ip::range::IpRange;

    /// A point-to-point link as Linux reports it through `netdev`: the peer
    /// where this host's own address belongs, in both families, beside an
    /// address that is this host's own and must be left alone.
    fn misread_ppp() -> netdev::Interface {
        let mut interface = netdev::Interface::dummy();
        interface.name = "ppp0".to_string();
        interface.ipv4 = vec![
            "203.0.113.2/32".parse().expect("a network"),
            "198.51.100.9/24".parse().expect("a network"),
        ];
        interface.ipv6 = vec!["2001:db8::2/128".parse().expect("a network")];
        interface
    }

    fn peer(link: &str, peer: &str, local: &str) -> PeerAddress {
        PeerAddress {
            link: link.to_string(),
            peer: peer.parse().expect("an address"),
            local: local.parse().expect("an address"),
        }
    }

    /// The link holds this host's address, at the prefix the pair was given,
    /// and the peer is no longer claimed as this host's own.
    #[test]
    fn a_point_to_point_link_holds_its_own_address_and_not_its_peers() {
        let mut interface = misread_ppp();
        own_addresses_for_peers(
            &mut interface,
            &[
                peer("ppp0", "203.0.113.2", "203.0.113.1"),
                peer("ppp0", "2001:db8::2", "2001:db8::1"),
            ],
        );

        let held: Vec<String> = Link::from_netdev(interface)
            .addresses()
            .iter()
            .map(|held| format!("{}/{}", held.address(), held.prefix()))
            .collect();
        assert_eq!(
            held,
            ["203.0.113.1/32", "198.51.100.9/24", "2001:db8::1/128"]
        );
    }

    /// A pair belongs to its own link. Another link that happens to list the
    /// same address is not rewritten by it.
    #[test]
    fn a_peer_is_corrected_on_its_own_link_only() {
        let mut interface = misread_ppp();
        interface.name = "eth0".to_string();
        own_addresses_for_peers(
            &mut interface,
            &[peer("ppp0", "203.0.113.2", "203.0.113.1")],
        );

        assert_eq!(
            interface.ipv4[0],
            "203.0.113.2/32".parse::<netdev::ipnet::Ipv4Net>().unwrap()
        );
    }

    fn link(name: &str, kind: LinkKind) -> Link {
        Link::new(name, 1)
            .with_kind(kind)
            .with_mac(MacAddr::new(1, 2, 3, 4, 5, 6))
    }
    fn holding(name: &str, address: &str, prefix: u8) -> Link {
        link(name, LinkKind::Wired).with_addresses(vec![LinkAddress::new(
            address.parse::<IpAddr>().expect("an address"),
            prefix,
        )])
    }
    fn targets(written: &str) -> IpSet {
        let mut set = IpSet::new();
        set.insert_range(written.parse::<IpRange>().expect("a range"));
        set
    }
    /// A range wholly inside the link's network is on it; one that leaves it,
    /// even halfway, is not.
    #[test]
    fn a_range_is_on_link_only_if_all_of_it_is() {
        let link = holding("en0", "198.51.100.7", 25);

        assert!(is_on_link(&link, &targets("198.51.100.1-198.51.100.50")));
        assert!(is_on_link(&link, &targets("198.51.100.0/25")), "the whole");
        assert!(
            !is_on_link(&link, &targets("198.51.100.130-198.51.100.135")),
            "past"
        );
        assert!(
            !is_on_link(&link, &targets("198.51.100.100-198.51.100.140")),
            "a range that starts on the link and leaves it is not on the link"
        );
    }
    /// A link with no address of its own puts nothing on it.
    #[test]
    fn a_link_with_no_addressing_has_nothing_on_it() {
        let bare = link("en0", LinkKind::Wired);

        assert!(!is_on_link(&bare, &targets("198.51.100.1-198.51.100.50")));
    }
    /// An IPv6 address on the link does not make an IPv4 range local.
    ///
    /// A v6 prefix that happens to contain the same bits must not be read as
    /// covering a v4 range.
    #[test]
    fn an_ipv6_prefix_does_not_answer_for_an_ipv4_range() {
        let v6_only = link("en0", LinkKind::Wired).with_addresses(vec![LinkAddress::new(
            "fe80::1".parse::<IpAddr>().expect("an address"),
            64,
        )]);

        assert!(!is_on_link(
            &v6_only,
            &targets("198.51.100.1-198.51.100.50")
        ));
    }
    use super::*;

    /// A tunnel is a link: Linux reports `unknown` for tun and WireGuard
    /// devices, and one with something attached to it carries traffic.
    #[test]
    fn an_interface_of_unknown_state_carries_traffic_while_it_runs() {
        use netdev::interface::state::OperState;

        assert!(carries_traffic(true, OperState::Up, true));
        assert!(
            carries_traffic(true, OperState::Unknown, true),
            "a tunnel in use"
        );
        assert!(
            !carries_traffic(true, OperState::Unknown, false),
            "a tunnel nothing is attached to"
        );
        assert!(
            !carries_traffic(false, OperState::Unknown, true),
            "brought down"
        );
        for down in [
            OperState::Down,
            OperState::LowerLayerDown,
            OperState::Dormant,
            OperState::Testing,
            OperState::NotPresent,
        ] {
            assert!(!carries_traffic(true, down, true), "{down:?}");
        }
    }

    fn v4(address: &str, prefix: u8) -> LinkAddress {
        LinkAddress::new(IpAddr::V4(address.parse().expect("an address")), prefix)
    }

    /// The network is derived from the prefix, and covers both ends.
    ///
    /// Both ends, because this is what the *link* carries; an on-link test
    /// that excluded them would place a host at `198.51.100.127` elsewhere.
    #[test]
    fn a_network_covers_every_address_its_prefix_names() {
        let held = v4("198.51.100.7", 25);
        let network = held.network();

        assert_eq!(
            network.start_addr(),
            "198.51.100.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            network.end_addr(),
            "198.51.100.127".parse::<IpAddr>().unwrap()
        );
        assert!(
            held.contains(&"198.51.100.0".parse().unwrap()),
            "the network"
        );
        assert!(
            held.contains(&"198.51.100.127".parse().unwrap()),
            "the broadcast"
        );
        assert!(
            !held.contains(&"198.51.100.128".parse().unwrap()),
            "the next one"
        );
    }

    /// A `/32` is one address, and a `/0` is all of them. Both are real: a
    /// point-to-point link routinely holds the first.
    #[test]
    fn the_ends_of_the_prefix_range_are_both_networks() {
        let single = v4("192.0.2.1", 32);
        assert_eq!(single.network().len(), 1);
        assert!(single.contains(&"192.0.2.1".parse().unwrap()));

        let everything = v4("192.0.2.1", 0);
        assert!(everything.contains(&"8.8.8.8".parse().unwrap()));
    }

    /// A prefix past the end of its family is clamped, which keeps the address
    /// and makes `network` total.
    #[test]
    fn a_prefix_past_its_family_is_clamped_and_the_address_survives() {
        let absurd = v4("198.51.100.7", 200);

        assert_eq!(absurd.prefix(), 32, "clamped to what IPv4 has");
        assert_eq!(absurd.address(), "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(absurd.network().len(), 1);

        let v6 = LinkAddress::new(IpAddr::V6("fe80::1".parse().unwrap()), 255);
        assert_eq!(v6.prefix(), 128, "and to what IPv6 has");
    }

    /// The three things a link-layer probe needs, and each one's absence.
    #[test]
    fn a_link_carries_frames_only_with_a_segment_and_an_address_to_send_from() {
        let mac = MacAddr::new(2, 0, 0, 0, 0, 1);
        let wired = Link::new("en0", 1).with_kind(LinkKind::Wired).with_mac(mac);
        assert!(wired.carries_frames());

        assert!(
            !Link::new("en0", 1)
                .with_kind(LinkKind::Wired)
                .carries_frames(),
            "no hardware address to send from"
        );
        assert!(
            !Link::new("lo0", 1)
                .with_kind(LinkKind::Loopback)
                .with_mac(mac)
                .carries_frames(),
            "nobody else on it"
        );
        assert!(
            !Link::new("utun0", 1)
                .with_kind(LinkKind::Wired)
                .with_mac(mac)
                .with_addressing(Addressing::PointToPoint)
                .carries_frames(),
            "a peer rather than a segment"
        );
    }

    /// The families are kept apart.
    #[test]
    fn a_links_addresses_are_readable_by_family() {
        let link = Link::new("en0", 1).with_addresses(vec![
            v4("198.51.100.7", 24),
            LinkAddress::new(IpAddr::V6("fe80::1".parse().unwrap()), 64),
            v4("192.0.2.5", 25),
        ]);

        let v4s: Vec<_> = link.ipv4().collect();
        assert_eq!(v4s.len(), 2);
        assert_eq!(v4s[0], ("198.51.100.7".parse().unwrap(), 24));
        assert_eq!(v4s[1], ("192.0.2.5".parse().unwrap(), 25));

        let v6s: Vec<_> = link.ipv6().collect();
        assert_eq!(v6s.len(), 1);
        assert_eq!(v6s[0], ("fe80::1".parse().unwrap(), 64));
    }

    /// A link names its own zone.
    #[test]
    fn a_link_is_its_own_zone() {
        let zone = Link::new("en0", 7).zone();

        assert_eq!(zone.name(), "en0");
        assert_eq!(zone.index(), Some(7));
    }

    /// A message about an interface names it the way the system settings do,
    /// falling back to the system name when the friendly name is empty or
    /// repeated.
    #[test]
    fn an_interface_is_called_what_a_person_calls_it() {
        let guid = "{4D36E972-E325-11CE-BFC1-08002BE10318}";
        let read = |friendly: Option<&str>| {
            let mut interface = netdev::Interface::dummy();
            interface.name = guid.to_owned();
            interface.friendly_name = friendly.map(str::to_owned);
            Link::from_netdev(interface)
        };

        assert_eq!(
            read(Some("vEthernet (WSL)")).display_name(),
            "vEthernet (WSL)"
        );
        assert_eq!(read(None).display_name(), guid);
        assert_eq!(read(Some("")).display_name(), guid);
    }

    /// A process with no descriptor free is told the interface table cannot
    /// be read, with the system's `EMFILE`: no segfault on macOS, no empty
    /// table elsewhere.
    #[cfg(unix)]
    #[test]
    fn a_first_read_in_a_full_table_is_refused_rather_than_ending_the_process() {
        use crate::system::descriptors::testing::{exhaust, in_a_process_of_its_own};

        if !in_a_process_of_its_own(
            module_path!(),
            "a_first_read_in_a_full_table_is_refused_rather_than_ending_the_process",
        ) {
            return;
        }
        let held = exhaust(64);
        let read = interfaces();
        drop(held);

        let refused = read.expect_err("a table read with no descriptor free");
        assert_eq!(refused.raw_os_error(), Some(libc::EMFILE), "{refused}");
        assert!(
            !interfaces()
                .expect("the table, once there is room")
                .is_empty(),
            "every host has a loopback interface"
        );
    }

    /// Once a process has read its interface table, it reads it whole again
    /// with no descriptor free, so a scan whose connections fill the table
    /// still knows which addresses are on its own segments.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_table_read_once_is_read_again_with_no_descriptor_free() {
        use crate::system::descriptors::testing::{exhaust, in_a_process_of_its_own};

        if !in_a_process_of_its_own(
            module_path!(),
            "a_table_read_once_is_read_again_with_no_descriptor_free",
        ) {
            return;
        }
        let names = |links: Vec<Link>| {
            let mut names: Vec<String> = links.iter().map(|l| l.name().to_owned()).collect();
            names.sort();
            names
        };
        let before = names(interfaces().expect("the table, with room to read it"));
        let held = exhaust(64);
        let again = interfaces();
        drop(held);

        assert_eq!(names(again.expect("a second read in a full table")), before);
    }

    /// Whatever the host says, read through the one function that reads it.
    ///
    /// Asserts properties of `from_netdev` for every interface present: a
    /// `Loopback` link does not claim to carry frames, and no address keeps a
    /// prefix its family cannot hold.
    #[test]
    fn every_interface_this_machine_has_reads_back_consistently() {
        for link in interfaces().expect("this machine's interfaces") {
            assert!(!link.name().is_empty(), "an interface with no name");

            if link.is_loopback() {
                assert!(
                    !link.carries_frames(),
                    "{} is loopback and claims a segment",
                    link.name()
                );
            }

            for held in link.addresses() {
                let ceiling = if held.address().is_ipv4() { 32 } else { 128 };
                assert!(
                    held.prefix() <= ceiling,
                    "{} holds {} with a /{} its family cannot express",
                    link.name(),
                    held.address(),
                    held.prefix()
                );
                assert!(
                    held.contains(&held.address()),
                    "{} holds {} on a network that excludes it",
                    link.name(),
                    held.address()
                );
            }
        }
    }
}
