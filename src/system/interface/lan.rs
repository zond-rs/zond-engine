// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::info;
use crate::system::interface::{Link, LinkAddress};
use std::net::Ipv6Addr;

/// Errors arising from network validation constraints during LAN interface selection.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ViabilityError {
    /// The interface is operationally down.
    IsDown,
    /// The interface was filtered out as "not physical" by the provided logic.
    NotPhysical,
    /// The interface does not have a MAC address.
    NoMacAddress,
    /// The interface does not support broadcast (required for ARP).
    NotBroadcast,
    /// The interface is a point-to-point link (e.g., a VPN).
    IsPointToPoint,
    /// The interface has no IPv4 address (for ARP) AND no IPv6 Link-Local (for NDP).
    NoValidLanIp,
}

/// The link a LAN scan runs on: the interface itself and how it is addressed in
/// both families.
///
/// The selection picks a *link*, and until this existed it returned an
/// `Ipv4Network` — so everything the link knew about itself was thrown away at
/// the moment it was chosen. The interface identity is what
/// [`Zone`](crate::model::ip::scoped::Zone) needs to make a link-local
/// address usable, and the IPv6 prefixes are what say which addresses are on
/// this segment at all.
///
/// `ipv4` is optional because a viable LAN link need not have one. An interface
/// carrying only a link-local IPv6 address is perfectly scannable — the
/// all-nodes echo and neighbour discovery both work — and treating that as "no
/// network found" is what the shape of the old return value forced.
#[derive(Debug, Clone)]
pub struct LanLink {
    pub link: Link,
    /// The private IPv4 network to sweep, when the link has one.
    pub ipv4: Option<LinkAddress>,
    /// Every IPv6 network the link is addressed in, link-local included.
    pub ipv6: Vec<LinkAddress>,
}

impl LanLink {
    /// The link-local address probes leave from, if it has one.
    pub fn link_local(&self) -> Option<Ipv6Addr> {
        self.ipv6
            .iter()
            .filter_map(|held| match held.address() {
                std::net::IpAddr::V6(v6) => Some(v6),
                std::net::IpAddr::V4(_) => None,
            })
            .find(Ipv6Addr::is_unicast_link_local)
    }
}

/// Identifies the best local area network (LAN) connected to the current host context.
///
/// Under the hood, this iterates over `pnet::datalink::interfaces()` directly.
pub fn get_lan_link() -> anyhow::Result<Option<LanLink>> {
    get_lan_link_with(crate::system::interface::interfaces())
}

/// The IPv4 half of [`get_lan_link`], for callers that only sweep IPv4.
///
/// Kept because it is the engine's published surface and a front end builds
/// against it; new work inside the engine wants the link, since half of what a
/// LAN scan now does is IPv6.
pub fn get_lan_network() -> anyhow::Result<Option<LinkAddress>> {
    Ok(get_lan_link()?.and_then(|link| link.ipv4))
}

/// Core LAN selection logic, decoupled from OS interface dependencies for testing.
///
/// `is_physical` is injected for the same reason
/// [`is_viable_lan_interface`] takes it: on a real host it asks the platform
/// which interfaces are hardware, and a hand-built interface is not one — so
/// without the seam this function can only be exercised against whatever the
/// machine running the tests happens to have plugged in.
pub(crate) fn get_lan_link_with(interfaces: Vec<Link>) -> anyhow::Result<Option<LanLink>> {
    let interfaces_str: &str = match interfaces.len() {
        1 => "interface",
        _ => "interfaces",
    };

    info!(
        verbosity = 1,
        "identified {} network {}, picking the best one",
        interfaces.len(),
        interfaces_str
    );

    let viable: Vec<Link> = interfaces
        .into_iter()
        .filter(|link| is_viable_lan_interface(link).is_ok())
        .collect();

    let Some(link) = select_best_lan_interface(viable) else {
        anyhow::bail!("No interfaces available for LAN discovery");
    };
    info!(
        verbosity = 1,
        "performing LAN scan on interface {}",
        link.name()
    );

    let ipv4 = link
        .addresses()
        .iter()
        .copied()
        .find(|held| matches!(held.address(), std::net::IpAddr::V4(v4) if v4.is_private()));
    let ipv6 = link
        .addresses()
        .iter()
        .copied()
        .filter(|held| held.address().is_ipv6())
        .collect();

    Ok(Some(LanLink { link, ipv4, ipv6 }))
}

fn is_viable_lan_interface(link: &Link) -> Result<(), ViabilityError> {
    if !link.is_up() {
        return Err(ViabilityError::IsDown);
    }
    if !link.is_physical() || link.is_loopback() {
        return Err(ViabilityError::NotPhysical);
    }
    if link.mac().is_none() {
        return Err(ViabilityError::NoMacAddress);
    }
    if !link.is_broadcast() {
        return Err(ViabilityError::NotBroadcast);
    }
    if link.is_point_to_point() {
        return Err(ViabilityError::IsPointToPoint);
    }

    let has_valid_ip = link.addresses().iter().any(|held| match held.address() {
        std::net::IpAddr::V4(v4) => v4.is_private(),
        std::net::IpAddr::V6(v6) => v6.is_unicast_link_local(),
    });
    if !has_valid_ip {
        return Err(ViabilityError::NoValidLanIp);
    }

    Ok(())
}

/// The best of the viable links: a wired one where there is one, and otherwise
/// whichever came first.
///
/// **The `is_physical` seam is gone.** It existed because the old interface type
/// could not say whether it was hardware — the answer came from a per-platform
/// function that shelled out on macOS — so a test had to inject one or be at the
/// mercy of whatever the machine had plugged in. A `Link` carries the answer, so
/// a test builds a link that is not physical and the seam has nothing left to do.
fn select_best_lan_interface(links: Vec<Link>) -> Option<Link> {
    links
        .iter()
        .find(|link| link.is_wired())
        .or_else(|| links.first())
        .cloned()
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
    use crate::system::interface::LinkKind;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn mock_interface(
        up: bool,
        mac: bool,
        broadcast: bool,
        p2p: bool,
        loopback: bool,
        ip: bool,
    ) -> Link {
        let mut link = Link::new("test0", 0)
            .up(up)
            .addressing(broadcast, p2p)
            // Every case this builds is a real interface unless it says
            // otherwise; the physical/virtual axis is exercised by `loopback`.
            .physical(!loopback)
            .of_kind(if loopback {
                LinkKind::Loopback
            } else {
                LinkKind::Wired
            });

        if mac {
            link = link.with_mac(crate::model::mac::MacAddr::new(1, 2, 3, 4, 5, 6));
        }
        if ip {
            link = link.with_addresses(vec![LinkAddress::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                24,
            )]);
        }

        link
    }

    #[test]
    fn a_link_with_only_ipv6_is_still_a_lan_link() {
        let intf = mock_interface(true, true, true, false, false, false).with_addresses(vec![
            LinkAddress::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 64),
        ]);

        assert_eq!(is_viable_lan_interface(&intf), Ok(()));

        let link = get_lan_link_with(vec![intf])
            .expect("selection succeeds")
            .expect("a viable link is selected");

        assert!(
            link.ipv4.is_none(),
            "there is no private IPv4 network here, and saying so is the point"
        );
        assert_eq!(
            link.link_local(),
            Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            "the address probes would leave from has to survive selection"
        );
        assert_eq!(link.link.name(), "test0");
    }

    /// The link carries both families, so a dual-stack segment does not have to
    /// choose which half of itself to be described by.
    #[test]
    fn a_dual_stack_link_carries_both_families() {
        let mut held = mock_interface(true, true, true, false, false, true)
            .addresses()
            .to_vec();
        held.push(LinkAddress::new(
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            64,
        ));
        let intf = mock_interface(true, true, true, false, false, true).with_addresses(held);

        let link = get_lan_link_with(vec![intf])
            .expect("selection succeeds")
            .expect("a viable link is selected");

        assert_eq!(
            link.ipv4.map(|held| held.address()),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
        );
        assert_eq!(link.ipv6.len(), 1);
    }

    /// The published IPv4-only entry point keeps answering exactly as it did,
    /// since a front end outside this repo builds against it.
    #[test]
    fn the_ipv4_view_of_a_link_is_unchanged() {
        let intf = mock_interface(true, true, true, false, false, true);

        let link = get_lan_link_with(vec![intf])
            .expect("selection succeeds")
            .expect("a viable link is selected");

        let held = link.ipv4.expect("the link has a private IPv4 network");
        assert_eq!(held.address(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(held.prefix(), 24);
    }

    #[test]
    fn is_viable_down() {
        let intf = mock_interface(false, true, true, false, false, true);
        assert_eq!(is_viable_lan_interface(&intf), Err(ViabilityError::IsDown));
    }

    /// A virtual adapter is not a LAN, however well-addressed it is.
    ///
    /// It says so itself now. This used to inject an `is_physical` that answered
    /// `false`, because the interface type could not carry the answer and the
    /// real one shelled out to `networksetup` on macOS. The link knows, so the
    /// test states the fact rather than stubbing the function that found it.
    #[test]
    fn is_viable_not_physical() {
        let intf = mock_interface(true, true, true, false, false, true).physical(false);
        assert_eq!(
            is_viable_lan_interface(&intf),
            Err(ViabilityError::NotPhysical)
        );
    }

    #[test]
    fn is_viable_no_mac() {
        let intf = mock_interface(true, false, true, false, false, true);
        assert_eq!(
            is_viable_lan_interface(&intf),
            Err(ViabilityError::NoMacAddress)
        );
    }

    #[test]
    fn is_viable_success() {
        let intf = mock_interface(true, true, true, false, false, true);
        assert_eq!(is_viable_lan_interface(&intf), Ok(()));
    }
}
