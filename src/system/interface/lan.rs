// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::os::{is_physical, is_wireless};
use crate::info;
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
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
/// [`Zone`](crate::core::models::ip::scoped::Zone) needs to make a link-local
/// address usable, and the IPv6 prefixes are what say which addresses are on
/// this segment at all.
///
/// `ipv4` is optional because a viable LAN link need not have one. An interface
/// carrying only a link-local IPv6 address is perfectly scannable — the
/// all-nodes echo and neighbour discovery both work — and treating that as "no
/// network found" is what the shape of the old return value forced.
#[derive(Debug, Clone)]
pub struct LanLink {
    pub interface: NetworkInterface,
    /// The private IPv4 network to sweep, when the link has one.
    pub ipv4: Option<Ipv4Network>,
    /// Every IPv6 network the link is addressed in, link-local included.
    pub ipv6: Vec<Ipv6Network>,
}

impl LanLink {
    /// The link-local address probes leave from, if it has one.
    pub fn link_local(&self) -> Option<Ipv6Addr> {
        self.ipv6
            .iter()
            .map(|net| net.ip())
            .find(Ipv6Addr::is_unicast_link_local)
    }
}

/// Identifies the best local area network (LAN) connected to the current host context.
///
/// Under the hood, this iterates over `pnet::datalink::interfaces()` directly.
pub fn get_lan_link() -> anyhow::Result<Option<LanLink>> {
    let interfaces: Vec<NetworkInterface> = pnet::datalink::interfaces();
    get_lan_link_with(interfaces, is_physical)
}

/// The IPv4 half of [`get_lan_link`], for callers that only sweep IPv4.
///
/// Kept because it is the engine's published surface and a front end builds
/// against it; new work inside the engine wants the link, since half of what a
/// LAN scan now does is IPv6.
pub fn get_lan_network() -> anyhow::Result<Option<Ipv4Network>> {
    Ok(get_lan_link()?.and_then(|link| link.ipv4))
}

/// Core LAN selection logic, decoupled from OS interface dependencies for testing.
///
/// `is_physical` is injected for the same reason
/// [`is_viable_lan_interface`] takes it: on a real host it asks the platform
/// which interfaces are hardware, and a hand-built interface is not one — so
/// without the seam this function can only be exercised against whatever the
/// machine running the tests happens to have plugged in.
pub(crate) fn get_lan_link_with(
    interfaces: Vec<NetworkInterface>,
    is_physical: impl Fn(&NetworkInterface) -> bool + Copy,
) -> anyhow::Result<Option<LanLink>> {
    let interfaces_str: &str = match interfaces.len() {
        1 => "interface",
        _ => "interfaces",
    };

    info!(
        verbosity = 1,
        "Identified {} network {}, picking the best one...",
        interfaces.len(),
        interfaces_str
    );

    let interfaces: Vec<NetworkInterface> = interfaces
        .into_iter()
        .filter_map(
            |interface| match is_viable_lan_interface(&interface, is_physical) {
                Ok(()) => Some(interface),
                Err(_) => None,
            },
        )
        .collect();

    let interface: NetworkInterface =
        if let Some(interface) = select_best_lan_interface(interfaces, is_wired) {
            info!(
                verbosity = 1,
                "Performing LAN scan on interface {}", interface.name
            );
            interface
        } else {
            anyhow::bail!("No interfaces available for LAN discovery");
        };
    let ipv4: Option<Ipv4Network> = interface.ips.iter().find_map(|net| match net {
        IpNetwork::V4(v4) if v4.ip().is_private() => Some(*v4),
        _ => None,
    });
    let ipv6: Vec<Ipv6Network> = interface
        .ips
        .iter()
        .filter_map(|net| match net {
            IpNetwork::V6(v6) => Some(*v6),
            IpNetwork::V4(_) => None,
        })
        .collect();

    Ok(Some(LanLink {
        interface,
        ipv4,
        ipv6,
    }))
}

fn is_viable_lan_interface(
    interface: &NetworkInterface,
    is_physical: impl Fn(&NetworkInterface) -> bool,
) -> Result<(), ViabilityError> {
    if !interface.is_up() {
        return Err(ViabilityError::IsDown);
    }
    if !is_physical(interface) {
        return Err(ViabilityError::NotPhysical);
    }
    if interface.is_loopback() {
        return Err(ViabilityError::NotPhysical);
    }
    if interface.mac.is_none() {
        return Err(ViabilityError::NoMacAddress);
    }
    if !interface.is_broadcast() {
        return Err(ViabilityError::NotBroadcast);
    }
    if interface.is_point_to_point() {
        return Err(ViabilityError::IsPointToPoint);
    }
    let has_valid_ip = interface.ips.iter().any(|net| match net {
        IpNetwork::V4(ipv4) => ipv4.ip().is_private(),
        IpNetwork::V6(ipv6) => ipv6.ip().is_unicast_link_local(),
    });
    if !has_valid_ip {
        return Err(ViabilityError::NoValidLanIp);
    }

    Ok(())
}

fn select_best_lan_interface(
    interfaces: Vec<NetworkInterface>,
    is_wired: impl Fn(&NetworkInterface) -> bool,
) -> Option<NetworkInterface> {
    match interfaces.len() {
        0 => None,
        1 => Some(interfaces[0].clone()),
        _ => interfaces
            .iter()
            .find(|&interface| is_wired(interface))
            .cloned()
            .or(Some(interfaces[0].clone())),
    }
}

/// Identifies if the specified interface is wired directly to the machine locally.
///
/// Considers virtual and remote connections as non-wired.
pub fn is_wired(interface: &NetworkInterface) -> bool {
    is_physical(interface) && !is_wireless(interface)
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
    use pnet::datalink::MacAddr;
    use pnet::ipnetwork::IpNetwork;
    use std::net::Ipv4Addr;

    fn mock_interface(
        up: bool,
        mac: bool,
        broadcast: bool,
        p2p: bool,
        loopback: bool,
        ip: bool,
    ) -> NetworkInterface {
        NetworkInterface {
            name: "test0".to_string(),
            description: "".to_string(),
            index: 0,
            mac: if mac {
                Some(MacAddr::new(1, 2, 3, 4, 5, 6))
            } else {
                None
            },
            ips: if ip {
                vec![IpNetwork::V4(
                    Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 100), 24).unwrap(),
                )]
            } else {
                vec![]
            },
            flags: {
                let mut flags = 0;
                if up {
                    flags |= 1;
                }
                if broadcast {
                    flags |= 2;
                }
                if p2p {
                    flags |= 16;
                }
                if loopback {
                    flags |= 8;
                } // roughly matching bitmasks
                flags
            },
        }
    }

    /// A link addressed only in IPv6 is viable, and the selection has to be
    /// able to say so.
    ///
    /// These two agreed on which interfaces were usable and disagreed about
    /// what a usable one produced: `is_viable_lan_interface` accepts an
    /// interface carrying only a link-local IPv6 address, and the selection
    /// then searched it for a private IPv4 network and returned `None` — which
    /// `resolve_lan` reported as "No active network interface found", after
    /// logging the name of the interface it had just chosen. The same happened
    /// on any segment whose IPv4 is not RFC1918.
    #[test]
    fn a_link_with_only_ipv6_is_still_a_lan_link() {
        let mut intf = mock_interface(true, true, true, false, false, false);
        intf.ips = vec![IpNetwork::V6(
            Ipv6Network::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64).unwrap(),
        )];

        assert_eq!(is_viable_lan_interface(&intf, |_| true), Ok(()));

        let link = get_lan_link_with(vec![intf], |_| true)
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
        assert_eq!(link.interface.name, "test0");
    }

    /// The link carries both families, so a dual-stack segment does not have to
    /// choose which half of itself to be described by.
    #[test]
    fn a_dual_stack_link_carries_both_families() {
        let mut intf = mock_interface(true, true, true, false, false, true);
        intf.ips.push(IpNetwork::V6(
            Ipv6Network::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64).unwrap(),
        ));

        let link = get_lan_link_with(vec![intf], |_| true)
            .expect("selection succeeds")
            .expect("a viable link is selected");

        assert_eq!(
            link.ipv4.map(|net| net.ip()),
            Some(Ipv4Addr::new(192, 168, 1, 100))
        );
        assert_eq!(link.ipv6.len(), 1);
    }

    /// The published IPv4-only entry point keeps answering exactly as it did,
    /// since a front end outside this repo builds against it.
    #[test]
    fn the_ipv4_view_of_a_link_is_unchanged() {
        let intf = mock_interface(true, true, true, false, false, true);

        let link = get_lan_link_with(vec![intf], |_| true)
            .expect("selection succeeds")
            .expect("a viable link is selected");

        assert_eq!(
            link.ipv4,
            Some(Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 100), 24).unwrap())
        );
    }

    #[test]
    fn is_viable_down() {
        let intf = mock_interface(false, true, true, false, false, true);
        assert_eq!(
            is_viable_lan_interface(&intf, |_| true),
            Err(ViabilityError::IsDown)
        );
    }

    #[test]
    fn is_viable_not_physical() {
        let intf = mock_interface(true, true, true, false, false, true);
        assert_eq!(
            is_viable_lan_interface(&intf, |_| false),
            Err(ViabilityError::NotPhysical)
        );
    }

    #[test]
    fn is_viable_no_mac() {
        let intf = mock_interface(true, false, true, false, false, true);
        assert_eq!(
            is_viable_lan_interface(&intf, |_| true),
            Err(ViabilityError::NoMacAddress)
        );
    }

    #[test]
    fn is_viable_success() {
        let intf = mock_interface(true, true, true, false, false, true);
        assert_eq!(is_viable_lan_interface(&intf, |_| true), Ok(()));
    }
}
