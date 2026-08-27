// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::model::ip::set::IpSet;
use crate::system::interface::Link;
use crate::system::interface::source::viable_interfaces;

/// The links most likely to be worth scanning from, best first.
pub fn get_prioritized_interfaces(limit: usize) -> Vec<Link> {
    get_prioritized_interfaces_with(limit, viable_interfaces())
}

/// The ordering, decoupled from the host so it can be tested.
///
/// **Wired before wireless, and a name is no longer consulted.** This sorted on
/// `name.starts_with("e")` — which is `eth0` and `en0` on Linux and macOS, and
/// nothing at all on Windows, where an adapter is named by its GUID. It also
/// ranked `en1` above `wlan0` on a machine where `en1` *is* the Wi-Fi, which is
/// this laptop. A link now says what it is, so the sort asks it.
pub(crate) fn get_prioritized_interfaces_with(limit: usize, mut links: Vec<Link>) -> Vec<Link> {
    links.sort_by_key(|link| if link.is_wireless() { 1 } else { 0 });
    links.into_iter().take(limit).collect()
}

/// Whether a link-layer probe can be put on this link.
///
/// Kept as a free function because it reads as a question about the link rather
/// than about this module; [`Link::carries_frames`] is where it lives.
pub fn is_layer_2_capable(link: &Link) -> bool {
    link.carries_frames()
}

/// Whether every target in `ips` is on the same segment as this link.
///
/// **Every range, wholly.** A range straddling the edge of the link's network is
/// not on-link: half of it is reachable by ARP and half needs a router, and
/// treating the whole as local would have the sweep wait out a timeout for every
/// address past the boundary.
pub fn is_on_link(link: &Link, ips: &mut IpSet) -> bool {
    ips.v4().iter().all(|range| {
        link.addresses().iter().any(|held| {
            held.address().is_ipv4()
                && held.contains(&range.start_addr().into())
                && held.contains(&range.end_addr().into())
        })
    })
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
    use crate::model::ip::range::IpRange;
    use crate::model::mac::MacAddr;
    use crate::system::interface::{LinkAddress, LinkKind};
    use std::net::IpAddr;

    fn link(name: &str, kind: LinkKind) -> Link {
        Link::new(name, 1)
            .of_kind(kind)
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

    /// A wired link outranks a wireless one, whatever either is called.
    ///
    /// The old ordering read the first letter of the name. `en1` is the Wi-Fi on
    /// this laptop and `eth0` is wired on that server, and both start with `e` —
    /// so the sort was right by accident where it was right at all, and had
    /// nothing to say on Windows, where an adapter is named by a GUID.
    #[test]
    fn a_wired_link_is_preferred_however_the_platform_names_it() {
        let ordered = get_prioritized_interfaces_with(
            10,
            vec![
                link("en1", LinkKind::Wireless),
                link("{3F2504E0-4F89}", LinkKind::Wired),
            ],
        );

        assert_eq!(ordered[0].name(), "{3F2504E0-4F89}");
        assert_eq!(ordered[1].name(), "en1");
    }

    /// The limit is a limit.
    #[test]
    fn no_more_links_than_were_asked_for() {
        let links = vec![
            link("en0", LinkKind::Wired),
            link("en1", LinkKind::Wired),
            link("en2", LinkKind::Wired),
        ];

        assert_eq!(get_prioritized_interfaces_with(2, links.clone()).len(), 2);
        assert_eq!(get_prioritized_interfaces_with(0, links).len(), 0);
    }

    /// A range wholly inside the link's network is on it; one that leaves is
    /// not, and half of one is not either.
    ///
    /// The last is the case worth the test. A range straddling the boundary is
    /// half reachable by ARP and half not, and calling it on-link makes the
    /// sweep wait out a timeout for every address past the edge.
    #[test]
    fn a_range_is_on_link_only_if_all_of_it_is() {
        let link = holding("en0", "10.0.0.7", 24);

        assert!(is_on_link(&link, &mut targets("10.0.0.1-10.0.0.50")));
        assert!(is_on_link(&link, &mut targets("10.0.0.0/24")), "the whole");
        assert!(
            !is_on_link(&link, &mut targets("10.0.1.1-10.0.1.5")),
            "past"
        );
        assert!(
            !is_on_link(&link, &mut targets("10.0.0.200-10.0.1.10")),
            "a range that starts on the link and leaves it is not on the link"
        );
    }

    /// A link with no address of its own puts nothing on it.
    #[test]
    fn a_link_with_no_addressing_has_nothing_on_it() {
        let bare = link("en0", LinkKind::Wired);

        assert!(!is_on_link(&bare, &mut targets("10.0.0.1-10.0.0.50")));
    }

    /// An IPv6 address on the link does not make an IPv4 range local.
    ///
    /// `is_on_link` answers for IPv4 only — the callers that ask it are the ARP
    /// path — and a link holding a v6 prefix that happens to contain the same
    /// bits must not be read as covering a v4 range.
    #[test]
    fn an_ipv6_prefix_does_not_answer_for_an_ipv4_range() {
        let v6_only = link("en0", LinkKind::Wired).with_addresses(vec![LinkAddress::new(
            "fe80::1".parse::<IpAddr>().expect("an address"),
            64,
        )]);

        assert!(!is_on_link(&v6_only, &mut targets("10.0.0.1-10.0.0.50")));
    }
}
