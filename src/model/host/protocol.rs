// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Which IP protocols a host's stack accepts
//!
//! One layer below ports: which protocols the host's stack takes delivery of. GRE, ESP,
//! OSPF and IPIP have no ports, so a TCP and UDP scan reports a tunnel endpoint or a
//! router as an empty host.
//!
//! It also reads a firewall's protocol policy, usually shorter and more revealing than
//! its port policy: a host with every TCP port closed that answers for protocol 47 is
//! one end of a tunnel.
//!
//! ## Separate from ports
//!
//! The protocol numbers include the transports themselves
//! ([`Protocol::Tcp`](crate::model::port::Protocol::Tcp) is 6,
//! [`Udp`](crate::model::port::Protocol::Udp) 17,
//! [`Sctp`](crate::model::port::Protocol::Sctp) 132), and a protocol number has none of
//! a [`Port`](crate::model::port::Port)'s service or TLS data. So this is a fact about
//! the host, kept beside [`Filtering`](super::Filtering).

/// What a scan established about a host accepting one IP protocol.
///
/// Ordered from least to most definitive, so [`Host::merge`](super::Host) promotes by
/// comparison.
///
/// As with [`PortState`](crate::model::port::PortState), a packet outranks silence:
/// [`Blocked`](Self::Blocked) sits above [`OpenOrNoReply`](Self::OpenOrNoReply).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IpProtocolState {
    /// No probe was sent, so nothing was established either way.
    ///
    /// A protocol the scan named but never reached. The counterpart of
    /// [`PortState::Unasked`](crate::model::port::PortState::Unasked).
    Unasked,

    /// A probe was sent and nothing came back.
    ///
    /// The ordinary verdict: most protocols answer nothing even where the host speaks
    /// them, so silence cannot tell acceptance from a filter.
    OpenOrNoReply,

    /// Something in the path refused the protocol, by an ICMP unreachable that
    /// was not a protocol unreachable: administratively prohibited, or a
    /// communication filter.
    ///
    /// A statement about the path; the host may speak the protocol.
    Blocked,

    /// The host's own stack said it does not speak this protocol, by an ICMP
    /// protocol unreachable (RFC 792 type 3 code 2, RFC 4443 type 1 code 4).
    ///
    /// The host's own negative verdict, which proves it is there.
    Closed,

    /// The host answered in the protocol that was asked about.
    ///
    /// Only reachable for a protocol whose answers this build can recognise and
    /// capture; see [`IpProtocolScan`](crate::scanner::strategy::protocols) for
    /// which those are and why silence is the usual answer for the rest.
    Open,
}

impl IpProtocolState {
    /// Every state, in declaration order, which is least definitive first and is
    /// the order this type's [`Ord`] ranks by.
    ///
    /// Read by the check holding the exported schema to what this build can write.
    pub const ALL: &'static [Self] = &[
        Self::Unasked,
        Self::OpenOrNoReply,
        Self::Blocked,
        Self::Closed,
        Self::Open,
    ];

    /// Whether the host is known to take delivery of the protocol.
    pub fn is_accepted(&self) -> bool {
        matches!(self, IpProtocolState::Open)
    }

    /// Whether anything at all was established.
    ///
    /// False only for [`Unasked`](Self::Unasked), a fact about the scan.
    pub fn is_established(&self) -> bool {
        !matches!(self, IpProtocolState::Unasked)
    }
}

/// The IANA name for a protocol number, where it has one worth printing.
///
/// A short list of the numbers a scan is likely to find something at; others render as
/// the number.
///
/// Lowercase, matching the registry's own keyword column and
/// [`record::wire`](crate::record::wire)'s convention for a name on the wire.
pub const fn ip_protocol_name(number: u8) -> Option<&'static str> {
    Some(match number {
        1 => "icmp",
        2 => "igmp",
        4 => "ipv4",
        6 => "tcp",
        17 => "udp",
        41 => "ipv6",
        47 => "gre",
        50 => "esp",
        51 => "ah",
        58 => "ipv6-icmp",
        89 => "ospfigp",
        103 => "pim",
        112 => "vrrp",
        132 => "sctp",
        136 => "udplite",
        137 => "mpls-in-ip",
        _ => return None,
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

    /// A later probe that learned less does not lower the state.
    #[test]
    fn the_states_rank_by_how_much_they_establish() {
        assert!(IpProtocolState::Unasked < IpProtocolState::OpenOrNoReply);
        assert!(IpProtocolState::OpenOrNoReply < IpProtocolState::Blocked);
        assert!(IpProtocolState::Blocked < IpProtocolState::Closed);
        assert!(IpProtocolState::Closed < IpProtocolState::Open);
    }

    /// Silence does not count as acceptance.
    #[test]
    fn silence_is_not_acceptance() {
        assert!(!IpProtocolState::OpenOrNoReply.is_accepted());
        assert!(IpProtocolState::OpenOrNoReply.is_established());
        assert!(IpProtocolState::Open.is_accepted());
    }

    /// The one state that is about the scan rather than the host.
    #[test]
    fn a_protocol_nobody_asked_about_establishes_nothing() {
        assert!(!IpProtocolState::Unasked.is_established());
        for &state in IpProtocolState::ALL {
            assert_eq!(
                state.is_established(),
                state != IpProtocolState::Unasked,
                "{state:?}"
            );
        }
    }

    /// Names come from the registry; unlisted numbers have none.
    #[test]
    fn a_number_is_named_only_where_the_registry_names_it() {
        assert_eq!(ip_protocol_name(47), Some("gre"));
        assert_eq!(ip_protocol_name(6), Some("tcp"));
        assert_eq!(ip_protocol_name(253), None, "an experimental number");
        assert_eq!(
            ip_protocol_name(0),
            None,
            "the hop-by-hop header is not one"
        );
    }
}
