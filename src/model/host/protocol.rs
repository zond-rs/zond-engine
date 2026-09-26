// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Which IP protocols a host's stack accepts
//!
//! A port scan asks what is listening behind a transport. This asks a question
//! one layer down: which protocols the host's stack takes delivery of at all.
//! GRE, ESP, OSPF and IPIP have no ports to enumerate, so a scan that asks about
//! TCP and UDP reports a tunnel endpoint or a router as an empty host.
//!
//! It also reads a different policy. A firewall has a rule for which ports it
//! forwards and a rule for which protocols it forwards, and the second is
//! usually the shorter list and the more revealing one: a host whose every TCP
//! port is closed and which answers for protocol 47 is one end of a tunnel.
//!
//! ## Not a port under another name
//!
//! An IP protocol number is not a port, and the difference is not a matter of
//! taste. The numbers this enumerates are a set that contains the transports:
//! [`Protocol::Tcp`](crate::model::port::Protocol::Tcp) is protocol 6,
//! [`Udp`](crate::model::port::Protocol::Udp) is 17 and
//! [`Sctp`](crate::model::port::Protocol::Sctp) is 132, so a variant sitting
//! beside those three to mean "an IP protocol" would be a category naming its
//! own members. A [`Port`](crate::model::port::Port) also carries a service, a
//! TLS handshake and the account of a segment, none of which a protocol number
//! has, and reusing it would put four empty halves on every record.
//!
//! So this is a fact about the host, kept where the other whole-host conclusions
//! are, beside [`Filtering`](super::Filtering).

/// What a scan established about a host accepting one IP protocol.
///
/// Ordered from least definitive to most, so that [`Host::merge`](super::Host)
/// promotes by an ordinary comparison and two probes that disagree resolve to
/// whichever learned more.
///
/// The order is not [`PortState`](crate::model::port::PortState)'s, and the
/// difference is in what the words mean here.
/// [`Filtered`](Self::Filtered) is a packet here, an intermediary refusing the
/// protocol in its own words, where a port scan reaches the same word from
/// silence. So it outranks the silent verdict here and sits below it there.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IpProtocolState {
    /// No probe was sent, so nothing was established either way.
    ///
    /// What a protocol the scan was not asked about says, and what one a run cut
    /// short never reached says. The counterpart of
    /// [`PortState::Unasked`](crate::model::port::PortState::Unasked), and there
    /// for the same reason: a protocol left off the record and one the host
    /// ignored look identical.
    Unasked,

    /// A probe was sent and nothing came back.
    ///
    /// The honest verdict and the ordinary one. Most protocols answer nothing
    /// even where the host speaks them, since there is no handshake to complete
    /// and nothing to refuse, so silence cannot tell a stack that accepted the
    /// datagram from a filter that dropped it.
    OpenFiltered,

    /// Something in the path refused the protocol, by an ICMP unreachable that
    /// was not a protocol unreachable: administratively prohibited, or a
    /// communication filter.
    ///
    /// A statement about the path rather than the host. The host may speak this
    /// protocol perfectly well and never hear a datagram of it.
    Filtered,

    /// The host's own stack said it does not speak this protocol, by an ICMP
    /// protocol unreachable (RFC 792 type 3 code 2, RFC 4443 type 1 code 4).
    ///
    /// The one negative verdict that is the host's own, and it proves the host
    /// is there as surely as any reply does.
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
    /// Here for the reason
    /// [`Protocol::ALL`](crate::model::port::Protocol::ALL) gives, and read by
    /// the gate holding the exported schema to what this build can write.
    pub const ALL: &'static [Self] = &[
        Self::Unasked,
        Self::OpenFiltered,
        Self::Filtered,
        Self::Closed,
        Self::Open,
    ];

    /// Whether the host is known to take delivery of the protocol.
    pub fn is_accepted(&self) -> bool {
        matches!(self, IpProtocolState::Open)
    }

    /// Whether anything at all was established.
    ///
    /// False for a protocol nobody asked about, which is the one state that is a
    /// fact about the scan rather than about the host.
    pub fn is_established(&self) -> bool {
        !matches!(self, IpProtocolState::Unasked)
    }
}

/// The IANA name for a protocol number, where it has one worth printing.
///
/// A short list rather than the whole registry. What a reader needs is to
/// recognise the numbers a scan is likely to find something at, and a table of a
/// hundred and fifty assignments most of which no host has ever answered for
/// would cost more to keep current than it pays back. A number with no name here
/// is rendered as the number, which is what it is.
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

    /// A later probe that learned less does not unlearn what an earlier one
    /// established, which is what the ordering is for.
    #[test]
    fn the_states_rank_by_how_much_they_establish() {
        assert!(IpProtocolState::Unasked < IpProtocolState::OpenFiltered);
        assert!(IpProtocolState::OpenFiltered < IpProtocolState::Filtered);
        assert!(IpProtocolState::Filtered < IpProtocolState::Closed);
        assert!(IpProtocolState::Closed < IpProtocolState::Open);
    }

    /// Silence is the ordinary answer, so it must not read as acceptance. A
    /// report that counted it as one would say a host speaks every protocol
    /// nobody stopped.
    #[test]
    fn silence_is_not_acceptance() {
        assert!(!IpProtocolState::OpenFiltered.is_accepted());
        assert!(IpProtocolState::OpenFiltered.is_established());
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

    /// The names are the registry's, and a number without one is not invented
    /// for.
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
