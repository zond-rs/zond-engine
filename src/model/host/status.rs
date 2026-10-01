// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Whether a host is there, and what says so
//!
//! [`HostStatus`] is the verdict and [`StatusReason`] is the evidence behind
//! it: which protocol produced it, which address sent it, and what it said.
//!
//! A scan promotes along `HostStatus`'s ordering and never lowers, so the verdict does
//! not depend on arrival order.
//!
//! A host keeps every reason it collected, so "up" can be checked.
//!
//! Who sent a reason is [`EvidenceSource`]: the host, a named middlebox, or a middlebox
//! the scan's [`Exclusions`](crate::model::exclusion::Exclusions) forbid it to name, as
//! with [`Hop::withheld`](crate::model::host::Hop::withheld).

use std::net::IpAddr;
use std::sync::Arc;

/// The high-level reachability state of a network host.
///
/// Ordered by how strong the evidence is: `Unknown < Down < Blocked < Up`.
///
/// [`Host::merge`](crate::model::host::Host::merge) and
/// [`Host::record_evidence`](crate::model::host::Host::record_evidence) promote along
/// it and never lower, so a router's late ICMP unreachable cannot overwrite the host's
/// own ARP reply.
///
/// The ordering depends on one rule every producer obeys: **silence never moves the
/// status.** Every variant but `Unknown` is backed by a received packet, so ranking by
/// aliveness also ranks by strength of evidence.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostStatus {
    /// Nothing was received about this host. A timeout means this, not
    /// [`HostStatus::Down`]: silence cannot tell a dead host from an unreachable one.
    Unknown,
    /// An intermediary reported this address unreachable, by an ICMP host
    /// unreachable, no route, or address unreachable quoting a probe this scan
    /// sent. Never inferred from silence.
    Down,
    /// An intermediary explicitly rejected traffic to this address by policy, so a
    /// perimeter is enforced around it though the host has not answered.
    Blocked,
    /// The host answered for itself. Any packet sourced by the host proves this,
    /// including ones that are negative about the port they report on: a TCP RST
    /// and an ICMP port unreachable each require a live stack to produce.
    Up,
}

impl HostStatus {
    /// Every reachability verdict, in declaration order, which is least
    /// definitive first.
    ///
    /// The wire round trip and the exported schema are checked against this list.
    pub const ALL: &'static [Self] = &[Self::Unknown, Self::Down, Self::Blocked, Self::Up];
}

/// Known protocols or events that provide evidence of host reachability.
///
/// Probe types are added as the engine learns them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatusProtocol {
    /// Discovered via Address Resolution Protocol (Layer 2). Usually confirms local adjacency.
    Arp,
    /// Discovered via IPv6 Neighbor Discovery at layer 2: a neighbor
    /// advertisement, solicited or in answer to an all-nodes solicitation. The
    /// IPv6 counterpart of [`StatusProtocol::Arp`], and equally conclusive,
    /// since the reply came off the local segment.
    Ndp,
    /// Discovered via ICMP Echo Request/Reply.
    IcmpEcho,
    /// Answered an ICMP timestamp request (RFC 792), which is a different
    /// question from an echo and is answered by hosts that drop one.
    ///
    /// IPv4 only: RFC 4443 defines no timestamp message. The reply also carries the
    /// target's clock.
    IcmpTimestamp,
    /// Discovered via an ICMP Destination Unreachable quoting one of this scan's
    /// probes. What it proves depends on who sent it and which code it carried,
    /// which is why [`StatusReason::source`] exists.
    IcmpUnreachable,
    /// Discovered via the SYN+ACK or RST a half-open SYN probe drew.
    TcpSyn,
    /// Discovered via a TCP connection the scanning host's own stack made:
    /// a handshake it completed, or a reset it surfaced as a refused
    /// connection.
    ///
    /// Separate from [`TcpSyn`](Self::TcpSyn) because it is more visible: a completed
    /// connection reaches the service, which may log it.
    TcpConnect,
    /// Discovered via a TCP segment answering a raw probe that was not a SYN.
    ///
    /// A RST answering a FIN, a flagless segment or a bare ACK says only that the stack
    /// is alive. Which probe drew it is in
    /// [`StatusReason::details`](super::StatusReason::details).
    Tcp,
    /// Discovered via a DHCP server reply overheard on the segment.
    ///
    /// Separate from [`Udp`](Self::Udp) because it names what answered.
    ///
    /// Unsolicited, unlike everything else here: a DHCP server answers the segment's
    /// traffic while a sweep is listening.
    ///
    /// Proves only that the sender is there; whether it is a
    /// [`NetworkRole::DhcpServer`](crate::model::host::NetworkRole::DhcpServer) is a
    /// separate question a relay can confuse. See `DhcpProtocol`.
    Dhcp,
    /// Discovered via a valid application-level response over UDP.
    ///
    /// Names only the transport. Where the engine can name what answered, it has a
    /// variant for it.
    Udp,
    /// Discovered via an SCTP chunk answering an INIT probe.
    ///
    /// Either answer proves the host is there: an INIT-ACK is an endpoint
    /// willing to open an association, and an ABORT is the same stack refusing
    /// one. Which of the two arrived is named in
    /// [`StatusReason::details`](super::StatusReason::details), as it is for
    /// [`Tcp`](Self::Tcp).
    Sctp,
    /// A custom discovery method initiated by a specialized scanning script.
    Custom(Arc<str>),
}

impl StatusProtocol {
    /// Every protocol event this build names, in declaration order.
    ///
    /// [`Custom`](Self::Custom) carries a strategy-chosen name, so it is written with a
    /// `custom:` prefix that the exported schema matches on.
    ///
    /// The schema holds the rest as a closed list, and the export conformance suite
    /// checks it against this.
    pub const ALL: &'static [Self] = &[
        Self::Arp,
        Self::Ndp,
        Self::IcmpEcho,
        Self::IcmpTimestamp,
        Self::IcmpUnreachable,
        Self::TcpSyn,
        Self::TcpConnect,
        Self::Tcp,
        Self::Dhcp,
        Self::Udp,
        Self::Sctp,
    ];
}

/// A structured rationale for a host's reachability state.
///
/// `StatusReason` pairs a protocol event with optional human-readable or machine-parsable
/// details to provide a transparent "audit trail" for host discovery.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct StatusReason {
    /// The specific protocol-level event that triggered this status.
    pub protocol: StatusProtocol,

    /// Who sent this evidence: the host it is about, or something in the path
    /// speaking for it.
    ///
    /// An ICMP error names two addresses: its sender and the destination of the
    /// datagram it quotes. A port unreachable from the target proves it alive; from a
    /// middlebox it proves only that something in the path speaks for the address, as
    /// a NAT may.
    pub source: EvidenceSource,

    /// Extended details about the response (e.g., "Received TCP RST", "TTL Exceeded in transit").
    ///
    /// An `Arc<str>`, since thousands of hosts report identical rationales.
    pub details: Option<Arc<str>>,
}

impl StatusReason {
    /// Creates a new `StatusReason` with the specified protocol and details.
    pub fn new(protocol: StatusProtocol, details: impl Into<Arc<str>>) -> Self {
        Self {
            protocol,
            source: EvidenceSource::Host,
            details: Some(details.into()),
        }
    }

    /// Creates a new `StatusReason` containing only protocol-level evidence without extra details.
    pub fn basic(protocol: StatusProtocol) -> Self {
        Self {
            protocol,
            source: EvidenceSource::Host,
            details: None,
        }
    }

    /// Attributes this evidence to the address that actually sent it.
    ///
    /// Only when `source` is not the host the reason is recorded against.
    pub fn from_source(mut self, source: IpAddr) -> Self {
        self.source = EvidenceSource::Intermediary(source);
        self
    }
}

/// Who sent a piece of evidence about a host.
///
/// One value, so a withheld sender carrying an address cannot be built, as with
/// [`Hop`](crate::model::host::Hop).
///
/// Not `#[non_exhaustive]`: the three variants partition the cases, and a reader must
/// handle each without a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceSource {
    /// The host the evidence is about sent it, which is the strongest claim a
    /// reason can make.
    Host,
    /// Something in the path sent it about the host, from this address: a
    /// router or firewall reporting the host unreachable, or a NAT answering on
    /// its behalf.
    Intermediary(IpAddr),
    /// Something in the path sent it about the host, from an address the
    /// scan's exclusions forbid it to report.
    ///
    /// Second-hand evidence whose sender the scan will not name. The finding about the
    /// host is kept.
    ///
    /// For reading a record back; a scan records evidence as it arrived and withholds
    /// the sender afterwards.
    Withheld,
}

impl EvidenceSource {
    /// The address that sent the evidence, or `None` where the host sent it
    /// or the sender is [withheld](Self::is_withheld).
    pub fn address(&self) -> Option<IpAddr> {
        match self {
            Self::Intermediary(address) => Some(*address),
            Self::Host | Self::Withheld => None,
        }
    }

    /// Whether the evidence came second-hand from an address the scan may not
    /// report.
    ///
    /// The one case where [`address`](Self::address) is `None` but the host did not
    /// answer for itself.
    pub fn is_withheld(&self) -> bool {
        *self == Self::Withheld
    }

    /// Withholds the sender if `keep` refuses its address, and returns whether
    /// it did.
    pub(crate) fn withhold(&mut self, keep: impl Fn(&IpAddr) -> bool) -> bool {
        match self {
            Self::Intermediary(address) if !keep(address) => {
                *self = Self::Withheld;
                true
            }
            Self::Host | Self::Intermediary(_) | Self::Withheld => false,
        }
    }
}

impl HostStatus {
    /// Returns `true` if the host is confirmed to be fully online and responding.
    #[inline]
    pub fn is_up(&self) -> bool {
        matches!(self, HostStatus::Up)
    }

    /// Returns `true` if the host is explicitly confirmed to be offline.
    #[inline]
    pub fn is_down(&self) -> bool {
        matches!(self, HostStatus::Down)
    }

    /// Returns `true` if there is evidence the host is present on the network,
    /// even if communication is restricted by a firewall.
    #[inline]
    pub fn is_alive(&self) -> bool {
        matches!(self, HostStatus::Up | HostStatus::Blocked)
    }
}

impl std::fmt::Display for HostStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostStatus::Unknown => write!(f, "Unknown"),
            HostStatus::Down => write!(f, "Down"),
            HostStatus::Blocked => write!(f, "Blocked"),
            HostStatus::Up => write!(f, "Up"),
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

    /// The declaration order is the promotion rule `Host::record_evidence` follows.
    #[test]
    fn the_variant_order_ranks_evidence_from_weakest_to_strongest() {
        assert!(HostStatus::Unknown < HostStatus::Down);
        assert!(HostStatus::Down < HostStatus::Blocked);
        assert!(HostStatus::Blocked < HostStatus::Up);
    }

    /// A `Blocked` host is alive, so it is carried into a port scan.
    #[test]
    fn a_blocked_host_counts_as_alive_and_an_unanswered_one_does_not() {
        assert!(HostStatus::Up.is_alive());
        assert!(HostStatus::Blocked.is_alive());
        assert!(!HostStatus::Down.is_alive());
        assert!(!HostStatus::Unknown.is_alive());
    }

    /// Every variant renders distinctly.
    #[test]
    fn every_status_renders_under_its_own_name() {
        let rendered: Vec<String> = [
            HostStatus::Unknown,
            HostStatus::Down,
            HostStatus::Blocked,
            HostStatus::Up,
        ]
        .iter()
        .map(ToString::to_string)
        .collect();

        assert_eq!(rendered, ["Unknown", "Down", "Blocked", "Up"]);
    }

    /// A reason carries its protocol and, when someone other than the host sent it,
    /// the sender's address.
    #[test]
    fn a_reason_records_its_protocol_and_who_it_came_from() {
        let unattributed = StatusReason::new(
            StatusProtocol::Custom(Arc::from("dns-probe")),
            "Resolved A record successfully",
        );

        assert_eq!(
            unattributed.protocol,
            StatusProtocol::Custom(Arc::from("dns-probe"))
        );
        assert_eq!(
            unattributed.details.as_deref(),
            Some("Resolved A record successfully")
        );
        assert_eq!(
            unattributed.source,
            EvidenceSource::Host,
            "unqualified means the host answered for itself"
        );

        let router: IpAddr = "192.0.2.1".parse().expect("a valid address");
        let attributed = StatusReason::basic(StatusProtocol::IcmpUnreachable).from_source(router);

        assert_eq!(attributed.source, EvidenceSource::Intermediary(router));
        assert_eq!(attributed.details, None);
    }

    /// Withholding reaches only a named sender the policy refuses, never the host's
    /// own evidence.
    #[test]
    fn only_a_refused_sender_is_withheld() {
        let refused: IpAddr = "198.51.100.1".parse().expect("a valid address");
        let allowed: IpAddr = "192.0.2.1".parse().expect("a valid address");
        let keep = |address: &IpAddr| *address != refused;

        let mut named = EvidenceSource::Intermediary(refused);
        assert!(named.withhold(keep));
        assert_eq!(named, EvidenceSource::Withheld);
        assert_eq!(named.address(), None);

        for mut untouched in [
            EvidenceSource::Host,
            EvidenceSource::Intermediary(allowed),
            EvidenceSource::Withheld,
        ] {
            let before = untouched;
            assert!(!untouched.withhold(keep), "{before:?}");
            assert_eq!(untouched, before);
        }
    }
}
