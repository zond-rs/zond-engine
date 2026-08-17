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
//! Probes answer in an order nobody controls, so the verdict has to be
//! independent of arrival order. That is what the ordering on `HostStatus` is
//! for — a scan promotes along it and never lowers — and the type's own
//! documentation has the rule that makes the ordering defensible.
//!
//! A host keeps every reason it collected, not just the one that settled the
//! verdict. Reachability is a claim someone will want to check, and "up" with
//! nothing behind it cannot be checked.

use std::net::IpAddr;
use std::sync::Arc;

/// The high-level reachability state of a network host.
///
/// Ordered by how strong the evidence is: `Unknown < Down < Filtered < Up`.
///
/// [`Host::merge`](crate::model::host::Host::merge) and
/// [`Host::record_evidence`](crate::model::host::Host::record_evidence) both
/// promote along it and never lower: a router's ICMP unreachable arriving after
/// the host's own ARP reply must not overwrite proof the host answered for
/// itself.
///
/// The ordering is only defensible because of the rule below, which every
/// producer of a status obeys: **silence never moves the status.** Each variant
/// other than `Unknown` is backed by a packet the engine received, so ranking by
/// aliveness also ranks by strength of evidence. Were a timeout allowed to
/// produce `Filtered`, a host nobody ever heard from would outrank an explicit
/// unreachable, and this ordering would invert the evidence it claims to rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostStatus {
    /// Nothing was received that says anything about this host. This is what a
    /// timeout means, and it is deliberately not [`HostStatus::Down`]: an
    /// address that answers nothing is indistinguishable from one that was never
    /// reachable in the first place, and the engine declines to guess between
    /// them.
    Unknown,
    /// An intermediary reported this address unreachable, by an ICMP host
    /// unreachable, no route, or address unreachable quoting a probe this scan
    /// sent. Never inferred from silence.
    Down,
    /// An intermediary explicitly rejected traffic to this address by policy, so
    /// something is enforcing a perimeter around it even though the host itself
    /// has not answered. Distinct from an address nothing answers for, which is
    /// [`HostStatus::Unknown`].
    Filtered,
    /// The host answered for itself. Any packet sourced by the host proves this,
    /// including ones that are negative about the port they report on: a TCP RST
    /// and an ICMP port unreachable each require a live stack to produce.
    Up,
}

/// Known protocols or events that provide evidence of host reachability.
///
/// Marked `#[non_exhaustive]`: probe types are added as the engine learns to
/// speak them, and a consumer matching on this enum should pay for that with a
/// recompile rather than a major version.
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
    /// Discovered via an ICMP Destination Unreachable quoting one of this scan's
    /// probes. What it proves depends on who sent it and which code it carried,
    /// which is why [`StatusReason::source`] exists.
    IcmpUnreachable,
    /// Discovered via a successful TCP 3-way handshake on an open port, or via
    /// the SYN+ACK or RST a half-open SYN probe drew.
    TcpSyn,
    /// Discovered via a TCP segment answering a raw probe that was not a SYN.
    ///
    /// Kept apart from [`TcpSyn`](Self::TcpSyn) because the probes differ in
    /// what they prove and in how visible they are: a RST answering a FIN, a
    /// flagless segment or a bare ACK says the host's stack is alive and
    /// nothing more, and it says so about a port that was never asked to accept
    /// a connection. Which probe drew it is named in
    /// [`StatusReason::details`](super::StatusReason::details).
    Tcp,
    /// Discovered via a valid application-level response over UDP.
    Udp,
    /// A custom discovery method initiated by a specialized scanning script.
    Custom(Arc<str>),
}

/// A structured rationale for a host's reachability state.
///
/// `StatusReason` pairs a protocol event with optional human-readable or machine-parsable
/// details to provide a transparent "audit trail" for host discovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct StatusReason {
    /// The specific protocol-level event that triggered this status.
    pub protocol: StatusProtocol,

    /// The address that sent this evidence, when it is **not** the host the
    /// evidence is about.
    ///
    /// An ICMP error names two addresses: the router or firewall that generated
    /// it, and the destination of the datagram it quotes. They are different
    /// claims. A port unreachable sourced by the target proves the target is
    /// alive; the same message from a middlebox proves only that something in
    /// the path speaks for that address, and recording the two identically would
    /// let a NAT answering on another host's behalf be reported as that host
    /// being up.
    ///
    /// `None` means the host answered for itself, which is the common case and
    /// the one needing no qualification.
    pub source: Option<IpAddr>,

    /// Extended details about the response (e.g., "Received TCP RST", "TTL Exceeded in transit").
    ///
    /// Stored as an `Arc<str>` to minimize heap churn when thousands of hosts report
    /// identical rationales.
    pub details: Option<Arc<str>>,
}

impl StatusReason {
    /// Creates a new `StatusReason` with the specified protocol and details.
    pub fn new(protocol: StatusProtocol, details: impl Into<Arc<str>>) -> Self {
        Self {
            protocol,
            source: None,
            details: Some(details.into()),
        }
    }

    /// Creates a new `StatusReason` containing only protocol-level evidence without extra details.
    pub fn basic(protocol: StatusProtocol) -> Self {
        Self {
            protocol,
            source: None,
            details: None,
        }
    }

    /// Attributes this evidence to the address that actually sent it.
    ///
    /// Only call this when `source` is not the host the reason is recorded
    /// against, since an unqualified reason already means the host answered for
    /// itself.
    pub fn from_source(mut self, source: IpAddr) -> Self {
        self.source = Some(source);
        self
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
        matches!(self, HostStatus::Up | HostStatus::Filtered)
    }
}

impl std::fmt::Display for HostStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostStatus::Unknown => write!(f, "Unknown"),
            HostStatus::Down => write!(f, "Down"),
            HostStatus::Filtered => write!(f, "Filtered"),
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

    /// The derived ordering is load-bearing: `Host::record_evidence` promotes
    /// along it, so the variants' declaration order *is* the merge rule. Adding
    /// a variant in the wrong place would silently let weaker evidence overrule
    /// stronger, and nothing else would say so.
    #[test]
    fn the_variant_order_ranks_evidence_from_weakest_to_strongest() {
        assert!(HostStatus::Unknown < HostStatus::Down);
        assert!(HostStatus::Down < HostStatus::Filtered);
        assert!(HostStatus::Filtered < HostStatus::Up);
    }

    /// "Alive" means something is there, which a perimeter enforcing policy
    /// around an address proves as surely as the host answering. It is what
    /// decides whether a host is carried into a port scan, so a `Filtered` host
    /// wrongly excluded is a host never scanned.
    #[test]
    fn a_filtered_host_counts_as_alive_and_an_unanswered_one_does_not() {
        assert!(HostStatus::Up.is_alive());
        assert!(HostStatus::Filtered.is_alive());
        assert!(!HostStatus::Down.is_alive());
        assert!(!HostStatus::Unknown.is_alive());
    }

    /// Every variant renders, and renders distinctly. `Display` reaches a
    /// report's reader directly, and two states sharing a rendering would be
    /// indistinguishable in the output whatever the model held.
    #[test]
    fn every_status_renders_under_its_own_name() {
        let rendered: Vec<String> = [
            HostStatus::Unknown,
            HostStatus::Down,
            HostStatus::Filtered,
            HostStatus::Up,
        ]
        .iter()
        .map(ToString::to_string)
        .collect();

        assert_eq!(rendered, ["Unknown", "Down", "Filtered", "Up"]);
    }

    /// A reason carries the protocol that produced it and, when the evidence
    /// came from somewhere other than the host itself, the address that sent
    /// it. The attribution is the point: a port unreachable from a middlebox
    /// proves something quite different from the same message sourced by the
    /// target.
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
            unattributed.source, None,
            "unqualified means the host answered for itself"
        );

        let router: IpAddr = "192.0.2.1".parse().expect("a valid address");
        let attributed = StatusReason::basic(StatusProtocol::IcmpUnreachable).from_source(router);

        assert_eq!(attributed.source, Some(router));
        assert_eq!(attributed.details, None);
    }
}
