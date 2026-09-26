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
//! for, with a scan promoting along it and never lowering, and the type's own
//! documentation carries the rule that makes the ordering defensible.
//!
//! A host keeps every reason it collected, not just the one that settled the
//! verdict. Reachability is a claim someone will want to check, and "up" with
//! nothing behind it cannot be checked.
//!
//! Who sent a reason is [`EvidenceSource`], which has a third answer besides
//! the host and a named middlebox: a middlebox the scan's
//! [`Exclusions`](crate::model::exclusion::Exclusions) forbid it to name. That
//! is the policy a traced path applies to its routers, for the same reason;
//! see [`Hop::withheld`](crate::model::host::Hop::withheld).

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
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostStatus {
    /// Nothing was received that says anything about this host. This is what a
    /// timeout means, and it is not [`HostStatus::Down`]: an
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

impl HostStatus {
    /// Every reachability verdict, in declaration order, which is least
    /// definitive first.
    ///
    /// Here for the reason [`Protocol::ALL`](crate::model::port::Protocol::ALL)
    /// gives: the enum is `#[non_exhaustive]`, so a status added without a name
    /// on the wire or a place in the exported schema would be a finding that
    /// survives a scan and cannot be written down.
    pub const ALL: [HostStatus; 4] = [Self::Unknown, Self::Down, Self::Filtered, Self::Up];
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
    /// Answered an ICMP timestamp request (RFC 792), which is a different
    /// question from an echo and is answered by hosts that drop one.
    ///
    /// IPv4 only: RFC 4443 defines no timestamp message, so there is nothing to
    /// ask an IPv6 address. What the reply adds beyond liveness is the target's
    /// own clock, which no other probe here obtains.
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
    /// Kept apart from [`TcpSyn`](Self::TcpSyn), which proves the same thing
    /// about the host, because the two differ in how visible they are. A
    /// half-open probe is reset before any connection exists, and a
    /// completed one reaches the service, which may log it. A reader weighing
    /// what a scan left behind on its targets, or comparing two scans of the
    /// same host, has to be able to tell which one asked.
    TcpConnect,
    /// Discovered via a TCP segment answering a raw probe that was not a SYN.
    ///
    /// Kept apart from [`TcpSyn`](Self::TcpSyn) because the probes differ in
    /// what they prove and in how visible they are: a RST answering a FIN, a
    /// flagless segment or a bare ACK says the host's stack is alive and
    /// nothing more, and it says so about a port that was never asked to accept
    /// a connection. Which probe drew it is named in
    /// [`StatusReason::details`](super::StatusReason::details).
    Tcp,
    /// Discovered via a DHCP server reply overheard on the segment.
    ///
    /// Kept apart from [`Udp`](Self::Udp) for the reason [`Tcp`](Self::Tcp) is
    /// kept apart from [`TcpSyn`](Self::TcpSyn): the two prove different things,
    /// and a reader of the evidence should not have to work out which. `Udp`
    /// names nothing above the transport because a reply to an arbitrary probed
    /// port has nothing above it to name. This frame is a DHCP server reply, and
    /// naming it is what makes the line worth reading. `udp` in an evidence list
    /// tells a reader that something answered; `dhcp` tells them what.
    ///
    /// Unsolicited, like a router advertisement and unlike everything else here:
    /// a DHCP server answers the segment's own traffic and a sweep is listening
    /// anyway, so this is evidence that arrives without a probe having been sent
    /// for it.
    ///
    /// Proves only that the sender is there. Whether it also makes the sender a
    /// [`NetworkRole::DhcpServer`](crate::model::host::NetworkRole::DhcpServer)
    /// is a separate question a relay can answer differently; see `DhcpProtocol`.
    Dhcp,
    /// Discovered via a valid application-level response over UDP.
    ///
    /// The transport and nothing above it, which is the honest answer for a
    /// reply to a port the scan probed without knowing what would be listening.
    /// Where the engine *can* name what answered, it has a variant for it.
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
    /// [`Custom`](Self::Custom) is not here and cannot be: it carries a name a
    /// strategy chose, so there is no fixed set of them to list. What a document
    /// says about it is a `custom:` prefix rather than a member of an
    /// enumeration, and the exported schema matches on the prefix.
    ///
    /// Here because the schema does hold the eight below as a closed list, and
    /// until this existed that list was maintained by hand against this enum
    /// with nothing comparing the two. The export conformance suite reads only
    /// the vocabularies that publish an `ALL`, and its own documentation says
    /// why: a name the schema advertises and the engine cannot produce is a
    /// promise to a third party that both report readers then refuse, and it is
    /// how `sctp` sat in `$defs/protocol` for a release. This was the one closed
    /// enum in the document the suite could not see.
    ///
    /// A slice where every other `ALL` in the module is a fixed-size array. The
    /// difference is `Custom`: a variant holding an `Arc<str>` makes this enum
    /// the one vocabulary that is not `Copy`, and an array would be moved out of
    /// by the first `for` loop to read it.
    pub const ALL: &'static [StatusProtocol] = &[
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
    /// An ICMP error names two addresses: the router or firewall that generated
    /// it, and the destination of the datagram it quotes. They are different
    /// claims. A port unreachable sourced by the target proves the target is
    /// alive; the same message from a middlebox proves only that something in
    /// the path speaks for that address, and recording the two identically would
    /// let a NAT answering on another host's behalf be reported as that host
    /// being up.
    ///
    /// [`EvidenceSource::Host`] is the common case and the one needing no
    /// qualification.
    pub source: EvidenceSource,

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
    /// Only call this when `source` is not the host the reason is recorded
    /// against, since an unqualified reason already means the host answered for
    /// itself.
    pub fn from_source(mut self, source: IpAddr) -> Self {
        self.source = EvidenceSource::Intermediary(source);
        self
    }
}

/// Who sent a piece of evidence about a host.
///
/// One value rather than an address and a flag beside it, so that a withheld
/// sender carrying an address cannot be built: the shape
/// [`Hop`](crate::model::host::Hop) gives a router, for the same reason.
///
/// Not `#[non_exhaustive]`, unlike most vocabularies in this module. The three
/// variants are a partition rather than a list that grows: the host sent it,
/// somebody else did and the report names them, somebody else did and the
/// report may not. A reader rendering one has to handle each, because the
/// defect this type exists to prevent is one of them read as another, and a
/// wildcard arm is where that would happen.
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
    /// Neither [`Host`](Self::Host), which would say the host answered for
    /// itself, nor the evidence dropped, which would lose a finding about a host
    /// the scan was allowed to probe. It says exactly what the report may say:
    /// this came second-hand, and the scan will not say from whom.
    ///
    /// A scan does not build these by hand. Evidence is recorded as it arrived,
    /// and the scan withholds the sender where the policy names it, on every
    /// way a reason reaches a host's record. This is how a record of one is read
    /// back.
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
    /// The one case where [`address`](Self::address) is `None` and the host
    /// did not answer for itself, so a reader weighing a reason has to ask this
    /// before it takes a missing address for the stronger claim.
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
            unattributed.source,
            EvidenceSource::Host,
            "unqualified means the host answered for itself"
        );

        let router: IpAddr = "192.0.2.1".parse().expect("a valid address");
        let attributed = StatusReason::basic(StatusProtocol::IcmpUnreachable).from_source(router);

        assert_eq!(attributed.source, EvidenceSource::Intermediary(router));
        assert_eq!(attributed.details, None);
    }

    /// Withholding reaches only a named sender the policy refuses. The host's
    /// own evidence has no sender to withhold, and marking it withheld would
    /// demote the strongest claim a reason makes to a second-hand one.
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
