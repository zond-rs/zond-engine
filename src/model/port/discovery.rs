// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Why a port is in the state it is
//!
//! [`PortState`](super::PortState) is the verdict; [`Discovery`] is the
//! evidence behind it: which packet decided it, when, how long it took to
//! arrive, the hop counter it carried, and who sent it.
//!
//! A report renders the verdict; an operator who doubts it reads this. A TTL of 64 from
//! a host three hops away, or a `Closed` sourced from an address that is not the
//! target's, is how a wrong answer is caught.
//!
//! Everything but the reason is optional, since an unprivileged connect attempt has no
//! header to read a TTL or sender from.
//!
//! ## Who sent the reply
//!
//! [`source_ip`](Discovery::source_ip) is the source address in the reply's IP header,
//! never this machine's. It matters where it is not the target's: an ICMP error from a
//! router or firewall is a fact about the path. It is the per-port counterpart of a
//! host's [`EvidenceSource`](crate::model::host::EvidenceSource).
//!
//! No scanner in this crate fills it; it arrives only on a record read back from a
//! document. A scanner that records one must withhold an excluded sender as
//! [`EvidenceSource::Withheld`](crate::model::host::EvidenceSource::Withheld) does, and
//! `tests/hygiene/exclusions.rs` holds every writer of the field to that.

use std::{
    net::IpAddr,
    time::{Duration, SystemTime},
};

/// The packet that settled a port's state, named rather than interpreted.
///
/// What these *mean* depends on the probe that provoked them, which is
/// [`TcpScanTechnique::verdict`](crate::model::technique::TcpScanTechnique::verdict)'s
/// job. Recording the packet lets a reader disagree with the conclusion.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScanResponse {
    /// Received a TCP SYN/ACK (Port is Open).
    TcpSynAck,
    /// A TCP SYN/ACK from this endpoint to **somebody else**, read off the wire
    /// without anything having been sent to it.
    ///
    /// Establishes what [`TcpSynAck`](Self::TcpSynAck) does, from a real client. It
    /// says nothing about whether the endpoint would answer this machine, so a scan and
    /// a listener disagreeing about a port is a finding.
    OverheardSynAck,
    /// Received a TCP RST (Port is Closed or Blocked).
    TcpRst,
    /// A connection the operating system refused: a TCP RST or an ICMP port
    /// unreachable, which it reports alike.
    ///
    /// What a connect through the operating system's TCP learns where a raw probe would
    /// read [`TcpRst`](Self::TcpRst). A reset means nothing is listening and a port
    /// unreachable means a filter, but a connect gets the same error for both and sees
    /// neither packet. Most refusals are resets, so the port is read closed.
    ConnectionRefused,
    /// Received a valid protocol response to a UDP payload.
    UdpResponse,
    /// Received an SCTP INIT-ACK: an endpoint willing to open an association,
    /// which is the SCTP analogue of [`TcpSynAck`](Self::TcpSynAck).
    SctpInitAck,
    /// Received an SCTP ABORT: a reachable stack refusing the association
    /// because nothing is listening, the analogue of [`TcpRst`](Self::TcpRst).
    SctpAbort,
    /// No response received within the timeout window.
    NoResponse,
    /// Received an ICMP Destination Unreachable.
    IcmpUnreachable,
    /// Received an ICMP Admin Prohibited (explicit firewall block).
    IcmpProhibited,
    /// Custom or application-layer response indicator.
    Custom(String),
}

/// The evidence behind a port's state: which packet decided it, when, how long
/// it took, and who sent it.
///
/// `timestamp` is wall-clock, for placing the finding on a timeline. `rtt` is measured
/// elapsed time, unaffected by a clock adjustment mid-scan.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The packet that settled the state.
    reason: ScanResponse,

    /// When the state was settled, for a reader placing it against everything
    /// else that happened.
    timestamp: SystemTime,

    /// How long the reply took. Absent for a probe nothing answered, and for a
    /// connect attempt that measured no round trip of its own.
    rtt: Option<Duration>,

    /// The TTL the reply carried, which bounds its sender's distance. A value
    /// inconsistent with the target's distance exposes a forged or middlebox reply.
    ttl: Option<u8>,

    /// The source address in the reply's IP header. See the module documentation.
    source_ip: Option<IpAddr>,
}

impl Discovery {
    /// Records that `reason` settled a port's state, as of now.
    ///
    /// Everything else is optional and attached by the builder methods below.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::model::port::discovery::{Discovery, ScanResponse};
    ///
    /// let telemetry = Discovery::new(ScanResponse::TcpSynAck);
    /// assert_eq!(telemetry.reason(), &ScanResponse::TcpSynAck);
    /// ```
    pub fn new(reason: ScanResponse) -> Self {
        Self {
            reason,
            timestamp: SystemTime::now(),
            rtt: None,
            ttl: None,
            source_ip: None,
        }
    }

    /// Restores the time this packet arrived.
    ///
    /// For a rebuild; [`new`](Self::new) stamps the current time.
    pub fn seen_at(mut self, timestamp: SystemTime) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// The packet that settled the state.
    pub fn reason(&self) -> &ScanResponse {
        &self.reason
    }

    /// When the state was settled.
    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    /// How long the reply took, if a round trip was measured.
    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    /// The TTL the reply carried, if it was read from a header.
    pub fn ttl(&self) -> Option<u8> {
        self.ttl
    }

    /// The reply's sender, the source address its IP header carried, if that
    /// was recorded. See the [module documentation](self).
    pub fn source_ip(&self) -> Option<IpAddr> {
        self.source_ip
    }

    /// Attaches the measured round trip.
    pub fn with_rtt(mut self, rtt: Duration) -> Self {
        self.rtt = Some(rtt);
        self
    }

    /// Attaches the TTL read from the reply's header.
    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Attaches the reply's sender, the source address its IP header carried.
    ///
    /// A scanner calling this withholds a sender the scan's exclusions forbid
    /// the report to name, as the [module documentation](self) says.
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
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
    use std::net::Ipv4Addr;

    /// The builders compose without displacing one another.
    #[test]
    fn the_optional_evidence_composes_without_displacing_the_reason() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let rtt = Duration::from_millis(45);

        let discovery = Discovery::new(ScanResponse::TcpRst)
            .with_ttl(64)
            .with_rtt(rtt)
            .with_source_ip(ip);

        assert_eq!(discovery.reason(), &ScanResponse::TcpRst);
        assert_eq!(discovery.ttl(), Some(64));
        assert_eq!(discovery.rtt(), Some(rtt));
        assert_eq!(discovery.source_ip(), Some(ip));
    }
}
