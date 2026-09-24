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
//! Kept beside the verdict rather than folded into it because the two are read
//! by different people for different reasons. A report renders the verdict; an
//! operator who does not believe the verdict reads this. A TTL of 64 against a
//! host three hops away, or a `Closed` sourced from an address that is not the
//! target's, is how a wrong answer is caught, and none of it is recoverable
//! once the state has been recorded on its own.
//!
//! Everything except the reason is optional, because an unprivileged connect
//! attempt knows only that it succeeded or failed: there is no header to read a
//! TTL or a sender from.
//!
//! ## Who sent the reply
//!
//! [`source_ip`](Discovery::source_ip) is the reply's sender, the source
//! address in its IP header, and never an address of this machine. It says
//! something only where it is not the target's own: an ICMP error from a
//! router or firewall on the path is a fact about the path rather than about
//! the port. It is the fact a host's
//! [`EvidenceSource`](crate::model::host::EvidenceSource) records about the
//! evidence it is alive, taken one level down to a single port.
//!
//! No scanner in this crate fills it, and it arrives only on a record read
//! back from a document that carries one. A sender can be an address the
//! scan's exclusions forbid the report to name, so a scanner that records one
//! has to withhold an excluded sender the way
//! [`EvidenceSource::Withheld`](crate::model::host::EvidenceSource::Withheld)
//! does for a host's evidence, and `tests/hygiene/exclusions.rs` holds every
//! writer of the field to saying how.

use std::{
    net::IpAddr,
    time::{Duration, SystemTime},
};

/// The packet that settled a port's state, named rather than interpreted.
///
/// What any of these *means* depends on the probe that provoked it, which is
/// [`TcpScanTechnique::verdict`](crate::model::technique::TcpScanTechnique::verdict)'s
/// job. Recording the segment rather than the conclusion is what lets a reader
/// disagree with the conclusion.
///
/// `#[non_exhaustive]`: a scan learns to recognise new replies as it learns to
/// send new probes, and a consumer matching on this should pay for that with a
/// recompile rather than with a major version.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScanResponse {
    /// Received a TCP SYN/ACK (Port is Open).
    TcpSynAck,
    /// A TCP SYN/ACK from this endpoint to **somebody else**, read off the wire
    /// without anything having been sent to it.
    ///
    /// It establishes what [`TcpSynAck`](Self::TcpSynAck) does, that a listener
    /// accepted a connection, and is in one respect the stronger evidence, since
    /// what it accepted was a real client rather than a knock.
    /// Kept apart because it answers a narrower question: the endpoint served
    /// *that* peer over *that* path, and nothing here says it would answer this
    /// machine. A scan and a listener disagreeing about one port is a finding
    /// rather than a contradiction, and a reader can only see it if the two are
    /// named apart.
    OverheardSynAck,
    /// Received a TCP RST (Port is Closed or Blocked).
    TcpRst,
    /// A connection the operating system refused: a TCP RST or an ICMP port
    /// unreachable, which it reports alike.
    ///
    /// What a connect made through the operating system's own TCP learns where
    /// a raw probe would read [`TcpRst`](Self::TcpRst). Named apart because
    /// the two packets mean different things, a reset is a stack with nothing
    /// listening and a port unreachable answering a TCP probe is a filter
    /// rejecting it, and a connect is handed the same error for either, with
    /// neither the packet nor its sender. Most refusals are resets, which is
    /// why the port is read closed; this says the reading rests on a refusal
    /// rather than on a packet anybody saw.
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
/// The two times answer different questions and neither substitutes for the
/// other. `timestamp` places the finding on a timeline a person reads, so it is
/// wall-clock. `rtt` is measured elapsed time, and stays correct across a clock
/// adjustment mid-scan because it was never derived from the clock.
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

    /// The TTL the reply carried, which bounds how many hops away its sender
    /// is. A value inconsistent with the target's distance is how a forged or
    /// middlebox-generated reply is caught.
    ttl: Option<u8>,

    /// The reply's sender: the source address in its IP header, never an
    /// address of this machine. Worth recording where it is not the target's,
    /// since a verdict sent by something on the path says something about the
    /// path rather than about the port.
    source_ip: Option<IpAddr>,
}

impl Discovery {
    /// Records that `reason` settled a port's state, as of now.
    ///
    /// Everything else is optional and attached by the builder methods below,
    /// because an unprivileged connect attempt knows only that it succeeded or
    /// failed: there is no header to read a TTL or a sender from.
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
    /// [`new`](Self::new) stamps the current time, which is what a scan wants
    /// and what a rebuild does not: the timestamp is when the reply that settled
    /// this port arrived, not when the record of it was read.
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
    /// was recorded. See the [module documentation](self) for what it is worth
    /// and what a scanner recording it owes the exclusion policy.
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

    /// Everything but the reason is optional and arrives separately, so the
    /// builders have to compose without any of them displacing another.
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
