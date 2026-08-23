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
//! arrive, and which of this host's interfaces it arrived on.
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
//! TTL from and no interface it can name.

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
    /// Received a TCP RST (Port is Closed or Blocked).
    TcpRst,
    /// Received a valid protocol response to a UDP payload.
    UdpResponse,
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
/// it took, and where it came from.
///
/// The two times answer different questions and neither substitutes for the
/// other. `timestamp` places the finding on a timeline a person reads, so it is
/// wall-clock. `rtt` is measured elapsed time, and stays correct across a clock
/// adjustment mid-scan because it was never derived from the clock.
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

    /// Who sent the reply, when that is worth recording separately — a `Closed`
    /// sourced from an address that is not the target's says something about
    /// the path rather than about the port.
    source_ip: Option<IpAddr>,
}

impl Discovery {
    /// Records that `reason` settled a port's state, as of now.
    ///
    /// Everything else is optional and attached by the builder methods below,
    /// because an unprivileged connect attempt knows only that it succeeded or
    /// failed: there is no header to read a TTL from and no interface to name.
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

    /// Who sent the reply, if that was recorded.
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

    /// Attaches the address the reply came from.
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
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
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
