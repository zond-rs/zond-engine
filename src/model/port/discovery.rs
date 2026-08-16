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

/// Telemetry and rationale for a port's discovered state.
///
/// This struct separates absolute timeline data (`timestamp`) from
/// relative performance data (`rtt`), ensuring safe operation even
/// if the host's wall-clock time is adjusted during a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The specific packet response that determined the state.
    reason: ScanResponse,

    /// The absolute time at which the port state was first confirmed.
    /// Useful for logging and database records.
    timestamp: SystemTime,

    /// The round-trip time (RTT) for the discovery probe.
    /// Crucial for timing adjustments in subsequent scan phases.
    rtt: Option<Duration>,

    /// The Time-to-Live (TTL) value from the response packet.
    /// Useful for network distance estimation and OS fingerprinting.
    ttl: Option<u8>,

    /// The IP address of the interface where this discovery was made.
    /// Essential for multi-homed hosts where port states vary by interface.
    source_ip: Option<IpAddr>,
}

impl Discovery {
    /// Creates a new discovery record with the current wall-clock timestamp.
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

    /// Returns the specific network response indicator.
    pub fn reason(&self) -> &ScanResponse {
        &self.reason
    }

    /// Returns the absolute time of discovery.
    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    /// Returns the round-trip time (RTT) of the probe, if available.
    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    /// Returns the packet TTL (Time-to-Live), if available.
    pub fn ttl(&self) -> Option<u8> {
        self.ttl
    }

    /// Returns the source IP address that responded to the probe.
    pub fn source_ip(&self) -> Option<IpAddr> {
        self.source_ip
    }

    /// Builder method to attach Round-Trip Time (RTT) telemetry.
    pub fn with_rtt(mut self, rtt: Duration) -> Self {
        self.rtt = Some(rtt);
        self
    }

    /// Builder method to attach packet TTL telemetry.
    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Builder method to attach the source IP of the responding interface.
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

    #[test]
    fn discovery_builder_pattern() {
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
