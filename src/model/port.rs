// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Port Discovery and Metadata
//!
//! This module defines the core types for identifying and detailing network services.
//! It is architected for future-proof service fingerprinting, security analysis,
//! and structured script execution telemetry.

use std::collections::HashMap;

pub mod discovery;
pub mod security;
pub mod service;
pub mod set;

pub use discovery::{Discovery, ScanResponse};
pub use security::{CertificateInfo, Security};
pub use service::Service;
pub use set::{PortSet, PortSetParseError};

/// Supported transport layer protocols.
///
/// Ordered so that a set of protocols has one canonical rendering, which is what
/// keeps two scans of the same targets producing byte-identical reports.
///
/// **A variant exists here only once a scanner speaks it.** SCTP was listed
/// before anything could probe it, and the cost was not the unused name: every
/// `match` over this enum had to invent an answer for a case that never
/// occurred, and [`PortSet`] invented the wrong one — it collected SCTP ports
/// into a vector it never stored, so they vanished with no error. A protocol
/// that cannot be probed is better absent than present and mishandled, and
/// adding one back is a deliberate act that the compiler will walk through every
/// site that has to decide something about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// The reachability state of a specific port.
///
/// The order of these variants is strictly defined from least definitive to
/// most definitive. This allows `Port::merge()` to automatically upgrade
/// ambiguous states into concrete ones using standard Ord comparisons.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PortState {
    /// State is ambiguous; port is either closed or filtered (e.g., IP ID idle scan).
    ClosedFiltered,

    /// Packets are being dropped silently by a firewall. We received no response.
    Filtered,

    /// Target is accessible, but we cannot determine if it is open or closed (e.g., TCP ACK scan).
    Unfiltered,

    /// Actively rejecting connections (e.g., TCP RST received).
    Closed,

    /// State is ambiguous; port might be open, or packets might be silently dropped (e.g., UDP scan).
    OpenFiltered,

    /// Actively accepting connections (e.g., TCP SYN/ACK received).
    Open,
}

/// Structured data returned by a scanning script or vulnerability engine.
///
/// Replaces legacy stringly-typed script outputs, allowing modern engines
/// to return complex nested data (e.g., parsed JSON directories, lists of CVEs).
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptOutput {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    List(Vec<ScriptOutput>),
    Map(HashMap<String, ScriptOutput>),
}

/// A comprehensive "Rich" model representing a service endpoint discovered on a host.
///
/// Unlike a simple port number, a `Port` captures the full lifecycle of a service:
/// how it was found, its security posture, and its functional identity.
#[derive(Debug, Clone, PartialEq)]
pub struct Port {
    /// The 16-bit port number.
    number: u16,

    /// The transport protocol (TCP/UDP/SCTP).
    protocol: Protocol,

    /// The discovered state of the port.
    state: PortState,

    /// Rich service identity (e.g., "OpenSSH 8.9", CPE strings).
    service: Option<Service>,

    /// Security/Encryption details (TLS certificate, negotiated ciphers).
    security: Option<Security>,

    /// Low-level discovery telemetry (TTL, reason for state, RTT).
    discovery: Option<Discovery>,

    /// Extensible map for scan scripts and custom detection engines.
    /// Wrapped in an Option to avoid heap allocation for filtered/dropped ports.
    scripts: Option<HashMap<String, ScriptOutput>>,
}

impl Port {
    /// Creates a new, basic Port instance.
    pub fn new(number: u16, protocol: Protocol, state: PortState) -> Self {
        Self {
            number,
            protocol,
            state,
            service: None,
            security: None,
            discovery: None,
            scripts: None,
        }
    }

    /// Returns the port number.
    pub fn number(&self) -> u16 {
        self.number
    }

    /// Returns the transport protocol.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Returns the current discovery state.
    pub fn state(&self) -> PortState {
        self.state
    }

    /// Updates the port discovery state.
    pub fn set_state(&mut self, state: PortState) {
        self.state = state;
    }

    /// Returns the service identification, if any.
    pub fn service(&self) -> Option<&Service> {
        self.service.as_ref()
    }

    /// Returns the high-level service name (e.g., "ssh"), if identified.
    ///
    /// This is a convenience helper for migrating from the legacy `service_info` model.
    pub fn service_name(&self) -> Option<&str> {
        self.service.as_ref().map(|s| s.name())
    }

    /// Sets or updates the service identification.
    pub fn set_service(&mut self, service: Service) {
        self.service = Some(service);
    }

    /// Returns the security/encryption telemetry, if any.
    pub fn security(&self) -> Option<&Security> {
        self.security.as_ref()
    }

    /// Sets or updates the security telemetry.
    pub fn set_security(&mut self, security: Security) {
        self.security = Some(security);
    }

    /// Returns the low-level discovery telemetry, if any.
    pub fn discovery(&self) -> Option<&Discovery> {
        self.discovery.as_ref()
    }

    /// Returns the script output map, if any.
    pub fn scripts(&self) -> Option<&HashMap<String, ScriptOutput>> {
        self.scripts.as_ref()
    }

    /// Builder method to attach service information.
    pub fn with_service(mut self, service: Service) -> Self {
        self.service = Some(service);
        self
    }

    /// Builder method to attach security metadata.
    pub fn with_security(mut self, security: Security) -> Self {
        self.security = Some(security);
        self
    }

    /// Builder method to attach low-level discovery telemetry.
    pub fn with_discovery(mut self, discovery: Discovery) -> Self {
        self.discovery = Some(discovery);
        self
    }

    /// Builder method to insert a structured script output.
    pub fn add_script(mut self, key: impl Into<String>, output: ScriptOutput) -> Self {
        let scripts = self.scripts.get_or_insert_with(HashMap::new);
        scripts.insert(key.into(), output);
        self
    }

    /// Merges architectural findings from another Port record into this one.
    ///
    /// Prioritizes the most definitive port state. Merges nested `Service`,
    /// `Security`, and `Discovery` metadata progressively.
    pub fn merge(&mut self, mut other: Port) {
        // The state this port held before the merge. Step 4 has to judge the
        // incoming telemetry against what it actually had to beat, and step 1
        // has already overwritten `self.state` by the time it runs.
        let previous_state = self.state;

        // 1. Merge State (Upgrades ambiguous states to definitive ones)
        self.state = std::cmp::max(self.state, other.state);

        // 2. Merge Service Info (Relies on Service's internal confidence logic)
        if let Some(other_service) = other.service {
            if let Some(ref mut self_service) = self.service {
                self_service.merge(other_service);
            } else {
                self.service = Some(other_service);
            }
        }

        // 3. Merge Security Info
        if let Some(other_security) = other.security {
            if let Some(ref mut self_security) = self.security {
                self_security.merge(other_security);
            } else {
                self.security = Some(other_security);
            }
        }

        // 4. Merge Discovery.
        //
        // The telemetry explains the state, so it follows the state. A probe
        // that upgraded this port carries the account of why it is now Open,
        // and that account replaces whatever explained the weaker verdict; a
        // probe that did not upgrade it explains a verdict this port no longer
        // holds, and the RTT and TTL of a `NoResponse` say nothing about a port
        // something has since answered on.
        //
        // A tie keeps the incumbent, which is the rule every other merge in
        // this module follows. Two probes reaching the same verdict are equally
        // good accounts of it, and preferring the later one would make the
        // recorded telemetry depend on which probe happened to finish last.
        //
        // A port with no telemetry at all takes whatever is offered: an
        // explanation of a weaker verdict still beats none.
        if other.discovery.is_some() && (other.state > previous_state || self.discovery.is_none()) {
            self.discovery = other.discovery;
        }

        // 5. Merge Scripts (Overwrite on key collision, assuming newer is better)
        if let Some(other_scripts) = other.scripts.take() {
            let self_scripts = self.scripts.get_or_insert_with(HashMap::new);
            for (key, value) in other_scripts {
                self_scripts.insert(key, value);
            }
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

    #[test]
    fn port_state_ordering_upgrades_correctly() {
        // Filtered -> Open
        let mut p1 = Port::new(80, Protocol::Tcp, PortState::Filtered);
        p1.merge(Port::new(80, Protocol::Tcp, PortState::Open));
        assert_eq!(p1.state(), PortState::Open);

        // OpenFiltered -> Open
        let mut p2 = Port::new(53, Protocol::Udp, PortState::OpenFiltered);
        p2.merge(Port::new(53, Protocol::Udp, PortState::Open));
        assert_eq!(p2.state(), PortState::Open);

        // Unfiltered -> Closed
        let mut p3 = Port::new(443, Protocol::Tcp, PortState::Unfiltered);
        p3.merge(Port::new(443, Protocol::Tcp, PortState::Closed));
        assert_eq!(p3.state(), PortState::Closed);
    }

    #[test]
    fn structured_scripts_merge_correctly() {
        let mut port = Port::new(80, Protocol::Tcp, PortState::Open)
            .add_script("http-title", ScriptOutput::String("Index".into()));

        // Add a complex nested script result
        let mut ssh_keys = HashMap::new();
        ssh_keys.insert("rsa".into(), ScriptOutput::Integer(2048));
        ssh_keys.insert("ed25519".into(), ScriptOutput::Integer(256));

        let other = Port::new(80, Protocol::Tcp, PortState::Open)
            .add_script("ssh-hostkey", ScriptOutput::Map(ssh_keys));

        port.merge(other);

        let scripts = port.scripts.as_ref().unwrap();
        assert_eq!(scripts.len(), 2);
        assert!(matches!(
            scripts.get("http-title"),
            Some(ScriptOutput::String(_))
        ));
        assert!(matches!(
            scripts.get("ssh-hostkey"),
            Some(ScriptOutput::Map(_))
        ));
    }

    /// Telemetry explains a verdict, so a probe that did not improve the
    /// verdict does not get to rewrite the account of it. Two probes reaching
    /// the same state are equally good accounts, and preferring the later one
    /// makes the record depend on which probe happened to finish last.
    #[test]
    fn a_tie_keeps_the_telemetry_already_on_record() {
        let mut first = Port::new(22, Protocol::Tcp, PortState::Open)
            .with_discovery(Discovery::new(ScanResponse::TcpSynAck).with_ttl(64));
        let second = Port::new(22, Protocol::Tcp, PortState::Open)
            .with_discovery(Discovery::new(ScanResponse::TcpSynAck).with_ttl(128));

        first.merge(second);

        assert_eq!(
            first.discovery().expect("telemetry survives").ttl(),
            Some(64)
        );
    }

    /// A probe that lost the state comparison still explains something, and a
    /// port holding no telemetry at all has nothing to lose by taking it.
    #[test]
    fn a_port_with_no_telemetry_adopts_a_weaker_probes() {
        let mut open = Port::new(22, Protocol::Tcp, PortState::Open);
        let filtered = Port::new(22, Protocol::Tcp, PortState::Filtered)
            .with_discovery(Discovery::new(ScanResponse::NoResponse));

        open.merge(filtered);

        assert_eq!(open.state(), PortState::Open, "the weaker state loses");
        assert_eq!(
            open.discovery().expect("adopted").reason(),
            &ScanResponse::NoResponse,
            "but its account of itself is better than none"
        );
    }

    #[test]
    fn discovery_telemetry_upgrades_on_better_state() {
        let disc_filtered = Discovery::new(ScanResponse::NoResponse);
        let mut p_filtered =
            Port::new(22, Protocol::Tcp, PortState::Filtered).with_discovery(disc_filtered.clone());

        let disc_open = Discovery::new(ScanResponse::TcpSynAck);
        let p_open =
            Port::new(22, Protocol::Tcp, PortState::Open).with_discovery(disc_open.clone());

        // Merging should upgrade the state AND the telemetry reason
        p_filtered.merge(p_open);

        assert_eq!(p_filtered.state(), PortState::Open);
        assert_eq!(
            p_filtered.discovery().unwrap().reason(),
            &ScanResponse::TcpSynAck
        );
    }
}
