// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Ports, and what was found behind them
//!
//! A [`Port`] is one transport endpoint on one host, and everything a scan
//! learned about it. That covers four separate questions, kept in four separate
//! types so that a scan answering one of them does not have to pretend it
//! answered the rest:
//!
//! | Question | Type |
//! |---|---|
//! | Is anything there? | [`PortState`], with [`discovery`]'s account of the packet that decided it |
//! | What is it? | [`Service`], refined as better evidence arrives |
//! | How is it protected? | [`Security`], for an endpoint that negotiated TLS |
//! | What did a script make of it? | [`ScriptOutput`] |
//!
//! Each is an `Option`, and an absent one means the question was not answered
//! rather than answered negatively. A port scan that has not run service
//! detection leaves [`Port::service`] empty rather than recording a service
//! named "unknown", because a later pass has to tell what it has yet to look at
//! apart from what it looked at and could not identify.
//!
//! ## Merging is how a port is built
//!
//! No single probe fills a `Port` in. Techniques run in sequence, a connect
//! fallback may repeat what a raw scan already asked, and service detection
//! arrives afterwards. Every one of these types therefore carries a `merge`, and
//! the rules they merge by are the substance of this module.
//!
//! They agree on one thing: a tie keeps what is already recorded. Two probes
//! that learned the same amount are equally good sources, and preferring the
//! later one would make a report depend on which probe happened to finish
//! last.

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
/// A variant exists here only once a scanner can speak it. A protocol nobody
/// can probe still forces every `match` over this enum to invent an answer for
/// a case that never arises, and those invented answers fail quietly. Adding one
/// is a deliberate act, and the compiler will walk you through every site that
/// has to decide something about it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    /// TCP. Probed by every technique in
    /// [`TcpScanTechnique`](crate::model::technique::TcpScanTechnique), and the
    /// only protocol the unprivileged connect fallback can speak.
    Tcp,
    /// UDP. Answered by a service that recognises the payload sent to it, by an
    /// ICMP port unreachable, or most often by nothing at all. That last case is
    /// why silence here means [`PortState::OpenFiltered`] rather than open.
    Udp,
}

/// What a scan established about a port.
///
/// Ordered from least definitive to most, so that [`Port::merge`] promotes by an
/// ordinary comparison and two probes that disagree resolve to whichever learned
/// more.
///
/// The ordering ranks evidence, not how alarming a state is. `Open` outranks
/// `Closed` because a SYN+ACK settles the question where a RST from a filtered
/// path does not, and the two ambiguous states sit below the states they are
/// ambiguous between.
///
/// Which reply produces which state depends on the probe that drew it, since a
/// RST means a closed port to a SYN and an unfiltered path to an ACK. That
/// mapping lives in
/// [`TcpScanTechnique`](crate::model::technique::TcpScanTechnique).
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

/// A value produced by a scanning script, in whatever shape the script found
/// it.
///
/// Typed rather than stringly-typed because the consumers are machines as often
/// as people: a list of CVEs, a table of host keys and their sizes, a boolean
/// verdict about a configuration. Rendered as a string at the point it was
/// gathered, each of those becomes something a report has to re-parse to do
/// anything with, and every exporter has to invent the same escaping.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptOutput {
    /// Free text: a banner, a title, a certificate subject.
    String(String),
    /// A whole number, such as a key size, a count or a version component.
    Integer(i64),
    /// A fractional measurement. Not every `f64` compares equal to itself, so a
    /// `Port` carrying a NaN here is never equal to itself either. That is why
    /// [`Port`] derives `PartialEq` and not `Eq`.
    Float(f64),
    /// A yes-or-no verdict.
    Boolean(bool),
    /// An ordered sequence, where the order is part of what was found.
    List(Vec<ScriptOutput>),
    /// Named fields. Unordered, so an exporter that needs a stable rendering
    /// sorts the keys itself.
    Map(HashMap<String, ScriptOutput>),
}

/// One transport endpoint on one host, and everything a scan learned about it.
///
/// The number and protocol identify it; everything else is a finding, and is
/// absent until something establishes it. See the module documentation for what
/// the four optional halves each answer and why they are kept apart.
#[derive(Debug, Clone, PartialEq)]
pub struct Port {
    /// The 16-bit port number.
    number: u16,

    /// The transport protocol this endpoint is reached over.
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

    /// Returns the high-level service name (e.g. `"ssh"`), if one was
    /// identified.
    ///
    /// The name alone, for a caller rendering a column of them.
    /// [`service`](Self::service) has the version, product and confidence that
    /// say how much the name is worth.
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
