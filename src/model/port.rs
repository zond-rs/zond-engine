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
//! learned about it. That covers three separate questions, kept in three
//! separate types so that a scan answering one of them does not have to pretend
//! it answered the rest:
//!
//! | Question | Type |
//! |---|---|
//! | Is anything there? | [`PortState`], with [`discovery`]'s account of the packet that decided it |
//! | What is it? | [`Service`], refined as better evidence arrives |
//! | How is it protected? | [`Security`], for an endpoint that negotiated TLS |
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
//! arrives afterwards. [`Port::merge`] folds one probe's account into another,
//! and the rules it merges by are the substance of this module. [`Service`] and
//! [`Security`] carry their own, since each knows what makes one of its findings
//! better than another; a [`Discovery`] is taken or discarded whole, because it
//! is the account of a single packet and half of one explains nothing.
//!
//! They agree on one thing: a tie keeps what is already recorded. Two probes
//! that learned the same amount are equally good sources, and preferring the
//! later one would make a report depend on which probe happened to finish
//! last.
//!
//! ## Which ports to ask about in the first place
//!
//! [`PortSet`] is what a caller asked for, and [`catalog`] is what this crate
//! answers when they asked for nothing: a ranked list of the ports most likely
//! to be listening, from which [`PortSet::top_tcp`] takes a prefix. It is a
//! deliberate opinion rather than a neutral default, and the module says where
//! the opinion comes from.

pub mod catalog;
pub mod discovery;
pub mod security;
pub mod service;
pub mod set;

pub use catalog::{TCP_BY_PREVALENCE, UDP_BY_PREVALENCE};
pub use discovery::{Discovery, ScanResponse};
pub use security::{CertificateInfo, Security};
pub use service::Service;
pub use set::{PortSet, PortSetParseError};

use std::collections::BTreeMap;

use crate::model::finding::{ClaimId, Finding, MAX_FINDINGS_PER_SUBJECT};

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
    /// Closed or filtered, and the probe cannot say which. What an idle scan
    /// concludes when the target's IP ID did not advance.
    ClosedFiltered,

    /// Something dropped the probe. The lowest state a scan will record from
    /// silence alone, and only for the techniques every live stack would have
    /// answered — see
    /// [`silence_means`](crate::model::technique::TcpScanTechnique::silence_means).
    Filtered,

    /// The probe reached the host's stack and nothing dropped it on the way,
    /// but whether anything is listening was not asked. What an ACK scan
    /// establishes.
    Unfiltered,

    /// Nothing is listening. A RST answering a SYN says so outright.
    Closed,

    /// Open, or silently dropped. The honest verdict for a probe whose positive
    /// result *is* silence: a bare FIN that an open port is required to ignore,
    /// or a UDP payload no service recognised.
    OpenFiltered,

    /// Something is listening and accepted the connection attempt. Only a SYN
    /// draws the SYN+ACK that establishes this.
    ///
    /// **The SYN need not have been ours.** A listener reading a segment off the
    /// wire sees the same handshake completed for somebody else, which
    /// establishes the same thing — and in one respect more, since what was
    /// accepted was a real client rather than a knock. What it does *not*
    /// establish is that this machine could reach the endpoint: the peer and the
    /// path were somebody else's.
    ///
    /// [`Discovery::reason`](discovery::Discovery::reason) is what tells the two
    /// apart, and it is worth reading before acting on an open port from a
    /// merged report.
    Open,
}

/// One transport endpoint on one host, and everything a scan learned about it.
///
/// The number and protocol identify it; everything else is a finding, and is
/// absent until something establishes it. See the module documentation for what
/// the four optional halves each answer and why they are kept apart.
#[must_use]
#[derive(Debug, Clone, PartialEq)]
pub struct Port {
    /// The 16-bit port number.
    number: u16,

    /// The transport protocol this endpoint is reached over.
    protocol: Protocol,

    /// What a probe established about it.
    state: PortState,

    /// What is listening, and how sure the identification is.
    service: Option<Service>,

    /// What a TLS handshake negotiated, for an endpoint that completed one.
    security: Option<Security>,

    /// The packet that settled [`state`](Self::state), and what it carried.
    discovery: Option<Discovery>,

    /// What a detection concluded was wrong with this endpoint, keyed on the
    /// claim so that the same finding reached twice records once.
    ///
    /// The per-port findings — a vulnerable service, a weak configuration on the
    /// thing listening here — as distinct from the cross-host findings a
    /// [`Host`](crate::model::host::Host) carries. Bounded by
    /// [`MAX_FINDINGS_PER_SUBJECT`], and folded through [`Finding::corroborate`]
    /// when a detection re-fires.
    findings: BTreeMap<ClaimId, Finding>,
}

impl Port {
    /// A port in `state`, with nothing yet established about what is behind it.
    pub fn new(number: u16, protocol: Protocol, state: PortState) -> Self {
        Self {
            number,
            protocol,
            state,
            service: None,
            security: None,
            discovery: None,
            findings: BTreeMap::new(),
        }
    }

    /// The 16-bit port number.
    pub fn number(&self) -> u16 {
        self.number
    }

    /// The transport this endpoint is reached over.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// What a probe established about this port.
    pub fn state(&self) -> PortState {
        self.state
    }

    /// Raises the recorded state to `state`, if that is more definitive.
    ///
    /// Promotes and never lowers, on the same ordering [`merge`](Self::merge)
    /// uses. A second probe that learned less about a port does not get to
    /// unlearn what the first established.
    pub fn set_state(&mut self, state: PortState) {
        self.state = std::cmp::max(self.state, state);
    }

    /// What is listening, if anything identified it.
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

    /// Records a service identification, replacing any already held.
    ///
    /// A caller refining an identification rather than replacing it should
    /// merge into [`service`](Self::service) instead; see [`Service::merge`].
    pub fn set_service(&mut self, service: Service) {
        self.service = Some(service);
    }

    /// What a TLS handshake negotiated here, if one completed.
    pub fn security(&self) -> Option<&Security> {
        self.security.as_ref()
    }

    /// Records what a handshake negotiated, replacing anything already held.
    pub fn set_security(&mut self, security: Security) {
        self.security = Some(security);
    }

    /// The account of the packet that settled this port's state, if there is
    /// one. An unprivileged connect attempt produces none.
    pub fn discovery(&self) -> Option<&Discovery> {
        self.discovery.as_ref()
    }

    /// Builder form of [`set_service`](Self::set_service).
    pub fn with_service(mut self, service: Service) -> Self {
        self.service = Some(service);
        self
    }

    /// Builder form of [`set_security`](Self::set_security).
    pub fn with_security(mut self, security: Security) -> Self {
        self.security = Some(security);
        self
    }

    /// Attaches the account of the packet that settled this port's state.
    pub fn with_discovery(mut self, discovery: Discovery) -> Self {
        self.discovery = Some(discovery);
        self
    }

    /// This port's findings, in a stable order.
    ///
    /// What is wrong with the service listening here. Ordered by claim, so two
    /// runs that found the same things render them the same way.
    pub fn findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.values()
    }

    /// Records a finding about this port, and reports whether it was new
    /// information — a claim not seen before, or a stronger reading of one that
    /// was.
    ///
    /// A finding reached again folds into the one on record through
    /// [`Finding::corroborate`] rather than accumulating. The ceiling
    /// ([`MAX_FINDINGS_PER_SUBJECT`]) turns away only a genuinely new claim.
    pub fn add_finding(&mut self, finding: Finding) -> bool {
        let claim = finding.claim_id();

        let full = self.findings.len() >= MAX_FINDINGS_PER_SUBJECT;

        match self.findings.get_mut(&claim) {
            Some(existing) => existing.corroborate(finding),
            None if full => false,
            None => {
                self.findings.insert(claim, finding);
                true
            }
        }
    }

    /// Folds another probe's account of this same endpoint into this one.
    ///
    /// The state rises to whichever of the two is the more definitive and never
    /// falls. Service and security details fold by their own confidence rules,
    /// and findings accumulate, a claim on both sides corroborating rather than
    /// landing twice. The discovery record follows the state: only a probe that
    /// raised the verdict replaces it, so a tie leaves the account already on
    /// record in place.
    ///
    /// # Panics
    ///
    /// In debug builds, if `other` describes a different endpoint. A number
    /// names one endpoint per transport, so merging TCP/53 into UDP/53 produces
    /// a record of neither. [`Host`](crate::model::host::Host) keys on both and
    /// cannot reach this; a caller merging by hand can.
    pub fn merge(&mut self, other: Port) {
        debug_assert_eq!(
            (self.number, self.protocol),
            (other.number, other.protocol),
            "merging two different endpoints into one record"
        );

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

        // 5. Merge findings. A claim missing from one record is a detection that
        // did not run there, not a retraction, so a fold adds and never removes;
        // a claim on both corroborates through `add_finding`.
        for finding in other.findings.into_values() {
            self.add_finding(finding);
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

    /// A second probe that learned more replaces the verdict; one that learned
    /// less does not. The ordering on [`PortState`] is what decides, so these
    /// pin the three promotions a scan actually performs.
    #[test]
    fn a_probe_that_learned_more_raises_the_verdict() {
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

    /// The telemetry explains the verdict, so when the verdict is replaced the
    /// account of it has to be replaced too — the RTT and TTL of a `NoResponse`
    /// say nothing about a port something has since answered on.
    #[test]
    fn telemetry_follows_the_verdict_it_explains() {
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

    fn a_finding(detection_id: &str) -> Finding {
        use crate::model::confidence::Confidence;
        use crate::model::finding::{DetectionClass, DetectionId, Severity, Version};
        Finding::new(
            DetectionId::new(detection_id, Version::new(1, 0, 0), "hash").unwrap(),
            "A port finding",
            Severity::High,
            Confidence::Certain,
            DetectionClass::ActiveBenign,
        )
        .unwrap()
    }

    #[test]
    fn a_merge_keeps_both_ports_findings() {
        // The silent failure: a merge that folds state and service but forgets
        // findings reports a clean port that had one.
        let mut base = Port::new(443, Protocol::Tcp, PortState::Open);
        base.add_finding(a_finding("det-a"));

        let mut other = Port::new(443, Protocol::Tcp, PortState::Open);
        other.add_finding(a_finding("det-b"));

        base.merge(other);

        assert_eq!(
            base.findings().count(),
            2,
            "a merge must not drop the other's findings"
        );
    }
}
