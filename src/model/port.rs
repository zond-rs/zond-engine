// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Ports, and what was found behind them
//!
//! A [`Port`] is one transport endpoint on one host, and everything a scan learned about
//! it, as three separately answered questions:
//!
//! | Question | Type |
//! |---|---|
//! | Is anything there? | [`PortState`], with [`discovery`]'s account of the packet that decided it |
//! | What is it? | [`Service`], refined as better evidence arrives |
//! | How is it protected? | [`Security`], for an endpoint that negotiated TLS |
//!
//! Each is an `Option`, and absent means not answered. A scan that has not run service
//! detection leaves [`Port::service`] empty, so a later pass can tell what it has yet to
//! look at from what it could not identify.
//!
//! ## Merging is how a port is built
//!
//! Techniques run in sequence, a connect fallback may repeat what a raw scan asked, and
//! service detection arrives afterwards. [`Port::merge`] folds one probe's account into
//! another. [`Service`] and [`Security`] carry their own merge rules; a [`Discovery`],
//! the account of a single packet, is taken or discarded whole.
//!
//! In every case a tie keeps what is already recorded, so a report does not depend on
//! which probe finished last.
//!
//! ## Which ports to ask about
//!
//! [`PortSet`] is what a caller asked for. [`catalog`] is the default: a ranked list of
//! the ports most likely to be listening, from which [`PortSet::top_tcp`] takes a
//! prefix. The module says where the ranking comes from.

pub mod build;
pub mod catalog;
pub mod discovery;
pub mod security;
pub mod service;
pub mod set;

pub use build::{Build, Distributor, Release, ReleaseBasis};
pub use catalog::{TCP_BY_PREVALENCE, UDP_BY_PREVALENCE};
pub use discovery::{Discovery, ScanResponse};
pub use security::{CertificateInfo, Security};
pub use service::Service;
pub use set::{PortSet, PortSetParseError};

use std::collections::BTreeMap;

use crate::model::finding::{ClaimId, Finding, MAX_FINDINGS_PER_SUBJECT};

/// Supported transport layer protocols.
///
/// Ordered, so a set of protocols has one canonical rendering.
///
/// A variant exists only once a scanner can speak it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    /// TCP. Probed by every technique in
    /// [`TcpScanTechnique`](crate::model::technique::TcpScanTechnique), and the
    /// only protocol the unprivileged connect fallback can speak.
    Tcp,
    /// UDP. Answered by a service that recognises the payload, by an ICMP port
    /// unreachable, or most often by nothing, so silence means
    /// [`PortState::OpenOrNoReply`].
    Udp,
    /// SCTP. Probed with an INIT chunk, which a listener accepts and a stack with
    /// nothing there refuses, so both verdicts come from one exchange as with a SYN
    /// scan.
    ///
    /// Carries Diameter, S1AP and M3UA, so a mobile core can look empty to a TCP and
    /// UDP scan.
    Sctp,
}

impl Protocol {
    /// Every transport this build can probe, in declaration order.
    ///
    /// The export conformance suite checks this against the schema's list.
    ///
    /// A slice, like every `ALL` in this crate, so a new variant is not a breaking
    /// change. Iterate it; do not treat it as complete.
    pub const ALL: &'static [Self] = &[Self::Tcp, Self::Udp, Self::Sctp];

    /// What a written port specification puts in front of this protocol's
    /// ports: nothing for TCP, `u:` for UDP, `s:` for SCTP.
    ///
    /// A specification is TCP until a qualifier says otherwise, and a qualifier holds
    /// until the next. This is the spelling for a specification listing TCP first, as
    /// [`PortSet`] renders it. TCP ports written after another protocol's need `t:`.
    pub const fn spec_prefix(self) -> &'static str {
        match self {
            Self::Tcp => "",
            Self::Udp => "u:",
            Self::Sctp => "s:",
        }
    }

    /// The qualifier that switches a written specification to this protocol:
    /// `t:`, `u:` or `s:`.
    ///
    /// A qualifier holds until the next one, so getting back to TCP needs `t:`:
    /// `u:53,t:80`. [`spec_prefix`](Self::spec_prefix) leaves it off for TCP listed
    /// first.
    pub(crate) const fn qualifier(self) -> &'static str {
        match self {
            Self::Tcp => "t:",
            Self::Udp | Self::Sctp => self.spec_prefix(),
        }
    }
}

/// What a scan established about a port.
///
/// Ordered from least definitive to most, so [`Port::merge`] promotes by comparison.
///
/// The ordering ranks evidence in three tiers.
///
/// - **`Unasked`** is lowest: no evidence at all.
/// - **The silences** come next: `ClosedOrNoReply`, `OpenOrNoReply`,
///   `NoReply`. Each is drawn from nothing arriving, so any packet outranks
///   all of them, whichever probe drew it. Among them the one that admits
///   fewer readings ranks higher: a SYN every live stack answers, drawing
///   nothing, is narrower than a FIN an open port may ignore. An idle scan's
///   `ClosedOrNoReply` is lowest, read off a third party's counter rather
///   than anything the target sent.
/// - **The packets**: `Blocked` (a refusal from the host or the path), then
///   `Reachable` and `Closed` (the host's own stack), then `Open`. `Open`
///   outranks `Closed` because a SYN+ACK settles the question where a RST does
///   not always: a stack that resets every segment it did not expect answers
///   a flag probe to an open port with one too.
///
/// Merging keeps the higher state; it does not intersect what two readings allow,
/// because a silence describes the probe as much as the port. A filter may pass an ACK
/// and drop a SYN, so `Reachable` plus `OpenOrNoReply` does not establish `Open`. The
/// result is always a verdict some single probe drew.
///
/// A cause is named only where a packet showed it: [`Blocked`](Self::Blocked) is a
/// refusal someone sent, [`NoReply`](Self::NoReply) is silence, and where silence is
/// also what an open or closed port would say, the state names both readings.
///
/// Which reply produces which state depends on the probe that drew it, since a
/// RST means a closed port to a SYN and a reachable one to an ACK. That
/// mapping lives in
/// [`TcpScanTechnique`](crate::model::technique::TcpScanTechnique).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PortState {
    /// No verdict was reached, so nothing was established either way.
    ///
    /// The question was never put: the scan ran out of wall clock with targets queued,
    /// the host spent
    /// [`ZondConfig::host_timeout`](crate::config::ZondConfig::host_timeout) first, or
    /// the operating system refused to send the probe. Or the scan stopped before the
    /// answer had the time the retry schedule allows.
    ///
    /// Such a port stays on the record, so a truncated port list can be told from a
    /// complete one, and an unasked port is not confused with a silent one.
    ///
    /// As the bottom of the ordering it never overrides anything.
    Unasked,

    /// Closed, or no reply, and the probe cannot say which. What an idle scan
    /// concludes when the target's IP ID did not advance: a closed port and a
    /// port whose probes never arrived both leave the zombie's counter alone.
    ClosedOrNoReply,

    /// Open, or no reply. The verdict for a probe whose positive result *is* silence: a
    /// bare FIN an open port must ignore, or a UDP payload no service recognised.
    OpenOrNoReply,

    /// Asked on every attempt the retry schedule allows, and nothing came back.
    ///
    /// Recorded only for techniques every live stack would answer, so the likeliest
    /// cause is a filter, though a lost probe or a late answer reads the same. See
    /// [`silence_means`](crate::model::technique::TcpScanTechnique::silence_means).
    NoReply,

    /// Something refused the probe in words: an ICMP unreachable that did not
    /// mean a closed port, such as an administrative prohibition, from the host
    /// or from somewhere on the path.
    ///
    /// A packet, so it ranks above [`NoReply`](Self::NoReply). Whether the target or a
    /// device in front of it refused is on the port's [`Discovery`] and the host's
    /// evidence.
    Blocked,

    /// The probe reached the host's stack and nothing dropped it on the way,
    /// but whether anything is listening was not asked. What an ACK scan
    /// establishes from the RST a live stack sends to any stray ACK.
    Reachable,

    /// Nothing is listening. A RST answering a SYN says so outright.
    Closed,

    /// Something is listening and accepted the connection attempt. Only a SYN
    /// draws the SYN+ACK that establishes this.
    ///
    /// The SYN need not have been this scan's: a listener may see a handshake completed
    /// for a real client, which does not show this machine can reach the endpoint.
    /// [`Discovery::reason`](discovery::Discovery::reason) tells the two apart; check it
    /// before acting on an open port from a merged report.
    Open,
}

impl PortState {
    /// Every state a port can be recorded in, in declaration order, which is
    /// least definitive first and is the order this type's [`Ord`] ranks by.
    ///
    /// Checked against the exported schema, as [`Protocol::ALL`] is. The order matters
    /// for a caller rendering a legend; `model`'s test holds it to declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Unasked,
        Self::ClosedOrNoReply,
        Self::OpenOrNoReply,
        Self::NoReply,
        Self::Blocked,
        Self::Reachable,
        Self::Closed,
        Self::Open,
    ];
}

/// Folds `port` into `ports`, merging it into the record already held for the
/// same endpoint, keyed as [`Host`](crate::model::host::Host) keys its own.
///
/// For a reader gathering a host's ports before the host exists. Folding as they arrive
/// bounds the cost by the endpoints, however often a document repeats one.
#[cfg(any(feature = "import-json", feature = "import-nmap"))]
pub(crate) fn fold(ports: &mut BTreeMap<(u16, Protocol), Port>, port: Port) {
    match ports.entry((port.number, port.protocol)) {
        std::collections::btree_map::Entry::Occupied(slot) => slot.into_mut().merge(port),
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert(port);
        }
    }
}

/// One transport endpoint on one host, and everything a scan learned about it.
///
/// The number and protocol identify it; everything else is a finding, absent until
/// something establishes it. See the module documentation.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    /// The 16-bit port number.
    number: u16,

    /// The transport protocol this endpoint is reached over.
    protocol: Protocol,

    /// What a probe established about it.
    state: PortState,

    /// What is listening, and how sure the identification is.
    ///
    /// Boxed, as [`security`](Self::security) is: a full-range scan holds 65,535 ports
    /// per host, nearly all without either.
    service: Option<Box<Service>>,

    /// What a TLS handshake negotiated, for an endpoint that completed one.
    security: Option<Box<Security>>,

    /// The packet that settled [`state`](Self::state), and what it carried.
    ///
    /// Inline, since nearly every port has one.
    discovery: Option<Discovery>,

    /// What a detection concluded was wrong with this endpoint, keyed on the
    /// claim so that the same finding reached twice records once.
    ///
    /// Per-port findings, such as a vulnerable service; cross-host ones are on the
    /// [`Host`](crate::model::host::Host). Bounded by [`MAX_FINDINGS_PER_SUBJECT`], and
    /// folded through [`Finding::corroborate`] when a detection re-fires.
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
    /// Promotes and never lowers, on the ordering [`merge`](Self::merge) uses.
    pub fn set_state(&mut self, state: PortState) {
        self.state = std::cmp::max(self.state, state);
    }

    /// What is listening, if anything identified it.
    pub fn service(&self) -> Option<&Service> {
        self.service.as_deref()
    }

    /// Returns the high-level service name (e.g. `"ssh"`), if one was
    /// identified.
    ///
    /// The name alone; [`service`](Self::service) has the version, product and
    /// confidence.
    pub fn service_name(&self) -> Option<&str> {
        self.service.as_ref().map(|s| s.name())
    }

    /// Records a service identification, replacing any already held.
    ///
    /// To refine an identification, merge into [`service`](Self::service); see
    /// [`Service::merge`].
    pub fn set_service(&mut self, service: Service) {
        self.service = Some(Box::new(service));
    }

    /// What a TLS handshake negotiated here, if one completed.
    pub fn security(&self) -> Option<&Security> {
        self.security.as_deref()
    }

    /// Records what a handshake negotiated, replacing anything already held.
    pub fn set_security(&mut self, security: Security) {
        self.security = Some(Box::new(security));
    }

    /// The account of the packet that settled this port's state, if there is
    /// one. An unprivileged connect attempt produces none.
    pub fn discovery(&self) -> Option<&Discovery> {
        self.discovery.as_ref()
    }

    /// Builder form of [`set_service`](Self::set_service).
    pub fn with_service(mut self, service: Service) -> Self {
        self.set_service(service);
        self
    }

    /// Builder form of [`set_security`](Self::set_security).
    pub fn with_security(mut self, security: Security) -> Self {
        self.set_security(security);
        self
    }

    /// Attaches the account of the packet that settled this port's state.
    pub fn with_discovery(mut self, discovery: Discovery) -> Self {
        self.discovery = Some(discovery);
        self
    }

    /// This port's findings, in a stable order.
    ///
    /// What is wrong with the service listening here, ordered by claim.
    pub fn findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.values()
    }

    /// Records a finding about this port, and reports whether it was new
    /// information: a claim not seen before, or a stronger reading of one that
    /// was.
    ///
    /// A finding reached again folds into the one on record through
    /// [`Finding::corroborate`]. The ceiling ([`MAX_FINDINGS_PER_SUBJECT`]) turns away
    /// only new claims.
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

    /// Replaces every correlation `detection` drew on this port with
    /// `findings`, and reports whether anything changed.
    ///
    /// A correlation is computed from the service identification and its data, so a new
    /// computation replaces the old; folding would keep claims it no longer makes.
    /// Other detections' findings are left alone.
    pub(crate) fn replace_correlations(&mut self, detection: &str, findings: Vec<Finding>) -> bool {
        let drawn_by_it =
            |finding: &Finding| finding.is_correlation() && finding.detection().id() == detection;
        let before: Vec<Finding> = self
            .findings
            .values()
            .filter(|finding| drawn_by_it(finding))
            .cloned()
            .collect();
        self.findings.retain(|_, finding| !drawn_by_it(finding));
        for finding in findings {
            self.add_finding(finding);
        }
        let after: Vec<&Finding> = self
            .findings
            .values()
            .filter(|finding| drawn_by_it(finding))
            .collect();
        before.len() != after.len() || before.iter().zip(after).any(|(a, b)| a != b)
    }

    /// Withdraws each correlation a newer version of the same detection also
    /// judged this port for, and reports whether any went.
    ///
    /// For a record folded from several accounts: an older catalogue's or correlator's
    /// correlations are superseded as a whole, since a newer correlator may key its
    /// claims differently.
    pub(crate) fn retire_superseded_correlations(&mut self) -> bool {
        let mut newest: BTreeMap<String, crate::model::finding::Version> = BTreeMap::new();
        for finding in self.findings.values().filter(|f| f.is_correlation()) {
            let version = finding.detection().version();
            newest
                .entry(finding.detection().id().to_owned())
                .and_modify(|held| *held = (*held).max(version))
                .or_insert(version);
        }
        let before = self.findings.len();
        self.findings.retain(|_, finding| {
            !finding.is_correlation()
                || newest
                    .get(finding.detection().id())
                    .is_none_or(|&newest| finding.detection().version() >= newest)
        });
        self.findings.len() != before
    }

    /// Folds another probe's account of this same endpoint into this one.
    ///
    /// The state rises to the more definitive and never falls. Service and security
    /// fold by their own rules, and findings accumulate, a shared claim corroborating.
    /// The discovery record follows the state: only a probe that raised the verdict
    /// replaces it.
    ///
    /// # Panics
    ///
    /// In debug builds, if `other` describes a different endpoint (TCP/53 into UDP/53,
    /// say). [`Host`](crate::model::host::Host) keys on both and cannot reach this.
    pub fn merge(&mut self, other: Port) {
        debug_assert_eq!(
            (self.number, self.protocol),
            (other.number, other.protocol),
            "merging two different endpoints into one record"
        );

        // Destructured, so a new field fails to compile until it is merged.
        let Port {
            // Checked by the assertion above.
            number: _,
            protocol: _,
            state,
            service,
            security,
            discovery,
            findings,
        } = other;

        // Taken before the state moves, for judging the telemetry below.
        let previous_state = self.state;

        self.state = std::cmp::max(self.state, state);

        if let Some(service) = service {
            match &mut self.service {
                Some(recorded) => recorded.merge(*service),
                None => self.service = Some(service),
            }
        }

        if let Some(security) = security {
            match &mut self.security {
                Some(recorded) => recorded.merge(*security),
                None => self.security = Some(security),
            }
        }

        // The telemetry explains the state, so it follows the state: a probe that
        // raised the verdict brings its account. A tie keeps the incumbent. A port
        // with no telemetry takes whatever is offered.
        if discovery.is_some() && (state > previous_state || self.discovery.is_none()) {
            self.discovery = discovery;
        }

        // A claim missing from one record is a detection that did not run there, so
        // a fold only adds; a claim on both corroborates through `add_finding`.
        for finding in findings.into_values() {
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

    /// A probe that learned more replaces the verdict; one that learned less does not.
    #[test]
    fn a_probe_that_learned_more_raises_the_verdict() {
        // NoReply -> Open
        let mut p1 = Port::new(80, Protocol::Tcp, PortState::NoReply);
        p1.merge(Port::new(80, Protocol::Tcp, PortState::Open));
        assert_eq!(p1.state(), PortState::Open);

        // OpenOrNoReply -> Open
        let mut p2 = Port::new(53, Protocol::Udp, PortState::OpenOrNoReply);
        p2.merge(Port::new(53, Protocol::Udp, PortState::Open));
        assert_eq!(p2.state(), PortState::Open);

        // Reachable -> Closed
        let mut p3 = Port::new(443, Protocol::Tcp, PortState::Reachable);
        p3.merge(Port::new(443, Protocol::Tcp, PortState::Closed));
        assert_eq!(p3.state(), PortState::Closed);
    }

    /// A refusal outranks silence, whichever probe finished first.
    #[test]
    fn a_refusal_outranks_a_silence_in_either_order() {
        assert!(PortState::NoReply < PortState::Blocked);

        let mut refused = Port::new(80, Protocol::Tcp, PortState::Blocked);
        refused.merge(Port::new(80, Protocol::Tcp, PortState::NoReply));
        assert_eq!(refused.state(), PortState::Blocked);

        let mut silent = Port::new(80, Protocol::Tcp, PortState::NoReply);
        silent.merge(Port::new(80, Protocol::Tcp, PortState::Blocked));
        assert_eq!(silent.state(), PortState::Blocked);
    }

    /// A packet outranks a silence, whichever probe drew which.
    ///
    /// A FIN scan's silence does not undo a SYN scan's reset, and a later UDP silence
    /// does not undo an earlier port unreachable (as a host rationing ICMP errors would
    /// produce).
    #[test]
    fn a_silence_never_outranks_a_packet() {
        let silences = [
            PortState::ClosedOrNoReply,
            PortState::OpenOrNoReply,
            PortState::NoReply,
        ];
        let packets = [
            PortState::Blocked,
            PortState::Reachable,
            PortState::Closed,
            PortState::Open,
        ];
        for silence in silences {
            for packet in packets {
                assert!(silence < packet, "{silence:?} outranks {packet:?}");

                let mut first = Port::new(80, Protocol::Tcp, silence);
                first.merge(Port::new(80, Protocol::Tcp, packet));
                assert_eq!(first.state(), packet, "{packet:?} over {silence:?}");

                let mut first = Port::new(80, Protocol::Tcp, packet);
                first.merge(Port::new(80, Protocol::Tcp, silence));
                assert_eq!(first.state(), packet, "{silence:?} over {packet:?}");
            }
        }
    }

    /// Among silences, the one that admits fewer readings wins.
    ///
    /// A SYN's silence is narrower than a FIN's, so it is kept.
    #[test]
    fn a_syn_silence_narrows_a_flag_probe_silence() {
        let mut port = Port::new(80, Protocol::Tcp, PortState::OpenOrNoReply);
        port.merge(Port::new(80, Protocol::Tcp, PortState::NoReply));
        assert_eq!(port.state(), PortState::NoReply);
    }

    /// A probe that did not improve the verdict does not replace its telemetry.
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

    /// A port with no telemetry takes a losing probe's.
    #[test]
    fn a_port_with_no_telemetry_adopts_a_weaker_probes() {
        let mut open = Port::new(22, Protocol::Tcp, PortState::Open);
        let silent = Port::new(22, Protocol::Tcp, PortState::NoReply)
            .with_discovery(Discovery::new(ScanResponse::NoResponse));

        open.merge(silent);

        assert_eq!(open.state(), PortState::Open, "the weaker state loses");
        assert_eq!(
            open.discovery().expect("adopted").reason(),
            &ScanResponse::NoResponse,
            "but its account of itself is better than none"
        );
    }

    /// `Unasked` never overrides anything, in either direction.
    #[test]
    fn an_unasked_port_loses_to_every_verdict() {
        for &verdict in PortState::ALL {
            if verdict == PortState::Unasked {
                continue;
            }
            assert!(
                PortState::Unasked < verdict,
                "{verdict:?} does not outrank a port nobody probed"
            );
        }

        let mut probed = Port::new(22, Protocol::Tcp, PortState::Closed);
        probed.merge(Port::new(22, Protocol::Tcp, PortState::Unasked));
        assert_eq!(
            probed.state(),
            PortState::Closed,
            "a later sitting that never asked unlearned the first one's answer"
        );

        let mut unasked = Port::new(22, Protocol::Tcp, PortState::Unasked);
        unasked.merge(Port::new(22, Protocol::Tcp, PortState::Closed));
        assert_eq!(unasked.state(), PortState::Closed);
    }

    /// Replacing the verdict replaces its telemetry.
    #[test]
    fn telemetry_follows_the_verdict_it_explains() {
        let disc_silent = Discovery::new(ScanResponse::NoResponse);
        let mut p_silent =
            Port::new(22, Protocol::Tcp, PortState::NoReply).with_discovery(disc_silent.clone());

        let disc_open = Discovery::new(ScanResponse::TcpSynAck);
        let p_open =
            Port::new(22, Protocol::Tcp, PortState::Open).with_discovery(disc_open.clone());

        // The state and the telemetry both upgrade.
        p_silent.merge(p_open);

        assert_eq!(p_silent.state(), PortState::Open);
        assert_eq!(
            p_silent.discovery().unwrap().reason(),
            &ScanResponse::TcpSynAck
        );
    }

    /// An unanswered port pays at most a pointer for each empty half; a full-range scan
    /// keeps 65,535 per host.
    #[test]
    fn an_unanswered_port_pays_a_pointer_for_what_it_did_not_learn() {
        use std::mem::size_of;

        let carried = size_of::<(u16, Protocol, PortState)>()
            + size_of::<Option<Discovery>>()
            + size_of::<BTreeMap<ClaimId, Finding>>();
        let absent = 2 * size_of::<usize>();
        let padding = std::mem::align_of::<Port>();

        assert!(
            size_of::<Port>() <= carried + absent + padding,
            "a port record is {} bytes where what an unanswered port holds is {carried}",
            size_of::<Port>(),
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
        // A merge that forgot findings would report a clean port.
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
