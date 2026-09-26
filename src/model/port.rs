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
/// is a deliberate act, and the compiler names every site that has to decide
/// something about it.
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
    /// SCTP. Probed with an INIT chunk, which a listener answers by accepting
    /// the association and a stack with nothing there refuses outright, so both
    /// verdicts come from a single exchange the way a SYN scan's do.
    ///
    /// Carries Diameter, S1AP and M3UA, which is why a mobile core is the place
    /// a scan that asks about TCP and UDP alone reports an empty host.
    Sctp,
}

impl Protocol {
    /// Every transport this build can probe, in declaration order.
    ///
    /// The enum is `#[non_exhaustive]`, so nothing outside the crate can write
    /// an exhaustive list of its own and nothing inside should: a transport
    /// added without a name on the wire, or without a place in the exported
    /// schema, is a port that survives a scan and cannot be written down. The
    /// export conformance suite reads this and the schema's own list and fails
    /// unless they hold the same names.
    ///
    /// Every `ALL` in this crate is a slice, never a fixed-size array. An
    /// array's length is part of its type, so a caller that wrote down
    /// `[Protocol; 3]` would stop compiling at the next variant, which is the
    /// break `#[non_exhaustive]` exists to prevent. The list is every variant
    /// this build knows, not a promise about the next one: iterate it, never
    /// match against it as though it were complete.
    pub const ALL: &'static [Self] = &[Self::Tcp, Self::Udp, Self::Sctp];

    /// What a written port specification puts in front of this protocol's
    /// ports: nothing for TCP, `u:` for UDP, `s:` for SCTP.
    ///
    /// Nothing for TCP because a specification is TCP until a qualifier says
    /// otherwise, and a qualifier then holds until the next one. So this is
    /// the spelling of a specification that lists its TCP ports first, as
    /// [`PortSet`]'s rendering does, and the parser reads the same prefixes,
    /// so what a caller writes and what a report renders cannot come apart.
    /// TCP ports written after another protocol's need `t:` in front.
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
    /// A qualifier holds for every port after it until the next one, so TCP
    /// needs one as well. [`spec_prefix`](Self::spec_prefix) leaves it off
    /// because a specification starts out as TCP, and a writer that emits
    /// ports in no fixed order has to name TCP to get back to it: `u:53,t:80`.
    pub(crate) const fn qualifier(self) -> &'static str {
        match self {
            Self::Tcp => "t:",
            Self::Udp | Self::Sctp => self.spec_prefix(),
        }
    }
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
/// ambiguous between. `Unasked` is beneath all of them because it is the absence
/// of evidence rather than a weak grade of it.
///
/// Which reply produces which state depends on the probe that drew it, since a
/// RST means a closed port to a SYN and an unfiltered path to an ACK. That
/// mapping lives in
/// [`TcpScanTechnique`](crate::model::technique::TcpScanTechnique).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PortState {
    /// No verdict was reached, so nothing was established either way.
    ///
    /// Every state below is a reading of an answer or of a silence that followed
    /// a question. This one is what a port says when the question was never put:
    /// a scan that ran out of wall clock with targets still queued, a
    /// host that spent
    /// [`ZondConfig::host_timeout`](crate::config::ZondConfig::host_timeout)
    /// before the scan reached this port, a probe the operating system refused
    /// to send. Or when it was put and the scan stopped before its answer had
    /// the time the retry schedule gives it: that silence is not yet a reading,
    /// and the answer may have been on its way.
    ///
    /// Such a port stays on the record rather than being left off the host,
    /// because a truncated port list and a complete one look identical and the
    /// count agrees with itself either way. Without this state the only way to
    /// keep it would be to file it under whatever the scan reads silence as,
    /// which puts a port nobody looked at beside ports that were probed and
    /// stayed quiet, and a comparison would read the pair as a port that had
    /// changed.
    ///
    /// Being the bottom of the ordering, it never overrides anything:
    /// [`Port::merge`] folding a probed record onto an unasked one keeps the
    /// probe's verdict.
    Unasked,

    /// Closed or filtered, and the probe cannot say which. What an idle scan
    /// concludes when the target's IP ID did not advance.
    ClosedFiltered,

    /// Something dropped the probe. The lowest state a scan will record from
    /// silence alone, and only for the techniques every live stack would have
    /// answered. See
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
    /// The SYN need not have been this scan's. A listener reading a segment off
    /// the wire sees the same handshake completed for somebody else, which
    /// establishes the same thing and in one respect more, since what was
    /// accepted was a real client rather than a knock. What it does not establish
    /// is that this machine could reach the endpoint: the peer and the path were
    /// somebody else's.
    ///
    /// [`Discovery::reason`](discovery::Discovery::reason) is what tells the two
    /// apart, and it is worth reading before acting on an open port from a
    /// merged report.
    Open,
}

impl PortState {
    /// Every state a port can be recorded in, in declaration order, which is
    /// least definitive first and is the order this type's [`Ord`] ranks by.
    ///
    /// Here for the reason [`Protocol::ALL`] gives, and read by the gate holding
    /// the exported schema to what this build can write.
    ///
    /// The order matters although the gate does not see it: the gate compares
    /// names as a set, and a caller rendering a legend from this list gets the
    /// states in whatever order it holds, so any order but the declaration's is
    /// one the type says is wrong. `model`'s own test holds every `ALL` to its
    /// enum's declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Unasked,
        Self::ClosedFiltered,
        Self::Filtered,
        Self::Unfiltered,
        Self::Closed,
        Self::OpenFiltered,
        Self::Open,
    ];
}

/// Folds `port` into `ports`, merging it into the record already held for the
/// same endpoint, keyed as [`Host`](crate::model::host::Host) keys its own.
///
/// For a reader gathering a host's ports before the host exists. Folding as
/// they arrive rather than collecting them keeps what a host costs bounded by
/// the endpoints it can have, where a list grows with every entry a document
/// repeats.
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
/// The number and protocol identify it; everything else is a finding, and is
/// absent until something establishes it. See the module documentation for what
/// the four optional halves each answer and why they are kept apart.
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
    /// Boxed, as [`security`](Self::security) is, because a record is kept for
    /// every port asked and only the few that answered have either. A
    /// full-range scan of one host holds 65,535 of these, nearly all closed or
    /// filtered, and inline the two halves they leave empty would be most of
    /// what each of them occupies.
    service: Option<Box<Service>>,

    /// What a TLS handshake negotiated, for an endpoint that completed one.
    security: Option<Box<Security>>,

    /// The packet that settled [`state`](Self::state), and what it carried.
    ///
    /// Inline, unlike the two above: nearly every port asked has one, and a
    /// box would add an allocation to each of them.
    discovery: Option<Discovery>,

    /// What a detection concluded was wrong with this endpoint, keyed on the
    /// claim so that the same finding reached twice records once.
    ///
    /// The per-port findings, such as a vulnerable service or a weak
    /// configuration on the thing listening here, as distinct from the cross-host
    /// findings a [`Host`](crate::model::host::Host) carries. Bounded by
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
        self.service.as_deref()
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
    /// What is wrong with the service listening here. Ordered by claim, so two
    /// runs that found the same things render them the same way.
    pub fn findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.values()
    }

    /// Records a finding about this port, and reports whether it was new
    /// information: a claim not seen before, or a stronger reading of one that
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

        // Destructured rather than reached through `other.…`, so a field added
        // to this struct is a compile error here and not a value that quietly
        // stops being folded.
        let Port {
            // The endpoint, which the assertion above has just established is
            // this one's.
            number: _,
            protocol: _,
            state,
            service,
            security,
            discovery,
            findings,
        } = other;

        // Taken before the state moves, because the telemetry below has to be
        // judged against what it actually had to beat.
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
        if discovery.is_some() && (state > previous_state || self.discovery.is_none()) {
            self.discovery = discovery;
        }

        // A claim missing from one record is a detection that did not run there,
        // not a retraction, so a fold adds and never removes; a claim on both
        // corroborates through `add_finding`.
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

    /// Nothing established outranks nothing at all, in both directions, so a
    /// sitting that never reached a port cannot undo what an earlier one learned
    /// about it and cannot invent anything either.
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

    /// The telemetry explains the verdict, so replacing the verdict replaces the
    /// account of it. The RTT and TTL of a `NoResponse` say nothing about a port
    /// something has since answered on.
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

    /// A port nothing answered on carries a state and the account of the
    /// packet that settled it, and pays at most a pointer for each half it
    /// leaves empty. A full-range scan keeps 65,535 of these per host, in the
    /// live store and again in the report, and a service or a TLS record held
    /// inline is several hundred bytes on every one of them.
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
