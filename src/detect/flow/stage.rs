// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Running the flow corpus over a host
//!
//! The Tier-1 detection stage. For each open port a host holds, every enabled
//! flow whose `when` gate fits the port is run against it, and the findings it
//! produces are recorded on the port. It is the active analogue of the [CVE
//! correlator](crate::cve): that reads what a scan already gathered, this
//! exchanges bytes with the port to decide, and both hand a [`Finding`] to the
//! subject it concerns.
//!
//! ## What runs, and how it reaches the port
//!
//! A flow runs for a port when its `when` fits the port's service, number and
//! protocol, and its class is one the default policy enables — `passive` and
//! `active-benign` for now, the intrusive classes staying off until an operator
//! opts them in through an envelope (a later increment). The [`Probe`] each flow
//! speaks through is supplied *per port* by the caller: that is the seam the live
//! transport plugs into, and it keeps this stage testable with a canned socket
//! and free of any transport of its own. A caller that cannot reach a port
//! returns [`None`], and the port is skipped.

// The stage is wired into a scan by a later increment (the live transport that
// supplies the Probe), so for now only the tests exercise it.
#![allow(dead_code)]

use crate::detect::DetectionEnvelope;
use crate::model::finding::Finding;
use crate::model::host::Host;
use crate::model::port::{Port, PortState, Protocol};
use crate::record::wire;

use super::Probe;
use super::db::FlowDb;
use crate::detect::manifest::{CapabilitySpec, Class, Rule};

/// Runs `corpus`'s enabled, applicable flows against each open port of `host`,
/// recording every finding they produce. `probe_for` supplies the [`Probe`] a
/// flow speaks through for a given port, or [`None`] to skip that port. A scan
/// passes [`FlowDb::global`]; a test can pass a corpus of its own.
///
/// The host-level convenience over [`detect_port`], for a synchronous caller with
/// the whole host in hand.
pub(crate) fn run_flows(
    host: &mut Host,
    corpus: &FlowDb,
    envelope: &DetectionEnvelope,
    mut probe_for: impl FnMut(&Port) -> Option<Box<dyn Probe>>,
) {
    // Collect first, mutate second: reading the ports borrows the host, and
    // recording a finding needs them back mutably, so the two cannot overlap.
    let mut hits: Vec<(u16, Protocol, Finding)> = Vec::new();
    for port in host.ports() {
        if port.state() != PortState::Open {
            continue;
        }
        let number = port.number();
        let protocol = port.protocol();
        let service = port.service().map(|service| service.name());
        for finding in detect_port(corpus, envelope, service, number, protocol, |_caps| {
            probe_for(port)
        }) {
            hits.push((number, protocol, finding));
        }
    }

    for (number, protocol, finding) in hits {
        host.add_port_finding(number, protocol, finding);
    }
}

/// The findings `corpus`'s enabled, applicable flows produce for one port with
/// these facts. `probe_for` is handed the running flow's declared
/// [`CapabilitySpec`] (its budget) and yields a fresh [`Probe`] bound to the port,
/// or [`None`] to skip that flow. This is the per-port core the live detection
/// phase drives: it holds no host and does no I/O of its own, so a caller can run
/// it wherever the socket lives.
pub(crate) fn detect_port(
    corpus: &FlowDb,
    envelope: &DetectionEnvelope,
    service: Option<&str>,
    number: u16,
    protocol: Protocol,
    mut probe_for: impl FnMut(&CapabilitySpec) -> Option<Box<dyn Probe>>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for flow in corpus.flows() {
        let manifest = &flow.flow().detection;
        if !enabled(manifest.capabilities.class, envelope)
            || !applies(&manifest.when, service, number, protocol)
        {
            continue;
        }
        let Some(mut probe) = probe_for(&manifest.capabilities) else {
            continue;
        };
        findings.extend(flow.run(probe.as_mut()));
    }
    findings
}

/// Whether any enabled flow in `corpus` gates onto a port with these facts, so a
/// caller can skip opening a socket to a port no flow would probe.
pub(crate) fn interested(
    corpus: &FlowDb,
    envelope: &DetectionEnvelope,
    service: Option<&str>,
    number: u16,
    protocol: Protocol,
) -> bool {
    corpus.flows().any(|flow| {
        let manifest = &flow.flow().detection;
        enabled(manifest.capabilities.class, envelope)
            && applies(&manifest.when, service, number, protocol)
    })
}

/// Whether `envelope` permits a flow of this class to run. The class is the
/// flow's declared intrusiveness; the envelope is the operator's grant.
fn enabled(class: Class, envelope: &DetectionEnvelope) -> bool {
    envelope.permits(class.into_model())
}

/// Whether a flow's `when` gate fits a port's facts. Every set field must hold;
/// an empty gate fits any open port.
fn applies(when: &Rule, service: Option<&str>, number: u16, protocol: Protocol) -> bool {
    let service_ok = when
        .service
        .as_deref()
        .is_none_or(|name| service == Some(name));
    let number_ok = when.port.is_none_or(|wanted| wanted == number)
        && (when.ports.is_empty() || when.ports.contains(&number));
    let protocol_ok = when
        .protocol
        .as_deref()
        .is_none_or(|wanted| wanted == wire::protocol_name(protocol));

    service_ok && number_ok && protocol_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::finding::DetectionClass;
    use crate::model::port::Service;
    use std::net::{IpAddr, Ipv4Addr};

    /// The default grant: passive and active-benign run.
    fn default_envelope() -> DetectionEnvelope {
        DetectionEnvelope::default()
    }

    /// A socket that answers every send with one canned reply.
    struct Canned(&'static [u8]);
    impl Probe for Canned {
        fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
            Some(self.0.to_vec())
        }
    }

    fn host_with(port: Port) -> Host {
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        host.add_port(port);
        host
    }

    fn open(number: u16, protocol: Protocol, service: &str) -> Port {
        Port::new(number, protocol, PortState::Open).with_service(Service::new(service, 100))
    }

    #[test]
    fn a_matching_flow_runs_and_records_its_finding_on_the_port() {
        let mut host = host_with(open(6379, Protocol::Tcp, "redis"));

        run_flows(&mut host, FlowDb::global(), &default_envelope(), |_port| {
            Some(Box::new(Canned(b"# Server\r\nredis_version:7.2.4")))
        });

        let port = host.ports().find(|port| port.number() == 6379).unwrap();
        let findings: Vec<_> = port.findings().collect();
        assert_eq!(findings.len(), 1, "the redis flow fired");
        assert_eq!(findings[0].detection().id(), "redis-unauth-access");
        // Its provenance is the flow's real content hash, not an empty one.
        assert_eq!(findings[0].detection().content_hash().len(), 64);
    }

    #[test]
    fn the_envelope_decides_which_classes_run() {
        // The default permits benign flows but withholds the intrusive ones.
        let default = default_envelope();
        assert!(enabled(Class::Passive, &default));
        assert!(enabled(Class::ActiveBenign, &default));
        assert!(!enabled(Class::ActiveMutating, &default));
        assert!(!enabled(Class::Exploit, &default));
        assert!(!enabled(Class::Dos, &default));

        // Raising the ceiling opens a class the default withheld.
        let permissive = DetectionEnvelope::up_to(DetectionClass::Exploit);
        assert!(enabled(Class::Exploit, &permissive));
    }

    #[test]
    fn a_flow_is_skipped_when_its_gate_or_the_port_does_not_fit() {
        // Wrong service: the redis flow's `when.service = "redis"` does not fit an
        // http port, so nothing fires even though the socket would answer.
        let mut http = host_with(open(6379, Protocol::Tcp, "http"));
        run_flows(&mut http, FlowDb::global(), &default_envelope(), |_| {
            Some(Box::new(Canned(b"# Server\r\nredis_version:7.2.4")))
        });
        let port = http.ports().find(|port| port.number() == 6379).unwrap();
        assert_eq!(port.findings().count(), 0, "the service gate did not match");

        // A closed port is never probed, whatever runs on it.
        let mut closed = host_with(
            Port::new(6379, Protocol::Tcp, PortState::Closed)
                .with_service(Service::new("redis", 100)),
        );
        run_flows(&mut closed, FlowDb::global(), &default_envelope(), |_| {
            Some(Box::new(Canned(b"# Server\r\nredis_version:7.2.4")))
        });
        let port = closed.ports().find(|port| port.number() == 6379).unwrap();
        assert_eq!(port.findings().count(), 0, "a closed port was probed");
    }

    #[test]
    fn an_intrusive_flow_does_not_run_under_the_default_policy() {
        use crate::detect::flow::db::CompiledFlow;
        use crate::detect::flow::schema::FlowDetection;

        // A flow whose class is off by default. Even on a matching port answering
        // exactly what its `expect` wants, the stage must refuse to run it.
        let source = r#"
            [detection]
            id      = "dangerous"
            version = "1.0.0"
            title   = "Dangerous"
            [detection.when]
            service = "redis"
            [detection.capabilities]
            class = "exploit"
            speak = "target"
            [[step]]
            send   = "ATTACK"
            expect = "ok"
            [[step.finding]]
            when     = "matched"
            severity = "critical"
            summary  = "the exploit fired"
        "#;
        let flow: FlowDetection = toml::from_str(source).expect("a valid flow");
        let corpus = FlowDb::from_flows(vec![CompiledFlow::from_parts(flow, "0".repeat(64))]);

        // Under the default envelope the exploit is withheld.
        let mut host = host_with(open(6379, Protocol::Tcp, "redis"));
        run_flows(&mut host, &corpus, &default_envelope(), |_| {
            Some(Box::new(Canned(b"ok")))
        });
        let port = host.ports().find(|port| port.number() == 6379).unwrap();
        assert_eq!(
            port.findings().count(),
            0,
            "an exploit-class flow ran under the default envelope"
        );

        // Raise the ceiling to exploit and the same flow now runs.
        let mut opened = host_with(open(6379, Protocol::Tcp, "redis"));
        let permissive = DetectionEnvelope::up_to(DetectionClass::Exploit);
        run_flows(&mut opened, &corpus, &permissive, |_| {
            Some(Box::new(Canned(b"ok")))
        });
        let port = opened.ports().find(|port| port.number() == 6379).unwrap();
        assert_eq!(
            port.findings().count(),
            1,
            "an exploit the operator opted into did not run"
        );
    }
}
