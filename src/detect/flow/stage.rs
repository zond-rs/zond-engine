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

use crate::model::finding::Finding;
use crate::model::host::Host;
use crate::model::port::{Port, PortState, Protocol};
use crate::record::wire;

use super::Probe;
use super::db::FlowDb;
use super::schema::{Class, Rule};

/// Runs `corpus`'s enabled, applicable flows against each open port of `host`,
/// recording every finding they produce. `probe_for` supplies the [`Probe`] a
/// flow speaks through for a given port, or [`None`] to skip that port. A scan
/// passes [`FlowDb::global`]; a test can pass a corpus of its own.
pub(crate) fn run_flows(
    host: &mut Host,
    corpus: &FlowDb,
    mut probe_for: impl FnMut(&Port) -> Option<Box<dyn Probe>>,
) {
    // Collect first, mutate second: reading the ports borrows the host, and
    // recording a finding needs them back mutably, so the two cannot overlap.
    let mut hits: Vec<(u16, Protocol, Finding)> = Vec::new();
    for port in host.ports() {
        if port.state() != PortState::Open {
            continue;
        }
        for flow in corpus.flows() {
            let manifest = &flow.flow().detection;
            if !enabled(manifest.capabilities.class) || !applies(&manifest.when, port) {
                continue;
            }
            let Some(mut probe) = probe_for(port) else {
                continue;
            };
            for finding in flow.run(probe.as_mut()) {
                hits.push((port.number(), port.protocol(), finding));
            }
        }
    }

    for (number, protocol, finding) in hits {
        host.add_port_finding(number, protocol, finding);
    }
}

/// Whether the default policy runs a flow of this class. `passive` and
/// `active-benign` are on; the intrusive classes are off until an operator opts
/// them in, so a flow that mutates, exploits, or degrades never runs unasked.
fn enabled(class: Class) -> bool {
    matches!(class, Class::Passive | Class::ActiveBenign)
}

/// Whether a flow's `when` gate fits `port`. Every set field must hold; an empty
/// gate fits any open port.
fn applies(when: &Rule, port: &Port) -> bool {
    let service_ok = when
        .service
        .as_deref()
        .is_none_or(|name| port.service().is_some_and(|service| service.name() == name));
    let number_ok = when.port.is_none_or(|number| number == port.number())
        && (when.ports.is_empty() || when.ports.contains(&port.number()));
    let protocol_ok = when
        .protocol
        .as_deref()
        .is_none_or(|protocol| protocol == wire::protocol_name(port.protocol()));

    service_ok && number_ok && protocol_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::port::Service;
    use std::net::{IpAddr, Ipv4Addr};

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

        run_flows(&mut host, FlowDb::global(), |_port| {
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
    fn the_default_policy_enables_benign_flows_but_not_intrusive_ones() {
        assert!(enabled(Class::Passive));
        assert!(enabled(Class::ActiveBenign));
        assert!(!enabled(Class::ActiveMutating));
        assert!(!enabled(Class::Exploit));
        assert!(!enabled(Class::Dos));
    }

    #[test]
    fn a_flow_is_skipped_when_its_gate_or_the_port_does_not_fit() {
        // Wrong service: the redis flow's `when.service = "redis"` does not fit an
        // http port, so nothing fires even though the socket would answer.
        let mut http = host_with(open(6379, Protocol::Tcp, "http"));
        run_flows(&mut http, FlowDb::global(), |_| {
            Some(Box::new(Canned(b"# Server\r\nredis_version:7.2.4")))
        });
        let port = http.ports().find(|port| port.number() == 6379).unwrap();
        assert_eq!(port.findings().count(), 0, "the service gate did not match");

        // A closed port is never probed, whatever runs on it.
        let mut closed = host_with(
            Port::new(6379, Protocol::Tcp, PortState::Closed)
                .with_service(Service::new("redis", 100)),
        );
        run_flows(&mut closed, FlowDb::global(), |_| {
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

        let mut host = host_with(open(6379, Protocol::Tcp, "redis"));
        run_flows(&mut host, &corpus, |_| Some(Box::new(Canned(b"ok"))));

        let port = host.ports().find(|port| port.number() == 6379).unwrap();
        assert_eq!(
            port.findings().count(),
            0,
            "an exploit-class flow ran under the default policy"
        );
    }
}
