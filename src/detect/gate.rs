// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Gating a detection to a port
//!
//! Every tier asks the same two questions before it runs a detection against a
//! port: does the operator's [envelope](super::DetectionEnvelope) permit the
//! detection's intrusiveness class, and does the detection's `when` rule fit this
//! port. The envelope answers the first through
//! [`permits`](super::DetectionEnvelope::permits); this module answers the second,
//! as a method on the shared [`Rule`] both a [flow](super::flow) and a [compute
//! module](super::compute) gate on, so the two tiers select ports by one rule
//! rather than each restating it.

use crate::model::port::Protocol;
use crate::record::wire;

use super::manifest::Rule;

impl Rule {
    /// Whether this gate fits a port's facts. Every set field must hold, and an
    /// empty gate fits any open port. A `service`/`services` names the identified
    /// service, a `port`/`ports` the number, and a `protocol` the transport — the
    /// last of which decides whether a UDP or a TCP socket serves the detection,
    /// so a wrong one probes a service nobody asked about.
    pub(crate) fn applies(&self, service: Option<&str>, number: u16, protocol: Protocol) -> bool {
        let service_ok = self
            .service
            .as_deref()
            .is_none_or(|name| service == Some(name))
            && (self.services.is_empty()
                || self
                    .services
                    .iter()
                    .any(|wanted| service == Some(wanted.as_str())));
        let number_ok = self.port.is_none_or(|wanted| wanted == number)
            && (self.ports.is_empty() || self.ports.contains(&number));
        let protocol_ok = self
            .protocol
            .as_deref()
            .is_none_or(|wanted| wanted == wire::protocol_name(protocol));

        service_ok && number_ok && protocol_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gate with the given fields, the rest left open.
    fn rule(service: Option<&str>, port: Option<u16>, protocol: Option<&str>) -> Rule {
        Rule {
            service: service.map(str::to_owned),
            services: Vec::new(),
            port,
            ports: Vec::new(),
            protocol: protocol.map(str::to_owned),
        }
    }

    #[test]
    fn an_empty_gate_fits_any_port() {
        let any = rule(None, None, None);
        assert!(any.applies(Some("redis"), 6379, Protocol::Tcp));
        assert!(any.applies(None, 1, Protocol::Udp));
    }

    #[test]
    fn every_set_field_must_hold() {
        let gate = rule(Some("redis"), None, Some("tcp"));
        assert!(gate.applies(Some("redis"), 6379, Protocol::Tcp));
        // Wrong service, wrong protocol, or a missing service each fail the gate.
        assert!(!gate.applies(Some("http"), 6379, Protocol::Tcp));
        assert!(!gate.applies(Some("redis"), 6379, Protocol::Udp));
        assert!(!gate.applies(None, 6379, Protocol::Tcp));
    }

    #[test]
    fn a_ports_list_admits_only_its_members() {
        let gate = Rule {
            service: None,
            services: Vec::new(),
            port: None,
            ports: vec![80, 443],
            protocol: None,
        };
        assert!(gate.applies(None, 443, Protocol::Tcp));
        assert!(!gate.applies(None, 8080, Protocol::Tcp));
    }

    /// One piece of software the corpus names two ways fits a gate naming both.
    #[test]
    fn a_services_list_admits_any_of_its_members() {
        let gate = Rule {
            service: None,
            services: vec!["http".to_string(), "grafana".to_string()],
            port: None,
            ports: Vec::new(),
            protocol: None,
        };
        assert!(gate.applies(Some("http"), 8080, Protocol::Tcp));
        assert!(gate.applies(Some("grafana"), 3000, Protocol::Tcp));
        assert!(!gate.applies(Some("redis"), 6379, Protocol::Tcp));
        assert!(!gate.applies(None, 8080, Protocol::Tcp));
    }
}
