// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Gating a detection to a port
//!
//! Before running a detection against a port, every tier checks that the
//! operator's [envelope](crate::config::DetectionEnvelope)
//! [`permits`](crate::config::DetectionEnvelope::permits) its class, and that its
//! `when` rule fits the port. This module answers the second, on the [`Rule`]
//! both [flows](super::flow) and [compute modules](super::compute) use.

use crate::fingerprint::{SignatureDb, Tunnel};
use crate::model::port::Protocol;
use crate::record::wire;

use super::manifest::Rule;

impl Rule {
    /// Whether this gate fits a port's facts. Every set field must hold; an empty
    /// gate fits any open port. `service`/`services` match the identified service,
    /// `port`/`ports` the number, `protocol` the transport (which also decides
    /// whether a UDP or TCP socket serves the detection), and `speaks` the
    /// application protocol the service is carried over, per the fingerprint
    /// corpus.
    ///
    /// A service name is compared with the protocol part of a label: `ssl/http`
    /// fits `http`, since the detection seam opens the tunnel first.
    pub fn applies(&self, service: Option<&str>, number: u16, protocol: Protocol) -> bool {
        let carried = service.map(|label| Tunnel::split_label(label).1);
        let service_ok = self
            .service
            .as_deref()
            .is_none_or(|name| carried == Some(name))
            && (self.services.is_empty()
                || self
                    .services
                    .iter()
                    .any(|wanted| carried == Some(wanted.as_str())));
        let number_ok = self.port.is_none_or(|wanted| wanted == number)
            && (self.ports.is_empty() || self.ports.contains(&number));
        let protocol_ok = self
            .protocol
            .as_deref()
            .is_none_or(|wanted| wanted == wire::protocol_name(protocol));

        // An unidentified port fits no `speaks`, as with `service`.
        let speaks_ok = self.speaks.as_deref().is_none_or(|wanted| {
            service.and_then(|name| SignatureDb::global().speaks(name)) == Some(wanted)
        });

        service_ok && number_ok && protocol_ok && speaks_ok
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
            speaks: None,
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
            speaks: None,
        };
        assert!(gate.applies(None, 443, Protocol::Tcp));
        assert!(!gate.applies(None, 8080, Protocol::Tcp));
    }

    /// A gate naming what a port speaks fits every service the corpus says is
    /// carried over it, and nothing else.
    ///
    /// Against the shipped corpus.
    #[test]
    fn a_speaks_gate_fits_every_service_carried_over_that_protocol() {
        let gate = Rule {
            service: None,
            services: Vec::new(),
            port: None,
            ports: Vec::new(),
            protocol: None,
            speaks: Some("http".to_string()),
        };

        assert!(gate.applies(Some("http"), 80, Protocol::Tcp));
        assert!(gate.applies(Some("grafana"), 3000, Protocol::Tcp));
        assert!(gate.applies(Some("kibana"), 5601, Protocol::Tcp));
        assert!(gate.applies(Some("kubernetes"), 6443, Protocol::Tcp));

        // Redis is not carried over HTTP, and neither is a port nothing named.
        assert!(!gate.applies(Some("redis"), 6379, Protocol::Tcp));
        assert!(!gate.applies(None, 80, Protocol::Tcp));

        // A web server inside TLS still speaks HTTP.
        assert!(gate.applies(Some("ssl/http"), 443, Protocol::Tcp));
        assert!(gate.applies(Some("ssl/grafana"), 3000, Protocol::Tcp));
    }

    /// Riak, Neo4j and RethinkDB are fingerprinted by their binary protocols, so
    /// they do not fit a `speaks = "http"` gate.
    #[test]
    fn a_product_with_an_http_api_fingerprinted_on_its_own_protocol_does_not_speak_http() {
        let gate = Rule {
            service: None,
            services: Vec::new(),
            port: None,
            ports: Vec::new(),
            protocol: None,
            speaks: Some("http".to_string()),
        };

        assert!(!gate.applies(Some("riak"), 8087, Protocol::Tcp));
        assert!(!gate.applies(Some("neo4j"), 7687, Protocol::Tcp));
        assert!(!gate.applies(Some("rethinkdb"), 28015, Protocol::Tcp));
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
            speaks: None,
        };
        assert!(gate.applies(Some("http"), 8080, Protocol::Tcp));
        assert!(gate.applies(Some("grafana"), 3000, Protocol::Tcp));
        assert!(!gate.applies(Some("redis"), 6379, Protocol::Tcp));
        assert!(!gate.applies(None, 8080, Protocol::Tcp));
    }

    /// A service identified inside TLS fits a gate naming that service, the
    /// way it fits a `speaks` gate.
    ///
    /// The detection seam opens the tunnel first.
    #[test]
    fn a_service_identified_inside_tls_fits_a_gate_naming_that_service() {
        let services = Rule {
            services: vec!["http".to_string(), "grafana".to_string()],
            ..Rule::default()
        };
        assert!(services.applies(Some("ssl/http"), 443, Protocol::Tcp));
        assert!(services.applies(Some("ssl/grafana"), 3000, Protocol::Tcp));
        assert!(!services.applies(Some("ssl/redis"), 6379, Protocol::Tcp));

        let service = rule(Some("ftp"), None, None);
        assert!(service.applies(Some("ssl/ftp"), 990, Protocol::Tcp));

        // A bare `ssl` names nothing inside the tunnel.
        assert!(!service.applies(Some("ssl"), 990, Protocol::Tcp));
    }
}
