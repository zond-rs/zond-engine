// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # An nmap document, for holding against a real parser
//!
//! Prints what [`NmapXmlExporter`] writes, so the document can be validated by
//! something that did not write it.
//!
//! ```text
//! cargo run --example nmap_dump --features export-nmap > zond.xml
//! xmllint --dtdvalid /path/to/nmap.dtd --noout zond.xml
//! ```
//!
//! Against nmap 7.99's DTD that reports one intended error: `scanner="zond"`
//! is not `scanner="nmap"`. With the name substituted it validates clean. Run
//! the check on real nmap output first to confirm the setup.
//!
//! ## Why an example
//!
//! Validity needs an outside validator; assertions in the crate compare against
//! strings the exporter wrote. As an example it is compiled by
//! `cargo check --all-targets`.
//!
//! ## Coverage
//!
//! A report built through the public API: hosts up and blocked, TCP and UDP,
//! open and closed ports, identified services. Fields only the crate's internal
//! export fixture reaches are not validated here.

use std::net::IpAddr;

use zond_engine::export::{ExportOptions, Exporter, NmapXmlExporter};
use zond_engine::model::host::{Host, HostStatus};
use zond_engine::model::port::{Port, PortState, Protocol, Service};
use zond_engine::report::ScanReport;

fn main() {
    let mut out = Vec::new();
    NmapXmlExporter::new(ExportOptions::new())
        .export(&report(), &mut out)
        .expect("the report exports");
    print!("{}", String::from_utf8(out).expect("the document is UTF-8"));
}

/// A report with one of each shape the exported document has an element for.
fn report() -> ScanReport {
    let mut gateway = Host::new("203.0.113.1".parse::<IpAddr>().expect("an address"));
    gateway.set_status(HostStatus::Up);
    gateway.set_hostname(Some("gateway.example".to_string()));
    gateway.add_port(
        Port::new(22, Protocol::Tcp, PortState::Open).with_service(
            Service::new("ssh", 95)
                .with_product("OpenSSH")
                .with_version("9.6p1"),
        ),
    );
    gateway.add_port(Port::new(53, Protocol::Udp, PortState::Open));
    gateway.add_port(Port::new(8080, Protocol::Tcp, PortState::Closed));

    let mut quiet = Host::new("203.0.113.7".parse::<IpAddr>().expect("an address"));
    quiet.set_status(HostStatus::Blocked);
    quiet.add_port(Port::new(25, Protocol::Tcp, PortState::NoReply));

    ScanReport::recorded("zond-example 1.0.0", Vec::new(), vec![gateway, quiet])
}
