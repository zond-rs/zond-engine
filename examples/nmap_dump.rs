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
//! Against nmap 7.99's DTD that reports exactly one error, the deliberate one:
//! `scanner="zond"` is not `scanner="nmap"`. Substituting the name and nothing
//! else validates clean. Run the same check on real nmap output first, because
//! it passes, and that is what makes the instrument worth trusting.
//!
//! ## Why this is an example and not a test
//!
//! It asserts nothing, and it cannot: no assertion inside this crate can say
//! the output is XML a stranger will open, because every one of them compares
//! the document against strings the exporter itself wrote. That proves
//! consistency, not validity. The thing that answers the real question is
//! `xmllint` and a DTD, both outside the crate.
//!
//! It lived behind `#[ignore]` in `export::nmap`'s tests until W22, where it
//! read as a coverage claim the repository never cashed. An example is compiled
//! by `cargo check --all-targets`, so it cannot rot, and it runs without a test
//! harness flag.
//!
//! ## What it covers
//!
//! A report built here through the public API, which is smaller than the
//! fixture the crate's own export tests use. It carries hosts that are up and
//! filtered, TCP and UDP, open and closed ports, and identified services, which
//! is the part of the DTD an exported document exercises. A field only the
//! internal fixture reaches is a field this check does not validate.

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
    let mut gateway = Host::new("192.168.0.1".parse::<IpAddr>().expect("an address"));
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

    let mut quiet = Host::new("192.168.0.7".parse::<IpAddr>().expect("an address"));
    quiet.set_status(HostStatus::Filtered);
    quiet.add_port(Port::new(25, Protocol::Tcp, PortState::Filtered));

    ScanReport::recorded("zond-example 1.0.0", Vec::new(), vec![gateway, quiet])
}
