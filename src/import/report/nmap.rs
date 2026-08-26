// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading nmap's XML as a report
//!
//! The same `-oX` file [`import::nmap`](crate::import::nmap) reads as targets,
//! read instead as what that scan found: hosts with their reachability, ports
//! with their states, services with their versions, and the operating system
//! nmap settled on. What comes back is a [`ScanReport`], so an nmap scan from
//! last quarter and a scan this engine ran tonight are the same input to
//! [`diff`](crate::diff).
//!
//! The parsing is `xml`'s, refusals and bounds included.
//! This module is the mapping and nothing else.
//!
//! ## Nmap's vocabulary is not this engine's, and the gaps are where the care is
//!
//! Three places where a literal translation would record something the scan did
//! not establish.
//!
//! **A host nmap calls `down` is [`Unknown`](HostStatus::Unknown) unless
//! something said otherwise.** Nmap uses one word for "an intermediary told me
//! this address is unreachable" and "nothing came back", and this engine
//! separates them on purpose — [`HostStatus::Down`]'s own documentation refuses
//! to infer it from silence. So the `reason` attribute decides: `host-unreach`
//! and its relatives give [`Down`](HostStatus::Down), `admin-prohibited` and its
//! relatives give [`Filtered`](HostStatus::Filtered), and everything else,
//! including a bare `no-response`, gives `Unknown`.
//!
//! **A host nmap calls `up` for the reason `user-set` is `Unknown`.** That is
//! what nmap records when it was told to skip host discovery: no probe was sent
//! and nothing answered, so the word "up" there is an instruction being echoed
//! back rather than a finding. Where such a host has a port that answered, the
//! port is what proves the stack is alive, and the status is promoted on that
//! evidence instead — which is the same inference this engine's own port scanner
//! makes.
//!
//! **A service nmap identified by `method="table"` is recorded at confidence
//! zero.** That method means nmap looked the port number up in a file, which is
//! exactly what this engine's own
//! [`baseline_service`](crate::fingerprint::baseline_service) does to every
//! classified port. Recording it the same way keeps the two symmetrical, and
//! [`Service::is_inferred`](crate::model::port::Service::is_inferred) is what
//! tells either apart from an identification — a comparison ignores both, so
//! two tools with different port catalogues do not appear to disagree about
//! every port on the network.
//!
//! ## What the report says it covered
//!
//! [`TargetScope`] is what lets a comparison tell a host that went away from one
//! nobody looked for, and nmap's XML does not record its resolved target set.
//! What it does record is a `<host>` element per address it accounted for — and
//! whether that accounting is complete is knowable: **nmap lists the addresses
//! that did not answer only when asked to, so a document containing any host
//! that is not `up` is one that lists everything it considered.**
//!
//! So the scope is the addresses the document accounts for, claimed only when
//! such a host appears. A document of nothing but live hosts states no scope at
//! all, and every question a comparison asks of it answers
//! [`Unstated`](crate::diff::Coverage::Unstated). Under-claiming costs a
//! comparison some confirmations. Over-claiming would have it report hosts as
//! gone on the strength of a scan that never looked.
//!
//! ## What is not read
//!
//! Traceroute hops, host script output, the `<extraports>` summary, timing
//! statistics and the raw service fingerprints. The first four have no bearing
//! on what [`diff`](crate::diff) compares, and `<extraports>` is a count of ports
//! nmap did not name — it says a thousand ports were closed without saying which,
//! and there is nothing to record it against.

use std::io::BufRead;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::config::{OsDetection, ServiceDetection, ZondConfig};
use crate::import::report::{ReportOptions, ReportReader};
use crate::import::xml::{Element, Event, Parser};
use crate::import::{ImportError, Origin};
use crate::model::exclusion::Exclusions;
use crate::model::host::os::OsFingerprint;
use crate::model::host::{Host, HostStatus, StatusProtocol, StatusReason};
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;
use crate::model::port::discovery::{Discovery, ScanResponse};
use crate::model::port::{Port, PortSet, PortState, Protocol, Service};
use crate::model::technique::TcpScanTechnique;
use crate::scanner::report::{
    PhaseParts, PortScope, ScanKind, ScanPhase, ScanReport, ScanSettings, ScopeParts, TargetScope,
};

/// The format's name in errors.
const FORMAT: &str = "nmap XML";

/// The attributes this reader keeps. Everything else is skipped unbuffered.
///
/// Longer than the target reader's four, because a finding is more than an
/// address. Several names appear on more than one element — `version` on both
/// `<nmaprun>` and `<service>`, `name` on three — and which is meant is decided
/// by the element the parser is inside, never by the name alone.
///
/// `args` is deliberately absent: it runs to kilobytes and nothing reads it.
/// `services` and `ports` are kept despite doing the same, because between them
/// they are what nmap knows and its port list does not say: which ports were
/// walked, and which of them it found uninteresting enough to leave out. Both
/// are [lossy](crate::import::xml::Parser::with_lossy) — a sparse sweep of every
/// port could write several hundred kilobytes of either, and neither is worth
/// refusing a file over.
const KEPT: &[&[u8]] = &[
    b"addr",
    b"addrtype",
    b"portid",
    b"protocol",
    b"state",
    b"reason",
    b"name",
    b"product",
    b"version",
    b"extrainfo",
    b"conf",
    b"method",
    b"accuracy",
    b"osfamily",
    b"osgen",
    b"vendor",
    b"type",
    b"start",
    b"starttime",
    b"endtime",
    b"elapsed",
    b"numservices",
    b"services",
    b"ports",
    b"scanner",
];

/// The attributes dropped rather than refused when they run long.
///
/// Both are port lists, and both only ever enrich: without them a comparison
/// falls back to saying it cannot tell whether an endpoint was probed, which is
/// the honest answer rather than a wrong one.
const LOSSY: &[&[u8]] = &[b"services", b"ports"];

/// The longest attribute value kept, in bytes.
///
/// Well past the parser's default, because of `services`: nmap writes its
/// default port set out as an explicit list of a thousand entries, which runs to
/// several kilobytes. Every other kept value here is free text a service
/// reported about itself and runs to a few dozen bytes. The element's whole
/// markup is still bounded by
/// [`ImportLimits::max_line_bytes`](crate::import::ImportLimits::max_line_bytes),
/// which is where an unbounded document is actually stopped.
const MAX_VALUE_BYTES: usize = 16 * 1024;

/// nmap's `conf` runs 0 to 10, and this engine's confidence runs 0 to 100.
const CONFIDENCE_SCALE: u8 = 10;

/// Reads an nmap XML document as the report of the scan that produced it.
#[derive(Debug, Clone, Copy, Default)]
pub struct NmapXmlReportReader {
    options: ReportOptions,
}

impl NmapXmlReportReader {
    /// A reader bounded by `options`.
    pub fn new(options: ReportOptions) -> Self {
        Self { options }
    }
}

impl ReportReader for NmapXmlReportReader {
    fn read(&self, input: &mut dyn BufRead) -> Result<ScanReport, ImportError> {
        let mut parser = Parser::new(input, self.options.limits.max_line_bytes, FORMAT, KEPT)
            .with_max_value_bytes(MAX_VALUE_BYTES)
            .with_lossy(LOSSY);
        let mut run = Run::default();
        let mut host: Option<HostAcc> = None;
        let mut port: Option<PortAcc> = None;
        // The state an `<extraports>` block is reporting, while inside one.
        let mut bulk: Option<String> = None;
        let mut inside = Inside::Nothing;

        loop {
            match parser.next_event()? {
                Event::Eof => break,

                Event::Start { self_closing } => {
                    let tag = Tag::of(&parser.element.name);

                    match tag {
                        Tag::NmapRun => {
                            run.saw_root = true;
                            run.scanner = attr(&parser.element, b"scanner");
                            run.scanner_version = attr(&parser.element, b"version");
                            run.started = attr(&parser.element, b"start").and_then(|s| epoch(&s));
                        }
                        Tag::ScanInfo => run.scan_info(&parser.element),
                        Tag::Host => {
                            host = Some(HostAcc {
                                started: attr(&parser.element, b"starttime")
                                    .and_then(|s| epoch(&s)),
                                ended: attr(&parser.element, b"endtime").and_then(|s| epoch(&s)),
                                ..HostAcc::default()
                            });
                        }
                        Tag::Status => {
                            if let Some(host) = host.as_mut() {
                                host.state = attr(&parser.element, b"state");
                                host.reason = attr(&parser.element, b"reason");
                            }
                        }
                        Tag::Address => {
                            if host.is_some() {
                                let address = HostAcc::read_address(&parser.element, &parser)?;
                                if let (Some(host), Some(address)) = (host.as_mut(), address) {
                                    host.record(address);
                                }
                            }
                        }
                        Tag::HostName => {
                            if let Some(host) = host.as_mut()
                                && host.hostname.is_none()
                            {
                                host.hostname = attr(&parser.element, b"name");
                            }
                        }
                        Tag::Port => port = Some(PortAcc::open(&parser.element, &parser)?),
                        // The ports nmap did not think worth listing one by
                        // one. It still probed them and still knows what it
                        // found, and both are here.
                        Tag::ExtraPorts => {
                            bulk = attr(&parser.element, b"state");
                        }
                        Tag::ExtraReasons => {
                            if let (Some(host), Some(state)) = (host.as_mut(), bulk.as_deref()) {
                                let state = PortAcc::state_named(state, &parser)?;
                                host.extend(state, &parser.element);
                            }
                        }
                        Tag::State => {
                            if port.is_some() {
                                let settled = PortAcc::read_state(&parser.element, &parser)?;
                                if let (Some(port), Some((state, reason))) =
                                    (port.as_mut(), settled)
                                {
                                    port.state = state;
                                    port.reason = reason;
                                }
                            }
                        }
                        Tag::Service => {
                            if let Some(port) = port.as_mut() {
                                port.identify(&parser.element);
                                run.probed_services |= port.service.is_some();
                            }
                            if !self_closing {
                                inside = Inside::Service;
                            }
                        }
                        Tag::OsMatch => {
                            if let Some(host) = host.as_mut() {
                                host.match_os(&parser.element);
                                run.identified_os |= host.os.is_some();
                            }
                            if !self_closing {
                                inside = Inside::Os;
                            }
                        }
                        Tag::OsClass => {
                            if let Some(host) = host.as_mut() {
                                host.classify_os(&parser.element);
                            }
                            if !self_closing {
                                inside = Inside::Os;
                            }
                        }
                        Tag::Cpe => {
                            if !self_closing && inside != Inside::Nothing {
                                parser.begin_text();
                            }
                        }
                        Tag::Finished => {
                            run.elapsed = attr(&parser.element, b"elapsed")
                                .and_then(|s| s.parse::<f64>().ok())
                                .and_then(|seconds| Duration::try_from_secs_f64(seconds).ok());
                        }
                        Tag::Other => {}
                    }

                    // A self-closing `<host/>` or `<port/>` opens and closes in
                    // one event and never sees an `End`.
                    if self_closing {
                        match tag {
                            Tag::Host => run.close(host.take()),
                            Tag::Port => {
                                if let (Some(host), Some(port)) = (host.as_mut(), port.take()) {
                                    host.ports.push(port.into_port());
                                }
                            }
                            _ => {}
                        }
                    }
                }

                Event::End => match Tag::of(&parser.element.name) {
                    Tag::ExtraPorts => bulk = None,
                    Tag::Host => run.close(host.take()),
                    Tag::Port => {
                        if let (Some(host), Some(port)) = (host.as_mut(), port.take()) {
                            host.ports.push(port.into_port());
                        }
                    }
                    Tag::Cpe => {
                        let cpe = parser.take_text();
                        if !cpe.is_empty() {
                            match inside {
                                Inside::Service => {
                                    if let Some(service) =
                                        port.as_mut().and_then(|port| port.service.as_mut())
                                    {
                                        service.add_cpe(cpe);
                                    }
                                }
                                Inside::Os => {
                                    if let Some(os) =
                                        host.as_mut().and_then(|host| host.os.as_mut())
                                    {
                                        os.add_cpe(cpe);
                                    }
                                }
                                Inside::Nothing => {}
                            }
                        }
                    }
                    Tag::Service | Tag::OsMatch => inside = Inside::Nothing,
                    _ => {}
                },
            }
        }

        if !run.saw_root {
            return Err(ImportError::Malformed {
                format: FORMAT,
                origin: Origin::unknown(),
                message: "no <nmaprun> element: this is not an nmap document".to_string(),
            });
        }

        Ok(run.into_report())
    }
}

/// Which element the parser is inside, for the ones whose text belongs to
/// something further out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inside {
    Nothing,
    Service,
    Os,
}

/// The elements this reader acts on. Everything else is `Other` and is skipped
/// without its content being examined.
///
/// Resolved from the name once per element, so nothing borrows the parser across
/// the work of handling one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    NmapRun,
    ScanInfo,
    Host,
    Status,
    Address,
    HostName,
    Port,
    ExtraPorts,
    ExtraReasons,
    State,
    Service,
    Cpe,
    OsMatch,
    OsClass,
    Finished,
    Other,
}

impl Tag {
    fn of(name: &[u8]) -> Self {
        match name {
            b"nmaprun" => Tag::NmapRun,
            b"scaninfo" => Tag::ScanInfo,
            b"host" => Tag::Host,
            b"status" => Tag::Status,
            b"address" => Tag::Address,
            b"hostname" => Tag::HostName,
            b"port" => Tag::Port,
            b"extraports" => Tag::ExtraPorts,
            b"extrareasons" => Tag::ExtraReasons,
            b"state" => Tag::State,
            b"service" => Tag::Service,
            b"cpe" => Tag::Cpe,
            b"osmatch" => Tag::OsMatch,
            b"osclass" => Tag::OsClass,
            b"finished" => Tag::Finished,
            _ => Tag::Other,
        }
    }
}

/// One attribute as an owned string, which ends the parser borrow before
/// anything is done with the value.
fn attr(element: &Element, name: &[u8]) -> Option<String> {
    element.value(name).map(str::to_owned)
}

/// The port set a `<scaninfo>` names, in this engine's specification grammar.
///
/// Nmap writes a bare list of numbers and ranges and says which transport it
/// means in a sibling attribute; this grammar carries the transport in the
/// specification itself, so a UDP list is rewritten with the prefix each entry
/// needs.
fn services(spec: &str, protocol: Protocol) -> Option<PortSet> {
    let spec = match protocol {
        Protocol::Tcp => spec.to_owned(),
        Protocol::Udp => spec
            .split(',')
            .map(|entry| format!("u:{}", entry.trim()))
            .collect::<Vec<_>>()
            .join(","),
    };

    PortSet::try_from(spec.as_str()).ok()
}

/// Seconds since the epoch, as nmap writes every time in its document.
fn epoch(seconds: &str) -> Option<SystemTime> {
    seconds
        .parse::<u64>()
        .ok()
        .map(|seconds| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/// Everything the document says about the scan as a whole.
#[derive(Debug, Default)]
struct Run {
    saw_root: bool,
    scanner: Option<String>,
    scanner_version: Option<String>,
    started: Option<SystemTime>,
    elapsed: Option<Duration>,
    technique: Option<TcpScanTechnique>,
    probes: Option<u128>,
    /// The port set every `<scaninfo>` between them named.
    ports: Option<PortSet>,
    protocols: Vec<Protocol>,
    probed_services: bool,
    identified_os: bool,
    hosts: Vec<Host>,
    /// Every address the document accounted for with a `<host>` element.
    accounted: IpSet,
    /// Whether the accounting is complete; see the module documentation.
    exhaustive: bool,
}

impl Run {
    /// Takes a `<scaninfo>`, which is where nmap says which probe it sent and
    /// which ports it sent it to.
    fn scan_info(&mut self, element: &Element) {
        let protocol = match element.value(b"protocol") {
            Some("tcp") => Some(Protocol::Tcp),
            Some("udp") => Some(Protocol::Udp),
            // `ip` and `sctp` name transports this engine's scope has no word
            // for. Ignored rather than refused: an unreadable `<scaninfo>` is
            // not a reason to refuse the findings under it.
            _ => None,
        };
        if let Some(protocol) = protocol {
            self.protocols.push(protocol);

            // The resolved port set, which nmap applies to every host it scans.
            if let Some(ports) = element
                .value(b"services")
                .and_then(|spec| services(spec, protocol))
            {
                self.ports = Some(match self.ports.take() {
                    Some(existing) => existing.union(&ports),
                    None => ports,
                });
            }
        }

        if let Some(count) = element
            .value(b"numservices")
            .and_then(|n| n.parse::<u128>().ok())
        {
            *self.probes.get_or_insert(0) += count;
        }

        // The scan type says both which segment went out and whether it took a
        // raw socket to send it.
        match element.value(b"type") {
            Some("syn") => self.raw(Some(TcpScanTechnique::Syn)),
            Some("ack") => self.raw(Some(TcpScanTechnique::Ack)),
            Some("fin") => self.raw(Some(TcpScanTechnique::Fin)),
            Some("null") => self.raw(Some(TcpScanTechnique::Null)),
            Some("xmas") => self.raw(Some(TcpScanTechnique::Xmas)),
            Some("maimon") => self.raw(Some(TcpScanTechnique::Maimon)),
            Some("udp" | "window" | "ipproto" | "sctpinit" | "sctpcookieecho") => self.raw(None),
            // A connect scan is the one nmap performs without privileges, and
            // this engine records the same fallback the same way.
            _ => {}
        }
    }

    /// Records that a raw probe was sent, and which one where this engine has a
    /// word for it.
    ///
    /// The technique and nothing else. That nmap sent raw probes says nmap was
    /// privileged, which is a fact about nmap's run: see the phase's own
    /// `privileged`, which stays `None` for exactly that reason.
    fn raw(&mut self, technique: Option<TcpScanTechnique>) {
        if let Some(technique) = technique {
            self.technique.get_or_insert(technique);
        }
    }

    /// Folds a finished `<host>` in.
    fn close(&mut self, host: Option<HostAcc>) {
        let Some(accumulated) = host else {
            return;
        };

        for ip in &accumulated.addresses {
            self.accounted.insert(*ip);
        }

        // An address nmap listed as anything but up is one it was asked to
        // account for whether or not it answered, which is what makes the
        // listing a statement of scope.
        if accumulated
            .state
            .as_deref()
            .is_some_and(|state| state != "up")
        {
            self.exhaustive = true;
        }

        if let Some(host) = accumulated.into_host(self.started) {
            self.hosts.push(host);
        }
    }

    /// The report the scan would have produced.
    fn into_report(mut self) -> ScanReport {
        let kind = if self.hosts.iter().any(|host| host.port_count() > 0) {
            ScanKind::PortScan
        } else {
            ScanKind::Discovery
        };

        // Nmap gives every host it scans the same port set, so what
        // `<scaninfo>` names is true of every address the scan covered.
        let ports = match self.ports.take() {
            Some(ports) if !ports.is_empty() => PortScope::Every(ports),
            _ => PortScope::NoPorts,
        };

        let targets = if self.exhaustive {
            let mut scope = TargetScope::from_ip_set(&mut self.accounted, &Exclusions::none());
            scope = TargetScope::from_parts(ScopeParts {
                ranges: scope.ranges().to_vec(),
                // Nmap's document names no interface, so it cannot say it swept
                // a link whole even where it did.
                links: Vec::new(),
                addresses: scope.addresses(),
                probes: self.probes,
                ports,
                protocols: self.protocols.clone(),
                excluded: Vec::new(),
                withheld: 0,
            });
            scope
        } else {
            TargetScope::from_parts(ScopeParts {
                ranges: Vec::new(),
                links: Vec::new(),
                addresses: 0,
                probes: self.probes,
                ports,
                protocols: self.protocols.clone(),
                excluded: Vec::new(),
                withheld: 0,
            })
        };

        let phase = ScanPhase::from_parts(PhaseParts {
            kind,
            started_at: self.started.unwrap_or(SystemTime::UNIX_EPOCH),
            elapsed: self.elapsed.unwrap_or_default(),
            // Not this engine's question to answer. Whether *these* strategies
            // held the sockets they need is not something a scan another
            // program ran says anything about, and answering `false` claimed a
            // sweep nmap performed over ARP as root had none — which put this
            // engine's advice about running as root under findings that plainly
            // contradicted it.
            privileged: None,
            targets,
            settings: self.settings(),
            failures: Vec::new(),
            unroutable: Vec::new(),
            probes: Vec::new(),
            origin: None,
        });

        ScanReport::recorded(self.attribution(), vec![phase], self.hosts)
    }

    /// The settings, as far as the document states them.
    ///
    /// Nmap records which probe it sent and whether it looked for services and
    /// an operating system. It does not record a retransmission budget, a rate
    /// ceiling or a redaction policy, and those keep this engine's defaults — so
    /// read this for what nmap stated and not as a description of how nmap was
    /// tuned.
    fn settings(&self) -> ScanSettings {
        let mut settings = ScanSettings::from(&ZondConfig::default());
        if let Some(technique) = self.technique {
            settings.tcp_technique = technique;
        }
        settings.service_detection = if self.probed_services {
            ServiceDetection::default()
        } else {
            ServiceDetection::Off
        };
        settings.os_detection = if self.identified_os {
            OsDetection::default()
        } else {
            OsDetection::Off
        };
        settings.traceroute = false;
        settings
    }

    /// What produced the document, as it named itself.
    fn attribution(&self) -> String {
        let scanner = self.scanner.as_deref().unwrap_or("nmap");
        match self.scanner_version.as_deref() {
            Some(version) => format!("{scanner} {version}"),
            None => scanner.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// One host
// ---------------------------------------------------------------------------

/// An `<address>`, once it has been recognised.
enum Address {
    Ip(IpAddr),
    Hardware(MacAddr),
}

/// One `<host>`, gathered until its element closes.
#[derive(Debug, Default)]
struct HostAcc {
    addresses: Vec<IpAddr>,
    macs: Vec<MacAddr>,
    hostname: Option<String>,
    state: Option<String>,
    reason: Option<String>,
    ports: Vec<Port>,
    os: Option<OsFingerprint>,
    started: Option<SystemTime>,
    ended: Option<SystemTime>,
}

impl HostAcc {
    /// Reads an `<address>`, which is an IP address or a hardware one.
    fn read_address(
        element: &Element,
        parser: &Parser<'_>,
    ) -> Result<Option<Address>, ImportError> {
        let Some(addr) = element.value(b"addr") else {
            return Ok(None);
        };

        Ok(match element.value(b"addrtype") {
            Some("ipv4" | "ipv6") => {
                let ip = addr.parse::<IpAddr>().map_err(|_| {
                    parser.malformed(format!(
                        "'{addr}' is not an address nmap could have written"
                    ))
                })?;
                Some(Address::Ip(ip))
            }
            // A hardware address that will not parse is not a reason to refuse
            // the host: the addresses and ports under it are the finding, and
            // this is decoration on top of them.
            Some("mac") => MacAddr::from_str(addr).ok().map(Address::Hardware),
            _ => None,
        })
    }

    fn record(&mut self, address: Address) {
        match address {
            Address::Ip(ip) => self.addresses.push(ip),
            Address::Hardware(mac) => self.macs.push(mac),
        }
    }

    /// Takes an `<extrareasons>`, which names every port nmap left out of its
    /// list along with what it found there.
    ///
    /// This is the difference between a comparison that is readable and one that
    /// is a wall. Nmap lists the interesting ports and summarises the rest; this
    /// engine's own scans record every port they probed. Without this the
    /// hundreds nmap summarised read as ports that *appeared* the moment the two
    /// were compared, when in fact both scans found them closed.
    ///
    /// A `ports` attribute that ran past the parser's bound is simply absent,
    /// and then nothing is recorded — which reads as "not probed" rather than as
    /// a wrong verdict. See [`LOSSY`].
    fn extend(&mut self, state: PortState, element: &Element) {
        let Some(list) = element.value(b"ports") else {
            return;
        };
        let protocol = match element.value(b"proto") {
            Some("udp") => Protocol::Udp,
            // `tcp`, and anything this engine has no word for is left alone
            // rather than recorded as TCP.
            Some("tcp") | None => Protocol::Tcp,
            Some(_) => return,
        };

        let Some(ports) = services(list, protocol) else {
            return;
        };
        let reason = element.value(b"reason").map(str::to_owned);

        for (number, protocol) in ports.iter() {
            let mut port = Port::new(number, protocol, state);
            if let Some(reason) = &reason {
                port = port.with_discovery(Discovery::new(scan_response(reason)));
            }
            self.ports.push(port);
        }
    }

    /// Takes an `<osmatch>`, keeping only the first.
    ///
    /// Nmap lists every candidate it considered, best first. Keeping the rest
    /// would make a comparison report a change every time the also-rans
    /// reshuffled beneath an unchanged winner.
    fn match_os(&mut self, element: &Element) {
        if self.os.is_some() {
            return;
        }
        let Some(name) = element.value(b"name") else {
            return;
        };
        let accuracy = element
            .value(b"accuracy")
            .and_then(|a| a.parse::<u8>().ok())
            .unwrap_or(0);

        self.os = Some(OsFingerprint::new(name, accuracy));
    }

    /// Takes an `<osclass>`, which carries the family and generation the match
    /// above it does not. Only the first class of the first match contributes,
    /// for the reason [`match_os`](Self::match_os) gives.
    fn classify_os(&mut self, element: &Element) {
        let Some(os) = self.os.take() else {
            return;
        };
        if os.family().is_some() {
            self.os = Some(os);
            return;
        }

        let mut os = os;
        if let Some(family) = element.value(b"osfamily") {
            os = os.with_family(family);
        }
        if let Some(generation) = element.value(b"osgen") {
            os = os.with_generation(generation);
        }
        if let Some(vendor) = element.value(b"vendor") {
            os = os.with_vendor(vendor);
        }
        self.os = Some(os);
    }

    /// The host this record describes, or `None` if it named no address.
    fn into_host(self, run_started: Option<SystemTime>) -> Option<Host> {
        let (primary, rest) = self.addresses.split_first()?;

        let mut host = Host::new(*primary);
        host.extend_ips(rest.iter().copied());

        if let Some(hostname) = self.hostname {
            host.set_hostname(Some(hostname));
        }

        for mac in self.macs {
            host.record_mac(mac);
        }

        let status = status_of(self.state.as_deref(), self.reason.as_deref());
        match self.reason.as_deref() {
            Some(reason) if status != HostStatus::Unknown => {
                host.record_evidence(status, StatusReason::new(status_protocol(reason), reason));
            }
            _ => host.set_status(status),
        }

        let answered = self
            .ports
            .iter()
            .any(|port| matches!(port.state(), PortState::Open | PortState::Closed));
        for port in self.ports {
            host.add_port(port);
        }

        // A port that accepted a connection or refused one was answered by the
        // host's own stack, whatever the discovery phase concluded. This is the
        // inference that recovers a host nmap was told not to probe.
        if answered {
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::Tcp, "a probed port answered for the host"),
            );
        }

        if let Some(os) = self.os {
            host.set_os(os);
        }

        // Last, because every mutator above stamps the current time and this is
        // the record of when the scan saw the host.
        let first = self.started.or(run_started);
        let last = self.ended.or(first);
        if let (Some(first), Some(last)) = (first, last) {
            host.restore_seen(first, last);
        }

        Some(host)
    }
}

/// What a `<status>` establishes, in this engine's four states.
fn status_of(state: Option<&str>, reason: Option<&str>) -> HostStatus {
    match state {
        // `user-set` is what nmap records when it was told to skip discovery.
        // Nothing was sent and nothing answered, so the word is an instruction
        // echoed back rather than a finding.
        Some("up") if reason == Some("user-set") => HostStatus::Unknown,
        Some("up") => HostStatus::Up,
        Some("down") => match reason {
            Some(reason) if reason.ends_with("-prohibited") => HostStatus::Filtered,
            Some(reason) if reason.ends_with("-unreach") => HostStatus::Down,
            // Including `no-response`, which is silence, and silence is not
            // evidence of absence.
            _ => HostStatus::Unknown,
        },
        Some("filtered") => HostStatus::Filtered,
        _ => HostStatus::Unknown,
    }
}

/// Which protocol carried the evidence nmap named.
fn status_protocol(reason: &str) -> StatusProtocol {
    match reason {
        "arp-response" => StatusProtocol::Arp,
        "nd-response" => StatusProtocol::Ndp,
        "echo-reply" | "timestamp-reply" | "netmask-reply" => StatusProtocol::IcmpEcho,
        "syn-ack" => StatusProtocol::TcpSyn,
        "reset" | "conn-refused" => StatusProtocol::Tcp,
        "udp-response" => StatusProtocol::Udp,
        reason if reason.ends_with("-unreach") || reason.ends_with("-prohibited") => {
            StatusProtocol::IcmpUnreachable
        }
        other => StatusProtocol::Custom(Arc::from(other)),
    }
}

// ---------------------------------------------------------------------------
// One port
// ---------------------------------------------------------------------------

/// One `<port>`, gathered until its element closes.
#[derive(Debug)]
struct PortAcc {
    number: u16,
    protocol: Protocol,
    state: PortState,
    reason: Option<String>,
    service: Option<Service>,
}

impl PortAcc {
    /// Takes a `<port>`, which names the endpoint and nothing about it.
    fn open(element: &Element, parser: &Parser<'_>) -> Result<Self, ImportError> {
        let number = element
            .value(b"portid")
            .and_then(|id| id.parse::<u16>().ok())
            .ok_or_else(|| parser.malformed("a port with no readable number".to_string()))?;

        // An unrecognised transport is refused rather than guessed at, for the
        // reason the target reader gives: it is not a field a reader can skip,
        // it is the value that decides what the record says.
        let protocol = match element.value(b"protocol") {
            Some("tcp") => Protocol::Tcp,
            Some("udp") => Protocol::Udp,
            Some(other) => {
                return Err(parser.malformed(format!(
                    "port {number} names transport '{other}', which this engine cannot scan"
                )));
            }
            None => return Err(parser.malformed(format!("port {number} names no transport"))),
        };

        Ok(Self {
            number,
            protocol,
            state: PortState::Filtered,
            reason: None,
            service: None,
        })
    }

    /// Reads the `<state>` inside a port, which is the verdict.
    fn read_state(
        element: &Element,
        parser: &Parser<'_>,
    ) -> Result<Option<(PortState, Option<String>)>, ImportError> {
        let Some(state) = element.value(b"state") else {
            return Ok(None);
        };

        Ok(Some((
            Self::state_named(state, parser)?,
            attr(element, b"reason"),
        )))
    }

    /// One of nmap's six verdicts, in this engine's terms.
    ///
    /// An unrecognised one is refused rather than guessed at, for the reason the
    /// target reader gives: it is the value that decides what the record says.
    fn state_named(state: &str, parser: &Parser<'_>) -> Result<PortState, ImportError> {
        Ok(match state {
            "open" => PortState::Open,
            "closed" => PortState::Closed,
            "filtered" => PortState::Filtered,
            "unfiltered" => PortState::Unfiltered,
            "open|filtered" => PortState::OpenFiltered,
            "closed|filtered" => PortState::ClosedFiltered,
            other => {
                return Err(parser.malformed(format!(
                    "a port is in state '{other}', which this engine has no verdict for"
                )));
            }
        })
    }

    /// Takes the `<service>` inside a port, unless nmap only looked the number
    /// up.
    fn identify(&mut self, element: &Element) {
        let Some(name) = element.value(b"name") else {
            return;
        };

        // `table` means nmap read the port number out of a file rather than
        // asking the service. Confidence zero is how this engine records the
        // same thing about its own port-number labels, and what a comparison
        // reads to know it is not a finding.
        let confidence = if element.value(b"method") == Some("probed") {
            element
                .value(b"conf")
                .and_then(|c| c.parse::<u8>().ok())
                .unwrap_or(0)
                .saturating_mul(CONFIDENCE_SCALE)
        } else {
            0
        };

        let mut service = Service::new(name, confidence);
        if let Some(product) = element.value(b"product") {
            service = service.with_product(product);
        }
        if let Some(version) = element.value(b"version") {
            service = service.with_version(version);
        }
        if let Some(extra) = element.value(b"extrainfo") {
            service = service.with_extrainfo(extra);
        }

        self.service = Some(service);
    }

    /// The port this record describes.
    fn into_port(self) -> Port {
        let mut port = Port::new(self.number, self.protocol, self.state);

        if let Some(service) = self.service {
            port.set_service(service);
        }

        if let Some(reason) = self.reason {
            port = port.with_discovery(Discovery::new(scan_response(&reason)));
        }

        port
    }
}

/// The packet nmap says settled a port's state.
fn scan_response(reason: &str) -> ScanResponse {
    match reason {
        "syn-ack" => ScanResponse::TcpSynAck,
        "reset" | "conn-refused" => ScanResponse::TcpRst,
        "no-response" => ScanResponse::NoResponse,
        "udp-response" | "proto-response" => ScanResponse::UdpResponse,
        reason if reason.ends_with("-prohibited") => ScanResponse::IcmpProhibited,
        reason if reason.ends_with("-unreach") => ScanResponse::IcmpUnreachable,
        other => ScanResponse::Custom(other.to_string()),
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
    use std::io::Cursor;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::diff::{Coverage, Presence, ScanDiff};

    fn read(document: &str) -> Result<ScanReport, ImportError> {
        let reader = NmapXmlReportReader::default();
        reader.read(&mut Cursor::new(document))
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, last))
    }

    /// What nmap writes for `-sS -sV -O --reason` over two addresses, one of
    /// which did not answer.
    const SWEEP: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -sV" start="1690000000" version="7.94">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1024"/>
<host starttime="1690000001" endtime="1690000009">
<status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.168.0.10" addrtype="ipv4"/>
<address addr="2C:CF:67:F2:51:E3" addrtype="mac" vendor="Raspberry Pi"/>
<hostnames><hostname name="pi.local" type="PTR"/></hostnames>
<ports>
<extraports state="closed" count="998"><extrareasons reason="resets" count="998"/></extraports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu" method="probed" conf="10">
<cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
</service>
</port>
<port protocol="tcp" portid="80">
<state state="closed" reason="reset" reason_ttl="64"/>
<service name="http" method="table" conf="3"/>
</port>
</ports>
<os><osmatch name="Linux 5.0 - 5.14" accuracy="97">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="97">
<cpe>cpe:/o:linux:linux_kernel:5</cpe>
</osclass></osmatch></os>
</host>
<host starttime="1690000001" endtime="1690000009">
<status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.0.11" addrtype="ipv4"/>
</host>
<runstats><finished time="1690000010" elapsed="9.42"/></runstats>
</nmaprun>"#;

    #[test]
    fn a_scan_reads_back_as_its_hosts_ports_and_services() {
        let report = read(SWEEP).expect("a readable document");

        assert_eq!(report.engine_version(), "nmap 7.94");
        assert_eq!(report.host_count(), 2);

        let host = report.host(&ip(10)).expect("the host that answered");
        assert_eq!(host.status(), HostStatus::Up);
        assert_eq!(host.hostname(), Some("pi.local"));
        assert_eq!(
            host.mac(),
            Some(MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3))
        );

        let ssh = host.ports().find(|port| port.number() == 22).expect("22");
        assert_eq!(ssh.state(), PortState::Open);
        let service = ssh.service().expect("a probed service");
        assert_eq!(service.name(), "ssh");
        assert_eq!(service.product(), Some("OpenSSH"));
        assert_eq!(service.version(), Some("8.9p1"));
        assert_eq!(service.extrainfo(), Some("Ubuntu"));
        assert!(
            service
                .cpes()
                .iter()
                .any(|cpe| &**cpe == "cpe:/a:openbsd:openssh:8.9p1"),
            "the CPE is element text, not an attribute: {:?}",
            service.cpes()
        );

        let os = host.os().expect("an operating system");
        assert_eq!(os.name(), "Linux 5.0 - 5.14");
        assert_eq!(os.family(), Some("Linux"));
        assert_eq!(os.generation(), Some("5.X"));
        assert_eq!(os.accuracy(), 97);
        assert!(
            os.cpes()
                .iter()
                .any(|cpe| &**cpe == "cpe:/o:linux:linux_kernel:5")
        );
    }

    /// A port-number lookup is recorded, and recorded as the guess it is.
    ///
    /// This engine seeds the same label on every classified port of its own, so
    /// dropping nmap's would make the two asymmetrical — and a comparison would
    /// then report a service on every well-known port the moment an nmap scan
    /// entered one.
    #[test]
    fn a_service_nmap_looked_up_in_a_table_is_marked_as_inferred() {
        let report = read(SWEEP).expect("a readable document");
        let host = report.host(&ip(10)).expect("the host");
        let http = host.ports().find(|port| port.number() == 80).expect("80");

        assert_eq!(http.state(), PortState::Closed);
        let service = http.service().expect("the label is kept");
        assert_eq!(service.name(), "http");
        assert!(
            service.is_inferred(),
            "nothing asked the port what it was running"
        );

        // And a probed one is not.
        let ssh = host.ports().find(|port| port.number() == 22).expect("22");
        assert!(!ssh.service().expect("a probed service").is_inferred());
    }

    /// The property the one above exists to protect.
    #[test]
    fn a_port_number_label_never_reaches_a_comparison() {
        let report = read(SWEEP).expect("a readable document");

        // The same scan with nmap's table label changed to another one, which is
        // what a different port catalogue amounts to.
        let renamed = SWEEP.replace(
            r#"<service name="http" method="table" conf="3"/>"#,
            r#"<service name="www" method="table" conf="3"/>"#,
        );
        let other = read(&renamed).expect("a readable document");

        assert!(
            ScanDiff::between(&report, &other).is_empty(),
            "two port catalogues disagreeing is not a change to the network"
        );
    }

    // -----------------------------------------------------------------------
    // Nmap's `down` is not this engine's
    // -----------------------------------------------------------------------

    #[test]
    fn a_host_that_merely_did_not_answer_is_unknown_not_down() {
        let report = read(SWEEP).expect("a readable document");
        let quiet = report.host(&ip(11)).expect("the host that did not answer");

        assert_eq!(
            quiet.status(),
            HostStatus::Unknown,
            "silence is not evidence that an address is unreachable"
        );
    }

    #[test]
    fn a_host_an_intermediary_reported_unreachable_is_down() {
        let document = SWEEP.replace(
            r#"<status state="down" reason="no-response" reason_ttl="0"/>"#,
            r#"<status state="down" reason="host-unreach" reason_ttl="61"/>"#,
        );

        let report = read(&document).expect("a readable document");
        assert_eq!(
            report.host(&ip(11)).expect("the host").status(),
            HostStatus::Down
        );
    }

    #[test]
    fn a_host_a_policy_rejected_is_filtered() {
        let document = SWEEP.replace(
            r#"<status state="down" reason="no-response" reason_ttl="0"/>"#,
            r#"<status state="down" reason="admin-prohibited" reason_ttl="61"/>"#,
        );

        let report = read(&document).expect("a readable document");
        assert_eq!(
            report.host(&ip(11)).expect("the host").status(),
            HostStatus::Filtered
        );
    }

    #[test]
    fn a_host_up_only_because_discovery_was_skipped_is_unknown() {
        // What `-Pn --reason` writes: nmap was told the host is up and repeats
        // it back, having sent nothing.
        let document = r#"<nmaprun scanner="nmap" start="1690000000" version="7.94">
<host><status state="up" reason="user-set"/>
<address addr="192.168.0.11" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80">
<state state="filtered" reason="no-response"/>
</port></ports></host></nmaprun>"#;

        let report = read(document).expect("a readable document");
        assert_eq!(
            report.host(&ip(11)).expect("the host").status(),
            HostStatus::Unknown,
            "an instruction echoed back is not evidence the host answered"
        );
    }

    #[test]
    fn a_port_that_answered_proves_the_host_is_up_whatever_discovery_said() {
        let document = r#"<nmaprun scanner="nmap" start="1690000000" version="7.94">
<host><status state="up" reason="user-set"/>
<address addr="192.168.0.11" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443">
<state state="open" reason="syn-ack"/>
</port></ports></host></nmaprun>"#;

        let report = read(document).expect("a readable document");
        assert_eq!(
            report.host(&ip(11)).expect("the host").status(),
            HostStatus::Up,
            "a SYN+ACK requires a live stack, whether or not discovery ran"
        );
    }

    // -----------------------------------------------------------------------
    // What the document says it covered
    // -----------------------------------------------------------------------

    #[test]
    fn a_document_listing_an_address_that_did_not_answer_states_its_scope() {
        let report = read(SWEEP).expect("a readable document");
        let scope = report.phases()[0].targets();

        assert_eq!(
            scope.addresses(),
            2,
            "both addresses were accounted for, so both were walked"
        );
        assert!(scope.ranges().iter().any(|range| range.contains(&ip(10))));
        assert!(scope.ranges().iter().any(|range| range.contains(&ip(11))));
    }

    #[test]
    fn a_document_of_nothing_but_live_hosts_claims_no_scope() {
        let document = r#"<nmaprun scanner="nmap" start="1690000000" version="7.94">
<host><status state="up" reason="echo-reply"/>
<address addr="192.168.0.10" addrtype="ipv4"/></host></nmaprun>"#;

        let report = read(document).expect("a readable document");
        assert!(
            report.phases()[0].targets().ranges().is_empty(),
            "nmap lists the addresses that did not answer only when asked to, so \
             a document without one cannot say what it walked"
        );

        // And a comparison against it therefore confirms nothing.
        let baseline = ScanReport::recorded("test", Vec::new(), vec![Host::new(ip(99))]);
        let diff = ScanDiff::between(&baseline, &report);
        let gone = diff
            .hosts()
            .iter()
            .find(|delta| delta.address() == ip(99))
            .expect("the host only the baseline has");
        assert_eq!(
            gone.presence(),
            Presence::Removed {
                after: Coverage::Unstated
            }
        );
    }

    // -----------------------------------------------------------------------
    // Refusals
    // -----------------------------------------------------------------------

    #[test]
    fn a_port_state_this_engine_has_no_verdict_for_is_refused() {
        let document = r#"<nmaprun><host><address addr="192.168.0.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="perhaps"/></port></ports>
</host></nmaprun>"#;

        let error = read(document).expect_err("refused");
        assert!(error.to_string().contains("perhaps"), "{error}");
    }

    #[test]
    fn a_document_that_is_not_nmaps_is_refused() {
        let error = read("<other><host/></other>").expect_err("refused");
        assert!(error.to_string().contains("nmaprun"), "{error}");
    }

    #[test]
    fn an_entity_declaration_is_refused_here_too() {
        let document = r#"<?xml version="1.0"?>
<!DOCTYPE nmaprun [<!ENTITY x "boom">]>
<nmaprun><host><address addr="192.168.0.10" addrtype="ipv4"/></host></nmaprun>"#;

        let error = read(document).expect_err("refused");
        assert!(error.to_string().contains("DOCTYPE"), "{error}");
    }

    // -----------------------------------------------------------------------
    // The whole point: comparing an nmap scan with something else
    // -----------------------------------------------------------------------

    #[test]
    fn two_nmap_scans_compare_as_a_network_that_changed() {
        let later = SWEEP
            .replace(r#"version="8.9p1""#, r#"version="9.6p1""#)
            .replace(
                r#"<state state="closed" reason="reset" reason_ttl="64"/>"#,
                r#"<state state="open" reason="syn-ack" reason_ttl="64"/>"#,
            );

        let before = read(SWEEP).expect("a readable document");
        let after = read(&later).expect("a readable document");

        let diff = ScanDiff::between(&before, &after);
        let summary = diff.summary();

        assert_eq!(
            summary.ports_opened.total, 1,
            "port 80 went from closed to open"
        );
        assert_eq!(
            summary.ports_opened.confirmed, 1,
            "both scans hold a record for it"
        );
        assert_eq!(summary.services_changed, 1, "OpenSSH moved a version");
        assert_eq!(summary.hosts_added.total, 0);
        assert_eq!(summary.hosts_removed.total, 0);
    }

    #[test]
    fn an_unchanged_nmap_document_compares_as_unchanged() {
        let before = read(SWEEP).expect("a readable document");
        let after = read(SWEEP).expect("a readable document");

        assert!(
            ScanDiff::between(&before, &after).is_empty(),
            "reading the same file twice must not manufacture a change"
        );
    }
}
