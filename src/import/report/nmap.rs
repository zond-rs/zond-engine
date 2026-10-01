// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading nmap's XML as a report
//!
//! The nmap XML file [`import::nmap`](crate::import::nmap) reads as targets, read
//! here as what that scan found: hosts with their reachability, ports with their
//! states, services with their versions, and the operating system nmap settled
//! on. The result is a [`ScanReport`], ready for [`diff`](crate::diff).
//!
//! Parsing, refusals and bounds come from `xml`; this module is the mapping.
//!
//! ## Where nmap's vocabulary differs
//!
//! Four places where a literal translation would record something the scan did
//! not establish.
//!
//! A host nmap calls `down` is [`Unknown`](HostStatus::Unknown) unless its
//! `reason` says otherwise. Nmap uses the word both for an intermediary reporting
//! an address unreachable and for silence, and [`HostStatus::Down`] is never
//! inferred from silence. `host-unreach` and its relatives give
//! [`Down`](HostStatus::Down), `admin-prohibited` and its relatives give
//! [`Blocked`](HostStatus::Blocked), and everything else, including
//! `no-response`, gives `Unknown`.
//!
//! A host nmap calls `up` for the reason `user-set` is `Unknown`. Nmap records
//! that when told to skip host discovery, so no probe was sent. If such a host
//! has a port that answered, the status is promoted on that evidence, as this
//! engine's own port scanner does.
//!
//! A service nmap identified by `method="table"` is recorded at confidence zero.
//! That method is a lookup of the port number, which is what
//! [`baseline_service`](crate::fingerprint::baseline_service) does here, and
//! [`Service::is_inferred`](crate::model::port::Service::is_inferred) marks both.
//! A comparison ignores inferred services, so two tools with different port
//! catalogues do not appear to disagree about every port.
//!
//! The hostname is the first `<hostname>` of any type, except a `user` name in a
//! document this engine wrote. Nmap uses `user` for a name the operator gave as a
//! target; this engine's exporter uses it for DNS names a host gave for itself,
//! which are not what a lookup resolved.
//!
//! ## Scope
//!
//! [`TargetScope`] lets a comparison tell a host that went away from one nobody
//! looked for, but nmap's XML does not record its resolved target set. It writes
//! a `<host>` per address it accounted for, and lists addresses that did not
//! answer only when asked to. So a document containing any host that is not `up`
//! lists everything it considered.
//!
//! The scope is therefore the addresses the document accounts for, claimed only
//! when such a host appears. A document of only live hosts states no scope, and a
//! comparison answers [`Unstated`](crate::diff::Coverage::Unstated) for it.
//! Under-claiming costs some confirmations; over-claiming would report hosts as
//! gone that were never looked for.
//!
//! ## What is not read
//!
//! Traceroute hops, `<distance>`, `<times>`, `<uptime>`, the sequence
//! predictions, `<owner>`, the raw service fingerprints, and every `<script>`
//! element on a port or under `<hostscript>`. None bears on what
//! [`diff`](crate::diff) compares.
//!
//! This engine's own nmap exporter writes findings and paths, so a report
//! exported to nmap XML and read back here loses both: nmap carries a finding as
//! `<script output>` text, without the detection identity, version and content
//! hash a `Finding` needs. `<distance>` and `<times>` are recoverable but not read
//! yet. [`json`](super::json) is the round trip that keeps everything.
//!
//! `<extraports>` and its `<extrareasons ports="…">` are read. Nmap names the
//! summarised ports there when asked to, and without them hundreds of closed
//! ports would appear to have opened in a comparison.

use std::collections::BTreeMap;
use std::io::BufRead;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::config::{OsDetection, ServiceDetection, ZondConfig};
use crate::import::report::{ReportOptions, ReportReader};
use crate::import::xml::{Element, Event, Parser, elements_within};
use crate::import::{ImportError, ImportOrigin};
use crate::model::exclusion::Exclusions;
use crate::model::host::os::OsFingerprint;
use crate::model::host::{Host, HostStatus, IpProtocolState, StatusProtocol, StatusReason};
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;
use crate::model::port::discovery::{Discovery, ScanResponse};
use crate::model::port::{self, Port, PortSet, PortState, Protocol, Service};
use crate::model::technique::TcpScanTechnique;
use crate::report::{
    PhaseParts, PortScope, ScanKind, ScanPhase, ScanReport, ScanSettings, ScopeParts, TargetScope,
};

/// The format's name in errors.
const FORMAT: &str = "nmap XML";

/// The attributes this reader keeps. Everything else is skipped unbuffered.
///
/// Several names appear on more than one element (`version` on `<nmaprun>` and
/// `<service>`, `name` on three), so the element being read decides which is
/// meant.
///
/// `args` is left out: it runs to kilobytes and nothing reads it. `services` and
/// `ports` can be as long, but say which ports were probed and which were left
/// out of the port list. Both are [lossy](crate::import::xml::Parser::with_lossy),
/// since a sparse sweep of every port could write several hundred kilobytes of
/// either.
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
    b"tunnel",
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
    b"proto",
    b"scanner",
];

/// The attributes dropped, not refused, when they run long.
///
/// Without them a comparison can only say it cannot tell whether an endpoint was
/// probed, which is still correct.
const LOSSY: &[&[u8]] = &[b"services", b"ports"];

/// The longest attribute value kept, in bytes.
///
/// Well past the parser's default because nmap writes its default port set to
/// `services` as an explicit list of a thousand entries, several kilobytes. The
/// element's markup is still bounded by
/// [`ImportLimits::max_line_bytes`](crate::import::ImportLimits::max_line_bytes),
/// and the document by [`ReportOptions::max_document_bytes`].
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
        let max_document_bytes = self.options.max_document_bytes;
        crate::import::bounded::within(input, max_document_bytes, |input| self.read_within(input))
    }
}

impl NmapXmlReportReader {
    /// The parser a document is read with. The element ceiling is derived from
    /// the document ceiling, so raising the byte ceiling raises both.
    fn parser<'a>(&self, input: &'a mut dyn BufRead) -> Parser<'a> {
        Parser::new(input, self.options.limits.max_line_bytes, FORMAT, KEPT)
            .with_max_value_bytes(MAX_VALUE_BYTES)
            .with_lossy(LOSSY)
            .with_max_elements(elements_within(self.options.max_document_bytes))
    }

    /// [`read`](ReportReader::read), over an input already cut off at the
    /// document ceiling.
    fn read_within(&self, input: &mut dyn BufRead) -> Result<ScanReport, ImportError> {
        crate::import::skip_bom(input)?;

        let mut parser = self.parser(input);
        let mut state = State::new(self.options.limits.max_addresses);

        loop {
            match parser.next_event()? {
                Event::Eof => break,

                Event::Start { self_closing } => {
                    let tag = Tag::of(&parser.element.name);
                    state.on_start(tag, self_closing, &mut parser)?;

                    // A self-closing `<host/>` or `<port/>` opens and closes in
                    // one event and never sees an `End`.
                    if self_closing {
                        state.close_element(tag)?;
                    }
                }

                Event::End => {
                    let tag = Tag::of(&parser.element.name);
                    state.on_end(tag, &mut parser)?;
                }
            }
        }

        let run = state.run;
        if !run.saw_root {
            return Err(ImportError::Malformed {
                format: FORMAT,
                origin: ImportOrigin::unknown(),
                message: "no <nmaprun> element: this is not an nmap document".to_string(),
            });
        }

        // The host ceiling was checked as each `<host>` closed.
        Ok(run.into_report())
    }
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

/// Everything the document has said so far, as the parser walks it.
///
/// The run being assembled, the host and port currently being read, and the
/// context that decides what a nested element belongs to.
#[derive(Debug, Default)]
struct State {
    run: Run,
    host: Option<HostAcc>,
    port: Option<PortAcc>,
    /// The state an `<extraports>` block is reporting, while inside one.
    bulk: Option<String>,
    inside: Inside,
    /// The most hosts the document may name, checked as each one closes.
    max_hosts: u128,
}

impl State {
    /// A walk bounded by how many hosts the document may name.
    fn new(max_hosts: u128) -> Self {
        Self {
            max_hosts,
            ..Self::default()
        }
    }

    /// Takes one opening element and folds what it carries in.
    ///
    /// A self-closing element opens nothing, so the arms that set what the parser
    /// is inside, or begin capturing text, skip it. The caller closes it through
    /// [`close_element`](Self::close_element).
    fn on_start(
        &mut self,
        tag: Tag,
        self_closing: bool,
        parser: &mut Parser<'_>,
    ) -> Result<(), ImportError> {
        match tag {
            Tag::NmapRun => {
                self.run.saw_root = true;
                self.run.scanner = attr(&parser.element, b"scanner");
                self.run.scanner_version = attr(&parser.element, b"version");
                self.run.started = attr(&parser.element, b"start").and_then(|s| epoch(&s));
            }
            Tag::ScanInfo => self.run.scan_info(&parser.element),
            Tag::Host => {
                self.host = Some(HostAcc {
                    started: attr(&parser.element, b"starttime").and_then(|s| epoch(&s)),
                    ended: attr(&parser.element, b"endtime").and_then(|s| epoch(&s)),
                    ..HostAcc::default()
                });
            }
            Tag::Status => {
                if let Some(host) = self.host.as_mut() {
                    host.state = attr(&parser.element, b"state");
                    host.reason = attr(&parser.element, b"reason");
                }
            }
            Tag::Address => self.record_address(parser)?,
            // The first name is the hostname, except a `user` name in this
            // engine's own document, which is a DNS name the host gave for itself.
            Tag::HostName => {
                let stated = self.run.scanner.as_deref() == Some(crate::format::NMAP_SCANNER)
                    && attr(&parser.element, b"type").as_deref() == Some("user");
                if let Some(host) = self.host.as_mut()
                    && host.hostname.is_none()
                    && !stated
                {
                    host.hostname = attr(&parser.element, b"name");
                }
            }
            Tag::Port => self.port = Some(PortAcc::open(&parser.element, parser)?),
            // Ports nmap probed but summarised, not listed one by one.
            Tag::ExtraPorts => self.bulk = attr(&parser.element, b"state"),
            Tag::ExtraReasons => {
                if let (Some(host), Some(state)) = (self.host.as_mut(), self.bulk.as_deref()) {
                    let reason = parser.element.value(b"reason");
                    let state = PortAcc::state_named(state, reason, parser)?;
                    host.extend(state, &parser.element);
                }
            }
            Tag::State => self.settle_port(parser)?,
            Tag::Service => {
                if let Some(port) = self.port.as_mut() {
                    port.identify(&parser.element);
                    self.run.probed_services |= port.service.is_some();
                }
                if !self_closing {
                    self.inside = Inside::Service;
                }
            }
            Tag::OsMatch => {
                if let Some(host) = self.host.as_mut() {
                    host.match_os(&parser.element);
                    self.run.identified_os |= host.os.is_some();
                }
                if !self_closing {
                    self.inside = Inside::Os;
                }
            }
            Tag::OsClass => {
                if let Some(host) = self.host.as_mut() {
                    host.classify_os(&parser.element);
                }
                if !self_closing {
                    self.inside = Inside::Os;
                }
            }
            Tag::Cpe => {
                if !self_closing && self.inside != Inside::Nothing {
                    parser.begin_text();
                }
            }
            Tag::Finished => {
                self.run.elapsed = attr(&parser.element, b"elapsed")
                    .and_then(|s| s.parse::<f64>().ok())
                    .and_then(|seconds| Duration::try_from_secs_f64(seconds).ok());
            }
            Tag::Other => {}
        }

        Ok(())
    }

    /// Takes one closing element.
    fn on_end(&mut self, tag: Tag, parser: &mut Parser<'_>) -> Result<(), ImportError> {
        match tag {
            Tag::ExtraPorts => self.bulk = None,
            Tag::Host | Tag::Port => self.close_element(tag)?,
            Tag::Cpe => self.record_cpe(parser.take_text()?),
            Tag::Service | Tag::OsMatch => self.inside = Inside::Nothing,
            _ => {}
        }

        Ok(())
    }

    /// Folds a finished element into what holds it: a `<host>` into the run, a
    /// `<port>` into the host it was found on.
    ///
    /// A port found outside a host is dropped, since there is nothing to record
    /// it against.
    fn close_element(&mut self, tag: Tag) -> Result<(), ImportError> {
        match tag {
            Tag::Host => {
                self.run.close(self.host.take());
                // Checked as each host closes, before the next allocation.
                if self.run.hosts.len() as u128 > self.max_hosts {
                    return Err(ImportError::TooManyHosts {
                        limit: self.max_hosts,
                    });
                }
            }
            Tag::Port => {
                if let (Some(host), Some(port)) = (self.host.as_mut(), self.port.take()) {
                    match port.ip_protocol {
                        true => host.ip_protocols.push(port.into_ip_protocol()),
                        false => port::fold(&mut host.ports, port.into_port()),
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Records what an `<address>` names on the host being read.
    ///
    /// One outside a `<host>` is skipped unread, so a malformed address refuses
    /// the document only where it belongs to a host.
    fn record_address(&mut self, parser: &Parser<'_>) -> Result<(), ImportError> {
        if self.host.is_none() {
            return Ok(());
        }

        let address = HostAcc::read_address(&parser.element, parser)?;
        if let (Some(host), Some(address)) = (self.host.as_mut(), address) {
            host.record(address);
        }

        Ok(())
    }

    /// Settles the port being read on the verdict its `<state>` names.
    ///
    /// One outside a `<port>` is skipped unread, as in
    /// [`record_address`](Self::record_address).
    fn settle_port(&mut self, parser: &Parser<'_>) -> Result<(), ImportError> {
        if self.port.is_none() {
            return Ok(());
        }

        let settled = PortAcc::read_state(&parser.element, parser)?;
        if let (Some(port), Some((state, reason))) = (self.port.as_mut(), settled) {
            port.state = state;
            port.reason = reason;
        }

        Ok(())
    }

    /// Files a `<cpe>` under the identification it qualifies.
    ///
    /// An empty one, and one that appeared outside a `<service>` or an
    /// `<osmatch>`, qualifies nothing and is dropped.
    fn record_cpe(&mut self, cpe: String) {
        if cpe.is_empty() {
            return;
        }

        match self.inside {
            Inside::Service => {
                if let Some(service) = self.port.as_mut().and_then(|port| port.service.as_mut()) {
                    service.add_cpe(cpe);
                }
            }
            Inside::Os => {
                if let Some(os) = self.host.as_mut().and_then(|host| host.os.as_mut()) {
                    os.add_cpe(cpe);
                }
            }
            Inside::Nothing => {}
        }
    }
}

/// Which element the parser is inside, for the ones whose text belongs to
/// something further out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Inside {
    #[default]
    Nothing,
    Service,
    Os,
}

/// The elements this reader acts on. Everything else is `Other` and skipped.
///
/// Resolved from the name once per element, so nothing borrows the parser while
/// the element is handled.
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

/// One attribute as an owned string, ending the parser borrow.
fn attr(element: &Element, name: &[u8]) -> Option<String> {
    element.value(name).map(str::to_owned)
}

/// The port set a `<scaninfo>` names, in this engine's specification grammar.
///
/// Nmap writes a bare list and names the transport in a sibling attribute. This
/// grammar carries the transport in each entry, so every entry gets its prefix.
fn services(spec: &str, protocol: Protocol) -> Option<PortSet> {
    let prefix = protocol.spec_prefix();
    let spec = spec
        .split(',')
        .map(|entry| format!("{prefix}{}", entry.trim()))
        .collect::<Vec<_>>()
        .join(",");

    PortSet::try_from(spec.as_str()).ok()
}

/// Seconds since the epoch, as nmap writes every time in its document.
///
/// `None` for a count [`SystemTime`] cannot represent, such as
/// `start="16847805878974283974"`. The addition is checked because `+` would
/// panic on such a value from an untrusted file.
fn epoch(seconds: &str) -> Option<SystemTime> {
    let seconds = seconds.parse::<u64>().ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
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
    /// Takes a `<scaninfo>`, where nmap says which probe it sent and to which
    /// ports.
    fn scan_info(&mut self, element: &Element) {
        // `ip` (a protocol scan) names no transport and is ignored, as is any
        // other unreadable value: a bad `<scaninfo>` does not refuse the
        // findings.
        let protocol = element
            .value(b"protocol")
            .and_then(crate::record::wire::protocol);
        if let Some(protocol) = protocol {
            // Nmap writes one `<scaninfo>` per scan type, so a SYN and an ACK
            // scan name TCP twice.
            if !self.protocols.contains(&protocol) {
                self.protocols.push(protocol);
            }

            // The resolved port set, applied to every host.
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

        // Saturating: the number of `<scaninfo>` elements is unbounded, and a
        // wrapped total would read as a plausible count.
        if let Some(count) = element
            .value(b"numservices")
            .and_then(|n| n.parse::<u128>().ok())
        {
            let probes = self.probes.get_or_insert(0);
            *probes = probes.saturating_add(count);
        }

        // The scan type says which segment went out and whether it needed a
        // raw socket.
        match element.value(b"type") {
            Some("syn") => self.raw(Some(TcpScanTechnique::Syn)),
            Some("ack") => self.raw(Some(TcpScanTechnique::Ack)),
            Some("fin") => self.raw(Some(TcpScanTechnique::Fin)),
            Some("null") => self.raw(Some(TcpScanTechnique::Null)),
            Some("xmas") => self.raw(Some(TcpScanTechnique::Xmas)),
            Some("maimon") => self.raw(Some(TcpScanTechnique::Maimon)),
            Some("window") => self.raw(Some(TcpScanTechnique::Window)),
            Some("udp" | "ipproto" | "sctpinit" | "sctpcookieecho") => self.raw(None),
            // A connect scan, nmap's unprivileged fallback, records nothing.
            _ => {}
        }
    }

    /// Records that a raw probe was sent, and which one where this engine has a
    /// word for it.
    ///
    /// Records only the technique. Nmap's privileges are a fact about nmap's run,
    /// so the phase's `privilege` stays `None`.
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

        // Nmap lists a host that is not up only when asked to account for every
        // address, which makes the listing a statement of scope.
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

        // Nmap scans every host on the same port set.
        let ports = match self.ports.take() {
            Some(ports) if !ports.is_empty() => PortScope::Every(ports),
            _ => PortScope::NoPorts,
        };

        let targets = if self.exhaustive {
            let mut scope = TargetScope::from_ip_set(&mut self.accounted, &Exclusions::none());
            scope = TargetScope::from_parts(ScopeParts {
                // Nmap has no listen-only phase.
                listened: Vec::new(),
                ranges: scope.ranges().to_vec(),
                // The document names no interface.
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
                listened: Vec::new(),
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
            // Nmap's format has none.
            attachments: Vec::new(),
            kind,
            started_at: self.started.unwrap_or(SystemTime::UNIX_EPOCH),
            elapsed: self.elapsed.unwrap_or_default(),
            // Unknown: nmap's privileges say nothing about this engine's
            // strategies, and `false` would contradict a root ARP sweep.
            privilege: None,
            targets,
            settings: self.settings(),
            failures: Vec::new(),
            // Nmap's output does not distinguish ground it declined.
            refusals: Vec::new(),
            unroutable: Vec::new(),
            refused_by_route: Vec::new(),
            timed_out: Vec::new(),
            icmp_rate_limited: Vec::new(),
            reached_by_connect: Vec::new(),
            // The scope holds only addresses the document gave a verdict on.
            undecided: Vec::new(),
            // The document does not say whether host discovery ran.
            liveness_skipped: None,
            silent: Vec::new(),
            stopped: None,
            passes_cut: Vec::new(),
            unreached: 0,
            unheard_probes: 0,
            probes: Vec::new(),
            origin: None,
            // Nmap writes its document once the scan is done.
            open: false,
        });

        ScanReport::recorded(self.attribution(), vec![phase], self.hosts)
    }

    /// The settings, as far as the document states them.
    ///
    /// Nmap records which probe it sent and whether it looked for services and an
    /// operating system. Everything else, such as retries, rate limits and
    /// redaction, keeps this engine's defaults and says nothing about how nmap
    /// was tuned.
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
    /// Keyed as the host keys them and folded as read, so an endpoint named many
    /// times, in `<port>` elements or an `<extrareasons>` list, is built once.
    ports: BTreeMap<(u16, Protocol), Port>,
    ip_protocols: Vec<(u8, IpProtocolState)>,
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
            // An unparseable hardware address is dropped; the host is kept.
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
    /// This engine's scans record every port they probed, so without this the
    /// hundreds of ports nmap summarised would appear in a comparison as newly
    /// opened.
    ///
    /// A `ports` attribute past the parser's bound is absent, so nothing is
    /// recorded and the ports read as not probed. See [`LOSSY`].
    fn extend(&mut self, state: PortState, element: &Element) {
        let Some(list) = element.value(b"ports") else {
            return;
        };
        // Older nmap releases omit `proto`, which means TCP. An unknown
        // transport is skipped.
        let protocol = match element.value(b"proto") {
            Some(name) => match crate::record::wire::protocol(name) {
                Some(protocol) => protocol,
                None => return,
            },
            None => Protocol::Tcp,
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
            port::fold(&mut self.ports, port);
        }
    }

    /// Takes an `<osmatch>`, keeping only the first.
    ///
    /// Nmap lists candidates best first. Keeping the rest would make a comparison
    /// report a change whenever the runners-up reshuffled.
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

    /// Takes an `<osclass>`, which carries the family, generation, vendor and
    /// device type. Only the first class of the first match contributes, as in
    /// [`match_os`](Self::match_os).
    fn classify_os(&mut self, element: &Element) {
        let Some(os) = self.os.take() else {
            return;
        };
        if os.family().is_some() {
            self.os = Some(os);
            return;
        }

        // An empty value means unknown, as this engine's exporter writes it.
        let value = |name: &[u8]| element.value(name).filter(|value| !value.is_empty());
        let mut os = os;
        if let Some(family) = value(b"osfamily") {
            os = os.with_family(family);
        }
        if let Some(generation) = value(b"osgen") {
            os = os.with_generation(generation);
        }
        if let Some(vendor) = value(b"vendor") {
            os = os.with_vendor(vendor);
        }
        if let Some(device) = value(b"type") {
            os = os.with_device(device);
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
            .values()
            .any(|port| matches!(port.state(), PortState::Open | PortState::Closed));
        for port in self.ports.into_values() {
            host.add_port(port);
        }
        for (number, state) in self.ip_protocols {
            host.record_ip_protocol(number, state);
        }

        // An open or closed port was answered by the host's own stack, whatever
        // discovery concluded. This recovers hosts nmap was told not to probe.
        if answered {
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::Tcp, "a probed port answered for the host"),
            );
        }

        if let Some(os) = self.os {
            host.set_os(os);
        }

        // Last, because every mutator above stamps the current time.
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
        // `user-set` means nmap was told to skip discovery; nothing was sent.
        Some("up") if reason == Some("user-set") => HostStatus::Unknown,
        // This engine's exporter writes a blocked host as `up` with this reason,
        // since nmap has no such state.
        Some("up") if reason == Some("probes-blocked") => HostStatus::Blocked,
        Some("up") => HostStatus::Up,
        Some("down") => match reason {
            Some(reason) if reason.ends_with("-prohibited") => HostStatus::Blocked,
            Some(reason) if reason.ends_with("-unreach") => HostStatus::Down,
            // Including `no-response`: silence is not evidence of absence.
            _ => HostStatus::Unknown,
        },
        Some("filtered") => HostStatus::Blocked,
        _ => HostStatus::Unknown,
    }
}

/// Which protocol carried the evidence nmap named.
fn status_protocol(reason: &str) -> StatusProtocol {
    match reason {
        "arp-response" => StatusProtocol::Arp,
        "nd-response" => StatusProtocol::Ndp,
        "echo-reply" | "netmask-reply" | "addressmask-reply" => StatusProtocol::IcmpEcho,
        "timestamp-reply" => StatusProtocol::IcmpTimestamp,
        "syn-ack" => StatusProtocol::TcpSyn,
        "reset" | "tcp-response" => StatusProtocol::Tcp,
        "conn-refused" => StatusProtocol::TcpConnect,
        "udp-response" => StatusProtocol::Udp,
        "init-ack" | "abort" | "sctp-response" => StatusProtocol::Sctp,
        "dhcp-response" => StatusProtocol::Dhcp,
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
    /// Whether this element was `protocol="ip"`: an IP protocol verdict in a
    /// port's shape. [`protocol`](Self::protocol) is then meaningless.
    ip_protocol: bool,
}

impl PortAcc {
    /// Takes a `<port>`, which names the endpoint and nothing about it.
    fn open(element: &Element, parser: &Parser<'_>) -> Result<Self, ImportError> {
        let number = element
            .value(b"portid")
            .and_then(|id| id.parse::<u16>().ok())
            .ok_or_else(|| parser.malformed("a port with no readable number".to_string()))?;

        // An unrecognised transport is refused: it decides what the record says.
        let protocol = match element.value(b"protocol") {
            // Nmap reports a protocol scan as `<port protocol="ip">`, with an IP
            // protocol number in `portid`. Read into the host's protocol verdicts;
            // `export::nmap::write_ip_protocols` writes the same shape.
            Some("ip") => {
                let number = u8::try_from(number).map_err(|_| {
                    parser.malformed(format!(
                        "'{number}' is not an IP protocol number, which is a byte"
                    ))
                })?;
                return Ok(Self {
                    number: u16::from(number),
                    protocol: Protocol::Tcp,
                    state: PortState::NoReply,
                    reason: None,
                    service: None,
                    ip_protocol: true,
                });
            }
            Some(name) => crate::record::wire::protocol(name).ok_or_else(|| {
                parser.malformed(format!(
                    "port {number} names transport '{name}', which this engine cannot scan"
                ))
            })?,
            None => return Err(parser.malformed(format!("port {number} names no transport"))),
        };

        Ok(Self {
            number,
            protocol,
            state: PortState::NoReply,
            reason: None,
            service: None,
            ip_protocol: false,
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
        let reason = attr(element, b"reason");

        Ok(Some((
            Self::state_named(state, reason.as_deref(), parser)?,
            reason,
        )))
    }

    /// One of nmap's six verdicts, in this engine's terms, read beside the
    /// reason nmap gave for it.
    ///
    /// Nmap's `filtered` maps to [`Blocked`](PortState::Blocked) when the reason
    /// names a refusal, an ICMP prohibition or unreachable, and to
    /// [`NoReply`](PortState::NoReply) otherwise, including when the reason is
    /// missing or unrecognised.
    ///
    /// An unrecognised state is refused, since it decides what the record says.
    fn state_named(
        state: &str,
        reason: Option<&str>,
        parser: &Parser<'_>,
    ) -> Result<PortState, ImportError> {
        Ok(match state {
            "open" => PortState::Open,
            "closed" => PortState::Closed,
            "filtered" => match reason.map(scan_response) {
                Some(ScanResponse::IcmpProhibited | ScanResponse::IcmpUnreachable) => {
                    PortState::Blocked
                }
                _ => PortState::NoReply,
            },
            "unfiltered" => PortState::Reachable,
            "open|filtered" => PortState::OpenOrNoReply,
            "closed|filtered" => PortState::ClosedOrNoReply,
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

        // `table` is a port-number lookup. Confidence zero marks it inferred, as
        // this engine's own port-number labels are, so a comparison ignores it.
        let confidence = if element.value(b"method") == Some("probed") {
            element
                .value(b"conf")
                .and_then(|c| c.parse::<u8>().ok())
                .unwrap_or(0)
                .saturating_mul(CONFIDENCE_SCALE)
        } else {
            0
        };

        // Nmap puts the tunnel in its own attribute; this engine's label carries
        // both, as `ssl/http`, and later probes use it to decide whether to
        // speak through a handshake.
        let mut service = match element.value(b"tunnel") {
            Some("ssl") => Service::new(format!("ssl/{name}"), confidence),
            _ => Service::new(name, confidence),
        };
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

    /// The protocol verdict this record describes, for an element that was
    /// `protocol="ip"`.
    ///
    /// Nmap uses the port vocabulary for protocol verdicts too. A refusal is
    /// `filtered` with the refusal named in the reason, which reads as
    /// [`Blocked`](IpProtocolState::Blocked); `filtered` without one is silence,
    /// as `open|filtered` is. `unfiltered` and `closed|filtered`, which a
    /// protocol scan cannot produce, are read as silence too, so one odd word
    /// does not refuse the host.
    fn into_ip_protocol(self) -> (u8, IpProtocolState) {
        let state = match self.state {
            PortState::Open => IpProtocolState::Open,
            PortState::Closed => IpProtocolState::Closed,
            PortState::Blocked => IpProtocolState::Blocked,
            // All of these amount to silence for a protocol verdict.
            PortState::NoReply
            | PortState::OpenOrNoReply
            | PortState::Reachable
            | PortState::ClosedOrNoReply => IpProtocolState::OpenOrNoReply,
            PortState::Unasked => IpProtocolState::Unasked,
        };

        // `open` checked that the number fits in a byte.
        (self.number as u8, state)
    }
}

/// The packet nmap says settled a port's state.
fn scan_response(reason: &str) -> ScanResponse {
    match reason {
        "syn-ack" => ScanResponse::TcpSynAck,
        "reset" => ScanResponse::TcpRst,
        "conn-refused" => ScanResponse::ConnectionRefused,
        "no-response" => ScanResponse::NoResponse,
        "udp-response" | "proto-response" => ScanResponse::UdpResponse,
        "init-ack" => ScanResponse::SctpInitAck,
        "abort" => ScanResponse::SctpAbort,
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
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    /// The element ceiling follows the document ceiling, at its default and at
    /// one a caller set.
    ///
    /// Showing it by reading would take a document past the parser's fixed count,
    /// some 134 MB, so the parser is inspected directly.
    #[test]
    fn the_element_ceiling_is_the_one_the_document_ceiling_implies() {
        for reader in [
            NmapXmlReportReader::default(),
            NmapXmlReportReader::new(ReportOptions::default().with_max_document_bytes(1 << 36)),
        ] {
            let mut input = Cursor::new(Vec::new());
            let parser = reader.parser(&mut input);
            let implied = elements_within(reader.options.max_document_bytes);
            assert_ne!(
                implied,
                crate::import::xml::MAX_ELEMENTS,
                "a ceiling that shows it"
            );
            assert_eq!(parser.max_elements(), implied);
        }
    }

    /// A timestamp past what [`SystemTime`] holds is dropped without panicking.
    #[test]
    fn a_time_past_what_a_clock_can_hold_is_dropped_rather_than_fatal() {
        for seconds in ["16847805878974283974", "18446744073709551615"] {
            let document = format!(
                r#"<nmaprun scanner="nmap" start="{seconds}" version="7.94">
<host starttime="{seconds}" endtime="{seconds}">
<status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
</host>
</nmaprun>"#
            );

            let report = read(&document).expect("a time it cannot hold is not a broken document");
            assert_eq!(report.host_count(), 1, "the host survived the bad stamp");
        }

        // A representable time still reads.
        assert!(read(SWEEP).is_ok());
    }

    /// What nmap writes for a SYN scan with service and OS detection and reasons
    /// over two addresses, one of which did not answer.
    const SWEEP: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -sV" start="1690000000" version="7.94">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1024"/>
<host starttime="1690000001" endtime="1690000009">
<status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<address addr="2C:CF:67:00:00:01" addrtype="mac" vendor="Raspberry Pi"/>
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
<address addr="192.0.2.11" addrtype="ipv4"/>
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
            Some(MacAddr::new(0x2c, 0xcf, 0x67, 0x00, 0x00, 0x01))
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
        assert_eq!(os.device(), Some("general purpose"));
        assert_eq!(os.accuracy(), 97);
        assert!(
            os.cpes()
                .iter()
                .any(|cpe| &**cpe == "cpe:/o:linux:linux_kernel:5")
        );
    }

    /// A service nmap found inside TLS reads as this engine labels one, with
    /// the tunnel in its name.
    ///
    /// Nmap writes HTTPS as `name="http" tunnel="ssl"`. Read by name alone it
    /// would be plain HTTP, a changed service against this engine's own scan.
    #[test]
    fn a_service_nmap_found_inside_tls_keeps_its_tunnel() {
        let document = r#"<nmaprun scanner="nmap" version="7.94">
<host><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="http" product="nginx" tunnel="ssl" method="probed" conf="10"/>
</port></ports></host></nmaprun>"#;

        let report = read(document).expect("a readable document");
        let host = report.host(&ip(10)).expect("the host");
        let https = host.ports().next().expect("443");
        assert_eq!(https.service_name(), Some("ssl/http"));
    }

    /// A port-number lookup is kept, marked as inferred, matching the labels this
    /// engine puts on its own classified ports.
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

        // A probed one is not inferred.
        let ssh = host.ports().find(|port| port.number() == 22).expect("22");
        assert!(!ssh.service().expect("a probed service").is_inferred());
    }

    /// Port-number labels from different catalogues do not show as changes.
    #[test]
    fn a_port_number_label_never_reaches_a_comparison() {
        let report = read(SWEEP).expect("a readable document");

        // The same scan with a different port catalogue's label.
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
    // Host status mapping
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
    fn a_host_a_policy_rejected_is_blocked() {
        let document = SWEEP.replace(
            r#"<status state="down" reason="no-response" reason_ttl="0"/>"#,
            r#"<status state="down" reason="admin-prohibited" reason_ttl="61"/>"#,
        );

        let report = read(&document).expect("a readable document");
        assert_eq!(
            report.host(&ip(11)).expect("the host").status(),
            HostStatus::Blocked
        );
    }

    #[test]
    fn a_host_up_only_because_discovery_was_skipped_is_unknown() {
        // What nmap writes when told to skip discovery: `up`, with nothing sent.
        let document = r#"<nmaprun scanner="nmap" start="1690000000" version="7.94">
<host><status state="up" reason="user-set"/>
<address addr="192.0.2.11" addrtype="ipv4"/>
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
<address addr="192.0.2.11" addrtype="ipv4"/>
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
    // Scope
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
<address addr="192.0.2.10" addrtype="ipv4"/></host></nmaprun>"#;

        let report = read(document).expect("a readable document");
        assert!(
            report.phases()[0].targets().ranges().is_empty(),
            "nmap lists the addresses that did not answer only when asked to, so \
             a document without one cannot say what it walked"
        );

        // So a comparison against it confirms nothing.
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
        let document = r#"<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/>
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
<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/></host></nmaprun>"#;

        let error = read(document).expect_err("refused");
        assert!(error.to_string().contains("DOCTYPE"), "{error}");
    }

    /// A connect scan's refusal reads as a refusal, not a reset.
    ///
    /// `conn-refused` is the error a connect is handed, from a reset or an ICMP
    /// port unreachable, and this engine's connect scan records it the same way.
    /// Read as a reset, it would claim a packet nobody saw.
    #[test]
    fn a_refused_connect_is_read_as_a_refusal_rather_than_a_reset() {
        assert_eq!(
            scan_response("conn-refused"),
            ScanResponse::ConnectionRefused
        );
        assert_eq!(scan_response("reset"), ScanResponse::TcpRst);
    }

    // -----------------------------------------------------------------------
    // Comparing an nmap scan with something else
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
