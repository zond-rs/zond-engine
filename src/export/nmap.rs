// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Nmap-compatible XML export
//!
//! The format every security pipeline already reads. DefectDojo, Metasploit,
//! Faraday and Dradis all ingest nmap's XML and none of them ingest this
//! engine's JSON, so this is the file that puts a zond scan into somebody's
//! existing workflow without asking them to change it.
//!
//! That is the whole justification. Nothing here describes a scan better than
//! [`super::json`] does; it is a narrower description in somebody else's
//! vocabulary, and it earns its place by being understood downstream.
//!
//! ## It says who wrote it
//!
//! `scanner="zond"`, never `scanner="nmap"`.
//!
//! A scan report is evidence: it says a particular tool observed a particular
//! thing at a particular time, and somebody downstream will act on it, cite it in
//! an audit or attach it to a finding. A document claiming to be nmap's output
//! when it is not is a fabricated record, and no amount of parser convenience is
//! worth producing one.
//!
//! `xmloutputversion` is still nmap's, since that names the format and this
//! document really is in it.
//!
//! ## The one place this deviates from nmap's DTD
//!
//! Nmap's own DTD declares `scanner (nmap) #REQUIRED`, an enumeration with one
//! member, so no honest producer of this format can be DTD-valid. Every other
//! tool that emits it is in the same position.
//!
//! Measured against `nmap.dtd` from nmap 7.99, this document validates
//! completely, every element and ordering and required attribute, with the
//! scanner name changed to `nmap` and nothing else. That deviation is the whole
//! of it.
//!
//! It costs nothing that matters. Consumers of this format parse it structurally
//! with lenient parsers rather than validating against the DTD, and a document
//! this one produces reads correctly through a standard XML parser, yielding the
//! hosts, addresses and port states the scan recorded.
//!
//! Writing `nmap` here fails a test that exists for the purpose.
//!
//! ## What survives
//!
//! Nmap's vocabulary is not this engine's, and where the two disagree the
//! document says less rather than saying something false. Port states map
//! exactly, both naming the same six. Host status is flattened: nmap knows `up`,
//! `down` and `unknown`, so a host this engine calls `filtered` is exported `up`,
//! with the distinction carried in the `reason`.
//!
//! Everything the format has no place for, the phases and the probe
//! instrumentation and the TLS detail and the per-address timing, is absent.
//! [`super::json`] is where the whole record lives.
//!
//! ## Characters XML cannot carry
//!
//! A scanner writes attacker-controlled text: hostnames, service banners,
//! certificate subjects. Putting that in an XML attribute brings two problems,
//! and only one of them is escaping.
//!
//! The first is ordinary. `&`, `<`, `>`, `"` and `'` are escaped everywhere,
//! unconditionally. So are tab, line feed and carriage return, which XML allows
//! raw and every parser then normalises to a space inside an attribute value;
//! nmap writes them as character references, and so does this, so a banner's
//! lines survive the trip into somebody else's tool.
//!
//! The second has no escape. XML 1.0 forbids most C0 control characters from a
//! document at all, and forbids a numeric character reference to one just as
//! firmly, so `&#1;` is not a way out. A banner containing a `0x01` cannot be
//! represented, and emitting it raw produces a file no parser downstream will
//! open. Those are dropped, along with the bidirectional formatting characters,
//! which reorder the text around them and would let a hostname make a report
//! display one thing and mean another.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::export::schema::{ENGINE_NAME, protocol_name, reference_text, severity_name};
use crate::export::{ExportError, ExportOptions, Exporter};
use crate::fingerprint::Tunnel;
use crate::model::finding::Finding;
use crate::model::host::{
    EvidenceSource, Host, HostStatus, IpProtocolState, StatusProtocol, StatusReason,
};
use crate::model::ip::range::IpRange;
use crate::model::ip::set::IpSet;
use crate::model::port::discovery::ScanResponse;
use crate::model::port::{Port, PortState, Protocol};
use crate::model::technique::TcpScanTechnique;
use crate::report::{ScanPhase, ScanReport, ScannerFailure};
use crate::system::privilege::Privilege;

/// The nmap XML output version this document is written to.
///
/// Nmap's own, because it names the format rather than the producer, and this
/// document really is in it. Consumers key their parsing on this.
const XML_OUTPUT_VERSION: &str = "1.05";

/// Writes a report as nmap-compatible XML.
///
/// ```no_run
/// use std::fs::File;
/// use zond_engine::report::ScanReport;
/// use zond_engine::export::{ExportOptions, Exporter, NmapXmlExporter};
///
/// # fn example(report: &ScanReport) -> Result<(), Box<dyn std::error::Error>> {
/// let mut file = File::create("scan.xml")?;
/// NmapXmlExporter::new(ExportOptions::new()).export(report, &mut file)?;
/// # Ok(())
/// # }
/// ```
#[must_use]
#[derive(Debug, Clone, Default)]
pub struct NmapXmlExporter {
    options: ExportOptions,
}

impl NmapXmlExporter {
    /// An exporter under the given options.
    pub fn new(options: ExportOptions) -> Self {
        Self { options }
    }

    /// The options in force.
    pub fn options(&self) -> &ExportOptions {
        &self.options
    }
}

impl Exporter for NmapXmlExporter {
    fn export(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), ExportError> {
        let started = epoch_seconds(report.started_at());
        let elapsed = report.elapsed().as_secs_f64();

        writeln!(out, r#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
        write_exclusion_note(out, report)?;
        writeln!(
            out,
            concat!(
                r#"<nmaprun scanner="zond" args="" start="{}" startstr="{}" "#,
                r#"version="{}" xmloutputversion="{}">"#
            ),
            started,
            Attr(&time_string(report.started_at())),
            // This build's, since the attribute beside it says
            // `scanner="zond"`. Writing the report's own attribution here put a
            // foreign scanner's version on zond's name.
            Attr(crate::report::ENGINE_VERSION),
            XML_OUTPUT_VERSION,
        )?;

        // One per transport per phase, as nmap writes them. This is what tells
        // a consumer which ports were looked at, and so the difference between
        // a port absent because it was closed and one nobody asked about.
        for phase in report.phases() {
            write_scan_info(out, phase)?;
        }

        writeln!(out, r#"<verbose level="0"/>"#)?;
        writeln!(out, r#"<debugging level="0"/>"#)?;

        for host in report.hosts() {
            write_host(out, host, &self.options)?;
        }

        let counts = HostCounts::of(report);
        // One reading used twice: two calls to the clock can straddle a second
        // and leave `time` and `timestr` naming different instants.
        let finished = SystemTime::now();

        writeln!(out, "<runstats>")?;
        writeln!(
            out,
            r#"<finished time="{}" timestr="{}" elapsed="{:.2}" summary="{}" exit="{}"/>"#,
            epoch_seconds(finished),
            Attr(&time_string(finished)),
            elapsed,
            Attr(&format!(
                "{ENGINE_NAME} done; {} IP addresses ({} hosts up) scanned in {elapsed:.2} seconds",
                counts.addresses, counts.up
            )),
            // A strategy that failed is the one shortfall nmap's own runs
            // call an error. A host its budget left early and a port left
            // unasked are, in nmap's output, part of a run that succeeded,
            // and a consumer of this format reads the attribute that way. A
            // journal that could not be written is no strategy and cost the
            // run nothing it covered; see `ScannerFailure::narrows_coverage`.
            if report.failures().any(ScannerFailure::narrows_coverage) {
                "error"
            } else {
                "success"
            },
        )?;
        writeln!(
            out,
            r#"<hosts up="{}" down="{}" total="{}"/>"#,
            counts.up,
            counts.down,
            counts.up + counts.down,
        )?;
        writeln!(out, "</runstats>")?;
        writeln!(out, "</nmaprun>")?;

        Ok(())
    }
}

/// The run's host counts as nmap states them in `<runstats>`.
///
/// Nmap counts what it scanned, not what it listed: a sweep of a /24 with thirty
/// hosts answering is 256 addresses, 30 up and 226 down, and the tools that
/// read the document report coverage from these. A count of the recorded hosts
/// alone says a sweep of 256 addresses scanned thirty, every one of them up.
///
/// The addresses scanned are every range a phase walked, after its exclusions,
/// together with every address a recorded host holds, since a host found on a
/// swept link or overheard on the segment was in no range anybody named. A host
/// is up as its `<status>` says it is, and every scanned address no up host
/// holds is down, which is how nmap, counting each address as a host, arrives
/// at the same arithmetic. A host answering at two addresses is one host up, so
/// `total` can fall short of the addresses scanned by the second address of
/// each; the summary line names both numbers as what they are.
struct HostCounts {
    addresses: u128,
    up: u128,
    down: u128,
}

impl HostCounts {
    fn of(report: &ScanReport) -> Self {
        let mut scanned = IpSet::new();
        for phase in report.phases() {
            for range in phase.targets().ranges() {
                scanned.insert_range(*range);
            }
        }
        let mut held_up = IpSet::new();
        let mut up = 0;
        for host in report.hosts() {
            // Exactly the hosts `host_state` writes `up`.
            let is_up = host.is_alive();
            up += u128::from(is_up);
            for ip in host.ips() {
                scanned.insert(*ip);
                if is_up {
                    held_up.insert(*ip);
                }
            }
        }
        scanned.canonicalize();
        held_up.canonicalize();

        let addresses = scanned.len();
        Self {
            addresses,
            up,
            down: addresses.saturating_sub(held_up.len()),
        }
    }
}

/// Records an exclusion policy as an XML comment, when there was one.
///
/// A comment because this format has nowhere else to put it. Nmap's own
/// `--exclude` survives only inside the `args` attribute, which is a command line
/// this engine was never handed, and inventing an element instead would cost the
/// document its validity against `nmap.dtd`.
///
/// A comment costs neither. It is valid anywhere in XML content, invisible to
/// every consumer that parses this file, and legible to the person who opens it.
///
/// Saying nothing is not an option: a file reporting a scan of a range while
/// omitting that part of it was deliberately skipped overstates its own
/// coverage.
///
/// Every phase carries the policy it ran under, and most carry the same one, so
/// the note is their union, merged as an address set merges it: a range two
/// phases share is named once and two that touch read as the one range they
/// amount to. The union is built in one sort, which keeps the note's cost
/// proportional to the policy however many phases repeat it; a blocklist runs to
/// tens of thousands of ranges, and a note deduplicated by searching what it has
/// already written grows with the square of that.
fn write_exclusion_note(out: &mut dyn Write, report: &ScanReport) -> Result<(), ExportError> {
    let mut excluded = IpSet::new();
    for phase in report.phases() {
        for range in phase.targets().excluded() {
            excluded.insert_range(*range);
        }
    }

    if excluded.is_empty() {
        return Ok(());
    }
    excluded.canonicalize();

    // Rendered from addresses rather than anything a caller wrote, so no
    // attacker-controlled text reaches this line and `--` cannot appear in it
    // to close the comment early.
    write!(out, "<!-- zond: excluded by policy, not scanned: ")?;
    let v4 = excluded.v4().iter().copied().map(IpRange::V4);
    let v6 = excluded.v6().iter().copied().map(IpRange::V6);
    for (index, range) in v4.chain(v6).enumerate() {
        if index > 0 {
            write!(out, ", ")?;
        }
        write!(out, "{}-{}", range.start_addr(), range.end_addr())?;
    }
    writeln!(out, " -->")?;

    Ok(())
}

/// Writes one `<scaninfo>` per transport the phase walked ports on.
///
/// Nothing is written for a phase whose port scope is not recorded, and nothing
/// for a discovery sweep. An element claiming zero services would read as a scan
/// that looked at no ports, which is a different statement from staying silent.
fn write_scan_info(out: &mut dyn Write, phase: &ScanPhase) -> Result<(), ExportError> {
    let Some(ports) = phase.targets().ports().ports() else {
        return Ok(());
    };

    for protocol in Protocol::ALL {
        let ranges = ports.ranges(protocol);
        if ranges.is_empty() {
            continue;
        }

        let services = ranges
            .iter()
            .map(|range| {
                if range.start() == range.end() {
                    range.start().to_string()
                } else {
                    format!("{}-{}", range.start(), range.end())
                }
            })
            .collect::<Vec<_>>()
            .join(",");

        writeln!(
            out,
            r#"<scaninfo type="{}" protocol="{}" numservices="{}" services="{}"/>"#,
            scan_type(phase, protocol),
            protocol_name(protocol),
            ports.len_on(protocol),
            Attr(&services),
        )?;
    }

    Ok(())
}

/// The scan type in nmap's vocabulary.
///
/// A UDP scan is `udp` and an SCTP one `sctpinit` whatever the TCP technique
/// was, and an unprivileged phase is `connect` for the same reason nmap's is: no
/// raw segment went out, so naming the technique would describe a probe that was
/// never sent. So is a privileged phase that reached every address it covered
/// by connect, as it reaches loopback and this host's own addresses; see
/// [`ScanPhase::reached_by_connect`].
///
/// A phase that reached only some of its addresses that way names the
/// technique it sent the rest. Nmap runs one TCP technique per scan and writes
/// one `<scaninfo>` per transport, which is what its readers key on, so a
/// second element for the same transport would be dropped or misread; the
/// addresses probed by connect are in the report's own record of the phase.
fn scan_type(phase: &ScanPhase, protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Udp => return "udp",
        // Nmap's own name for an INIT scan, which is the only SCTP scan either
        // engine performs.
        Protocol::Sctp => return "sctpinit",
        Protocol::Tcp => {}
    }
    // Only where the phase is known to have reached its addresses so. A phase
    // this engine did not measure keeps whatever technique its own document
    // named.
    if phase.privilege() == Some(Privilege::Connect) || reached_wholly_by_connect(phase) {
        return "connect";
    }

    match phase.settings().tcp_technique {
        TcpScanTechnique::Syn => "syn",
        TcpScanTechnique::Fin => "fin",
        TcpScanTechnique::Null => "null",
        TcpScanTechnique::Xmas => "xmas",
        TcpScanTechnique::Maimon => "maimon",
        TcpScanTechnique::Ack => "ack",
        TcpScanTechnique::Window => "window",
    }
}

/// Whether every address `phase` covered is one it reached by connect though
/// it held the privilege its raw strategies need.
///
/// False for a phase that recorded no such address, which is also every phase
/// whose scope names none: nothing is claimed of a phase that says nothing.
fn reached_wholly_by_connect(phase: &ScanPhase) -> bool {
    let reached = phase.reached_by_connect();
    let covered = phase.targets().ranges();
    if reached.is_empty() || covered.is_empty() {
        return false;
    }
    let mut left = IpSet::new();
    for range in covered {
        left.insert_range(*range);
    }
    let mut by_connect = IpSet::new();
    for range in reached {
        by_connect.insert_range(*range);
    }
    left.subtract(&by_connect);
    left.is_empty()
}

/// Writes one `<host>` element.
fn write_host(
    out: &mut dyn Write,
    host: &Host,
    options: &ExportOptions,
) -> Result<(), ExportError> {
    let redaction = options.redaction;

    writeln!(
        out,
        r#"<host starttime="{}" endtime="{}">"#,
        epoch_seconds(host.first_seen()),
        epoch_seconds(host.last_seen()),
    )?;

    writeln!(
        out,
        r#"<status state="{}" reason="{}" reason_ttl="{}"/>"#,
        host_state(host.status()),
        Attr(status_reason(host)),
        // Nmap puts the TTL of the packet that established the host's state
        // here, and the attribute is required. This engine records none, so it
        // writes zero, which is what nmap writes for the same absence.
        0,
    )?;

    // Every address, so a dual-stack host is one record with two of them, as
    // nmap describes the same thing.
    //
    // The address the host is keyed by leads. Nmap has no attribute naming that
    // one, but a reader takes the first address it sees as the host's. In the
    // set's own order a multi-homed host came back keyed by whichever address
    // sorted lowest, so a scan exported and read again compared against its own
    // source as one host gone and one arrived.
    let primary = host.primary_ip();
    let addresses = std::iter::once(&primary).chain(host.ips().iter().filter(|ip| **ip != primary));

    for ip in addresses {
        writeln!(
            out,
            r#"<address addr="{}" addrtype="{}"/>"#,
            Attr(&ip.to_string()),
            if ip.is_ipv4() { "ipv4" } else { "ipv6" },
        )?;
    }

    if let Some(mac) = host.mac() {
        match host.vendor() {
            Some(vendor) => writeln!(
                out,
                r#"<address addr="{}" addrtype="mac" vendor="{}"/>"#,
                Attr(&redaction.mac(&mac)),
                Attr(vendor),
            )?,
            None => writeln!(
                out,
                r#"<address addr="{}" addrtype="mac"/>"#,
                Attr(&redaction.mac(&mac)),
            )?,
        }
    }

    // The names a host gave for itself are not written. nmap's `<hostname>`
    // is a name for the address, typed `PTR` or `user`, and every tool reading
    // this format takes it as the host's identity: a NetBIOS domain written
    // there would be read as the machine's DNS name. nmap reports them as the
    // output of a script, and this engine runs no script to attribute them to.
    if let Some(hostname) = host.hostname() {
        writeln!(out, "<hostnames>")?;
        writeln!(
            out,
            r#"<hostname name="{}" type="PTR"/>"#,
            Attr(&redaction.hostname(hostname)),
        )?;
        writeln!(out, "</hostnames>")?;
    }

    write_ip_protocols(out, host)?;

    write_ports(out, host)?;

    if let Some(os) = host.os() {
        writeln!(out, "<os>")?;
        // `line` is required by nmap's DTD and names the row in `nmap-os-db`
        // a match came from. This engine has no such database, and 0 is not a
        // line number.
        writeln!(
            out,
            r#"<osmatch name="{}" accuracy="{}" line="0">"#,
            Attr(os.name()),
            os.accuracy(),
        )?;
        write_os_class(out, os)?;
        writeln!(out, "</osmatch>")?;
        writeln!(out, "</os>")?;
    }

    // Nmap's DTD fixes the sequence of a host's children: `<distance>` then
    // `<trace>`, both after `<os>`.
    if let Some(distance) = host.path().length() {
        writeln!(out, r#"<distance value="{distance}"/>"#)?;
    }

    // `<hostscript>` carries the host-level findings, after `<distance>` and
    // before `<trace>` as nmap's DTD fixes the order.
    if host.findings().next().is_some() {
        writeln!(out, "<hostscript>")?;
        write_finding_scripts(out, host.findings())?;
        writeln!(out, "</hostscript>")?;
    }

    write_trace(out, host)?;

    // Nmap reports these in microseconds, which is what the engine keeps.
    if let Some(rtt) = host.median_rtt() {
        writeln!(
            out,
            r#"<times srtt="{}" rttvar="0" to="{}"/>"#,
            rtt.as_micros(),
            rtt.as_micros(),
        )?;
    }

    writeln!(out, "</host>")?;
    Ok(())
}

/// Writes the host's `<ports>`: the ports worth reading one by one, and a
/// summary of the rest.
///
/// A port nobody asked about is left out rather than written down. Nmap's
/// `<ports>` is the record of what was probed, and its vocabulary has no word
/// for a port no probe was sent to, so filing one under any of the six states it
/// does have would put a verdict this scan never reached into a file another
/// tool parses. See `PortState::Unasked`.
///
/// Of the rest, a state held by more than [`LISTED_PER_STATE`] ports is written
/// as nmap writes it, one `<extraports>` giving the state and its count, with an
/// `<extrareasons>` per reason and transport naming every port in it. That is
/// the shape the tools reading this format expect, and what they do with a
/// listed port is why it matters: an exploit search looks up every listed
/// port's service name, an importer files every listed port as a service on
/// the host, and a stylesheet renders a row for each. A full-range scan of one
/// host listed whole is 65,535 of each, nearly all of them the port-number
/// label of a closed port, and ten megabytes of document for what nmap says in
/// one line. The ports are still named, so a reader that wants every verdict,
/// this engine's own among them, has it.
///
/// `open` is never summarised, for the reason nmap never summarises it: an
/// open port is the finding. Nor is a port whose record holds more than a
/// state and the packet behind it, an identified service or a finding, since
/// the summary has nowhere to put either and would lose it.
fn write_ports(out: &mut dyn Write, host: &Host) -> Result<(), ExportError> {
    let probed: Vec<&Port> = host
        .ports()
        .filter(|port| port_state(port.state()).is_some())
        .collect();
    if probed.is_empty() {
        return Ok(());
    }

    // The summarisable ports of each state, then kept only for the states
    // with more of them than are listed.
    let mut summarised: BTreeMap<PortState, Vec<&Port>> = BTreeMap::new();
    for port in probed.iter().copied().filter(|port| is_summarisable(port)) {
        summarised.entry(port.state()).or_default().push(port);
    }
    summarised.retain(|_, ports| ports.len() > LISTED_PER_STATE);

    writeln!(out, "<ports>")?;
    for (state, ports) in &summarised {
        write_extra_ports(out, *state, ports)?;
    }
    for port in probed {
        let listed = !is_summarisable(port) || !summarised.contains_key(&port.state());
        if listed {
            write_port(out, port)?;
        }
    }
    writeln!(out, "</ports>")?;
    Ok(())
}

/// How many ports of one state are listed one by one before the state is
/// summarised instead.
///
/// Nmap's own threshold at its default verbosity, so a document from this
/// engine lists what an nmap run over the same network would list.
const LISTED_PER_STATE: usize = 25;

/// Whether a port says nothing a summary cannot: it is not open, and its record
/// holds its state, the packet behind it and at most a port-number label.
///
/// The label is what nmap drops for a summarised port too; it is a lookup
/// rather than a finding, and on a closed port it is what an exploit search
/// mistakes for a service.
fn is_summarisable(port: &Port) -> bool {
    port.state() != PortState::Open
        && port.service().is_none_or(|service| service.is_inferred())
        && port.security().is_none()
        && port.findings().next().is_none()
}

/// Writes one `<extraports>`: a state, how many ports are in it, and which,
/// grouped by the reason each was decided on and its transport.
fn write_extra_ports(
    out: &mut dyn Write,
    state: PortState,
    ports: &[&Port],
) -> Result<(), ExportError> {
    let Some(name) = port_state(state) else {
        return Ok(());
    };

    let mut reasons: BTreeMap<(&str, Protocol), Vec<u16>> = BTreeMap::new();
    for port in ports {
        if let Some(reason) = port_reason(port) {
            reasons
                .entry((reason, port.protocol()))
                .or_default()
                .push(port.number());
        }
    }

    writeln!(
        out,
        r#"<extraports state="{name}" count="{}">"#,
        ports.len()
    )?;
    for ((reason, protocol), mut numbers) in reasons {
        numbers.sort_unstable();
        for (count, list) in port_lists(&numbers) {
            writeln!(
                out,
                r#"<extrareasons reason="{}" count="{count}" proto="{}" ports="{list}"/>"#,
                Attr(reason),
                transport(protocol),
            )?;
        }
    }
    writeln!(out, "</extraports>")?;
    Ok(())
}

/// Ascending port numbers as nmap lists them, runs as `first-last` and the
/// rest alone, comma-separated, in lists of at most [`MAX_PORT_LIST_BYTES`]
/// each with the count of ports it names.
///
/// A summary whose ports run in long stretches is a few bytes, but one whose
/// ports alternate with another state's is not: a full range where a host
/// rate-limits its resets scatters filtered ports through closed ones, and
/// thirty thousand isolated numbers are two hundred kilobytes in one attribute.
/// A reader bounding what one element may hold, this engine's own among them,
/// refuses a document with such an element rather than reading the rest of it.
/// Nmap's DTD allows any number of `<extrareasons>` in an `<extraports>`, and a
/// reader totalling them totals the same ports, so the list is split instead.
fn port_lists(numbers: &[u16]) -> Vec<(usize, String)> {
    let mut lists = vec![(0, String::new())];
    let mut index = 0;
    while index < numbers.len() {
        let first = numbers[index];
        let mut last = first;
        while numbers.get(index + 1) == Some(&last.wrapping_add(1)) && last != u16::MAX {
            index += 1;
            last = numbers[index];
        }
        index += 1;

        let run = if first == last {
            first.to_string()
        } else {
            format!("{first}-{last}")
        };
        if lists.last().is_some_and(|(_, list)| {
            !list.is_empty() && list.len() + 1 + run.len() > MAX_PORT_LIST_BYTES
        }) {
            lists.push((0, String::new()));
        }
        let (count, list) = lists.last_mut().expect("there is always a list");
        if !list.is_empty() {
            list.push(',');
        }
        list.push_str(&run);
        *count += usize::from(last - first) + 1;
    }
    lists.retain(|(count, _)| *count > 0);
    lists
}

/// The longest port list one `<extrareasons>` carries, in bytes.
///
/// Well inside what a reader bounding a value takes, this engine's own included,
/// and long enough that a summary of ports in stretches is always one list.
const MAX_PORT_LIST_BYTES: usize = 8 * 1024;

/// Writes the `<osclass>` beneath a match: the family, vendor, generation and
/// device type, and the CPEs naming the system.
///
/// This is where the tools reading nmap's format take an operating system from:
/// an importer files a host under its `osfamily`, and a vulnerability lookup
/// keys on the CPE, which nmap's DTD holds only here. A match written with its
/// name alone gives both nothing to read.
///
/// Written only once the family is known, which the DTD requires of every class,
/// as it requires a vendor. A vendor this engine did not establish is written
/// empty, which claims nothing, rather than leaving out the class and the CPEs
/// with it.
fn write_os_class(
    out: &mut dyn Write,
    os: &crate::model::host::OsFingerprint,
) -> Result<(), ExportError> {
    let Some(family) = os.family() else {
        return Ok(());
    };

    write!(
        out,
        r#"<osclass vendor="{}" osfamily="{}""#,
        Attr(os.vendor().unwrap_or_default()),
        Attr(family),
    )?;
    if let Some(generation) = os.generation() {
        write!(out, r#" osgen="{}""#, Attr(generation))?;
    }
    if let Some(device) = os.device() {
        write!(out, r#" type="{}""#, Attr(device))?;
    }
    write!(
        out,
        r#" accuracy="{}""#,
        os.detail_accuracy().unwrap_or(os.accuracy())
    )?;

    if os.cpes().is_empty() {
        writeln!(out, "/>")?;
        return Ok(());
    }
    writeln!(out, ">")?;
    write_cpes(out, os.cpes())?;
    writeln!(out, "</osclass>")?;
    Ok(())
}

/// Writes one `<cpe>` element per CPE, the form nmap's DTD gives them beneath
/// a service or an OS class.
fn write_cpes(
    out: &mut dyn Write,
    cpes: &std::collections::BTreeSet<std::sync::Arc<str>>,
) -> Result<(), ExportError> {
    for cpe in cpes {
        writeln!(out, "<cpe>{}</cpe>", Attr(cpe))?;
    }
    Ok(())
}

/// Writes the `<trace>` element, when a path was measured.
///
/// This is the one finding the engine produces that nmap's format has a
/// first-class place for, so a consumer that draws network topology from nmap XML
/// draws this without being taught anything new.
///
/// A silent hop is written as a `<hop>` carrying only its `ttl`, which is what
/// nmap does and what the DTD allows, since `ipaddr` is implied. A consumer
/// counting hops has to see that a router is there and would not name itself.
///
/// A [withheld](crate::model::host::Hop::is_withheld) hop is written the same
/// way. Its router did name itself, but the scan's exclusions forbid the
/// address, and a `ttl` alone is the only form the format has that keeps the
/// distance and names nobody. Like `inferred` below, the distinction survives
/// only in [`super::json`].
///
/// `rtt` is milliseconds with two decimals, nmap's own rendering. A consumer
/// reading this attribute expects nmap's units, and the engine's microseconds
/// would read as a path a thousand times slower.
///
/// `inferred` has nowhere to go. Nmap has no attribute for it and inventing one
/// would cost this document its DTD validity, so a hop copied from another host's
/// trace is written like a measured one. Anybody who needs the distinction has
/// [`super::json`].
fn write_trace(out: &mut dyn Write, host: &Host) -> Result<(), ExportError> {
    let hops = host.path().hops();
    if hops.is_empty() {
        return Ok(());
    }

    writeln!(out, "<trace>")?;
    for hop in hops {
        write!(out, r#"<hop ttl="{}""#, hop.distance())?;
        if let Some(address) = hop.address() {
            write!(out, r#" ipaddr="{}""#, Attr(&address.to_string()))?;
        }
        if let Some(rtt) = hop.rtt() {
            write!(out, r#" rtt="{:.2}""#, rtt.as_secs_f64() * 1000.0)?;
        }
        writeln!(out, "/>")?;
    }
    writeln!(out, "</trace>")?;
    Ok(())
}

/// A finding flattened to one line of `<script output>` text: severity, title,
/// references, the justifying excerpt, and any remediation. Every part is
/// attacker-influenced and is written through [`Attr`] at the call site, never
/// raw.
fn finding_output(finding: &Finding) -> String {
    let mut parts = vec![format!(
        "[{}] {}",
        severity_name(finding.severity()),
        finding.title()
    )];
    let references: Vec<String> = finding.references().map(reference_text).collect();
    if !references.is_empty() {
        parts.push(references.join(", "));
    }
    if !finding.excerpt().is_empty() {
        parts.push(finding.excerpt().as_str().to_owned());
    }
    if let Some(remediation) = finding.remediation() {
        parts.push(format!("fix: {remediation}"));
    }
    parts.join(" | ")
}

/// Writes a subject's findings as `<script id="…" output="…"/>` elements, the
/// shape nmap gives NSE output and the shape DefectDojo and its neighbours read.
/// The id and the flattened output are both attacker-influenced, so both pass
/// through [`Attr`].
fn write_finding_scripts<'a>(
    out: &mut dyn Write,
    findings: impl Iterator<Item = &'a Finding>,
) -> Result<(), ExportError> {
    for finding in findings {
        writeln!(
            out,
            r#"<script id="{}" output="{}"/>"#,
            Attr(finding.detection().id()),
            Attr(&finding_output(finding)),
        )?;
    }
    Ok(())
}

/// Writes the host's IP protocol verdicts, in the shape nmap's own protocol scan
/// writes them.
///
/// Nmap reports `-sO` as `<port protocol="ip" portid="N">`, reusing the port
/// element for a number that is not a port, and every tool that reads nmap XML
/// reads it that way. This engine keeps the two apart in its own model, for the
/// reason [`protocol`](crate::model::host::protocol) gives, and writes nmap's
/// shape here because the format is nmap's and a document in a private dialect
/// would be one nothing downstream understands.
///
/// Its own `<ports>` element, following the transport one. Nmap emits a second
/// block the same way when a scan asked both questions, and merging them would
/// put 47/ip beside 47/tcp under one heading as though they were the same
/// endpoint.
///
/// A protocol nobody asked about is left out, for the reason
/// [`port_state`] gives about an unasked port: the format has no word for it.
fn write_ip_protocols(out: &mut dyn Write, host: &Host) -> Result<(), ExportError> {
    let mut asked = host
        .ip_protocols()
        .iter()
        .filter(|(_, state)| state.is_established());

    let Some(first) = asked.next() else {
        return Ok(());
    };

    writeln!(out, "<ports>")?;
    for (number, state) in std::iter::once(first).chain(asked) {
        writeln!(out, r#"<port protocol="ip" portid="{number}">"#)?;
        writeln!(
            out,
            r#"<state state="{}" reason="{}" reason_ttl="0"/>"#,
            ip_protocol_state(*state),
            Attr(ip_protocol_reason(*state)),
        )?;
        if let Some(name) = crate::model::host::ip_protocol_name(*number) {
            writeln!(
                out,
                r#"<service name="{}" method="table" conf="3"/>"#,
                Attr(name),
            )?;
        }
        writeln!(out, "</port>")?;
    }
    writeln!(out, "</ports>")?;
    Ok(())
}

/// This engine's IP protocol verdicts in nmap's spelling.
///
/// The four correspond exactly, because nmap's protocol scan reaches the same
/// four conclusions from the same messages. [`Unasked`](IpProtocolState::Unasked)
/// has no spelling for the reason [`PortState::Unasked`] has none, and the
/// caller filters it out before reaching here.
fn ip_protocol_state(state: IpProtocolState) -> &'static str {
    match state {
        IpProtocolState::Open => "open",
        IpProtocolState::Closed => "closed",
        IpProtocolState::Filtered => "filtered",
        IpProtocolState::OpenFiltered => "open|filtered",
        // Filtered out by `write_ip_protocols`, which writes only what was
        // established. Reported as the format's nearest word rather than left to
        // a wildcard, so a state added later is a compile error here.
        IpProtocolState::Unasked => "open|filtered",
    }
}

/// What nmap would have written as the evidence for a protocol verdict.
///
/// Three of the four name the message that produced them and are exactly true: a
/// protocol unreachable is the only thing that closes a protocol here, an
/// administrative prohibition the only thing that filters one, and silence the
/// only thing that leaves it open-filtered.
///
/// `open` is the one that cannot be named. It is reached two ways, by an echo
/// reply and by a port unreachable proving the stack took delivery, and this
/// engine records the verdict without recording which; see
/// [`protocols`](crate::scanner::strategy::protocols). Every token nmap defines
/// names a specific packet, so writing one would name a packet that may not have
/// been sent. `response` is not nmap's word and is the honest one: consumers key
/// on `state`, and an unfamiliar reason costs a reader a moment where a false one
/// costs them the truth.
fn ip_protocol_reason(state: IpProtocolState) -> &'static str {
    match state {
        IpProtocolState::Closed => "proto-unreach",
        IpProtocolState::Filtered => "admin-prohibited",
        IpProtocolState::Open => "response",
        IpProtocolState::OpenFiltered | IpProtocolState::Unasked => "no-response",
    }
}

/// Writes one `<port>` element.
///
/// Writes nothing for a port this format cannot state, which is a port no probe
/// was sent to; the caller filters those out, and this returns rather than
/// writing an element with no `<state>` in it.
fn write_port(out: &mut dyn Write, port: &Port) -> Result<(), ExportError> {
    let (Some(state), Some(reason)) = (port_state(port.state()), port_reason(port)) else {
        return Ok(());
    };

    writeln!(
        out,
        r#"<port protocol="{}" portid="{}">"#,
        transport(port.protocol()),
        port.number(),
    )?;
    writeln!(
        out,
        r#"<state state="{}" reason="{}" reason_ttl="{}"/>"#,
        state,
        Attr(reason),
        reason_ttl(port),
    )?;

    if let Some(service) = port.service() {
        let (name, tunnel) = service_name(service.name());
        write!(out, r#"<service name="{}""#, Attr(name))?;
        if let Some(product) = service.product() {
            write!(out, r#" product="{}""#, Attr(product))?;
        }
        if let Some(version) = service.version() {
            write!(out, r#" version="{}""#, Attr(version))?;
        }
        if let Some(extrainfo) = service.extrainfo() {
            write!(out, r#" extrainfo="{}""#, Attr(extrainfo))?;
        }
        if let Some(tunnel) = tunnel {
            write!(out, r#" tunnel="{tunnel}""#)?;
        }
        // `probed` is nmap's word for a service identified by talking to the
        // port, `table` for one read out of a port-number list. Every classified
        // port is seeded with a port-number label, so writing those as `probed`
        // would claim a thousand closed ports had been interrogated.
        write!(
            out,
            r#" method="{}" conf="{}""#,
            if service.is_inferred() {
                "table"
            } else {
                "probed"
            },
            nmap_confidence(service.confidence()),
        )?;
        if service.cpes().is_empty() {
            writeln!(out, "/>")?;
        } else {
            writeln!(out, ">")?;
            write_cpes(out, service.cpes())?;
            writeln!(out, "</service>")?;
        }
    }

    // `<script>` follows `<service>` in nmap's DTD for a `<port>`.
    write_finding_scripts(out, port.findings())?;

    writeln!(out, "</port>")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// This engine's port states in nmap's spelling, and [`None`] for the one that
/// has none.
///
/// An exhaustive match, so a new state cannot be added without somebody deciding
/// what this format calls it. Six of the seven correspond exactly: they are the
/// six verdicts a probe can distinguish, which is the same six nmap's own probes
/// reach.
///
/// [`PortState::Unasked`] is the one that does not, and it is not an oversight in
/// nmap: a port nmap did not scan is a port nmap does not write, so the format
/// says what it has to say about this by omission. Answering [`None`] is how that
/// reaches the caller, which drops the element rather than picking the least
/// wrong of the six.
fn port_state(state: PortState) -> Option<&'static str> {
    Some(match state {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
        PortState::Unfiltered => "unfiltered",
        PortState::OpenFiltered => "open|filtered",
        PortState::ClosedFiltered => "closed|filtered",
        PortState::Unasked => return None,
    })
}

/// The packet that decided a port's state, in nmap's words.
///
/// Nmap's `reason` names that packet, and this engine records it on the port's
/// [`Discovery`](crate::model::port::discovery::Discovery), so the word is
/// read from there: a UDP port that answered is `udp-response`, a connection
/// the operating system refused `conn-refused`, an open port a window scan
/// read off a reset `reset`. Nothing is inferred from the state where the
/// record names the packet.
///
/// A port with no record of its packet falls back to the one packet its state
/// and transport admit, where there is exactly one: only a SYN/ACK opens a TCP
/// port, only a datagram a UDP one and only an INIT-ACK an SCTP one, only a
/// reset closes a TCP port or leaves it unfiltered, only a port unreachable
/// closes a UDP one and only an ABORT an SCTP one. The states silence decides
/// fall back to `no-response`, which a UDP scan reaching `open|filtered` records
/// no packet for because none arrived.
///
/// A port no probe was sent to did not fail to respond, so it answers [`None`]
/// here for the reason [`port_state`] does.
fn port_reason(port: &Port) -> Option<&str> {
    port_state(port.state())?;

    if let Some(discovery) = port.discovery() {
        return Some(response_reason(discovery.reason(), port));
    }

    Some(match (port.state(), port.protocol()) {
        (PortState::Open, Protocol::Tcp) => "syn-ack",
        (PortState::Open, Protocol::Udp) => "udp-response",
        (PortState::Open, Protocol::Sctp) => "init-ack",
        (PortState::Closed | PortState::Unfiltered, Protocol::Tcp) => "reset",
        (PortState::Closed, Protocol::Udp) => "port-unreach",
        (PortState::Closed, Protocol::Sctp) => "abort",
        _ => "no-response",
    })
}

/// A recorded response in nmap's reason vocabulary.
///
/// Nmap's words are finer than this engine's record in one place, the ICMP
/// unreachable, which nmap names by its code and this engine records without
/// one. A port unreachable is the only unreachable that closes a UDP port, so a
/// closed UDP port's is `port-unreach`; any other is `dest-unreach`, nmap's word
/// for a destination unreachable it does not single out by code, rather than a
/// code nobody read.
///
/// A response this engine names and nmap does not is written in this engine's
/// own name: an unfamiliar reason costs a reader a moment, where one naming a
/// packet that never arrived costs them the truth.
fn response_reason<'a>(response: &'a ScanResponse, port: &Port) -> &'a str {
    match response {
        // A SYN/ACK overheard on its way to another peer is still a SYN/ACK,
        // which is the packet the word names.
        ScanResponse::TcpSynAck | ScanResponse::OverheardSynAck => "syn-ack",
        ScanResponse::TcpRst => "reset",
        ScanResponse::ConnectionRefused => "conn-refused",
        ScanResponse::UdpResponse => "udp-response",
        ScanResponse::SctpInitAck => "init-ack",
        ScanResponse::SctpAbort => "abort",
        ScanResponse::NoResponse => "no-response",
        ScanResponse::IcmpUnreachable
            if port.state() == PortState::Closed && port.protocol() == Protocol::Udp =>
        {
            "port-unreach"
        }
        ScanResponse::IcmpUnreachable => "dest-unreach",
        ScanResponse::IcmpProhibited => "admin-prohibited",
        ScanResponse::Custom(name) => name.as_str(),
    }
}

/// The TTL the reply that decided a port carried, which nmap writes beside the
/// reason, or 0 where no reply was read from a header, which is what nmap
/// writes for the same absence.
fn reason_ttl(port: &Port) -> u8 {
    port.discovery()
        .and_then(|discovery| discovery.ttl())
        .unwrap_or(0)
}

/// This engine's host statuses in nmap's spelling.
///
/// Nmap has three where this engine has four. `filtered` means the host is there
/// and its probes are being dropped, which nmap has no separate word for and
/// which is unambiguously `up`. The distinction survives in the reason.
fn host_state(status: HostStatus) -> &'static str {
    match status {
        HostStatus::Up | HostStatus::Filtered => "up",
        HostStatus::Down => "down",
        HostStatus::Unknown => "unknown",
    }
}

/// The evidence behind a host's status, in nmap's words where nmap has one.
///
/// Read from the evidence the host holds rather than from its status, since
/// nmap's reason names the packet that decided the state: a host its neighbour
/// table answered for is `arp-response`, one that answered a ping `echo-reply`.
/// Of several, the most direct is named, in the order [`host_reason_rank`]
/// gives, so a document reads the same whichever arrived first.
///
/// A host holding no evidence for its status says so without naming a packet:
/// `response` for one that is up for a reason nothing recorded, which is not a
/// word of nmap's and is the honest one, and `no-response` for one nothing
/// answered for, which is what an unknown host is.
fn status_reason(host: &Host) -> &str {
    let status = host.status();
    if status == HostStatus::Filtered {
        // Nmap has no reason string for this because it has no such state. The
        // word is this engine's and says what happened.
        return "probes-filtered";
    }

    let evidence = host
        .reasons()
        .iter()
        .filter_map(|reason| Some((host_reason_rank(reason, status)?, reason)))
        .min_by(|(rank, reason), (other_rank, other)| {
            rank.cmp(other_rank)
                .then_with(|| host_reason(reason).cmp(host_reason(other)))
        });
    if let Some((_, reason)) = evidence {
        return host_reason(reason);
    }

    match status {
        HostStatus::Up => "response",
        HostStatus::Down => "dest-unreach",
        HostStatus::Filtered | HostStatus::Unknown => "no-response",
    }
}

/// How directly a piece of evidence establishes `status`, lowest first, or
/// [`None`] for evidence that does not establish it at all.
///
/// A host keeps every reason it was given as its status rose, so one that is up
/// may also hold the unreachable a router sent before it answered, and only
/// evidence the host sent for itself says it is up. Among those, the neighbour
/// table answering is the most direct and is what nmap names on a local
/// segment, then the probes nmap's own discovery sends, in the order it sends
/// them, then the rest.
fn host_reason_rank(reason: &StatusReason, status: HostStatus) -> Option<u8> {
    let from_host = reason.source == EvidenceSource::Host;
    match status {
        HostStatus::Up if from_host => Some(match reason.protocol {
            StatusProtocol::Arp | StatusProtocol::Ndp => 0,
            StatusProtocol::IcmpEcho => 1,
            StatusProtocol::TcpSyn | StatusProtocol::TcpConnect => 2,
            StatusProtocol::Tcp => 3,
            StatusProtocol::IcmpTimestamp => 4,
            StatusProtocol::Udp | StatusProtocol::Sctp => 5,
            StatusProtocol::IcmpUnreachable => 6,
            StatusProtocol::Dhcp => 7,
            StatusProtocol::Custom(_) => 8,
        }),
        // An unreachable is the only evidence that puts a host down, and
        // whoever sent it is somebody in the path by definition.
        HostStatus::Down => (reason.protocol == StatusProtocol::IcmpUnreachable).then_some(0),
        HostStatus::Up | HostStatus::Filtered | HostStatus::Unknown => None,
    }
}

/// One piece of host evidence in nmap's reason vocabulary.
///
/// The TCP and SCTP protocols carry either of two packets, an acceptance or a
/// reset, and record which only in prose, so their word names the transport
/// rather than guessing the packet: `tcp-response` is nmap's word for a TCP
/// reply it names no further, and `sctp-response` follows its shape. A DHCP server overheard on the segment has no
/// word in nmap's vocabulary, which never listens, and is named for what it was.
/// An ICMP unreachable is `dest-unreach` for the reason [`response_reason`]
/// gives.
fn host_reason(reason: &StatusReason) -> &str {
    match &reason.protocol {
        StatusProtocol::Arp => "arp-response",
        StatusProtocol::Ndp => "nd-response",
        StatusProtocol::IcmpEcho => "echo-reply",
        StatusProtocol::IcmpTimestamp => "timestamp-reply",
        StatusProtocol::IcmpUnreachable => "dest-unreach",
        StatusProtocol::TcpSyn | StatusProtocol::TcpConnect | StatusProtocol::Tcp => "tcp-response",
        StatusProtocol::Sctp => "sctp-response",
        StatusProtocol::Udp => "udp-response",
        StatusProtocol::Dhcp => "dhcp-response",
        StatusProtocol::Custom(name) => name,
    }
}

/// A service label split into the protocol nmap names and the tunnel it names
/// beside it.
///
/// This engine labels a protocol read through TLS `ssl/http`, one string holding
/// both facts. Nmap keeps them apart, `name="http" tunnel="ssl"`, and what reads
/// its XML keys on the name: an exploit search, a screenshot tool, an importer
/// filing web services. Written whole, the label is a protocol none of them has
/// heard of, and an HTTPS server is missing from every list of web servers built
/// from the document.
///
/// A bare `ssl` is a handshake with nothing identified inside it, which nmap
/// also writes as that name alone.
fn service_name(label: &str) -> (&str, Option<&'static str>) {
    match (Tunnel::from_service_label(label), label.split_once('/')) {
        (Some(Tunnel::Tls), Some((_, protocol))) => (protocol, Some("ssl")),
        _ => (label, None),
    }
}

/// A transport in nmap's spelling.
fn transport(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Sctp => "sctp",
    }
}

/// This engine's service confidence on nmap's 1-to-10 scale.
///
/// Nmap's `conf` is an integer from 1 to 10 and this engine's is a percentage,
/// so the mapping is arithmetic rather than a judgement. It never reaches 0,
/// which is not a value nmap's scale has.
fn nmap_confidence(confidence: u8) -> u8 {
    // Three is what nmap records for a port-number lookup, and zero is this
    // engine's spelling of the same thing.
    if confidence == 0 {
        return TABLE_CONFIDENCE;
    }

    (u16::from(confidence).saturating_mul(10) / 100).clamp(1, 10) as u8
}

/// What nmap records for a service it read out of its port-number list.
const TABLE_CONFIDENCE: u8 = 3;

// ---------------------------------------------------------------------------
// Times
// ---------------------------------------------------------------------------

/// A time as nmap writes it: whole seconds since the epoch.
///
/// A time before the epoch has no representation here and becomes 0, which
/// cannot arise from a scan that has happened.
fn epoch_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// The human-readable companion nmap writes beside every timestamp.
///
/// Nmap writes a local-time C `ctime` string here. This writes RFC 3339 in UTC,
/// the same instant, unambiguous about its zone and matching every other document
/// this engine emits. Consumers parse the numeric field beside it; this one is
/// for a person.
fn time_string(time: SystemTime) -> String {
    crate::format::time::rfc3339(time)
}

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

/// Report text on its way into an XML attribute value.
///
/// Escapes the five characters that have meaning and drops the ones XML 1.0
/// cannot carry. There is no escape for a `0x01` in XML 1.0, a numeric reference
/// to one being as illegal as the byte, so a service banner containing one has to
/// lose it or the whole document becomes unparseable.
struct Attr<'a>(&'a str);

impl fmt::Display for Attr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for character in self.0.chars() {
            match character {
                '&' => f.write_str("&amp;")?,
                '<' => f.write_str("&lt;")?,
                '>' => f.write_str("&gt;")?,
                '"' => f.write_str("&quot;")?,
                '\'' => f.write_str("&apos;")?,
                // Legal, and lost unless referenced: a parser reading an
                // attribute value turns each raw one into a space, so a
                // two-line banner would read back as one line.
                '\t' => f.write_str("&#x9;")?,
                '\n' => f.write_str("&#xa;")?,
                '\r' => f.write_str("&#xd;")?,
                character if is_forbidden(character) => {}
                character => f.write_char(character)?,
            }
        }
        Ok(())
    }
}

/// Whether a character cannot appear in an XML 1.0 document, or should not.
///
/// The first group is the specification's: the only C0 controls a document may
/// contain are tab, line feed and carriage return, and no numeric reference
/// makes the others legal. The surrogates and the two non-characters at the end
/// of the basic plane are equally forbidden, though Rust's `char` already
/// excludes the surrogates.
///
/// The second group is a judgement rather than a rule. The bidirectional
/// formatting characters are legal XML and dropped anyway, since they reorder the
/// text around them without being visible.
fn is_forbidden(character: char) -> bool {
    let code = u32::from(character);

    let control = matches!(code, 0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F);
    let noncharacter = matches!(code, 0xFFFE | 0xFFFF);
    let bidirectional = matches!(code, 0x202A..=0x202E | 0x2066..=0x2069 | 0x200E | 0x200F);

    control || noncharacter || bidirectional
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
    use crate::export::fixture;
    use crate::model::exclusion::Exclusions;

    fn render() -> String {
        let mut out = Vec::new();
        NmapXmlExporter::new(ExportOptions::new())
            .export(&fixture::report(), &mut out)
            .expect("the fixture exports");
        String::from_utf8(out).expect("the document is UTF-8")
    }

    /// A report of nothing but `hosts`, exported.
    fn export(hosts: &[Host]) -> String {
        let report = ScanReport::recorded("zond", Vec::new(), hosts.to_vec());
        let mut out = Vec::new();
        NmapXmlExporter::new(ExportOptions::new())
            .export(&report, &mut out)
            .expect("the report exports");
        String::from_utf8(out).expect("the document is UTF-8")
    }

    /// A phase of `kind` over `targets`, which failed as `failures` say and
    /// recorded nothing else.
    fn phase(
        kind: crate::report::ScanKind,
        targets: crate::report::TargetScope,
        failures: Vec<ScannerFailure>,
    ) -> ScanPhase {
        ScanPhase::from_parts(phase_parts(kind, targets, failures))
    }

    /// The parts of [`phase`], for a test that records something more.
    fn phase_parts(
        kind: crate::report::ScanKind,
        targets: crate::report::TargetScope,
        failures: Vec<ScannerFailure>,
    ) -> crate::report::PhaseParts {
        crate::report::PhaseParts {
            open: false,
            kind,
            started_at: std::time::SystemTime::UNIX_EPOCH,
            elapsed: std::time::Duration::from_secs(1),
            privilege: None,
            targets,
            settings: crate::report::ScanSettings::from(&crate::config::ZondConfig::default()),
            failures,
            refusals: Vec::new(),
            unroutable: Vec::new(),
            timed_out: Vec::new(),
            icmp_rate_limited: Vec::new(),
            reached_by_connect: Vec::new(),
            undecided: Vec::new(),
            liveness_skipped: None,
            silent: Vec::new(),
            stopped: None,
            passes_cut: Vec::new(),
            unreached: 0,
            unheard_probes: 0,
            probes: Vec::new(),
            origin: None,
            attachments: Vec::new(),
        }
    }

    /// A report of `phases` and `hosts`, exported.
    fn export_phases(phases: Vec<ScanPhase>, hosts: Vec<Host>) -> String {
        let report = ScanReport::recorded("zond", phases, hosts);
        let mut out = Vec::new();
        NmapXmlExporter::new(ExportOptions::new())
            .export(&report, &mut out)
            .expect("the report exports");
        String::from_utf8(out).expect("the document is UTF-8")
    }

    /// The exclusion note names the policy once, however many phases ran
    /// under it, and a range one phase added beside it joins it.
    ///
    /// Every phase records the policy in force, so a discovery sweep followed
    /// by a port scan carries it twice, and a note listing each phase's copy
    /// would state it twice. A phase can also widen it, by the other addresses
    /// of a machine the policy names, and the note is the union: an address
    /// set, merged as the policy itself is merged.
    #[test]
    fn the_exclusion_note_is_the_union_of_every_phases_policy() {
        use crate::report::{ScanKind, TargetScope};
        use std::net::{IpAddr, Ipv4Addr};

        let policy = |last: &[u8]| {
            let mut set = IpSet::new();
            for last in last {
                set.insert(IpAddr::V4(Ipv4Addr::new(192, 0, 2, *last)));
            }
            Exclusions::new(set)
        };
        let scope =
            |exclusions: &Exclusions| TargetScope::from_ip_set(&mut IpSet::new(), exclusions);

        let document = export_phases(
            vec![
                phase(ScanKind::Discovery, scope(&policy(&[1, 9])), Vec::new()),
                phase(ScanKind::PortScan, scope(&policy(&[1, 2, 9])), Vec::new()),
            ],
            Vec::new(),
        );

        let note = document
            .lines()
            .find(|line| line.starts_with("<!-- zond: excluded"))
            .expect("a policy was in force");
        assert_eq!(
            note,
            "<!-- zond: excluded by policy, not scanned: \
             192.0.2.1-192.0.2.2, 192.0.2.9-192.0.2.9 -->"
        );
    }

    /// **A privileged phase that reached every address it covered by connect
    /// is a connect scan, and one that reached only some of them so is not.**
    ///
    /// Loopback and this host's own addresses are beyond a raw probe, so a
    /// privileged scan of them connects, and its closed ports carry the
    /// refusal a connect draws. Named after the technique, the document
    /// claims SYNs went to ports that were never sent one.
    #[test]
    fn a_privileged_phase_that_reached_everything_by_connect_is_a_connect_scan() {
        use crate::report::{ScanKind, TargetScope};

        let phase = |covered: &str, reached: &str| {
            let mut covered: IpSet = covered.parse().expect("addresses");
            let reached: IpSet = reached.parse().expect("addresses");
            let targets = TargetScope::from_ip_set(&mut covered, &Exclusions::none());
            let mut parts = phase_parts(ScanKind::PortScan, targets, Vec::new());
            parts.privilege = Some(Privilege::Raw);
            parts.reached_by_connect = reached.v4().iter().copied().map(IpRange::V4).collect();
            ScanPhase::from_parts(parts)
        };

        assert_eq!(
            scan_type(&phase("127.0.0.1", "127.0.0.1"), Protocol::Tcp),
            "connect"
        );
        assert_eq!(
            scan_type(&phase("127.0.0.1,192.0.2.1", "127.0.0.1"), Protocol::Tcp),
            "syn",
            "the rest were sent SYNs"
        );
        assert_eq!(
            scan_type(&phase("127.0.0.1", "127.0.0.1"), Protocol::Udp),
            "udp"
        );
    }

    /// The `<state>` line of `port`, as written.
    fn state_line(port: &Port) -> String {
        let mut out = Vec::new();
        write_port(&mut out, port).expect("writing to a vector");
        let written = String::from_utf8(out).expect("UTF-8");
        written
            .lines()
            .find(|line| line.starts_with("<state "))
            .expect("a probed port has a state")
            .to_owned()
    }

    /// A port's reason names the packet its record says decided it, with the
    /// TTL that packet carried.
    ///
    /// Nmap's reason is per port and says which packet arrived, and a consumer
    /// reading it learns how the verdict was reached: a UDP port that answered
    /// is not a TCP handshake, and a connection the operating system refused is
    /// not a reset anybody saw. A reason chosen by state alone would tell
    /// every open UDP port's reader that a SYN/ACK arrived.
    #[test]
    fn a_ports_reason_names_the_packet_that_decided_it() {
        use crate::model::port::discovery::Discovery;

        let udp_open = Port::new(53, Protocol::Udp, PortState::Open)
            .with_discovery(Discovery::new(ScanResponse::UdpResponse).with_ttl(63));
        assert_eq!(
            state_line(&udp_open),
            r#"<state state="open" reason="udp-response" reason_ttl="63"/>"#
        );

        let refused = Port::new(23, Protocol::Tcp, PortState::Closed)
            .with_discovery(Discovery::new(ScanResponse::ConnectionRefused));
        assert_eq!(
            state_line(&refused),
            r#"<state state="closed" reason="conn-refused" reason_ttl="0"/>"#
        );

        // A window scan opens a port on the reset it read, and says so.
        let window = Port::new(80, Protocol::Tcp, PortState::Open)
            .with_discovery(Discovery::new(ScanResponse::TcpRst).with_ttl(64));
        assert!(state_line(&window).contains(r#"reason="reset" reason_ttl="64""#));

        // The only unreachable that closes a UDP port is a port unreachable,
        // and one that filters a port is named without a code nobody read.
        let unreachable = |state| {
            Port::new(161, Protocol::Udp, state)
                .with_discovery(Discovery::new(ScanResponse::IcmpUnreachable))
        };
        assert!(state_line(&unreachable(PortState::Closed)).contains(r#"reason="port-unreach""#));
        assert!(state_line(&unreachable(PortState::Filtered)).contains(r#"reason="dest-unreach""#));
    }

    /// A port with no record of its packet is given the one packet its state
    /// and transport admit, and silence where silence is what decided it.
    #[test]
    fn a_port_with_no_recorded_packet_names_the_one_its_state_admits() {
        let line = |number, protocol, state| state_line(&Port::new(number, protocol, state));

        assert!(line(53, Protocol::Udp, PortState::Open).contains(r#"reason="udp-response""#));
        assert!(line(22, Protocol::Tcp, PortState::Open).contains(r#"reason="syn-ack""#));
        assert!(line(69, Protocol::Udp, PortState::Closed).contains(r#"reason="port-unreach""#));
        assert!(line(2905, Protocol::Sctp, PortState::Closed).contains(r#"reason="abort""#));
        assert!(
            line(123, Protocol::Udp, PortState::OpenFiltered).contains(r#"reason="no-response""#)
        );
    }

    /// A host's reason names the evidence it holds, the most direct first.
    ///
    /// A reason chosen by status alone would make every live host an
    /// `echo-reply`, including one only its neighbour table answered for on a
    /// segment that drops pings, and one a router reported unreachable
    /// `no-response`, which a reader of this format takes for silence and so
    /// reads back as unknown rather than down.
    #[test]
    fn a_hosts_reason_names_the_evidence_it_holds() {
        use std::net::{IpAddr, Ipv4Addr};

        let status = |host: &Host| {
            let document = export(std::slice::from_ref(host));
            document
                .lines()
                .find(|line| line.starts_with("<status "))
                .expect("a host has a status")
                .to_owned()
        };

        let mut neighbour = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)));
        neighbour.record_evidence(HostStatus::Up, StatusReason::basic(StatusProtocol::TcpSyn));
        neighbour.record_evidence(HostStatus::Up, StatusReason::basic(StatusProtocol::Arp));
        assert!(status(&neighbour).contains(r#"state="up" reason="arp-response""#));

        let pinged = {
            let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
            // A router's unreachable, then the host answering for itself: the
            // unreachable says nothing about a host that is up.
            host.record_evidence(
                HostStatus::Down,
                StatusReason::basic(StatusProtocol::IcmpUnreachable)
                    .from_source(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            );
            host.record_evidence(
                HostStatus::Up,
                StatusReason::basic(StatusProtocol::IcmpEcho),
            );
            host
        };
        assert!(status(&pinged).contains(r#"state="up" reason="echo-reply""#));

        let mut unreachable = Host::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 40)));
        unreachable.record_evidence(
            HostStatus::Down,
            StatusReason::basic(StatusProtocol::IcmpUnreachable)
                .from_source(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
        );
        assert!(status(&unreachable).contains(r#"state="down" reason="dest-unreach""#));

        let mut asserted = Host::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 41)));
        asserted.set_status(HostStatus::Up);
        assert!(
            status(&asserted).contains(r#"state="up" reason="response""#),
            "a host up on no recorded evidence named a packet: {}",
            status(&asserted)
        );
    }

    /// The reasons this module writes read back as the evidence they came from,
    /// and a filtered host as filtered.
    #[cfg(feature = "import-nmap")]
    #[test]
    fn reasons_survive_the_round_trip() {
        use crate::import::report::ReportReader;
        use crate::import::report::nmap::NmapXmlReportReader;
        use crate::model::port::discovery::Discovery;
        use std::net::{IpAddr, Ipv4Addr};

        let mut neighbour = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)));
        neighbour.record_evidence(HostStatus::Up, StatusReason::basic(StatusProtocol::Arp));
        neighbour.add_port(
            Port::new(53, Protocol::Udp, PortState::Open)
                .with_discovery(Discovery::new(ScanResponse::UdpResponse)),
        );
        let mut walled = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 21)));
        walled.record_evidence(
            HostStatus::Filtered,
            StatusReason::basic(StatusProtocol::IcmpUnreachable),
        );

        let restored = NmapXmlReportReader::default()
            .read(&mut std::io::Cursor::new(
                export(&[neighbour, walled]).into_bytes(),
            ))
            .expect("this crate's own document reads back");
        let mut hosts = restored.hosts();

        let neighbour = hosts.next().expect("the neighbour survived");
        assert!(
            neighbour
                .reasons()
                .iter()
                .any(|reason| reason.protocol == StatusProtocol::Arp),
            "{:?}",
            neighbour.reasons()
        );
        let port = neighbour.ports().next().expect("its port survived");
        assert_eq!(
            port.discovery().map(|discovery| discovery.reason()),
            Some(&ScanResponse::UdpResponse)
        );

        let walled = hosts.next().expect("the filtered host survived");
        assert_eq!(walled.status(), HostStatus::Filtered);
    }

    /// A service read through TLS is written as nmap writes one, the protocol
    /// named and the tunnel beside it, and reads back as the label it was.
    ///
    /// The tools that read this format find web servers by `name="http"`, so
    /// an HTTPS port written `name="ssl/http"` is one none of them lists.
    #[cfg(feature = "import-nmap")]
    #[test]
    fn a_service_read_through_tls_is_named_with_its_tunnel_beside_it() {
        use crate::import::report::ReportReader;
        use crate::import::report::nmap::NmapXmlReportReader;
        use crate::model::port::Service;
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30)));
        host.set_status(HostStatus::Up);
        host.add_port(
            Port::new(8443, Protocol::Tcp, PortState::Open)
                .with_service(Service::new("ssl/http", 90).with_product("nginx")),
        );
        host.add_port(
            Port::new(9443, Protocol::Tcp, PortState::Open).with_service(Service::new("ssl", 80)),
        );

        let document = export(&[host]);
        assert!(
            document.contains(r#"<service name="http" product="nginx" tunnel="ssl""#),
            "{document}"
        );
        assert!(!document.contains("ssl/"), "{document}");
        assert!(
            document.contains(r#"<service name="ssl" method="probed""#),
            "a handshake with nothing named inside it is nmap's bare `ssl`: {document}"
        );

        let restored = NmapXmlReportReader::default()
            .read(&mut std::io::Cursor::new(document.into_bytes()))
            .expect("this crate's own document reads back");
        let names: Vec<_> = restored
            .hosts()
            .flat_map(Host::ports)
            .filter_map(Port::service_name)
            .collect();
        assert_eq!(names, ["ssl/http", "ssl"]);
    }

    /// A full range of closed and silent ports is summarised as nmap
    /// summarises one, and every port in the summary reads back as it went out.
    ///
    /// Each listed port is a service row to an importer and a lookup to an
    /// exploit search, so a full-range scan listed whole puts 65,535 of both
    /// into every tool that reads it, nearly all the port-number label of a
    /// closed port. What stays listed is what a summary would lose: the open
    /// port, and a closed one somebody identified a service on.
    #[cfg(feature = "import-nmap")]
    #[test]
    fn the_dominant_closed_and_silent_states_are_summarised_and_read_back_whole() {
        use crate::import::report::ReportReader;
        use crate::import::report::nmap::NmapXmlReportReader;
        use crate::model::port::Service;
        use crate::model::port::discovery::Discovery;
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)));
        host.set_status(HostStatus::Up);
        for number in 1..=100 {
            let port = match number {
                22 => Port::new(22, Protocol::Tcp, PortState::Open)
                    .with_service(Service::new("ssh", 100)),
                // Closed, but somebody identified what answered, which the
                // summary has nowhere to put.
                80 => Port::new(80, Protocol::Tcp, PortState::Closed)
                    .with_service(Service::new("http", 90)),
                number => Port::new(number, Protocol::Tcp, PortState::Closed)
                    .with_discovery(Discovery::new(ScanResponse::TcpRst))
                    .with_service(Service::new("registered", 0)),
            };
            host.add_port(port);
        }
        for number in 1000..1040 {
            host.add_port(Port::new(number, Protocol::Udp, PortState::OpenFiltered));
        }
        // Too few to summarise, as nmap would list them.
        for number in 5000..5003 {
            host.add_port(Port::new(number, Protocol::Tcp, PortState::Filtered));
        }
        let before: Vec<(u16, Protocol, PortState)> = host
            .ports()
            .map(|port| (port.number(), port.protocol(), port.state()))
            .collect();

        let document = export(&[host]);

        assert_eq!(
            document.matches("<port ").count(),
            5,
            "only the open port, the identified closed one and the three \
             filtered ones are listed: {document}"
        );
        assert!(
            document.contains(
                r#"<extraports state="closed" count="98">
<extrareasons reason="reset" count="98" proto="tcp" ports="1-21,23-79,81-100"/>
</extraports>"#
            ),
            "{document}"
        );
        assert!(
            document.contains(
                r#"<extrareasons reason="no-response" count="40" proto="udp" ports="1000-1039"/>"#
            ),
            "{document}"
        );
        assert!(
            !document.contains("registered"),
            "a summarised port's port-number label was written: {document}"
        );
        // Nmap's DTD puts every summary before the first listed port.
        assert!(document.rfind("</extraports>") < document.find("<port "));

        let restored = NmapXmlReportReader::default()
            .read(&mut std::io::Cursor::new(document.into_bytes()))
            .expect("this crate's own document reads back");
        let host = restored.hosts().next().expect("the host survived");
        let after: Vec<(u16, Protocol, PortState)> = host
            .ports()
            .map(|port| (port.number(), port.protocol(), port.state()))
            .collect();
        assert_eq!(
            after, before,
            "a port changed on the way through the summary"
        );

        let reset = host
            .ports()
            .find(|port| port.number() == 1)
            .and_then(|port| port.discovery().map(|discovery| discovery.reason().clone()));
        assert_eq!(reset, Some(ScanResponse::TcpRst));
    }

    /// An SCTP port reads back as one, listed or summarised.
    ///
    /// Nmap writes SCTP as `protocol="sctp"` and this engine scans it, and a
    /// reader refusing the transport refuses every document an SCTP scan
    /// exports, not just the port.
    #[cfg(feature = "import-nmap")]
    #[test]
    fn an_sctp_port_survives_the_round_trip() {
        use crate::import::report::ReportReader;
        use crate::import::report::nmap::NmapXmlReportReader;
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 60)));
        host.set_status(HostStatus::Up);
        host.add_port(Port::new(2905, Protocol::Sctp, PortState::Open));
        for number in 3000..3030 {
            host.add_port(Port::new(number, Protocol::Sctp, PortState::Closed));
        }

        let restored = NmapXmlReportReader::default()
            .read(&mut std::io::Cursor::new(export(&[host]).into_bytes()))
            .expect("an SCTP scan's document reads back");
        let host = restored.hosts().next().expect("the host survived");

        assert_eq!(host.port_count(), 31);
        assert!(host.ports().all(|port| port.protocol() == Protocol::Sctp));
    }

    /// The run statistics count the addresses the scan covered, not the hosts
    /// it recorded.
    ///
    /// A sweep of a /24 with a handful answering covers 256 addresses, and a
    /// count of the recorded hosts would tell a consumer reporting coverage
    /// from `<runstats>` that it covered the handful, every one of them up.
    #[test]
    fn the_run_statistics_count_what_the_scan_covered() {
        use crate::report::{ScanKind, TargetScope};
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let mut swept = IpSet::new();
        swept.insert_range("192.0.2.0/24".parse().expect("a range"));
        let scope = TargetScope::from_ip_set(&mut swept, &Exclusions::none());

        let v4 = |last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last));
        let mut answered = Host::new(v4(10));
        answered.set_status(HostStatus::Up);
        // One machine at two of the swept addresses is one host up.
        let mut two_addresses = Host::new(v4(20));
        two_addresses.add_ip(v4(21));
        two_addresses.set_status(HostStatus::Up);
        // Found on the link, at an address no range named.
        let mut neighbour = Host::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5)));
        neighbour.set_status(HostStatus::Up);
        let mut unreachable = Host::new(v4(30));
        unreachable.set_status(HostStatus::Down);

        let document = export_phases(
            vec![phase(ScanKind::Discovery, scope, Vec::new())],
            vec![answered, two_addresses, neighbour, unreachable],
        );

        assert!(
            document.contains(r#"<hosts up="3" down="253" total="256"/>"#),
            "{document}"
        );
        assert!(
            document.contains("257 IP addresses (3 hosts up)"),
            "{document}"
        );
    }

    /// Line breaks in a value survive a standard XML parser.
    ///
    /// XML allows a raw line feed in an attribute value and a parser reading it
    /// turns it into a space, so written raw, a banner's second line reaches
    /// every tool downstream joined to its first.
    #[cfg(feature = "import-nmap")]
    #[test]
    fn a_line_break_in_a_value_is_written_as_a_reference_and_reads_back() {
        use crate::import::report::ReportReader;
        use crate::import::report::nmap::NmapXmlReportReader;
        use crate::model::port::Service;
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 70)));
        host.set_status(HostStatus::Up);
        host.add_port(
            Port::new(25, Protocol::Tcp, PortState::Open)
                .with_service(Service::new("smtp", 90).with_extrainfo("ESMTP\r\nready\t2")),
        );

        let document = export(&[host]);
        assert!(
            document.contains(r#"extrainfo="ESMTP&#xd;&#xa;ready&#x9;2""#),
            "{document}"
        );

        let restored = NmapXmlReportReader::default()
            .read(&mut std::io::Cursor::new(document.into_bytes()))
            .expect("this crate's own document reads back");
        let extrainfo = restored
            .hosts()
            .flat_map(Host::ports)
            .find_map(|port| port.service()?.extrainfo().map(str::to_owned));
        assert_eq!(extrainfo.as_deref(), Some("ESMTP\r\nready\t2"));
    }

    /// An operating system is written with its class and CPEs, and a service
    /// with its CPEs, where nmap's readers look for them.
    ///
    /// An importer files a host under the class's family and a vulnerability
    /// lookup keys on the CPE, and a match written with its name alone gives
    /// both nothing.
    #[cfg(feature = "import-nmap")]
    #[test]
    fn an_os_class_and_the_cpes_are_written_and_read_back() {
        use crate::import::report::ReportReader;
        use crate::import::report::nmap::NmapXmlReportReader;
        use crate::model::host::OsFingerprint;
        use crate::model::port::Service;
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80)));
        host.set_status(HostStatus::Up);
        let mut os = OsFingerprint::new("Linux 5.15", 95)
            .with_family("Linux")
            .with_generation("5.X")
            .with_device("general purpose");
        os.add_cpe("cpe:/o:linux:linux_kernel:5.15");
        host.set_os(os);
        host.add_port(
            Port::new(22, Protocol::Tcp, PortState::Open).with_service(
                Service::new("ssh", 100)
                    .with_product("OpenSSH")
                    .with_cpe("cpe:/a:openbsd:openssh:9.6"),
            ),
        );

        let document = export(&[host]);
        assert!(
            document.contains(
                r#"<osclass vendor="" osfamily="Linux" osgen="5.X" type="general purpose" accuracy="95">
<cpe>cpe:/o:linux:linux_kernel:5.15</cpe>
</osclass>"#
            ),
            "{document}"
        );
        assert!(
            document.contains("<cpe>cpe:/a:openbsd:openssh:9.6</cpe>\n</service>"),
            "{document}"
        );

        let restored = NmapXmlReportReader::default()
            .read(&mut std::io::Cursor::new(document.into_bytes()))
            .expect("this crate's own document reads back");
        let host = restored.hosts().next().expect("the host survived");
        let os = host.os().expect("the operating system survived");
        assert_eq!(os.family(), Some("Linux"));
        assert_eq!(os.generation(), Some("5.X"));
        assert_eq!(
            os.vendor(),
            None,
            "a vendor nobody established came back named"
        );
        assert!(
            os.cpes()
                .iter()
                .any(|cpe| &**cpe == "cpe:/o:linux:linux_kernel:5.15")
        );
        let service = host
            .ports()
            .find_map(Port::service)
            .expect("the service survived");
        assert!(
            service
                .cpes()
                .iter()
                .any(|cpe| &**cpe == "cpe:/a:openbsd:openssh:9.6")
        );
    }

    /// Runs of port numbers are written as nmap writes them.
    #[test]
    fn a_port_list_is_written_in_runs() {
        assert!(port_lists(&[]).is_empty());
        assert_eq!(port_lists(&[7]), [(1, "7".to_owned())]);
        assert_eq!(
            port_lists(&[1, 2, 3, 5, 7, 8, 65535]),
            [(7, "1-3,5,7-8,65535".to_owned())]
        );
        assert_eq!(port_lists(&[65534, 65535]), [(2, "65534-65535".to_owned())]);
    }

    /// A summary of scattered ports is split into lists a bounded reader
    /// takes, and every port in them reads back.
    ///
    /// Every other port of a full range in one attribute is two hundred
    /// kilobytes, past the bound on one element that this engine's own reader
    /// refuses a whole document over.
    #[cfg(feature = "import-nmap")]
    #[test]
    fn a_scattered_summary_is_split_into_lists_a_bounded_reader_takes() {
        use crate::import::report::ReportReader;
        use crate::import::report::nmap::NmapXmlReportReader;
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 90)));
        host.set_status(HostStatus::Up);
        for number in 1..=u16::MAX {
            let state = match number % 2 {
                0 => PortState::Closed,
                _ => PortState::Filtered,
            };
            host.add_port(Port::new(number, Protocol::Tcp, state));
        }

        let document = export(&[host]);
        let lists: Vec<&str> = document
            .lines()
            .filter(|line| line.starts_with("<extrareasons "))
            .collect();
        assert!(lists.len() > 2, "{} lists", lists.len());
        assert!(
            lists
                .iter()
                .all(|list| list.len() < 2 * MAX_PORT_LIST_BYTES)
        );

        let restored = NmapXmlReportReader::default()
            .read(&mut std::io::Cursor::new(document.into_bytes()))
            .expect("the document reads back under the default bounds");
        let host = restored.hosts().next().expect("the host survived");
        assert_eq!(host.port_count(), usize::from(u16::MAX));
        assert!(host.ports().all(|port| match port.number() % 2 {
            0 => port.state() == PortState::Closed,
            _ => port.state() == PortState::Filtered,
        }));
    }

    /// A run whose journal fell behind finished as a run that succeeded, and
    /// one whose strategy failed as one that did not.
    ///
    /// nmap calls a run an error when its scanning failed. A journal that
    /// could not be written probed nothing and dropped no answer, so a
    /// consumer reading the attribute would be told the scan went wrong when
    /// the disk did.
    #[test]
    fn a_journal_that_fell_behind_is_not_a_run_that_failed() {
        use crate::report::{ScanKind, ScannerKind, TargetScope};

        let exit = |failed: ScannerKind| {
            let phase = phase(
                ScanKind::PortScan,
                TargetScope::from_ip_set(&mut IpSet::new(), &Exclusions::none()),
                vec![ScannerFailure::new(failed, "it could not")],
            );
            let document = export_phases(vec![phase], Vec::new());
            let at = document.find(r#" exit=""#).expect("a finished element") + 7;
            document[at..]
                .split('"')
                .next()
                .expect("a value")
                .to_owned()
        };

        assert_eq!(exit(ScannerKind::Journal), "success");
        assert_eq!(exit(ScannerKind::Routed), "error");
    }

    /// The point of the whole format. A consumer keys on the root element and
    /// its output version, and gets a document in nmap's shape.
    #[test]
    fn the_document_is_in_nmaps_shape() {
        let document = render();

        assert!(document.starts_with(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
        assert!(document.contains(r#"<nmaprun scanner="zond""#));
        assert!(document.contains(&format!(r#"xmloutputversion="{XML_OUTPUT_VERSION}""#)));
        assert!(document.contains("<host "));
        assert!(document.contains("<ports>"));
        assert!(document.contains("<runstats>"));
        assert!(document.trim_end().ends_with("</nmaprun>"));
    }

    /// The one line of this module that is not a technical decision. A report
    /// that says it came from nmap when it did not is a fabricated record, and
    /// no parser's convenience is worth producing one.
    #[test]
    fn the_document_never_claims_to_be_nmap() {
        let document = render();

        assert!(
            document.contains(r#"scanner="zond""#),
            "the document must say who wrote it"
        );
        assert!(
            !document.contains(r#"scanner="nmap""#),
            "the document must never claim to be nmap's output"
        );
    }

    /// Every verdict a probe reaches has a name in this vocabulary, so a document
    /// is never less specific about a port than the scan was.
    ///
    /// Read off [`PortState::ALL`] rather than a list written out here, which is
    /// what a state added later has to pass through: the six verdicts map, and
    /// the one state that is not a verdict declines to, which the test below
    /// holds it to.
    #[test]
    fn every_port_state_a_probe_reaches_maps_to_a_state_nmap_defines() {
        const NMAP_STATES: [&str; 6] = [
            "open",
            "closed",
            "filtered",
            "unfiltered",
            "open|filtered",
            "closed|filtered",
        ];

        for state in PortState::ALL {
            let Some(name) = port_state(state) else {
                assert_eq!(
                    state,
                    PortState::Unasked,
                    "{state:?} has no name in nmap's vocabulary and is not the \
                     one state that has none"
                );
                continue;
            };
            assert!(
                NMAP_STATES.contains(&name),
                "{state:?} maps to '{name}', which nmap does not define"
            );
        }
    }

    /// A protocol verdict survives the round trip through nmap's own shape for
    /// one, which is a `<port>` element with `protocol="ip"`.
    ///
    /// Written in that shape because the format is nmap's and every tool that
    /// reads it reads protocol scans that way. It has to come back as a protocol
    /// rather than as a port, or this engine would read its own document as a
    /// host with a port 47 nobody found.
    #[test]
    fn a_protocol_verdict_is_written_as_nmap_writes_one_and_reads_back_as_one() {
        use crate::import::report::ReportReader;
        use crate::import::report::nmap::NmapXmlReportReader;
        use crate::model::host::IpProtocolState;
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)));
        host.set_status(HostStatus::Up);
        host.record_ip_protocol(47, IpProtocolState::Open);
        host.record_ip_protocol(89, IpProtocolState::Closed);
        // Named and never reached, so there is nothing for the format to say.
        host.record_ip_protocol(103, IpProtocolState::Unasked);

        let document = export(&[host]);
        assert!(
            document.contains(r#"<port protocol="ip" portid="47">"#),
            "{document}"
        );
        assert!(document.contains(r#"<service name="gre""#), "{document}");
        assert!(
            !document.contains(r#"portid="103""#),
            "a protocol nobody reached was written down anyway"
        );

        let restored = NmapXmlReportReader::default()
            .read(&mut std::io::Cursor::new(document.into_bytes()))
            .expect("this crate's own document reads back");
        let restored = restored.hosts().next().expect("the host survived");

        assert_eq!(
            restored.ip_protocols().get(&47),
            Some(&IpProtocolState::Open)
        );
        assert_eq!(
            restored.ip_protocols().get(&89),
            Some(&IpProtocolState::Closed)
        );
        assert_eq!(
            restored.port_count(),
            0,
            "a protocol came back as a port, which is the one reading that must not happen"
        );
    }

    /// A port no probe was sent to is not written at all.
    ///
    /// Nmap does not emit a `<port>` for a port it did not scan, so there is no
    /// state to file one under and no honest way to invent one. Writing it as
    /// `filtered`, the nearest of the six, would tell every tool that reads this
    /// format that a firewall dropped a probe this scan never sent.
    #[test]
    fn a_port_nobody_asked_about_is_left_out_of_the_document() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
        host.set_status(HostStatus::Up);
        host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        host.add_port(Port::new(23, Protocol::Tcp, PortState::Unasked));

        let document = export(&[host]);

        assert!(
            document.contains(r#"portid="22""#),
            "the probed port is missing"
        );
        assert!(
            !document.contains(r#"portid="23""#),
            "a port nobody asked about was written down anyway"
        );
    }

    /// And a host whose every port went unasked writes no `<ports>` at all,
    /// rather than an empty one.
    #[test]
    fn a_host_with_nothing_probed_writes_no_ports_element() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
        host.set_status(HostStatus::Up);
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Unasked));

        assert!(!export(&[host]).contains("<ports>"));
    }

    /// A multi-homed host comes back keyed by the address it went out under.
    ///
    /// Nmap has no attribute for which address is the host's, so a reader takes
    /// the first one in the document, and a writer emitting them in the set's
    /// own ascending order would re-key the host. One keyed by `203.0.113.10`
    /// that also held `198.51.100.4` would come back keyed by `198.51.100.4`, so
    /// a scan exported here and read again would compare against its own source
    /// as one host removed and one added.
    #[cfg(feature = "import-nmap")]
    #[test]
    fn a_multi_homed_host_keeps_the_address_it_is_keyed_by() {
        use crate::import::report::ReportReader;
        use crate::import::report::nmap::NmapXmlReportReader;
        use std::net::{IpAddr, Ipv4Addr};

        let keyed = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let lower = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));

        let mut host = Host::new(keyed);
        host.add_ip(lower);
        assert_eq!(
            host.primary_ip(),
            keyed,
            "two addresses of one family rank alike, so the first seen leads"
        );

        let report = ScanReport::recorded("zond", Vec::new(), [host]);
        let mut document = Vec::new();
        NmapXmlExporter::new(ExportOptions::new())
            .export(&report, &mut document)
            .expect("the report exports");

        let restored = NmapXmlReportReader::default()
            .read(&mut std::io::Cursor::new(document))
            .expect("this crate's own document reads back");

        let host = restored.hosts().next().expect("the host survived");
        assert_eq!(
            host.primary_ip(),
            keyed,
            "the round trip re-keyed the host onto its other address"
        );
        assert!(host.ips().contains(&lower), "and kept the other one");
    }

    /// Nmap has three host states where this engine has four, and a filtered
    /// host is unambiguously up. Exporting it `down` would be a false negative
    /// in somebody else's tracker.
    #[test]
    fn a_filtered_host_is_exported_as_up_because_that_is_what_it_is() {
        assert_eq!(host_state(HostStatus::Filtered), "up");
        assert_eq!(host_state(HostStatus::Up), "up");
        assert_eq!(host_state(HostStatus::Down), "down");
        assert_eq!(host_state(HostStatus::Unknown), "unknown");
    }

    /// The escaping half of putting attacker-controlled text in an attribute.
    #[test]
    fn the_five_meaningful_characters_are_escaped() {
        let escaped = Attr(r#"<a href="x">&'</a>"#).to_string();

        assert_eq!(escaped, "&lt;a href=&quot;x&quot;&gt;&amp;&apos;&lt;/a&gt;");
    }

    /// The half that has no escape. A numeric reference to a forbidden control
    /// character is as illegal as the character, so a banner carrying one has to
    /// lose it - and a document that kept it would not open at all.
    #[test]
    fn characters_xml_cannot_carry_are_dropped_rather_than_referenced() {
        let banner = "OpenSSH\u{0}\u{1}\u{1f} 9.6\u{202e}drowssap";
        let escaped = Attr(banner).to_string();

        assert_eq!(escaped, "OpenSSH 9.6drowssap");
        assert!(!escaped.contains('&'), "no reference was invented for them");

        // The three C0 characters XML does allow survive, because they are
        // ordinary whitespace and a banner may legitimately contain them. They
        // survive as references, since a parser turns each raw one inside an
        // attribute value into a space.
        assert_eq!(Attr("a\tb\nc\rd").to_string(), "a&#x9;b&#xa;c&#xd;d");
    }

    /// Every attribute nmap's DTD marks `#REQUIRED` has to be present on every
    /// element written, or a validating consumer rejects the document. `line`
    /// on `osmatch` is the one easiest to miss without running nmap's own DTD
    /// against the output.
    #[test]
    fn required_attributes_the_dtd_demands_are_present() {
        let document = render();

        for required in [
            r#"<nmaprun scanner="#,
            r#" version="#,
            r#" xmloutputversion="#,
            r#"<status state="#,
            r#" reason="#,
            r#"<address addr="#,
            r#" addrtype="#,
            r#"<port protocol="#,
            r#" portid="#,
            r#"<hosts up="#,
        ] {
            assert!(
                document.contains(required),
                "the document is missing {required:?}, which the DTD requires"
            );
        }

        // `osmatch` carries a line number into `nmap-os-db`. This engine has no
        // such database and says so with 0, rather than omitting an attribute
        // the DTD marks required.
        if document.contains("<osmatch ") {
            assert!(document.contains(r#" line="0">"#));
        }
        // And an OS class names its vendor and family, both required, and its
        // accuracy.
        for class in document
            .lines()
            .filter(|line| line.starts_with("<osclass "))
        {
            for required in [" vendor=", " osfamily=", " accuracy="] {
                assert!(class.contains(required), "{class} lacks {required}");
            }
        }
    }

    /// A discovery sweep finds hosts and no ports at all. The document still
    /// has to be a document - an exporter that only works on port scans is half
    /// an exporter.
    #[test]
    fn a_report_with_no_ports_still_produces_a_whole_document() {
        let document = render();

        assert!(
            document.contains(r#"<host starttime="#),
            "the fixture's portless host is missing"
        );
        assert!(document.contains("</nmaprun>"));

        // A host with no ports gets no `<ports>` element rather than an empty
        // one, which is what nmap does and what the DTD's content model allows.
        // `skip(1)` drops everything before the first host, which is the
        // document preamble and would otherwise match "has no ports" trivially.
        let portless = document
            .split("<host ")
            .skip(1)
            .find(|section| !section.contains("<ports>"))
            .expect("the fixture has a host with no ports");
        assert!(portless.contains("<status state="));
    }

    /// Redaction is an export-time policy and this format is not exempt from
    /// it. A report handed to a third party through an ingest pipeline is
    /// exactly the case the policy exists for.
    #[test]
    fn redaction_applies_to_this_format_like_any_other() {
        let mut out = Vec::new();
        NmapXmlExporter::new(
            ExportOptions::new().with_redaction(crate::export::Redaction::Standard),
        )
        .export(&fixture::report(), &mut out)
        .expect("exports");
        let document = String::from_utf8(out).expect("UTF-8");

        assert!(
            document.contains(r#"addrtype="mac""#),
            "the fixture has a hardware address to mask"
        );
        assert!(
            !document.contains("2c:cf:67:00:00:01"),
            "an unmasked hardware address survived redaction"
        );
        assert!(
            document.contains("2c:cf:67:XX:XX:XX"),
            "the vendor half has to survive, which is the point of the policy"
        );
    }

    /// A confidence percentage has to land on nmap's 1-to-10 scale without ever
    /// reaching 0, which is not a value that scale has.
    #[test]
    fn service_confidence_lands_on_nmaps_scale() {
        assert_eq!(nmap_confidence(100), 10);
        assert_eq!(nmap_confidence(85), 8);
        assert_eq!(nmap_confidence(50), 5);
        assert_eq!(nmap_confidence(255), 10, "and stops at 10");
        assert_eq!(
            nmap_confidence(0),
            TABLE_CONFIDENCE,
            "a port-number lookup is what nmap spells 3, not the weakest identification"
        );
    }

    /// A guess and an identification must not read alike, or every consumer of
    /// this document is told a thousand closed ports were interrogated.
    #[test]
    fn a_port_number_label_is_written_as_the_lookup_it_is() {
        use crate::model::port::{Port, PortState, Protocol, Service};

        let mut out = Vec::new();
        write_port(
            &mut out,
            &Port::new(80, Protocol::Tcp, PortState::Closed).with_service(Service::new("http", 0)),
        )
        .expect("writing to a vector");
        let inferred = String::from_utf8(out).expect("UTF-8");
        assert!(inferred.contains(r#"method="table""#), "{inferred}");

        let mut out = Vec::new();
        write_port(
            &mut out,
            &Port::new(80, Protocol::Tcp, PortState::Open).with_service(Service::new("http", 100)),
        )
        .expect("writing to a vector");
        let probed = String::from_utf8(out).expect("UTF-8");
        assert!(probed.contains(r#"method="probed""#), "{probed}");
    }

    /// Every attacker-controlled string reaches the document escaped.
    ///
    /// The companion to the per-character test above, and the one that matters
    /// for a format somebody else parses: an unescaped `<` from a scanned host's
    /// banner does not merely look wrong, it ends the element it is inside and
    /// hands the rest of the report to whoever wrote the banner. A consumer
    /// ingesting this XML into DefectDojo or Metasploit parses whatever results.
    ///
    /// It covers fields nobody has added yet, which the per-character test
    /// cannot: any new string written without the escaper fails this the moment
    /// the fixture carries it.
    #[test]
    fn no_field_of_a_hostile_report_reaches_the_document_unescaped() {
        let mut out = Vec::new();
        NmapXmlExporter::new(ExportOptions::new())
            .export(&fixture::hostile(), &mut out)
            .expect("the document renders");
        let document = String::from_utf8(out).expect("utf-8");

        assert!(
            document.contains("&lt;script&gt;"),
            "the payload should be present, escaped - otherwise this proves \
             nothing about a document that simply dropped it"
        );
        assert!(
            !document.contains("<script>"),
            "a scanned host's banner opened an element in the report"
        );
        assert!(
            !document.contains(fixture::HOSTILE),
            "the payload survived intact somewhere in the document"
        );
    }
}
