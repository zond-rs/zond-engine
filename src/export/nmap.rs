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
//! unconditionally.
//!
//! The second has no escape. XML 1.0 forbids most C0 control characters from a
//! document at all, and forbids a numeric character reference to one just as
//! firmly, so `&#1;` is not a way out. A banner containing a `0x01` cannot be
//! represented, and emitting it raw produces a file no parser downstream will
//! open. Those are dropped, along with the bidirectional formatting characters,
//! which reorder the text around them and would let a hostname make a report
//! display one thing and mean another.

use std::fmt::{self, Write as _};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::export::schema::{ENGINE_NAME, protocol_name, reference_text, severity_name};
use crate::export::{ExportError, ExportOptions, Exporter};
use crate::model::finding::Finding;
use crate::model::host::{Host, HostStatus};
use crate::model::port::{Port, PortState, Protocol};
use crate::model::technique::TcpScanTechnique;
use crate::report::{ScanPhase, ScanReport};
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

        let summary = report.summary();
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
                summary.hosts_total, summary.hosts_alive
            )),
            if report.is_partial() {
                "error"
            } else {
                "success"
            },
        )?;
        writeln!(
            out,
            r#"<hosts up="{}" down="{}" total="{}"/>"#,
            summary.hosts_alive,
            summary.hosts_total.saturating_sub(summary.hosts_alive),
            summary.hosts_total,
        )?;
        writeln!(out, "</runstats>")?;
        writeln!(out, "</nmaprun>")?;

        Ok(())
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
fn write_exclusion_note(out: &mut dyn Write, report: &ScanReport) -> Result<(), ExportError> {
    let mut excluded: Vec<String> = Vec::new();
    for phase in report.phases() {
        for range in phase.targets().excluded() {
            let text = format!("{}-{}", range.start_addr(), range.end_addr());
            if !excluded.contains(&text) {
                excluded.push(text);
            }
        }
    }

    if excluded.is_empty() {
        return Ok(());
    }

    // Rendered from addresses rather than anything a caller wrote, so no
    // attacker-controlled text reaches this line and `--` cannot appear in it
    // to close the comment early.
    writeln!(
        out,
        "<!-- zond: excluded by policy, not scanned: {} -->",
        excluded.join(", ")
    )?;

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

    for protocol in [Protocol::Tcp, Protocol::Udp] {
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
/// A UDP scan is `udp` whatever the TCP technique was, and an unprivileged phase
/// is `connect` for the same reason nmap's is: no raw segment went out, so
/// naming the technique would describe a probe that was never sent.
fn scan_type(phase: &ScanPhase, protocol: Protocol) -> &'static str {
    if protocol == Protocol::Udp {
        return "udp";
    }
    // Only where the phase is known to have been unprivileged. A phase this
    // engine did not measure keeps whatever technique its own document named.
    if phase.privilege() == Some(Privilege::Connect) {
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
        Attr(status_reason(host.status())),
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

    if let Some(hostname) = host.hostname() {
        writeln!(out, "<hostnames>")?;
        writeln!(
            out,
            r#"<hostname name="{}" type="PTR"/>"#,
            Attr(&redaction.hostname(hostname)),
        )?;
        writeln!(out, "</hostnames>")?;
    }

    if host.port_count() > 0 {
        writeln!(out, "<ports>")?;
        for port in host.ports() {
            write_port(out, port)?;
        }
        writeln!(out, "</ports>")?;
    }

    if let Some(os) = host.os() {
        writeln!(out, "<os>")?;
        // `line` is required by nmap's DTD and names the row in `nmap-os-db`
        // a match came from. This engine has no such database, and 0 is not a
        // line number.
        writeln!(
            out,
            r#"<osmatch name="{}" accuracy="{}" line="0"/>"#,
            Attr(os.name()),
            os.accuracy(),
        )?;
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

/// Writes one `<port>` element.
fn write_port(out: &mut dyn Write, port: &Port) -> Result<(), ExportError> {
    writeln!(
        out,
        r#"<port protocol="{}" portid="{}">"#,
        transport(port.protocol()),
        port.number(),
    )?;
    writeln!(
        out,
        r#"<state state="{}" reason="{}" reason_ttl="0"/>"#,
        port_state(port.state()),
        Attr(port_reason(port.state())),
    )?;

    if let Some(service) = port.service() {
        write!(out, r#"<service name="{}""#, Attr(service.name()))?;
        if let Some(product) = service.product() {
            write!(out, r#" product="{}""#, Attr(product))?;
        }
        if let Some(version) = service.version() {
            write!(out, r#" version="{}""#, Attr(version))?;
        }
        if let Some(extrainfo) = service.extrainfo() {
            write!(out, r#" extrainfo="{}""#, Attr(extrainfo))?;
        }
        // `probed` is nmap's word for a service identified by talking to the
        // port, `table` for one read out of a port-number list. Every classified
        // port is seeded with a port-number label, so writing those as `probed`
        // would claim a thousand closed ports had been interrogated.
        writeln!(
            out,
            r#" method="{}" conf="{}"/>"#,
            if service.is_inferred() {
                "table"
            } else {
                "probed"
            },
            nmap_confidence(service.confidence()),
        )?;
    }

    // `<script>` follows `<service>` in nmap's DTD for a `<port>`.
    write_finding_scripts(out, port.findings())?;

    writeln!(out, "</port>")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// This engine's port states in nmap's spelling.
///
/// An exhaustive match, so a new state cannot be added without somebody deciding
/// what this format calls it. All six correspond exactly: they are the six states
/// a probe can distinguish.
fn port_state(state: PortState) -> &'static str {
    match state {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
        PortState::Unfiltered => "unfiltered",
        PortState::OpenFiltered => "open|filtered",
        PortState::ClosedFiltered => "closed|filtered",
    }
}

/// What nmap would have written as the evidence for a state.
///
/// Nmap's `reason` names the packet that decided a state. This engine records its
/// evidence per host rather than per port, so these say only as much as is
/// certainly true rather than naming a packet nobody saw.
fn port_reason(state: PortState) -> &'static str {
    match state {
        PortState::Open => "syn-ack",
        PortState::Closed => "reset",
        PortState::Filtered
        | PortState::Unfiltered
        | PortState::OpenFiltered
        | PortState::ClosedFiltered => "no-response",
    }
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

/// The evidence behind a host's status, in as much of nmap's vocabulary as is
/// honest.
fn status_reason(status: HostStatus) -> &'static str {
    match status {
        HostStatus::Up => "echo-reply",
        // Nmap has no reason string for this because it has no such state. The
        // word is this engine's and says what happened.
        HostStatus::Filtered => "probes-filtered",
        HostStatus::Down => "no-response",
        HostStatus::Unknown => "unknown-response",
    }
}

/// A transport in nmap's spelling.
fn transport(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
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

    fn render() -> String {
        let mut out = Vec::new();
        NmapXmlExporter::new(ExportOptions::new())
            .export(&fixture::report(), &mut out)
            .expect("the fixture exports");
        String::from_utf8(out).expect("the document is UTF-8")
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

    /// Every state has a name in this vocabulary and the six correspond
    /// exactly, so a document is never less specific about a port than the scan
    /// was.
    #[test]
    fn every_port_state_maps_to_a_state_nmap_defines() {
        const NMAP_STATES: [&str; 6] = [
            "open",
            "closed",
            "filtered",
            "unfiltered",
            "open|filtered",
            "closed|filtered",
        ];

        for state in [
            PortState::Open,
            PortState::Closed,
            PortState::Filtered,
            PortState::Unfiltered,
            PortState::OpenFiltered,
            PortState::ClosedFiltered,
        ] {
            assert!(
                NMAP_STATES.contains(&port_state(state)),
                "{state:?} maps to '{}', which nmap does not define",
                port_state(state)
            );
        }
    }

    /// A multi-homed host comes back keyed by the address it went out under.
    ///
    /// It once did not. Nmap has no attribute for which address is the host's,
    /// so a reader takes the first one in the document, and this writer emitted
    /// them in the set's own ascending order. A host keyed by `192.168.0.10`
    /// that also held `10.0.0.4` came back keyed by `10.0.0.4`, so a scan
    /// exported here and read again compared against its own source as one host
    /// removed and one added.
    ///
    /// Found by the `import_nmap` fuzz target, on a mangled document whose
    /// broken markup put two addresses under one host.
    #[cfg(feature = "import-nmap")]
    #[test]
    fn a_multi_homed_host_keeps_the_address_it_is_keyed_by() {
        use crate::import::report::ReportReader;
        use crate::import::report::nmap::NmapXmlReportReader;
        use std::net::{IpAddr, Ipv4Addr};

        let keyed = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10));
        let lower = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));

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
        // ordinary whitespace and a banner may legitimately contain them.
        assert_eq!(Attr("a\tb\nc\rd").to_string(), "a\tb\nc\rd");
    }

    /// Every attribute nmap's DTD marks `#REQUIRED` has to be present on every
    /// element written, or a validating consumer rejects the document. `line`
    /// on `osmatch` is the one this missed until nmap's own DTD was run against
    /// the output.
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
            assert!(document.contains(r#" line="0"/>"#));
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
            !document.contains("2c:cf:67:f2:51:e3"),
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
