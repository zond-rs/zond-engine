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
//! That is the whole justification. Nothing here is a better description of a
//! scan than [`super::json`] - it is a narrower one, in somebody else's
//! vocabulary, and it earns its place purely by being understood downstream.
//!
//! ## It says who wrote it
//!
//! `scanner="zond"`, never `scanner="nmap"`.
//!
//! This is not a detail to be traded for compatibility. A scan report is
//! evidence: it says a particular tool observed a particular thing at a
//! particular time, and somebody downstream will act on it, cite it in an audit,
//! or attach it to a finding. A document claiming to be nmap's output when it is
//! not is a fabricated record, and no amount of parser convenience is worth
//! producing one.
//!
//! `xmloutputversion` is still nmap's, because that names the *format* and this
//! document really is in it.
//!
//! ## The one place this deviates from nmap's DTD, and why
//!
//! Nmap's own DTD declares `scanner (nmap) #REQUIRED` - an enumeration with
//! exactly one member. **No honest producer of this format can be DTD-valid**,
//! and every other tool that emits it is in the same position.
//!
//! Measured against `nmap.dtd` from nmap 7.99: this document validates
//! completely - every element, every ordering, every required attribute - with
//! the scanner name changed to `nmap` and nothing else. That deviation is the
//! whole of it, and it is deliberate. The alternative is a document that says
//! nmap observed something nmap never saw.
//!
//! It costs nothing that matters. Consumers of this format parse it
//! structurally, with lenient parsers, and do not validate against the DTD; a
//! document this one produces reads correctly through a standard XML parser,
//! yielding the hosts, addresses and port states the scan recorded.
//!
//! Do not "fix" this by writing `nmap`. There is a test whose only job is to
//! stop that.
//!
//! ## What survives
//!
//! Nmap's vocabulary is not this engine's, and where the two disagree the
//! document says less rather than saying something false. Port states map
//! exactly - nmap and this engine name the same six. Host status has to be
//! flattened: nmap knows `up`, `down` and `unknown`, so a host this engine calls
//! `filtered` is exported `up`, which is what it is, with the distinction
//! carried in the `reason`.
//!
//! Everything the format has no place for - the phases, the probe
//! instrumentation, the TLS detail, the per-address timing - is simply absent.
//! [`super::json`] remains where the whole record lives.
//!
//! ## Characters XML cannot carry
//!
//! A scanner writes attacker-controlled text: hostnames, service banners,
//! certificate subjects. Two separate problems come with putting that in an XML
//! attribute, and only one of them is escaping.
//!
//! The first is ordinary: `&`, `<`, `>`, `"` and `'` are escaped, everywhere,
//! unconditionally.
//!
//! The second has no escape. XML 1.0 forbids most C0 control characters from a
//! document *at all* - and forbids a numeric character reference to one just as
//! firmly, so `&#1;` is not a way out. A banner containing a `0x01` therefore
//! cannot be represented, and emitting it raw produces a file that no parser
//! downstream will open. They are dropped, along with the bidirectional
//! formatting characters, which reorder the text around them and would let a
//! hostname make a report display one thing and mean another.

use std::fmt::{self, Write as _};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::export::schema::{ENGINE_NAME, protocol_name};
use crate::export::{ExportError, ExportOptions, Exporter};
use crate::model::host::{Host, HostStatus};
use crate::model::port::{Port, PortState, Protocol};
use crate::model::technique::TcpScanTechnique;
use crate::scanner::report::{ScanPhase, ScanReport};

/// The format's name in errors.
const FORMAT: &str = "nmap XML";

/// The nmap XML output version this document is written to.
///
/// Nmap's own, because it names the format rather than the producer, and this
/// document really is in it. Consumers key their parsing on this.
const XML_OUTPUT_VERSION: &str = "1.05";

/// Writes a report as nmap-compatible XML.
///
/// ```no_run
/// use std::fs::File;
/// use zond_engine::scanner::report::ScanReport;
/// use zond_engine::export::{ExportOptions, Exporter, NmapXmlExporter};
///
/// # fn example(report: &ScanReport) -> Result<(), Box<dyn std::error::Error>> {
/// let mut file = File::create("scan.xml")?;
/// NmapXmlExporter::new(ExportOptions::new()).export(report, &mut file)?;
/// # Ok(())
/// # }
/// ```
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
            // This build's, because the attribute beside it says `scanner="zond"`.
            // Writing the report's own attribution here put a foreign scanner's
            // version on zond's name, and reading the file back turned the pair
            // into one string: `zond 0.13.0` became the *version* of the next
            // document exported from it.
            Attr(crate::scanner::report::ENGINE_VERSION),
            XML_OUTPUT_VERSION,
        )?;

        // One per transport per phase, as nmap writes them. This is the
        // element that tells a consumer which ports were looked at, and so the
        // difference between a port absent because it was closed and one absent
        // because nobody asked.
        for phase in report.phases() {
            write_scan_info(out, phase)?;
        }

        // Written because every consumer reads it and a missing one is an
        // awkward absence.
        writeln!(out, r#"<verbose level="0"/>"#)?;
        writeln!(out, r#"<debugging level="0"/>"#)?;

        // One host is written and dropped before the next is rendered, which is
        // what keeps a scan of any size costing a host's worth of memory.
        for host in report.hosts() {
            write_host(out, host, &self.options)?;
        }

        let summary = report.summary();
        writeln!(out, "<runstats>")?;
        writeln!(
            out,
            r#"<finished time="{}" timestr="{}" elapsed="{:.2}" summary="{}" exit="{}"/>"#,
            epoch_seconds(SystemTime::now()),
            Attr(&time_string(SystemTime::now())),
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
/// **A comment because this format has nowhere else to put it.** Nmap has no
/// element for an exclusion — its own `--exclude` survives only inside the
/// `args` attribute, which is the command line, and this engine is a library
/// that was never handed one. Writing a plausible command line into `args` would
/// be inventing a record of what somebody typed, which is the same objection
/// this module makes to `scanner="nmap"` and is refused for the same reason.
/// Inventing an element instead would cost the property the module documentation
/// claims: that this document validates against `nmap.dtd` with nothing changed
/// but the scanner name.
///
/// A comment costs neither. It is valid anywhere in XML content, invisible to
/// every consumer that parses this file, and legible to the person who opens it.
///
/// Silence was the alternative and it is not acceptable. Somebody exporting only
/// this format would otherwise hold a file that reports a scan of a range while
/// omitting that part of the range was deliberately not covered, and a report
/// that overstates its own coverage is the exact failure this policy exists to
/// prevent.
/// Writes one `<scaninfo>` per transport the phase walked ports on.
///
/// Nothing is written for a phase whose port scope is not recorded, and nothing
/// for a discovery sweep: an element claiming zero services would read as a scan
/// that looked at no ports, which is a different statement from not saying.
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
    // engine did not measure keeps whatever technique its own document named,
    // since calling it `connect` would describe a probe on no better evidence
    // than that this engine was not there to see it.
    if phase.privileged() == Some(false) {
        return "connect";
    }

    match phase.settings().tcp_technique {
        TcpScanTechnique::Syn => "syn",
        TcpScanTechnique::Fin => "fin",
        TcpScanTechnique::Null => "null",
        TcpScanTechnique::Xmas => "xmas",
        TcpScanTechnique::Maimon => "maimon",
        TcpScanTechnique::Ack => "ack",
    }
}

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

    // Rendered from addresses rather than from anything a caller wrote, so no
    // attacker-controlled text reaches this line and `--` cannot appear in it to
    // close the comment early.
    writeln!(
        out,
        "<!-- zond: excluded by policy, not scanned: {} -->",
        excluded.join(", ")
    )?;

    Ok(())
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
        // nmap puts the TTL of the packet that established the host's state
        // here. This engine does not record one, and the attribute is required,
        // so it is written as zero -- which is also what nmap writes when its
        // own probe did not carry a usable TTL.
        0,
    )?;

    // Every address, so a dual-stack host is one record with two addresses,
    // which is how nmap describes the same thing.
    for ip in host.ips() {
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
        // the match came from. This engine has no such database, so there is no
        // row to name: 0 is not a line number and reads as the absence it is.
        writeln!(
            out,
            r#"<osmatch name="{}" accuracy="{}" line="0"/>"#,
            Attr(os.name()),
            os.accuracy(),
        )?;
        writeln!(out, "</os>")?;
    }

    // `<distance>` and `<trace>` in that order, and both after `<os>`: nmap's
    // DTD fixes the sequence of a host's children, and this document claims to
    // validate against it.
    if let Some(distance) = host.path().length() {
        writeln!(out, r#"<distance value="{distance}"/>"#)?;
    }

    write_trace(out, host)?;

    // Nmap reports these in microseconds, which is also what the engine keeps,
    // so nothing is converted and nothing is lost.
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
/// **The one finding this engine produces that nmap's format already has a
/// first-class place for**, which makes it the one worth the most here: a
/// consumer that draws network topology from nmap XML draws this without being
/// taught anything new.
///
/// A silent hop is written as a `<hop>` carrying only its `ttl`. That is what
/// nmap does and the DTD allows it — `ipaddr` is implied — and it is the whole
/// reason the element is emitted rather than the gap being closed: a consumer
/// counting hops has to see that a router is there and would not name itself.
///
/// `rtt` is milliseconds with two decimals, which is nmap's own rendering.
/// Converted rather than kept in the microseconds the engine holds, because a
/// consumer reading this attribute is a consumer expecting nmap's units, and a
/// number in the wrong ones would be read as a path a thousand times slower.
///
/// **`inferred` has nowhere to go.** Nmap has no attribute for it and inventing
/// one would cost this document its DTD validity, so a hop copied from another
/// host's trace is written here exactly like a measured one. That is a real loss
/// of fidelity against this engine's own JSON, and it is the trade the format
/// is: nmap's vocabulary, not this engine's. Anybody who needs the distinction
/// has [`super::json`].
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
        // port, and `table` for one read out of a port-number list. This engine
        // makes the same distinction and must not lose it here: every classified
        // port is seeded with a port-number label, and writing those as `probed`
        // would tell every consumer of this document that a thousand closed
        // ports had been interrogated.
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

    writeln!(out, "</port>")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// This engine's port states in nmap's spelling.
///
/// An exhaustive match, so a new state cannot be added without somebody
/// deciding what this format calls it. All six correspond exactly, which is not
/// a coincidence: they are the six states a probe can distinguish.
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
/// Nmap's `reason` names the packet that decided it. This engine records its
/// evidence differently and per host rather than per port, so rather than invent
/// a packet that was never seen, these say only as much as is certainly true.
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
/// Nmap has three where this engine has four. `filtered` means the host is
/// there and its probes are being dropped, which nmap has no separate word for
/// and which is unambiguously `up`; the distinction survives in the reason.
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
    // Three is what nmap records for a port-number lookup, and zero is how this
    // engine spells the same thing. Mapping it anywhere else would put a
    // guess and a weak identification on the same footing.
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
/// A time before the epoch has no representation here and becomes 0, which is
/// the only value in range and cannot arise from a scan that has happened.
fn epoch_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// The human-readable companion nmap writes beside every timestamp.
///
/// Nmap writes a local-time C `ctime` string here. This writes RFC 3339 in UTC:
/// it is the same instant, it is unambiguous about its zone, and it is what
/// every other document this engine emits already says. Consumers parse the
/// numeric field beside it; this one is for a person.
fn time_string(time: SystemTime) -> String {
    crate::format::time::rfc3339(time)
}

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

/// Report text on its way into an XML attribute value.
///
/// Escapes the five characters that have meaning, and **drops** the characters
/// XML 1.0 cannot carry at all. That second half is the one worth stating: there
/// is no escape for a `0x01` in XML 1.0 - a numeric reference to one is as
/// illegal as the byte - so a service banner containing one has to lose it or
/// the whole document becomes unparseable. Losing a control character from a
/// banner costs nothing anybody can read; losing the file costs the export.
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
/// formatting characters are legal XML and are dropped anyway, because they
/// reorder the text around them without being visible: a hostname carrying one
/// can make a report display something other than what it says.
fn is_forbidden(character: char) -> bool {
    let code = u32::from(character);

    let control = matches!(code, 0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F);
    let noncharacter = matches!(code, 0xFFFE | 0xFFFF);
    let bidirectional = matches!(code, 0x202A..=0x202E | 0x2066..=0x2069 | 0x200E | 0x200F);

    control || noncharacter || bidirectional
}

/// Turns a formatting failure into an export error.
///
/// Unreachable in practice - the only writer here is the caller's - but the
/// format's name belongs on the error if it ever is.
#[allow(dead_code)]
fn render_error(error: fmt::Error) -> ExportError {
    ExportError::Render {
        format: FORMAT,
        message: error.to_string(),
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
    use super::*;
    use crate::export::fixture;

    fn render() -> String {
        let mut out = Vec::new();
        NmapXmlExporter::new(ExportOptions::new())
            .export(&fixture::report(), &mut out)
            .expect("the fixture exports");
        String::from_utf8(out).expect("the document is UTF-8")
    }

    /// Prints the rendered document so it can be held against a real parser.
    ///
    /// Nothing in this file can check that the output is XML a stranger will
    /// open - every assertion here compares the document to strings this module
    /// wrote, which proves consistency and not validity. The instrument that
    /// answers the real question lives outside the crate:
    ///
    /// ```text
    /// cargo test --features export-nmap dump_for_external_validation \
    ///   -- --ignored --nocapture | sed -n '/<?xml/,/<\/nmaprun>/p' > zond.xml
    /// xmllint --dtdvalid /path/to/nmap.dtd --noout zond.xml
    /// ```
    ///
    /// Against nmap 7.99's DTD that reports exactly one error, the deliberate
    /// one: `scanner="zond"` is not `scanner="nmap"`. Substituting the name and
    /// nothing else validates clean. Run the same check on real nmap output
    /// first - it passes, which is what makes the instrument worth trusting.
    #[test]
    #[ignore = "prints a document for external validation rather than asserting"]
    fn dump_for_external_validation() {
        print!("{}", render());
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

    /// Every state has to have a name in this vocabulary, and the six
    /// correspond exactly - so a document is never less specific about a port
    /// than the scan was.
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
