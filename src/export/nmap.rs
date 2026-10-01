// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Nmap-compatible XML export
//!
//! DefectDojo, Metasploit, Faraday and Dradis all ingest nmap's XML, so this
//! is the file that puts a scan into an existing pipeline. It is a narrower
//! description than [`super::json`], in nmap's vocabulary.
//!
//! ## It says who wrote it
//!
//! The document carries `scanner="zond"`. A scan report is evidence that
//! somebody downstream will act on or cite, and a document claiming to be
//! nmap's output would be a fabricated record. `xmloutputversion` is nmap's,
//! since it names the format.
//!
//! ## The one deviation from nmap's DTD
//!
//! Nmap's DTD declares `scanner (nmap) #REQUIRED`, an enumeration with one
//! member, so no other producer of this format can be DTD-valid. Against
//! `nmap.dtd` from nmap 7.99 this document validates completely, every element,
//! ordering and required attribute, once the scanner name is changed to `nmap`.
//! Consumers parse the format structurally with lenient parsers and do not
//! validate against the DTD. A test fails if `nmap` is written here.
//!
//! ## What survives
//!
//! Where nmap's vocabulary and this engine's disagree, the document says less.
//! Port states map one to one except nmap's `filtered`, which covers both
//! blocked and no reply, told apart in the `reason`. Nmap's host status knows
//! only `up`, `down` and `unknown`, so a host this engine calls blocked is
//! exported `up`, with the distinction in the `reason`.
//!
//! The phases, probe instrumentation, TLS detail and per-address timing have no
//! place in the format and are absent. [`super::json`] holds the whole record.
//!
//! ## Characters XML cannot carry
//!
//! Hostnames, service banners and certificate subjects are attacker-controlled.
//! `&`, `<`, `>`, `"` and `'` are escaped everywhere. So are tab, line feed and
//! carriage return: XML allows them raw, but parsers normalise them to a space
//! inside an attribute value, so nmap writes them as character references and
//! so does this.
//!
//! XML 1.0 forbids most C0 control characters, and numeric character
//! references to them too, so a banner containing `0x01` cannot be represented
//! and raw output would be a file no parser opens. Those are dropped, along with
//! the bidirectional formatting characters, which reorder the text around them
//! and would let a hostname make a report display one thing and mean another.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::export::schema::{ENGINE_NAME, protocol_name, reference_text, severity_name};
use crate::export::{ExportError, ExportOptions, Exporter, HostRedaction};
use crate::fingerprint::Tunnel;
use crate::model::finding::Finding;
use crate::model::host::{
    EvidenceSource, Host, HostStatus, IpProtocolState, NameKind, StatusProtocol, StatusReason,
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
/// Nmap's own, since it names the format. Consumers key their parsing on it.
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
                r#"<nmaprun scanner="{}" args="" start="{}" startstr="{}" "#,
                r#"version="{}" xmloutputversion="{}">"#
            ),
            crate::format::NMAP_SCANNER,
            started,
            Attr(&time_string(report.started_at())),
            // This build's version, to match `scanner="zond"`; an imported
            // report's own attribution may name another scanner.
            Attr(crate::report::ENGINE_VERSION),
            XML_OUTPUT_VERSION,
        )?;

        // One per transport per phase, as nmap writes them. It tells a consumer
        // which ports were looked at, so an absent port reads as closed only if
        // it was asked.
        for phase in report.phases() {
            write_scan_info(out, phase)?;
        }

        writeln!(out, r#"<verbose level="0"/>"#)?;
        writeln!(out, r#"<debugging level="0"/>"#)?;

        for host in report.hosts() {
            write_host(out, host, &self.options)?;
        }

        let counts = HostCounts::of(report);
        // One reading, so `time` and `timestr` cannot straddle a second.
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
            // Only a failed strategy is an error, as in nmap's runs. A host left
            // early or a port left unasked is part of a successful run, and an
            // unwritable journal costs no coverage; see
            // `ScannerFailure::narrows_coverage`.
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
/// Nmap counts what it scanned: a sweep of a /24 with thirty hosts answering is
/// 256 addresses, 30 up and 226 down, and the tools reading the document report
/// coverage from these.
///
/// The addresses scanned are every range a phase walked, after its exclusions,
/// plus every address a recorded host holds, since a host found on a swept link
/// or overheard on the segment was in no named range. A host is up as its
/// `<status>` says, and every scanned address no up host holds is down. A host
/// answering at two addresses is one host up, so `total` can fall short of the
/// addresses scanned; the summary line names both numbers.
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
/// The format has no element for it: nmap keeps its exclusions only in the
/// `args` command line, and a new element would break validity against
/// `nmap.dtd`. A comment is invisible to parsers and legible to a person, and
/// without it a file reporting a scan of a range overstates its coverage.
///
/// The note is the union of every phase's policy, merged as an address set
/// merges it: a shared range is named once and touching ranges read as one. The
/// union is built in one sort, so the cost stays proportional to the policy
/// however many phases repeat it; a blocklist can run to tens of thousands of
/// ranges.
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

    // Rendered from addresses only, so `--` cannot appear and close the comment
    // early.
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
/// Nothing is written for a phase whose port scope is not recorded, or for a
/// discovery sweep: an element claiming zero services would read as a scan that
/// looked at no ports.
fn write_scan_info(out: &mut dyn Write, phase: &ScanPhase) -> Result<(), ExportError> {
    let Some(ports) = phase.targets().ports().ports() else {
        return Ok(());
    };

    for &protocol in Protocol::ALL {
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
/// A UDP scan is `udp` and an SCTP one `sctpinit` whatever the TCP technique.
/// An unprivileged phase is `connect`, as nmap's is, since no raw segment went
/// out. So is a privileged phase that reached every address it covered by
/// connect, as it reaches loopback and this host's own addresses; see
/// [`ScanPhase::reached_by_connect`].
///
/// A phase that reached only some of its addresses by connect names the
/// technique it sent the rest. Readers key on one `<scaninfo>` per transport,
/// so a second one would be dropped or misread; the addresses probed by connect
/// are in the report's own record of the phase.
fn scan_type(phase: &ScanPhase, protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Udp => return "udp",
        // Nmap's name for an INIT scan, the only SCTP scan either performs.
        Protocol::Sctp => return "sctpinit",
        Protocol::Tcp => {}
    }
    // Only where the phase is known to have reached its addresses so; a phase
    // this engine did not measure keeps the technique its own document named.
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
/// False for a phase that recorded no such address or whose scope names none.
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
    let masking = redaction.for_host(host);

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
        // Required: the TTL of the packet that established the host's state.
        // This engine records none, and nmap writes zero for the same absence.
        0,
    )?;

    // Every address, so a dual-stack host is one record, as nmap writes it.
    // The key address leads, since a reader takes the first as the host's;
    // otherwise a re-imported multi-homed host would compare against its source
    // as one host gone and one arrived.
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
        // From the OUI, or by a rule from a reply, which can name the machine
        // too, hence the masking.
        match host.vendor() {
            Some(vendor) => writeln!(
                out,
                r#"<address addr="{}" addrtype="mac" vendor="{}"/>"#,
                Attr(&redaction.mac(&mac)),
                Attr(&masking.text(vendor)),
            )?,
            None => writeln!(
                out,
                r#"<address addr="{}" addrtype="mac"/>"#,
                Attr(&redaction.mac(&mac)),
            )?,
        }
    }

    let stated = stated_hostnames(host);
    if host.hostname().is_some() || !stated.is_empty() {
        writeln!(out, "<hostnames>")?;
        if let Some(hostname) = host.hostname() {
            writeln!(
                out,
                r#"<hostname name="{}" type="PTR"/>"#,
                Attr(&redaction.hostname(hostname)),
            )?;
        }
        for name in stated {
            writeln!(
                out,
                r#"<hostname name="{}" type="user"/>"#,
                Attr(&redaction.hostname(name)),
            )?;
        }
        writeln!(out, "</hostnames>")?;
    }

    write_ip_protocols(out, host)?;

    write_ports(out, host, &masking)?;

    if let Some(os) = host.os() {
        writeln!(out, "<os>")?;
        // `line` is required and names the `nmap-os-db` row a match came from.
        // This engine has no such database; 0 is not a line number.
        writeln!(
            out,
            r#"<osmatch name="{}" accuracy="{}" line="0">"#,
            Attr(&masking.text(os.name())),
            os.accuracy(),
        )?;
        write_os_class(out, os, &masking)?;
        writeln!(out, "</osmatch>")?;
        writeln!(out, "</os>")?;
    }

    // Nmap's DTD fixes the sequence of a host's children: `<distance>` then
    // `<trace>`, both after `<os>`.
    if let Some(distance) = host.path().length() {
        writeln!(out, r#"<distance value="{distance}"/>"#)?;
    }

    // Host-level findings, between `<distance>` and `<trace>`.
    if host.findings().next().is_some() {
        writeln!(out, "<hostscript>")?;
        write_finding_scripts(out, host.findings(), &masking)?;
        writeln!(out, "</hostscript>")?;
    }

    write_trace(out, host)?;

    // Microseconds, as nmap writes them.
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

/// The DNS names a host gave for itself that `<hostnames>` carries beside the
/// one the scan resolved: each [`NameKind::Host`] once, in any case, and none
/// the resolved name already is.
///
/// Readers take `<hostname>` as the machine's DNS name, which these are, stated
/// by its directory or its authentication. NetBIOS names, domains and forests
/// would be misread there and are left to formats with a field for them. They
/// are typed `user`, nmap's type for a name not from a reverse lookup, and the
/// importer reads them back as stated names.
fn stated_hostnames(host: &Host) -> Vec<&str> {
    let mut stated: Vec<&str> = Vec::new();
    for name in host.names().filter(|name| name.kind() == NameKind::Host) {
        let name = name.name();
        let known = host
            .hostname()
            .into_iter()
            .chain(stated.iter().copied())
            .any(|seen| seen.eq_ignore_ascii_case(name));
        if !known {
            stated.push(name);
        }
    }
    stated
}

/// Writes the host's `<ports>`: the ports worth reading one by one, and a
/// summary of the rest.
///
/// A port nobody asked about is left out: nmap's vocabulary has no state for a
/// port no probe was sent to, and any of its six would be a verdict this scan
/// never reached. See `PortState::Unasked`.
///
/// Of the rest, a state held by more than [`LISTED_PER_STATE`] ports is written
/// as nmap writes it: one `<extraports>` with the state and its count, and an
/// `<extrareasons>` per reason and transport naming every port in it. Readers
/// act on every listed port (an exploit search looks up its service name, an
/// importer files it as a service, a stylesheet renders a row), and a
/// full-range scan of one host listed whole is ten megabytes. The ports are
/// still named, so a reader wanting every verdict has it.
///
/// `open` is never summarised, as in nmap: an open port is the finding. Nor is
/// a port with an identified service or a finding, which the summary has no
/// place for.
fn write_ports(
    out: &mut dyn Write,
    host: &Host,
    masking: &HostRedaction,
) -> Result<(), ExportError> {
    let probed: Vec<&Port> = host
        .ports()
        .filter(|port| port_state(port.state()).is_some())
        .collect();
    if probed.is_empty() {
        return Ok(());
    }

    // Keyed by the word written, so the two states nmap calls `filtered` share
    // one summary, as nmap's own do.
    let mut summarised: BTreeMap<&str, Vec<&Port>> = BTreeMap::new();
    for port in probed.iter().copied().filter(|port| is_summarisable(port)) {
        if let Some(name) = port_state(port.state()) {
            summarised.entry(name).or_default().push(port);
        }
    }
    summarised.retain(|_, ports| ports.len() > LISTED_PER_STATE);

    writeln!(out, "<ports>")?;
    for (name, ports) in &summarised {
        write_extra_ports(out, name, ports)?;
    }
    for port in probed {
        let listed = !is_summarisable(port)
            || port_state(port.state()).is_none_or(|name| !summarised.contains_key(name));
        if listed {
            write_port(out, port, masking)?;
        }
    }
    writeln!(out, "</ports>")?;
    Ok(())
}

/// How many ports of one state are listed one by one before the state is
/// summarised instead.
///
/// Nmap's own threshold at its default verbosity.
const LISTED_PER_STATE: usize = 25;

/// Whether a port says nothing a summary cannot: it is not open, and its record
/// holds its state, the packet behind it and at most a port-number label.
///
/// Nmap drops the label for a summarised port too; it is a lookup, and on a
/// closed port an exploit search mistakes it for a service.
fn is_summarisable(port: &Port) -> bool {
    port.state() != PortState::Open
        && port.service().is_none_or(|service| service.is_inferred())
        && port.security().is_none()
        && port.findings().next().is_none()
}

/// Writes one `<extraports>`: a state, how many ports are in it, and which,
/// grouped by the reason each was decided on and its transport.
fn write_extra_ports(out: &mut dyn Write, name: &str, ports: &[&Port]) -> Result<(), ExportError> {
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
/// Ports alternating with another state's make long lists: a host that
/// rate-limits its resets scatters silent ports through closed ones, and thirty
/// thousand isolated numbers are two hundred kilobytes in one attribute, which
/// a reader bounding element size (this engine's own among them) refuses. Nmap's
/// DTD allows any number of `<extrareasons>` per `<extraports>`, so the list is
/// split.
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
/// and long enough that ports in stretches always fit one list.
const MAX_PORT_LIST_BYTES: usize = 8 * 1024;

/// Writes the `<osclass>` beneath a match: the family, vendor, generation and
/// device type, and the CPEs naming the system.
///
/// Importers file a host under its `osfamily`, and vulnerability lookups key on
/// the CPE, which nmap's DTD holds only here.
///
/// Written only once the family is known, which the DTD requires of every class,
/// as it requires a vendor. An unknown vendor is written empty, so the class
/// and its CPEs are still written.
///
/// Every string is read through `masking`, since a rule fills each from the
/// reply.
fn write_os_class(
    out: &mut dyn Write,
    os: &crate::model::host::OsFingerprint,
    masking: &HostRedaction,
) -> Result<(), ExportError> {
    let Some(family) = os.family() else {
        return Ok(());
    };

    write!(
        out,
        r#"<osclass vendor="{}" osfamily="{}""#,
        Attr(&masking.text(os.vendor().unwrap_or_default())),
        Attr(&masking.text(family)),
    )?;
    if let Some(generation) = os.generation() {
        write!(out, r#" osgen="{}""#, Attr(&masking.text(generation)))?;
    }
    if let Some(device) = os.device() {
        write!(out, r#" type="{}""#, Attr(&masking.text(device)))?;
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
    write_cpes(out, os.cpes(), masking)?;
    writeln!(out, "</osclass>")?;
    Ok(())
}

/// Writes one `<cpe>` element per CPE, the form nmap's DTD gives them beneath
/// a service or an OS class, each read through `masking`: a CPE is a template
/// a rule fills from the reply.
fn write_cpes(
    out: &mut dyn Write,
    cpes: &std::collections::BTreeSet<std::sync::Arc<str>>,
    masking: &HostRedaction,
) -> Result<(), ExportError> {
    for cpe in cpes {
        writeln!(out, "<cpe>{}</cpe>", Attr(&masking.text(cpe)))?;
    }
    Ok(())
}

/// Writes the `<trace>` element, when a path was measured.
///
/// A silent hop is a `<hop>` with only its `ttl`, as nmap writes it (`ipaddr`
/// is implied), so a consumer counting hops still sees the router.
///
/// A [withheld](crate::model::host::Hop::is_withheld) hop is written the same
/// way: a `ttl` alone keeps the distance and names nobody. A hop copied from
/// another host's trace is written like a measured one, since nmap has no
/// attribute for it. Both distinctions survive only in [`super::json`].
///
/// `rtt` is milliseconds with two decimals, nmap's own rendering.
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
/// attacker-influenced: the caller writes it through [`Attr`], and parts the
/// host's reply filled are read through `masking`.
fn finding_output(finding: &Finding, masking: &HostRedaction) -> String {
    let mut parts = vec![format!(
        "[{}] {}",
        severity_name(finding.severity()),
        masking.text(finding.title())
    )];
    let references: Vec<String> = finding
        .references()
        .map(|reference| reference_text(reference, masking))
        .collect();
    if !references.is_empty() {
        parts.push(references.join(", "));
    }
    if !finding.excerpt().is_empty() {
        parts.push(masking.excerpt(finding.excerpt().as_str()).into_owned());
    }
    if let Some(remediation) = finding.remediation() {
        parts.push(format!("fix: {}", masking.text(remediation)));
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
    masking: &HostRedaction,
) -> Result<(), ExportError> {
    for finding in findings {
        writeln!(
            out,
            r#"<script id="{}" output="{}"/>"#,
            Attr(finding.detection().id()),
            Attr(&finding_output(finding, masking)),
        )?;
    }
    Ok(())
}

/// Writes the host's IP protocol verdicts, in the shape nmap's own protocol scan
/// writes them.
///
/// Nmap writes a protocol scan as `<port protocol="ip" portid="N">`, reusing the
/// port element for a protocol number, and its readers expect that. The engine's
/// own model keeps the two apart; see [`protocol`](crate::model::host::protocol).
///
/// In a second `<ports>` element after the transport one, as nmap writes it, so
/// 47/ip is not read as the same endpoint as 47/tcp.
///
/// A protocol nobody asked about is left out, as an unasked port is; see
/// [`port_state`].
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
/// The four established states correspond exactly to nmap's.
/// [`Unasked`](IpProtocolState::Unasked) has no spelling, as
/// [`PortState::Unasked`] has none, and the caller filters it out.
fn ip_protocol_state(state: IpProtocolState) -> &'static str {
    match state {
        IpProtocolState::Open => "open",
        IpProtocolState::Closed => "closed",
        IpProtocolState::Blocked => "filtered",
        IpProtocolState::OpenOrNoReply => "open|filtered",
        // Filtered out by `write_ip_protocols`. Spelled out with no wildcard
        // arm, so a new state is a compile error here.
        IpProtocolState::Unasked => "open|filtered",
    }
}

/// What nmap would have written as the evidence for a protocol verdict.
///
/// Three verdicts each come from exactly one message: a protocol unreachable
/// closes a protocol, an administrative prohibition filters one, and silence
/// leaves it open or no reply.
///
/// `open` is reached by an echo reply or by a port unreachable proving the
/// stack took delivery, and the engine does not record which; see
/// [`protocols`](crate::scanner::strategy::protocols). Every nmap token names a
/// specific packet, so this writes `response`, which is not nmap's word.
/// Consumers key on `state`.
fn ip_protocol_reason(state: IpProtocolState) -> &'static str {
    match state {
        IpProtocolState::Closed => "proto-unreach",
        IpProtocolState::Blocked => "admin-prohibited",
        IpProtocolState::Open => "response",
        IpProtocolState::OpenOrNoReply | IpProtocolState::Unasked => "no-response",
    }
}

/// Writes one `<port>` element.
///
/// Writes nothing for a port no probe was sent to, which the format cannot
/// state; the caller filters those out.
fn write_port(
    out: &mut dyn Write,
    port: &Port,
    masking: &HostRedaction,
) -> Result<(), ExportError> {
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
        let label = masking.text(service.name());
        let (name, tunnel) = service_name(&label);
        write!(out, r#"<service name="{}""#, Attr(name))?;
        if let Some(product) = service.product() {
            write!(out, r#" product="{}""#, Attr(&masking.text(product)))?;
        }
        if let Some(version) = service.version() {
            write!(out, r#" version="{}""#, Attr(&masking.text(version)))?;
        }
        if let Some(extrainfo) = service.extrainfo() {
            write!(out, r#" extrainfo="{}""#, Attr(&masking.text(extrainfo)))?;
        }
        if let Some(tunnel) = tunnel {
            write!(out, r#" tunnel="{tunnel}""#)?;
        }
        // `probed` is nmap's word for a service identified by talking to the
        // port, `table` for one read from a port-number list. Every classified
        // port is seeded with a port-number label, which is `table`.
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
            write_cpes(out, service.cpes(), masking)?;
            writeln!(out, "</service>")?;
        }
    }

    // `<script>` follows `<service>` in nmap's DTD for a `<port>`.
    write_finding_scripts(out, port.findings(), masking)?;

    writeln!(out, "</port>")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// This engine's port states in nmap's spelling, and [`None`] for the one that
/// has none.
///
/// An exhaustive match, so a new state needs a decision here. Nmap has six words
/// and this engine eight states. [`Blocked`](PortState::Blocked) and
/// [`NoReply`](PortState::NoReply) are both nmap's `filtered`, told apart in the
/// reason, which [`port_reason`] writes. The rest correspond exactly, except
/// [`PortState::Unasked`]: nmap does not write a port it did not scan, so this
/// answers [`None`] and the caller drops the element.
fn port_state(state: PortState) -> Option<&'static str> {
    Some(match state {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Blocked | PortState::NoReply => "filtered",
        PortState::Reachable => "unfiltered",
        PortState::OpenOrNoReply => "open|filtered",
        PortState::ClosedOrNoReply => "closed|filtered",
        PortState::Unasked => return None,
    })
}

/// The packet that decided a port's state, in nmap's words.
///
/// Read from the packet recorded on the port's
/// [`Discovery`](crate::model::port::discovery::Discovery) when there is one: a
/// UDP port that answered is `udp-response`, a connection the operating system
/// refused `conn-refused`, an open port a window scan read off a reset `reset`.
///
/// Otherwise it falls back to the one packet the state and transport admit:
/// only a SYN/ACK opens a TCP port, a datagram a UDP one and an INIT-ACK an
/// SCTP one; only a reset closes a TCP port or leaves it reachable, a port
/// unreachable closes a UDP one and an ABORT an SCTP one. A blocked port falls
/// back to `dest-unreach`, a refusal with no recorded code. The states silence
/// decides fall back to `no-response`.
///
/// [`None`] for a port no probe was sent to, as with [`port_state`].
fn port_reason(port: &Port) -> Option<&str> {
    port_state(port.state())?;

    if let Some(discovery) = port.discovery() {
        return Some(response_reason(discovery.reason(), port));
    }

    Some(match (port.state(), port.protocol()) {
        (PortState::Open, Protocol::Tcp) => "syn-ack",
        (PortState::Open, Protocol::Udp) => "udp-response",
        (PortState::Open, Protocol::Sctp) => "init-ack",
        (PortState::Closed | PortState::Reachable, Protocol::Tcp) => "reset",
        (PortState::Closed, Protocol::Udp) => "port-unreach",
        (PortState::Closed, Protocol::Sctp) => "abort",
        (PortState::Blocked, _) => "dest-unreach",
        _ => "no-response",
    })
}

/// A recorded response in nmap's reason vocabulary.
///
/// Nmap names an ICMP unreachable by its code, which this engine does not
/// record. Only a port unreachable closes a UDP port, so a closed UDP port's is
/// `port-unreach`; any other is `dest-unreach`, nmap's generic word.
///
/// A response nmap has no word for is written in this engine's own name.
fn response_reason<'a>(response: &'a ScanResponse, port: &Port) -> &'a str {
    match response {
        // Overheard on its way to another peer, but still a SYN/ACK.
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

/// The TTL of the reply that decided a port, or 0 when none was read, as nmap
/// writes the same absence.
fn reason_ttl(port: &Port) -> u8 {
    port.discovery()
        .and_then(|discovery| discovery.ttl())
        .unwrap_or(0)
}

/// This engine's host statuses in nmap's spelling.
///
/// Nmap has three where this engine has four. A blocked host is one a device
/// refused probes to by policy, so something is there and it is written `up`;
/// the reason carries the distinction.
fn host_state(status: HostStatus) -> &'static str {
    match status {
        HostStatus::Up | HostStatus::Blocked => "up",
        HostStatus::Down => "down",
        HostStatus::Unknown => "unknown",
    }
}

/// The evidence behind a host's status, in nmap's words where nmap has one.
///
/// Read from the evidence the host holds, since nmap's reason names the packet
/// that decided the state: a host its neighbour table answered for is
/// `arp-response`, one that answered a ping `echo-reply`. Of several, the most
/// direct by [`host_reason_rank`] is named, so the output does not depend on
/// arrival order.
///
/// A host with no evidence for its status gets `response` if up (not nmap's
/// word) and `no-response` if unknown.
fn status_reason(host: &Host) -> &str {
    let status = host.status();
    if status == HostStatus::Blocked {
        // Nmap has no such state, so the word is this engine's.
        return "probes-blocked";
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
        HostStatus::Blocked | HostStatus::Unknown => "no-response",
    }
}

/// How directly a piece of evidence establishes `status`, lowest first, or
/// [`None`] for evidence that does not establish it at all.
///
/// A host keeps every reason it was given, so one that is up may also hold an
/// unreachable a router sent earlier; only evidence the host sent for itself
/// says it is up. The neighbour table ranks first, as nmap names it on a local
/// segment, then the probes nmap's discovery sends, in its order, then the
/// rest.
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
        // Only an unreachable puts a host down, and its sender is in the path.
        HostStatus::Down => (reason.protocol == StatusProtocol::IcmpUnreachable).then_some(0),
        HostStatus::Up | HostStatus::Blocked | HostStatus::Unknown => None,
    }
}

/// One piece of host evidence in nmap's reason vocabulary.
///
/// TCP and SCTP evidence may be an acceptance or a reset, recorded only in
/// prose, so the word names the transport: `tcp-response` is nmap's word for an
/// unspecified TCP reply, and `sctp-response` follows its shape. A DHCP server
/// overheard on the segment has no nmap word and is named for what it was. An
/// ICMP unreachable is `dest-unreach`, as in [`response_reason`].
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
/// This engine labels a protocol read through TLS `ssl/http`. Nmap writes
/// `name="http" tunnel="ssl"`, and its readers (exploit searches, screenshot
/// tools, importers) key on the name, so written whole an HTTPS server would
/// drop out of every list of web servers.
///
/// A bare `ssl`, a handshake with nothing identified inside, stays as is, as in
/// nmap.
fn service_name(label: &str) -> (&str, Option<&'static str>) {
    match Tunnel::split_label(label) {
        (Some(Tunnel::Tls), protocol) => (protocol, Some("ssl")),
        (None, _) => (label, None),
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
/// The engine's percentage, scaled down and clamped to 1..=10.
fn nmap_confidence(confidence: u8) -> u8 {
    // Zero is this engine's port-number lookup, which nmap records as three.
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
/// A time before the epoch becomes 0.
fn epoch_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// The human-readable companion nmap writes beside every timestamp.
///
/// RFC 3339 in UTC, as every other document this engine writes; nmap writes a
/// local-time `ctime` string. Consumers parse the numeric field beside it.
fn time_string(time: SystemTime) -> String {
    crate::format::time::rfc3339(time)
}

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

/// Report text on its way into an XML attribute value.
///
/// Escapes the five markup characters and drops the ones XML 1.0 cannot carry,
/// such as `0x01`, whose numeric reference is as illegal as the byte.
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
                // Legal, but a parser turns each raw one in an attribute value
                // into a space.
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
/// The specification allows only tab, line feed and carriage return among the C0
/// controls, and no numeric reference makes the others legal. The two
/// non-characters at the end of the basic plane are forbidden too; Rust's `char`
/// already excludes the surrogates.
///
/// The bidirectional formatting characters are legal XML, dropped because they
/// invisibly reorder the text around them.
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
            refused_by_route: Vec::new(),
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
    /// under it, and a range one phase added joins it.
    ///
    /// A phase can widen the policy by the other addresses of a machine it
    /// names, so the note is the union, merged as an address set.
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
    /// privileged scan of them connects and sends no SYNs.
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
        write_port(&mut out, port, &HostRedaction::default()).expect("writing to a vector");
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
    /// A reason chosen by state alone would say a SYN/ACK opened every open
    /// UDP port.
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

        // Only a port unreachable closes a UDP port; any other is generic.
        let unreachable = |state| {
            Port::new(161, Protocol::Udp, state)
                .with_discovery(Discovery::new(ScanResponse::IcmpUnreachable))
        };
        assert!(state_line(&unreachable(PortState::Closed)).contains(r#"reason="port-unreach""#));
        assert!(state_line(&unreachable(PortState::NoReply)).contains(r#"reason="dest-unreach""#));
    }

    /// A port with no recorded packet is given the one its state and transport
    /// admit, or silence where silence decided it.
    #[test]
    fn a_port_with_no_recorded_packet_names_the_one_its_state_admits() {
        let line = |number, protocol, state| state_line(&Port::new(number, protocol, state));

        assert!(line(53, Protocol::Udp, PortState::Open).contains(r#"reason="udp-response""#));
        assert!(line(22, Protocol::Tcp, PortState::Open).contains(r#"reason="syn-ack""#));
        assert!(line(69, Protocol::Udp, PortState::Closed).contains(r#"reason="port-unreach""#));
        assert!(line(2905, Protocol::Sctp, PortState::Closed).contains(r#"reason="abort""#));
        assert!(
            line(123, Protocol::Udp, PortState::OpenOrNoReply).contains(r#"reason="no-response""#)
        );
    }

    /// A host's reason names the evidence it holds, the most direct first.
    ///
    /// A reason chosen by status alone would make every live host an
    /// `echo-reply`, and one a router reported unreachable `no-response`,
    /// which a reader takes for silence and reads back as unknown.
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
            // A router's unreachable, then the host answering for itself.
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
    /// and a blocked host as blocked.
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
            HostStatus::Blocked,
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

        let walled = hosts.next().expect("the blocked host survived");
        assert_eq!(walled.status(), HostStatus::Blocked);
    }

    /// A service read through TLS is written as nmap writes one, the protocol
    /// named and the tunnel beside it, and reads back as the label it was.
    ///
    /// Readers find web servers by `name="http"`.
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
    /// What stays listed is what a summary would lose: the open port, and a
    /// closed one with an identified service.
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
                // Closed, with an identified service the summary cannot hold.
                80 => Port::new(80, Protocol::Tcp, PortState::Closed)
                    .with_service(Service::new("http", 90)),
                number => Port::new(number, Protocol::Tcp, PortState::Closed)
                    .with_discovery(Discovery::new(ScanResponse::TcpRst))
                    .with_service(Service::new("registered", 0)),
            };
            host.add_port(port);
        }
        for number in 1000..1040 {
            host.add_port(Port::new(number, Protocol::Udp, PortState::OpenOrNoReply));
        }
        // Too few to summarise, as nmap would list them.
        for number in 5000..5003 {
            host.add_port(Port::new(number, Protocol::Tcp, PortState::NoReply));
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
             silent ones are listed: {document}"
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
    /// A reader refusing the transport would refuse the whole document.
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
    /// A parser turns a raw line feed in an attribute value into a space.
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
            os.device(),
            Some("general purpose"),
            "the class's type was dropped"
        );
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
    /// kilobytes, past this engine's own reader's element bound.
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
                _ => PortState::NoReply,
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
            _ => port.state() == PortState::NoReply,
        }));
    }

    /// A run whose journal fell behind finished as a run that succeeded, and
    /// one whose strategy failed as one that did not.
    ///
    /// A journal probes nothing and drops no answer, so its failure costs no
    /// coverage.
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

    /// Consumers key on the root element and its output version.
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

    /// A report claiming to come from nmap would be a fabricated record.
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

    /// Every verdict a probe reaches has a name in nmap's vocabulary.
    ///
    /// Read off [`PortState::ALL`], so a state added later is checked too. The
    /// one state that is not a verdict maps to nothing.
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

        for &state in PortState::ALL {
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
    /// It must come back as a protocol, or this engine would read its own
    /// document as a host with a port 47 nobody found.
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
        // Never asked, so not written.
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
    /// Writing it as `filtered`, the nearest of nmap's six, would say a
    /// firewall dropped a probe this scan never sent.
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

    /// A host whose every port went unasked writes no `<ports>` element.
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
    /// A reader takes the first address as the host's, so in ascending order
    /// a host keyed by `203.0.113.10` that also held `198.51.100.4` would come
    /// back re-keyed.
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

    /// Nmap has three host states where this engine has four; a blocked host
    /// is up.
    #[test]
    fn a_blocked_host_is_exported_as_up_because_that_is_what_it_is() {
        assert_eq!(host_state(HostStatus::Blocked), "up");
        assert_eq!(host_state(HostStatus::Up), "up");
        assert_eq!(host_state(HostStatus::Down), "down");
        assert_eq!(host_state(HostStatus::Unknown), "unknown");
    }

    #[test]
    fn the_five_meaningful_characters_are_escaped() {
        let escaped = Attr(r#"<a href="x">&'</a>"#).to_string();

        assert_eq!(escaped, "&lt;a href=&quot;x&quot;&gt;&amp;&apos;&lt;/a&gt;");
    }

    /// A numeric reference to a forbidden control character is as illegal as
    /// the character, so it is dropped.
    #[test]
    fn characters_xml_cannot_carry_are_dropped_rather_than_referenced() {
        let banner = "OpenSSH\u{0}\u{1}\u{1f} 9.6\u{202e}drowssap";
        let escaped = Attr(banner).to_string();

        assert_eq!(escaped, "OpenSSH 9.6drowssap");
        assert!(!escaped.contains('&'), "no reference was invented for them");

        // The three C0 characters XML allows survive, as references.
        assert_eq!(Attr("a\tb\nc\rd").to_string(), "a&#x9;b&#xa;c&#xd;d");
    }

    /// Every attribute nmap's DTD marks `#REQUIRED` is present. `line` on
    /// `osmatch` is the easiest to miss.
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

        if document.contains("<osmatch ") {
            assert!(document.contains(r#" line="0">"#));
        }
        for class in document
            .lines()
            .filter(|line| line.starts_with("<osclass "))
        {
            for required in [" vendor=", " osfamily=", " accuracy="] {
                assert!(class.contains(required), "{class} lacks {required}");
            }
        }
    }

    /// A discovery sweep finds hosts and no ports, and still exports whole.
    #[test]
    fn a_report_with_no_ports_still_produces_a_whole_document() {
        let document = render();

        assert!(
            document.contains(r#"<host starttime="#),
            "the fixture's portless host is missing"
        );
        assert!(document.contains("</nmaprun>"));

        // A host with no ports gets no `<ports>` element, as in nmap.
        // `skip(1)` drops the preamble, which would match trivially.
        let portless = document
            .split("<host ")
            .skip(1)
            .find(|section| !section.contains("<ports>"))
            .expect("the fixture has a host with no ports");
        assert!(portless.contains("<status state="));
    }

    /// The DNS name a host gave for itself is written beside the resolved one
    /// and masked as it is. A NetBIOS name, a domain and a forest are not
    /// written.
    #[test]
    fn a_dns_name_the_host_gave_is_written_as_a_hostname_and_nothing_else_is() {
        use crate::model::host::{HostName, NameKind, NameSource};

        let mut host = Host::new("192.0.2.30".parse().expect("an address"));
        host.set_hostname(Some("gw.example.net".to_string()));
        for (kind, source, name) in [
            (NameKind::Host, NameSource::Ntlm, "dc01.corp.example"),
            (NameKind::Host, NameSource::Ldap, "DC01.corp.example"),
            (NameKind::NetbiosHost, NameSource::Ntlm, "DC01"),
            (NameKind::Domain, NameSource::Ntlm, "corp.example"),
            (NameKind::Forest, NameSource::Ldap, "corp.example"),
        ] {
            host.record_name(HostName::new(kind, source, name).expect("a name"));
        }
        let report = ScanReport::recorded("zond", Vec::new(), vec![host]);
        let render = |options: ExportOptions| {
            let mut out = Vec::new();
            NmapXmlExporter::new(options)
                .export(&report, &mut out)
                .expect("the report exports");
            let document = String::from_utf8(out).expect("UTF-8");
            let start = document.find("<hostnames>").expect("a hostnames element");
            let end = document.find("</hostnames>").expect("closed");
            document[start..end].to_string()
        };

        assert_eq!(
            render(ExportOptions::new()),
            "<hostnames>\n\
             <hostname name=\"gw.example.net\" type=\"PTR\"/>\n\
             <hostname name=\"dc01.corp.example\" type=\"user\"/>\n"
        );
        assert_eq!(
            render(ExportOptions::new().with_redaction(crate::export::Redaction::Standard)),
            "<hostnames>\n\
             <hostname name=\"gwXXXXXet\" type=\"PTR\"/>\n\
             <hostname name=\"dcXXXXXle\" type=\"user\"/>\n"
        );
    }

    /// A document this engine wrote reads back with the hostname the scan
    /// resolved, or none, and never the name the host gave.
    #[cfg(feature = "import-nmap")]
    #[test]
    fn a_name_the_host_gave_does_not_come_back_as_its_hostname() {
        use crate::import::report::ReportReader;
        use crate::import::report::nmap::NmapXmlReportReader;
        use crate::model::host::{HostName, NameKind, NameSource};

        let named = |last: u8, hostname: Option<&str>| {
            let mut host = Host::new(format!("192.0.2.{last}").parse().expect("an address"));
            host.set_status(HostStatus::Up);
            host.set_hostname(hostname.map(str::to_owned));
            host.record_name(
                HostName::new(NameKind::Host, NameSource::Ntlm, "dc01.corp.example")
                    .expect("a name"),
            );
            host
        };

        let restored = NmapXmlReportReader::default()
            .read(&mut std::io::Cursor::new(
                export(&[named(31, None), named(32, Some("gw.example.net"))]).into_bytes(),
            ))
            .expect("this crate's own document reads back");
        let hostnames: Vec<Option<&str>> = restored.hosts().map(Host::hostname).collect();

        assert_eq!(hostnames, [None, Some("gw.example.net")]);
    }

    /// Redaction applies to this format too.
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

    /// A confidence percentage lands on nmap's 1-to-10 scale, never 0.
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

    /// A port-number label is `table`, an identification `probed`.
    #[test]
    fn a_port_number_label_is_written_as_the_lookup_it_is() {
        use crate::model::port::{Port, PortState, Protocol, Service};

        let mut out = Vec::new();
        write_port(
            &mut out,
            &Port::new(80, Protocol::Tcp, PortState::Closed).with_service(Service::new("http", 0)),
            &HostRedaction::default(),
        )
        .expect("writing to a vector");
        let inferred = String::from_utf8(out).expect("UTF-8");
        assert!(inferred.contains(r#"method="table""#), "{inferred}");

        let mut out = Vec::new();
        write_port(
            &mut out,
            &Port::new(80, Protocol::Tcp, PortState::Open).with_service(Service::new("http", 100)),
            &HostRedaction::default(),
        )
        .expect("writing to a vector");
        let probed = String::from_utf8(out).expect("UTF-8");
        assert!(probed.contains(r#"method="probed""#), "{probed}");
    }

    /// Every attacker-controlled string reaches the document escaped.
    ///
    /// An unescaped `<` from a banner ends the element it is in and hands the
    /// rest of the document to whoever wrote the banner. Any new field written
    /// without the escaper fails this once the fixture carries it.
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
