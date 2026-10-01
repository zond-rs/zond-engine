// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # HTML export
//!
//! The report as a page: one file, opened in a browser, read by a person.
//!
//! ## One file, and nothing outside it
//!
//! The stylesheet is inlined, and the page makes no request of any kind: no
//! image, font or favicon. A report travels as an email attachment or a file on
//! a ticket or share, where a request to a CDN either fails and leaves unstyled
//! text or tells a third party that the report was opened, when, and from where.
//!
//! ## No JavaScript
//!
//! Security output is read where scripts are blocked: mail clients, restricted
//! documentation viewers, strict browsers, reviewers told never to run a page
//! built from an unknown network's data.
//!
//! So the host list cannot be sorted or filtered; [`csv`](super::csv) is for
//! that. The light/dark switch is CSS: `prefers-color-scheme` decides and the
//! masthead control inverts it through `:has()`. A browser without `:has()`
//! follows the system preference and hides the control.
//!
//! ## Printing
//!
//! There is no PDF exporter; a PDF crate costs more than this engine should
//! spend. An `@media print` stylesheet uses ink-cheap colours, hides controls and
//! keeps each host on one page, so `Ctrl-P` produces the appendix copy.
//!
//! ## Escaping is the security control
//!
//! Hostnames, service banners, certificate subjects and script output are text
//! the scanned network chose. Unescaped, a device named `<script>…</script>`
//! runs on whoever opens the report.
//!
//! Everything from the report goes through one escaping writer in
//! `export::write`, shared with the comparison page. It escapes the five markup
//! characters and renders control characters as their code point: a hostname
//! containing U+202E reverses the text after it, so a report could display one
//! address while carrying another. No report value is written into an
//! attribute, so there is only one escaping context.
//!
//! ## What the page shows
//!
//! The page renders the same [`schema`](super::schema) DTOs the JSON serializes,
//! so the two agree on every value, ordering and name. States, protocols and
//! stop reasons keep their wire spelling, so grepping the JSON for what the page
//! shows finds it.
//!
//! It differs from the JSON in two ways. A field with no value is not shown.
//! And of the fields with a value, only those that change how the rest should be
//! read are shown: an idle scan, since the port states were inferred through a
//! third party; an evasion profile, since the target answered an unusual
//! packet; what the phase covered and could not route to; and which document a
//! phase was folded in from. Instrumentation stays in the JSON. A field added to
//! [`schema`](super::schema) faces the same test.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::io::Write;
use std::time::SystemTime;

use crate::export::schema::{
    ENGINE_NAME, FindingDto, HostDto, PhaseDto, PortDto, ProbeStatsDto, RangeDto, SCHEMA_VERSION,
    SummaryDto, host_status_name, port_state_name, scan_kind_name, total_elapsed_us,
};
use crate::export::write::{TONE_FOUND, TONE_INERT, TONE_NONE, TONE_PARTIAL, Text, esc};
use crate::export::{ExportError, ExportOptions, Exporter, write};
use crate::format::time::rfc3339;
use crate::model::host::{Host, HostStatus};
use crate::model::port::{Port, PortState};
use crate::report::{ScanReport, ScannerFailure};

/// The heading a report carries when the caller names none.
const DEFAULT_HEADING: &str = "Scan report";

/// How many columns a host's port table has.
const PORT_COLUMNS: usize = 7;

/// The tone a host status is drawn in.
fn host_tone(status: HostStatus) -> &'static str {
    match status {
        HostStatus::Up => TONE_FOUND,
        HostStatus::Blocked => TONE_PARTIAL,
        HostStatus::Down => TONE_INERT,
        HostStatus::Unknown => TONE_NONE,
    }
}

/// The tone a port state is drawn in.
fn port_tone(state: PortState) -> &'static str {
    match state {
        PortState::Open => TONE_FOUND,
        PortState::OpenOrNoReply
        | PortState::NoReply
        | PortState::Blocked
        | PortState::Reachable
        | PortState::ClosedOrNoReply => TONE_PARTIAL,
        PortState::Closed => TONE_INERT,
        // As for a host of unknown status: nothing was learned here.
        PortState::Unasked => TONE_NONE,
    }
}

// ---------------------------------------------------------------------------
// The exporter
// ---------------------------------------------------------------------------

/// Writes a report as a single self-contained HTML page.
///
/// ```no_run
/// use std::fs::File;
/// use std::io::BufWriter;
/// use zond_engine::report::ScanReport;
/// use zond_engine::export::{ExportOptions, Exporter, HtmlExporter};
///
/// # fn example(report: &ScanReport) -> Result<(), Box<dyn std::error::Error>> {
/// let mut file = BufWriter::new(File::create("scan.html")?);
/// HtmlExporter::new(ExportOptions::new()).export(report, &mut file)?;
/// # Ok(())
/// # }
/// ```
///
/// The page is written incrementally, in many small writes, so a destination
/// that costs a syscall per write wants a [`BufWriter`] as above.
///
/// [`BufWriter`]: std::io::BufWriter
#[must_use]
#[derive(Debug, Clone, Default)]
pub struct HtmlExporter {
    options: ExportOptions,
    heading: Option<String>,
}

impl HtmlExporter {
    /// An exporter under the given options.
    pub fn new(options: ExportOptions) -> Self {
        Self {
            options,
            heading: None,
        }
    }

    /// Sets the report's heading, which is also the page's title.
    ///
    /// For a front end that knows what the scan was for, such as an engagement,
    /// a change number or a customer.
    pub fn with_heading(mut self, heading: impl Into<String>) -> Self {
        self.heading = Some(heading.into());
        self
    }

    /// The options in force.
    pub fn options(&self) -> &ExportOptions {
        &self.options
    }

    /// The heading shown on the page.
    fn heading(&self) -> &str {
        self.heading.as_deref().unwrap_or(DEFAULT_HEADING)
    }

    /// The page's title.
    ///
    /// Carries the scan's date when the caller named nothing, so tabs and
    /// printed headers tell reports apart.
    fn title<'a>(&'a self, started_at: &str) -> Cow<'a, str> {
        match &self.heading {
            Some(heading) => Cow::Borrowed(heading.as_str()),
            None => {
                let day = started_at.split('T').next().unwrap_or(started_at);
                Cow::Owned(format!("zond scan report — {day}"))
            }
        }
    }
}

impl Exporter for HtmlExporter {
    fn export(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), ExportError> {
        let started_at = rfc3339(report.started_at());
        let generated_at = rfc3339(SystemTime::now());
        let summary = SummaryDto::new(&report.summary());
        let phases: Vec<PhaseDto<'_>> = report
            .phases()
            .iter()
            .map(|phase| PhaseDto::new(phase, &self.options))
            .collect();
        let elapsed_us = total_elapsed_us(&phases);

        write::head(out, &self.title(&started_at))?;
        write_masthead(out, self.heading(), report, &started_at, elapsed_us)?;
        write_notices(out, report, &phases, &self.options)?;
        write_tiles(out, &summary, &phases)?;
        write_distributions(out, &summary)?;
        write_hosts(out, report, &self.options)?;
        write_scan_detail(out, &phases)?;
        write_colophon(out, report, &generated_at)?;

        write::foot(out)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// What produced the findings, where that is not the build that wrote the page.
///
/// Empty when this build produced the findings, as for any scan it ran itself;
/// an imported scan names its own scanner here.
fn findings_from(report: &ScanReport) -> String {
    if report.engine_version() == crate::report::ENGINE_VERSION {
        return String::new();
    }

    format!(" · findings from {}", Text(report.engine_version()))
}

/// A one-line description of the scan, under the shared masthead.
///
/// It states no total the schema does not define, so every figure can be
/// checked against the JSON.
fn write_masthead(
    out: &mut dyn Write,
    heading: &str,
    report: &ScanReport,
    started_at: &str,
    elapsed_us: u64,
) -> Result<(), ExportError> {
    let count = report.phases().len();
    let kinds: Vec<String> = report
        .phases()
        .iter()
        .map(|phase| esc(scan_kind_name(phase.kind())))
        .collect();

    let subtitle = format!(
        "{kinds} · started {started_at} · {elapsed} · {count} {word}",
        kinds = kinds.join(" + "),
        started_at = Text(started_at),
        elapsed = duration(elapsed_us),
        word = plural(count, "phase", "phases"),
    );

    write::masthead(out, heading, &subtitle)
}

/// The things that change how the rest of the page should be read.
///
/// Each is a fact about the report that changes what the findings mean: a
/// partial scan did not finish, an unprivileged one saw less, an idle scan saw
/// no verdict directly, an evasion profile asked differently, and a redacted
/// copy hides some of what it knows.
fn write_notices(
    out: &mut dyn Write,
    report: &ScanReport,
    phases: &[PhaseDto<'_>],
    options: &ExportOptions,
) -> Result<(), ExportError> {
    // Only phases this engine measured as unprivileged; `None` is an imported
    // phase, which this engine's advice about raw sockets does not fit.
    let unprivileged = phases
        .iter()
        .filter(|phase| phase.privileged == Some(false))
        .count();
    let idle = phases
        .iter()
        .any(|phase| phase.settings.idle_scan.is_some());
    let evaded = phases.iter().any(|phase| phase.settings.evasion.is_some());
    // A privileged phase that reached some targets by connect: the same caveat,
    // for those targets.
    let connected = phases
        .iter()
        .any(|phase| !phase.reached_by_connect.is_empty());

    if !report.is_partial()
        && unprivileged == 0
        && !connected
        && !idle
        && !evaded
        && !options.redaction.is_active()
    {
        return Ok(());
    }

    writeln!(out, "<p class=\"notices\">")?;

    if idle {
        write::notice(
            out,
            true,
            "idle scan",
            "no port state here was seen directly; each was inferred from a third party's IP identification counter, which a busy zombie makes unreliable",
        )?;
    }
    if evaded {
        write::notice(
            out,
            true,
            "evasion",
            "the probes were altered before they went out, so a state here says how the target answered an unusual packet rather than an ordinary one",
        )?;
    }

    if report.is_partial() {
        write::notice(
            out,
            true,
            "partial",
            &format!(
                "these findings are narrower than the scan asked for: {}",
                shortfalls(report).join(", ")
            ),
        )?;
    }
    if unprivileged > 0 {
        write::notice(
            out,
            true,
            "unprivileged",
            "raw probes were unavailable; those targets were reached over plain connect attempts, which see less",
        )?;
    }
    if connected {
        write::notice(
            out,
            true,
            "by connect",
            "some targets were out of reach of this machine's raw probes and were reached over plain connect attempts, which see less; each phase lists them",
        )?;
    }
    if options.redaction.is_active() {
        write::notice(
            out,
            false,
            "redacted",
            "host and domain names, hardware addresses and certificate subjects are masked in this copy",
        )?;
    }

    writeln!(out, "</p>")?;
    Ok(())
}

/// The four figures somebody reads before they read anything else.
fn write_tiles(
    out: &mut dyn Write,
    summary: &SummaryDto,
    phases: &[PhaseDto<'_>],
) -> Result<(), ExportError> {
    writeln!(out, "<section class=\"tiles\">")?;

    write::tile(out, summary.hosts_total, "hosts", &ranges_note(phases))?;
    write::tile(
        out,
        summary.hosts_alive,
        "alive",
        &esc("up or blocked — confirmed present"),
    )?;
    write::tile(
        out,
        summary.ports_open,
        "open ports",
        &format!("of {} recorded", summary.ports_total),
    )?;
    write::tile(
        out,
        summary.services_identified,
        "services",
        &esc("identified by fingerprinting"),
    )?;

    writeln!(out, "</section>")?;
    Ok(())
}

/// What the phases covered, as escaped markup, for the hosts tile.
fn ranges_note(phases: &[PhaseDto<'_>]) -> String {
    let ranges: Vec<String> = phases
        .iter()
        .flat_map(|phase| phase.targets.ranges.iter())
        .map(|range| format!("{}–{}", esc(&range.start), esc(&range.end)))
        .collect();

    match ranges.len() {
        0 => String::new(),
        1..=2 => ranges.join(", "),
        count => format!("{}, and {} more", ranges[0], count - 1),
    }
}

/// The two distributions behind the headline figures.
///
/// A stacked meter and a legend listing every category, empty ones included,
/// as the JSON summary does: `blocked: 0` is information.
fn write_distributions(out: &mut dyn Write, summary: &SummaryDto) -> Result<(), ExportError> {
    let statuses = &summary.hosts_by_status;
    let states = &summary.ports_by_state;

    writeln!(out, "<section class=\"distributions\">")?;

    distribution(
        out,
        "Host status",
        summary.hosts_total,
        &[
            status_slice(HostStatus::Up, statuses.up),
            status_slice(HostStatus::Blocked, statuses.blocked),
            status_slice(HostStatus::Down, statuses.down),
            status_slice(HostStatus::Unknown, statuses.unknown),
        ],
    )?;

    distribution(
        out,
        "Port state",
        summary.ports_total,
        &[
            state_slice(PortState::Open, states.open),
            state_slice(PortState::OpenOrNoReply, states.open_or_no_reply),
            state_slice(PortState::Closed, states.closed),
            state_slice(PortState::Reachable, states.reachable),
            state_slice(PortState::Blocked, states.blocked),
            state_slice(PortState::NoReply, states.no_reply),
            state_slice(PortState::ClosedOrNoReply, states.closed_or_no_reply),
            state_slice(PortState::Unasked, states.unasked),
        ],
    )?;

    writeln!(out, "</section>")?;
    Ok(())
}

/// One category of a distribution: its wire name, its tone, and its count.
struct Slice {
    label: &'static str,
    tone: &'static str,
    count: usize,
}

/// One band of the host-status bar: its label, its tone class, and how many
/// hosts fall in it.
fn status_slice(status: HostStatus, count: usize) -> Slice {
    Slice {
        label: host_status_name(status),
        tone: host_tone(status),
        count,
    }
}

/// [`status_slice`] for port states, counted across every host.
fn state_slice(state: PortState, count: usize) -> Slice {
    Slice {
        label: port_state_name(state),
        tone: port_tone(state),
        count,
    }
}

/// Writes one proportional bar and its legend.
///
/// The widths are the only values on this page written into an attribute,
/// which is safe because they are computed from counts.
fn distribution(
    out: &mut dyn Write,
    title: &str,
    total: usize,
    slices: &[Slice],
) -> Result<(), ExportError> {
    writeln!(
        out,
        "<div class=\"dist\">\n<h2 class=\"dist-title\">{title}</h2>",
        title = Text(title),
    )?;

    let empty = if total == 0 { " meter-empty" } else { "" };
    write!(out, "<div class=\"meter{empty}\">")?;
    for slice in slices.iter().filter(|slice| slice.count > 0) {
        write!(
            out,
            "<span class=\"seg {tone}\" style=\"width:{width:.3}%\"></span>",
            tone = slice.tone,
            width = percent(slice.count, total),
        )?;
    }
    writeln!(out, "</div>\n<ul class=\"legend\">")?;

    for slice in slices {
        let zero = if slice.count == 0 { " legend-zero" } else { "" };
        writeln!(
            out,
            "<li class=\"legend-item{zero}\"><span class=\"swatch {tone}\"></span><span class=\"legend-label\">{label}</span><span class=\"legend-value\">{count}</span></li>",
            tone = slice.tone,
            label = Text(slice.label),
            count = slice.count,
        )?;
    }

    writeln!(out, "</ul>\n</div>")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

/// The hosts section: the heading, the count, and one block per host.
fn write_hosts(
    out: &mut dyn Write,
    report: &ScanReport,
    options: &ExportOptions,
) -> Result<(), ExportError> {
    writeln!(
        out,
        "<section class=\"section\">\n<h2 class=\"section-title\">Hosts <span class=\"section-count\">{count}</span></h2>",
        count = report.host_count(),
    )?;

    if report.host_count() == 0 {
        writeln!(out, "<p class=\"empty\">no hosts recorded</p>")?;
    }

    for host in report.hosts() {
        write_host(out, host, options)?;
    }

    writeln!(out, "</section>")?;
    Ok(())
}

/// One host: its identity, what it was found to be, and its ports.
///
/// Every value comes through `HostDto`, which applies redaction, and is written
/// through the page's one escaper.
fn write_host(
    out: &mut dyn Write,
    host: &Host,
    options: &ExportOptions,
) -> Result<(), ExportError> {
    let dto = HostDto::new(host, options);

    write!(
        out,
        "<article class=\"host\">\n<header class=\"host-head\"><span class=\"host-ip\">{ip}</span>",
        ip = Text(&dto.primary_ip),
    )?;
    if let Some(hostname) = &dto.hostname {
        write!(out, "<span class=\"host-name\">{}</span>", Text(hostname))?;
    }
    write!(
        out,
        "<span class=\"tag {tone}\">{status}</span>",
        tone = host_tone(host.status()),
        status = Text(dto.status),
    )?;
    for role in &dto.roles {
        write!(out, "<span class=\"tag tag-role\">{}</span>", Text(role))?;
    }
    writeln!(out, "</header>\n<div class=\"host-body\">")?;

    write_host_facts(out, &dto)?;
    write_ports(out, host, &dto)?;

    writeln!(out, "</div>\n</article>")?;
    Ok(())
}

/// Everything known about the host that is not one of its ports.
fn write_host_facts(out: &mut dyn Write, dto: &HostDto<'_>) -> Result<(), ExportError> {
    writeln!(out, "<dl class=\"facts\">")?;

    if !dto.findings.is_empty() {
        let mut findings = String::new();
        write_finding_facts(&mut findings, &dto.findings);
        write!(out, "{findings}")?;
    }

    if dto.ips.len() > 1 {
        let addresses: Vec<String> = dto.ips.iter().map(|ip| esc(ip)).collect();
        fact(out, "addresses", &addresses.join(", "))?;
    }

    // One line per name, qualified by what it names and who said it. Beside
    // the addresses, since both identify the machine; the header's hostname is
    // what name resolution answered.
    let mut names = String::new();
    for name in &dto.names {
        let detail = [name.kind.replace('_', " "), name.source.to_owned()];
        let _ = write!(names, "<div>{}{}</div>", esc(&name.name), dim(&detail));
    }
    fact(out, "names", &names)?;

    if let Some(os) = &dto.os {
        let mut detail = vec![format!("{}% confidence", os.accuracy)];
        if let Some(family) = &os.family {
            detail.push(esc(family));
        }
        if let Some(vendor) = &os.vendor {
            detail.push(esc(vendor));
        }
        let name = match &os.generation {
            Some(generation) => format!("{} {}", esc(&os.name), esc(generation)),
            None => esc(&os.name),
        };
        fact(out, "os", &format!("{name}{}", dim(&detail)))?;
    }

    if !dto.ip_protocols.is_empty() {
        // Only the two verdicts a reader acts on; the count covers the silent
        // ones.
        let named = |state: &str| -> Vec<String> {
            dto.ip_protocols
                .iter()
                .filter(|entry| entry.state == state)
                .map(|entry| match entry.name {
                    Some(name) => esc(name),
                    None => entry.protocol.to_string(),
                })
                .collect()
        };

        let accepted = named("open");
        let refused = named("closed");
        let mut detail = Vec::new();
        if !refused.is_empty() {
            detail.push(format!("refuses {}", refused.join(", ")));
        }
        detail.push(format!("{} asked about", dto.ip_protocols.len()));

        let value = match accepted.is_empty() {
            false => accepted.join(", "),
            // The ordinary result: most protocols answer an unsolicited header
            // with nothing whether or not the stack implements them.
            true => "none answered".to_string(),
        };
        fact(out, "ip protocols", &format!("{value}{}", dim(&detail)))?;
    }

    if let Some(hardware) = &dto.hardware {
        let mut value = hardware.mac.as_deref().map(esc).unwrap_or_default();
        let mut detail = Vec::new();
        if let Some(vendor) = &hardware.vendor {
            detail.push(esc(vendor));
        }
        if hardware.macs.len() > 1 {
            detail.push(format!("{} addresses seen", hardware.macs.len()));
        }
        value.push_str(&dim(&detail));
        fact(out, "hardware", &value)?;
    }

    let telemetry = &dto.telemetry;
    if let Some(median) = telemetry.rtt_median_us {
        let mut detail = Vec::new();
        if let (Some(min), Some(max)) = (telemetry.rtt_min_us, telemetry.rtt_max_us) {
            detail.push(format!("{} – {}", duration(min), duration(max)));
        }
        if let Some(jitter) = telemetry.jitter_us {
            detail.push(format!("jitter {}", duration(jitter)));
        }
        detail.push(format!(
            "{} {}",
            telemetry.samples,
            plural(telemetry.samples, "sample", "samples")
        ));
        fact(
            out,
            "rtt",
            &format!("{} median{}", duration(median), dim(&detail)),
        )?;
    }

    if !dto.path.is_empty() {
        // One line per router, distance first, so a silent router reads as a
        // gap. An inherited hop is marked, since this host's probes never met
        // it. A withheld hop's router did answer, so it reads `excluded`.
        let mut path = String::new();
        for hop in &dto.path {
            let address = match hop.address.as_deref() {
                Some(address) => address,
                None if hop.withheld => "excluded",
                None => "*",
            };
            let mut detail = Vec::new();
            if let Some(rtt) = hop.rtt_us {
                detail.push(duration(rtt));
            }
            if hop.inferred {
                detail.push("from another trace".to_string());
            }
            let _ = write!(
                path,
                "<div>{:>2}. {}{}</div>",
                hop.distance,
                esc(address),
                dim(&detail)
            );
        }
        fact(out, "path", &path)?;
    }

    // A middlebox's word about a host differs from the host's own, so the
    // sender is named, or marked excluded when withheld.
    let mut evidence = String::new();
    for reason in &dto.reasons {
        let mut detail: Vec<String> = reason.details.as_deref().map(esc).into_iter().collect();
        match &reason.source_ip {
            Some(source) => detail.push(format!("via {}", esc(source))),
            None if reason.source_withheld => detail.push("via an excluded address".to_owned()),
            None => {}
        }
        let _ = write!(
            evidence,
            "<div>{}{}</div>",
            Text(&reason.protocol),
            dim(&detail)
        );
    }
    fact(out, "evidence", &evidence)?;

    fact(
        out,
        "seen",
        &format!(
            "{}{}",
            esc(&dto.first_seen),
            dim(&[format!("last {}", esc(&dto.last_seen))])
        ),
    )?;

    writeln!(out, "</dl>")?;
    Ok(())
}

/// A host's port table, or the line that says it has none.
fn write_ports(out: &mut dyn Write, host: &Host, dto: &HostDto<'_>) -> Result<(), ExportError> {
    if dto.ports.is_empty() {
        writeln!(out, "<p class=\"empty\">no ports recorded</p>")?;
        return Ok(());
    }

    writeln!(
        out,
        "<div class=\"scroll\">\n<table class=\"table\">\n<thead><tr><th>port</th><th>state</th><th>service</th><th>product</th><th>version</th><th class=\"num\">rtt</th><th>evidence</th></tr></thead>\n<tbody>"
    )?;

    // `HostDto` builds its ports from the host's, in order, so they pair up:
    // values from the DTO, colour from the state.
    for (port, port_dto) in host.ports().zip(dto.ports.iter()) {
        debug_assert_eq!(
            port.number(),
            port_dto.port,
            "the rendered ports and the host's ports have diverged"
        );
        write_port(out, port, port_dto)?;
    }

    writeln!(out, "</tbody>\n</table>\n</div>")?;
    Ok(())
}

/// One row of a host's port table, and the detail block that expands under it.
fn write_port(out: &mut dyn Write, port: &Port, dto: &PortDto<'_>) -> Result<(), ExportError> {
    let service = dto.service.as_ref();
    let discovery = dto.discovery.as_ref();

    write!(
        out,
        "<tr><td class=\"mono\">{number}/{protocol}</td><td><span class=\"tag {tone}\">{state}</span></td>",
        number = dto.port,
        protocol = Text(dto.protocol),
        tone = port_tone(port.state()),
        state = Text(dto.state),
    )?;

    write!(
        out,
        "<td>{}</td>",
        service
            .map(|service| esc(&service.name))
            .unwrap_or_default()
    )?;
    write!(
        out,
        "<td>{}</td>",
        service
            .and_then(|service| service.product.as_deref())
            .map(esc)
            .unwrap_or_default()
    )?;

    let version = service
        .map(|service| {
            let mut text = service.version.as_deref().map(esc).unwrap_or_default();
            // The build first, since it says whose fixes the version carries.
            // Extra detail that only restates the revision, as an OpenSSH
            // comment does, is skipped.
            let revision = service
                .build
                .as_ref()
                .and_then(|build| build.revision.as_deref());
            if let Some(build) = &service.build {
                text.push_str(&dim(&[esc(&build_text(build))]));
            }
            if let Some(extra) = &service.extrainfo
                && revision.is_none_or(|revision| !extra.contains(revision))
            {
                text.push_str(&dim(&[esc(extra)]));
            }
            text
        })
        .unwrap_or_default();
    write!(out, "<td>{version}</td>")?;

    write!(
        out,
        "<td class=\"num\">{}</td>",
        discovery
            .and_then(|discovery| discovery.rtt_us)
            .map(duration)
            .unwrap_or_default()
    )?;
    writeln!(
        out,
        "<td>{}</td></tr>",
        discovery
            .map(|discovery| esc(&discovery.reason))
            .unwrap_or_default()
    )?;

    write_port_detail(out, dto)
}

/// Appends a subject's findings to a fact list, worst-first.
///
/// The attacker-influenced fields (title, excerpt, remediation, URL references)
/// are written as element content through [`Text`] or [`esc`]. The classes are
/// the stylesheet's own, which the class-name test checks.
fn write_finding_facts(facts: &mut String, findings: &[FindingDto<'_>]) {
    for finding in findings {
        let mut detail = vec![Text(finding.confidence).to_string()];
        // Beside the confidence: it says which are being exploited, which is
        // separate from severity.
        if let Some(exploited) = &finding.exploited {
            detail.push(format!(
                "known exploited: {}",
                esc(&exploited.cves.join(", "))
            ));
        }
        if !finding.references.is_empty() {
            let references: Vec<String> =
                finding.references.iter().map(|r| esc(&r.value)).collect();
            detail.push(references.join(", "));
        }
        let _ = write!(
            facts,
            "<dt>{severity}</dt><dd>{title}{detail}",
            severity = Text(finding.severity),
            title = Text(&finding.title),
            detail = dim(&detail),
        );
        if let Some(excerpt) = &finding.excerpt {
            let _ = write!(facts, "<div class=\"mono\">{}</div>", Text(excerpt));
        }
        if let Some(remediation) = &finding.remediation {
            let _ = write!(facts, "<div>{}</div>", Text(remediation));
        }
        facts.push_str("</dd>");
    }
}

/// The second row a port gets when there is more to say than fits in a column.
fn write_port_detail(out: &mut dyn Write, dto: &PortDto<'_>) -> Result<(), ExportError> {
    let mut facts = String::new();

    // Findings lead.
    write_finding_facts(&mut facts, &dto.findings);

    if let Some(service) = &dto.service {
        let cpes: Vec<String> = service.cpes.iter().map(|cpe| esc(cpe)).collect();
        let _ = write!(
            facts,
            "<dt>service</dt><dd>{}% confidence{}</dd>",
            service.confidence,
            dim(&[cpes.join(", ")])
        );
    }

    if let Some(security) = &dto.security {
        let mut detail = Vec::new();
        if let Some(cipher) = security.cipher_suite {
            detail.push(esc(cipher));
        }
        if !security.alpn.is_empty() {
            let alpn: Vec<String> = security.alpn.iter().map(|name| esc(name)).collect();
            detail.push(alpn.join(" "));
        }
        let _ = write!(
            facts,
            "<dt>tls</dt><dd>{}{}</dd>",
            security.tls_version.map(esc).unwrap_or_default(),
            dim(&detail)
        );

        // What the endpoint accepts: one line per version, worst suite first,
        // so a withdrawn version or broken cipher shows at a glance.
        for accepted in &security.accepts {
            let mut detail = Vec::new();
            if accepted.deprecated {
                detail.push(esc("withdrawn"));
            }
            let insecure = accepted
                .suites
                .iter()
                .filter(|suite| suite.strength != "strong")
                .count();
            if insecure > 0 {
                detail.push(format!(
                    "{insecure} of {} below strong",
                    accepted.suites.len()
                ));
            }
            if !accepted.unrecognised.is_empty() {
                detail.push(format!("{} unnamed", accepted.unrecognised.len()));
            }
            // A walk cut short found only a floor.
            if let Some(unfinished) = security
                .unfinished
                .iter()
                .find(|unfinished| unfinished.version == accepted.version)
            {
                detail.push(format!("incomplete, {}", esc(unfinished.interruption)));
            }

            let suites: Vec<String> = accepted
                .suites
                .iter()
                .map(|suite| match suite.faults.is_empty() {
                    true => esc(suite.name),
                    false => format!("{} ({})", esc(suite.name), esc(&suite.faults.join(", "))),
                })
                .collect();

            let _ = write!(
                facts,
                "<dt>accepts</dt><dd>{}{}<br>{}</dd>",
                esc(accepted.version),
                dim(&detail),
                dim(&[suites.join(" · ")])
            );
        }

        // A version whose walk ended before any answer is neither accepted nor
        // refused; left out, it would read as refused.
        for unfinished in security.unfinished.iter().filter(|unfinished| {
            !security
                .accepts
                .iter()
                .any(|accepted| accepted.version == unfinished.version)
        }) {
            let _ = write!(
                facts,
                "<dt>unsettled</dt><dd>{}{}</dd>",
                esc(unfinished.version),
                dim(&[esc(unfinished.interruption)])
            );
        }

        if let Some(certificate) = &security.certificate {
            let mut detail = vec![format!("issued by {}", esc(&certificate.issuer))];
            if !certificate.sans.is_empty() {
                let sans: Vec<String> = certificate.sans.iter().map(|san| esc(san)).collect();
                detail.push(format!("also {}", sans.join(", ")));
            }
            detail.push(format!(
                "{} {}-bit",
                esc(certificate.pubkey_type),
                certificate.pubkey_bits
            ));

            let _ = write!(
                facts,
                "<dt>certificate</dt><dd>{}{}</dd>",
                esc(&certificate.common_name),
                dim(&detail)
            );
            let _ = write!(
                facts,
                "<dt>validity</dt><dd>{} – {}</dd>",
                esc(&certificate.validity_start),
                esc(&certificate.validity_end)
            );
            let _ = write!(
                facts,
                "<dt>fingerprint</dt><dd>{}</dd>",
                esc(certificate.fingerprint_sha256)
            );
        }
    }

    if let Some(discovery) = &dto.discovery {
        let mut detail = Vec::new();
        if let Some(ttl) = discovery.ttl {
            detail.push(format!("ttl {ttl}"));
        }
        if let Some(source) = &discovery.source_ip {
            detail.push(format!("reply from {}", esc(source)));
        }
        let _ = write!(
            facts,
            "<dt>probe</dt><dd>{}{}</dd>",
            esc(&discovery.timestamp),
            dim(&detail)
        );
    }

    if facts.is_empty() {
        return Ok(());
    }

    writeln!(
        out,
        "<tr class=\"port-detail\"><td colspan=\"{PORT_COLUMNS}\"><dl class=\"facts\">{facts}</dl></td></tr>"
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Scan detail
// ---------------------------------------------------------------------------

/// What the scan did, which says how far the host list can be trusted. Last on
/// the page, since a reader opens a report for the hosts.
fn write_scan_detail(out: &mut dyn Write, phases: &[PhaseDto<'_>]) -> Result<(), ExportError> {
    writeln!(
        out,
        "<section class=\"section\">\n<h2 class=\"section-title\">Scan detail <span class=\"section-count\">{count} {word}</span></h2>",
        count = phases.len(),
        word = plural(phases.len(), "phase", "phases"),
    )?;

    for phase in phases {
        write_phase(out, phase)?;
    }

    writeln!(out, "</section>")?;
    Ok(())
}

/// One phase: what it covered, what it ran under, what failed, and what each
/// scanner in it sent and saw: whether the phase's silence is evidence.
fn write_phase(out: &mut dyn Write, phase: &PhaseDto<'_>) -> Result<(), ExportError> {
    let privilege = match phase.privileged {
        Some(true) => "privileged",
        Some(false) => "unprivileged",
        // A phase read from another scanner's document.
        None => "privilege not recorded",
    };

    writeln!(
        out,
        "<article class=\"phase\">\n<header class=\"phase-head\"><span class=\"phase-kind\">{kind}</span><span class=\"dim\">{started} · {elapsed} · {privilege}</span></header>\n<dl class=\"facts\">",
        kind = Text(phase.kind),
        started = Text(&phase.started_at),
        elapsed = duration(phase.elapsed_us),
    )?;

    let scope = &phase.targets;
    let mut targets = vec![format!(
        "{} {}",
        esc(&scope.addresses),
        plural_str(&scope.addresses, "address", "addresses")
    )];
    if let Some(probes) = &scope.probes {
        targets.push(format!(
            "{} {}",
            esc(probes),
            plural_str(probes, "probe", "probes")
        ));
    }
    if !scope.protocols.is_empty() {
        targets.push(scope.protocols.join(", "));
    }
    fact(out, "targets", &targets.join(" · "))?;

    let ranges: Vec<String> = scope
        .ranges
        .iter()
        .map(|range| format!("{}–{}", esc(&range.start), esc(&range.end)))
        .collect();
    fact(out, "ranges", &ranges.join("<br>"))?;

    // A sweep of a segment covers every host on it, which no range expresses.
    // Listening covers nothing, since a quiet machine looks absent, so the two
    // are separate rows.
    if !scope.links.is_empty() {
        let links: Vec<String> = scope.links.iter().map(|name| esc(name)).collect();
        fact(out, "links swept", &links.join(", "))?;
    }
    if !scope.listened.is_empty() {
        let listened: Vec<String> = scope.listened.iter().map(|name| esc(name)).collect();
        fact(
            out,
            "links listened on",
            &format!(
                "{}{}",
                listened.join(", "),
                dim(&[esc("not coverage: silence here is not absence")])
            ),
        )?;
    }

    // Which ports were walked, and whether the same for every address, so an
    // absent port reads as closed or unasked correctly.
    if let Some(ports) = &scope.ports {
        let spec = if ports.spec.is_empty() {
            String::new()
        } else {
            dim(&[esc(&ports.spec)])
        };
        fact(out, "ports", &format!("{}{spec}", esc(ports.kind)))?;
    }

    // Only when a policy was set, so the row is not routinely skipped.
    if !scope.excluded.is_empty() {
        let excluded: Vec<String> = scope
            .excluded
            .iter()
            .map(|range| format!("{}–{}", esc(&range.start), esc(&range.end)))
            .collect();
        fact(
            out,
            "excluded",
            &format!(
                "{}<br><span class=\"dim\">{} {} withheld</span>",
                excluded.join("<br>"),
                esc(&scope.withheld),
                plural_str(&scope.withheld, "address", "addresses"),
            ),
        )?;
    }

    let retry = &phase.settings.retry;
    let mut budget = vec![esc(retry.effort)];
    if let Some(attempts) = retry.max_attempts {
        budget.push(format!("{attempts} attempts"));
    }
    if let Some(scale) = retry.timeout_scale {
        budget.push(format!("timeout ×{scale}"));
    }
    if retry.dampen_silent_hosts {
        budget.push("silent hosts dampened".to_string());
    }
    fact(out, "retry", &budget.join(" · "))?;

    let settings = &phase.settings;
    // Named as bounds: "500 probes/s" alone would read as the pace the scan
    // ran at.
    let rate = match (settings.min_probe_rate, settings.max_probe_rate) {
        (Some(min), Some(max)) => format!("min {min} · max {max} probes/s"),
        (Some(min), None) => format!("min {min} probes/s"),
        (None, Some(max)) => format!("max {max} probes/s"),
        (None, None) => "scanner default rate".to_string(),
    };
    let dns = if settings.dns_enabled {
        "dns enabled"
    } else {
        "dns disabled"
    };
    // The wall-clock bounds get their own line: each is a reason the page may
    // be short.
    let bounds: Vec<String> = [
        settings
            .host_timeout_us
            .map(|us| format!("per host {}", duration(us))),
        settings
            .scan_timeout_us
            .map(|us| format!("whole scan {}", duration(us))),
        // Gaps, not budgets, but each explains how long the scan took.
        settings
            .host_probe_interval_us
            .map(|us| format!("{} between probes at one host", duration(us))),
        settings
            .probe_interval_us
            .map(|us| format!("{} between any two probes", duration(us))),
    ]
    .into_iter()
    .flatten()
    .collect();
    // The technique leads: `closed` from a SYN scan and from a FIN scan are
    // different findings.
    fact(
        out,
        "wire",
        &format!(
            "{} · sctp {} · send {} · {rate} · {dns} · os {} · service {} · detection {}",
            esc(settings.tcp_technique),
            esc(settings.sctp_technique),
            esc(settings.send_mode),
            esc(settings.os_detection),
            esc(settings.service_detection),
            esc(settings.detection),
        ),
    )?;

    if !bounds.is_empty() {
        fact(out, "time limit", &bounds.join(" · "))?;
    }

    // The two settings that change what a state means, repeated per phase from
    // the notice at the top.
    if let Some(idle) = &settings.idle_scan {
        let port = idle
            .zombie_port
            .map(|port| format!("port {port}"))
            .unwrap_or_default();
        fact(
            out,
            "idle scan",
            &format!(
                "{}{}",
                esc(&idle.zombie),
                dim(&[port, esc("states inferred, not seen")])
            ),
        )?;
    }
    if let Some(evasion) = &settings.evasion {
        fact(out, "evasion", &evasion_detail(evasion))?;
    }

    // Ports sent nothing on purpose: one here with no product was never asked.
    if !settings.listen_only_ports.is_empty() {
        let ports: crate::model::port::PortSet = settings
            .listen_only_ports
            .iter()
            .map(|&number| (number, crate::model::port::Protocol::Tcp))
            .collect();
        fact(
            out,
            "listened only",
            &format!(
                "tcp {}{}",
                esc(&ports.to_string()),
                dim(&[esc("sent nothing, since a printer prints what arrives")])
            ),
        )?;
    }

    // Ports named and kept out of the scan.
    if !settings.excluded_ports.is_empty() {
        fact(
            out,
            "excluded ports",
            &format!(
                "{}{}",
                esc(&settings.excluded_ports),
                dim(&[esc("sent nothing on any target")])
            ),
        )?;
    }

    // Addresses the caller named that no probe was sent to.
    if !phase.unroutable.is_empty() {
        let addresses: Vec<String> = phase.unroutable.iter().map(|ip| esc(ip)).collect();
        fact(
            out,
            "unreachable",
            &format!(
                "{}{}",
                addresses.join(", "),
                dim(&[esc("named, never probed")])
            ),
        )?;
    }

    // Of those, the ones this machine's own routing table refuses, where the
    // remedy is.
    if !phase.refused_by_route.is_empty() {
        let addresses: Vec<String> = phase.refused_by_route.iter().map(|ip| esc(ip)).collect();
        fact(
            out,
            "refused by a route",
            &format!(
                "{}{}",
                addresses.join(", "),
                dim(&[esc("this host's routing table")])
            ),
        )?;
    }

    // Addresses the scan left unfinished. Their ports carry the silence
    // verdict, so without this line they read as quiet machines.
    if !phase.timed_out.is_empty() {
        let addresses: Vec<String> = phase.timed_out.iter().map(|ip| esc(ip)).collect();
        fact(
            out,
            "out of time",
            &format!(
                "{}{}",
                addresses.join(", "),
                dim(&[esc("left part-scanned")])
            ),
        )?;
    }

    // Addresses that rationed the ICMP errors that mark a closed UDP port, so
    // their open-or-no-reply ports are mostly closed.
    if !phase.icmp_rate_limited.is_empty() {
        let addresses: Vec<String> = phase.icmp_rate_limited.iter().map(|ip| esc(ip)).collect();
        fact(
            out,
            "ICMP rate-limited",
            &format!(
                "{}{}",
                addresses.join(", "),
                dim(&[esc("closed UDP ports may read open|no-reply")])
            ),
        )?;
    }

    // Addresses with no verdict, absent from the hosts like the silent ones.
    // Capped, since a sweep stopped halfway through a shuffled range leaves
    // scattered gaps, and the count is what matters.
    if !phase.undecided.is_empty() {
        const SHOWN: usize = 6;
        let mut ranges: Vec<String> = phase
            .undecided
            .iter()
            .take(SHOWN)
            .map(|range| match range.start == range.end {
                true => esc(&range.start),
                false => format!("{}–{}", esc(&range.start), esc(&range.end)),
            })
            .collect();
        let more = phase.undecided.len().saturating_sub(SHOWN);
        if more > 0 {
            ranges.push(esc(&format!(
                "and {more} more {}",
                if more == 1 { "range" } else { "ranges" }
            )));
        }
        let count = addresses_in(&phase.undecided);
        fact(
            out,
            "undecided",
            &format!(
                "{}{}",
                ranges.join(", "),
                dim(&[esc(&format!(
                    "{count} {} with no verdict, not found down",
                    if count == 1 { "address" } else { "addresses" }
                ))])
            ),
        )?;
    }

    // Why the scan was stopped, and how many planned targets it never asked;
    // those are on no host below. A phase that was not stopped can leave some
    // too, for an address its liveness pass never decided.
    if phase.stopped.is_none()
        && let Some(count) = phase.unreached.as_deref()
    {
        fact(
            out,
            "never asked",
            &esc(&format!(
                "{count} {}",
                if count == "1" { "target" } else { "targets" }
            )),
        )?;
    }
    if let Some(stopped) = phase.stopped {
        let why = match stopped {
            "timed_out" => "scan budget spent",
            _ => "aborted by the caller",
        };
        let unreached = phase.unreached.as_deref().map(|count| {
            esc(&format!(
                "{count} {} never asked",
                if count == "1" { "target" } else { "targets" }
            ))
        });
        let cut = (!phase.passes_cut.is_empty())
            .then(|| esc(&format!("{} not finished", phase.passes_cut.join(", "))));
        fact(
            out,
            "stopped",
            &format!(
                "{}{}",
                esc(why),
                dim(&unreached.into_iter().chain(cut).collect::<Vec<_>>())
            ),
        )?;
    }

    // A phase recorded before it closed: its sitting was killed, or had not
    // ended when its journal was read. What only its close would say, a stop
    // or a count never asked, is missing.
    if phase.open {
        fact(
            out,
            "closed",
            &format!(
                "{}{}",
                esc("never"),
                dim(&[esc("its sitting ended before the phase did")])
            ),
        )?;
    }

    // Why a port phase ran with no liveness pass, which says how to read the
    // hosts.
    if let Some(skip) = phase.liveness_skipped {
        let why = match skip {
            "assume_up" => "every address probed as up, as asked",
            "idle_scan" => "an idle scan asks the target nothing directly",
            _ => "probing the ports cost no more; an answer on any found the host",
        };
        fact(
            out,
            "liveness pass",
            &format!("{}{}", esc("skipped"), dim(&[esc(why)])),
        )?;
    }

    // Addresses silent on every port where the port phase stood in for a
    // liveness pass. Absent from the hosts, as a pass would have left them.
    // Capped like the undecided list.
    if !phase.silent.is_empty() {
        const SHOWN: usize = 6;
        let mut ranges: Vec<String> = phase
            .silent
            .iter()
            .take(SHOWN)
            .map(|range| match range.start == range.end {
                true => esc(&range.start),
                false => format!("{}–{}", esc(&range.start), esc(&range.end)),
            })
            .collect();
        let more = phase.silent.len().saturating_sub(SHOWN);
        if more > 0 {
            ranges.push(esc(&format!(
                "and {more} more {}",
                if more == 1 { "range" } else { "ranges" }
            )));
        }
        let count = addresses_in(&phase.silent);
        fact(
            out,
            "silent",
            &format!(
                "{}{}",
                ranges.join(", "),
                dim(&[esc(&format!(
                    "{count} {} silent on every port, not listed",
                    if count == 1 { "address" } else { "addresses" }
                ))])
            ),
        )?;
    }

    // Addresses a privileged phase reached by connect, whose results sit
    // beside raw ones.
    if !phase.reached_by_connect.is_empty() {
        let ranges: Vec<String> = phase
            .reached_by_connect
            .iter()
            .map(|range| match range.start == range.end {
                true => esc(&range.start),
                false => format!("{}–{}", esc(&range.start), esc(&range.end)),
            })
            .collect();
        fact(
            out,
            "by connect",
            &format!(
                "{}{}",
                ranges.join(", "),
                dim(&[esc("out of reach of raw probes")])
            ),
        )?;
    }

    // For a merged report: which document this phase came from.
    if let Some(origin) = &phase.origin {
        let label = origin.label.map(esc).into_iter().collect::<Vec<_>>();
        fact(
            out,
            "read from",
            &format!("{}{}", esc(origin.engine_version), dim(&label)),
        )?;
    }

    writeln!(out, "</dl>")?;

    write_attachments(out, &phase.attachments)?;

    if !phase.failures.is_empty() {
        writeln!(
            out,
            "<div class=\"block\">\n<div class=\"block-title\">failures</div>\n<div class=\"scroll\">\n<table class=\"table\">\n<thead><tr><th>scanner</th><th>outcome</th><th>reason</th><th>at</th></tr></thead>\n<tbody>"
        )?;
        for failure in &phase.failures {
            writeln!(
                out,
                "<tr><td class=\"mono\">{scanner}</td><td>{outcome}</td><td>{reason}</td><td class=\"mono\">{at}</td></tr>",
                scanner = Text(failure.scanner),
                outcome = if failure.cut_short {
                    "cut short"
                } else {
                    "failed"
                },
                reason = Text(failure.reason),
                at = Text(&failure.at),
            )?;
        }
        writeln!(out, "</tbody>\n</table>\n</div>\n</div>")?;
    }

    for stats in &phase.probe_stats {
        write_probe_stats(out, stats)?;
    }

    writeln!(out, "</article>")?;
    Ok(())
}

/// What a scan changed about the packets it sent, as one line.
///
/// Each field is present only for a technique the scan used.
fn evasion_detail(evasion: &crate::export::schema::EvasionDto) -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Some(port) = evasion.source_port {
        parts.push(format!("from port {port}"));
    }
    if let Some(ttl) = evasion.ttl {
        parts.push(format!("ttl {ttl}"));
    }
    if let Some(padding) = evasion.padding {
        parts.push(format!("{padding} bytes of padding"));
    }
    if evasion.bad_tcp_checksum {
        parts.push("wrong TCP checksum".to_string());
    }
    if let Some(mac) = &evasion.spoof_mac {
        parts.push(format!("spoofing {}", esc(mac)));
    }
    if let Some(bytes) = evasion.fragment {
        parts.push(format!("fragmented to {bytes} bytes"));
    }
    if let Some(flags) = &evasion.flags {
        parts.push(format!("flags {}", esc(flags)));
    }
    if !evasion.decoys.is_empty() {
        let decoys: Vec<String> = evasion.decoys.iter().map(|ip| esc(ip)).collect();
        parts.push(format!("decoys {}", decoys.join(", ")));
    }

    parts.join(" · ")
}

/// Where the machine that ran this phase was plugged in.
///
/// Its own table: it describes where the scan stood, not any host. Empty on an
/// unmanaged network, which does not mean the machine is attached to nothing.
fn write_attachments(
    out: &mut dyn Write,
    attachments: &[crate::export::schema::AttachmentDto<'_>],
) -> Result<(), ExportError> {
    if attachments.is_empty() {
        return Ok(());
    }

    writeln!(
        out,
        "<div class=\"block\">\n<div class=\"block-title\">where this ran from</div>\n<div class=\"scroll\">\n<table class=\"table\">\n<thead><tr><th>link</th><th>device</th><th>port</th><th>vlan</th><th>seen</th></tr></thead>\n<tbody>"
    )?;

    for attachment in attachments {
        let device = match (&attachment.device_name, &attachment.device_mac) {
            (Some(name), Some(mac)) => format!("{}{}", Text(name), dim(&[esc(mac)])),
            (Some(name), None) => Text(name).to_string(),
            (None, Some(mac)) => esc(mac),
            (None, None) => String::new(),
        };

        writeln!(
            out,
            "<tr><td class=\"mono\">{link}</td><td>{device}{source}</td><td class=\"mono\">{port}</td><td class=\"num\">{vlan}</td><td class=\"mono\">{seen}</td></tr>",
            link = Text(attachment.link),
            source = dim(&[esc(attachment.source)]),
            port = attachment.port.map(esc).unwrap_or_default(),
            vlan = attachment
                .native_vlan
                .map(|vlan| vlan.to_string())
                .unwrap_or_default(),
            seen = Text(&attachment.observed_at),
        )?;
    }

    writeln!(out, "</tbody>\n</table>\n</div>\n</div>")?;
    Ok(())
}

/// What one scanner observed about its own run.
fn write_probe_stats(out: &mut dyn Write, stats: &ProbeStatsDto) -> Result<(), ExportError> {
    writeln!(
        out,
        "<div class=\"block\">\n<div class=\"block-title\">{scanner} · {targets} targets</div>\n<dl class=\"facts\">",
        scanner = Text(stats.scanner),
        targets = Text(&stats.targets),
    )?;

    let completion = if stats.complete {
        "finished what it had to do"
    } else {
        "cut short"
    };
    fact(
        out,
        "stopped",
        &format!(
            "{}{}",
            esc(stats.stop_reason),
            dim(&[
                esc(completion),
                format!("after {}", duration(stats.elapsed_us)),
            ])
        ),
    )?;

    let mut sends = vec![format!("{} attempted", stats.sends_attempted)];
    // Not "refused": the count includes unreachable addresses as well as sends
    // the sender turned down.
    if stats.sends_failed > 0 {
        sends.push(format!("{} never left this host", stats.sends_failed));
    }
    // One decimal below ten, so a trickle does not round to nothing.
    if let Some(rate) = stats.achieved_send_rate {
        sends.push(match rate {
            10.0.. => format!("{rate:.0}/s"),
            _ => format!("{rate:.1}/s"),
        });
    }
    fact(out, "probes", &sends.join(" · "))?;

    let mut seen = vec![format!("{} seen", stats.segments_seen)];
    if stats.segments_off_target > 0 {
        seen.push(format!("{} off target", stats.segments_off_target));
    }
    if stats.replies_without_rtt > 0 {
        seen.push(format!(
            "{} without a round trip",
            stats.replies_without_rtt
        ));
    }
    if stats.refusals_unattributed > 0 {
        seen.push(format!(
            "{} refusals naming no probe, not credited",
            stats.refusals_unattributed
        ));
    }
    fact(out, "segments", &seen.join(" · "))?;

    let mut timing = Vec::new();
    if let Some(first) = stats.first_reply_us {
        timing.push(format!("first at {}", duration(first)));
    }
    if let Some(last) = stats.last_reply_us {
        timing.push(format!("last at {}", duration(last)));
    }
    fact(
        out,
        "hosts found",
        &format!("{}{}", stats.hosts_found, dim(&timing)),
    )?;

    if let Some(capture) = &stats.capture {
        let mut counts = vec![format!("{} received", capture.received)];
        if capture.dropped > 0 {
            counts.push(format!("{} dropped by the buffer", capture.dropped));
        }
        if capture.if_dropped > 0 {
            counts.push(format!("{} dropped by the interface", capture.if_dropped));
        }
        // Last, and in words: it says the counts beside it cover less of the
        // network than they appear to.
        if capture.stopped_early > 0 {
            counts.push(match capture.stopped_early {
                1 => "one capture stopped early and heard nothing after".to_string(),
                many => format!("{many} captures stopped early and heard nothing after"),
            });
        }
        fact(out, "capture", &counts.join(" · "))?;
    }

    writeln!(out, "</dl>")?;

    let attempts: Vec<(String, u64)> = stats
        .answered_on
        .iter()
        .map(|entry| {
            let label = if entry.or_later {
                format!("{}+", entry.attempt)
            } else {
                entry.attempt.to_string()
            };
            (label, entry.count)
        })
        .collect();
    histogram(
        out,
        "hosts by attempt",
        &attempts,
        stats.answered_unattributed,
    )?;

    let buckets: Vec<(String, u64)> = stats
        .found_at
        .iter()
        .map(|bucket| {
            let label = match bucket.le_ms {
                Some(bound) => format!("≤ {bound} ms"),
                None => "slower".to_string(),
            };
            (label, bucket.count)
        })
        .collect();
    histogram(out, "hosts by discovery time", &buckets, 0)?;

    writeln!(out, "</div>")?;
    Ok(())
}

/// A row of labelled counts, drawn as bars against the largest of them.
///
/// One bucket usually holds nearly everything, and scaling to the total would
/// draw the rest as invisible lines.
fn histogram(
    out: &mut dyn Write,
    title: &str,
    rows: &[(String, u64)],
    unattributed: u64,
) -> Result<(), ExportError> {
    let peak = rows.iter().map(|(_, count)| *count).max().unwrap_or(0);
    if peak == 0 && unattributed == 0 {
        return Ok(());
    }

    writeln!(
        out,
        "<div class=\"block-title\">{title}</div>\n<table class=\"hist\">\n<tbody>",
        title = Text(title),
    )?;

    for (label, count) in rows {
        histogram_row(out, label, *count, peak)?;
    }
    if unattributed > 0 {
        histogram_row(out, "unmatched", unattributed, peak)?;
    }

    writeln!(out, "</tbody>\n</table>")?;
    Ok(())
}

/// One bar of a histogram, scaled against the tallest in it. A `peak` of zero
/// draws an empty bar.
fn histogram_row(
    out: &mut dyn Write,
    label: &str,
    count: u64,
    peak: u64,
) -> Result<(), ExportError> {
    let width = if peak == 0 {
        0.0
    } else {
        count as f64 * 100.0 / peak as f64
    };
    let zero = if count == 0 { " bar-zero" } else { "" };

    writeln!(
        out,
        "<tr><th>{label}</th><td><span class=\"bar-track\"><span class=\"bar{zero}\" style=\"width:{width:.3}%\"></span></span></td><td class=\"num\">{count}</td></tr>",
        label = Text(label),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Colophon
// ---------------------------------------------------------------------------

/// The footer: which engine wrote the page, against which schema, and when.
///
/// The findings attribution comes from whatever wrote an imported or merged
/// document, so it is escaped.
fn write_colophon(
    out: &mut dyn Write,
    report: &ScanReport,
    generated_at: &str,
) -> Result<(), ExportError> {
    writeln!(
        out,
        r#"<footer class="colophon">
<div>{engine} {version}{findings} · schema {schema} · generated {generated}</div>
<div>self-contained: no scripts, no external requests</div>
</footer>"#,
        engine = ENGINE_NAME,
        version = crate::report::ENGINE_VERSION,
        findings = findings_from(report),
        schema = SCHEMA_VERSION,
        generated = Text(generated_at),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

/// One label/value row of a fact list. `value` is markup the caller escaped.
///
/// A row with nothing in it is not written.
fn fact(out: &mut dyn Write, key: &str, value: &str) -> Result<(), ExportError> {
    if value.is_empty() {
        return Ok(());
    }
    writeln!(out, "<dt>{key}</dt><dd>{value}</dd>", key = Text(key))?;
    Ok(())
}

/// What made a report partial, a clause each, in the order a reader would
/// look for them: the faults first, then the ground left unfinished.
///
/// Names exactly the causes [`ScanReport::is_partial`] counts; a journal that
/// fell behind or a resolver that failed narrows no coverage. A failed strategy
/// and one a limit cut short are named apart, since one points at a fault and
/// the other at the limit.
fn shortfalls(report: &ScanReport) -> Vec<&'static str> {
    let mut causes = Vec::new();
    let narrowing = || {
        report
            .failures()
            .filter(|failure| failure.narrows_coverage())
    };
    if narrowing().any(|failure| !failure.is_cut_short()) {
        causes.push("a strategy failed");
    }
    if narrowing().any(ScannerFailure::is_cut_short) {
        causes.push("a strategy was cut short by a limit");
    }
    if report.refusals().next().is_some() {
        causes.push("ground was declined");
    }
    if !report.timed_out().is_empty() {
        causes.push("a host's time budget ran out");
    }
    if !report.undecided().is_empty() {
        causes.push("addresses were never decided");
    }
    if report.left_ports_unasked() {
        causes.push("ports went unasked");
    }
    if report.unreached() > 0 {
        causes.push("targets were never asked");
    }
    if !report.passes_cut().is_empty() {
        causes.push("a stop cut passes over the findings short");
    }
    causes
}

/// How many addresses `ranges` hold, read back off their rendered ends.
///
/// A range whose ends do not parse as one family's addresses adds nothing, so
/// the count can fall short but never overstate.
fn addresses_in(ranges: &[RangeDto]) -> u128 {
    ranges
        .iter()
        .filter_map(|range| {
            let start: std::net::IpAddr = range.start.parse().ok()?;
            let end: std::net::IpAddr = range.end.parse().ok()?;
            match (start, end) {
                (std::net::IpAddr::V4(start), std::net::IpAddr::V4(end)) => {
                    Some(u128::from(end.to_bits().checked_sub(start.to_bits())?) + 1)
                }
                (std::net::IpAddr::V6(start), std::net::IpAddr::V6(end)) => {
                    end.to_bits().checked_sub(start.to_bits())?.checked_add(1)
                }
                _ => None,
            }
        })
        .fold(0u128, u128::saturating_add)
}

/// A build as the report shows it: the distributor, then the release and the
/// package revision where they are known.
fn build_text(build: &super::schema::BuildDto<'_>) -> String {
    let mut parts: Vec<&str> = vec![distributor_label(build.distributor)];
    if let Some(release) = &build.release {
        parts.push(&release.name);
    }
    if let Some(revision) = &build.revision {
        parts.push(revision);
    }
    parts.join(" ")
}

/// The label for a distributor's wire name, which is what the document holds.
fn distributor_label(wire_name: &str) -> &str {
    crate::record::wire::distributor(wire_name)
        .map(crate::model::port::Distributor::label)
        .unwrap_or(wire_name)
}

/// The secondary half of a value, drawn dimmed.
///
/// Renders to nothing when every part is empty, so a caller can append it
/// unconditionally.
fn dim(parts: &[String]) -> String {
    let parts: Vec<&str> = parts
        .iter()
        .map(String::as_str)
        .filter(|part| !part.is_empty())
        .collect();

    if parts.is_empty() {
        return String::new();
    }
    format!(" <span class=\"dim\">{}</span>", parts.join(" · "))
}

/// Renders microseconds the way somebody reads them.
///
/// The JSON keeps microseconds; the page picks a unit and shows two decimals.
fn duration(micros: u64) -> String {
    match micros {
        0..1_000 => format!("{micros} µs"),
        1_000..1_000_000 => format!("{:.2} ms", micros as f64 / 1_000.0),
        1_000_000..60_000_000 => format!("{:.2} s", micros as f64 / 1_000_000.0),
        _ => {
            let seconds = micros / 1_000_000;
            format!("{} min {} s", seconds / 60, seconds % 60)
        }
    }
}

/// A share of a whole, as a percentage; 0 when the whole is 0.
fn percent(part: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    part as f64 * 100.0 / total as f64
}

/// Picks a noun's form for a count.
fn plural(count: usize, one: &'static str, many: &'static str) -> &'static str {
    if count == 1 { one } else { many }
}

/// Picks a noun's form for a count too large for a `usize`: the address and probe
/// totals, which are decimal strings because an IPv6 sweep's can exceed any
/// integer type.
fn plural_str(count: &str, one: &'static str, many: &'static str) -> &'static str {
    if count == "1" { one } else { many }
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
    use crate::export::write::STYLE;
    use crate::export::{Redaction, fixture};

    fn page(exporter: &HtmlExporter) -> String {
        let mut bytes = Vec::new();
        exporter
            .export(&fixture::report(), &mut bytes)
            .expect("the export succeeds");
        String::from_utf8(bytes).expect("utf-8")
    }

    fn default_page() -> String {
        page(&HtmlExporter::new(ExportOptions::new()))
    }

    /// Every class the exporter wrote, in the order it wrote them.
    fn classes(page: &str) -> Vec<String> {
        let mut found = Vec::new();
        let mut rest = page;

        while let Some(start) = rest.find("class=\"") {
            rest = &rest[start + "class=\"".len()..];
            let end = rest.find('"').expect("an unterminated class attribute");
            for class in rest[..end].split_whitespace() {
                found.push(class.to_string());
            }
            rest = &rest[end..];
        }
        found
    }

    /// Failed sends include unreachable addresses as well as sender refusals,
    /// so the page says only that they never left.
    #[test]
    fn sends_that_never_left_are_not_all_called_refused() {
        let mut stats = fixture::probe_stats();
        stats.sends_failed = 3;

        let mut bytes = Vec::new();
        write_probe_stats(&mut bytes, &ProbeStatsDto::new(&stats)).expect("the block renders");
        let block = String::from_utf8(bytes).expect("utf-8");

        assert!(block.contains("3 never left this host"), "{block}");
        assert!(!block.contains("refused"), "{block}");
    }

    /// The rate a scanner achieved stands beside the probes it sent.
    #[test]
    fn a_scanners_block_says_how_fast_it_sent() {
        let mut stats = fixture::probe_stats();
        stats.sends_attempted = 500;
        stats.elapsed = std::time::Duration::from_millis(250);

        let mut bytes = Vec::new();
        write_probe_stats(&mut bytes, &ProbeStatsDto::new(&stats)).expect("the block renders");
        let block = String::from_utf8(bytes).expect("utf-8");

        assert!(block.contains("500 attempted · 2000/s"), "{block}");
    }

    /// A complete document that reaches nothing outside itself.
    #[test]
    fn the_page_is_one_self_contained_document() {
        let page = default_page();

        assert!(page.starts_with("<!doctype html>"));
        assert!(page.trim_end().ends_with("</html>"));
        assert!(page.contains("<meta charset=\"utf-8\">"));

        for outside in ["<script", "http://", "https://", "<img", "@import", "url("] {
            assert!(
                !page.contains(outside),
                "the page reaches outside itself: {outside}"
            );
        }
    }

    /// A class the stylesheet does not define renders as nothing.
    #[test]
    fn every_class_written_is_a_class_the_stylesheet_styles() {
        for class in classes(&default_page()) {
            assert!(
                STYLE.contains(&format!(".{class}")),
                "nothing styles .{class}"
            );
        }
    }

    /// The compiler checks the tone match; this checks the stylesheet.
    #[test]
    fn every_state_has_a_tone_the_stylesheet_defines() {
        let statuses = [
            HostStatus::Up,
            HostStatus::Blocked,
            HostStatus::Down,
            HostStatus::Unknown,
        ];
        let states = [
            PortState::Open,
            PortState::OpenOrNoReply,
            PortState::Closed,
            PortState::Reachable,
            PortState::NoReply,
            PortState::ClosedOrNoReply,
        ];

        for status in statuses {
            let tone = host_tone(status);
            assert!(
                STYLE.contains(&format!(".{tone}")),
                "nothing styles .{tone}"
            );
        }
        for state in states {
            let tone = port_tone(state);
            assert!(
                STYLE.contains(&format!(".{tone}")),
                "nothing styles .{tone}"
            );
        }
    }

    /// The findings, in the places a reader looks for them.
    #[test]
    fn the_page_shows_what_the_scan_found() {
        let page = default_page();

        assert!(page.contains("203.0.113.1"));
        assert!(page.contains("router.local"));
        assert!(page.contains("22/tcp"));
        assert!(page.contains("OpenSSH"));
        assert!(page.contains("8.9p1"));
        assert!(page.contains("Raspberry Pi Trading Ltd"));
        assert!(page.contains("Local CA"));
        // The instrumentation, which tells a sweep that ran out of time from
        // one that finished.
        assert!(page.contains("deadline_expired"));
        assert!(page.contains("raw socket unavailable"));
    }

    /// The facts that change what a state on this page means are on the page:
    /// an idle scan and an evasion profile change every port state under them.
    #[test]
    fn what_changes_the_meaning_of_a_state_reaches_the_page() {
        let page = default_page();

        for expected in [
            // The two notices at the top.
            "idle scan",
            "evasion",
            "inferred from a third party",
            "altered before they went out",
            // The per-phase detail.
            "detection ",
            "where this ran from",
        ] {
            assert!(page.contains(expected), "the page never says {expected:?}");
        }
    }

    /// The addresses a phase never decided reach the page with their count, so
    /// they do not read as silent.
    #[test]
    fn what_a_phase_never_decided_reaches_the_page() {
        let report = fixture::report();
        let undecided: u128 = report
            .phases()
            .iter()
            .flat_map(|phase| phase.undecided())
            .map(|range| {
                let (start, end) = match range {
                    crate::model::ip::range::IpRange::V4(range) => (
                        u128::from(range.start_addr().to_bits()),
                        u128::from(range.end_addr().to_bits()),
                    ),
                    crate::model::ip::range::IpRange::V6(range) => {
                        (range.start_addr().to_bits(), range.end_addr().to_bits())
                    }
                };
                end - start + 1
            })
            .sum();
        assert!(undecided > 1, "the fixture leaves addresses undecided");

        let page = default_page();
        assert!(page.contains("<dt>undecided</dt>"), "{page}");
        assert!(
            page.contains(&format!("{undecided} addresses with no verdict")),
            "the count is what a reader acts on"
        );
    }

    /// A router whose address was withheld answered, so it reads as excluded
    /// and not as the `*` of a quiet router.
    #[test]
    fn a_withheld_router_is_not_drawn_as_silence() {
        let page = default_page();

        assert!(page.contains("<div> 4. excluded"), "{page}");
        assert!(
            page.contains("<div> 2. *"),
            "a silent router still reads as one"
        );
    }

    /// Evidence a middlebox sent names it, and evidence from a withheld one
    /// says it came second-hand, so neither reads as the host's own answer.
    #[test]
    fn second_hand_evidence_says_who_sent_it() {
        let page = default_page();

        assert!(
            page.contains("unreachable, from the path · via 198.51.100.1"),
            "{page}"
        );
        assert!(
            page.contains("unreachable · via an excluded address"),
            "{page}"
        );
    }

    /// An enumeration that did not finish says so beside what it found, so an
    /// unanswered version does not read as refused or a cut list as complete.
    #[test]
    fn an_unfinished_enumeration_says_so_on_the_page() {
        let page = default_page();

        assert!(
            page.contains("<dt>unsettled</dt><dd>TLSv1.1"),
            "a version never settled is named"
        );
        assert!(
            page.contains("incomplete, stopped"),
            "an accepted version whose walk was cut short says so"
        );
    }

    /// An ordinary phase carries none of the notices, so they stay worth
    /// reading.
    #[test]
    fn an_ordinary_scan_carries_none_of_those_notices() {
        let mut plain = Vec::new();
        HtmlExporter::new(ExportOptions::new())
            .export(&crate::export::fixture::compared().0, &mut plain)
            .expect("the page writes");
        let page = String::from_utf8(plain).expect("valid UTF-8");

        assert!(!page.contains("idle scan"));
        assert!(!page.contains("altered before they went out"));
        assert!(!page.contains("where this ran from"));
    }

    /// A report narrower than the scan asked for says so above the findings.
    #[test]
    fn a_narrowed_report_says_so_before_the_findings() {
        let page = default_page();
        let notice = page.find(">partial<").expect("a partial notice");
        let hosts = page.find("Hosts <span").expect("a host section");

        assert!(notice < hosts, "the notice sits below the findings");
        for cause in [
            "a strategy failed",
            "a strategy was cut short by a limit",
            "a stop cut passes over the findings short",
            "a host's time budget ran out",
            "addresses were never decided",
        ] {
            assert!(
                page[notice..hosts].contains(&esc(cause)),
                "the notice never names {cause:?}, which the fixture has"
            );
        }
    }

    /// States keep the JSON's spelling, so grepping the document finds them.
    #[test]
    fn states_are_spelled_the_way_the_document_spells_them() {
        let page = default_page();

        assert!(page.contains(">open<"));
        assert!(page.contains(">up<"));
        assert!(page.contains(">blocked<"));
        assert!(page.contains(">no_reply<"));
        assert!(page.contains(">tcp_syn_ack<"));
    }

    /// The page honours redaction everywhere the JSON does.
    #[test]
    fn redaction_reaches_the_page() {
        let page = page(&HtmlExporter::new(
            ExportOptions::new().with_redaction(Redaction::Standard),
        ));

        assert!(!page.contains("router.local"));
        assert!(page.contains("roXXXXXal"));
        // The names the host gave for itself, the domain among them.
        assert!(!page.contains("corp.example"));
        assert!(page.contains("gwXXXXXle"));
        assert!(page.contains("2c:cf:67:XX:XX:XX"));
        // The vendor comes from the OUI, which masking preserves.
        assert!(page.contains("Raspberry Pi Trading Ltd"));
        // And the page says this copy is masked.
        assert!(page.contains(">redacted<"));
    }

    /// A host with no ports still appears, saying so.
    #[test]
    fn a_host_with_no_ports_still_appears() {
        let page = default_page();

        assert!(page.contains("203.0.113.9"));
        assert!(page.contains("no ports recorded"));
    }

    #[test]
    fn a_caller_can_name_the_report() {
        let page = page(&HtmlExporter::new(ExportOptions::new()).with_heading("Acme Q3 audit"));

        assert!(page.contains("<title>Acme Q3 audit</title>"));
        assert!(page.contains("<h1>Acme Q3 audit</h1>"));
        assert!(default_page().contains("<title>zond scan report — "));
    }

    #[test]
    fn durations_are_rendered_for_a_person() {
        assert_eq!(duration(0), "0 µs");
        assert_eq!(duration(999), "999 µs");
        assert_eq!(duration(1_450), "1.45 ms");
        assert_eq!(duration(677_669), "677.67 ms");
        assert_eq!(duration(1_500_000), "1.50 s");
        assert_eq!(duration(3_723_000_000), "62 min 3 s");
    }

    #[test]
    fn a_share_of_nothing_is_not_a_division_by_zero() {
        assert_eq!(percent(0, 0), 0.0);
        assert_eq!(percent(1, 4), 25.0);
    }

    #[test]
    fn a_failing_destination_surfaces_as_an_error() {
        struct Full;

        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    "no space left on device",
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let error = HtmlExporter::new(ExportOptions::new())
            .export(&fixture::report(), &mut Full)
            .expect_err("a full disk fails the export");

        assert!(matches!(error, ExportError::Io(_)), "got {error:?}");
    }

    /// Every attacker-controlled string in a report reaches the page escaped.
    ///
    /// One payload in every string the schema carries, rendered as a whole
    /// page, so a new field written straight into the markup fails. A string
    /// added to the schema has to reach
    /// [`fixture::hostile`](crate::export::fixture::hostile) too.
    #[test]
    fn no_field_of_a_hostile_report_reaches_the_page_unescaped() {
        let mut bytes = Vec::new();
        HtmlExporter::new(ExportOptions::new())
            .export(&fixture::hostile(), &mut bytes)
            .expect("the page renders");
        let page = String::from_utf8(bytes).expect("utf-8");

        assert!(
            page.contains("&lt;script&gt;"),
            "the payload should be present, escaped - otherwise this test proves \
             nothing about a document that simply dropped it"
        );
        assert!(
            !page.contains("<script>"),
            "a scanned host's own banner opened a script tag in the report"
        );
        assert!(
            !page.contains(fixture::HOSTILE),
            "the payload survived intact somewhere on the page"
        );
        // The bidi override invisibly reorders everything after it, so it is
        // neutralized, not just escaped.
        assert!(
            !page.contains('\u{202e}'),
            "a right-to-left override reached the page and will reorder it"
        );
    }
}
