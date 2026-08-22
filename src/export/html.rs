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
//! The stylesheet is inlined and there is no image, no font, no favicon and no
//! request of any kind to anywhere. A scan report travels as an email
//! attachment, as an artifact on a ticket, as a file on a share; each of those
//! is a place where a request to a CDN either quietly fails and leaves the
//! reader with unstyled text, or succeeds and tells a third party that the
//! report was opened, when, and from which address. Neither is acceptable in a
//! document that lists somebody's internal network.
//!
//! ## No JavaScript at all
//!
//! Not "no third-party JavaScript" - none. The output of a security tool should
//! not need code execution to be read, because the places it is read are exactly
//! the places where scripts are blocked: a mail client, a restricted
//! documentation viewer, a browser with strict settings, a reviewer who has been
//! told never to run a page that an unknown network's data produced.
//!
//! Two things a reader might otherwise expect follow from this and are worth
//! stating plainly. **Sorting and filtering the host list are not available** -
//! [`csv`](super::csv) exists for the person who wants to sort, and it opens in
//! the tool they would sort with. **The light/dark switch is CSS**: the system
//! preference decides through `prefers-color-scheme`, and the control in the
//! masthead inverts whatever it decided, with `:has()` doing the work. A browser
//! too old for `:has()` still follows the system preference, and hides a control
//! that could not have functioned.
//!
//! ## Printing is a first-class output
//!
//! There is no PDF exporter and there will not be one; a PDF crate costs more
//! than a lightweight engine should spend. An `@media print` stylesheet is the
//! answer instead: ink-cheap colours, no control that only exists to be clicked,
//! and no host split across a page boundary. `Ctrl-P` produces the document that
//! goes in the appendix.
//!
//! ## Escaping is the security control here
//!
//! A scan report is full of text the scanned network chose: hostnames, service
//! banners, certificate subjects, script output. Written into a page unescaped,
//! a device named `<script>…</script>` executes on whoever opens the report -
//! the same class of attack the CSV exporter neutralises for spreadsheets.
//!
//! Everything from the report therefore goes through one escaping writer. It
//! escapes the five characters that carry markup, and renders control characters
//! as their code point rather than emitting them. That second part is not
//! decoration: a hostname containing U+202E reverses the text that follows it,
//! which is how a report is made to display one address while carrying another.
//! No value from a report is ever written into an attribute, so there is one
//! escaping context in the whole exporter and no way to pick the wrong one.
//!
//! ## What the page says, and what it leaves out
//!
//! The page renders the same [`schema`](super::schema) DTOs the JSON serializes,
//! so the two cannot disagree about a value, an ordering or a name. States,
//! protocols and stop reasons keep their wire spelling - a reader who greps the
//! JSON for what they saw in the browser finds it.
//!
//! It parts company with the document in one way, deliberately: **a field with
//! no value is not shown.** The JSON keeps every field so a parser never has to
//! tell absent from empty from unknown; a page has a different scarce resource,
//! which is the reader's attention, and a host described by fourteen empty rows
//! is a host nobody reads.

use std::borrow::Cow;
use std::fmt::{self, Write as _};
use std::io::Write;
use std::time::SystemTime;

use crate::export::schema::{
    ENGINE_NAME, HostDto, PhaseDto, PortDto, ProbeStatsDto, SCHEMA_VERSION, SummaryDto,
    host_status_name, port_state_name, scan_kind_name, total_elapsed_us,
};
use crate::export::time::rfc3339;
use crate::export::{ExportError, ExportOptions, Exporter};
use crate::model::host::{Host, HostStatus};
use crate::model::port::{Port, PortState};
use crate::scanner::report::ScanReport;

/// The stylesheet inlined into every report.
///
/// A file of its own rather than a string in this one: it is a stylesheet, it is
/// edited as a stylesheet, and a test pins the class names it defines to the
/// ones written here.
const STYLE: &str = include_str!("../../assets/html/report.css");

/// The heading a report carries when the caller names none.
const DEFAULT_HEADING: &str = "Scan report";

/// How many columns a host's port table has.
const PORT_COLUMNS: usize = 7;

// ---------------------------------------------------------------------------
// Tones
//
// Four of them, rather than one colour per state name. The state's name is
// always printed beside its colour, so the colour is free to carry something
// the name does not: how much the finding is worth a second look.
// ---------------------------------------------------------------------------

/// Something is there and answering: `up`, `open`.
const TONE_FOUND: &str = "s-found";

/// Something is there and the scan could not pin it down. Drawn hatched as well
/// as coloured, because green against amber is the pair a colour-blind reader
/// loses first and a printed report is often greyscale.
const TONE_PARTIAL: &str = "s-partial";

/// A definite negative: `down`, `closed`. Real evidence, and rarely what the
/// reader came for.
const TONE_INERT: &str = "s-inert";

/// Nothing was established at all.
const TONE_NONE: &str = "s-none";

/// The tone a host status is drawn in.
fn host_tone(status: HostStatus) -> &'static str {
    match status {
        HostStatus::Up => TONE_FOUND,
        HostStatus::Filtered => TONE_PARTIAL,
        HostStatus::Down => TONE_INERT,
        HostStatus::Unknown => TONE_NONE,
    }
}

/// The tone a port state is drawn in.
fn port_tone(state: PortState) -> &'static str {
    match state {
        PortState::Open => TONE_FOUND,
        PortState::OpenFiltered
        | PortState::Filtered
        | PortState::Unfiltered
        | PortState::ClosedFiltered => TONE_PARTIAL,
        PortState::Closed => TONE_INERT,
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
/// use zond_engine::scanner::report::ScanReport;
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
    /// For a front end that knows what the scan was *for* - an engagement, a
    /// change number, a customer - which the engine never does.
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
    /// Carries the scan's date when the caller named nothing, because a tab and
    /// a printed page header are where several reports get told apart.
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
        let phases: Vec<PhaseDto<'_>> = report.phases().iter().map(PhaseDto::new).collect();
        let elapsed_us = total_elapsed_us(&phases);

        write_head(out, &self.title(&started_at), report)?;
        write_masthead(out, self.heading(), report, &started_at, elapsed_us)?;
        write_notices(out, report, &phases, &self.options)?;
        write_tiles(out, &summary, &phases)?;
        write_distributions(out, &summary)?;
        write_hosts(out, report, &self.options)?;
        write_scan_detail(out, &phases)?;
        write_colophon(out, report, &generated_at)?;

        out.write_all(b"</div>\n</body>\n</html>\n")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// The head, the stylesheet, and everything down to the open page container.
fn write_head(out: &mut dyn Write, title: &str, report: &ScanReport) -> Result<(), ExportError> {
    writeln!(
        out,
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="{engine} {version}">
<meta name="robots" content="noindex, nofollow">
<title>{title}</title>
<style>
{style}</style>
</head>
<body>
<input type="checkbox" id="zond-theme" class="theme-switch" aria-label="Use the other colour scheme">
<div class="sheet">"#,
        engine = ENGINE_NAME,
        version = report.engine_version(),
        title = Plain(title),
        style = STYLE,
    )?;
    Ok(())
}

/// The brand, the heading, a one-line description of the scan, and the switch.
///
/// The description states no total the schema does not define. A figure that
/// appears nowhere else is a figure nobody can check.
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

    writeln!(
        out,
        r#"<header class="masthead">
<div class="brand">zond<span class="brand-mark">_</span></div>
<div class="masthead-title">
<h1>{heading}</h1>
<p class="subtitle">{kinds} · started {started_at} · {elapsed} · {count} {word}</p>
</div>
<label class="theme-label" for="zond-theme" title="Switch between light and dark"><span class="theme-icon"></span>theme</label>
</header>"#,
        heading = Text(heading),
        kinds = kinds.join(" + "),
        started_at = Text(started_at),
        elapsed = duration(elapsed_us),
        word = plural(count, "phase", "phases"),
    )?;
    Ok(())
}

/// The three things that change how the rest of the page should be read.
///
/// Each is a fact about the report rather than about the network, and each makes
/// the findings narrower than they look: a partial scan did not finish, an
/// unprivileged one saw less, a redacted one is not showing everything it knows.
fn write_notices(
    out: &mut dyn Write,
    report: &ScanReport,
    phases: &[PhaseDto<'_>],
    options: &ExportOptions,
) -> Result<(), ExportError> {
    let unprivileged = phases.iter().filter(|phase| !phase.privileged).count();

    if !report.is_partial() && unprivileged == 0 && !options.redaction.is_active() {
        return Ok(());
    }

    writeln!(out, "<p class=\"notices\">")?;

    if report.is_partial() {
        notice(
            out,
            true,
            "partial",
            "a strategy did not run to completion, so these findings are narrower than the scan asked for",
        )?;
    }
    if unprivileged > 0 {
        notice(
            out,
            true,
            "unprivileged",
            "raw probes were unavailable; those targets were reached over plain connect attempts, which see less",
        )?;
    }
    if options.redaction.is_active() {
        notice(
            out,
            false,
            "redacted",
            "hostnames, hardware addresses and certificate subjects are masked in this copy",
        )?;
    }

    writeln!(out, "</p>")?;
    Ok(())
}

/// One notice.
fn notice(out: &mut dyn Write, alert: bool, key: &str, text: &str) -> Result<(), ExportError> {
    let class = if alert {
        "notice notice-alert"
    } else {
        "notice"
    };

    writeln!(
        out,
        "<span class=\"{class}\"><span class=\"notice-key\">{key}</span><span>{text}</span></span>",
        key = Text(key),
        text = Text(text),
    )?;
    Ok(())
}

/// The four figures somebody reads before they read anything else.
fn write_tiles(
    out: &mut dyn Write,
    summary: &SummaryDto,
    phases: &[PhaseDto<'_>],
) -> Result<(), ExportError> {
    writeln!(out, "<section class=\"tiles\">")?;

    tile(out, summary.hosts_total, "hosts", &ranges_note(phases))?;
    tile(
        out,
        summary.hosts_alive,
        "alive",
        &esc("up or filtered — confirmed present"),
    )?;
    tile(
        out,
        summary.ports_open,
        "open ports",
        &format!("of {} recorded", summary.ports_total),
    )?;
    tile(
        out,
        summary.services_identified,
        "services",
        &esc("identified by fingerprinting"),
    )?;

    writeln!(out, "</section>")?;
    Ok(())
}

/// One headline figure. `note` is markup the caller escaped.
fn tile(out: &mut dyn Write, value: usize, label: &str, note: &str) -> Result<(), ExportError> {
    writeln!(
        out,
        "<div class=\"tile\"><div class=\"tile-value\">{value}</div><div class=\"tile-label\">{label}</div><div class=\"tile-note\">{note}</div></div>",
        label = Text(label),
    )?;
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
/// A stacked meter and a legend listing every category, including the ones
/// nothing landed in - the rule the JSON summary follows, for the same reason: a
/// reader learns something from `filtered: 0` and nothing from a category that
/// is simply missing.
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
            status_slice(HostStatus::Filtered, statuses.filtered),
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
            state_slice(PortState::OpenFiltered, states.open_filtered),
            state_slice(PortState::Closed, states.closed),
            state_slice(PortState::Unfiltered, states.unfiltered),
            state_slice(PortState::Filtered, states.filtered),
            state_slice(PortState::ClosedFiltered, states.closed_filtered),
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

fn status_slice(status: HostStatus, count: usize) -> Slice {
    Slice {
        label: host_status_name(status),
        tone: host_tone(status),
        count,
    }
}

fn state_slice(state: PortState, count: usize) -> Slice {
    Slice {
        label: port_state_name(state),
        tone: port_tone(state),
        count,
    }
}

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

    // One host is rendered, written and dropped before the next is built, which
    // is what keeps a scan of any size costing a host's worth of memory to
    // export.
    for host in report.hosts() {
        write_host(out, host, options)?;
    }

    writeln!(out, "</section>")?;
    Ok(())
}

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

    if dto.ips.len() > 1 {
        let addresses: Vec<String> = dto.ips.iter().map(|ip| esc(ip)).collect();
        fact(out, "addresses", &addresses.join(", "))?;
    }

    if let Some(os) = &dto.os {
        let mut detail = vec![format!("{}% confidence", os.accuracy)];
        if let Some(family) = os.family {
            detail.push(esc(family));
        }
        if let Some(vendor) = os.vendor {
            detail.push(esc(vendor));
        }
        let name = match os.generation {
            Some(generation) => format!("{} {}", esc(os.name), esc(generation)),
            None => esc(os.name),
        };
        fact(out, "os", &format!("{name}{}", dim(&detail)))?;
    }

    if let Some(hardware) = &dto.hardware {
        let mut value = hardware.mac.as_deref().map(esc).unwrap_or_default();
        let mut detail = Vec::new();
        if let Some(vendor) = hardware.vendor {
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
        // One line per router, distance first, so a reader can see a gap where a
        // router declined to answer rather than reading a shorter path than the
        // one measured. An inherited hop says so: it is a claim about a router
        // this host's own probes never met.
        let mut path = String::new();
        for hop in &dto.path {
            let address = hop.address.as_deref().unwrap_or("*");
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

    let mut evidence = String::new();
    for reason in &dto.reasons {
        let detail: Vec<String> = reason.details.map(esc).into_iter().collect();
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

fn write_ports(out: &mut dyn Write, host: &Host, dto: &HostDto<'_>) -> Result<(), ExportError> {
    if dto.ports.is_empty() {
        writeln!(out, "<p class=\"empty\">no ports recorded</p>")?;
        return Ok(());
    }

    writeln!(
        out,
        "<div class=\"scroll\">\n<table class=\"table\">\n<thead><tr><th>port</th><th>state</th><th>service</th><th>product</th><th>version</th><th class=\"num\">rtt</th><th>evidence</th></tr></thead>\n<tbody>"
    )?;

    // The DTO's ports and the host's are one sequence: `HostDto` builds the
    // first from the second, in order. Pairing them lets a row carry the
    // document's values and take its colour from the state itself, without
    // rendering either of them twice.
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
        service.map(|service| esc(service.name)).unwrap_or_default()
    )?;
    write!(
        out,
        "<td>{}</td>",
        service
            .and_then(|service| service.product)
            .map(esc)
            .unwrap_or_default()
    )?;

    let version = service
        .map(|service| {
            let mut text = service.version.map(esc).unwrap_or_default();
            if let Some(extra) = service.extrainfo {
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

/// The second row a port gets when there is more to say than fits in a column.
fn write_port_detail(out: &mut dyn Write, dto: &PortDto<'_>) -> Result<(), ExportError> {
    let mut facts = String::new();

    if let Some(service) = &dto.service {
        let cpes: Vec<String> = service.cpe.iter().map(|cpe| esc(cpe)).collect();
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

        if let Some(certificate) = &security.certificate {
            let mut detail = vec![format!("issued by {}", esc(certificate.issuer))];
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
            detail.push(format!("answered on {}", esc(source)));
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

/// What the scan did, as opposed to what it found.
///
/// Last on the page rather than first: a reader opens a report for the hosts.
/// This is the section that says how far the host list can be trusted, and it is
/// where somebody who has already read the findings comes back to.
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

fn write_phase(out: &mut dyn Write, phase: &PhaseDto<'_>) -> Result<(), ExportError> {
    let privilege = if phase.privileged {
        "privileged"
    } else {
        "unprivileged"
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

    // Only when a policy was set. "excluded: nothing" on every report of every
    // scan that never configured one is noise, and worse, it trains a reader to
    // skip the row on the one report where it says something.
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
    let rate = match settings.max_probe_rate {
        Some(rate) => format!("max {rate} probes/s"),
        None => "scanner default rate".to_string(),
    };
    let dns = if settings.dns_enabled {
        "dns enabled"
    } else {
        "dns disabled"
    };
    // The technique leads, because it is what a reader needs before the port
    // table underneath means anything: `closed` from a SYN scan and `closed`
    // from a FIN scan are different findings.
    fact(
        out,
        "wire",
        &format!(
            "{} · send {} · {rate} · {dns} · os {} · service {}",
            esc(settings.tcp_technique),
            esc(settings.send_mode),
            esc(settings.os_detection),
            esc(settings.service_detection)
        ),
    )?;

    writeln!(out, "</dl>")?;

    if !phase.failures.is_empty() {
        writeln!(
            out,
            "<div class=\"block\">\n<div class=\"block-title\">failures</div>\n<div class=\"scroll\">\n<table class=\"table\">\n<thead><tr><th>scanner</th><th>reason</th><th>at</th></tr></thead>\n<tbody>"
        )?;
        for failure in &phase.failures {
            writeln!(
                out,
                "<tr><td class=\"mono\">{scanner}</td><td>{reason}</td><td class=\"mono\">{at}</td></tr>",
                scanner = Text(failure.scanner),
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
    if stats.sends_failed > 0 {
        sends.push(format!("{} refused by the sender", stats.sends_failed));
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
/// Against the largest rather than against the total: these are distributions
/// where one bucket usually holds nearly everything, and scaling to the total
/// draws every other bucket as an invisible line.
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

fn write_colophon(
    out: &mut dyn Write,
    report: &ScanReport,
    generated_at: &str,
) -> Result<(), ExportError> {
    writeln!(
        out,
        r#"<footer class="colophon">
<div>{engine} {version} · schema {schema} · generated {generated}</div>
<div>self-contained: no scripts, no external requests</div>
</footer>"#,
        engine = ENGINE_NAME,
        version = report.engine_version(),
        schema = SCHEMA_VERSION,
        generated = Text(generated_at),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

/// Report text, escaped for the page as it is written.
///
/// Everything the scanned network chose to call itself passes through here.
/// Beyond the five characters that carry markup, this renders the characters
/// that carry *direction* - U+202E and the rest of the bidirectional set - as
/// their code points instead of emitting them, because a hostname that reverses
/// the text after it makes a report display one thing and mean another. The
/// remaining control characters are shown the same way for the same reason: what
/// a report claims to have found should be legible as bytes.
///
/// This writes markup, so it belongs in element content and nowhere else. No
/// value from a report is written into an attribute anywhere in this module,
/// which is what keeps that a rule rather than something to remember.
struct Text<'a>(&'a str);

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for character in self.0.chars() {
            match character {
                '&' => f.write_str("&amp;")?,
                '<' => f.write_str("&lt;")?,
                '>' => f.write_str("&gt;")?,
                '"' => f.write_str("&quot;")?,
                '\'' => f.write_str("&#39;")?,
                character if is_neutralized(character) => write!(
                    f,
                    "<span class=\"ctl\">U+{:04X}</span>",
                    u32::from(character)
                )?,
                character => f.write_char(character)?,
            }
        }
        Ok(())
    }
}

/// Report text for somewhere markup cannot go.
///
/// The document's title is text, not content: a `<span>` written into it renders
/// as its own source. A neutralized character therefore becomes the replacement
/// character, which already means "something was here that this cannot show"
/// everywhere else.
struct Plain<'a>(&'a str);

impl fmt::Display for Plain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for character in self.0.chars() {
            match character {
                '&' => f.write_str("&amp;")?,
                '<' => f.write_str("&lt;")?,
                '>' => f.write_str("&gt;")?,
                '"' => f.write_str("&quot;")?,
                '\'' => f.write_str("&#39;")?,
                character if is_neutralized(character) => f.write_char('\u{fffd}')?,
                character => f.write_char(character)?,
            }
        }
        Ok(())
    }
}

/// Whether a character is shown as its code point rather than emitted.
///
/// The bidirectional formatting characters are the reason this exists: they
/// reorder the text around them, and a reader cannot see that they are there.
/// The control characters are included because a page renders them as nothing,
/// so a banner containing one would silently lose it.
///
/// Tab, newline and carriage return pass through. They are ordinary whitespace
/// in HTML, they cannot spoof anything, and a script's multi-line output is
/// worth keeping the shape of.
fn is_neutralized(character: char) -> bool {
    matches!(character,
        '\u{0}'..='\u{8}'
        | '\u{b}' | '\u{c}'
        | '\u{e}'..='\u{1f}'
        | '\u{7f}'..='\u{9f}'
        | '\u{61c}'
        | '\u{200e}' | '\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}')
}

/// Escapes one value into markup.
fn esc(text: &str) -> String {
    Text(text).to_string()
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

/// One label/value row of a fact list. `value` is markup the caller escaped.
///
/// A row with nothing in it is not written at all - that is the whole difference
/// between this page and the document it renders.
fn fact(out: &mut dyn Write, key: &str, value: &str) -> Result<(), ExportError> {
    if value.is_empty() {
        return Ok(());
    }
    writeln!(out, "<dt>{key}</dt><dd>{value}</dd>", key = Text(key))?;
    Ok(())
}

/// The secondary half of a value: present, but not what the eye should land on.
///
/// Renders to nothing at all when there is nothing to say, so a caller can
/// append it unconditionally.
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
/// The document keeps every duration in microseconds because a machine should
/// never have to guess a unit. A person reading `677669 µs` has to do arithmetic
/// to learn that the scan took two thirds of a second, so the page does it for
/// them, to three significant figures - more than any of these measurements is
/// accurate to anyway.
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

/// A share of a whole, as a percentage. Nothing of nothing is nothing.
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

/// Picks a noun's form for a count too large to have been counted into a
/// `usize` - the address and probe totals, which are decimal strings because an
/// IPv6 sweep's does not fit anything narrower.
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

    /// What a browser needs before it will render anything at all, and the
    /// property that makes this format worth having.
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

    /// A class the stylesheet does not define renders as nothing, and the file
    /// that would have said so is not the file this exporter lives in.
    #[test]
    fn every_class_written_is_a_class_the_stylesheet_styles() {
        for class in classes(&default_page()) {
            assert!(
                STYLE.contains(&format!(".{class}")),
                "nothing styles .{class}"
            );
        }
    }

    /// The tones are the one place a new enum variant could reach the page
    /// unstyled: the compiler checks the match, and nothing checks that the
    /// stylesheet kept up.
    #[test]
    fn every_state_has_a_tone_the_stylesheet_defines() {
        let statuses = [
            HostStatus::Up,
            HostStatus::Filtered,
            HostStatus::Down,
            HostStatus::Unknown,
        ];
        let states = [
            PortState::Open,
            PortState::OpenFiltered,
            PortState::Closed,
            PortState::Unfiltered,
            PortState::Filtered,
            PortState::ClosedFiltered,
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

        assert!(page.contains("192.168.0.1"));
        assert!(page.contains("router.local"));
        assert!(page.contains("22/tcp"));
        assert!(page.contains("OpenSSH"));
        assert!(page.contains("8.9p1"));
        assert!(page.contains("Raspberry Pi Trading Ltd"));
        // The certificate, whose subject is the one field on a port that names
        // a machine.
        assert!(page.contains("Local CA"));
        // The instrumentation, without which a sweep that ran out of time reads
        // exactly like one that finished.
        assert!(page.contains("deadline_expired"));
        assert!(page.contains("raw socket unavailable"));
    }

    /// A report that is narrower than the scan asked for has to say so where
    /// somebody will see it, which means above the findings.
    #[test]
    fn a_narrowed_report_says_so_before_the_findings() {
        let page = default_page();
        let notice = page.find(">partial<").expect("a partial notice");
        let hosts = page.find("Hosts <span").expect("a host section");

        assert!(notice < hosts, "the notice sits below the findings");
    }

    /// States keep the spelling the JSON gives them, so a reader who greps the
    /// document for what the page showed them finds it.
    #[test]
    fn states_are_spelled_the_way_the_document_spells_them() {
        let page = default_page();

        assert!(page.contains(">open<"));
        assert!(page.contains(">up<"));
        assert!(page.contains(">filtered<"));
        assert!(page.contains(">tcp_syn_ack<"));
    }

    /// A device names itself, and what it calls itself is written into a page
    /// somebody opens. This is the security control of this module.
    #[test]
    fn a_hostname_that_would_execute_is_escaped() {
        let hostile = "<script>alert('pwned')</script>";

        assert_eq!(
            esc(hostile),
            "&lt;script&gt;alert(&#39;pwned&#39;)&lt;/script&gt;"
        );
        assert_eq!(esc("a & b"), "a &amp; b");
        assert_eq!(esc("say \"hi\""), "say &quot;hi&quot;");
    }

    /// A right-to-left override reverses everything after it, so one address can
    /// be made to read as another. It is shown as what it is instead.
    #[test]
    fn direction_and_control_characters_are_shown_rather_than_obeyed() {
        assert_eq!(
            esc("host\u{202e}txt.exe"),
            "host<span class=\"ctl\">U+202E</span>txt.exe"
        );
        assert_eq!(esc("bell\u{7}"), "bell<span class=\"ctl\">U+0007</span>");
        // Whitespace is whitespace, and a script's line breaks are worth having.
        assert_eq!(esc("two\nlines\tapart"), "two\nlines\tapart");
        // A title holds no markup, so the same character degrades instead.
        assert_eq!(Plain("host\u{202e}txt").to_string(), "host\u{fffd}txt");
    }

    /// Redaction is chosen when the report is written, and the page has to
    /// honour it everywhere the JSON does.
    #[test]
    fn redaction_reaches_the_page() {
        let page = page(&HtmlExporter::new(
            ExportOptions::new().with_redaction(Redaction::Standard),
        ));

        assert!(!page.contains("router.local"));
        assert!(page.contains("roXXXXXal"));
        assert!(page.contains("2c:cf:67:XX:XX:XX"));
        // The vendor comes from the OUI, which masking preserves.
        assert!(page.contains("Raspberry Pi Trading Ltd"));
        // And the reader is told this copy is masked.
        assert!(page.contains(">redacted<"));
    }

    /// A discovery sweep finds hosts and no ports. The host still has to appear,
    /// saying there was nothing on it.
    #[test]
    fn a_host_with_no_ports_still_appears() {
        let page = default_page();

        assert!(page.contains("192.168.0.9"));
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

    /// Every attacker-controlled string in a report reaches the page escaped —
    /// not just the hostname somebody thought to write a test for.
    ///
    /// **This is the test that covers a field nobody has added yet.** The two
    /// above check that `esc` escapes; neither would notice a new `PortDto` field
    /// written straight into the markup, because neither renders a page. This
    /// one puts one payload in every string the schema carries, renders the whole
    /// document, and asserts the payload never survives intact anywhere in it.
    ///
    /// What it cannot catch is a field the fixture does not set. Adding a string
    /// to the schema means adding it to
    /// [`fixture::hostile`](crate::export::fixture::hostile) as well, and that is
    /// the whole maintenance burden of this test.
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
        // The bidi override reorders everything after it and is invisible while
        // doing so, which is the whole reason it is neutralized rather than
        // merely escaped.
        assert!(
            !page.contains('\u{202e}'),
            "a right-to-left override reached the page and will reorder it"
        );
    }
}
