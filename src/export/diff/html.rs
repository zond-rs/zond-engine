// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A comparison as a page
//!
//! What changed, in one file, opened in a browser and read by a person. The
//! digest a nightly job attaches to an email, where [`json`](super::json) is
//! what its pipeline ingests.
//!
//! Everything [`export::html`](crate::export::html) commits to holds here
//! unchanged, and for the same reasons: the stylesheet is inlined and nothing
//! is fetched from anywhere, there is no JavaScript at all, printing is a
//! first-class output, and every value a scanned network chose goes through the
//! same escaping writer. The escaper, the stylesheet and the frame the two
//! pages share all live in `export::write`, so there is one of each and no
//! second copy to keep in step.
//!
//! ## What a comparison page leads with
//!
//! Not the hosts. A report's reader is looking for a host; a comparison's reader
//! is asking whether anything happened, and usually wants the answer without
//! scrolling. So the page opens with the counts, and each headline count states
//! how much of it the other scan is known to have looked for — the number the
//! whole comparison is arranged to protect, and the one an email skims past if
//! it is not said out loud.
//!
//! ## Three states, carried by colour
//!
//! A host is one the later scan gained, one it lost, or one both hold. That is
//! the first thing to see and it costs a border rather than a line of prose, so
//! a reader running down the left edge takes in the shape of the night before
//! reading a word of it.
//!
//! ## A change unconfirmed is a change said differently
//!
//! Where the other scan is not known to have covered a host, the card says so.
//! Suppressing those would hide a finding; showing them as though they were
//! findings about the network is what makes a monitoring tool cry wolf. They are
//! shown, and they are labelled.

use std::io::Write;

use crate::diff::{HostDelta, Presence, ScanDiff};
use crate::export::diff::DiffExporter;
use crate::export::diff::schema::{ChangeDto, DiffDto, HostDeltaDto, PortDeltaDto};
use crate::export::schema::ENGINE_NAME;
use crate::export::write::{TONE_FOUND, TONE_INERT, TONE_NONE, TONE_PARTIAL, Text, esc};
use crate::export::{ExportError, ExportOptions, write};
use crate::report::ENGINE_VERSION;

/// What the page is called when a caller names nothing.
const DEFAULT_HEADING: &str = "Scan comparison";

/// Writes a comparison as one self-contained HTML page.
///
/// ```no_run
/// use std::fs::File;
/// use zond_engine::diff::ScanDiff;
/// use zond_engine::export::diff::{DiffExporter, HtmlDiffExporter};
///
/// # fn example(diff: &ScanDiff) -> Result<(), Box<dyn std::error::Error>> {
/// let mut file = File::create("changes.html")?;
/// HtmlDiffExporter::default().export(diff, &mut file)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct HtmlDiffExporter {
    options: ExportOptions,
    heading: Option<String>,
}

impl HtmlDiffExporter {
    /// An exporter under `options`.
    pub fn new(options: ExportOptions) -> Self {
        Self {
            options,
            heading: None,
        }
    }

    /// Sets the heading, for a page that is about a named engagement rather
    /// than about a comparison in the abstract.
    pub fn with_heading(mut self, heading: impl Into<String>) -> Self {
        self.heading = Some(heading.into());
        self
    }

    /// The options in force.
    pub fn options(&self) -> &ExportOptions {
        &self.options
    }
}

impl DiffExporter for HtmlDiffExporter {
    fn export(&self, diff: &ScanDiff, out: &mut dyn Write) -> Result<(), ExportError> {
        let document = DiffDto::new(diff, &self.options);
        let heading = self.heading.as_deref().unwrap_or(DEFAULT_HEADING);

        write::head(out, heading)?;
        write_masthead(out, heading, &document)?;
        write_notices(out, diff, &document)?;
        write_tiles(out, &document)?;
        write_hosts(out, diff, &document)?;
        write_colophon(out, &document)?;

        write::foot(out)?;
        Ok(())
    }
}

/// Which two scans these are, under the shared masthead.
fn write_masthead(
    out: &mut dyn Write,
    heading: &str,
    document: &DiffDto<'_>,
) -> Result<(), ExportError> {
    let subtitle = format!(
        "{before} → {after}",
        before = Text(&document.baseline.at),
        after = Text(&document.current.at),
    );

    write::masthead(out, heading, &subtitle)
}

/// The things that change how the rest of the page should be read.
///
/// Each is a fact about the two *scans* rather than about the network, and each
/// makes what follows mean something other than it appears to: a comparison
/// against a scan that stated no scope can confirm nothing, and one between two
/// different kinds of scan reports every port only one of them looked at.
fn write_notices(
    out: &mut dyn Write,
    diff: &ScanDiff,
    document: &DiffDto<'_>,
) -> Result<(), ExportError> {
    let mut notices: Vec<(bool, &str, String)> = Vec::new();

    if document.unchanged {
        notices.push((
            false,
            "no change",
            "the two scans describe the same network".into(),
        ));
    }

    for (side, provenance) in [
        ("earlier scan", &document.baseline),
        ("later scan", &document.current),
    ] {
        if !provenance.states_scope {
            notices.push((
                true,
                "unstated scope",
                format!("the {side} does not say what it covered, so nothing it is missing can be confirmed"),
            ));
        }
    }

    let ports = |kinds: &[&'static str]| kinds.contains(&"port_scan");
    match (
        ports(&document.baseline.kinds),
        ports(&document.current.kinds),
    ) {
        (false, true) => notices.push((
            true,
            "different scans",
            "only the later scan looked at ports, so most of what follows is the earlier one not having looked".into(),
        )),
        (true, false) => notices.push((
            true,
            "different scans",
            "only the earlier scan looked at ports, so most of what follows is the later one not having looked".into(),
        )),
        _ => {}
    }

    if diff.baseline().at() > diff.current().at() {
        notices.push((
            true,
            "reversed",
            "the first scan is the later of the two, so this page reads backwards".into(),
        ));
    }

    if notices.is_empty() {
        return Ok(());
    }

    writeln!(out, "<div class=\"notices\">")?;
    for (alert, key, text) in notices {
        write::notice(out, alert, key, &text)?;
    }
    writeln!(out, "</div>")?;
    Ok(())
}

/// The figures somebody reads before they read anything else.
///
/// Each headline count says how much of it the other scan is known to have
/// looked for. A page that printed only the total would be the one place this
/// whole comparison's care about coverage is thrown away.
fn write_tiles(out: &mut dyn Write, document: &DiffDto<'_>) -> Result<(), ExportError> {
    let summary = &document.summary;

    writeln!(out, "<div class=\"tiles\">")?;
    for (count, label) in [
        (&summary.hosts_added, "hosts appeared"),
        (&summary.hosts_removed, "hosts gone"),
        (&summary.ports_opened, "ports opened"),
        (&summary.ports_closed, "ports closed"),
    ] {
        // A count of nothing has nothing to qualify, and "all confirmed" under a
        // zero reads as an answer to a question nobody asked.
        let note = match (count.total, count.total - count.confirmed) {
            (0, _) => "none".to_string(),
            (_, 0) => "all confirmed".to_string(),
            (_, unconfirmed) => format!("{unconfirmed} nobody had looked for"),
        };
        write::tile(out, count.total, label, &esc(&note))?;
    }

    write::tile(
        out,
        summary.hosts_changed,
        "hosts changed",
        &esc("in both scans, and different"),
    )?;
    write::tile(
        out,
        summary.certificates_rotated + summary.certificates_expiring + summary.certificates_expired,
        "certificates",
        &esc("rotated, expiring or lapsed"),
    )?;
    writeln!(out, "</div>")?;
    Ok(())
}

/// One card per host that differs, ascending by address.
fn write_hosts(
    out: &mut dyn Write,
    diff: &ScanDiff,
    document: &DiffDto<'_>,
) -> Result<(), ExportError> {
    if document.hosts.is_empty() {
        writeln!(
            out,
            "<section class=\"section\"><p class=\"empty\">Nothing changed between these two scans.</p></section>"
        )?;
        return Ok(());
    }

    writeln!(
        out,
        "<section class=\"section\">\n<h2 class=\"section-title\">Hosts <span class=\"section-count\">{}</span></h2>",
        document.hosts.len()
    )?;

    for (delta, dto) in diff.hosts().iter().zip(&document.hosts) {
        write_host(out, delta, dto)?;
    }

    writeln!(out, "</section>")?;
    Ok(())
}

/// One host's card: what happened to it, what moved, and which endpoints moved.
fn write_host(
    out: &mut dyn Write,
    delta: &HostDelta,
    dto: &HostDeltaDto<'_>,
) -> Result<(), ExportError> {
    let (border, tone, word) = match delta.presence() {
        Presence::Added { .. } => ("d-added", TONE_FOUND, "appeared"),
        Presence::Removed { .. } => ("d-removed", TONE_NONE, "gone"),
        Presence::Both => ("d-changed", TONE_PARTIAL, "changed"),
    };

    write!(
        out,
        "<article class=\"host {border}\">\n<header class=\"host-head\"><span class=\"host-ip\">{ip}</span>",
        ip = Text(&dto.address),
    )?;

    // From the rendered record rather than the host itself: the masking policy
    // is applied on the way into the document, and reaching past it for a
    // hostname would put an unredacted one on a page meant to carry none.
    let named = dto
        .current
        .as_ref()
        .or(dto.baseline.as_ref())
        .and_then(|host| host.hostname.as_deref());
    if let Some(hostname) = named {
        write!(out, "<span class=\"host-name\">{}</span>", Text(hostname))?;
    }
    write!(out, "<span class=\"tag {tone}\">{word}</span>")?;

    if dto.regrouped {
        write!(
            out,
            "<span class=\"tag {TONE_INERT}\">regrouped {}→{}</span>",
            dto.records.baseline, dto.records.current
        )?;
    }
    writeln!(out, "</header>\n<div class=\"host-body\">")?;

    for change in &dto.changes {
        write_change(out, change)?;
    }
    for port in &dto.ports {
        write_port(out, port)?;
    }

    // Said once, and only where it changes what the card above means.
    if let Some(coverage) = delta.presence().counterpart_coverage()
        && !delta.presence().is_confirmed()
    {
        let other = if delta.presence().is_added() {
            "the earlier scan"
        } else {
            "the later scan"
        };
        writeln!(
            out,
            "<span class=\"unconfirmed\">{other} is not known to have covered this host ({coverage}), so this is a fact about the scans rather than about the network.</span>",
            coverage = Text(coverage_word(coverage)),
        )?;
    }

    writeln!(out, "</div>\n</article>")?;
    Ok(())
}

/// One endpoint's changes, under the endpoint that carries them.
fn write_port(out: &mut dyn Write, port: &PortDeltaDto) -> Result<(), ExportError> {
    let verdict = if port.opened {
        Some(("opened", TONE_FOUND))
    } else if port.closed {
        Some(("closed", TONE_NONE))
    } else {
        None
    };

    write!(
        out,
        "<div class=\"change\"><span class=\"change-kind mono\">{port}/{protocol}</span>",
        port = port.port,
        protocol = Text(port.protocol),
    )?;

    if let Some((word, tone)) = verdict {
        write!(out, "<span class=\"tag {tone}\">{word}</span>")?;
    }
    if !port.confirmed {
        write!(
            out,
            "<span class=\"tag {TONE_INERT}\">not looked for</span>"
        )?;
    }
    writeln!(out, "</div>")?;

    for change in &port.changes {
        write_change(out, change)?;
    }
    Ok(())
}

/// One field that moved, as the pair it is.
fn write_change(out: &mut dyn Write, change: &ChangeDto) -> Result<(), ExportError> {
    write!(
        out,
        "<div class=\"change\"><span class=\"change-kind\">{kind}</span>",
        kind = Text(&change.kind.replace('_', " ")),
    )?;

    match (&change.before, &change.after) {
        (Some(before), Some(after)) => write!(
            out,
            "<span class=\"change-was mono\">{was}</span><span class=\"change-arrow\">→</span><span class=\"mono\">{now}</span>",
            was = Text(before),
            now = Text(after),
        )?,
        (None, Some(after)) => write!(out, "<span class=\"mono\">{}</span>", Text(after))?,
        // A set member that went is said once: the kind above already reads
        // "address lost", and an arrow pointing at "nothing" after it says the
        // same thing a second time.
        (Some(before), None) if change.kind.ends_with("_lost") => {
            write!(
                out,
                "<span class=\"change-was mono\">{}</span>",
                Text(before)
            )?;
        }
        (Some(before), None) => write!(
            out,
            "<span class=\"change-was mono\">{}</span><span class=\"change-arrow\">→</span><span>nothing</span>",
            Text(before)
        )?,
        (None, None) => {}
    }

    writeln!(out, "</div>")?;
    Ok(())
}

/// What a coverage answer is called on a page a person reads.
fn coverage_word(coverage: crate::diff::Coverage) -> &'static str {
    use crate::diff::Coverage;
    match coverage {
        Coverage::Covered => "covered",
        Coverage::Withheld => "a policy forbade it",
        Coverage::OutOfScope => "outside what it walked",
        Coverage::Unstated => "it does not say",
    }
}

/// Which two scans this was, and what wrote the page.
fn write_colophon(out: &mut dyn Write, document: &DiffDto<'_>) -> Result<(), ExportError> {
    writeln!(
        out,
        "<footer class=\"colophon\"><p>Comparing {before} ({before_at}) with {after} ({after_at}). Written by {ENGINE_NAME} {ENGINE_VERSION} at {generated}.</p></footer>",
        before = Text(&document.baseline.engine_version),
        before_at = Text(&document.baseline.at),
        after = Text(&document.current.engine_version),
        after_at = Text(&document.current.at),
        generated = Text(&document.generated_at),
    )?;
    Ok(())
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
    use crate::export::Redaction;
    use crate::export::fixture;
    use crate::report::ScanReport;

    fn page(diff: &ScanDiff) -> String {
        let mut bytes = Vec::new();
        HtmlDiffExporter::default()
            .export(diff, &mut bytes)
            .expect("the export succeeds");
        String::from_utf8(bytes).expect("a page is text")
    }

    fn compared() -> String {
        let (before, after) = fixture::compared();
        page(&ScanDiff::between(&before, &after))
    }

    #[test]
    fn the_page_is_one_file_that_fetches_nothing() {
        let page = compared();

        assert!(page.starts_with("<!doctype html>"), "{}", &page[..40]);
        assert!(page.trim_end().ends_with("</html>"));
        assert!(page.contains("<style>"), "the stylesheet is inlined");

        for outside in ["http://", "https://", "<script", "<img", "@import", "src="] {
            assert!(
                !page.contains(outside),
                "a comparison page reaches outside itself: {outside}"
            );
        }
    }

    /// The three states are what a reader takes in first, so each has to be on
    /// the page and be told apart.
    #[test]
    fn every_host_carries_what_happened_to_it() {
        let page = compared();

        for state in ["d-added", "d-removed", "d-changed"] {
            assert!(page.contains(state), "no host is {state}: {page}");
        }
        for word in ["appeared", "gone", "changed"] {
            assert!(page.contains(word), "{word} is not said anywhere");
        }
    }

    /// The number the whole comparison is arranged to protect. A page that
    /// printed only the total would throw it away at the last step.
    #[test]
    fn a_headline_count_says_how_much_of_it_nobody_looked_for() {
        let (before, after) = fixture::compared();
        // A sweep that walked no ports: everything the port scan found on them
        // is then something nobody had looked for.
        let unconfirmed = page(&ScanDiff::between(&fixture::report(), &after));

        assert!(
            unconfirmed.contains("nobody had looked for"),
            "the page does not say how much of its counts is unconfirmed: {unconfirmed}"
        );
        // The endpoints nobody had looked for are marked where they are shown.
        assert!(unconfirmed.contains("not looked for"), "{unconfirmed}");

        // And where everything is confirmed it says so rather than staying
        // silent, which would read as the question not having been asked.
        let confirmed = page(&ScanDiff::between(&before, &after));
        assert!(confirmed.contains("all confirmed"), "{confirmed}");

        // And a count of nothing has nothing to qualify.
        let (before, _) = fixture::compared();
        let quiet = page(&ScanDiff::between(&before, &before));
        assert!(quiet.contains("tile-note\">none"), "{quiet}");
        assert!(!quiet.contains("all confirmed"), "{quiet}");
    }

    /// A host on ground the other scan was forbidden is not a host that
    /// appeared, and the card says which of the two it is.
    #[test]
    fn a_host_on_ground_nobody_covered_says_so_on_its_card() {
        use crate::model::host::{Host, HostStatus};
        use std::net::{IpAddr, Ipv4Addr};

        // The report fixture walks 192.168.0.0/25 and is forbidden the rest, so
        // a host in the upper half was ground it was told not to look at.
        let mut withheld = Host::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 200)));
        withheld.set_status(HostStatus::Up);

        let later = ScanReport::recorded("test", Vec::new(), vec![withheld]);
        let page = page(&ScanDiff::between(&fixture::report(), &later));

        assert!(
            page.contains("class=\"unconfirmed\""),
            "the card does not say nobody looked: {page}"
        );
        assert!(page.contains("a policy forbade it"), "{page}");
        assert!(
            page.contains("about the scans rather than about the network"),
            "{page}"
        );
    }

    /// A set member that went says so once. The kind already reads "address
    /// lost"; an arrow pointing at "nothing" after it says it twice.
    #[test]
    fn a_set_member_that_went_is_not_also_pointed_at_nothing() {
        let (before, after) = fixture::compared();
        let page = page(&ScanDiff::between(&before, &after));

        for row in page.split("<div class=\"change\">") {
            if row.contains("lost") {
                assert!(!row.contains("nothing"), "a departure is said twice: {row}");
            }
        }
    }

    #[test]
    fn what_moved_is_shown_as_the_pair_it_is() {
        let page = compared();

        assert!(page.contains("change-was"), "no before/after pair: {page}");
        assert!(
            page.contains("service version"),
            "an underscore reached the page"
        );
        assert!(page.contains("8.9p1") && page.contains("9.6p1"), "{page}");
    }

    #[test]
    fn an_unchanged_comparison_still_writes_a_page() {
        let (before, _) = fixture::compared();
        let page = page(&ScanDiff::between(&before, &before));

        assert!(
            page.contains("Nothing changed between these two scans"),
            "{page}"
        );
        assert!(page.contains("no change"), "{page}");
        assert!(page.trim_end().ends_with("</html>"));
    }

    /// A scanned host chooses its own hostname, banner and certificate subject,
    /// and a page is where those are read by a person.
    #[test]
    fn every_value_a_scanned_host_chose_reaches_the_page_escaped() {
        let hostile = fixture::hostile();
        let page = page(&ScanDiff::between(&fixture::report(), &hostile));

        assert!(
            !page.contains(fixture::HOSTILE),
            "an attacker-controlled string reached the page intact"
        );
        assert!(!page.contains("<script>"), "markup survived: {page}");
        assert!(
            !page.contains('\u{202e}'),
            "a right-to-left override survived, which reverses the text after it"
        );
        assert!(
            page.contains("&lt;script&gt;"),
            "and it is on the page, escaped"
        );
    }

    #[test]
    fn redaction_reaches_the_page() {
        let (before, after) = fixture::compared();
        let diff = ScanDiff::between(&before, &after);

        let mut bytes = Vec::new();
        HtmlDiffExporter::new(ExportOptions::new().with_redaction(Redaction::Standard))
            .export(&diff, &mut bytes)
            .expect("the export succeeds");
        let page = String::from_utf8(bytes).expect("text");

        assert!(
            !page.contains("gateway.local"),
            "a hostname survived: {page}"
        );
        assert!(
            !page.contains("2c:cf:67:f2:51:e3"),
            "a MAC survived: {page}"
        );
    }

    #[test]
    fn a_caller_can_name_the_page() {
        let (before, after) = fixture::compared();
        let diff = ScanDiff::between(&before, &after);

        let mut bytes = Vec::new();
        HtmlDiffExporter::default()
            .with_heading("Acme, week 32")
            .export(&diff, &mut bytes)
            .expect("the export succeeds");
        let page = String::from_utf8(bytes).expect("text");

        assert!(page.contains("<title>Acme, week 32</title>"), "{page}");
        assert!(page.contains("<h1>Acme, week 32</h1>"), "{page}");
    }
}
