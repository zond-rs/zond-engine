// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # HTTP header analyzer
//!
//! Identifies HTTP servers by parsing the status line and headers and reading
//! named fields. It lifts product and version out of any `Server` header
//! (`gunicorn/21.2.0`, `Microsoft-IIS/10.0`, `openresty/1.25.3.1`, `Caddy`)
//! without a per-product regex.
//!
//! ## Passive
//!
//! It reads the response the transport already captured (the shared
//! [`ResponseSet`], the reply to the `get_root` probe), so all its work is in
//! [`analyze`](Analyzer::analyze).
//!
//! ## Evidence
//!
//! It reports the **`Server`** product and version, the **`X-Powered-By`**
//! component (`PHP/8.2` behind Apache) as `extrainfo` so it never takes the
//! product slot, and a baseline `http` service label.
//!
//! [`ResponseSet`]: super::response::ResponseSet

use async_trait::async_trait;

use super::analyzer::{Analyzer, PortContext};
use super::model::{Evidence, SourceId};
use super::response::{Collected, ResponseSet};
use std::borrow::Cow;

use crate::model::confidence::Confidence;
use crate::model::port::{Build, Distributor};

/// Identifies HTTP servers from the structured headers of a captured response.
/// See the module docs.
pub struct HttpHeadersAnalyzer;

#[async_trait]
impl Analyzer for HttpHeadersAnalyzer {
    fn id(&self) -> SourceId {
        SourceId::HttpHeaders
    }

    // Any port: `analyze` gates on an HTTP status line.
    fn interested(&self, _ctx: &PortContext) -> bool {
        true
    }

    // Passive. See the module docs.

    fn analyze(
        &self,
        ctx: &PortContext,
        responses: &ResponseSet,
        _collected: &Collected,
    ) -> Vec<Evidence> {
        // Every captured HTTP reply. There may be several: a redirect and the
        // page it pointed at, where the application names itself.
        let parsed: Vec<HttpResponse<'_>> = responses
            .banners
            .iter()
            .filter_map(|banner| HttpResponse::parse(banner))
            .collect();
        // Headers come from the direct answer, not the page one hop away.
        let Some(http) = parsed.first() else {
            return Vec::new();
        };

        // Baseline: the service only. A product here would tie with a
        // versionless `Server` match and could bury the real server name.
        let mut evidence = vec![stamp(
            Evidence::new(SourceId::HttpHeaders, Confidence::Probable).with_service("http"),
            ctx,
        )];

        if let Some(header) = http.header("server") {
            if let Some((product, version)) = parse_server(header) {
                let confidence = if version.is_some() {
                    Confidence::Strong
                } else {
                    Confidence::Probable
                };
                let mut server = Evidence::new(SourceId::HttpHeaders, confidence)
                    .with_service("http")
                    .with_product(product);
                server.version = version;
                server.build = server_build(header);
                evidence.push(stamp(server, ctx));
            }

            // The whole header value against the signature set. Those rules are
            // anchored on a `Server` value (`^Microsoft-IIS/6.0$`) and map server
            // versions to Windows releases; a whole response never matches them.
            let (os, from_corpus) = corpus_reading(header);

            if let Some(os) = os {
                let mut carrier =
                    Evidence::new(SourceId::HttpHeaders, Confidence::Probable).with_service("http");
                carrier.os = Some(os);
                evidence.push(stamp(carrier, ctx));
            }

            // What the same match said about the service, such as the runtime in
            // `SimpleHTTP/0.6 Python/3.13.5`. Pushed after `parse_server`'s
            // reading, so on a tie it only fills empty fields.
            if let Some(from_corpus) = from_corpus {
                evidence.push(stamp(from_corpus, ctx));
            }
        }

        // `X-Powered-By` (PHP, ASP.NET, Express) goes to `extrainfo`.
        if let Some(powered_by) = http.header("x-powered-by").and_then(super::identity_field) {
            evidence.push(stamp(
                Evidence::new(SourceId::HttpHeaders, Confidence::Probable)
                    .with_service("http")
                    .with_extrainfo(powered_by),
                ctx,
            ));
        }

        // What is running on the server. See `application_hint`.
        let named = http
            .header("server")
            .and_then(parse_server)
            .map(|(product, _)| product);
        let application = parsed
            .iter()
            .find_map(|response| application_hint(response, named.as_deref()))
            .or_else(|| leads_elsewhere(http, ctx).map(|to| format!("redirects to {to}")));
        if let Some(application) = application.as_deref().and_then(super::identity_field) {
            evidence.push(stamp(
                Evidence::new(SourceId::HttpHeaders, Confidence::Probable)
                    .with_service("http")
                    .with_extrainfo(application),
                ctx,
            ));
        }

        evidence
    }
}

/// What application this response belongs to, where it can be read off the
/// response without anybody having written a rule for that application.
///
/// Covers self-hosted software nobody wrote a signature for, using two
/// structural signals:
///
/// A vendor prefix on a header name: `X-Emby-Token`, `X-Plex-Protocol`,
/// `X-Jenkins`, `X-Drupal-Cache`, `X-Shopify-Stage`. The CORS allow-list is read
/// too, so a server names itself even when its body is a bare redirect.
///
/// The document title, which for a self-hosted web interface is often just the
/// product name: `Sonarr`, `Netdata`, `Grafana`, `Squoosh`. It is user-controlled
/// text, so it only ever reaches `extrainfo`.
///
/// The prefix wins where both exist, since a header name comes from the
/// software's own code.
///
/// `named` is the product from the `Server` header; a title mentioning it is
/// discarded, since default landing pages (`Welcome to nginx!`) are titled after
/// the server.
fn application_hint(http: &HttpResponse<'_>, named: Option<&str>) -> Option<String> {
    if let Some(vendor) = vendor_prefix(http) {
        return Some(vendor);
    }

    // A redirect's page is the server's: nginx titles every one `301 Moved
    // Permanently`.
    if http.is_redirect() {
        return None;
    }
    let title = document_title(http.body)?;
    let echoes_the_server = named.is_some_and(|product| {
        let (title, product) = (title.to_ascii_lowercase(), product.to_ascii_lowercase());
        title.contains(&product) || product.contains(&title)
    });

    (!echoes_the_server).then_some(title)
}

/// Where a redirect the port answered with leads, when that is somewhere the
/// identification did not follow it: another name, another port or another
/// scheme.
///
/// A server that sends every visitor to `http://box.example/` is saying which
/// site it holds. A redirect that stays on the port was followed instead.
///
/// Only an absolute URL leads elsewhere. With no address to compare against,
/// every absolute URL is taken to.
fn leads_elsewhere<'a>(http: &HttpResponse<'a>, ctx: &PortContext) -> Option<&'a str> {
    if !http.is_redirect() {
        return None;
    }
    let location = http.header("location")?;
    if !(location.contains("://") || location.starts_with("//"))
        || location.chars().any(char::is_control)
    {
        return None;
    }
    let stays = ctx.addr.is_some_and(|addr| {
        let peer =
            super::authority::Authority::new(addr).named(ctx.host_name.as_deref().map(Into::into));
        let peer = match ctx.tunnel {
            Some(_) => peer.through_tls(),
            None => peer,
        };
        peer.path_of(location).is_some()
    });
    (!stays).then_some(location)
}

/// Header names that begin with `x-` and name no vendor.
///
/// Without it `X-Frame-Options` would report a product called "Frame". These are
/// the de-facto standard extension headers, a small and stable set.
const NOT_A_VENDOR: &[&str] = &[
    "accel",
    "access",
    "api",
    "app",
    "auth",
    "cache",
    "content",
    "correlation",
    "csrf",
    "dns",
    "download",
    "forwarded",
    "frame",
    "http",
    "instance",
    "permitted",
    "powered",
    "ratelimit",
    "rate",
    "real",
    "request",
    "requested",
    "response",
    "robots",
    "runtime",
    "served",
    "server",
    "sourcemap",
    "timer",
    "total",
    "trace",
    "transaction",
    "ua",
    "upstream",
    "varnish",
    "version",
    "xss",
];

/// The vendor a response names by prefixing its own headers with it.
///
/// The most repeated prefix wins. Software uses its own namespace several times,
/// while a stray prefix from a proxy or a former name appears once: Emby's
/// allow-list leads with one `X-MediaBrowser-Token` and then names itself three
/// times.
///
/// Ties go to whichever appeared first.
fn vendor_prefix(http: &HttpResponse<'_>) -> Option<String> {
    let mut counts: Vec<(String, usize)> = Vec::new();

    for name in http.header_vocabulary() {
        let lowered = name.to_ascii_lowercase();
        let Some(rest) = lowered.strip_prefix("x-") else {
            continue;
        };
        // `x-emby-token` -> `emby`; a bare `x-jenkins` is the vendor itself.
        let token = rest.split('-').next().unwrap_or(rest);
        if token.len() < 3
            || !token.chars().all(|c| c.is_ascii_alphanumeric())
            || NOT_A_VENDOR.contains(&token)
        {
            continue;
        }

        match counts.iter_mut().find(|(seen, _)| seen == token) {
            Some((_, count)) => *count += 1,
            None => counts.push((token.to_string(), 1)),
        }
    }

    // `counts` is in first-seen order; the index breaks ties toward the front,
    // where `max_by_key` alone would take the last.
    counts
        .iter()
        .enumerate()
        .max_by_key(|(index, (_, count))| (*count, std::cmp::Reverse(*index)))
        .map(|(_, (token, _))| capitalize(token))
}

/// `emby` -> `Emby`. Header names were lowercased on the way in.
fn capitalize(token: &str) -> String {
    let mut chars = token.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Titles that name the page rather than the application.
///
/// Error pages, login prompts and default landing pages are served by thousands
/// of unrelated things.
const NOT_AN_APPLICATION: &[&str] = &[
    "400 bad request",
    "401 unauthorized",
    "403 forbidden",
    "404 not found",
    "500 internal server error",
    "bad request",
    "document",
    "error",
    "forbidden",
    "home",
    "index",
    "index of /",
    "log in",
    "login",
    "not found",
    "sign in",
    "unauthorized",
    "welcome",
];

/// The document's `<title>`, where it is short enough and specific enough to be
/// naming an application.
fn title_text(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let open = lower.find("<title")?;
    let start = open + lower[open..].find('>')? + 1;
    let end = start + lower[start..].find("</title>")?;

    let title = body
        .get(start..end)?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    (!title.is_empty()).then_some(title)
}

/// The header values and document title the signature corpus writes rules
/// against, as texts to match a response by.
///
/// A corpus rule anchors on one field at both ends, so `^Microsoft-IIS/6.0$`
/// matches the `Server` value and never the whole response.
///
/// `Server` is left out: [`corpus_reading`] already reads it, and offering it
/// twice would let one header vote twice.
///
/// Borrowed from the response, except the title, whose whitespace is
/// normalised. Empty for anything that is not an HTTP response.
pub(super) fn corpus_fields(raw: &str) -> Vec<Cow<'_, str>> {
    let Some(http) = HttpResponse::parse(raw) else {
        return Vec::new();
    };

    let mut fields: Vec<Cow<'_, str>> = ["set-cookie", "www-authenticate", "x-powered-by"]
        .iter()
        .filter_map(|name| http.header(name))
        .map(Cow::Borrowed)
        .collect();

    fields.extend(title_text(http.body).map(Cow::Owned));
    fields
}

/// The `Server` value of an HTTP-shaped message, whole.
///
/// The header [`corpus_fields`] leaves out, for callers with no analyzer reading
/// it. On TCP [`HttpHeadersAnalyzer`] reads it; a UDP reply such as SSDP goes
/// only through [`from_datagram`](super::extract::from_datagram), which uses
/// this.
///
/// [`None`] for anything that is not HTTP-shaped or carries no such header.
pub(super) fn server_value(raw: &str) -> Option<&str> {
    HttpResponse::parse(raw)?.header("server")
}

/// The title, held to what may stand in for a product name.
///
/// Stricter than [`title_text`]. The corpus matches raw titles and has rules for
/// `301 Moved Permanently` that these filters would reject.
fn document_title(body: &str) -> Option<String> {
    let title = title_text(body)?;

    // Longer than this is a description, not a product name.
    if title.len() > 40 {
        return None;
    }
    if NOT_AN_APPLICATION.contains(&title.to_ascii_lowercase().as_str()) {
        return None;
    }
    reads_as_a_name(&title).then_some(title)
}

/// Words that may appear lowercase inside a name without making it a sentence.
///
/// Kept short: it separates `Bill of Materials` from `Yo whats up`, and every
/// added word moves the line toward accepting the second.
const NAME_CONNECTIVES: &[&str] = &["of", "the", "and", "for", "de", "la", "du"];

/// Whether `title` reads as the name of something rather than as a remark about
/// a page.
///
/// Every word must be capitalised: `Home Assistant`, `Proxmox Virtual
/// Environment` and `Uptime Kuma` are names; `Yo whats up` is not. A single word
/// is accepted in any case (`phpMyAdmin`, `openHAB`, `code-server`).
///
/// A title with a separator is declined: `Dashboard - Grafana` and
/// `Sonarr - Series` put the product on opposite sides.
fn reads_as_a_name(title: &str) -> bool {
    if title.contains(['-', '|', ':', '·', '—', '–', '/', '(']) {
        return false;
    }

    let mut words = title.split_whitespace();
    let Some(first) = words.next() else {
        return false;
    };
    if !first.chars().next().is_some_and(char::is_alphanumeric) {
        return false;
    }

    words.all(|word| {
        NAME_CONNECTIVES.contains(&word.to_ascii_lowercase().as_str())
            || word.chars().next().is_some_and(char::is_uppercase)
    })
}

/// Marks `evidence` with the tunnel its response was read through, so an HTTP
/// response parsed inside TLS is labelled `ssl/http` by the resolver.
fn stamp(mut evidence: Evidence, ctx: &PortContext) -> Evidence {
    evidence.tunnel = ctx.tunnel;
    evidence
}

/// What the signature set makes of one header value, as an operating system.
///
/// Matched globally: these rules are registered under their own service, not
/// port 80. The prefilter keeps that cheap.
///
/// Only the most complete match contributes, so one header cannot corroborate
/// itself.
///
/// Ranked by how much a reading says, as `SignatureDb::identify` ranks: a rule
/// pinning a product exactly would outrank one that also names a release, and
/// ranking by confidence would lose the release. Keep the two consistent.
///
/// Costs 22 to 37 µs per header, most on a miss. Paid once per open HTTP port.
fn corpus_reading(header: &str) -> (Option<crate::model::host::OsEvidence>, Option<Evidence>) {
    use crate::fingerprint::prefilter::Prefilter;

    let db = crate::fingerprint::SignatureDb::global();
    let matched: Vec<_> = db
        .prefilter()
        .candidates(header)
        .into_iter()
        .filter_map(|index| {
            db.signature(index)?
                .identify(header, crate::model::host::OsSource::ServiceBanner)
        })
        .collect();

    // `reduce` keeps the earlier reading on a tie; `max_by` would keep the last.
    let os = matched
        .iter()
        .filter_map(|matched| matched.os.clone())
        .reduce(
            |best, os| match super::db::os_detail(&os) > super::db::os_detail(&best) {
                true => os,
                false => best,
            },
        );

    // Only a match that names a service is a service reading; an "assert
    // nothing" rule (a bare `null`) may still carry an OS reading.
    let service = matched
        .into_iter()
        .filter(|matched| matched.evidence.service.is_some())
        .reduce(|best, matched| match matched.quality > best.quality {
            true => matched,
            false => best,
        })
        .map(|matched| matched.evidence);

    (os, service)
}

/// Splits a `Server` header value into a product and optional version.
///
/// Reads the first whitespace-delimited token (so trailing OS/comment tokens
/// like `Apache/2.4.58 (Ubuntu)` are ignored) and splits it into a product and a
/// version at the first `/`, keeping the version only when it actually looks like
/// one (starts with a digit). A comment opener `(` also ends the product, so
/// `Jetty(9.4)` yields `Jetty`. Returns `None` for an empty value, or for a
/// placeholder token like `null` that names no real product.
fn parse_server(value: &str) -> Option<(String, Option<String>)> {
    let token = super::identity_field(value.split_whitespace().next()?)?;

    if let Some((product, version)) = token.split_once('/') {
        let product = product.trim_end_matches('(');
        let versioned = version.starts_with(|c: char| c.is_ascii_digit());
        if !product.is_empty() && !is_placeholder(product) && versioned {
            return Some((product.to_string(), Some(version.to_string())));
        }
        // A `/` but no numeric version: the left side is the product.
        if !product.is_empty() && !is_placeholder(product) {
            return Some((product.to_string(), None));
        }
    }

    // No `/`: the token is a bare product name (possibly with a `(` comment).
    let product = token.split('(').next().unwrap_or(token);
    (!product.is_empty() && !is_placeholder(product)).then(|| (product.to_string(), None))
}

/// Whose build the server is, where the header's comment names a distributor.
///
/// The comment in parentheses after the product is where Apache and nginx as
/// Debian, Ubuntu and the Red Hat family package them say whose package this
/// is: `Apache/2.4.7 (Ubuntu)`, `Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips`,
/// `Apache/2.4.37 (Red Hat Enterprise Linux)`. It names no revision, so the
/// build says only who packaged the server, which matters because the
/// distributor backports fixes without changing the upstream version.
///
/// Only a distributor's name counts; `(Unix)` and `(Win64)` do not.
fn server_build(value: &str) -> Option<Build> {
    value
        .split('(')
        .skip(1)
        .filter_map(|rest| rest.split_once(')').map(|(comment, _)| comment))
        .flat_map(|comment| comment.split([';', ',']))
        .find_map(Distributor::from_name)
        .map(Build::new)
}

/// Whether a server token is a placeholder. Embedded and router HTTP stacks emit
/// `Server: null`, `unknown`, `-` and the like.
fn is_placeholder(product: &str) -> bool {
    matches!(
        product.trim().to_ascii_lowercase().as_str(),
        "" | "null" | "nil" | "none" | "unknown" | "unspecified" | "-"
    )
}

/// A minimally-parsed HTTP response: enough to read headers by name. The body is
/// discarded, leaving the status line as the marker that this is HTTP, and the
/// header block.
struct HttpResponse<'a> {
    /// The status code, where the status line carries one.
    status: Option<u16>,
    /// `(lowercased name, trimmed value)` in wire order, borrowing the value.
    headers: Vec<(String, &'a str)>,
    /// Whatever followed the blank line, as far as the response was read.
    ///
    /// A self-hosted single-page app often names itself only in its `<title>`.
    body: &'a str,
}

impl<'a> HttpResponse<'a> {
    /// Parses `raw` if it begins with an HTTP status line. Returns `None` for
    /// anything that is not an HTTP response, so the analyzer can scan a mixed
    /// set of banners and pick the HTTP one.
    fn parse(raw: &'a str) -> Option<Self> {
        if !raw.starts_with("HTTP/") {
            return None;
        }

        // CRLF or bare LF, and a response cut off before the blank line.
        let (head, body) = raw
            .find("\r\n\r\n")
            .map(|at| (&raw[..at], &raw[at + 4..]))
            .or_else(|| raw.find("\n\n").map(|at| (&raw[..at], &raw[at + 2..])))
            .unwrap_or((raw, ""));

        let mut headers = Vec::new();
        for line in head.split('\n').skip(1) {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim()));
            }
        }

        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok());
        Some(HttpResponse {
            status,
            headers,
            body,
        })
    }

    /// Whether this is a redirect, whose body is the server's note about the
    /// hop rather than a page of the site's.
    fn is_redirect(&self) -> bool {
        self.status.is_some_and(|code| (300..400).contains(&code))
    }

    /// Every header name this response carries, plus the names it *mentions* in
    /// its CORS allow-list.
    ///
    /// The allow-list is the server's own header vocabulary. An Emby server was
    /// identified from nothing else.
    fn header_vocabulary(&self) -> impl Iterator<Item = &str> {
        self.headers.iter().map(|(name, _)| name.as_str()).chain(
            self.header("access-control-allow-headers")
                .into_iter()
                .flat_map(|value| value.split(',').map(str::trim)),
        )
    }

    /// The value of the first header named `name` (which must be lowercase),
    /// case-insensitively. `None` if absent or empty.
    fn header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| *value)
            .filter(|value| !value.is_empty())
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
    use crate::fingerprint::model::Tunnel;
    use proptest::prelude::*;

    fn analyze(port: u16, banner: &str) -> Vec<Evidence> {
        HttpHeadersAnalyzer.analyze(
            &PortContext {
                protocol: crate::model::port::Protocol::Tcp,
                port,
                addr: None,
                tunnel: None,
                speaks_http: false,
                detection: crate::config::ServiceDetection::default(),
                host_name: None,
            },
            &ResponseSet::from_banners(vec![banner.to_string()]),
            &Collected::default(),
        )
    }

    /// [`analyze`] over several responses, as a port that redirected produces.
    fn analyze_all(port: u16, banners: &[&str]) -> Vec<Evidence> {
        HttpHeadersAnalyzer.analyze(
            &PortContext {
                protocol: crate::model::port::Protocol::Tcp,
                port,
                addr: None,
                tunnel: None,
                speaks_http: false,
                detection: crate::config::ServiceDetection::default(),
                host_name: None,
            },
            &ResponseSet::from_banners(banners.iter().map(|b| (*b).to_string()).collect()),
            &Collected::default(),
        )
    }

    /// A redirect and the page it pointed at are both this port's answer, and
    /// the application names itself in the second one.
    ///
    /// The root is a bare 302 naming only the framework (`Kestrel`), and one hop
    /// away a page titled with the product, as Jellyfin and Sonarr do.
    #[test]
    fn a_redirect_and_its_destination_are_read_together() {
        let evidence = analyze_all(
            8096,
            &[
                "HTTP/1.1 302 Found\r\nServer: Kestrel\r\nLocation: /web/index.html\r\n\r\n",
                "HTTP/1.1 200 OK\r\nServer: Kestrel\r\n\r\n\
                 <!DOCTYPE html><html><head><title>Jellyfin</title></head>",
            ],
        );

        assert_eq!(
            evidence.iter().find_map(|e| e.extrainfo.as_deref()),
            Some("Jellyfin"),
            "the page one hop away is where the application named itself"
        );
        assert!(
            evidence
                .iter()
                .any(|e| e.product.as_deref() == Some("Kestrel")),
            "and the framework it runs on is still recorded, from the direct answer"
        );
    }

    /// What the analyzer read as supplementary detail, if anything.
    fn extrainfo(port: u16, banner: &str) -> Option<String> {
        analyze(port, banner)
            .into_iter()
            .find_map(|evidence| evidence.extrainfo)
    }

    /// A redirect page's title (`301 Moved Permanently`) is not an application.
    /// Where the redirect leads elsewhere, the target is reported.
    #[test]
    fn a_redirect_off_the_port_is_recorded_and_its_title_is_not_a_product() {
        let nginx = "HTTP/1.1 301 Moved Permanently\r\nServer: nginx/1.24.0\r\n\
                     Location: http://box.example/\r\nContent-Type: text/html\r\n\r\n\
                     <html><head><title>301 Moved Permanently</title></head></html>";
        let evidence = analyze(80, nginx);

        assert!(
            evidence
                .iter()
                .all(|e| e.extrainfo.as_deref() != Some("301 Moved Permanently")),
            "the redirect's title was taken for an application: {evidence:?}"
        );
        assert_eq!(
            extrainfo(80, nginx).as_deref(),
            Some("redirects to http://box.example/")
        );
    }

    /// A redirect that stays on the port is not reported.
    #[test]
    fn a_redirect_that_stays_on_the_port_is_not_recorded() {
        let relative = "HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n\
                        <html><head><title>Found</title></head></html>";
        assert_eq!(extrainfo(80, relative), None);
    }

    /// A media server that names no product but lists its own headers in the
    /// CORS allow-list. Captured from a real Emby server on port 8097, whose
    /// `Server` header names its embedded DLNA stack.
    #[test]
    fn a_server_that_names_itself_only_in_its_cors_list_is_still_named() {
        let banner = "HTTP/1.1 200 OK\r\n\
             Server: UPnP/1.0 DLNADOC/1.50\r\n\
             Access-Control-Allow-Headers: Accept, Authorization, Content-Type, \
             X-MediaBrowser-Token, X-Emby-Token, X-Emby-Client, X-Emby-Authorization\r\n\
             Content-Length: 0\r\n\r\n";

        assert_eq!(extrainfo(8097, banner).as_deref(), Some("Emby"));
    }

    /// The prefix convention, read off a header the server actually sent.
    #[test]
    fn a_vendor_prefix_on_a_header_names_the_vendor() {
        let banner = "HTTP/1.1 200 OK\r\nServer: Kestrel\r\nX-Plex-Protocol: 1.0\r\n\r\n";
        assert_eq!(extrainfo(32400, banner).as_deref(), Some("Plex"));
    }

    /// The standard extension headers name no vendor.
    #[test]
    fn the_standard_extension_headers_name_nothing() {
        let banner = "HTTP/1.1 200 OK\r\n\
             Server: nginx/1.22.1\r\n\
             X-Frame-Options: DENY\r\n\
             X-Content-Type-Options: nosniff\r\n\
             X-XSS-Protection: 1; mode=block\r\n\
             X-Request-Id: abc123\r\n\
             X-Cache: HIT\r\n\r\n";

        assert_eq!(extrainfo(80, banner), None);
    }

    /// A self-hosted application named only by its title. Captured from a real
    /// server on port 7778 serving `<title>Squoosh</title>`.
    #[test]
    fn the_document_title_names_an_application_nobody_wrote_a_rule_for() {
        let banner = "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=utf-8\r\n\r\n\
             <!DOCTYPE html><html lang=\"en\"><head><title>Squoosh</title><meta \
             name=\"description\" content=\"Squoosh is the ultimate image optimizer\" />";

        assert_eq!(extrainfo(7778, banner).as_deref(), Some("Squoosh"));
    }

    /// A title mentioning the `Server` product (`Welcome to nginx!`) is dropped.
    #[test]
    fn a_title_that_only_echoes_the_server_is_not_an_application() {
        let welcome = "HTTP/1.1 200 OK\r\n\
             Server: nginx/1.22.1\r\n\r\n\
             <html><head><title>Welcome to nginx!</title>";
        assert_eq!(extrainfo(80, welcome), None);

        let repeat = "HTTP/1.1 200 OK\r\n\
             Server: Netdata Embedded HTTP Server v2.11.0\r\n\r\n\
             <html><head><title>Netdata</title>";
        assert_eq!(extrainfo(19999, repeat), None, "nor is a bare repeat of it");

        // A title naming something else survives.
        let different = "HTTP/1.1 200 OK\r\n\
             Server: Kestrel\r\n\r\n\
             <html><head><title>Jellyfin</title>";
        assert_eq!(extrainfo(8096, different).as_deref(), Some("Jellyfin"));
    }

    /// A title naming the page, not the application, is dropped.
    #[test]
    fn a_page_title_is_not_an_application_name() {
        for title in ["404 Not Found", "Sign in", "Welcome", "Index of /"] {
            let banner = format!("HTTP/1.1 200 OK\r\n\r\n<html><head><title>{title}</title>");
            assert_eq!(extrainfo(8080, &banner), None, "{title} names no product");
        }

        let sentence = "HTTP/1.1 200 OK\r\n\r\n<html><head><title>The quick brown fox \
             jumps over the lazy dog and keeps going</title>";
        assert_eq!(
            extrainfo(8080, sentence),
            None,
            "a sentence is a page description, not a product"
        );
    }

    /// Equally frequent prefixes resolve to the first mentioned.
    #[test]
    fn a_tie_between_prefixes_goes_to_the_first_mentioned() {
        let banner = "HTTP/1.1 200 OK\r\nX-Alpha-One: a\r\nX-Bravo-One: b\r\n\r\n";
        let http = HttpResponse::parse(banner).expect("an HTTP response");
        assert_eq!(vendor_prefix(&http).as_deref(), Some("Alpha"));
    }

    /// Most titles are not product names.
    #[test]
    fn a_title_that_is_somebody_talking_is_not_a_product() {
        for title in [
            "Yo whats up",
            "this page is under construction",
            "please log in to continue",
        ] {
            let banner = format!("HTTP/1.1 200 OK\r\n\r\n<html><head><title>{title}</title>");
            assert_eq!(extrainfo(8080, &banner), None, "`{title}` names no product");
        }
    }

    /// Capitalised multi-word names, and single words in any case.
    #[test]
    fn a_title_shaped_like_a_name_is_taken_as_one() {
        for title in [
            "Grafana",
            "phpMyAdmin",
            "openHAB",
            "Home Assistant",
            "Proxmox Virtual Environment",
            "Bill of Materials",
        ] {
            let banner = format!("HTTP/1.1 200 OK\r\n\r\n<html><head><title>{title}</title>");
            assert_eq!(
                extrainfo(8080, &banner).as_deref(),
                Some(title),
                "`{title}` reads as a name"
            );
        }
    }

    /// Titles with a separator are declined: the product may be on either side.
    #[test]
    fn a_title_with_a_separator_is_declined_rather_than_guessed_at() {
        for title in [
            "Dashboard - Grafana",
            "Sonarr - Series",
            "Log in | Nextcloud",
        ] {
            let banner = format!("HTTP/1.1 200 OK\r\n\r\n<html><head><title>{title}</title>");
            assert_eq!(extrainfo(8080, &banner), None, "`{title}` is ambiguous");
        }
    }

    /// A vendor prefix beats a title.
    #[test]
    fn a_vendor_prefix_outranks_a_title() {
        let banner = "HTTP/1.1 200 OK\r\n\
             X-Jenkins: 2.426.3\r\n\r\n\
             <html><head><title>Dashboard</title>";

        assert_eq!(extrainfo(8080, banner).as_deref(), Some("Jenkins"));
    }

    /// The parser keeps the body.
    #[test]
    fn the_parser_separates_the_body_from_the_headers() {
        let response = HttpResponse::parse(
            "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html><body>hello</body></html>",
        )
        .expect("an HTTP response");

        assert_eq!(response.header("server"), Some("nginx"));
        assert_eq!(response.body, "<html><body>hello</body></html>");

        let headers_only = HttpResponse::parse("HTTP/1.1 204 No Content\r\nServer: nginx\r\n\r\n")
            .expect("an HTTP response");
        assert_eq!(headers_only.body, "");
    }

    #[test]
    fn extracts_long_tail_server_product_and_version() {
        // No hand-authored regex for this server.
        let evidence = analyze(
            8000,
            "HTTP/1.1 200 OK\r\nServer: gunicorn/21.2.0\r\nContent-Type: text/html\r\n\r\n<html>",
        );
        let server = evidence
            .iter()
            .find(|e| e.product.as_deref() == Some("gunicorn"))
            .expect("names gunicorn");
        assert_eq!(server.version.as_deref(), Some("21.2.0"));
        assert_eq!(server.confidence, Confidence::Strong);
        assert_eq!(server.service.as_deref(), Some("http"));
    }

    #[test]
    fn iis_ten_is_covered_where_the_curated_regexes_stop() {
        // The imported `^Microsoft-IIS/[1234]\.0$` rules do not cover 10.0.
        let evidence = analyze(80, "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n");
        let server = evidence
            .iter()
            .find(|e| e.product.as_deref() == Some("Microsoft-IIS"))
            .expect("names IIS");
        assert_eq!(server.version.as_deref(), Some("10.0"));
    }

    #[test]
    fn server_without_version_is_probable_product_only() {
        let evidence = analyze(80, "HTTP/1.0 200 OK\r\nServer: cloudflare\r\n\r\n");
        let server = evidence
            .iter()
            .find(|e| e.product.as_deref() == Some("cloudflare"))
            .expect("names cloudflare");
        assert_eq!(server.version, None);
        assert_eq!(server.confidence, Confidence::Probable);
    }

    #[test]
    fn trailing_os_comment_token_is_ignored() {
        let evidence = analyze(
            80,
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Ubuntu)\r\n\r\n",
        );
        let server = evidence
            .iter()
            .find(|e| e.product.as_deref() == Some("Apache"))
            .expect("names Apache");
        assert_eq!(server.version.as_deref(), Some("2.4.58"));
    }

    #[test]
    fn valid_http_without_server_header_still_labels_http() {
        let evidence = analyze(80, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].service.as_deref(), Some("http"));
        // The baseline names no product.
        assert_eq!(evidence[0].product, None);
    }

    #[test]
    fn x_powered_by_becomes_extrainfo_beside_the_server_product() {
        let evidence = analyze(
            80,
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\nX-Powered-By: PHP/8.2.1\r\n\r\n",
        );
        assert!(
            evidence
                .iter()
                .any(|e| e.product.as_deref() == Some("Apache")),
            "server keeps the product slot"
        );
        assert!(
            evidence
                .iter()
                .any(|e| e.extrainfo.as_deref() == Some("PHP/8.2.1")),
            "framework lands in extrainfo"
        );
        // No evidence names PHP as a product.
        assert!(
            evidence
                .iter()
                .all(|e| e.product.as_deref() != Some("PHP/8.2.1"))
        );
    }

    #[test]
    fn placeholder_server_token_names_no_product() {
        // `Server: null` leaves only the baseline `http` evidence.
        let evidence = analyze(80, "HTTP/1.1 200 OK\r\nServer: null\r\n\r\n");
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].service.as_deref(), Some("http"));
        assert_eq!(evidence[0].product, None);

        // The raw splitter rejects the same tokens directly.
        assert_eq!(parse_server("null"), None);
        assert_eq!(parse_server("-"), None);
        assert_eq!(parse_server("Unknown"), None);
    }

    #[test]
    fn non_http_banner_yields_nothing() {
        assert!(analyze(22, "SSH-2.0-OpenSSH_9.6p1 Debian-3").is_empty());
    }

    proptest! {
        /// The response parser never panics. `(?s)` lets `.` match newlines, so
        /// framing edge cases are fuzzed.
        #[test]
        fn http_parse_never_panics(raw in "(?s).*") {
            let _ = HttpResponse::parse(&raw);
        }

        /// A valid status line, so the fuzzed part reaches header splitting.
        #[test]
        fn http_header_parsing_never_panics(body in "(?s).*") {
            if let Some(response) = HttpResponse::parse(&format!("HTTP/1.1 200 OK\r\n{body}")) {
                let _ = response.header("server");
                let _ = response.header("x-powered-by");
            }
        }

        /// `Server` value splitting must never panic on arbitrary content.
        #[test]
        fn parse_server_never_panics(value in "(?s).*") {
            let _ = parse_server(&value);
        }
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        // Header names are case-insensitive.
        let evidence = analyze(80, "HTTP/1.1 200 OK\r\nSERVER: nginx/1.25.3\r\n\r\n");
        assert!(
            evidence
                .iter()
                .any(|e| e.product.as_deref() == Some("nginx"))
        );
    }

    #[test]
    fn evidence_carries_the_tunnel_for_ssl_labelling() {
        let evidence = HttpHeadersAnalyzer.analyze(
            &PortContext {
                port: 443,
                protocol: crate::model::port::Protocol::Tcp,
                addr: None,
                tunnel: Some(Tunnel::Tls),
                speaks_http: false,
                detection: crate::config::ServiceDetection::default(),
                host_name: None,
            },
            &ResponseSet::from_banners(vec![
                "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n".to_string(),
            ]),
            &Collected::default(),
        );
        assert!(evidence.iter().all(|e| e.tunnel == Some(Tunnel::Tls)));
    }
}

#[cfg(test)]
mod os_from_headers {
    use super::*;
    use crate::fingerprint::response::Collected;

    /// A real `Server` header, through the real analyzer and the shipped corpus,
    /// reaches the imported rule mapping that server version to a Windows
    /// release.
    #[test]
    fn a_server_header_reaches_the_rules_that_name_a_windows_release() {
        let evidence = HttpHeadersAnalyzer.analyze(
            &PortContext {
                port: 80,
                protocol: crate::model::port::Protocol::Tcp,
                addr: None,
                tunnel: None,
                speaks_http: false,
                detection: crate::config::ServiceDetection::default(),
                host_name: None,
            },
            &ResponseSet::from_banners(vec![
                "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/6.0\r\nContent-Length: 0\r\n\r\n"
                    .to_string(),
            ]),
            &Collected::default(),
        );

        let os = evidence
            .iter()
            .find_map(|e| e.os.as_ref())
            .expect("the Server value reaches the operating-system rules");

        assert_eq!(os.family.as_deref(), Some("Windows"));
        assert_eq!(
            os.product.as_deref(),
            Some("Windows Server 2003"),
            "and carries the precise release the corpus knows, not just the family"
        );
    }

    /// The whole response does not match a rule anchored on a header value; the
    /// extracted value does.
    #[test]
    fn the_whole_response_is_not_what_those_rules_match() {
        use crate::fingerprint::prefilter::Prefilter;

        let response = "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/6.0\r\nContent-Length: 0\r\n\r\n";
        let db = crate::fingerprint::SignatureDb::global();

        let from_response = db
            .prefilter()
            .candidates(response)
            .into_iter()
            .filter_map(|index| {
                db.signature(index)?
                    .identify(response, crate::model::host::OsSource::ServiceBanner)
            })
            .find_map(|matched| matched.os);

        assert!(
            from_response.is_none(),
            "if this ever starts matching, the rules changed shape and \
             `corpus_reading` should be reconsidered rather than left as a \
             workaround"
        );
        assert!(
            corpus_reading("Microsoft-IIS/6.0").0.is_some(),
            "while the value those rules are written against does match"
        );
    }

    /// A server the corpus does not know names no operating system.
    #[test]
    fn a_server_the_corpus_does_not_know_names_nothing() {
        assert!(corpus_reading("SomeServer/1.0").0.is_none());
    }
}

#[cfg(test)]
mod server_builds {
    use super::*;
    use crate::fingerprint::model::ServiceVerdict;
    use crate::fingerprint::response::Collected;

    fn verdict(banner: &str) -> ServiceVerdict {
        let evidence = HttpHeadersAnalyzer.analyze(
            &PortContext {
                port: 80,
                protocol: crate::model::port::Protocol::Tcp,
                addr: None,
                tunnel: None,
                speaks_http: true,
                detection: crate::config::ServiceDetection::default(),
                host_name: None,
            },
            &ResponseSet::from_banners(vec![banner.to_string()]),
            &Collected::default(),
        );
        ServiceVerdict::resolve(evidence)
    }

    /// The distributor named in the comment reaches the verdict, even when a
    /// corpus rule calling the server by another name wins the product slot.
    #[test]
    fn a_server_header_naming_a_distributor_yields_its_build() {
        for (header, distributor) in [
            ("Apache/2.4.7 (Ubuntu)", Distributor::Ubuntu),
            ("Apache/2.4.62 (Debian)", Distributor::Debian),
            (
                "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16",
                Distributor::CentOs,
            ),
            (
                "Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k",
                Distributor::RedHat,
            ),
            ("nginx/1.18.0 (Ubuntu)", Distributor::Ubuntu),
        ] {
            let verdict = verdict(&format!("HTTP/1.1 200 OK\r\nServer: {header}\r\n\r\n"));
            let build = verdict
                .build
                .as_ref()
                .unwrap_or_else(|| panic!("{header}: no build"));
            assert_eq!(build.distributor(), distributor, "{header}");
            assert_eq!(
                build.revision(),
                None,
                "{header}: a header states no revision"
            );
        }
    }

    /// `(Unix)` names no distributor.
    #[test]
    fn a_server_header_naming_no_distributor_yields_no_build() {
        for header in [
            "Apache/2.4.58 (Unix)",
            "Apache/2.4.41 (Win64)",
            "nginx/1.25.3",
        ] {
            let verdict = verdict(&format!("HTTP/1.1 200 OK\r\nServer: {header}\r\n\r\n"));
            assert!(verdict.build.is_none(), "{header}: {:?}", verdict.build);
        }
    }
}
