// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # HTTP header analyzer
//!
//! Identifies HTTP servers by **parsing the response structurally** — splitting
//! the status line and headers, then reading named fields — rather than running
//! a regex over the raw banner. Its headline contribution is *long-tail* server
//! coverage: it lifts product and version out of the `Server` header for *any*
//! server (`gunicorn/21.2.0`, `Microsoft-IIS/10.0`, `openresty/1.25.3.1`,
//! `Caddy`), with no hand-authored regex per product. That is exactly where the
//! banner-regex analyzer is weakest — its curated `Server:` rules cover only the
//! handful of servers someone wrote a pattern for.
//!
//! ## Passive, by design
//!
//! The analyzer reads the HTTP response the transport already captured (the
//! shared [`ResponseSet`] — the reply to the `get_root` probe) instead of
//! sending its own `GET`. On the standard HTTP ports the probe has already run,
//! so re-probing here would only double the request count on the busiest ports.
//! It therefore keeps the default no-op `collect` and does all its work in
//! [`analyze`](Analyzer::analyze). (Active HTTP probing on non-standard ports —
//! where no probe is configured — is a separate, later step; it needs the
//! collect phase to know the port is worth a `GET`.)
//!
//! ## Scope of the evidence it emits
//!
//! It reports the **`Server`** product/version, the **`X-Powered-By`** secondary
//! technology (as `extrainfo`), and a baseline `http` service label. Server and
//! X-Powered-By live in different slots on purpose: `X-Powered-By` names a
//! *component* (`Apache` serving `PHP/8.2`), so it goes to `extrainfo` and can
//! never displace the real server in the resolver's single `product` slot. The
//! parser exposes every header, so further secondary-tech signals (`Set-Cookie`
//! framework cookies, `X-AspNet-Version`) are a few lines more when wanted.
//!
//! [`ResponseSet`]: super::response::ResponseSet

use async_trait::async_trait;

use super::analyzer::{Analyzer, PortContext};
use super::model::{Confidence, Evidence, SourceId};
use super::response::{Collected, ResponseSet};

/// Identifies HTTP servers from the structured headers of a captured response.
/// See the module docs for why it is passive and what evidence it emits.
pub struct HttpHeadersAnalyzer;

#[async_trait]
impl Analyzer for HttpHeadersAnalyzer {
    fn id(&self) -> SourceId {
        SourceId::HttpHeaders
    }

    // Cheap to run on any port: `analyze` self-gates on an HTTP status line, so a
    // non-HTTP banner falls straight through. Kept always-interested (like the
    // banner analyzer) rather than guessing HTTP from the port, so HTTP on an
    // unusual port is still parsed once its response has been captured.
    fn interested(&self, _ctx: &PortContext) -> bool {
        true
    }

    // Passive: the default no-op `collect` is exactly right — see the module docs.

    fn analyze(
        &self,
        ctx: &PortContext,
        responses: &ResponseSet,
        _collected: &Collected,
    ) -> Vec<Evidence> {
        // Every captured response that is actually an HTTP reply. Banners that
        // aren't HTTP (a bare grab, another protocol) are skipped.
        //
        // Several, because a port may have answered more than once: a redirect
        // and the page it pointed at are both this port's answer, and the second
        // is where the application names itself. Reading only the first left the
        // engine looking at a `302` with no body and concluding the port ran
        // whatever framework served the redirect.
        let parsed: Vec<HttpResponse<'_>> = responses
            .banners
            .iter()
            .filter_map(|banner| HttpResponse::parse(banner))
            .collect();
        // The headers below come from the *direct* answer: what this port said
        // when it was asked, not what a page one hop away said.
        let Some(http) = parsed.first() else {
            return Vec::new();
        };

        // Baseline: a valid HTTP response is itself the evidence that the port
        // speaks HTTP, even when the server does not name itself. It asserts only
        // the *service* — deliberately no product. Naming a product here (e.g.
        // "http") would, being equal-confidence with a versionless `Server`
        // match, win the resolver's single product slot on the stable-sort tie
        // and bury the real server name (`cloudflare`, `Caddy`, bare `nginx`) —
        // exactly the long tail this analyzer exists to surface.
        let mut evidence = vec![stamp(
            Evidence::new(SourceId::HttpHeaders, Confidence::Probable).with_service("http"),
            ctx,
        )];

        // The `Server` header: the long-tail product/version signal.
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
                evidence.push(stamp(server, ctx));
            }

            // And the same header, whole, against the signature set — which is
            // what reaches the imported rules that name an *operating system*.
            //
            // They cannot be reached any other way. Those patterns are written
            // against a `Server` value and anchored at both ends
            // (`^Microsoft-IIS/6.0$`), so matching them against a whole response
            // fails however much of the response is right. That single mismatch
            // hid the largest family of operating-system-bearing rules in the
            // corpus — the web servers, which map a server version to a precise
            // Windows release — behind an analyzer that had the exact text they
            // wanted sitting in a local.
            if let Some(os) = os_from(header) {
                let mut carrier =
                    Evidence::new(SourceId::HttpHeaders, Confidence::Probable).with_service("http");
                carrier.os = Some(os);
                evidence.push(stamp(carrier, ctx));
            }
        }

        // `X-Powered-By`: a *secondary* technology (PHP, ASP.NET, Express). It
        // names a component running behind the server, not the server itself, so
        // it goes to `extrainfo` — never the product slot the server owns.
        if let Some(powered_by) = http.header("x-powered-by") {
            evidence.push(stamp(
                Evidence::new(SourceId::HttpHeaders, Confidence::Probable)
                    .with_service("http")
                    .with_extrainfo(powered_by),
                ctx,
            ));
        }

        // What is *running on* the server, as distinct from the server. See
        // `application_hint`.
        let named = http
            .header("server")
            .and_then(parse_server)
            .map(|(product, _)| product);
        if let Some(application) = parsed
            .iter()
            .find_map(|response| application_hint(response, named.as_deref()))
        {
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
/// This is the answer to a question the corpus scales badly against. A signature
/// per product identifies the products somebody has written a signature for, and
/// the long tail of self-hosted software is precisely the part nobody has —
/// which is also the part a scan of somebody's own network is mostly made of. So
/// the two signals here are chosen for being *structural*: they identify by
/// where a name appears, not by matching a name that was known in advance.
///
/// **A vendor prefix on a header name.** `X-Emby-Token`, `X-Plex-Protocol`,
/// `X-Jenkins`, `X-Drupal-Cache`, `X-Shopify-Stage` — the convention of
/// prefixing one's own headers with one's own name is near-universal and it
/// hands over the vendor for free. Read across the CORS allow-list too, which is
/// where a server enumerates the vocabulary it accepts and so names itself even
/// when its response body is a bare redirect.
///
/// **The document title.** For a self-hosted application serving its own web
/// interface, the `<title>` is very often the product name and nothing else:
/// `Sonarr`, `Netdata`, `Grafana`, `Squoosh`. It is user-controlled text and so
/// is never allowed near the product slot; as supplementary detail it is the
/// difference between a row that says `http` and one that says which one.
///
/// The prefix is preferred where both exist: a title is whatever somebody typed,
/// and a header name is what the software calls itself in its own code.
///
/// `named` is the product the `Server` header already gave up, and a title that
/// mentions it is discarded. Almost every default landing page on the internet
/// is titled after the server serving it — `Welcome to nginx!`, `Apache2 Ubuntu
/// Default Page` — and repeating a name the row already carries is at best noise
/// and at worst the claim that an unconfigured web server is an application. A
/// title naming something *else* is the case this exists for, and survives.
fn application_hint(http: &HttpResponse<'_>, named: Option<&str>) -> Option<String> {
    if let Some(vendor) = vendor_prefix(http) {
        return Some(vendor);
    }

    let title = document_title(http.body)?;
    let echoes_the_server = named.is_some_and(|product| {
        let (title, product) = (title.to_ascii_lowercase(), product.to_ascii_lowercase());
        title.contains(&product) || product.contains(&title)
    });

    (!echoes_the_server).then_some(title)
}

/// Header names that begin with `x-` and name no vendor.
///
/// The list is what makes the prefix rule usable: without it `X-Frame-Options`
/// reports a product called "Frame". These are the de-facto standard extension
/// headers — a closed, slow-moving set that has nothing to do with how many
/// products exist, which is the whole reason this approach scales where a
/// signature per product does not.
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
/// The **most repeated** prefix wins, not the first. A server that has its own
/// header namespace uses it several times over, while a stray prefix from a
/// proxy, a framework or a former product name appears once — so counting
/// separates the software that is running here from everything else that
/// touched the response. Emby is the case that settled it: its allow-list leads
/// with the single `X-MediaBrowser-Token` it kept for compatibility and then
/// names itself three times.
///
/// Ties go to whichever appeared first, so the result does not depend on hash
/// ordering.
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

    // `counts` is in first-seen order, and the index breaks the tie toward the
    // front — `max_by_key` alone would take the last of equal maxima and make
    // the answer depend on header order for no reason.
    counts
        .iter()
        .enumerate()
        .max_by_key(|(index, (_, count))| (*count, std::cmp::Reverse(*index)))
        .map(|(_, (token, _))| capitalize(token))
}

/// `emby` -> `Emby`. The header was lowercased on the way in and a product name
/// rendered in lower case reads as a mistake rather than as a finding.
fn capitalize(token: &str) -> String {
    let mut chars = token.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Titles that name the page rather than the application.
///
/// An error page, a login prompt or a default landing page is served by
/// thousands of unrelated things, so reporting one as though it identified
/// something would be worse than reporting nothing.
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
fn document_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let open = lower.find("<title")?;
    let start = open + lower[open..].find('>')? + 1;
    let end = start + lower[start..].find("</title>")?;

    let title = body
        .get(start..end)?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    // A sentence is a page description, not a product. Anything this long is
    // being read for the wrong reason.
    if title.is_empty() || title.len() > 40 {
        return None;
    }
    if NOT_AN_APPLICATION.contains(&title.to_ascii_lowercase().as_str()) {
        return None;
    }
    reads_as_a_name(&title).then_some(title)
}

/// Words that may appear lowercase inside a name without making it a sentence.
///
/// Short and closed on purpose. It is the difference between `Bill of Materials`
/// and `Yo whats up`, and every word added to it moves the line toward accepting
/// the second.
const NAME_CONNECTIVES: &[&str] = &["of", "the", "and", "for", "de", "la", "du"];

/// Whether `title` reads as the name of something rather than as a remark about
/// a page.
///
/// A product name is a proper noun and is written like one, so the test is
/// whether every word is capitalised: `Home Assistant`, `Proxmox Virtual
/// Environment`, `Uptime Kuma` are names, and `Yo whats up` is somebody talking.
/// A single word is taken as a name whatever its case, because that is how a
/// great many of them are actually written — `phpMyAdmin`, `openHAB`,
/// `code-server`.
///
/// A title carrying a separator is declined outright. `Dashboard - Grafana` and
/// `Sonarr - Series` both name their product, and they name it on *opposite
/// sides*; with one page to look at there is no way to tell which convention is
/// in use, and picking wrong reports the page as the product. Declining costs a
/// name the row would have liked; guessing costs a name that is wrong, and this
/// is the weakest signal the engine has — it has no business guessing.
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
/// Matched globally rather than through the port index: a rule naming a system
/// from a `Server` value is registered under whatever service it belongs to, not
/// under port 80, so narrowing by port would skip exactly the rules wanted here.
/// The literal prefilter keeps that affordable — it selects a handful of
/// candidates out of thousands before any regex is compiled.
///
/// Only the strongest match contributes. A `Server` value that matches several
/// rules has matched several statements about one machine, and taking them all
/// would count one header as corroborating itself.
///
/// Costs 22–37 µs per header, measured — slowest when nothing matches, since a
/// miss compiles and tries every candidate the prefilter selected. Paid once per
/// open HTTP port, against a path that has already spent a TCP connect and up to
/// half a second waiting for the banner, so it does not show.
fn os_from(header: &str) -> Option<crate::fingerprint::os::OsEvidence> {
    use crate::fingerprint::prefilter::Prefilter;

    let db = crate::fingerprint::SignatureDb::global();
    db.prefilter()
        .candidates(header)
        .into_iter()
        .filter_map(|index| {
            db.signature(index)
                .identify(header, crate::fingerprint::os::OsSource::ServiceBanner)
        })
        .filter_map(|matched| matched.os)
        .max_by(|a, b| {
            a.confidence
                .partial_cmp(&b.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
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
    let token = value.split_whitespace().next()?;

    if let Some((product, version)) = token.split_once('/') {
        let product = product.trim_end_matches('(');
        let versioned = version.starts_with(|c: char| c.is_ascii_digit());
        if !product.is_empty() && !is_placeholder(product) && versioned {
            return Some((product.to_string(), Some(version.to_string())));
        }
        // A `/` but no numeric version (e.g. a URL-ish token): treat the whole
        // left side as the product name, no version.
        if !product.is_empty() && !is_placeholder(product) {
            return Some((product.to_string(), None));
        }
    }

    // No `/`: the token is a bare product name (possibly with a `(` comment).
    let product = token.split('(').next().unwrap_or(token);
    (!product.is_empty() && !is_placeholder(product)).then(|| (product.to_string(), None))
}

/// Whether a server token is a null-ish placeholder rather than a real product
/// name. Some devices (notably embedded/router HTTP stacks) emit `Server: null`,
/// `unknown`, `-`, and the like — a captured value, but no identification. We
/// drop it so the resolver keeps the clean `http` baseline instead of surfacing
/// a bogus product.
fn is_placeholder(product: &str) -> bool {
    matches!(
        product.trim().to_ascii_lowercase().as_str(),
        "" | "null" | "nil" | "none" | "unknown" | "unspecified" | "-"
    )
}

/// A minimally-parsed HTTP response: enough to read headers by name. The body is
/// discarded — only the status line (as the marker that this *is* HTTP) and the
/// header block are retained.
struct HttpResponse<'a> {
    /// `(lowercased name, trimmed value)` in wire order.
    headers: Vec<(String, String)>,
    /// Whatever followed the blank line, as far as the response was read.
    ///
    /// Kept because on the ports that need identifying most, the body is the
    /// only place the application names itself: a self-hosted service on an
    /// unregistered number very often serves a single-page app whose `<title>`
    /// is its own name and whose `Server` header names the framework
    /// underneath it, if it sets one at all.
    body: &'a str,
}

impl<'a> HttpResponse<'a> {
    /// Parses `raw` if it begins with an HTTP status line. Returns `None` for
    /// anything that is not an HTTP response, so the analyzer can scan a mixed
    /// set of banners and pick the HTTP one.
    fn parse(raw: &'a str) -> Option<Self> {
        // The status line must lead. This is what distinguishes an HTTP reply
        // from any other captured banner.
        if !raw.starts_with("HTTP/") {
            return None;
        }

        // Headers end at the first blank line and the body follows it. Tolerant
        // of both CRLF and bare LF, and of a response cut off before either.
        let (head, body) = raw
            .find("\r\n\r\n")
            .map(|at| (&raw[..at], &raw[at + 4..]))
            .or_else(|| raw.find("\n\n").map(|at| (&raw[..at], &raw[at + 2..])))
            .unwrap_or((raw, ""));

        let mut headers = Vec::new();
        // Skip the status line; every remaining line of the head is a header.
        for line in head.split('\n').skip(1) {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }

        Some(HttpResponse { headers, body })
    }

    /// Every header name this response carries, plus the names it *mentions* in
    /// its CORS allow-list.
    ///
    /// The allow-list is included because it is a list of header names the
    /// server expects a client to send, which is the server enumerating its own
    /// vocabulary — and a server's vocabulary names it. One media server was
    /// identified from nothing else: it sent no product anywhere in its
    /// response, and then listed `X-Emby-Token` among the headers it would
    /// accept.
    fn header_vocabulary(&self) -> impl Iterator<Item = &str> {
        self.headers.iter().map(|(name, _)| name.as_str()).chain(
            self.header("access-control-allow-headers")
                .into_iter()
                .flat_map(|value| value.split(',').map(str::trim)),
        )
    }

    /// The value of the first header named `name` (which must be lowercase),
    /// case-insensitively. `None` if absent or empty.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
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
            },
            &ResponseSet::from_banners(banners.iter().map(|b| (*b).to_string()).collect()),
            &Collected::default(),
        )
    }

    /// A redirect and the page it pointed at are both this port's answer, and
    /// the application names itself in the second one.
    ///
    /// The shape every ASP.NET media server has: the root is a bare 302 whose
    /// only product is the framework, and one hop away is a page whose title is
    /// the product. Reading the first response alone reported both Jellyfin and
    /// Sonarr as `Kestrel`, which is true and useless.
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

    /// A media server that names no product anywhere in its response, and then
    /// lists the headers it will accept — among them its own.
    ///
    /// Captured from a real Emby server on port 8097, which nmap reported as
    /// `upnp` from the `Server` header of its embedded DLNA stack. The DLNA
    /// stack is real and so is the header; it is just not what is running there.
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

    /// The standard extension headers name no vendor, and reporting one as a
    /// product would make the whole rule unusable — every response on the
    /// internet carries some of these.
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

    /// For a self-hosted application the document title is very often the
    /// product name and nothing else, and on the ports that most need
    /// identifying it is the only place the name appears.
    ///
    /// Captured from a real server on port 7778, which nmap reported as
    /// `interwise?` — unrecognised — with `<title>Squoosh</title>` in the body
    /// it had already read.
    #[test]
    fn the_document_title_names_an_application_nobody_wrote_a_rule_for() {
        let banner = "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=utf-8\r\n\r\n\
             <!DOCTYPE html><html lang=\"en\"><head><title>Squoosh</title><meta \
             name=\"description\" content=\"Squoosh is the ultimate image optimizer\" />";

        assert_eq!(extrainfo(7778, banner).as_deref(), Some("Squoosh"));
    }

    /// The default landing page of a web server is titled after the web server,
    /// and a row reading `nginx 1.22.1 (Welcome to nginx!)` has said one thing
    /// twice and called the second one an application.
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

        // A title naming something the `Server` header did not is the whole
        // point, and has to survive the filter.
        let different = "HTTP/1.1 200 OK\r\n\
             Server: Kestrel\r\n\r\n\
             <html><head><title>Jellyfin</title>";
        assert_eq!(extrainfo(8096, different).as_deref(), Some("Jellyfin"));
    }

    /// A title that names the page rather than the application identifies
    /// thousands of unrelated things, so it identifies nothing.
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

    /// Two prefixes used equally often resolve to the one the server mentioned
    /// first, so the answer does not depend on header order beyond that.
    #[test]
    fn a_tie_between_prefixes_goes_to_the_first_mentioned() {
        let banner = "HTTP/1.1 200 OK\r\nX-Alpha-One: a\r\nX-Bravo-One: b\r\n\r\n";
        let http = HttpResponse::parse(banner).expect("an HTTP response");
        assert_eq!(vendor_prefix(&http).as_deref(), Some("Alpha"));
    }

    /// The case that motivated the shape test: a title is whatever somebody
    /// typed, and most of the web is not a product name.
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

    /// A product name is a proper noun and is written like one — including the
    /// several-word ones, and including the single words that are not
    /// capitalised at all.
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

    /// `Dashboard - Grafana` and `Sonarr - Series` both name their product, on
    /// opposite sides of the separator. With one page to look at there is no way
    /// to tell which convention is in use, so neither is guessed at.
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

    /// A vendor prefix is what the software calls itself in its own code; a
    /// title is whatever somebody typed into a template. Where both exist the
    /// first one wins.
    #[test]
    fn a_vendor_prefix_outranks_a_title() {
        let banner = "HTTP/1.1 200 OK\r\n\
             X-Jenkins: 2.426.3\r\n\r\n\
             <html><head><title>Dashboard</title>";

        assert_eq!(extrainfo(8080, banner).as_deref(), Some("Jenkins"));
    }

    /// The body is only reachable if the parser kept it, and it only exists if
    /// the transport read past the header block. Both were true of neither
    /// before this analyzer learned to read a title.
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
        // A server with no hand-authored regex: the structured parse still names
        // product and version, which is the whole point of this analyzer.
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
        // The imported `^Microsoft-IIS/[1234]\.0$` rules never reach 10.0 — and
        // are anchored to a bare value they never see in a full response anyway.
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
        // The baseline names no product: that slot is reserved for a real server
        // name so a versionless `Server` header is never clobbered (see below).
        assert_eq!(evidence[0].product, None);
    }

    #[test]
    fn x_powered_by_becomes_extrainfo_beside_the_server_product() {
        // The server owns the product slot; the framework is a separate signal.
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
        // Crucially, no evidence names PHP as a *product*.
        assert!(
            evidence
                .iter()
                .all(|e| e.product.as_deref() != Some("PHP/8.2.1"))
        );
    }

    #[test]
    fn placeholder_server_token_names_no_product() {
        // Embedded/router stacks that answer `Server: null` must not surface
        // "null" as a product; the response still counts as HTTP, so only the
        // baseline `http` evidence (no product) remains.
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
        /// The response parser must never panic on arbitrary input — banners come
        /// off the wire. `(?s)` lets `.` match newlines, so CRLF/LF framing edge
        /// cases (empty lines, colon-less lines, unterminated headers) are fuzzed.
        #[test]
        fn http_parse_never_panics(raw in "(?s).*") {
            let _ = HttpResponse::parse(&raw);
        }

        /// A valid status line forces the header-parsing path, so the fuzzed body
        /// exercises header splitting rather than bouncing off the `HTTP/` gate.
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
        // Header names are case-insensitive on the wire; a lowercase `server`
        // must still be found.
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

    /// The seam this exists to close, checked against the shipped corpus rather
    /// than a fixture.
    ///
    /// A real `Server` header, through the real analyzer, has to reach the
    /// imported rule that maps that server version to a Windows release. Before
    /// this, the rule was compiled into the database and unreachable: it is
    /// anchored to a header *value*, and the matcher only ever saw whole
    /// responses.
    #[test]
    fn a_server_header_reaches_the_rules_that_name_a_windows_release() {
        let evidence = HttpHeadersAnalyzer.analyze(
            &PortContext {
                port: 80,
                protocol: crate::model::port::Protocol::Tcp,
                addr: None,
                tunnel: None,
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

    /// The failure mode this replaced. Matching the whole response against rules
    /// anchored to a header value cannot succeed, and looks exactly like a corpus
    /// that has no such rule — so the check is that the *response* form still
    /// fails while the extracted form works.
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
                db.signature(index)
                    .identify(response, crate::fingerprint::os::OsSource::ServiceBanner)
            })
            .find_map(|matched| matched.os);

        assert!(
            from_response.is_none(),
            "if this ever starts matching, the rules changed shape and `os_from` \
             should be reconsidered rather than left as a workaround"
        );
        assert!(
            os_from("Microsoft-IIS/6.0").is_some(),
            "while the value those rules are written against does match"
        );
    }

    /// A server the corpus knows nothing about must name no operating system,
    /// rather than falling through to whichever rule is loosest.
    #[test]
    fn a_server_the_corpus_does_not_know_names_nothing() {
        assert!(os_from("SomeServer/1.0").is_none());
    }
}
