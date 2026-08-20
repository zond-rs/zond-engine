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
        // The first captured response that is actually an HTTP reply. Banners
        // that aren't HTTP (a bare grab, another protocol) are skipped.
        let Some(http) = responses
            .banners
            .iter()
            .find_map(|banner| HttpResponse::parse(banner))
        else {
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

        evidence
    }
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
        .filter_map(|index| db.signature(index).identify(header))
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
struct HttpResponse {
    /// `(lowercased name, trimmed value)` in wire order.
    headers: Vec<(String, String)>,
}

impl HttpResponse {
    /// Parses `raw` if it begins with an HTTP status line. Returns `None` for
    /// anything that is not an HTTP response, so the analyzer can scan a mixed
    /// set of banners and pick the HTTP one.
    fn parse(raw: &str) -> Option<Self> {
        // The status line must lead. This is what distinguishes an HTTP reply
        // from any other captured banner.
        if !raw.starts_with("HTTP/") {
            return None;
        }

        let mut headers = Vec::new();
        // Skip the status line; headers follow until the first blank line, which
        // separates them from the body. Tolerant of both CRLF and bare LF.
        for line in raw.split('\n').skip(1) {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.is_empty() {
                break; // end of the header block
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }

        Some(HttpResponse { headers })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::model::Tunnel;
    use proptest::prelude::*;

    fn analyze(port: u16, banner: &str) -> Vec<Evidence> {
        HttpHeadersAnalyzer.analyze(
            &PortContext {
                port,
                addr: None,
                tunnel: None,
            },
            &ResponseSet::from_banners(vec![banner.to_string()]),
            &Collected::default(),
        )
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

        assert_eq!(os.family, "Windows");
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
            .filter_map(|index| db.signature(index).identify(response))
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
