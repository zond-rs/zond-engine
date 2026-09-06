// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The icon a web application serves, as an identifier
//!
//! A self-hosted application very often names itself nowhere in its HTTP
//! response: no `Server` value of its own, a generic title, a body that is one
//! script tag. It still serves `/favicon.ico`, and that file is part of the
//! product rather than of the deployment, so the same application serves the
//! same bytes everywhere it is installed.
//!
//! The corpus is keyed on the MD5 of those bytes and holds several hundred
//! products under it, which makes this the largest single identification source
//! here that costs one request.
//!
//! ## MD5 because the data says so
//!
//! The digest is fixed by the corpus, which was imported already keyed on it.
//! Nothing here is a security decision: the hash is a lookup key, a collision
//! would name the wrong product rather than admit anything, and an attacker who
//! wants to be identified as something else can simply serve that product's icon.
//!
//! ## What it costs, and when it is paid
//!
//! One `GET` on a connection of its own, and only where first contact already
//! drew an HTTP response. That is what
//! [`speaks_http`](super::analyzer::PortContext::speaks_http) is for: gating on
//! the port number instead would skip the long tail, which is exactly where an
//! application declines to name itself and the icon is the only thing left.

use async_trait::async_trait;
use md5::{Digest, Md5};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use std::time::Duration;

use super::analyzer::{Analyzer, PortContext};
use super::model::{Evidence, SourceId};
use super::response::{Collected, ResponseSet};

/// How long the whole exchange may take, connect included.
///
/// Shorter than a banner read, because this is a second request to a server that
/// has already answered once: it is known reachable, and a server that has
/// started responding and then stops is not worth waiting out.
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// The most of a response body to read.
///
/// A favicon is a few kilobytes. The cap is generous enough for the ones that
/// are not, and is what stops a server that answers this request with an endless
/// stream from being able to.
const MAX_ICON_BYTES: usize = 256 * 1024;

/// Where an icon lives when a page declares none. Still worth asking for: it is
/// the convention every browser falls back on, and plenty of servers honour it.
const CONVENTIONAL_PATH: &str = "/favicon.ico";

/// One request. `Host` is a fixed `localhost`, as the signature corpus sends it;
/// the scanned host is not seeded as a variable anywhere in this engine yet.
fn request(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

/// Identifies a web application by the MD5 of the icon it serves.
pub struct FaviconAnalyzer;

#[async_trait]
impl Analyzer for FaviconAnalyzer {
    fn id(&self) -> SourceId {
        SourceId::Favicon
    }

    fn interested(&self, ctx: &PortContext) -> bool {
        // A second TCP request, so it needs a peer to dial and a reason to think
        // one is worth making.
        ctx.speaks_http && ctx.addr.is_some()
    }

    async fn collect(&self, ctx: &PortContext, responses: &ResponseSet) -> Collected {
        let Some(addr) = ctx.addr else {
            return Collected::default();
        };
        // One budget for the whole search, however many requests it takes, so a
        // slow server cannot cost more by declaring its icon than by not.
        match timeout(FETCH_TIMEOUT, icon_of(addr, responses)).await {
            Ok(Some(icon)) => Collected::from_frames(vec![icon]),
            _ => Collected::default(),
        }
    }

    fn analyze(
        &self,
        _ctx: &PortContext,
        _responses: &ResponseSet,
        collected: &Collected,
    ) -> Vec<Evidence> {
        let Some(icon) = collected.frames.first() else {
            return Vec::new();
        };

        // The digest is the whole text a rule reads, so it goes to the field
        // matcher rather than through a port's signatures: a favicon rule is
        // registered under whatever service owns the product, never under 80.
        let digest = md5_hex(icon);
        super::db::SignatureDb::global()
            .identify_field(&digest)
            .map(|evidence| vec![as_application(evidence)])
            .unwrap_or_default()
    }
}

/// Marks a corpus match as this analyzer's, and states the name it found in both
/// the product slot and beside it.
///
/// Twice on purpose. An icon names the *application*; a `Server` value names the
/// listener in front of it. Metabase behind nginx is both, and they are two
/// facts about one port rather than a disagreement.
///
/// Only one of them can hold the product, and it will not be this one: a
/// `Server: nginx/1.24.0` captures a version, which makes it `Strong`, and it is
/// port-confirmed, so it takes the slot on both tiebreaks. Without the second
/// statement the application name is discarded on every reverse-proxied host,
/// which is a large share of the deployments these rules exist for.
///
/// [`ServiceVerdict::resolve`](super::model::ServiceVerdict::resolve) drops the
/// duplicate where the icon does take the product slot, so an anonymous server
/// reports the application once rather than twice.
fn as_application(mut evidence: Evidence) -> Evidence {
    evidence.source = SourceId::Favicon;
    match evidence.product.clone() {
        Some(product) => evidence.with_extrainfo(product),
        None => evidence,
    }
}

/// The digest of the icon `addr` serves, found exactly as a scan finds it.
///
/// An instrument for the container tier, which measures real software so a rule
/// can be written against what an application serves today. It goes through
/// `icon_of` rather than reimplementing the search, because a harvester that
/// measured differently from the scanner would produce hashes no scan can match:
/// that is how the certificate work nearly shipped two hundred dead rules.
///
/// Behind `test-support`, since nothing in a scan needs it.
#[cfg(any(test, feature = "test-support"))]
pub async fn digest_of(addr: std::net::SocketAddr) -> Option<String> {
    let icon = icon_of(addr, &ResponseSet::default()).await?;
    Some(md5_hex(&icon))
}

/// The lowercase hex MD5 of `bytes`, which is the form the corpus is keyed on.
fn md5_hex(bytes: &[u8]) -> String {
    Md5::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The icon this endpoint serves, found the way a browser finds one.
///
/// Asking for `/favicon.ico` and stopping there is what the first version of
/// this did, and it reaches almost none of the applications the corpus is for.
/// Anything built with a bundler serves its icon under a content-hashed name
/// (`favicon.bc8d51405ec040305a87.ico`) and declares it in a `<link>`; Jellyfin
/// answers the conventional path with a 404 while serving an icon whose digest
/// the corpus holds. So the page is read first and its declaration followed,
/// with the conventional path as the fallback it always was.
///
/// The page usually costs nothing: first contact already fetched `/`, and only a
/// root that redirects (which a self-hosted application very often does) needs a
/// request to reach the markup.
async fn icon_of(addr: std::net::SocketAddr, responses: &ResponseSet) -> Option<Vec<u8>> {
    let (page, base) = page_of(addr, responses).await;

    let declared = page
        .as_deref()
        .and_then(declared_icon)
        .and_then(|href| resolve(&base, href));

    // The declared path first, then the convention. A page that names its icon
    // is describing itself, and the fallback exists for the servers that say
    // nothing rather than to second-guess the ones that do.
    for path in declared
        .iter()
        .map(String::as_str)
        .chain([CONVENTIONAL_PATH])
    {
        if let Some(icon) = fetch(addr, path).await {
            return Some(icon);
        }
    }
    None
}

/// The markup this endpoint serves at its root, and the path it was served from.
///
/// The path matters because a declared icon is usually relative to it: Jellyfin
/// redirects `/` to `/web/index.html` and declares `favicon.<hash>.ico`, which
/// resolves under `/web/` and nowhere else.
///
/// Reuses what first contact read and follows one same-host redirect from it. A
/// second hop is not followed: one is what a self-hosted root costs, and a chain
/// is a server that does not want to be read.
async fn page_of(addr: std::net::SocketAddr, responses: &ResponseSet) -> (Option<String>, String) {
    let root = "/".to_string();

    // `None` where nothing was read, which is how the container tier drives this
    // with no scan behind it. The root is asked for either way below.
    let first = responses
        .banners
        .iter()
        .find(|banner| banner.starts_with("HTTP/"));

    // A reply that already declares an icon is the page, whatever drew it.
    if let Some(page) = first.filter(|page| declared_icon(page).is_some()) {
        return (Some(page.clone()), root);
    }

    // Otherwise ask for the root. A port some service registered a probe for is
    // answered with that probe rather than with `GET /`, so on a claimed port the
    // banners hold whatever the probe drew and never the markup: Grafana on 3000
    // answers its registered probe with a `400` and its root with the page that
    // names it. The banner is still consulted for a redirect first, so an
    // unclaimed port that already fetched `/` spends no request re-fetching it.
    let path = first
        .and_then(|page| super::redirect_path(page, Some(addr)))
        .unwrap_or_else(|| root.clone());
    let Some(page) = fetch_text(addr, &path).await else {
        return (first.cloned(), root);
    };

    // The root may redirect on this request rather than on the scan's. One hop,
    // because a chain is a server that does not want to be read.
    match super::redirect_path(&page, Some(addr)) {
        Some(next) => match fetch_text(addr, &next).await {
            Some(followed) => (Some(followed), next),
            None => (Some(page), path),
        },
        None => (Some(page), path),
    }
}

/// The icon a page declares, as the `href` of a `<link>` whose `rel` names one.
///
/// Reads `rel` and `href` in either order and matches `rel` on a word rather
/// than a whole value, because the attribute is a list and the ones in use are
/// `icon`, `shortcut icon` and `apple-touch-icon`. Case-insensitive throughout:
/// markup is not consistent about it and nothing here depends on the casing.
fn declared_icon(page: &str) -> Option<&str> {
    let lower = page.to_ascii_lowercase();
    let mut at = 0;

    while let Some(start) = lower[at..].find("<link").map(|i| at + i) {
        let end = lower[start..].find('>').map(|i| start + i)?;
        let tag = &lower[start..end];
        at = end;

        let names_an_icon = attribute(tag, "rel")
            .is_some_and(|rel| rel.split_whitespace().any(|word| word == "icon"));
        if !names_an_icon {
            continue;
        }
        // Taken from the original rather than the lowered copy: a path is
        // case-sensitive and the lowered one would 404.
        if let Some(href) = attribute(tag, "href") {
            let offset = tag.find(href)?;
            return page.get(start + offset..start + offset + href.len());
        }
    }
    None
}

/// The value of `name` in a tag, for a quoted attribute.
fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let at = tag.find(&format!("{name}="))? + name.len() + 1;
    let rest = tag.get(at..)?;
    let quote = rest.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let value = rest.get(1..)?;
    value.get(..value.find(quote)?)
}

/// Resolves a declared `href` against the path the page was served from.
///
/// An absolute path is taken as written. A relative one is joined to the page's
/// own directory, which is what puts Jellyfin's icon under `/web/`. Anything
/// naming a scheme or another host is declined: the corpus is keyed on what
/// *this* endpoint serves, and hashing a content delivery network's bytes would
/// key another host's icon to this port.
fn resolve(base: &str, href: &str) -> Option<String> {
    let href = href.trim();
    if href.is_empty() || href.starts_with("//") {
        return None;
    }

    // Anything naming a scheme. An absolute URL is another host's bytes, and a
    // `data:` icon is inline rather than fetchable: Portainer declares one, and
    // reading it as a path would put four kilobytes of base64 into a request
    // line. A scheme is what precedes the first `:`, and only before the first
    // `/`, so a path may still contain a colon of its own.
    let scheme_end = href
        .find(':')
        .filter(|at| *at < href.find('/').unwrap_or(usize::MAX));
    if scheme_end.is_some() {
        return None;
    }
    if href.starts_with('/') {
        return Some(href.to_string());
    }

    let directory = match base.rfind('/') {
        Some(at) => &base[..=at],
        None => "/",
    };

    // `./` is legal and common (Prometheus declares `./favicon.svg`). Servers
    // tolerate it, but a path this engine may later compare or record should not
    // carry a segment that means nothing.
    let href = href.strip_prefix("./").unwrap_or(href);
    Some(format!("{directory}{href}"))
}

/// Fetches `path` and returns its body, or [`None`] where there is not one.
///
/// A body is returned only for a `200`. A `404` is the ordinary answer from a
/// server that serves no icon at the path asked for.
///
/// One same-host redirect is followed, because an icon is very often served from
/// somewhere other than where it is asked for: Grafana answers `/favicon.ico`
/// with a `302` to the file it actually holds.
async fn fetch(addr: std::net::SocketAddr, path: &str) -> Option<Vec<u8>> {
    let response = exchange(addr, path).await?;

    if let Some(body) = body_of(&response) {
        return Some(body.to_vec());
    }

    let head = String::from_utf8_lossy(&response);
    let next = super::redirect_path(&head, Some(addr))?;
    let followed = exchange(addr, &next).await?;
    body_of(&followed).map(<[u8]>::to_vec)
}

/// The same exchange, as text, for a page rather than an icon.
async fn fetch_text(addr: std::net::SocketAddr, path: &str) -> Option<String> {
    let response = exchange(addr, path).await?;
    Some(String::from_utf8_lossy(&response).into_owned())
}

/// One request and the response it draws, whole and bounded.
async fn exchange(addr: std::net::SocketAddr, path: &str) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await.ok()?;
    stream.write_all(&request(path)).await.ok()?;

    let mut response = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = stream.read(&mut buffer).await.ok()?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..read]);
        if response.len() >= MAX_ICON_BYTES {
            break;
        }
    }
    Some(response)
}

/// The body of a `200` response, or [`None`] for anything else.
///
/// Split on the header terminator rather than parsed: nothing here reads a
/// header, and an icon is bytes rather than text, so the response cannot be
/// handled as a string without corrupting exactly the thing being hashed.
fn body_of(response: &[u8]) -> Option<&[u8]> {
    let status = response.get(..response.iter().position(|b| *b == b'\r')?)?;
    if !status.starts_with(b"HTTP/") || !is_success(status) {
        return None;
    }

    let at = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let body = response.get(at + 4..)?;
    (!body.is_empty()).then_some(body)
}

/// Whether a status line carries a `200`, whatever reason phrase follows it.
///
/// Read as the second field rather than by matching `200 OK`, because the reason
/// phrase is the server's to choose and several embedded stacks choose their own.
fn is_success(status: &[u8]) -> bool {
    status
        .split(|byte| *byte == b' ')
        .nth(1)
        .is_some_and(|code| code == b"200")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest of the empty string, which is the one MD5 vector everybody
    /// knows by sight, so a broken hash is visible rather than merely different.
    #[test]
    fn the_digest_is_lowercase_hex() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn a_body_is_taken_from_a_200_and_from_nothing_else() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Type: image/x-icon\r\n\r\n\x00\x01icon";
        assert_eq!(body_of(ok), Some(&b"\x00\x01icon"[..]));

        let missing = b"HTTP/1.1 404 Not Found\r\n\r\nnope";
        assert_eq!(body_of(missing), None);
    }

    /// A redirect names somewhere else's bytes, and hashing those would key
    /// another host's icon to this port.
    #[test]
    fn a_redirect_is_declined_rather_than_followed() {
        let moved = b"HTTP/1.1 302 Found\r\nLocation: https://cdn.example/favicon.ico\r\n\r\n";
        assert_eq!(body_of(moved), None);
    }

    #[test]
    fn a_reason_phrase_other_than_ok_still_reads_as_success() {
        let odd = b"HTTP/1.0 200 Document follows\r\n\r\nbytes";
        assert_eq!(body_of(odd), Some(&b"bytes"[..]));
    }

    #[test]
    fn a_response_with_no_body_yields_nothing_to_hash() {
        assert_eq!(body_of(b"HTTP/1.1 200 OK\r\n\r\n"), None);
        assert_eq!(body_of(b"not http at all"), None);
        assert_eq!(body_of(b""), None);
    }

    /// The gate, both halves. A port that never spoke HTTP is not dialled again,
    /// and neither is one with no address to dial.
    #[test]
    fn only_a_port_that_answered_in_http_is_asked_for_an_icon() {
        use crate::model::port::Protocol;

        let addr = Some("127.0.0.1:80".parse().unwrap());
        let http = PortContext::new(80, Protocol::Tcp)
            .with_addr(addr)
            .with_speaks_http(true);
        assert!(FaviconAnalyzer.interested(&http));

        let quiet = PortContext::new(80, Protocol::Tcp)
            .with_addr(addr)
            .with_speaks_http(false);
        assert!(!FaviconAnalyzer.interested(&quiet));

        let no_socket = PortContext::new(80, Protocol::Tcp).with_speaks_http(true);
        assert!(!FaviconAnalyzer.interested(&no_socket));
    }

    /// The fallback, end to end: a page that declares no icon still gets the
    /// conventional path asked for, which is what the convention is for.
    #[tokio::test]
    async fn a_page_declaring_no_icon_falls_back_to_the_conventional_path() {
        use crate::model::port::Protocol;
        use tokio::net::TcpListener;

        const ICON: &[u8] = b"\x00\x00\x01\x00 not really an icon, but bytes are bytes";

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut asked = Vec::new();
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buffer = [0u8; 512];
                let read = stream.read(&mut buffer).await.unwrap();
                let path = String::from_utf8_lossy(&buffer[..read])
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                asked.push(path.clone());

                if path == CONVENTIONAL_PATH {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: image/x-icon\r\n\r\n")
                        .await
                        .unwrap();
                    stream.write_all(ICON).await.unwrap();
                } else {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head></head></html>",
                        )
                        .await
                        .unwrap();
                }
            }
            asked
        });

        // A banner that is a page, and declares nothing.
        let responses = ResponseSet::from_banners(vec![
            "HTTP/1.1 200 OK\r\n\r\n<html><head></head></html>".to_string(),
        ]);

        let ctx = PortContext::new(addr.port(), Protocol::Tcp)
            .with_addr(Some(addr))
            .with_speaks_http(true);
        let collected = FaviconAnalyzer.collect(&ctx, &responses).await;
        let asked = server.await.unwrap();

        assert_eq!(collected.frames.first().map(Vec::as_slice), Some(ICON));
        assert!(
            asked.contains(&CONVENTIONAL_PATH.to_string()),
            "the convention should be tried when nothing is declared, got {asked:?}"
        );
    }

    /// The other half, without a socket: a digest the corpus knows names its
    /// product. Metabase, whose icon MD5 is one of the shipped rules.
    #[test]
    fn a_known_digest_names_the_application_that_serves_it() {
        let evidence = crate::fingerprint::SignatureDb::global()
            .identify_field("4297c114f263c206ed12aaff4b0c7a50")
            .expect("the corpus names it");
        assert_eq!(evidence.product.as_deref(), Some("Metabase"));
    }

    /// The name is stated in both slots so it survives losing the product
    /// tiebreak to a `Server` header, and is stamped as this analyzer's.
    #[test]
    fn a_match_states_the_application_in_both_slots() {
        let found = Evidence::new(
            SourceId::BannerRegex,
            crate::model::confidence::Confidence::Probable,
        )
        .with_service("favicons.xml")
        .with_product("Metabase");

        let marked = as_application(found);
        assert_eq!(marked.source, SourceId::Favicon);
        assert_eq!(marked.product.as_deref(), Some("Metabase"));
        assert_eq!(marked.extrainfo.as_deref(), Some("Metabase"));
    }

    /// A rule that names no product has nothing to carry into the second slot.
    #[test]
    fn a_match_naming_no_product_states_nothing_beside_it() {
        let found = Evidence::new(
            SourceId::BannerRegex,
            crate::model::confidence::Confidence::Probable,
        )
        .with_service("favicons.xml");
        assert_eq!(as_application(found).extrainfo, None);
    }

    /// A server answering with a stream that does not end cannot hold the scan.
    /// The read stops at the cap and what was collected is still hashed, so a
    /// hostile peer costs a bounded amount rather than the process.
    #[tokio::test]
    async fn an_endless_response_is_cut_off_at_the_cap() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 512];
            let _ = stream.read(&mut buffer).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: image/x-icon\r\n\r\n")
                .await
                .unwrap();
            // More than the cap, in chunks, until the reader gives up on us.
            let chunk = vec![0xab; 32 * 1024];
            for _ in 0..64 {
                if stream.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });

        let icon = fetch(addr, "/favicon.ico").await.expect("a bounded body");
        server.abort();

        assert!(
            icon.len() <= MAX_ICON_BYTES,
            "read {} bytes, past the {MAX_ICON_BYTES} cap",
            icon.len()
        );
        assert!(!icon.is_empty(), "what was read is still worth hashing");
    }

    /// Jellyfin's real markup, which is why this analyzer was rewritten: the
    /// icon is under a bundler's content hash and named only in a `<link>`.
    const JELLYFIN: &str = r#"<html><head>
        <link rel="apple-touch-icon" sizes="180x180" href="touchicon.f5bbb798cb2c65908633.png">
        <link rel="shortcut icon" href="favicon.bc8d51405ec040305a87.ico">
        </head></html>"#;

    #[test]
    fn a_declared_icon_is_read_out_of_the_markup() {
        assert_eq!(
            declared_icon(JELLYFIN),
            Some("favicon.bc8d51405ec040305a87.ico")
        );
    }

    /// `rel` is a list, so the match is on a word. `apple-touch-icon` is one
    /// token and must not be read as naming the icon.
    #[test]
    fn a_rel_that_merely_contains_icon_does_not_count() {
        let only_touch = r#"<link rel="apple-touch-icon" href="touch.png">"#;
        assert_eq!(declared_icon(only_touch), None);

        let shortcut = r#"<link rel="shortcut icon" href="a.ico">"#;
        assert_eq!(declared_icon(shortcut), Some("a.ico"));
    }

    /// Attributes come in either order, and single quotes are legal markup.
    #[test]
    fn the_href_is_found_whatever_order_and_quoting_the_tag_uses() {
        assert_eq!(
            declared_icon(r#"<link href="/static/f.ico" rel="icon">"#),
            Some("/static/f.ico")
        );
        assert_eq!(
            declared_icon("<link rel='icon' href='/q.ico'>"),
            Some("/q.ico")
        );
    }

    /// The path is taken from the original markup rather than the lowered copy
    /// used for scanning, because a path is case-sensitive and a lowered one
    /// would 404.
    #[test]
    fn a_mixed_case_path_survives_the_search() {
        assert_eq!(
            declared_icon(r#"<link rel="ICON" href="/Static/FavIcon.ICO">"#),
            Some("/Static/FavIcon.ICO")
        );
    }

    /// The resolution that puts Jellyfin's icon under `/web/`.
    #[test]
    fn a_relative_icon_resolves_against_the_page_that_declared_it() {
        assert_eq!(
            resolve("/web/index.html", "favicon.bc8d51405ec040305a87.ico").as_deref(),
            Some("/web/favicon.bc8d51405ec040305a87.ico")
        );
        assert_eq!(resolve("/", "favicon.ico").as_deref(), Some("/favicon.ico"));
        assert_eq!(
            resolve("/web/index.html", "/f.ico").as_deref(),
            Some("/f.ico")
        );
    }

    /// An icon somewhere else is another host's bytes, and hashing them would
    /// key that host's identity to this port.
    #[test]
    fn an_icon_on_another_host_is_declined() {
        assert_eq!(resolve("/", "https://cdn.example/f.ico"), None);
        assert_eq!(resolve("/", "//cdn.example/f.ico"), None);
        assert_eq!(resolve("/", ""), None);
    }

    /// Portainer declares its icon inline. Read as a path it would put four
    /// kilobytes of base64 into a request line, so a scheme of any kind is
    /// declined.
    #[test]
    fn an_inline_data_icon_is_not_mistaken_for_a_path() {
        let inline = "data:image/vnd.microsoft.icon;base64,AAABAAEAEBAAAAEAIABoBAAA";
        assert_eq!(resolve("/", inline), None);
        assert_eq!(resolve("/", "mailto:someone@example.com"), None);
    }

    /// A colon after the first slash is part of a path, not a scheme.
    #[test]
    fn a_colon_inside_a_path_is_still_a_path() {
        assert_eq!(
            resolve("/", "/assets/img:v2/f.ico").as_deref(),
            Some("/assets/img:v2/f.ico")
        );
    }

    #[test]
    fn markup_declaring_no_icon_yields_nothing() {
        assert_eq!(
            declared_icon("<html><head><title>x</title></head></html>"),
            None
        );
        assert_eq!(declared_icon(""), None);
    }

    /// The whole path against a server shaped like Jellyfin: the root redirects,
    /// the page declares a hashed icon under `/web/`, and only that path serves
    /// the bytes. The conventional path 404s, exactly as the real one does.
    #[tokio::test]
    async fn the_declared_icon_is_fetched_from_a_root_that_redirects() {
        use crate::model::port::Protocol;
        use tokio::net::TcpListener;

        const ICON: &[u8] = b"\x00\x00\x01\x00 the bytes only /web/ serves";

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut asked = Vec::new();
            for _ in 0..3 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buffer = [0u8; 512];
                let read = stream.read(&mut buffer).await.unwrap();
                let path = String::from_utf8_lossy(&buffer[..read])
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();

                match path.as_str() {
                    "/web/index.html" => {
                        let body =
                            format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{JELLYFIN}");
                        stream.write_all(body.as_bytes()).await.unwrap();
                    }
                    "/web/favicon.bc8d51405ec040305a87.ico" => {
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: image/x-icon\r\n\r\n")
                            .await
                            .unwrap();
                        stream.write_all(ICON).await.unwrap();
                        // The search stops here, so accepting again would block
                        // on a connection that is never made.
                        asked.push(path);
                        break;
                    }
                    _ => {
                        stream
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .unwrap();
                    }
                }
                asked.push(path);
            }
            asked
        });

        // What first contact drew: the 302 the real server answers `GET /` with.
        let responses = ResponseSet::from_banners(vec![
            "HTTP/1.1 302 Found\r\nLocation: /web/index.html\r\nServer: Kestrel\r\n\r\n"
                .to_string(),
        ]);

        let ctx = PortContext::new(addr.port(), Protocol::Tcp)
            .with_addr(Some(addr))
            .with_speaks_http(true);
        let collected = FaviconAnalyzer.collect(&ctx, &responses).await;
        let asked = server.await.unwrap();

        assert_eq!(collected.frames.first().map(Vec::as_slice), Some(ICON));
        assert_eq!(
            asked,
            vec![
                "/web/index.html".to_string(),
                "/web/favicon.bc8d51405ec040305a87.ico".to_string(),
            ],
            "the conventional path should not be asked for once a page declares one"
        );
    }

    /// Prometheus declares `./favicon.svg`, and a segment meaning "here" should
    /// not survive into a path this engine records.
    #[test]
    fn a_here_segment_is_dropped_from_a_declared_path() {
        assert_eq!(
            resolve("/query", "./favicon.svg").as_deref(),
            Some("/favicon.svg")
        );
        assert_eq!(
            resolve("/web/index.html", "./f.ico").as_deref(),
            Some("/web/f.ico")
        );
    }

    /// A port some service registered a probe for is answered with that probe
    /// rather than with `GET /`, so the banners hold whatever the probe drew.
    /// Grafana on 3000 answers its registered probe with a `400` and its root
    /// with the page that names it, and reading only the banner found neither.
    #[tokio::test]
    async fn a_banner_that_is_not_the_page_still_leads_to_the_root() {
        use crate::model::port::Protocol;
        use tokio::net::TcpListener;

        const ICON: &[u8] = b"\x89PNG the icon only the root leads to";

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut asked = Vec::new();
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buffer = [0u8; 512];
                let read = stream.read(&mut buffer).await.unwrap();
                let path = String::from_utf8_lossy(&buffer[..read])
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                asked.push(path.clone());

                match path.as_str() {
                    // The root redirects, as Grafana's does.
                    "/" => {
                        stream
                            .write_all(b"HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .unwrap();
                    }
                    "/login" => {
                        let body = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
                             <html><head><link rel=\"icon\" href=\"static/fav32.png\"></head></html>";
                        stream.write_all(body.as_bytes()).await.unwrap();
                    }
                    "/static/fav32.png" => {
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n")
                            .await
                            .unwrap();
                        stream.write_all(ICON).await.unwrap();
                        break;
                    }
                    _ => {
                        stream
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .unwrap();
                    }
                }
            }
            asked
        });

        // What a claimed port's registered probe drew: not the page.
        let responses = ResponseSet::from_banners(vec![
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_string(),
        ]);

        let ctx = PortContext::new(addr.port(), Protocol::Tcp)
            .with_addr(Some(addr))
            .with_speaks_http(true);
        let collected = FaviconAnalyzer.collect(&ctx, &responses).await;
        let asked = server.await.unwrap();

        assert_eq!(collected.frames.first().map(Vec::as_slice), Some(ICON));
        assert_eq!(asked, vec!["/", "/login", "/static/fav32.png"]);
    }

    /// Grafana answers `/favicon.ico` with a redirect to the file it actually
    /// holds, so the fallback has to follow one hop too.
    #[tokio::test]
    async fn a_redirect_on_the_icon_itself_is_followed() {
        use tokio::net::TcpListener;

        const ICON: &[u8] = b"\x00\x00\x01\x00 behind a redirect";

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buffer = [0u8; 512];
                let read = stream.read(&mut buffer).await.unwrap();
                let path = String::from_utf8_lossy(&buffer[..read])
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();

                if path == "/real.ico" {
                    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                    stream.write_all(ICON).await.unwrap();
                } else {
                    stream
                        .write_all(b"HTTP/1.1 302 Found\r\nLocation: /real.ico\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .unwrap();
                }
            }
        });

        let icon = fetch(addr, "/favicon.ico").await;
        server.await.unwrap();
        assert_eq!(icon.as_deref(), Some(ICON));
    }
}
