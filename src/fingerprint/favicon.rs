// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The icon a web application serves, as an identifier
//!
//! A self-hosted application often names itself nowhere in its HTTP response:
//! no `Server` value of its own, a generic title, a body that is one script tag.
//! Its icon ships with the product, so the same application serves the same
//! bytes everywhere it is installed.
//!
//! The corpus is keyed on the MD5 of those bytes and holds several hundred
//! products.
//!
//! ## MD5
//!
//! The corpus was imported keyed on MD5. The hash is only a lookup key; a
//! collision names the wrong product.
//!
//! ## Cost
//!
//! One `GET` on a connection of its own, only where first contact drew an HTTP
//! response ([`speaks_http`](super::analyzer::PortContext::speaks_http)).

use async_trait::async_trait;
use md5::{Digest, Md5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout};

use std::sync::Arc;
use std::time::Duration;

use super::analyzer::{Analyzer, PortContext};
use super::authority::Authority;
use super::model::{Evidence, SourceId, Tunnel};
use super::response::{Collected, ResponseSet};
use crate::transport::dial::pacing;

/// How long the whole exchange may take, connect included.
///
/// Short, since the server has already answered once. A scan adds the path
/// delay it measured (see [`on_path`](super::on_path)).
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// The least an icon request waits for its response to begin, where the server
/// has answered this search before; see [`icon_patience`].
const ICON_PATIENCE_FLOOR: Duration = Duration::from_secs(1);

/// An icon request waits this multiple of the page's slowest time to first
/// byte; see [`icon_patience`].
const ICON_PACE_MULTIPLE: u32 = 4;

/// The most of a response body to read.
///
/// A favicon is a few kilobytes; the cap allows for larger ones and bounds an
/// endless stream.
const MAX_ICON_BYTES: usize = 256 * 1024;

/// Where an icon lives when a page declares none, by browser convention.
const CONVENTIONAL_PATH: &str = "/favicon.ico";

/// One request, for the site `peer` names; see [`Authority`].
fn request(peer: &Authority, path: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        peer.header()
    )
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
        ctx.speaks_http && ctx.addr.is_some()
    }

    async fn collect(&self, ctx: &PortContext, responses: &ResponseSet) -> Collected {
        let Some(addr) = ctx.addr else {
            return Collected::default();
        };
        let peer = Authority::new(addr).named(ctx.host_name.as_deref().map(Arc::from));
        let peer = match ctx.tunnel {
            Some(Tunnel::Tls) => peer.through_tls(),
            None => peer,
        };
        // One budget for the whole search, however many requests it takes. The
        // scan's pacing gaps are not counted; see `dial::pacing`.
        match pacing::timeout(super::on_path(FETCH_TIMEOUT), || icon_of(&peer, responses)).await {
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

        // Field matcher, not port signatures: a favicon rule is registered under
        // the product's service, not under 80.
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
/// An icon names the *application*; a `Server` value names the listener in front
/// of it (Metabase behind nginx). `Server: nginx/1.24.0` is `Strong` and
/// port-confirmed, so it wins the product slot, and the second statement keeps
/// the application name on reverse-proxied hosts.
///
/// [`ServiceVerdict::resolve`](super::model::ServiceVerdict::resolve) drops the
/// duplicate where the icon does take the product slot.
fn as_application(mut evidence: Evidence) -> Evidence {
    evidence.source = SourceId::Favicon;
    match evidence.product.clone() {
        Some(product) => evidence.with_extrainfo(product),
        None => evidence,
    }
}

/// The digest of the icon `addr` serves, found exactly as a scan finds it.
///
/// For the container tier, which measures real software to write rules
/// against. It uses `icon_of` so the hashes it harvests are ones a scan can
/// match.
///
/// `None` covers a port serving no icon and a port that never answers. The peer
/// is not checked for HTTP; the search is bounded by `FETCH_TIMEOUT`, as in
/// `Favicon::collect`.
///
/// Behind `test-support`.
#[cfg(any(test, feature = "test-support"))]
pub async fn digest_of(addr: std::net::SocketAddr) -> Option<String> {
    let icon = timeout(
        FETCH_TIMEOUT,
        icon_of(&Authority::new(addr), &ResponseSet::default()),
    )
    .await
    .ok()??;
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
/// Anything built with a bundler serves its icon under a content-hashed name
/// (`favicon.bc8d51405ec040305a87.ico`) declared in a `<link>`; Jellyfin answers
/// `/favicon.ico` with a 404. So the page's declaration is followed first, with
/// the conventional path as the fallback.
///
/// The page is usually already in first contact's reply; a root that redirects
/// costs one request.
async fn icon_of(peer: &Authority, responses: &ResponseSet) -> Option<Vec<u8>> {
    let Page { markup, base, pace } = page_of(peer, responses).await;
    let patience = icon_patience(pace);

    let declared = markup
        .as_deref()
        .and_then(declared_icon)
        .and_then(|href| resolve(&base, href));

    // The declared path first, then the convention.
    for path in declared
        .iter()
        .map(String::as_str)
        .chain([CONVENTIONAL_PATH])
    {
        if let Some(icon) = fetch(peer, path, patience).await {
            return Some(icon);
        }
    }
    None
}

/// How long an icon request waits for its response to begin, given `pace`,
/// the slowest the same server began answering this search's requests for its
/// page, or [`None`] where the search asked it nothing.
///
/// A server that answered for its page promptly but has not begun answering
/// for its icon after several times as long is holding the request: a
/// WebSocket endpoint or an embedded API that leaves unknown paths open, as a
/// smart TV's control port does over TLS. An icon is no more work than the
/// page, so [`ICON_PACE_MULTIPLE`] times the page's slowest answer allows for a
/// busy server or an application woken behind a proxy. The pace already
/// includes the path's round trip; the [floor](ICON_PATIENCE_FLOOR), which
/// stops a page served from cache in a millisecond from making the icon a race,
/// gets the path delay added.
///
/// Where the search asked nothing (first contact already had the page) there
/// is no pace, and the request has the search's budget. This bounds only the
/// wait for the first byte.
fn icon_patience(pace: Option<Duration>) -> Option<Duration> {
    pace.map(|pace| {
        super::on_path(ICON_PATIENCE_FLOOR).max(pace.saturating_mul(ICON_PACE_MULTIPLE))
    })
}

/// The page a search reads for a declared icon, and what reading it showed of
/// the server.
struct Page {
    /// The markup served at the root, or at the one redirect it named.
    markup: Option<String>,
    /// The path the markup was served from, which a relative icon resolves
    /// against.
    base: String,
    /// The slowest the server began answering the requests this search sent
    /// for the page, or [`None`] where it sent none; see [`icon_patience`].
    pace: Option<Duration>,
}

/// The markup this endpoint serves at its root, the path it was served from,
/// and how promptly the server answered for it.
///
/// A declared icon is usually relative to the path: Jellyfin redirects `/` to
/// `/web/index.html` and declares `favicon.<hash>.ico`, which resolves under
/// `/web/`.
///
/// Reuses what first contact read and follows at most one same-host redirect.
async fn page_of(peer: &Authority, responses: &ResponseSet) -> Page {
    let root = "/".to_string();

    // `None` where nothing was read, as when the container tier drives this.
    let first = responses
        .banners
        .iter()
        .find(|banner| banner.starts_with("HTTP/"));

    // A reply that already declares an icon is the page, whatever drew it.
    if let Some(page) = first.filter(|page| declared_icon(page).is_some()) {
        return Page {
            markup: Some(page.clone()),
            base: root,
            pace: None,
        };
    }

    // Otherwise ask for the root. On a port with a registered probe the banners
    // hold what that probe drew, not the markup (Grafana on 3000 answers its
    // probe with a `400`). A redirect in the banner is followed first.
    let path = first
        .and_then(|page| super::redirect_path(page, Some(peer)))
        .unwrap_or_else(|| root.clone());
    let Some(answer) = exchange(peer, &path, None).await else {
        return Page {
            markup: first.cloned(),
            base: root,
            pace: None,
        };
    };
    let page = answer.text();

    // The root may redirect on this request too. One hop.
    let followed = match super::redirect_path(&page, Some(peer)) {
        Some(next) => exchange(peer, &next, None)
            .await
            .map(|followed| (followed, next)),
        None => None,
    };
    match followed {
        Some((followed, next)) => Page {
            markup: Some(followed.text()),
            base: next,
            pace: Some(answer.began_after.max(followed.began_after)),
        },
        None => Page {
            markup: Some(page),
            base: path,
            pace: Some(answer.began_after),
        },
    }
}

/// The icon a page declares, as the `href` of a `<link>` whose `rel` names one.
///
/// Reads `rel` and `href` in either order and matches `rel` by word, since it is
/// a list (`icon`, `shortcut icon`, `apple-touch-icon`). Case-insensitive.
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
        // From the original markup: paths are case-sensitive.
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
/// An absolute path is taken as written; a relative one is joined to the page's
/// directory. Anything naming a scheme or another host is declined, since
/// another host's icon says nothing about this port.
fn resolve(base: &str, href: &str) -> Option<String> {
    let href = href.trim();
    if href.is_empty() || href.starts_with("//") {
        return None;
    }

    // Decline any scheme, including `data:` (Portainer declares an inline icon).
    // A scheme is what precedes the first `:` before any `/`.
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

    // Prometheus declares `./favicon.svg`.
    let href = href.strip_prefix("./").unwrap_or(href);
    Some(format!("{directory}{href}"))
}

/// Fetches `path` and returns its body, or [`None`] where there is not one.
///
/// A body is returned only for a `200`.
///
/// One same-host redirect is followed: Grafana answers `/favicon.ico` with a
/// `302` to the file it holds.
///
/// Each request waits no longer than `patience` for its response to begin,
/// where the search has one; see [`icon_patience`].
async fn fetch(peer: &Authority, path: &str, patience: Option<Duration>) -> Option<Vec<u8>> {
    let response = exchange(peer, path, patience).await?.bytes;

    if let Some(body) = body_of(&response) {
        return Some(body.to_vec());
    }

    let head = String::from_utf8_lossy(&response);
    let next = super::redirect_path(&head, Some(peer))?;
    let followed = exchange(peer, &next, patience).await?.bytes;
    body_of(&followed).map(<[u8]>::to_vec)
}

/// A response, and how long the server took to begin it.
struct Answer {
    /// The response, whole and bounded; see [`exchange`].
    bytes: Vec<u8>,
    /// From the request written to the response's first byte, or to the close
    /// where the server sent none.
    began_after: Duration,
}

impl Answer {
    /// The response as text, for a page rather than an icon.
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

/// One request and the response it draws, whole and bounded.
///
/// Read to the end the response declares (`Content-Length` or the closing
/// chunk), or to the close if it declares neither, since many servers ignore
/// `Connection: close` and hold the socket.
///
/// Over TLS where the port answered through TLS.
///
/// A response that has not begun `patience` after the request was written
/// counts as none; with [`None`] the caller's budget bounds the wait.
async fn exchange(peer: &Authority, path: &str, patience: Option<Duration>) -> Option<Answer> {
    let stream = super::analyzer_connect(peer.socket()).await.ok()?;
    match peer.is_tls() {
        true => {
            let (mut tunnel, _) = super::tls::handshake(stream, peer.server_name()).await?;
            converse(&mut tunnel, peer, path, patience).await
        }
        false => {
            let mut stream = stream;
            converse(&mut stream, peer, path, patience).await
        }
    }
}

/// Writes the request for `path` to `stream` and reads the response, whole
/// and bounded, waiting no longer than `patience` for it to begin; see
/// [`exchange`].
async fn converse<S>(
    stream: &mut S,
    peer: &Authority,
    path: &str,
    patience: Option<Duration>,
) -> Option<Answer>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&request(peer, path)).await.ok()?;
    let asked = Instant::now();

    let mut response = Vec::new();
    let mut began_after = None;
    let mut buffer = [0u8; 8192];
    loop {
        let read = match (began_after, patience) {
            (None, Some(patience)) => timeout(patience, stream.read(&mut buffer)).await.ok()?,
            _ => stream.read(&mut buffer).await,
        }
        .ok()?;
        began_after.get_or_insert_with(|| asked.elapsed());
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..read]);
        if let Some(end) = crate::protocols::http::message_end(&response) {
            response.truncate(end);
            break;
        }
        if response.len() >= MAX_ICON_BYTES {
            response.truncate(MAX_ICON_BYTES);
            break;
        }
    }
    Some(Answer {
        bytes: response,
        began_after: began_after.unwrap_or_else(|| asked.elapsed()),
    })
}

/// The body of a `200` response, or [`None`] for anything else.
///
/// Split on the header terminator, as bytes, so the icon is hashed exactly.
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
/// Reads the second field; embedded stacks use their own reason phrases.
fn is_success(status: &[u8]) -> bool {
    status
        .split(|byte| *byte == b' ')
        .nth(1)
        .is_some_and(|code| code == b"200")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::loopback::accept_from_this_process;

    /// The well-known MD5 of the empty string.
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

    /// A redirect to another host is not followed.
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

    /// A port that never spoke HTTP, or has no address, is not dialled.
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

    /// A page that declares no icon falls back to the conventional path.
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
                let Ok(mut stream) = accept_from_this_process(&listener).await else {
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

    /// A digest the corpus knows names its product: Metabase.
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

    /// An endless stream is read up to the cap and what was collected is
    /// hashed.
    #[tokio::test]
    async fn an_endless_response_is_cut_off_at_the_cap() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut stream = accept_from_this_process(&listener).await.unwrap();
            let mut buffer = [0u8; 512];
            let _ = stream.read(&mut buffer).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: image/x-icon\r\n\r\n")
                .await
                .unwrap();
            // More than the cap, in chunks.
            let chunk = vec![0xab; 32 * 1024];
            for _ in 0..64 {
                if stream.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });

        let icon = fetch(&Authority::new(addr), "/favicon.ico", None)
            .await
            .expect("a bounded body");
        server.abort();

        assert!(
            icon.len() <= MAX_ICON_BYTES,
            "read {} bytes, past the {MAX_ICON_BYTES} cap",
            icon.len()
        );
        assert!(!icon.is_empty(), "what was read is still worth hashing");
    }

    /// Jellyfin's real markup: the icon is under a content hash and named only in
    /// a `<link>`.
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

    /// The path keeps its original case.
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

    /// An icon on another host is declined.
    #[test]
    fn an_icon_on_another_host_is_declined() {
        assert_eq!(resolve("/", "https://cdn.example/f.ico"), None);
        assert_eq!(resolve("/", "//cdn.example/f.ico"), None);
        assert_eq!(resolve("/", ""), None);
    }

    /// Portainer declares its icon inline; any scheme is declined.
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

    /// A server shaped like Jellyfin: the root redirects, the page declares a
    /// hashed icon under `/web/`, and the conventional path 404s.
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
                let Ok(mut stream) = accept_from_this_process(&listener).await else {
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
                        // The search stops here; don't accept again.
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

    /// Prometheus declares `./favicon.svg`; the `./` is dropped.
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

    /// On a port with a registered probe the banners hold what the probe drew.
    /// Grafana on 3000 answers its probe with a `400` and its root with the page.
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
                let Ok(mut stream) = accept_from_this_process(&listener).await else {
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

    /// Grafana answers `/favicon.ico` with a redirect, so the fallback follows
    /// one hop.
    #[tokio::test]
    async fn a_redirect_on_the_icon_itself_is_followed() {
        use tokio::net::TcpListener;

        const ICON: &[u8] = b"\x00\x00\x01\x00 behind a redirect";

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let Ok(mut stream) = accept_from_this_process(&listener).await else {
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

        let icon = fetch(&Authority::new(addr), "/favicon.ico", None).await;
        server.await.unwrap();
        assert_eq!(icon.as_deref(), Some(ICON));
    }

    /// A response that says how long it is ends there, whatever the server then
    /// does with the connection.
    ///
    /// The server here answers in full and then holds every connection past
    /// [`FETCH_TIMEOUT`], so the icon arrives only if each reply is read to its
    /// declared length.
    #[tokio::test]
    async fn an_icon_is_read_to_its_declared_length_on_a_connection_held_open() {
        const ICON: &[u8] = b"\x00\x00\x01\x00held-open-icon";
        const HOLD: Duration = Duration::from_secs(30);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            while let Ok(mut stream) = accept_from_this_process(&listener).await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 512];
                    let Ok(read) = stream.read(&mut buffer).await else {
                        return;
                    };
                    let asked = String::from_utf8_lossy(&buffer[..read]).into_owned();
                    let reply = match asked.split_whitespace().nth(1) {
                        Some("/favicon.ico") => [
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", ICON.len())
                                .into_bytes(),
                            ICON.to_vec(),
                        ]
                        .concat(),
                        _ => {
                            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n<p>no icon</p>".to_vec()
                        }
                    };
                    let _ = stream.write_all(&reply).await;
                    tokio::time::sleep(HOLD).await;
                });
            }
        });

        let ctx = PortContext::new(8080, crate::model::port::Protocol::Tcp)
            .with_addr(Some(addr))
            .with_speaks_http(true);
        let responses = ResponseSet::from_banners(vec!["HTTP/1.1 200 OK\r\n\r\n".to_string()]);
        let collected = FaviconAnalyzer.collect(&ctx, &responses).await;
        server.abort();

        assert_eq!(
            collected.frames.first().map(Vec::as_slice),
            Some(ICON),
            "the icon was not read before the fetch budget ran out"
        );
    }

    /// **A server that answered for its page and holds its icon request
    /// unanswered is given up on at a multiple of how fast it answered, not
    /// at the end of the search's budget.**
    ///
    /// The server here answers the root at once and never answers the icon, so
    /// the search ends before [`FETCH_TIMEOUT`] only if it gives up at the
    /// patience the root's pace earned.
    #[tokio::test]
    async fn an_icon_request_held_unanswered_is_given_up_on_at_the_pages_pace() {
        const HOLD: Duration = Duration::from_secs(30);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (asked_tx, mut asked_rx) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            while let Ok(mut stream) = accept_from_this_process(&listener).await {
                let asked_tx = asked_tx.clone();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 512];
                    let Ok(read) = stream.read(&mut buffer).await else {
                        return;
                    };
                    let asked = String::from_utf8_lossy(&buffer[..read])
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    let _ = asked_tx.send(asked.clone());
                    if asked == "/" {
                        let page = b"<html><head></head></html>";
                        let head =
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", page.len());
                        let _ = stream.write_all(&[head.as_bytes(), page].concat()).await;
                    }
                    tokio::time::sleep(HOLD).await;
                });
            }
        });

        let ctx = PortContext::new(3001, crate::model::port::Protocol::Tcp)
            .with_addr(Some(addr))
            .with_speaks_http(true);
        let started = Instant::now();
        let collected = FaviconAnalyzer.collect(&ctx, &ResponseSet::default()).await;
        let took = started.elapsed();
        server.abort();

        let mut asked = Vec::new();
        while let Ok(path) = asked_rx.try_recv() {
            asked.push(path);
        }
        assert_eq!(asked, ["/", CONVENTIONAL_PATH], "both requests were sent");
        assert!(collected.frames.is_empty());
        assert!(
            took < FETCH_TIMEOUT,
            "the held icon request was waited out for {took:?}, the whole budget"
        );
    }

    /// The patience scales with the pace, has a floor, and is absent where
    /// nothing was measured.
    #[test]
    fn an_icons_patience_follows_the_pages_pace_above_a_floor() {
        assert_eq!(icon_patience(None), None);
        assert_eq!(
            icon_patience(Some(Duration::from_millis(2))),
            Some(ICON_PATIENCE_FLOOR)
        );
        assert_eq!(
            icon_patience(Some(Duration::from_millis(900))),
            Some(Duration::from_millis(900) * ICON_PACE_MULTIPLE)
        );
    }
}
