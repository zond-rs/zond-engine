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

/// The request. `Host` is a fixed `localhost`, as the signature corpus sends it;
/// the scanned host is not seeded as a variable anywhere in this engine yet.
const REQUEST: &[u8] =
    b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nConnection: close\r\n\r\n";

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

    async fn collect(&self, ctx: &PortContext) -> Collected {
        let Some(addr) = ctx.addr else {
            return Collected::default();
        };
        match timeout(FETCH_TIMEOUT, fetch(addr)).await {
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

/// The lowercase hex MD5 of `bytes`, which is the form the corpus is keyed on.
fn md5_hex(bytes: &[u8]) -> String {
    Md5::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Fetches `/favicon.ico` and returns its body, or [`None`] where there is not
/// one to have.
///
/// A body is returned only for a `200`. A `404` is the ordinary answer from a
/// server that serves no icon, and every redirect is declined rather than
/// followed: the corpus is keyed on what *this* endpoint serves, and a redirect
/// to a content delivery network would key the wrong host's bytes to this port.
async fn fetch(addr: std::net::SocketAddr) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await.ok()?;
    stream.write_all(REQUEST).await.ok()?;

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

    body_of(&response).map(<[u8]>::to_vec)
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

    /// The collect phase against a real socket: the analyzer connects, asks for
    /// the icon, and hands back exactly the bytes served.
    #[tokio::test]
    async fn collect_fetches_the_icon_over_a_real_socket() {
        use crate::model::port::Protocol;
        use tokio::net::TcpListener;

        const ICON: &[u8] = b"\x00\x00\x01\x00 not really an icon, but bytes are bytes";

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut request = [0u8; 512];
            let read = stream.read(&mut request).await.unwrap();
            assert!(
                request[..read].starts_with(b"GET /favicon.ico "),
                "the analyzer asked for something else"
            );

            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: image/x-icon\r\n\r\n")
                .await
                .unwrap();
            stream.write_all(ICON).await.unwrap();
        });

        let ctx = PortContext::new(addr.port(), Protocol::Tcp)
            .with_addr(Some(addr))
            .with_speaks_http(true);
        let collected = FaviconAnalyzer.collect(&ctx).await;
        server.await.unwrap();

        assert_eq!(collected.frames.first().map(Vec::as_slice), Some(ICON));
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

    /// A server that answers the second request with an endless stream cannot
    /// hold the scan: the read stops at the cap.
    #[test]
    fn the_body_read_is_bounded() {
        assert!(MAX_ICON_BYTES >= 64 * 1024, "room for a real icon");
        assert!(
            MAX_ICON_BYTES <= 1024 * 1024,
            "and a bound on a hostile one"
        );
    }
}
