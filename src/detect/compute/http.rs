// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # HTTP as a compute-module primitive
//!
//! The parse a detection would otherwise hand-roll, in tested Rust behind two
//! helpers the [Rhai backend](super::rhai) exposes: `http_response(blob)` turns a
//! raw reply into a status, a header map, and a decoded body, and
//! `http_request(map)` builds a well-formed request to hand to `speak`. Roughly
//! forty of the planned detections speak HTTP; without this each one re-derives
//! header splitting and chunked decoding in the sandbox language, which is where
//! the fiddly, off-by-one, security-relevant mistakes live.
//!
//! ## What it parses, and what it leaves alone
//!
//! One HTTP/1.1 response message: the status line, the header block, and a body
//! delimited by `Content-Length`, decoded from `Transfer-Encoding: chunked`, or
//! read to the end when neither says. It reads the head as Latin-1, the encoding
//! the rest of the detection tier reads a reply through, so a header carrying a
//! stray non-ASCII byte does not fail the parse. It does not follow a redirect,
//! decompress a `Content-Encoding`, or reassemble across messages: a detection
//! that wants those does them itself over `speak`, and a primitive that quietly
//! did them would hide from the module what actually crossed the wire.
//!
//! ## Bounded by its input
//!
//! Every loop here consumes input as it goes and stops when the input runs out,
//! so the cost is linear in the reply, which the byte budget already bounds. A
//! chunk that claims more than is present yields what is present rather than
//! reading past it.

/// A parsed HTTP response: the status line split out, the headers in the order
/// received with their names lowercased, and the body decoded.
///
/// Header names are lowercased because a detection matches them case-insensitively
/// and HTTP declares them case-insensitive; the values are left exactly as they
/// arrived. Duplicates are kept as separate entries here, the caller folding them
/// into one map value, so nothing is lost before the caller decides how to join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Response {
    /// The HTTP version token, `HTTP/1.1`.
    pub version: String,
    /// The three-digit status code.
    pub status: u16,
    /// The reason phrase, `OK`, which may be empty.
    pub reason: String,
    /// Header `(name, value)` pairs, names lowercased, in received order.
    pub headers: Vec<(String, String)>,
    /// The message body, de-chunked when it arrived chunked.
    pub body: Vec<u8>,
}

#[cfg(test)]
impl Response {
    /// The value of the first header named `name` (already lowercased), if
    /// present. A test convenience: the runtime reads the whole header map the
    /// [Rhai wrapper](super::rhai) folds, not one header at a time.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Parses one HTTP/1.1 response, or [`None`] if the bytes do not begin with a
/// status line naming a version and a code.
pub(crate) fn parse_response(raw: &[u8]) -> Option<Response> {
    let (head, body) = split_head(raw);
    let head = latin1(head);
    let mut lines = head.split("\r\n").flat_map(|line| line.split('\n'));

    let status_line = lines.next()?;
    let (version, status, reason) = parse_status_line(status_line)?;

    let headers: Vec<(String, String)> = lines
        .filter(|line| !line.is_empty())
        .filter_map(parse_header)
        .collect();

    let body = decode_body(&headers, body);
    Some(Response {
        version,
        status,
        reason,
        headers,
        body,
    })
}

/// Assembles a request message from its parts. `method` and `path` are the
/// request line, `host` fills the `Host` header a 1.1 request must carry, and
/// `headers` are added verbatim. A non-empty body sets `Content-Length`, so a
/// caller need not count the bytes itself.
pub(crate) fn build_request(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(&format!("{method} {path} HTTP/1.1\r\n"));
    out.push_str(&format!("Host: {host}\r\n"));
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Splits the header block from the body at the first blank line, `\r\n\r\n` or a
/// bare `\n\n`. With neither present the whole input is the head and the body is
/// empty, which is what a response still arriving looks like.
fn split_head(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(at) = find(raw, b"\r\n\r\n") {
        (&raw[..at], &raw[at + 4..])
    } else if let Some(at) = find(raw, b"\n\n") {
        (&raw[..at], &raw[at + 2..])
    } else {
        (raw, &[])
    }
}

/// `HTTP/1.1 200 OK` into its three parts, or [`None`] if the line does not name
/// a version and a numeric code.
fn parse_status_line(line: &str) -> Option<(String, u16, String)> {
    let mut parts = line.splitn(3, ' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    let status = parts.next()?.parse::<u16>().ok()?;
    let reason = parts.next().unwrap_or("").trim().to_string();
    Some((version.to_string(), status, reason))
}

/// `Name: value` into a lowercased name and its trimmed value. A line with no
/// colon is not a header and is dropped.
fn parse_header(line: &str) -> Option<(String, String)> {
    let (name, value) = line.split_once(':')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some((name.to_ascii_lowercase(), value.trim().to_string()))
}

/// The body a message carries: the `Content-Length` prefix of what follows, the
/// de-chunked stream when `Transfer-Encoding: chunked`, or everything present
/// when neither header says how long it is.
fn decode_body(headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };

    if header("transfer-encoding").is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
    }) {
        return dechunk(body);
    }

    if let Some(length) =
        header("content-length").and_then(|value| value.trim().parse::<usize>().ok())
    {
        return body[..length.min(body.len())].to_vec();
    }

    body.to_vec()
}

/// Decodes a chunked body: a hex length, a `\r\n`, that many bytes, and repeat
/// until a zero-length chunk or the input is spent. A chunk claiming more than is
/// present contributes what is present and ends the decode, so a truncated reply
/// yields a truncated body rather than reading past its end.
fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = find(data, b"\r\n") {
        // The size may carry a `;`-delimited chunk extension this ignores.
        let size_token = latin1(&data[..eol]);
        let size_token = size_token.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_token, 16) else {
            break;
        };
        if size == 0 {
            break;
        }
        let start = eol + 2;
        let end = start + size;
        if end > data.len() {
            out.extend_from_slice(&data[start..]);
            break;
        }
        out.extend_from_slice(&data[start..end]);
        // Step past the chunk and the `\r\n` that closes it.
        data = &data[(end + 2).min(data.len())..];
    }
    out
}

/// The first offset of `needle` in `haystack`, if any.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Bytes as a Latin-1 string, every byte its own code point, the decoding the
/// rest of the detection tier reads a reply through.
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| byte as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_content_length_response_parses_status_headers_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\n\
            Server: nginx/1.25.3\r\n\
            Content-Type: text/html\r\n\
            Content-Length: 5\r\n\r\n\
            helloTRAILING";
        let response = parse_response(raw).expect("a well-formed response parses");

        assert_eq!(response.version, "HTTP/1.1");
        assert_eq!(response.status, 200);
        assert_eq!(response.reason, "OK");
        assert_eq!(response.header("server"), Some("nginx/1.25.3"));
        // The name matched case-insensitively though it arrived capitalised.
        assert_eq!(response.header("content-type"), Some("text/html"));
        // Content-Length bounds the body: the trailing bytes are not part of it.
        assert_eq!(response.body, b"hello");
    }

    #[test]
    fn a_chunked_body_is_reassembled() {
        let raw = b"HTTP/1.1 200 OK\r\n\
            Transfer-Encoding: chunked\r\n\r\n\
            5\r\nhello\r\n7\r\n, world\r\n0\r\n\r\n";
        let response = parse_response(raw).expect("a chunked response parses");
        assert_eq!(response.body, b"hello, world");
    }

    #[test]
    fn a_redirect_status_line_reads_its_code() {
        let raw = b"HTTP/1.1 308 Permanent Redirect\r\nLocation: https://example.com/\r\n\r\n";
        let response = parse_response(raw).expect("a redirect parses");
        assert_eq!(response.status, 308);
        assert_eq!(response.header("location"), Some("https://example.com/"));
        assert!(response.body.is_empty());
    }

    #[test]
    fn a_non_http_reply_does_not_parse() {
        assert!(parse_response(b"SSH-2.0-OpenSSH_9.6p1\r\n").is_none());
        assert!(parse_response(b"").is_none());
        assert!(parse_response(b"+PONG\r\n").is_none());
    }

    #[test]
    fn a_truncated_chunk_yields_what_arrived_rather_than_reading_past_it() {
        // The chunk claims eight bytes but only four are present.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nabcd";
        let response = parse_response(raw).expect("a truncated chunked response still parses");
        assert_eq!(response.body, b"abcd");
    }

    #[test]
    fn a_built_request_is_well_formed_and_counts_its_body() {
        let request = build_request(
            "POST",
            "/login",
            "example.com",
            &[("Content-Type".to_string(), "application/json".to_string())],
            b"{}",
        );
        let text = latin1(&request);
        assert_eq!(
            text,
            "POST /login HTTP/1.1\r\n\
             Host: example.com\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 2\r\n\r\n\
             {}"
        );
    }

    #[test]
    fn a_bodyless_request_sets_no_content_length() {
        let request = build_request("GET", "/", "example.com", &[], b"");
        let text = latin1(&request);
        assert_eq!(text, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    }
}
