// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Where an HTTP response ends
//!
//! Two readers ask the same servers for pages: a detection's exchange and the
//! fingerprint engine's favicon fetch. Both have to stop reading where a
//! response says it ends, since plenty of servers hold a connection open after
//! answering, whatever the request's `Connection: close` asked for, and a
//! reader waiting for the close waits out the server's idle timeout instead.
//! One parser for both, so they cannot come to disagree about when a reply is
//! whole.

/// Where the HTTP/1.x response at the start of `reply` ends, once all of it has
/// arrived: [`None`] while it is still arriving, and for anything that does not
/// say where it ends.
///
/// A response ends where its own framing says (RFC 9112 §6.3): after the header
/// block for a status that carries no body, after the closing chunk and its
/// trailers for a chunked body, which takes precedence over any length, and
/// after `Content-Length` bytes otherwise. A response that says none of these
/// is delimited by the connection closing, and so is anything that is not an
/// HTTP response at all; both are left to the caller's read-to-close.
///
/// An interim `1xx` response is not the answer, so it ends nothing here. A
/// `Content-Length` that does not parse, or two that disagree, is a message
/// whose length is not known, and is read to close like one that gave none.
///
/// Bounded by its input: every loop consumes `reply` and stops at its end.
pub(crate) fn message_end(reply: &[u8]) -> Option<usize> {
    if !reply.starts_with(b"HTTP/1.") {
        return None;
    }
    let body = find(reply, b"\r\n\r\n")? + 4;
    let head = &reply[..body - 4];

    let status: u16 = std::str::from_utf8(head.get(9..12)?).ok()?.parse().ok()?;
    if status < 200 {
        return None;
    }
    if status == 204 || status == 304 {
        return Some(body);
    }

    let mut length: Option<usize> = None;
    let mut chunked = false;
    for line in head.split(|&byte| byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let (name, value) = (&line[..colon], line[colon + 1..].trim_ascii());
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            // Chunked is the final coding when it is named at all: a sender may
            // not apply another after it.
            chunked = value
                .rsplit(|&byte| byte == b',')
                .next()
                .is_some_and(|last| last.trim_ascii().eq_ignore_ascii_case(b"chunked"));
        } else if name.eq_ignore_ascii_case(b"content-length") {
            let declared: usize = std::str::from_utf8(value).ok()?.parse().ok()?;
            if length.is_some_and(|earlier| earlier != declared) {
                return None;
            }
            length = Some(declared);
        }
    }

    if chunked {
        return chunked_end(&reply[body..]).map(|end| body + end);
    }
    let end = body.checked_add(length?)?;
    (reply.len() >= end).then_some(end)
}

/// Where a chunked body at the start of `body` ends, past its closing
/// zero-length chunk and whatever trailer fields follow it, or [`None`] until
/// that much has arrived.
fn chunked_end(body: &[u8]) -> Option<usize> {
    let mut at = 0;
    loop {
        let line_end = at + find(&body[at..], b"\r\n")?;
        let size_field = &body[at..line_end];
        // A chunk extension follows the size after a `;` and changes nothing
        // about where the chunk ends.
        let digits = size_field.split(|&byte| byte == b';').next()?.trim_ascii();
        let size = usize::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()?;
        at = line_end + 2;
        if size == 0 {
            // The trailer section: fields, if any, then an empty line.
            if body[at..].starts_with(b"\r\n") {
                return Some(at + 2);
            }
            return find(&body[at..], b"\r\n\r\n").map(|end| at + end + 4);
        }
        at = at.checked_add(size)?.checked_add(2)?;
        if at > body.len() {
            return None;
        }
    }
}

/// The offset of the first `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
