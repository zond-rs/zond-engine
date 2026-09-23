// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Every connection to a target opened in one place, as a census
//!
//! `src/system/dial.rs` is where the engine opens the ordinary TCP and UDP
//! sockets it speaks to a scanned host through, and where each is given what
//! has to be set on it before it connects. On Windows that is a limit on the
//! SYN retransmissions of every TCP socket, without which a refused port waits
//! out the connect budget and reads as filtered.
//!
//! The rule is kept by the callers, and a caller that opens its own socket is
//! the one that breaks it without anything noticing: on Linux and macOS its
//! connection behaves exactly as before, and the difference shows up only on a
//! platform nobody ran it on. Opening a socket is a thing a grep can see, so
//! this is a census in the shape of `exclusions.rs`: every other production
//! file that opens a TCP or UDP socket is listed with why it is not a
//! connection to a target, and a new one fails the test until somebody writes
//! that line.
//!
//! What it cannot see is a socket a dependency opens on the engine's behalf.
//! The one such dependency is `hickory-resolver`, which asks the host's own
//! resolvers for names and never a scanned host.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The file every connection to a target is opened in.
const DIALLER: &str = "src/system/dial.rs";

/// The other files that open a TCP or UDP socket, and why theirs is not a
/// connection to a target.
///
/// **Adding a file here is the point of this census.** If new code opens a
/// socket, say on this line why it is not talking to a scanned host, and if it
/// is, open it through `dial` instead.
const OTHER_SOCKETS: &[(&str, &str)] = &[
    (
        "src/resolve/mdns.rs",
        "joins the mDNS multicast group on port 5353 of an interface the caller \
         named, pinning the send and the join to that interface itself. It asks the \
         link who answers to a name, and no scanned host is its peer.",
    ),
    (
        "src/scanner/rdns.rs",
        "asks the host's own resolvers for the names of the addresses a scan found. \
         Its peers are the name servers the system is configured with, never a \
         scanned host.",
    ),
    (
        "src/system/interface/source.rs",
        "connects an unbound UDP socket to a destination only to read back the source \
         the routing table picks for it. A UDP connect sends nothing, so no packet \
         reaches the target at all.",
    ),
];

/// What opening a TCP or UDP socket looks like, through `std`, `tokio` and
/// `socket2` alike. `socket2` names the socket type rather than a constructor
/// of its own, so its type constants stand in for it.
const OPENS: &[&str] = &[
    "TcpStream::connect",
    "TcpSocket::new",
    "UdpSocket::bind",
    "Type::STREAM",
    "Type::DGRAM",
];

/// **Every TCP or UDP socket the engine opens is either opened in `dial` or
/// listed here with why it is not a connection to a target.**
#[test]
fn every_socket_outside_the_dialler_has_said_why_it_is_not_a_connection_to_a_target() {
    let mut found = BTreeSet::new();
    for path in sources() {
        let text = fs::read_to_string(&path).expect("a source file is readable");
        let production = without_comments(&without_tests(&text));
        if OPENS.iter().any(|opens| production.contains(opens)) {
            found.insert(path.to_string_lossy().replace('\\', "/"));
        }
    }

    assert!(
        found.contains(DIALLER),
        "{DIALLER} opens no socket this census recognises, so the census has stopped \
         seeing what it is looking for. Update OPENS in tests/hygiene/dialling.rs."
    );
    found.remove(DIALLER);

    let listed: BTreeSet<String> = OTHER_SOCKETS
        .iter()
        .map(|(path, _)| (*path).to_string())
        .collect();

    let unlisted: Vec<&String> = found.difference(&listed).collect();
    assert!(
        unlisted.is_empty(),
        "these open a TCP or UDP socket outside {DIALLER} and are not in OTHER_SOCKETS: \
         {unlisted:?}\n\n\
         A connection to a scanned host has to be opened through `crate::system::dial`, \
         which is where each socket gets what the platform needs set before it connects: \
         on Windows, the SYN retransmission limit without which a refused port reads as \
         filtered. A socket opened anywhere else behaves the same on Linux and macOS and \
         differently on Windows, where nobody is looking.\n\n\
         Open it through `dial`, or, if it is not a connection to a target, add the file \
         to OTHER_SOCKETS in tests/hygiene/dialling.rs saying why."
    );

    let stale: Vec<&String> = listed.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "these are in OTHER_SOCKETS but no longer open a socket: {stale:?}\n\n\
         Remove them, so the list stays a census rather than a wish."
    );
}

/// Nobody explains themselves in a blank line.
#[test]
fn every_other_socket_says_something() {
    for (path, why) in OTHER_SOCKETS {
        assert!(
            why.len() > 60,
            "{path}'s note is too short to be an answer: {why:?}"
        );
    }
}

/// The census reads code and not what is said about it, so a socket named in a
/// comment is not a socket opened, and one opened in a test is not the engine's.
#[test]
fn the_census_reads_code_and_not_prose_or_tests() {
    let text = "\
        /// Unlike [`TcpStream::connect`], this pins the source.\n\
        fn engine() {} // not UdpSocket::bind either\n\
        #[cfg(test)]\n\
        mod tests { fn t() { TcpStream::connect(addr); } }\n\
        #[cfg(all(test, unix))]\n\
        mod unix { fn t() { UdpSocket::bind(addr); } }\n";
    let production = without_comments(&without_tests(text));
    assert!(
        OPENS.iter().all(|opens| !production.contains(opens)),
        "{production:?}"
    );

    let text = "fn engine() { let s = UdpSocket::bind(addr); }\n";
    assert!(without_comments(&without_tests(text)).contains("UdpSocket::bind"));
}

/// The files whose contents describe how the engine behaves, which is every
/// source that is not compiled only for a test.
fn sources() -> Vec<PathBuf> {
    let test_only = test_only_modules();
    every_source()
        .into_iter()
        .filter(|path| !test_only.contains(path))
        .collect()
}

fn every_source() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .expect("src is readable")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(Path::new("src"), &mut out);
    out
}

/// The files belonging to a module some parent declared `#[cfg(test)]`, which
/// [`without_tests`] cannot see from inside the file.
fn test_only_modules() -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    for path in every_source() {
        let text = fs::read_to_string(&path).expect("a source file is readable");
        let lines: Vec<&str> = text.lines().collect();
        for pair in lines.windows(2) {
            if pair[0].trim() != "#[cfg(test)]" {
                continue;
            }
            let next = pair[1].trim().trim_end_matches(';');
            let Some(name) = next.split_whitespace().last() else {
                continue;
            };
            if !next.contains("mod ") || !next.ends_with(name) || next.contains('{') {
                continue;
            }
            let dir = match path.file_stem().and_then(|s| s.to_str()) {
                Some("lib") | Some("mod") => path.parent().expect("a parent").to_path_buf(),
                Some(stem) => path.parent().expect("a parent").join(stem),
                None => continue,
            };
            out.insert(dir.join(format!("{name}.rs")));
            out.insert(dir.join(name).join("mod.rs"));
        }
    }
    out
}

/// `text` with every `#[cfg(test)]` or `#[cfg(all(test, …))]` item removed, by
/// matching the braces of the item the attribute is on. A test opening a
/// socket to a listener it bound says nothing about how the engine reaches a
/// target.
fn without_tests(text: &str) -> String {
    const GATES: [&str; 2] = ["#[cfg(test)]", "#[cfg(all(test"];

    let mut kept = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(at) = GATES.iter().filter_map(|gate| rest.find(gate)).min() {
        kept.push_str(&rest[..at]);
        // Past the attribute by its own brackets, so `#[cfg(all(test, unix))]`
        // ends where it ends rather than at the first `]`.
        let attribute = balanced(&rest[at..], b'[', b']').unwrap_or(rest.len() - at);
        let item = &rest[at + attribute..];
        // Then the item: a declaration up to its `;`, or a body in braces.
        let ends = match item.find(['{', ';']) {
            Some(i) if item.as_bytes()[i] == b';' => i + 1,
            Some(i) => i + balanced(&item[i..], b'{', b'}').unwrap_or(item.len() - i),
            None => item.len(),
        };
        rest = &item[ends..];
    }
    kept.push_str(rest);
    kept
}

/// How far into `text` the group its first `open` begins is closed.
fn balanced(text: &str, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0usize;
    for (i, byte) in text.bytes().enumerate() {
        if byte == open {
            depth += 1;
        } else if byte == close {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(i + 1);
            }
        }
    }
    None
}

/// `text` with every `//` comment blanked, doc comments included, since a doc
/// link naming a constructor opens nothing.
fn without_comments(text: &str) -> String {
    text.lines()
        .map(|line| match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}
