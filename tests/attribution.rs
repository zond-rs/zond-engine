// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Who is allowed to read an ICMP error, as a test rather than a comment
//!
//! An ICMP error carries no ports of its own. The only thing tying one to a
//! probe is the datagram it quotes back, and every byte of that quotation was
//! chosen by whoever sent the error. So a caller that reads one owes a check:
//! the quotation has to name something this scan actually sent, and *what* names
//! it differs by protocol and by technique.
//!
//! That obligation was written down nowhere and honoured unevenly. Four separate
//! findings, in four scanners, over two audit iterations:
//!
//! | scanner | what it believed on |
//! |---|---|
//! | SCTP port scan | the ports alone, for an INIT, whose nonce is never inside the guaranteed eight bytes |
//! | every port scan | the quoted source port alone, for a host-unreachable, which files a host down |
//! | TCP port scan | the ports alone, for the three techniques whose nonce needs twelve quoted bytes |
//! | IP protocol scan | membership of the scan's own target list, which is what the scanned host knows about itself |
//!
//! Each was found separately, fixed separately, and reasoned about separately by
//! somebody who had thought about it. The trace got it right from the start and
//! nothing carried that across.
//!
//! **This test is the thing that carries it across.** It is a census, in the
//! shape of [`architecture.rs`](../architecture.rs)'s module `ORDER`: every file
//! that reads an ICMP error has to be in [`ATTRIBUTED`] with a line saying how
//! it ties one to a probe. A new caller fails this test until somebody writes
//! that line, and writing it is the moment the question gets asked.
//!
//! It cannot check that the answer is *correct* — no lexical test can. What it
//! can do is make the answer exist.

use std::fs;
use std::path::{Path, PathBuf};

/// The two readers. A file calling either owes an attribution.
const READERS: &[&str] = &["icmp_error::parse", "parse_expired"];

/// Every file allowed to read an ICMP error, and how each ties one to a probe.
///
/// **Adding a file here is the point of this test.** If a new scanner reads an
/// error, say on this line what makes the quotation its own — a nonce, a drawn
/// port, an identifier — and if the honest answer is "less than the others
/// have", say that, as the protocol scan does.
const ATTRIBUTED: &[(&str, &str)] = &[
    (
        "src/scanner/strategy/ports/tcp.rs",
        "the quoted source port is this scan's, and the nonce is read from the \
         sequence number where the technique put it there. A refusal whose \
         quotation is too short to carry the acknowledgement field retires \
         nothing; a host-unreachable goes through ProbeLedger::names_attempt.",
    ),
    (
        "src/scanner/strategy/ports/udp.rs",
        "the quoted source port is this scan's. A UDP header has no nonce field \
         inside the guaranteed eight bytes, so the probe's identity is the whole \
         of it and a host-unreachable must name a live probe in the ledger.",
    ),
    (
        "src/scanner/strategy/ports/sctp.rs",
        "the Initiate Tag for an INIT, which needs twenty quoted bytes and \
         retires nothing without them; the common-header verification tag for a \
         COOKIE-ECHO, which is inside the guaranteed eight. A host-unreachable \
         goes through ProbeLedger::names_attempt.",
    ),
    (
        "src/scanner/strategy/protocols.rs",
        "the quoted source address is one this pass sent from, plus the drawn \
         source port for TCP, UDP and SCTP and the drawn echo identifier for \
         ICMP. A bare-header protocol carries nothing after the IP header, so \
         there the source address is the whole of it — weaker than the rest, \
         and Correlation::admits says so.",
    ),
    (
        "src/scanner/strategy/topology/traceroute.rs",
        "a marker drawn per run, checked in the quoted source port and again in \
         the sequence number for a SYN trace, and in the echo identifier for an \
         echo trace. Wrong protocol for the probe refuses outright. This one was \
         right first and is the model for the rest.",
    ),
];

/// Rust files under `src/`, in a stable order.
fn sources() -> Vec<PathBuf> {
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

/// `text` with `#[cfg(test)]` items removed, so a fixture calling a reader does
/// not read as a scanner doing it.
///
/// Brace-counted rather than parsed. A test module is the only `#[cfg(test)]`
/// item in this crate that contains one of these calls, and it is always a
/// `mod`, so counting braces from the attribute is enough.
fn without_tests(text: &str) -> String {
    let mut kept = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(at) = rest.find("#[cfg(test)]") {
        kept.push_str(&rest[..at]);
        let after = &rest[at..];
        let Some(open) = after.find('{') else {
            break;
        };
        let mut depth = 0usize;
        let mut end = None;
        for (offset, byte) in after[open..].bytes().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + offset + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        match end {
            Some(end) => rest = &after[end..],
            None => break,
        }
    }
    kept.push_str(rest);
    kept
}

/// Every file whose production code reads an ICMP error.
fn readers() -> Vec<String> {
    let mut found = Vec::new();
    for path in sources() {
        // The module that defines them is not a caller of them.
        if path.ends_with("icmp_error.rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("a source file is readable");
        let production = without_tests(&text);
        if READERS.iter().any(|reader| production.contains(reader)) {
            found.push(path.to_string_lossy().replace('\\', "/"));
        }
    }
    found
}

/// **Every reader of an ICMP error is one somebody wrote an attribution for.**
///
/// The census. Four findings say what happens when a caller reads one without
/// deciding what makes it theirs; this is what makes the next caller decide.
#[test]
fn every_icmp_error_reader_has_written_down_how_it_attributes() {
    let found = readers();
    let listed: Vec<&str> = ATTRIBUTED.iter().map(|(path, _)| *path).collect();

    for path in &found {
        assert!(
            listed.contains(&path.as_str()),
            "{path} reads an ICMP error and is not in ATTRIBUTED.\n\n\
             An ICMP error is attributable only through the datagram it quotes, \
             and every byte of that quotation was chosen by whoever sent it. \
             Add the file to ATTRIBUTED in tests/attribution.rs with a line \
             saying what makes a quotation this scanner's own — a nonce, a drawn \
             port, an identifier. If the honest answer is that it rests on less \
             than the others do, say that."
        );
    }

    for path in &listed {
        assert!(
            found.iter().any(|reader| reader == path),
            "{path} is listed in ATTRIBUTED but no longer reads an ICMP error; \
             remove it, so the list stays a census rather than a wish"
        );
    }
}

/// Nobody explains themselves in a blank line.
#[test]
fn every_attribution_says_something() {
    for (path, how) in ATTRIBUTED {
        assert!(
            how.len() > 60,
            "{path}'s attribution note is too short to be an answer: {how:?}"
        );
    }
}
