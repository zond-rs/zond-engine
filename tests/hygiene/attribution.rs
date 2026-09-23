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
//! shape of [`architecture.rs`](architecture.rs)'s module `ORDER`: every file
//! that names the ICMP error reader has to be in [`ATTRIBUTED`] with a line
//! saying how it ties an error to a probe. A new caller fails this test until
//! somebody writes that line, and writing it is the moment the question gets
//! asked.
//!
//! It cannot check that the answer is *correct* — no lexical test can. What it
//! can do is make the answer exist.
//!
//! ## The ICMP nobody reads through the reader
//!
//! Reading an error without attributing it is one way to get ICMP wrong. The
//! other is never reading it as ICMP at all. A capture that admits ICMP hands
//! it to whatever the strategy parses, and a Layer-4 header does not say what
//! it is: the SCTP discovery sweep read ICMP errors as SCTP chunks, and the
//! census above could not see it, because it called no reader to be counted
//! by. So there is a second list, [`LISTENING`], of every file that opens a
//! capture admitting ICMP, each with a line saying where the protocol is
//! checked before a byte is parsed. The echo trace taking its own requests for
//! answers was the same question, asked of the ICMP type rather than the
//! protocol.
//!
//! ## How a file is found
//!
//! By the names in its code, once comments and string and character literals
//! are blanked and `#[cfg(test)]` items taken out, so a doc comment or a
//! fixture naming something is not taken for the engine doing it.
//!
//! - **A reader** names the `icmp_error` module. Every route to its readers
//!   passes through that name, however a file imports them: qualified, braced,
//!   aliased, or by glob. A file naming it only for a type is counted too,
//!   since the types exist to carry what a reader returned, and a file holding
//!   one is handling an error somebody read.
//! - **A listener** names a [`ProbeKind`](../../src/transport/probe.rs) variant
//!   whose filter admits ICMP, in an expression or an import, through the
//!   enum's own name or an alias of it. [`ADMITS_ICMP`] and [`CLOSED_TO_ICMP`]
//!   say which variants those are, and a variant in neither fails
//!   `every_probe_kind_is_placed_by_whether_its_capture_admits_icmp`.
//!
//! ## What it cannot see
//!
//! - **A re-export.** A module handing a reader on under a name of its own is
//!   found where it re-exports, and its callers are not found at all.
//! - **A transport opened elsewhere.** A listener is found where the kind is
//!   named. A strategy that only ever receives a transport its caller opened,
//!   and a module like `exchange` that hands captured segments on unread, are
//!   seen at whichever file chose the kind, if that is in this crate.
//! - **Frames.** `local`, `passive` and `frames` read whole frames rather than
//!   a probe transport and parse their own ICMPv6, which is neighbour discovery
//!   and echo rather than errors about probes. Nothing here looks at them.
//! - **A computed `icmp_errors`.** A `TcpProbe` admits ICMP when its field
//!   says so, and only the literal `false` is read as a capture closed to it.
//!   One that computes `false` is counted as listening, which errs towards
//!   asking.

use std::fs;
use std::path::{Path, PathBuf};

/// The module the two readers live in, `parse` and `parse_expired`.
const READER_MODULE: &str = "icmp_error";

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

/// Every file whose capture admits ICMP, and where each checks a reply's
/// protocol, or its ICMP type, before reading a field of it.
///
/// **Adding a file here is the point of the second census.** If a new strategy
/// opens a transport that admits ICMP, say on this line what keeps an ICMP
/// message away from the parser for its own protocol, and what happens to the
/// ICMP it does not read.
const LISTENING: &[(&str, &str)] = &[
    (
        "src/scanner/strategy/identify/echo.rs",
        "handle_reply refuses anything but ICMP and ICMPv6 by protocol, and \
         classify_echo_reply checks the type and the identifier before a sequence \
         is read. A message that is not an echo reply goes to the timestamp \
         reader over IPv4, which checks its own type, and off-target otherwise.",
    ),
    (
        "src/scanner/strategy/ports/sctp.rs",
        "handle_reply dispatches on the protocol: SCTP to the chunk reader, and \
         everything else to icmp_error::parse, which reads nothing but ICMP.",
    ),
    (
        "src/scanner/strategy/ports/tcp.rs",
        "handle_reply dispatches on the protocol: TCP to the segment reader, and \
         everything else to icmp_error::parse. Only the techniques that read \
         ICMP errors open a capture admitting them at all.",
    ),
    (
        "src/scanner/strategy/ports/udp.rs",
        "the reply's protocol is matched first: UDP to answering_probe, which \
         also checks the port it came back to, and everything else to \
         icmp_error::parse.",
    ),
    (
        "src/scanner/strategy/protocols.rs",
        "the capture admits ICMP and nothing else. matched reads an error through \
         icmp_error::parse, and an echo reply only under ICMP or ICMPv6, through \
         classify_echo_reply, which checks the type.",
    ),
    (
        "src/scanner/strategy/routed.rs",
        "SweepProbe::answers compares the reply's protocol with the one the probe \
         is answered in before a byte is parsed. The INIT sweep's capture admits \
         ICMP for the SCTP port scan that shares its kind; the sweep reads none \
         of it and counts it off-target.",
    ),
    (
        "src/scanner/strategy/topology/traceroute.rs",
        "a Time Exceeded through icmp_error::parse_expired; a direct answer \
         through answered_distance, which checks the protocol, and for an echo \
         trace the type through classify_echo_reply, before the marker is read.",
    ),
];

/// The variants of `ProbeKind` whose capture filter admits ICMP whatever else
/// they are set to, as `ProbeKind::filter` writes them.
const ADMITS_ICMP: &[&str] = &["IcmpEcho", "IpProtocol", "Sctp", "UdpProbe"];

/// The variants whose capture filter admits no ICMP.
const CLOSED_TO_ICMP: &[&str] = &["TcpSyn", "UdpResolve"];

/// The one variant whose filter admits ICMP only when a field says so, and
/// that field.
const ADMITS_ICMP_WHEN_ASKED: (&str, &str) = ("TcpProbe", "icmp_errors");

/// The module that defines `ProbeKind`, which names every variant without
/// listening under any of them.
const KIND_MODULE: &str = "src/transport/probe.rs";

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

/// A path as the lists above write it, whichever platform read it.
fn display(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `text` with every comment and every string and character literal blanked,
/// so what is left is code a name can be looked for in.
///
/// Blanked rather than removed: each character becomes a space and a newline
/// stays one, so nothing that was apart runs together. A doc comment naming a
/// reader is not a reader and a string mentioning one is not either, and a
/// brace inside `'{'` or `"{}"` is no longer there for [`without_tests`] to
/// miscount.
fn code_of(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let blank = |out: &mut String, from: &[char]| {
        out.extend(from.iter().map(|&c| if c == '\n' { '\n' } else { ' ' }));
    };

    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        let starts_word = i == 0 || !is_ident(chars[i - 1]);

        let end = if c == '/' && next == Some('/') {
            // A line comment, doc comments included.
            chars[i..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(chars.len(), |at| i + at)
        } else if c == '/' && next == Some('*') {
            // A block comment, which nests.
            let mut depth = 0usize;
            let mut j = i;
            while j < chars.len() {
                match (chars[j], chars.get(j + 1)) {
                    ('/', Some('*')) => {
                        depth += 1;
                        j += 2;
                    }
                    ('*', Some('/')) => {
                        depth -= 1;
                        j += 2;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => j += 1,
                }
            }
            j
        } else if starts_word && (c == 'r' || (c == 'b' && next == Some('r'))) {
            // A raw string, if a quote follows the hashes. A raw identifier
            // like `r#type` has none and is left alone.
            let mut j = i + if c == 'b' { 2 } else { 1 };
            let hashes = chars[j..].iter().take_while(|&&c| c == '#').count();
            j += hashes;
            if chars.get(j) != Some(&'"') {
                out.push(c);
                i += 1;
                continue;
            }
            let closing: Vec<char> = std::iter::once('"')
                .chain(std::iter::repeat_n('#', hashes))
                .collect();
            (j + 1..=chars.len() - closing.len().min(chars.len()))
                .find(|&k| chars[k..].starts_with(&closing))
                .map_or(chars.len(), |k| k + closing.len())
        } else if c == '"' {
            // A string, stepping over each escape whole.
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '"' {
                j += if chars[j] == '\\' { 2 } else { 1 };
            }
            (j + 1).min(chars.len())
        } else if c == '\'' && next == Some('\\') {
            // An escaped character literal, whatever it escapes.
            chars
                .get(i + 3..)
                .and_then(|rest| rest.iter().position(|&c| c == '\''))
                .map_or(chars.len(), |at| i + 3 + at + 1)
        } else if c == '\'' && chars.get(i + 2) == Some(&'\'') {
            // A character literal. A lifetime has no closing quote two along.
            i + 3
        } else {
            out.push(c);
            i += 1;
            continue;
        };

        blank(&mut out, &chars[i..end.min(chars.len())]);
        i = end.max(i + 1);
    }
    out
}

/// `code` with `#[cfg(test)]` and `#[cfg(all(test, …))]` items removed, so a
/// fixture calling a reader does not read as a scanner doing it.
///
/// Brace-counted rather than parsed, which is sound once [`code_of`] has
/// blanked every brace a literal or a comment held. An item ending in `;`, a
/// test-only `mod` or `use`, ends there. One whose braces never close is kept
/// whole: counted as production it can only add a finding, where dropped it
/// would take every line after it out of sight.
fn without_tests(code: &str) -> String {
    const GATES: [&str; 2] = ["#[cfg(test)]", "#[cfg(all(test"];

    let mut kept = String::with_capacity(code.len());
    let mut rest = code;
    while let Some(at) = GATES.iter().filter_map(|gate| rest.find(gate)).min() {
        kept.push_str(&rest[..at]);
        let item = &rest[at..];
        let end = match item.find(['{', ';']) {
            Some(open) if item.as_bytes()[open] == b';' => Some(open + 1),
            Some(open) => {
                let mut depth = 0usize;
                item[open..].char_indices().find_map(|(offset, c)| {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                return Some(open + offset + 1);
                            }
                        }
                        _ => {}
                    }
                    None
                })
            }
            None => None,
        };
        let Some(end) = end else {
            rest = item;
            break;
        };
        rest = &item[end..];
    }
    kept.push_str(rest);
    kept
}

/// The names and punctuation of `code`, in order: an identifier is one token
/// and every other character that is not whitespace is one of its own.
fn tokens(code: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut chars = code.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        let mut end = start + c.len_utf8();
        if is_ident(c) {
            while let Some(&(at, next)) = chars.peek() {
                if !is_ident(next) {
                    break;
                }
                end = at + next.len_utf8();
                chars.next();
            }
        }
        out.push(&code[start..end]);
    }
    out
}

/// The tokens of the production code in `source`.
fn production(source: &str) -> Vec<String> {
    tokens(&without_tests(&code_of(source)))
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// [`production`], of the file at `path`.
fn production_tokens(path: &Path) -> Vec<String> {
    production(&fs::read_to_string(path).expect("a source file is readable"))
}

/// Whether `tokens` name the reader module anywhere but its own declaration.
fn names_the_reader(tokens: &[String]) -> bool {
    tokens
        .iter()
        .enumerate()
        .any(|(at, token)| token == READER_MODULE && (at == 0 || tokens[at - 1] != "mod"))
}

/// Where the group opened at `tokens[open]` closes, by `open_with` and
/// `close_with`.
fn closing(tokens: &[String], open: usize, open_with: &str, close_with: &str) -> usize {
    let mut depth = 0usize;
    for (at, token) in tokens.iter().enumerate().skip(open) {
        if token == open_with {
            depth += 1;
        } else if token == close_with {
            depth -= 1;
            if depth == 0 {
                return at;
            }
        }
    }
    tokens.len()
}

/// Whether `tokens` open a transport whose capture admits ICMP.
///
/// Every `ProbeKind::…` path is read, under the enum's name or any alias a
/// `use … as` gave it. A path ending in a variant counts by [`ADMITS_ICMP`],
/// and a `TcpProbe` unless its literal sets `icmp_errors: false`; an import of
/// the variants, braced or by glob, counts if it could bring one of those in.
fn listens_for_icmp(tokens: &[String]) -> bool {
    let (switched, field) = ADMITS_ICMP_WHEN_ASKED;
    let admits = |name: &str| ADMITS_ICMP.contains(&name) || name == switched;

    let mut names = vec!["ProbeKind".to_string()];
    for at in 0..tokens.len().saturating_sub(2) {
        if tokens[at] == "ProbeKind" && tokens[at + 1] == "as" {
            names.push(tokens[at + 2].clone());
        }
    }

    (0..tokens.len().saturating_sub(3)).any(|at| {
        if !names.contains(&tokens[at]) || tokens[at + 1] != ":" || tokens[at + 2] != ":" {
            return false;
        }
        let after = at + 3;
        match tokens[after].as_str() {
            "*" => true,
            "{" => {
                let end = closing(tokens, after, "{", "}");
                tokens[after..end].iter().any(|name| admits(name))
            }
            variant if variant == switched => {
                if tokens.get(after + 1).map(String::as_str) != Some("{") {
                    return true;
                }
                let end = closing(tokens, after + 1, "{", "}");
                !tokens[after + 1..end]
                    .windows(3)
                    .any(|run| run[0] == field && run[1] == ":" && run[2] == "false")
            }
            variant => ADMITS_ICMP.contains(&variant),
        }
    })
}

/// Every file whose production code names the ICMP error reader.
fn readers() -> Vec<String> {
    sources()
        .into_iter()
        // The module that defines the readers is not a caller of them.
        .filter(|path| !path.ends_with("icmp_error.rs"))
        .filter(|path| names_the_reader(&production_tokens(path)))
        .map(|path| display(&path))
        .collect()
}

/// Every file whose production code opens a capture admitting ICMP.
fn listeners() -> Vec<String> {
    sources()
        .into_iter()
        .filter(|path| display(path) != KIND_MODULE)
        .filter(|path| listens_for_icmp(&production_tokens(path)))
        .map(|path| display(&path))
        .collect()
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
            "{path} names the ICMP error reader and is not in ATTRIBUTED.\n\n\
             An ICMP error is attributable only through the datagram it quotes, \
             and every byte of that quotation was chosen by whoever sent it. \
             Add the file to ATTRIBUTED in tests/hygiene/attribution.rs with a line \
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

/// **Every strategy whose capture admits ICMP has said what keeps it from being
/// read as something else.**
///
/// The census the first one could not be. A strategy that never calls the
/// reader is invisible to it, and that is exactly the strategy that hands ICMP
/// bytes to a parser for another protocol.
#[test]
fn every_icmp_listener_has_written_down_where_it_checks_the_protocol() {
    let found = listeners();
    let listed: Vec<&str> = LISTENING.iter().map(|(path, _)| *path).collect();

    for path in &found {
        assert!(
            listed.contains(&path.as_str()),
            "{path} opens a capture that admits ICMP and is not in LISTENING.\n\n\
             A Layer-4 header does not say what protocol it is, so an ICMP message \
             handed to a TCP, UDP or SCTP parser is read as whatever its bytes \
             happen to spell. Add the file to LISTENING in \
             tests/hygiene/attribution.rs with a line saying where a reply's \
             protocol is checked before its bytes are parsed, and what becomes of \
             the ICMP it does not read."
        );
    }

    for path in &listed {
        assert!(
            found.iter().any(|listener| listener == path),
            "{path} is listed in LISTENING but no longer opens a capture admitting \
             ICMP; remove it, so the list stays a census rather than a wish"
        );
    }
}

/// **Every kind of probe transport is placed by whether its capture admits
/// ICMP.**
///
/// The listener census finds a strategy by the kind it opens, so a kind it has
/// not been told about is a kind whose listeners it cannot see. Read off the
/// enum itself, so a new variant fails here until somebody looks at its filter
/// and decides.
#[test]
fn every_probe_kind_is_placed_by_whether_its_capture_admits_icmp() {
    let tokens = production_tokens(Path::new(KIND_MODULE));
    let declared = tokens
        .windows(3)
        .position(|run| run[0] == "enum" && run[1] == "ProbeKind" && run[2] == "{")
        .expect("probe.rs declares ProbeKind")
        + 2;
    let body = &tokens[declared..closing(&tokens, declared, "{", "}")];

    // A variant is a name at the enum's own depth; its fields sit one deeper.
    let mut depth = 0usize;
    let mut variants = Vec::new();
    for token in body {
        match token.as_str() {
            "{" | "(" | "[" => depth += 1,
            "}" | ")" | "]" => depth -= 1,
            name if depth == 1 && name.starts_with(char::is_uppercase) => {
                variants.push(name.to_string());
            }
            _ => {}
        }
    }
    assert!(
        !variants.is_empty(),
        "no variants were read out of ProbeKind"
    );

    let placed: Vec<&str> = ADMITS_ICMP
        .iter()
        .chain(CLOSED_TO_ICMP)
        .copied()
        .chain([ADMITS_ICMP_WHEN_ASKED.0])
        .collect();

    for variant in &variants {
        assert!(
            placed.contains(&variant.as_str()),
            "ProbeKind::{variant} is not placed. Read its arm of ProbeKind::filter \
             and add it to ADMITS_ICMP or CLOSED_TO_ICMP in \
             tests/hygiene/attribution.rs, so the strategies that open it are \
             counted as listening for ICMP or not."
        );
    }
    for name in &placed {
        assert!(
            variants.iter().any(|variant| variant == name),
            "ProbeKind::{name} is placed here and no longer exists; remove it"
        );
    }
}

/// **Both censuses see a reader or a listener however it is spelled, and
/// nothing that only mentions one.**
///
/// A detector that cannot see leaves its census green, and matching the calls
/// as literal text is such a detector: a braced import of the reader never
/// spells them. So the instrument is checked on its own, against the spellings
/// it claims to see and the prose it claims to ignore.
#[test]
fn the_censuses_see_through_spelling_and_not_through_prose() {
    let reads = |source: &str| names_the_reader(&production(source));
    for spelling in [
        "use crate::scanner::strategy::icmp_error::parse;",
        "use crate::scanner::strategy::icmp_error::{parse};",
        "use super::icmp_error::{self as errors}; fn f() { errors::parse(r); }",
        "use super::icmp_error::*; fn f() { parse_expired(r); }",
        "fn f<'a>(r: &'a R) { crate::scanner::strategy::icmp_error::parse(r); }",
        "#[cfg(test)]\nmod tests { const OPEN: char = '{'; }\nuse super::icmp_error::parse;",
    ] {
        assert!(reads(spelling), "a reader went unseen: {spelling}");
    }
    for prose in [
        "/// Reads through [`icmp_error::parse`].\nfn f() {}",
        "/* icmp_error::parse */ fn f() {}",
        "fn f() { let _ = (\"icmp_error::parse\", r#\"icmp_error\"#); }",
        "pub mod icmp_error;",
        "#[cfg(test)]\nmod tests { const CLOSE: char = '}'; use super::icmp_error::parse; }",
    ] {
        assert!(!reads(prose), "a mention was taken for a reader: {prose}");
    }

    let listens = |source: &str| listens_for_icmp(&production(source));
    for spelling in [
        "fn f() { ProbeKind::Sctp { reply_port: 1 } }",
        "use crate::transport::probe::ProbeKind as Kind; fn f() { Kind::IcmpEcho { identifier: 1 } }",
        "use crate::transport::probe::ProbeKind::{TcpSyn, UdpProbe};",
        "fn f(asked: bool) { ProbeKind::TcpProbe { reply_port: 1, icmp_errors: asked } }",
    ] {
        assert!(listens(spelling), "a listener went unseen: {spelling}");
    }
    for quiet in [
        "fn f() { ProbeKind::TcpSyn }",
        "fn f() { ProbeKind::TcpProbe { reply_port: 1, icmp_errors: false } }",
        "/// Opens a [`ProbeKind::Sctp`] transport.\nfn f() {}",
    ] {
        assert!(
            !listens(quiet),
            "a capture closed to ICMP was counted: {quiet}"
        );
    }
}

/// Nobody explains themselves in a blank line.
#[test]
fn every_census_line_says_something() {
    for (path, how) in ATTRIBUTED.iter().chain(LISTENING) {
        assert!(
            how.len() > 60,
            "{path}'s census note is too short to be an answer: {how:?}"
        );
    }
}
