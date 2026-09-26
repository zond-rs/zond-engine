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
//! Nothing else states that obligation in one place, and each scanner has a way
//! of its own to get it wrong:
//!
//! | scanner | what it would believe on, unchecked |
//! |---|---|
//! | SCTP port scan | the ports alone, for an INIT, whose nonce is never inside the guaranteed eight bytes |
//! | every port scan | the quoted source port alone, for a host-unreachable, which files a host down |
//! | TCP port scan | the ports alone, for the three techniques whose nonce needs twelve quoted bytes |
//! | IP protocol scan | membership of the scan's own target list, which is what the scanned host knows about itself |
//!
//! Each is reasoned about separately, in its own scanner, and a scanner that
//! gets it right carries nothing across to the next.
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
//! it is: an SCTP discovery sweep can read ICMP errors as SCTP chunks, and the
//! census above cannot see that, because such a sweep calls no reader to be
//! counted by. So there is a second list, [`LISTENING`], of every file that
//! opens a capture admitting ICMP, each with a line saying where the protocol
//! is checked before a byte is parsed. An echo trace taking its own requests
//! for answers is the same question, asked of the ICMP type rather than the
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
use std::path::Path;

use crate::source::{self, display, is_ident, sources};

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

/// The tokens of the production code in `text`.
fn production(text: &str) -> Vec<String> {
    tokens(&source::production(text))
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
