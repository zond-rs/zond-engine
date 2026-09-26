// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Every connection to a target opened in one place, as a census
//!
//! `src/transport/dial.rs` is where the engine opens the ordinary TCP and UDP
//! sockets it speaks to a scanned host through, and where each is given what
//! has to be set on it before it connects: the forced source and interface of
//! a scan pinned to one, and on Windows a limit on the SYN retransmissions of
//! every TCP socket, without which a refused port waits out the connect
//! budget and reads as filtered.
//!
//! The rule is kept by the callers, and a caller that breaks it does so without
//! anything noticing: its connection behaves exactly as before on an ordinary
//! run, and the difference shows up only under a forced source or on a
//! platform nobody ran it on. Two ways to break it are things a grep can see,
//! so these are censuses in the shape of `exclusions.rs`:
//!
//! - **A socket opened somewhere else.** Every other production file that
//!   opens a TCP or UDP socket is listed with why it is not a connection to a
//!   target.
//! - **A connection that ignores the scan's egress.** Every file that dials by
//!   the routing table's own choice is listed with the public ways in it
//!   offers, and nothing else in the crate may call them.
//!
//! - **A pass that dials a port without asking whether it may send there.**
//!   A printer prints whatever arrives on its raw-print ports, so a scan only
//!   listens on the ports it was told to, and every pass that dials a target
//!   has to ask first. Every file that takes a scan's egress to dial with also
//!   asks that question, or is listed with why it sends a port no payload.
//!
//! A new one of any of these fails the test until somebody writes that line.
//!
//! What it cannot see is a socket a dependency opens on the engine's behalf.
//! The one such dependency is `hickory-resolver`, which asks the host's own
//! resolvers for names and never a scanned host.

use std::collections::BTreeSet;
use std::fs;

use crate::source::{display, production, sources};

/// The file every connection to a target is opened in.
const DIALLER: &str = "src/transport/dial.rs";

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

/// The files that dial by the routing table's choice rather than by the
/// egress a scan chose, the public ways in each offers that do, and why no
/// scan goes through them.
///
/// A forced source reaches a connection only as an `Egress` its caller was
/// handed, so a phase that dials through one of these instead leaves by the
/// routing table's link while the probe before it left by the forced one. That
/// is exactly how a service pass came to go out through the VPN a scan was
/// pinned out of, and it looks like correct code from anywhere but a capture.
///
/// **Adding a file here is the point of this census.** Choosing the routing
/// table is right for a caller outside a scan, and has to say so; the scan's
/// own phases call the form that takes an egress.
const KERNEL_EGRESS: &[(&str, &[&str], &str)] = &[
    (
        "src/fingerprint.rs",
        &[
            "fingerprint_tcp(",
            "fingerprint_tcp_detailed(",
            "fingerprint_udp_detailed(",
            "probe_udp_with(",
            "probe_udp_raw(",
        ],
        "the public ways to fingerprint a port a caller reached on their own, which \
         dial again as the routing table says. The scan's passes call the `_via` form \
         of each with the egress `ScanContext::egress_toward` gave them. An analyzer \
         driven directly through `analyze_with` dials the same way, since it runs \
         outside any fingerprint's collection and so outside its egress.",
    ),
    (
        "src/fingerprint/tls_enum.rs",
        &["enumerate_tls("],
        "`enumerate_tls` is the public way to enumerate an endpoint outside a scan. \
         The scan's own pass calls `enumerate_tls_while` with the endpoint's egress.",
    ),
    (
        "src/detect/flow/socket.rs",
        &[],
        "`SocketProbe::new` builds a probe dialling as the routing table says, for a \
         caller driving a detection outside a scan. The scan's detection phase pins it \
         with `via` before a byte is sent; a call that stops at `new` is not caught \
         here, because the pin is a second call on the same line.",
    ),
    (
        "src/detect/compute/live.rs",
        &[],
        "`LiveCapabilities::new` is the same as `SocketProbe::new` for a compute \
         module: the routing table's choice for a caller outside a scan, pinned with \
         `via` by the detection phase.",
    ),
];

/// How a file chooses the routing table over a scan's egress.
const KERNEL: &str = "Egress::KERNEL";

/// How a scan pass takes the egress it dials a target with.
const TAKES_EGRESS: &str = "egress_toward(";

/// The two ways a pass asks whether it may send a port anything past the
/// connection: whether the port is listen-only, and how far identification
/// may go on it.
const ASKS_LISTEN_ONLY: &[&str] = &["listens_only(", "service_detection_on("];

/// The files that take a scan's egress and put no payload on a TCP port with
/// it, and why.
///
/// **Adding a file here is the point of this census.** A pass that writes to a
/// port it dialled asks `ScanContext::listens_only` first, or through
/// `service_detection_on`; one that only establishes a port's state, or speaks
/// nothing but UDP, says so on this line.
const SENDS_NO_PAYLOAD: &[(&str, &str)] = &[(
    "src/scanner/session.rs",
    "defines `egress_toward` and `listens_only` alike, and dials nothing itself.",
)];

/// **Every scan pass that dials a target asks whether it may send there.**
///
/// File-grained, as the other censuses here are: a second pass added to a file
/// whose first one already asks is not caught, and its own test is what holds
/// it. What this catches is the pass nobody thought of as a sender, in a file
/// of its own.
#[test]
fn every_pass_that_dials_a_target_asks_whether_it_may_send_there() {
    let mut takes = BTreeSet::new();
    let mut unasked = Vec::new();
    for path in sources() {
        let text = fs::read_to_string(&path).expect("a source file is readable");
        let code = production(&text);
        let path = display(&path);
        if !code.contains(TAKES_EGRESS) {
            continue;
        }
        takes.insert(path.clone());
        let listed = SENDS_NO_PAYLOAD.iter().any(|(listed, _)| *listed == path);
        if !listed && !ASKS_LISTEN_ONLY.iter().any(|asks| calls(&code, asks)) {
            unasked.push(path);
        }
    }

    assert!(
        takes.len() > SENDS_NO_PAYLOAD.len(),
        "no pass takes a scan's egress by `{TAKES_EGRESS}`, so the census has stopped \
         seeing what it is looking for. Update TAKES_EGRESS in tests/hygiene/dialling.rs."
    );
    assert!(
        unasked.is_empty(),
        "these take a scan's egress to dial with and never ask whether the port may be \
         sent anything: {unasked:?}\n\n\
         A printer prints whatever arrives on its raw-print ports, so a scan connects to \
         the ports in `ZondConfig::listen_only_ports` and sends them nothing. A pass that \
         writes to a port it dialled without asking prints a page per probe.\n\n\
         Ask `ScanContext::listens_only` (or `service_detection_on`) before sending, or, \
         if the pass puts no payload on a TCP port, add the file to SENDS_NO_PAYLOAD in \
         tests/hygiene/dialling.rs saying why."
    );

    let stale: Vec<&str> = SENDS_NO_PAYLOAD
        .iter()
        .map(|(path, _)| *path)
        .filter(|path| !takes.contains(*path))
        .collect();
    assert!(
        stale.is_empty(),
        "these are in SENDS_NO_PAYLOAD but no longer take a scan's egress: {stale:?}\n\n\
         Remove them, so the list stays a census rather than a wish."
    );
}

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
        let code = production(&text);
        if OPENS.iter().any(|opens| code.contains(opens)) {
            found.insert(display(&path));
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
         A connection to a scanned host has to be opened through `crate::transport::dial`, \
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

/// **Every connection that ignores a scan's forced source has said why, and
/// nothing in a scan calls it.**
#[test]
fn every_connection_that_leaves_by_the_routing_table_has_said_why() {
    let mut found = BTreeSet::new();
    let mut codes = Vec::new();
    for path in sources() {
        let text = fs::read_to_string(&path).expect("a source file is readable");
        let code = production(&text);
        let path = display(&path);
        if path != DIALLER && code.contains(KERNEL) {
            found.insert(path.clone());
        }
        codes.push((path, code));
    }

    let listed: BTreeSet<String> = KERNEL_EGRESS
        .iter()
        .map(|(path, _, _)| (*path).to_string())
        .collect();

    let unlisted: Vec<&String> = found.difference(&listed).collect();
    assert!(
        unlisted.is_empty(),
        "these dial by the routing table's choice and are not in KERNEL_EGRESS: \
         {unlisted:?}\n\n\
         A scan forced to a source pins every connection it opens to that source and its \
         interface, through the `Egress` `ScanContext::egress_toward` gives. `{KERNEL}` \
         ignores it, so a connection made with it leaves by whatever link the routing \
         table picks, which under a full-tunnel VPN is the tunnel the scan was pinned \
         out of.\n\n\
         Pass the scan's egress down instead, or, for a public way in used outside a \
         scan, add the file to KERNEL_EGRESS in tests/hygiene/dialling.rs saying so."
    );

    let stale: Vec<&String> = listed.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "these are in KERNEL_EGRESS but no longer dial by the routing table: {stale:?}\n\n\
         Remove them, so the list stays a census rather than a wish."
    );

    for (owner, entries, _) in KERNEL_EGRESS {
        for entry in *entries {
            let callers: Vec<&str> = codes
                .iter()
                .filter(|(path, code)| path != owner && calls(code, entry))
                .map(|(path, _)| path.as_str())
                .collect();
            assert!(
                callers.is_empty(),
                "{callers:?} call `{entry}`, which {owner} offers for a caller outside a \
                 scan and which dials by the routing table's choice. Inside the engine, \
                 call the form that takes the scan's egress."
            );
        }
    }
}

/// Whether `code` calls `entry` by its own name rather than by a longer one
/// ending the same way.
fn calls(code: &str, entry: &str) -> bool {
    code.match_indices(entry).any(|(at, _)| {
        !code[..at]
            .chars()
            .next_back()
            .is_some_and(|before| before.is_alphanumeric() || before == '_')
    })
}

/// Nobody explains themselves in a blank line.
#[test]
fn every_other_socket_says_something() {
    for (path, _, why) in KERNEL_EGRESS {
        assert!(
            why.len() > 60,
            "{path}'s note is too short to be an answer: {why:?}"
        );
    }
    for (path, why) in OTHER_SOCKETS.iter().chain(SENDS_NO_PAYLOAD) {
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
    let code = production(text);
    assert!(OPENS.iter().all(|opens| !code.contains(opens)), "{code:?}");

    let text = "fn engine() { let s = UdpSocket::bind(addr); }\n";
    assert!(production(text).contains("UdpSocket::bind"));

    // A call by name is a call; a longer name ending the same way is another
    // function.
    assert!(calls(
        "x = fingerprint::probe_udp_raw(a, b)",
        "probe_udp_raw("
    ));
    assert!(!calls("x = probe_udp_raw_via(a, b, e)", "probe_udp_raw("));
    assert!(!calls("x = my_probe_udp_raw(a, b)", "probe_udp_raw("));
}
