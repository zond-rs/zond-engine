// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Fingerprinting corpus regression tests
//!
//! Locks matching behaviour against silent regression, in four layers:
//!
//! 1. **Self-consistency** ([`every_signature_matches_its_example`]): 95% of
//!    signature rules ship a recorded `example` banner they are meant to match.
//!    Every example is run through the real signature and the count of
//!    non-matching examples is pinned to a baseline.
//! 2. **Prefilter soundness** ([`prefilter_never_drops_a_matching_signature`]):
//!    for every example that matches its pattern, the global-match prefilter
//!    must select that signature as a candidate. This is what makes it safe to
//!    narrow the global set instead of scanning all of it.
//! 3. **One reply, one witness** ([`one_reply_is_one_witness`]): whatever a
//!    rule's example leaves on a host's record, it leaves under the source it
//!    was read as, so the arithmetic that combines sources never counts one
//!    reading as two witnesses.
//! 4. **Golden end-to-end** ([`golden_cases_resolve_end_to_end`],
//!    [`non_standard_port_is_identified_via_global_fallback`]): real banners
//!    driven through the whole pipeline with the exact verdict pinned.
//!
//! ## Known baseline
//!
//! 218 recorded examples do not match their own pattern, overwhelmingly case
//! mismatches (`"MIPS"` against `mips`, `"FTP server"` against `FTP Server`)
//! from imported rapid7/recog signatures whose per-pattern case flag was dropped
//! on import.
//! Restoring it takes a re-import that preserves `flags`, not a blanket
//! case-fold; the baseline is pinned so it cannot grow.

use proptest::prelude::*;
use rayon::prelude::*;

use super::db::SignatureDb;
use super::matcher::Signature;
use super::prefilter::{LiteralPrefilter, Prefilter};
use super::response::{Collected, ResponseSet, TlsInfo};
use super::{Analyzer, BannerRegexAnalyzer, PortContext, ServiceVerdict, TlsCertAnalyzer, Tunnel};
use crate::model::confidence::Confidence;

/// Recorded examples that do not match their own pattern today, from lost recog
/// case flags; see the module docs. Ratchet down as fixed, since a rise is a
/// regression.
const KNOWN_EXAMPLE_MISMATCHES: usize = 218;

/// The signature set flattened exactly as the runtime builds it, paired with
/// each signature's recorded example (if any).
fn signatures_with_examples() -> (Vec<Signature>, Vec<Option<String>>) {
    let defs = SignatureDb::embedded_definitions();
    let mut signatures = Vec::new();
    let mut examples = Vec::new();
    for def in &defs {
        for rule in &def.r#match {
            signatures.push(Signature::new(&def.service.name, rule));
            examples.push(rule.example.clone().filter(|e| !e.is_empty()));
        }
    }
    (signatures, examples)
}

#[test]
fn every_signature_matches_its_example() {
    let (signatures, examples) = signatures_with_examples();

    let mut mismatches: Vec<String> = signatures
        .par_iter()
        .zip(examples.par_iter())
        .filter_map(|(signature, example)| {
            let example = example.as_deref()?;
            signature
                .identify(example, crate::model::host::OsSource::ServiceBanner)
                .is_none()
                .then(|| format!("example={example:?} pattern={:?}", signature.pattern()))
        })
        .collect();
    mismatches.sort();

    assert_eq!(
        mismatches.len(),
        KNOWN_EXAMPLE_MISMATCHES,
        "example-match count changed (found {}, baseline {KNOWN_EXAMPLE_MISMATCHES}). If you \
         changed signatures, review the delta and update KNOWN_EXAMPLE_MISMATCHES.\nFirst:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[test]
fn prefilter_never_drops_a_matching_signature() {
    let (signatures, examples) = signatures_with_examples();
    let prefilter = LiteralPrefilter::build(&signatures);

    // For every example that genuinely matches its signature, the prefilter must
    // list that signature as a candidate, or global matching would miss it.
    let violations: usize = signatures
        .par_iter()
        .zip(examples.par_iter())
        .enumerate()
        .filter(|(idx, (signature, example))| {
            let Some(example) = example.as_deref() else {
                return false;
            };
            if signature
                .identify(example, crate::model::host::OsSource::ServiceBanner)
                .is_none()
            {
                return false; // example doesn't match anyway (known baseline)
            }
            !prefilter.candidates(example).contains(idx)
        })
        .count();

    assert_eq!(
        violations,
        0,
        "prefilter dropped {}",
        crate::logging::counted(
            violations as u128,
            "matching signature",
            "matching signatures"
        )
    );
}

/// One reply is one witness, whatever the rule that read it says about the
/// machine.
///
/// Every shipped rule's example, read as each kind of text a rule is matched
/// against, and filed with a host the way a reply's reading is: what it implies
/// about the system and the hardware it describes, together, on a host with no
/// address behind it and no name. Whatever that leaves on record has to be
/// filed under the source that was read. Filed under another, the reply stands
/// in for a witness that said nothing, and beside its own reading it is counted
/// twice, which the arithmetic that combines sources takes for two witnesses
/// agreeing: a vendor a service described, read back as its address's own,
/// carries a single SNMP description past the confidence at which the active
/// OS probe is skipped.
///
/// What it sees is what one reply produces. A scanner joining two exchanges,
/// such as a name one of them learned and a record the other fetched under
/// that name, is outside any sweep of single replies, and each such join is
/// pinned where it is made.
#[test]
fn one_reply_is_one_witness() {
    use crate::model::host::{Host, OsSource};
    use std::collections::BTreeSet;

    let (signatures, examples) = signatures_with_examples();
    let read_as = [
        OsSource::ServiceBanner,
        OsSource::SnmpAgent,
        OsSource::MdnsResponder,
    ];

    let mut misfiled: Vec<String> = signatures
        .par_iter()
        .zip(examples.par_iter())
        .filter_map(|(signature, example)| Some((signature, example.as_deref()?)))
        .flat_map_iter(|(signature, example)| {
            read_as.into_iter().filter_map(move |source| {
                let matched = signature.identify(example, source)?;
                let mut host = Host::new("192.0.2.1".parse().expect("a literal address"));
                super::AboutTheHost {
                    os: matched.os.into_iter().collect(),
                    hardware: matched.hardware,
                }
                .apply(&mut host);

                let filed: BTreeSet<OsSource> =
                    host.os_evidence().map(|evidence| evidence.source).collect();
                filed
                    .iter()
                    .any(|other| *other != source)
                    .then(|| format!("{example:?} read as {source:?} left {filed:?}"))
            })
        })
        .collect();
    misfiled.sort();

    assert!(
        misfiled.is_empty(),
        "{} left a reading under a source they were not read as:\n{}",
        crate::logging::counted(misfiled.len() as u128, "example", "examples"),
        misfiled
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[test]
fn golden_cases_resolve_end_to_end() {
    struct Case {
        port: u16,
        response: &'static str,
        service: &'static str,
        product: Option<&'static str>,
        version: Option<&'static str>,
    }

    let cases = [
        Case {
            port: 22,
            response: "SSH-2.0-OpenSSH_9.6p1 Debian-3",
            service: "ssh",
            product: Some("OpenSSH"),
            version: Some("9.6p1"),
        },
        Case {
            port: 22,
            response: "SSH-2.0-dropbear_2022.83",
            service: "ssh",
            product: Some("dropbear"),
            version: Some("2022.83"),
        },
        // Best-match, not first-match: the generic `HTTP/1.1` signature is
        // listed before the `Server: nginx` one and matches this response too,
        // but the more specific match, naming product and version, has to win.
        Case {
            port: 80,
            response: "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Type: text/html\r\n\r\n",
            service: "http",
            product: Some("nginx"),
            version: Some("1.25.3"),
        },
    ];

    for case in cases {
        let responses = ResponseSet::from_banners(vec![case.response.to_string()]);
        let evidence = BannerRegexAnalyzer.analyze(
            &PortContext {
                port: case.port,
                protocol: crate::model::port::Protocol::Tcp,
                addr: None,
                tunnel: None,
                speaks_http: false,
                detection: crate::config::ServiceDetection::default(),
                host_name: None,
            },
            &responses,
            &Collected::default(),
        );
        let verdict = ServiceVerdict::resolve(evidence);

        assert_eq!(
            verdict.service.as_deref(),
            Some(case.service),
            "service for {:?}",
            case.response
        );
        if let Some(product) = case.product {
            assert_eq!(
                verdict.product.as_deref(),
                Some(product),
                "product for {:?}",
                case.response
            );
        }
        if let Some(version) = case.version {
            assert_eq!(
                verdict.version.as_deref(),
                Some(version),
                "version for {:?}",
                case.response
            );
        }
    }
}

#[test]
fn non_standard_port_is_identified_via_global_fallback() {
    // SSH on an unclaimed high port: no linked signatures, so identification
    // must come from the prefilter-narrowed global fallback.
    let port = 51987;
    assert!(
        SignatureDb::global().signatures_for_port(port).is_empty(),
        "test assumes port {port} is unclaimed"
    );

    let responses = ResponseSet::from_banners(vec!["SSH-2.0-OpenSSH_9.6p1".to_string()]);
    let evidence = BannerRegexAnalyzer.analyze(
        &PortContext {
            protocol: crate::model::port::Protocol::Tcp,
            port,
            addr: None,
            tunnel: None,
            speaks_http: false,
            detection: crate::config::ServiceDetection::default(),
            host_name: None,
        },
        &responses,
        &Collected::default(),
    );
    // A global-fallback match is not corroborated by the port.
    assert!(
        evidence.iter().all(|e| !e.port_confirmed),
        "global-fallback evidence must not be port-confirmed"
    );
    let verdict = ServiceVerdict::resolve(evidence);

    assert_eq!(verdict.service.as_deref(), Some("ssh"));
    assert_eq!(verdict.product.as_deref(), Some("OpenSSH"));
    assert_eq!(verdict.version.as_deref(), Some("9.6p1"));
}

proptest! {
    /// The headline fuzz target: adversarial banners driven through the whole
    /// banner-matching pipeline against the real signature set, so prefilter,
    /// then regex, then best-match, then resolve. It never panics and always
    /// terminates, whatever bytes arrive on the wire. Port 80 exercises the
    /// port-linked tier; unmatched banners fall through to the global prefilter,
    /// so both matching paths are covered.
    #[test]
    fn banner_pipeline_never_panics_on_adversarial_input(banner in "(?s).*") {
        let responses = ResponseSet::from_banners(vec![banner]);
        let ctx = PortContext {
            port: 80,
            protocol: crate::model::port::Protocol::Tcp,
            addr: None,
            tunnel: None,
            speaks_http: false,
            detection: crate::config::ServiceDetection::default(),
            host_name: None,
        };
        let evidence = BannerRegexAnalyzer.analyze(&ctx, &responses, &Collected::default());
        let _ = ServiceVerdict::resolve(evidence);
    }
}

#[test]
fn port_linked_match_is_tagged_port_confirmed() {
    // The same SSH banner on port 22 matches a signature registered for the
    // port, so its evidence is port-confirmed, the flag the resolver ranks on.
    let responses = ResponseSet::from_banners(vec!["SSH-2.0-OpenSSH_9.6p1 Debian-3".to_string()]);
    let evidence = BannerRegexAnalyzer.analyze(
        &PortContext {
            port: 22,
            protocol: crate::model::port::Protocol::Tcp,
            addr: None,
            tunnel: None,
            speaks_http: false,
            detection: crate::config::ServiceDetection::default(),
            host_name: None,
        },
        &responses,
        &Collected::default(),
    );
    assert!(
        evidence.iter().any(|e| e.port_confirmed),
        "a port-linked match must be tagged port-confirmed"
    );
}

/// A recorded self-signed appliance certificate (DER). Subject == issuer,
/// `O=Zond Appliance`, `CN=zond-device.local`. Serves as the parse oracle for
/// the TLS analyzer, mirroring the recorded-banner corpus above.
const SELF_SIGNED_CERT: &[u8] = include_bytes!("testdata/selfsigned.der");

#[test]
fn tls_cert_identifies_self_signed_appliance() {
    let responses = ResponseSet {
        banners: Vec::new(),
        tls: Some(TlsInfo {
            certificates: vec![SELF_SIGNED_CERT.to_vec()],
            ..TlsInfo::default()
        }),
    };

    let evidence = TlsCertAnalyzer.analyze(
        &PortContext {
            port: 8443,
            protocol: crate::model::port::Protocol::Tcp,
            addr: None,
            tunnel: Some(Tunnel::Tls),
            speaks_http: false,
            detection: crate::config::ServiceDetection::default(),
            host_name: None,
        },
        &responses,
        &Collected::default(),
    );
    let verdict = ServiceVerdict::resolve(evidence);

    // The port is identified as TLS, and the self-signed subject O= names the vendor.
    assert_eq!(verdict.service.as_deref(), Some("ssl"));
    assert_eq!(verdict.vendor.as_deref(), Some("Zond Appliance"));
    assert_eq!(verdict.confidence, Confidence::Probable);
    let service = verdict.to_service().unwrap();
    // The tunnel's own `ssl` verdict is not re-prefixed into `ssl/ssl`, even
    // under a TLS context.
    assert_eq!(service.name(), "ssl");
    // The vendor reaches the projected Service, rather than being extracted
    // here and dropped by `to_service`.
    assert_eq!(service.vendor(), Some("Zond Appliance"));
}

#[test]
fn tls_analyzer_is_silent_without_a_certificate() {
    // No TLS captured: the analyzer must produce nothing, not a bare "ssl".
    let responses = ResponseSet::from_banners(vec!["HTTP/1.1 200 OK".to_string()]);
    assert!(
        TlsCertAnalyzer
            .analyze(
                &PortContext {
                    port: 80,
                    protocol: crate::model::port::Protocol::Tcp,
                    addr: None,
                    tunnel: None,
                    speaks_http: false,
                    detection: crate::config::ServiceDetection::default(),
                    host_name: None,
                },
                &responses,
                &Collected::default(),
            )
            .is_empty()
    );
}

#[test]
fn banner_matched_in_a_tunnel_is_labelled_with_scheme() {
    // A protocol identified from data read inside TLS keeps its bare service on
    // the evidence but is labelled `ssl/<proto>` for the user.
    let responses = ResponseSet::from_banners(vec!["SSH-2.0-OpenSSH_9.6p1".to_string()]);
    let ctx = PortContext {
        port: 22,
        protocol: crate::model::port::Protocol::Tcp,
        addr: None,
        tunnel: Some(Tunnel::Tls),
        speaks_http: false,
        detection: crate::config::ServiceDetection::default(),
        host_name: None,
    };
    let evidence = BannerRegexAnalyzer.analyze(&ctx, &responses, &Collected::default());
    let verdict = ServiceVerdict::resolve(evidence);

    assert_eq!(verdict.service.as_deref(), Some("ssh")); // evidence stays bare
    assert_eq!(verdict.tunnel, Some(Tunnel::Tls));
    assert_eq!(verdict.to_service().unwrap().name(), "ssl/ssh"); // label composes both
}

/// What the banner analyzer names `banner` on `port`, as the service and
/// product of its resolved verdict.
fn named(port: u16, protocol: crate::model::port::Protocol, banner: &str) -> ServiceVerdict {
    let responses = ResponseSet::from_banners(vec![banner.to_string()]);
    let evidence = BannerRegexAnalyzer.analyze(
        &PortContext {
            port,
            protocol,
            addr: None,
            tunnel: None,
            speaks_http: false,
            detection: crate::config::ServiceDetection::default(),
            host_name: None,
        },
        &responses,
        &Collected::default(),
    );
    ServiceVerdict::resolve(evidence)
}

/// A Zabbix agent is named by the header its protocol frames every reply
/// in, and not by the digit an `agent.ping` answer carries.
///
/// A rule anchored on that digit alone is consulted across the whole corpus
/// for any port its own did not name, and reads every text that begins with
/// a `1` as an agent: a session cookie, a page titled with a count, the
/// object identifier every SNMP agent answers with. Each of those put a
/// monitoring agent's name on a web server or a printer.
#[test]
fn only_a_framed_zabbix_reply_is_named_zabbix() {
    use crate::model::port::Protocol::{Tcp, Udp};

    let not_zabbix = [
        (
            8080,
            Tcp,
            "HTTP/1.1 200 OK\r\nServer: farm\r\nSet-Cookie: 1f3a9c=0; Path=/\r\n\
             Content-Type: text/html\r\n\r\n<title>1 new message</title>",
        ),
        (51987, Tcp, "1\r\n"),
        (161, Udp, "1.3.6.1.4.1.11.2.3.9.1"),
    ];
    for (port, protocol, banner) in not_zabbix {
        // Every witness rather than the winner: a reading that loses the
        // ranking on one port is still a reading, and it wins on the next
        // port that has nothing better to say.
        let verdict = named(port, protocol, banner);
        assert!(
            verdict
                .evidence
                .iter()
                .all(|evidence| evidence.service.as_deref() != Some("zabbix")),
            "{banner:?} on {port} was read as zabbix: {verdict:?}"
        );
    }

    // `agent.ping` answered: the header, the protocol flag, an eight-byte
    // little-endian length of one, and the `1` itself.
    let pong = "ZBXD\u{1}\u{1}\0\0\0\0\0\0\0\u{31}";
    for port in [10050, 51987] {
        let verdict = named(port, Tcp, pong);
        assert_eq!(verdict.service.as_deref(), Some("zabbix"), "on {port}");
    }
}

/// A raw-print port is named by the PJL its printer answers in, and not by
/// the two letters of a vendor's name wherever they fall.
///
/// A rule reading `HP` anywhere is consulted across the whole corpus for any
/// port its own did not name, and reads every reply that mentions PHP, an
/// `X-Powered-By` header or a page about it, as a JetDirect printer. What a
/// printer on its raw port says of its own accord is a PJL reply, which opens
/// with the `@PJL` command it answers.
#[test]
fn only_a_pjl_reply_is_named_a_raw_print_port() {
    use crate::model::port::Protocol::Tcp;

    let not_a_printer = [
        (
            8080,
            "HTTP/1.1 200 OK\r\nServer: Apache\r\nX-Powered-By: PHP/8.1.2\r\n\
             Content-Type: text/html\r\n\r\n<title>Welcome</title>",
        ),
        (51987, "X-Powered-By: PHP/8.1.2"),
        (9100, "Powered by PHP"),
    ];
    for (port, banner) in not_a_printer {
        let verdict = named(port, Tcp, banner);
        assert!(
            verdict
                .evidence
                .iter()
                .all(|evidence| evidence.service.as_deref() != Some("jetdirect")),
            "{banner:?} on {port} was read as a raw-print port: {verdict:?}"
        );
    }

    // `@PJL INFO ID` answered: the command echoed, then the model in quotes
    // and the form feed that ends every PJL reply.
    let id = "@PJL INFO ID\r\n\"HP LaserJet 4250\"\r\n\u{c}";
    let verdict = named(9100, Tcp, id);
    assert_eq!(verdict.service.as_deref(), Some("jetdirect"));
}

/// Every rule that reads a byte from 0x80 up ships an example, so the tests
/// above run it.
///
/// Those are the rules a reading of the reply as text can lose: a decoder that
/// turned such a byte into anything but its own code point left thirteen of
/// them matching nothing, and none carried an example that would have said so.
/// A rule of that kind without one is a rule nothing checks.
#[test]
fn every_rule_reading_a_high_byte_ships_an_example() {
    /// Whether `pattern` names, by escape, a byte from 0x80 up.
    fn names_a_high_byte(pattern: &str) -> bool {
        pattern
            .match_indices("\\x")
            .filter_map(|(at, _)| pattern.get(at + 2..at + 4))
            .filter_map(|digits| u8::from_str_radix(digits, 16).ok())
            .any(|byte| byte >= 0x80)
    }

    let mut unexampled: Vec<String> = SignatureDb::embedded_definitions()
        .iter()
        .flat_map(|def| {
            def.r#match
                .iter()
                .filter(|rule| names_a_high_byte(&rule.pattern))
                .filter(|rule| rule.example.as_deref().is_none_or(str::is_empty))
                .map(|rule| {
                    format!(
                        "{}#{}",
                        def.service.name,
                        rule.name.as_deref().unwrap_or("?")
                    )
                })
        })
        .collect();
    unexampled.sort();

    assert!(
        unexampled.is_empty(),
        "rules reading a high byte with no example: {unexampled:?}"
    );
}

/// Binary replies reach the rules written for their bytes, read the way the
/// transport reads them.
///
/// Each reply is built from the specification of its protocol and handed over
/// as bytes, so the decoding between the socket and the matcher is under test
/// as well as the rule: every one of these was once matched against text in
/// which its high bytes had become the replacement character.
#[test]
fn binary_replies_reach_the_rules_written_for_their_bytes() {
    use crate::model::port::Protocol::Tcp;

    let replies: &[(u16, &[u8], &str)] = &[
        // RFC 1002 §4.3.3: a positive session response.
        (139, b"\x82\x00\x00\x00", "netbios-ssn"),
        // RFC 1002 §4.3.4: a negative one, called name not present.
        (139, b"\x83\x00\x00\x01\x82", "netbios-ssn"),
        // RFC 854: IAC DO TERMINAL-TYPE.
        (23, b"\xff\xfd\x18\xff\xfd\x20", "telnet"),
        // An Active Directory bind response, every length in four bytes.
        (
            389,
            b"\x30\x84\x00\x00\x00\x10\x02\x01\x01\x61\x84\x00\x00\x00\x07\x0a\x01\x00\x04\x00\x04\x00",
            "ldap",
        ),
        // RFC 1928 §3: no acceptable method.
        (1080, b"\x05\xff", "socks5"),
        // RFC 4271 §4.5: NOTIFICATION, Cease.
        (
            179,
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x15\x03\x06\x05",
            "bgp",
        ),
        // RFC 2637 §2.2: Start-Control-Connection-Reply.
        (
            1723,
            b"\x00\x9c\x00\x01\x1a\x2b\x3c\x4d\x00\x02\x00\x00\x01\x00\x01\x00",
            "pptp",
        ),
        // ZMTP 3.0: the greeting's signature and version.
        (5556, b"\xff\x00\x00\x00\x00\x00\x00\x00\x01\x7f\x03\x00", "zeromq"),
        // A native protocol v4 ERROR frame.
        (9042, b"\x84\x00\x00\x01\x00\x00\x00\x00\x10", "cassandra"),
        // The legacy server list ping answered.
        (
            25565,
            b"\xff\x00\x16\x00\xa7\x00\x31\x00\x00\x00\x37\x00\x36",
            "minecraft",
        ),
        // A record-marked PMAPPROC_DUMP reply naming nothing.
        (
            111,
            b"\x80\x00\x00\x1czond\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            "rpcbind",
        ),
    ];

    for (port, reply, service) in replies {
        let text = super::extract::reply_text(reply);
        let verdict = named(*port, Tcp, &text);
        assert_eq!(
            verdict.service.as_deref(),
            Some(*service),
            "{reply:02x?} on {port}"
        );
    }
}

/// A high first byte alone names nothing.
///
/// These rules are consulted on every port nothing else names, and a dozen
/// binary protocols open on 0xFF or on a byte just past 0x80. Each is written
/// against its protocol's header whole, so a reply that shares one byte with
/// it is not taken for it.
#[test]
fn a_high_first_byte_alone_names_no_binary_protocol() {
    use crate::model::port::Protocol::Tcp;

    let others: &[&[u8]] = &[
        b"\x82\x01\x02\x03 something else",
        b"\x80\x00\x01\x00 not a reply to this engine",
        b"\xff\x00\x10\x00\x41\x00\x42",
    ];
    for reply in others {
        let verdict = named(51987, Tcp, &super::extract::reply_text(reply));
        for claimed in ["netbios-ssn", "rpcbind", "minecraft", "zeromq"] {
            assert!(
                verdict
                    .evidence
                    .iter()
                    .all(|evidence| evidence.service.as_deref() != Some(claimed)),
                "{reply:02x?} was read as {claimed}: {verdict:?}"
            );
        }
    }
}

/// A NetBIOS session service is named from its answer end to end, over a
/// socket, the one path every other test here stands in for.
#[tokio::test]
async fn a_session_service_is_named_from_its_answer_over_a_socket() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use crate::model::port::{PortState, Protocol};

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a socket");
    let addr = listener.local_addr().expect("its address");
    let server = tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut request = [0u8; 128];
        if sock.read(&mut request).await.is_ok_and(|read| read > 0) {
            let _ = sock.write_all(b"\x82\x00\x00\x00").await;
        }
        let _ = sock.read(&mut request).await;
    });

    let stream = TcpStream::connect(addr).await.expect("connects");
    let port = super::baseline_port(139, Protocol::Tcp, PortState::Open);
    let identified =
        super::fingerprint_tcp(stream, port, crate::config::ServiceDetection::Probe).await;
    server.abort();

    // Named above the label the port's number alone earns, which is what it
    // carries before anything is asked.
    let labelled = super::baseline_port(139, Protocol::Tcp, PortState::Open);
    let label = labelled.service().map(|service| service.confidence());
    let identified = identified.service().expect("the port is named");
    assert_eq!(identified.name(), "netbios-ssn");
    assert!(
        Some(identified.confidence()) > label,
        "{identified:?} is no more than the port's label"
    );
}

/// A server that answers the RDP negotiation is named, with the security layer
/// it chose.
///
/// Every Windows release since Vista and xrdp answer a negotiation request
/// with a 19-byte Connection Confirm (MS-RDPBCGR 2.2.1.2), and which layer the
/// server selects is the question an assessor asks of it first: CredSSP
/// authenticates before any session exists, and TLS alone puts a logon screen
/// in front of whoever connects.
#[test]
fn an_rdp_negotiation_answer_names_the_security_layer() {
    use crate::model::port::Protocol::Tcp;

    let answers: &[(&[u8], Option<&str>)] = &[
        (
            b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x1f\x08\x00\x02\x00\x00\x00",
            Some("security layer: CredSSP (NLA)"),
        ),
        (
            b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x01\x08\x00\x01\x00\x00\x00",
            Some("security layer: TLS without NLA"),
        ),
        (
            b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x03\x00\x08\x00\x02\x00\x00\x00",
            Some("security layer: standard RDP security only"),
        ),
        // A source reference whose two bytes form a UTF-8 sequence.
        (
            b"\x03\x00\x00\x13\x0e\xd0\x00\x00\xc3\xa9\x00\x02\x1f\x08\x00\x02\x00\x00\x00",
            Some("security layer: CredSSP (NLA)"),
        ),
        // A server from before negotiation existed.
        (b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00", None),
    ];
    for (answer, layer) in answers {
        let verdict = named(3389, Tcp, &super::extract::reply_text(answer));
        assert_eq!(verdict.service.as_deref(), Some("rdp"), "{answer:02x?}");
        assert_eq!(verdict.extrainfo.as_deref(), *layer, "{answer:02x?}");
    }
}

/// The same, end to end over a socket: the probe goes out, the confirm comes
/// back, and the port is named from it.
#[tokio::test]
async fn an_rdp_server_is_named_from_its_negotiation_over_a_socket() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use crate::model::port::{PortState, Protocol};

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a socket");
    let addr = listener.local_addr().expect("its address");
    let server = tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut request = [0u8; 64];
        // Answer only a negotiation request, as a real server does.
        if sock
            .read(&mut request)
            .await
            .is_ok_and(|read| read == 19 && request[5] == 0xe0)
        {
            let _ = sock
                .write_all(
                    b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x1f\x08\x00\x02\x00\x00\x00",
                )
                .await;
        }
        let _ = sock.read(&mut request).await;
    });

    let stream = TcpStream::connect(addr).await.expect("connects");
    let port = super::baseline_port(3389, Protocol::Tcp, PortState::Open);
    let identified =
        super::fingerprint_tcp(stream, port, crate::config::ServiceDetection::Probe).await;
    server.abort();

    let service = identified.service().expect("the port is named");
    assert_eq!(service.name(), "rdp");
    assert_eq!(service.extrainfo(), Some("security layer: CredSSP (NLA)"));
}

/// A domain controller's functional level names its release only as far as
/// the level does.
///
/// Level 7 is the highest Server 2016, 2019 and 2022 support alike, so it
/// names Windows Server and no release. A 2016 reading there would stand on
/// every 2019 and 2022 controller with a CPE sending it to the wrong
/// vulnerability records, and nothing else a modern controller answers would
/// contradict it. Level 10 is Server 2025's alone, and level 6 still names
/// 2012 R2.
#[test]
fn a_functional_level_names_the_release_only_as_far_as_it_goes() {
    use crate::model::port::Protocol::Tcp;

    /// The root DSE attributes the rules read, in the four-byte lengths Active
    /// Directory writes.
    fn root_dse(level: &[u8]) -> String {
        let mut bytes = b"\x04\x15supportedCapabilities1\x84\x00\x00\x00\x18\x04\x16".to_vec();
        bytes.extend_from_slice(b"1.2.840.113556.1.4.8000\x84\x00\x00\x00\x28");
        bytes.extend_from_slice(b"\x04\x1ddomainControllerFunctionality1\x84\x00\x00\x00");
        bytes.push(2 + level.len() as u8);
        bytes.extend_from_slice(&[0x04, level.len() as u8]);
        bytes.extend_from_slice(level);
        super::extract::reply_text(&bytes)
    }

    // The CPE a reading carries, release and all: `windows` is the family's
    // own, which is as far as level 7 goes.
    let cases: &[(&[u8], &str, &str)] = &[
        (b"7", "Windows Server", "cpe:/o:microsoft:windows:-"),
        (
            b"10",
            "Windows Server 2025",
            "cpe:/o:microsoft:windows_server_2025:-",
        ),
        (
            b"6",
            "Windows Server 2012 R2",
            "cpe:/o:microsoft:windows_server_2012:-",
        ),
    ];
    for (level, product, cpe) in cases {
        let found = SignatureDb::global()
            .identify(389, Tcp, &root_dse(level))
            .expect("a controller's root DSE is read");
        let os = found.os.expect("the level names an operating system");
        assert_eq!(os.product.as_deref(), Some(*product), "level {level:?}");
        assert_eq!(os.cpe.as_deref(), Some(*cpe), "level {level:?}");
        assert_eq!(
            found.product.as_deref(),
            Some("Active Directory Controller")
        );
    }
}

/// What the transport hands the matcher for `bytes` read from `port`: the
/// fields a structured reply yields, then the reply whole, as the banner
/// collection does.
fn read_as_the_transport(port: u16, bytes: &[u8]) -> ServiceVerdict {
    let mut banners = super::extract::from_stream(port, bytes);
    banners.push(super::extract::reply_text(bytes));
    let evidence = BannerRegexAnalyzer.analyze(
        &PortContext::new(port, crate::model::port::Protocol::Tcp),
        &ResponseSet::from_banners(banners),
        &Collected::default(),
    );
    ServiceVerdict::resolve(evidence)
}

/// The services a domain, a file server or a database host answers on every
/// day are named past a label, over TCP, from what each says before any
/// login.
///
/// Each reply is built from its protocol's specification: a password-protected
/// Redis refusing INFO, a VNC server's greeting, a SQL Server pre-login answer,
/// and a KDC, an NFS server and a nameserver each answering over TCP the
/// question the corpus had asked them only over UDP.
#[test]
fn everyday_services_are_named_over_tcp_from_what_they_say_first() {
    struct Case {
        port: u16,
        reply: Vec<u8>,
        service: &'static str,
        product: Option<&'static str>,
        version: Option<&'static str>,
        extrainfo: Option<&'static str>,
    }

    // A KRB-ERROR, error 6, behind its four-byte length.
    let krb_error = {
        let fields = [0xA6, 0x03, 0x02, 0x01, 6];
        let mut sequence = vec![0x30, fields.len() as u8];
        sequence.extend_from_slice(&fields);
        let mut error = vec![0x7E, sequence.len() as u8];
        error.extend_from_slice(&sequence);
        let mut framed = (error.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&error);
        framed
    };
    // A PROG_MISMATCH for versions 3 to 4, behind a last-fragment record mark.
    let nfs_mismatch = {
        let mut reply = b"zone".to_vec();
        for word in [1u32, 0, 0, 0, 2, 3, 4] {
            reply.extend_from_slice(&word.to_be_bytes());
        }
        let mut framed = (0x8000_0000 | reply.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        framed
    };
    // A version.bind answer from BIND, behind its two-byte length.
    let bind_version = {
        let mut message = b"\x00\x00\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00".to_vec();
        message.extend_from_slice(b"\x07version\x04bind\x00\x00\x10\x00\x03");
        let text = b"9.18.28-0ubuntu0.22.04.1-Ubuntu";
        message.extend_from_slice(b"\xc0\x0c\x00\x10\x00\x03\x00\x00\x00\x00");
        message.extend_from_slice(&((text.len() + 1) as u16).to_be_bytes());
        message.push(text.len() as u8);
        message.extend_from_slice(text);
        let mut framed = (message.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&message);
        framed
    };
    // A pre-login response: VERSION 15.0.2000, then ENCRYPTION, then the end.
    let prelogin = b"\x04\x01\x00\x1a\x00\x00\x01\x00\
        \x00\x00\x0b\x00\x06\x01\x00\x11\x00\x01\xff\x0f\x00\x07\xd0\x00\x00\x02"
        .to_vec();

    let cases = [
        Case {
            port: 6379,
            reply: b"-NOAUTH Authentication required.\r\n".to_vec(),
            service: "redis",
            product: None,
            version: None,
            extrainfo: Some("authentication required"),
        },
        Case {
            port: 5900,
            reply: b"RFB 003.008\n".to_vec(),
            service: "vnc",
            product: None,
            version: None,
            extrainfo: Some("protocol 3.8"),
        },
        Case {
            port: 1433,
            reply: prelogin,
            service: "mssql",
            product: Some("SQL Server"),
            version: Some("15.0.2000"),
            extrainfo: Some("SQL Server 2019"),
        },
        Case {
            port: 88,
            reply: krb_error,
            service: "kerberos",
            product: None,
            version: None,
            extrainfo: None,
        },
        Case {
            port: 2049,
            reply: nfs_mismatch,
            service: "nfs",
            product: Some("NFS"),
            version: Some("4"),
            extrainfo: Some("versions 3 to 4"),
        },
        Case {
            port: 53,
            reply: bind_version,
            service: "dns",
            product: Some("BIND"),
            version: Some("9.18.28"),
            extrainfo: None,
        },
    ];

    for case in cases {
        let verdict = read_as_the_transport(case.port, &case.reply);
        assert_eq!(
            verdict.service.as_deref(),
            Some(case.service),
            "on {}",
            case.port
        );
        assert_eq!(verdict.product.as_deref(), case.product, "on {}", case.port);
        assert_eq!(verdict.version.as_deref(), case.version, "on {}", case.port);
        assert_eq!(
            verdict.extrainfo.as_deref(),
            case.extrainfo,
            "on {}",
            case.port
        );
    }
}

/// A Kafka broker is named by its answer to the ApiVersions request, and a
/// reply that merely opens on two zero bytes is not taken for one.
///
/// Every protocol that frames its messages with a four-byte length opens that
/// way, and the rule is consulted on every port nothing else names. What only
/// a broker answering this engine's request sends is the correlation id the
/// request carried, and an error code behind it.
#[test]
fn only_a_reply_to_the_api_versions_request_is_named_kafka() {
    use crate::model::port::Protocol::Tcp;

    let broker = super::extract::reply_text(b"\x00\x00\x00\x06\x00\x00\x00\x03\x00\x00");
    assert_eq!(named(9092, Tcp, &broker).service.as_deref(), Some("kafka"));

    let others: &[&[u8]] = &[
        b"\x00\x00\x00\x0b\x7e\x09\x30\x07\xa6\x03\x02\x01\x06",
        b"\x00\x00\x01\x00 some other framed protocol",
    ];
    for reply in others {
        let verdict = named(51987, Tcp, &super::extract::reply_text(reply));
        assert!(
            verdict
                .evidence
                .iter()
                .all(|evidence| evidence.service.as_deref() != Some("kafka")),
            "{reply:02x?} was read as kafka: {verdict:?}"
        );
    }
}
