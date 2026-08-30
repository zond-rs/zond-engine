// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detections, from a live port to a finding in the report.
//!
//! Tier 1, alongside `service_fingerprint`: a real listener on loopback, a real
//! scan, no privileges. A detection gates on an *identified service*, so
//! nothing here is reachable without the port scan and the service pass that
//! run first, and that whole path is the point. The unit tests beside `detect`
//! hand one stage a canned probe; these make the scanner find the port, name
//! the service, decide a detection applies, open its own connection, spend a
//! budget, and file what it concluded.
//!
//! ## Why a binary of its own
//!
//! `detect` is the one large subsystem no integration test imported. It has
//! four things no other tier does: a gate that selects ports, an operator
//! envelope that decides which intrusiveness classes may run at all, a budget
//! the socket seam counts down, and two ways to author a detection. None of
//! those is a question about port state or service naming, so they get their
//! own file rather than a corner of `port_states`.
//!
//! ## What a test outside the crate can run
//!
//! Only the shipped corpus. `build.rs` compiles `assets/detect/` into the
//! binary and `FlowDb`/`ComputeDb` are crate-private, so a test cannot add a
//! detection to what a scan will run. Everything below is provoked out of the
//! real corpus: the Grafana flow for Tier 1 and the missing-headers module for
//! Tier 2, both of which gate on `http`, the one service a loopback listener on
//! an ephemeral port can be identified as. A server whose *root* names Grafana
//! is fingerprinted as `grafana` rather than `http` and fits neither gate, so
//! the version banner is served from `/login`, which is where the flow asks for
//! it anyway.
//!
//! The two refusal tests near the bottom drive the public compute seam directly
//! rather than a scan, because refusing a detection happens before a scan would
//! ever reach it.

mod common;

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use common::*;
use zond_engine::config::limits::CONNECT_CONCURRENCY;
use zond_engine::config::{DetectionEnvelope, ServiceDetection, ZondConfig};
use zond_engine::detect::compute::{
    ComputeRuntime, Grant, LiveCapabilities, LoadError, ModuleBody, ModuleFault, RhaiRuntime,
    RunOutcome,
};
use zond_engine::detect::manifest::{CapabilitySpec, Class, DetectionManifest, Rule, Speak};
use zond_engine::evasion::EvasionProfile;
use zond_engine::fingerprint::PortContext;
use zond_engine::model::finding::{DetectionClass, Finding, Reference, Severity};
use zond_engine::model::host::Host;
use zond_engine::model::port::{Port, Protocol};
use zond_engine::report::ScanReport;
use zond_engine::scanner::session::ScanSession;
use zond_engine::scanner::strategy::connect::ConnectPortScanner;
use zond_engine::scanner::{detect, service};

/// A loopback server keeping every request it read, so a test can assert on
/// what did and did not leave the scanner.
///
/// A *web* server answers the fingerprint pass with an HTTP response naming no
/// security header, and the Grafana flow's two probes with what that flow is
/// written against. A *greeting* server speaks first and says nothing more,
/// which is how a speak-first protocol is identified on any port.
struct Server {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
    _task: JoinHandle<()>,
}

impl Server {
    /// Whether any request the server read contains `needle`.
    fn saw(&self, needle: &str) -> bool {
        self.requests
            .lock()
            .expect("the request log")
            .iter()
            .any(|request| request.contains(needle))
    }
}

/// Stands a web server up on an ephemeral port. `login_padding` bytes are
/// appended to the `/login` reply, which is how a test makes one response
/// larger than the flow's declared byte budget.
async fn spawn_web_server(login_padding: usize) -> Server {
    spawn_server(None, login_padding).await
}

/// Stands a speak-first server up on an ephemeral port. It greets and answers
/// nothing, and keeps whatever was said to it.
async fn spawn_greeting_server(greeting: &'static [u8]) -> Server {
    spawn_server(Some(greeting), 0).await
}

async fn spawn_server(greeting: Option<&'static [u8]>, login_padding: usize) -> Server {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind loopback server");
    let port = listener.local_addr().expect("server local addr").port();
    let requests = Arc::new(Mutex::new(Vec::new()));

    let log = Arc::clone(&requests);
    let task = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            // One task per connection: the port scan holds one open while it
            // settles the state, and a flow opens its own alongside.
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                if let Some(greeting) = greeting {
                    let _ = sock.write_all(greeting).await;
                    let _ = sock.flush().await;
                }
                let mut buffer = vec![0u8; 8192];
                let Ok(Ok(read)) = timeout(Duration::from_secs(5), sock.read(&mut buffer)).await
                else {
                    return;
                };
                if read == 0 {
                    return;
                }
                let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
                log.lock().expect("the request log").push(request.clone());
                if greeting.is_none() {
                    let _ = sock.write_all(&web_reply(&request, login_padding)).await;
                    let _ = sock.flush().await;
                }
            });
        }
    });

    Server {
        port,
        requests,
        _task: task,
    }
}

/// What the server answers a request with. `/login` carries the version banner
/// the Grafana flow binds on, the traversal path carries the passwd line its
/// `expect` confirms on, and everything else is the plain response the service
/// pass reads and the compute module grades.
fn web_reply(request: &str, login_padding: usize) -> Vec<u8> {
    if request.contains("/login") {
        let mut reply = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
             <title>Dashboard</title> Grafana v8.2.0\n"
            .to_vec();
        reply.resize(reply.len() + login_padding, b'.');
        reply
    } else if request.contains("etc/passwd") {
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n\
          root:x:0:0:root:/root:/bin/bash\n"
            .to_vec()
    } else {
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
          <html><body>ok</body></html>\n"
            .to_vec()
    }
}

/// The loopback port a report recorded.
fn port(report: &ScanReport, number: u16) -> Option<&Port> {
    report
        .host(&LOOPBACK)?
        .ports()
        .find(|port| port.number() == number)
}

/// The finding `id` produced for the loopback port `number`, if it fired.
fn finding<'a>(report: &'a ScanReport, number: u16, id: &str) -> Option<&'a Finding> {
    port(report, number)?
        .findings()
        .find(|finding| finding.detection().id() == id)
}

/// The same lookup for a caller holding the store rather than a report.
fn port_finding<'a>(host: &'a Host, number: u16, id: &str) -> Option<&'a Finding> {
    host.ports()
        .find(|port| port.number() == number)?
        .findings()
        .find(|finding| finding.detection().id() == id)
}

/// Whether this run takes the raw paths rather than the connect fallback the
/// assertions here depend on.
fn skip_when_privileged() -> bool {
    if is_privileged() {
        eprintln!("SKIP: exercises the unprivileged connect path; run as non-root");
        return true;
    }
    false
}

/// A Tier-1 flow reaches its own conclusion over its own connection, and the
/// finding lands on the port in the report.
///
/// The Grafana flow's second step is conditional on what its first bound, so a
/// finding at `critical` is proof of the whole sequence: the port was named
/// `http`, the gate fitted, a version was bound off a live reply, the guard
/// compared it, and the traversal confirmed on the wire.
#[tokio::test]
async fn a_flow_probes_a_live_service_and_files_what_it_confirmed() {
    if skip_when_privileged() {
        return;
    }

    let server = spawn_web_server(0).await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &test_config(),
    )
    .await;

    let finding = finding(&outcome.report, server.port, "grafana-path-traversal")
        .expect("the grafana flow fired against the live port");

    assert_eq!(finding.severity(), Severity::Critical);
    assert_eq!(
        finding.title(),
        "Grafana is vulnerable to unauthenticated path traversal"
    );
    assert_eq!(finding.class(), DetectionClass::ActiveBenign);
    assert!(
        finding.excerpt().as_str().contains("root:x:0:0:"),
        "the excerpt should be the bytes the traversal read, got {:?}",
        finding.excerpt().as_str()
    );
    assert!(
        finding
            .references()
            .any(|reference| matches!(reference, Reference::Cve(id) if id == "CVE-2021-43798"))
    );
    // Provenance is the flow's own content hash, not the empty one the
    // interpreter stamps when no loader supplied it.
    assert_eq!(finding.detection().content_hash().len(), 64);

    assert!(
        server.saw("etc/passwd"),
        "the confirming probe never reached the server"
    );
}

/// A Tier-2 module reaches a verdict over the response the service pass already
/// drew, and adds no traffic of its own.
///
/// Its severity is *computed* rather than declared, which is what earns the
/// tier: four of the four baseline headers absent is `medium`, one or two would
/// be `low`.
///
/// The phases are assembled here rather than taken from `scanner::scan`, which
/// is the second of the three altitudes the `scanner` module documents. That is
/// the only way this runs today: the connect scanner fingerprints inline and
/// drops the responses it drew, so nothing reaches a passive detection on the
/// unprivileged path. See the ignored claim at the bottom of this file.
#[tokio::test]
async fn a_compute_module_grades_the_response_the_scan_already_gathered() {
    if skip_when_privileged() {
        return;
    }

    let server = spawn_web_server(0).await;
    let (session, ctx) = ScanSession::new();

    // The port scan settles the state and leaves identification to the service
    // pass, which is the order the raw path runs these phases in.
    let mut scanner = ConnectPortScanner::new(
        ctx.clone(),
        CONNECT_CONCURRENCY,
        ServiceDetection::Off,
        &EvasionProfile::default(),
    );
    run_port_scanner(&mut scanner, vec![tcp(LOOPBACK, server.port)]).await;
    service::detect(&ctx, ServiceDetection::Probe).await;
    detect::detect(&ctx, ServiceDetection::Probe, DetectionEnvelope::default()).await;

    let host = session.hosts().get(LOOPBACK).expect("the loopback host");
    let finding = port_finding(&host, server.port, "http-missing-security-headers")
        .expect("the compute module fired over the gathered response");

    assert_eq!(finding.severity(), Severity::Medium);
    assert_eq!(
        finding.title(),
        "the server omits 4 of 4 baseline HTTP security headers"
    );
    assert_eq!(finding.class(), DetectionClass::Passive);
    assert!(
        finding
            .excerpt()
            .as_str()
            .contains("content-security-policy"),
        "the detail should name the headers it counted, got {:?}",
        finding.excerpt().as_str()
    );
    assert!(
        finding
            .references()
            .any(|reference| matches!(reference, Reference::Cwe(693)))
    );
}

/// A port the gate does not fit is never handed to a detection, and the phase
/// that skipped it is the same one that fired on the port beside it.
///
/// Both ports are in one scan, so the negative half cannot pass for the
/// trivial reason that detection never ran: the web port carries a finding from
/// the very pass that left the SSH port alone. And the negative is asserted on
/// the wire rather than on the result, because a detection let through that
/// found nothing leaves the same empty list as one that was refused.
#[tokio::test]
async fn a_detection_whose_gate_does_not_fit_the_port_never_runs() {
    if skip_when_privileged() {
        return;
    }

    let web = spawn_web_server(0).await;
    let ssh = spawn_greeting_server(b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n").await;
    let spec = format!("{},{}", web.port, ssh.port);
    let outcome = run_scan(target_map(LOOPBACK, &spec), &test_config()).await;

    assert!(
        finding(&outcome.report, web.port, "grafana-path-traversal").is_some(),
        "the detection phase did not run at all, so the negative below proves nothing"
    );

    let ssh_port = port(&outcome.report, ssh.port).expect("the ssh port was scanned");
    assert_eq!(
        ssh_port.service().map(|service| service.name()),
        Some("ssh"),
        "the gate is only meaningful once the service pass has named the port"
    );
    assert!(!ssh.saw("/login"), "an http-gated flow probed an ssh port");
    let fired: Vec<&str> = ssh_port
        .findings()
        .map(|finding| finding.detection().id())
        .collect();
    assert!(
        fired.is_empty(),
        "an http-gated detection ran over an ssh port: {fired:?}"
    );
}

/// The envelope decides what runs. A class above the ceiling does not, and the
/// detection that declared it never reaches the network.
///
/// Both sides, one server type, one scan shape: the only difference between the
/// halves is the ceiling, so the flow's absence is the envelope withholding a
/// class rather than the phase being off or the server being unreachable.
#[tokio::test]
async fn the_envelope_withholds_the_class_above_its_ceiling_and_serves_the_one_below() {
    if skip_when_privileged() {
        return;
    }

    let withheld = spawn_web_server(0).await;
    let passive_only = ZondConfig {
        detection: DetectionEnvelope::up_to(DetectionClass::Passive),
        ..test_config()
    };
    let outcome = run_scan(
        target_map(LOOPBACK, &withheld.port.to_string()),
        &passive_only,
    )
    .await;

    assert!(
        finding(&outcome.report, withheld.port, "grafana-path-traversal").is_none(),
        "an active-benign flow ran under a passive-only envelope"
    );
    assert!(
        !withheld.saw("/login"),
        "a withheld flow still put bytes on the wire"
    );

    // The same server and the same scan under the default ceiling, which
    // permits active-benign: the flow runs, so what stopped it above was the
    // envelope and nothing else.
    let permitted = spawn_web_server(0).await;
    let outcome = run_scan(
        target_map(LOOPBACK, &permitted.port.to_string()),
        &test_config(),
    )
    .await;

    assert!(
        finding(&outcome.report, permitted.port, "grafana-path-traversal").is_some(),
        "raising the ceiling to active-benign did not let the flow run"
    );
    assert!(
        permitted.saw("/login"),
        "the permitted flow never reached the server"
    );
}

/// A flow cannot spend more bytes than it declared, because the socket that
/// would spend them refuses the exchange.
///
/// The Grafana flow declares 65536 bytes across its whole run. A first reply
/// larger than that leaves nothing for the second, so the traversal is never
/// sent and the flow falls back to the finding it draws from the version alone.
/// Its connection budget is two and it has spent one, so what refused is the
/// byte budget.
#[tokio::test]
async fn a_flow_that_would_outspend_its_byte_budget_never_sends_the_second_probe() {
    if skip_when_privileged() {
        return;
    }

    let server = spawn_web_server(200_000).await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &test_config(),
    )
    .await;

    let finding = finding(&outcome.report, server.port, "grafana-path-traversal")
        .expect("the flow still concluded something from the version it bound");

    assert_eq!(
        finding.severity(),
        Severity::Medium,
        "an unconfirmed leak must not be reported as a confirmed one"
    );
    assert_eq!(
        finding.excerpt().as_str(),
        "Grafana 8.2.0 is < 8.3.1 (CVE-2021-43798) but the probe did not read a file.",
        "the version the first step bound should have reached the detail"
    );
    assert!(
        server.saw("/login"),
        "the first exchange should have happened within budget"
    );
    assert!(
        !server.saw("etc/passwd"),
        "the second probe was sent past the flow's byte budget"
    );
}

/// A module the runtime cannot compile is refused with a cause, before any port
/// is touched.
#[test]
fn a_module_that_does_not_compile_is_refused_before_any_port_is_touched() {
    let runtime = RhaiRuntime::new();

    let source = ModuleBody::Rhai("fn analyze(ctx, responses) {".to_string());
    let Err(error) = runtime.load(&source) else {
        panic!("a body that does not parse was loaded");
    };
    assert!(
        matches!(error, LoadError::Compile(_)),
        "expected a compile refusal, got {error:?}"
    );

    // A body that parses but defines no entry point is refused here too, rather
    // than faulting once per port at run.
    let headless = ModuleBody::Rhai("fn helper(x) { x + 1 }".to_string());
    let Err(LoadError::Compile(reason)) = runtime.load(&headless) else {
        panic!("a module with no entry point was loaded");
    };
    assert!(
        reason.contains("analyze"),
        "the refusal should name the missing entry point, got {reason:?}"
    );
}

/// A detection that declares `passive` and asks to `speak` anyway is served no
/// socket, so a misdeclaration cannot become reach.
///
/// The build rejects this manifest, but the guarantee does not rest on the
/// build: the class decides which verbs the runtime registers, so the module
/// names a function that is *absent* rather than one that returns an error. The
/// listener counts what a socket would have opened, which is what makes this an
/// assertion about the network rather than about an error string.
#[test]
fn a_passive_detection_that_asks_to_speak_is_handed_no_socket_at_all() {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stream.is_err() {
                break;
            }
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });

    let manifest = DetectionManifest {
        id: "misdeclared-passive".to_string(),
        version: "1.0.0".to_string(),
        title: "Declares passive, asks to speak".to_string(),
        when: Rule::default(),
        capabilities: CapabilitySpec {
            class: Class::Passive,
            speak: Some(Speak::Target),
            resolve: true,
            max_bytes: None,
            max_millis: Some(500),
            max_connections: None,
        },
    };
    let grant = Grant::from_manifest(&manifest, &"0".repeat(64)).expect("the manifest resolves");
    assert!(!grant.speak, "a passive detection was granted speak");
    assert!(!grant.resolve, "a passive detection was granted resolve");

    let runtime = RhaiRuntime::new();
    let module = runtime
        .load(&ModuleBody::Rhai(
            "fn analyze(ctx, responses) { speak(blob(4, 0x41)); [] }".to_string(),
        ))
        .expect("the module compiles");
    let mut instance = runtime
        .instantiate(&module, &grant)
        .expect("the module instantiates");
    let mut caps = LiveCapabilities::new(addr, Protocol::Tcp, &grant.budget);
    let ctx = PortContext {
        port: addr.port(),
        protocol: Protocol::Tcp,
        addr: Some(addr),
        tunnel: None,
    };

    match runtime.run(&mut instance, &ctx, &[], &mut caps) {
        Err(RunOutcome::Faulted(ModuleFault::Runtime(reason))) => assert!(
            reason.contains("speak"),
            "the fault should name the ungranted verb, got {reason:?}"
        ),
        Ok(findings) => panic!("a passive module reached the network: {findings:?}"),
        Err(outcome) => panic!("expected an ungranted-capability fault, got {outcome:?}"),
    }

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "a passive detection opened a connection to the scanned port"
    );
}

/// A whole scan hands a passive detection the bytes it already drew.
///
/// A claim, not a switched-off test. `scanner::detect` says a passive module
/// reads the responses the service phase gathered, and on the raw path it does:
/// the SYN scanner runs `service::detect`, which records them. The connect
/// scanner fingerprints inline through `fingerprint_tcp`, the wrapper that
/// discards the third value `fingerprint_tcp_detailed` returns precisely so a
/// later detection can read it, so on the unprivileged path the store is
/// always empty and every passive detection reads nothing. Carrying those
/// responses out of the inline pass is what removing this attribute means.
#[tokio::test]
#[ignore = "the connect path discards the responses it gathered"]
async fn a_scan_hands_a_passive_detection_the_responses_it_already_drew() {
    if skip_when_privileged() {
        return;
    }

    let server = spawn_web_server(0).await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &test_config(),
    )
    .await;

    assert!(
        finding(
            &outcome.report,
            server.port,
            "http-missing-security-headers"
        )
        .is_some(),
        "a whole scan drew the response and then handed the module nothing"
    );
}
