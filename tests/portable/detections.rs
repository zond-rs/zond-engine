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
//! The shipped corpus, and a caller's own. Most tests below are provoked out of
//! the shipped corpus: the Grafana flow for Tier 1 and the missing-headers module
//! for Tier 2. A loopback listener on an ephemeral port is identified as `http`
//! while its root page names no product, and as `grafana` once that page says so,
//! which is the two halves of the Grafana flow's gate. The missing-headers module
//! gates on `http` alone, so its server keeps the quiet root page. The last test
//! builds a corpus of its own with [`Detections::builder`] and runs it in a scan,
//! which is the whole of the library-first promise for detections.
//!
//! The two refusal tests near the bottom drive the public compute seam directly
//! rather than a scan, because refusing a detection happens before a scan would
//! ever reach it.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::support::*;
use zond_engine::config::limits::CONNECT_CONCURRENCY;
use zond_engine::config::{DetectionEnvelope, ServiceDetection, ZondConfig};
use zond_engine::detect::Detections;
use zond_engine::detect::compute::{
    Capabilities, ComputeRuntime, Grant, LiveCapabilities, LoadError, ModuleBody, ModuleFault,
    RhaiRuntime, RunOutcome,
};
use zond_engine::detect::manifest::DetectionManifest;
use zond_engine::evasion::EvasionProfile;
use zond_engine::fingerprint::{PortContext, Tunnel};
use zond_engine::model::finding::{DetectionClass, Finding, Reference, Severity};
use zond_engine::model::host::Host;
use zond_engine::model::port::{Port, Protocol};
use zond_engine::report::ScanReport;
use zond_engine::scanner::session::ScanSession;
use zond_engine::scanner::strategy::connect::ConnectPortScanner;
use zond_engine::scanner::{detection, service};

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
    spawn_server(None, login_padding, RootPage::Plain).await
}

/// Stands a web server up whose *root page* names Grafana, which is what a real
/// Grafana does. The service pass identifies such a port as `grafana` rather
/// than `http`.
async fn spawn_grafana_server() -> Server {
    spawn_server(None, 0, RootPage::NamesGrafana).await
}

/// Stands a speak-first server up on an ephemeral port. It greets and answers
/// nothing, and keeps whatever was said to it.
async fn spawn_greeting_server(greeting: &'static [u8]) -> Server {
    spawn_server(Some(greeting), 0, RootPage::Plain).await
}

/// What the server's root page says about itself, which is what decides the
/// name the service pass puts on the port.
#[derive(Clone, Copy)]
enum RootPage {
    /// An unremarkable page naming no product: the port is identified as `http`.
    Plain,
    /// A page carrying the product's own name: the port is identified as
    /// `grafana`.
    NamesGrafana,
}

async fn spawn_server(
    greeting: Option<&'static [u8]>,
    login_padding: usize,
    root: RootPage,
) -> Server {
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
                    let _ = sock
                        .write_all(&web_reply(&request, login_padding, root))
                        .await;
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
fn web_reply(request: &str, login_padding: usize, root: RootPage) -> Vec<u8> {
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
        match root {
            RootPage::Plain => b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
                 <html><body>ok</body></html>\n"
                .to_vec(),
            RootPage::NamesGrafana => b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
                 <html><head><title>Grafana</title></head><body>ok</body></html>\n"
                .to_vec(),
        }
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

/// The test config with the detection envelope raised to permit an `exploit`.
///
/// The Grafana flow reads `/etc/passwd` off the target to confirm the CVE, which
/// is an exploit, so a default scan withholds it and a test that needs it to run
/// opts in the way an operator would.
fn exploit_config() -> ZondConfig {
    let mut cfg = test_config();
    cfg.detection = DetectionEnvelope::up_to(DetectionClass::Exploit);
    cfg
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
        &exploit_config(),
    )
    .await;

    let finding = finding(&outcome.report, server.port, "grafana-path-traversal")
        .expect("the grafana flow fired against the live port");

    assert_eq!(finding.severity(), Severity::Critical);
    assert_eq!(
        finding.title(),
        "Grafana is vulnerable to unauthenticated path traversal"
    );
    assert_eq!(finding.class(), DetectionClass::Exploit);
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

/// The gate fits the name the fingerprint corpus actually produces.
///
/// A real Grafana names itself on its root page, so the service pass calls the
/// port `grafana`, not `http`. A gate naming only `http` skipped every such
/// port, which is the whole detection silently not running against the software
/// it was written for. Both names are asserted here: the identification, so the
/// test cannot pass because the port was called `http` after all, and the
/// finding, so it cannot pass because the flow never ran.
#[tokio::test]
async fn a_flow_fires_against_the_service_name_its_own_fingerprint_produces() {
    if skip_when_privileged() {
        return;
    }

    let server = spawn_grafana_server().await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &exploit_config(),
    )
    .await;

    let scanned = port(&outcome.report, server.port).expect("the port was scanned");
    assert_eq!(
        scanned.service().map(|service| service.name()),
        Some("grafana"),
        "the corpus names a port that says Grafana for the product, not for http"
    );

    let finding = finding(&outcome.report, server.port, "grafana-path-traversal")
        .expect("the grafana flow fired against a port named grafana");
    assert_eq!(finding.severity(), Severity::Critical);
}

/// A Tier-2 module reaches a verdict over the response the service pass already
/// drew, and adds no traffic of its own.
///
/// Its severity is *computed* rather than declared, which is what earns the
/// tier: four of the four baseline headers absent is `medium`, one or two would
/// be `low`.
///
/// The phases are assembled here rather than taken from `scanner::scan`, which
/// is the second of the three altitudes the `scanner` module documents. It is
/// the raw path's arrangement, where discovery settles port state and a
/// separate `service::detect` names the service and keeps what it read. The
/// test at the bottom of this file runs the whole scan instead, which is the
/// unprivileged path fingerprinting inline.
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
    service::detect(&ctx, ServiceDetection::Probe, Protocol::Tcp).await;
    detection::detect(&ctx, ServiceDetection::Probe, DetectionEnvelope::default()).await;

    let host = session.hosts().get(LOOPBACK).expect("the loopback host");
    let finding = port_finding(&host, server.port, "http-missing-security-headers")
        .expect("the compute module fired over the gathered response");

    assert_eq!(finding.severity(), Severity::Medium);
    // The count, not the sentence around it. What earns the tier is that the
    // module counted four and graded on the number; the wording is report copy,
    // and pinning it here breaks this test on an edit that changes no behaviour,
    // which is how it came to assert a summary the module had stopped writing.
    assert!(
        finding.title().contains("4 of 4"),
        "the module should have counted all four headers absent, got {:?}",
        finding.title()
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

/// The generic HTTP detection has to reach a web application the corpus can put
/// a name to, and not only a web server it cannot.
///
/// The same module, the same scan shape, against a port the service pass
/// identifies as `grafana` rather than as `http`. Before the gate named the
/// protocol it named `http` alone, so this port, and every other product the
/// corpus recognises, went unexamined. The `http` case above is the control:
/// both must fire, or the gate has simply moved which half it misses.
#[tokio::test]
async fn the_http_module_reaches_a_web_application_the_corpus_names() {
    if skip_when_privileged() {
        return;
    }

    let server = spawn_grafana_server().await;
    let (session, ctx) = ScanSession::new();

    let mut scanner = ConnectPortScanner::new(
        ctx.clone(),
        CONNECT_CONCURRENCY,
        ServiceDetection::Off,
        &EvasionProfile::default(),
    );
    run_port_scanner(&mut scanner, vec![tcp(LOOPBACK, server.port)]).await;
    service::detect(&ctx, ServiceDetection::Probe, Protocol::Tcp).await;
    detection::detect(&ctx, ServiceDetection::Probe, DetectionEnvelope::default()).await;

    let host = session.hosts().get(LOOPBACK).expect("the loopback host");

    // The premise: this port is not called `http`. Without it the test could
    // pass because the identification failed rather than because the gate
    // widened.
    let port = host
        .ports()
        .find(|port| port.number() == server.port)
        .expect("the scanned port");
    assert_eq!(
        port.service().map(|service| service.name()),
        Some("grafana"),
        "the corpus names this port for its product, which is the whole premise"
    );

    port_finding(&host, server.port, "http-missing-security-headers")
        .expect("a detection gated on the protocol reaches a port named for its product");
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
    let outcome = run_scan(target_map(LOOPBACK, &spec), &exploit_config()).await;

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

    // The http-gated flow specifically, not every finding: a passive CVE
    // detection legitimately fires on the ssh banner's version.
    let flowed: Vec<&str> = ssh_port
        .findings()
        .map(|finding| finding.detection().id())
        .filter(|id| *id == "grafana-path-traversal")
        .collect();
    assert!(
        flowed.is_empty(),
        "an http-gated flow ran over an ssh port: {flowed:?}"
    );
}

/// The envelope decides what runs. An exploit above the default ceiling does not
/// reach the network, and raising the ceiling to it is what lets it.
///
/// Both sides, one server type, one scan shape: the only difference between the
/// halves is the ceiling, so the flow's absence is the envelope withholding the
/// class rather than the phase being off or the server being unreachable. It is
/// the guarantee a default scan makes: the Grafana flow reads a file off the
/// target, and nothing sends that probe until an operator opts in.
#[tokio::test]
async fn the_envelope_withholds_the_class_above_its_ceiling_and_serves_the_one_below() {
    if skip_when_privileged() {
        return;
    }

    // The default ceiling is active-benign, so the exploit-class Grafana flow is
    // withheld and never reaches the wire.
    let withheld = spawn_web_server(0).await;
    let outcome = run_scan(
        target_map(LOOPBACK, &withheld.port.to_string()),
        &test_config(),
    )
    .await;

    assert!(
        finding(&outcome.report, withheld.port, "grafana-path-traversal").is_none(),
        "an exploit-class flow ran under the default envelope"
    );
    assert!(
        !withheld.saw("/login"),
        "a withheld flow still put bytes on the wire"
    );

    // The same server and scan with the ceiling raised to exploit: the flow runs,
    // so what stopped it above was the envelope and nothing else.
    let permitted = spawn_web_server(0).await;
    let outcome = run_scan(
        target_map(LOOPBACK, &permitted.port.to_string()),
        &exploit_config(),
    )
    .await;

    assert!(
        finding(&outcome.report, permitted.port, "grafana-path-traversal").is_some(),
        "raising the ceiling to exploit did not let the flow run"
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
        &exploit_config(),
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

    // Parsed, not built: the authoring schema is `non_exhaustive`, and a parse also
    // reaches the manifest without the validation the builder applies, which is the
    // whole point here, a passive detection that asks to speak, one the build refuses.
    let manifest: DetectionManifest = toml::from_str(
        r#"
        id      = "misdeclared-passive"
        version = "1.0.0"
        title   = "Declares passive, asks to speak"
        [when]
        [capabilities]
        class      = "passive"
        speak      = "target"
        resolve    = true
        max_millis = 500
        "#,
    )
    .expect("the manifest parses");
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
    let mut caps = LiveCapabilities::new(addr, Protocol::Tcp, None, &grant.budget);
    let ctx = PortContext::new(addr.port(), Protocol::Tcp).with_addr(Some(addr));

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
/// The unprivileged path end to end, which is the one with no second
/// identification pass: the connect scanner fingerprints inline and carries the
/// responses out of that exchange itself, so a passive module reads them
/// without a byte being drawn twice. A raw scan reaches the same place through
/// `service::detect`, which is the arrangement
/// `a_compute_module_grades_the_response_the_scan_already_gathered` assembles.
#[tokio::test]
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

/// A caller-supplied detection runs in an ordinary scan, alongside the shipped
/// corpus, exactly as a first-party one does.
///
/// This is the whole of the library-first promise for detections: an embedder
/// writes a detection about their own software, passes it to the scan, and it runs
/// on the same seam and under the same envelope as the corpus this build ships,
/// without forking the crate. The scan finds the port, names it `http`, and the
/// caller's flow probes it and files what it concluded.
#[tokio::test]
async fn a_caller_supplied_detection_runs_in_a_scan() {
    if skip_when_privileged() {
        return;
    }

    const CALLER_FLOW: &str = r#"
        [detection]
        id      = "caller-http-check"
        version = "1.0.0"
        title   = "Caller HTTP check"
        [detection.when]
        service = "http"
        [detection.capabilities]
        class = "active-benign"
        speak = "target"
        [[step]]
        send        = "GET / HTTP/1.0\r\n\r\n"
        expect      = "HTTP/"
        on_no_match = "continue"
        [[step.finding]]
        when     = "matched"
        severity = "medium"
        summary  = "the caller's detection reached a web server"
    "#;

    let server = spawn_web_server(0).await;
    // The caller's flow is active-benign, so raise the ceiling past the passive
    // default, as an operator would.
    let mut cfg = test_config();
    cfg.detection = DetectionEnvelope::up_to(DetectionClass::ActiveBenign);
    let detections = Detections::builder()
        .flow(CALLER_FLOW, "caller-hash")
        .expect("the caller flow validates")
        .build();

    let outcome = run_scan_with(
        target_map(LOOPBACK, &server.port.to_string()),
        &cfg,
        detections,
    )
    .await;

    let caller = finding(&outcome.report, server.port, "caller-http-check")
        .expect("the caller's detection did not run");
    assert_eq!(caller.severity(), Severity::Medium);
    assert_eq!(
        caller.detection().content_hash(),
        "caller-hash",
        "the caller's provenance was not carried onto the finding"
    );

    // The shipped corpus still ran beside it: the missing-headers module fired too.
    assert!(
        finding(
            &outcome.report,
            server.port,
            "http-missing-security-headers"
        )
        .is_some(),
        "setting a caller corpus dropped the shipped detections"
    );
}

/// A detection speaks to a service that answered inside TLS, and reads the reply
/// in the clear.
///
/// The P0 that makes the web corpus possible: an `ssl/*` port is reached through
/// a handshake, not written to as plaintext. A loopback rustls server stands in
/// for the HTTPS service, holding an ephemeral self-signed certificate the
/// detection's accept-any client takes without a trust decision, the same as a
/// scan does against a live endpoint. The client is [`LiveCapabilities`] with the
/// TLS tunnel the scanner derives from the `ssl/` service label, so the path
/// under test is the one a real compute module runs.
#[test]
fn a_detection_speaks_through_tls_to_a_service_that_answered_inside_it() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    // A throwaway certificate, minted for this run so no key material is committed.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("a self-signed certificate");
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let server_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports the default versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![cert_der],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
    )
    .expect("a server config from the generated key");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback listener");
    let addr = listener.local_addr().expect("the listener's address");

    // The service: complete the handshake, read the probe, answer it. `PONG` back
    // proves the bytes crossed the tunnel decrypted in both directions.
    let config = std::sync::Arc::new(server_config);
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("an inbound connection");
        let mut conn = rustls::ServerConnection::new(config).expect("a server connection");
        let mut tls = rustls::Stream::new(&mut conn, &mut socket);
        let mut probe = [0u8; 4];
        tls.read_exact(&mut probe)
            .expect("the probe arrives through TLS");
        assert_eq!(&probe, b"PING", "the server read the decrypted probe");
        tls.write_all(b"PONG")
            .expect("the reply is written through TLS");
        tls.flush().expect("the reply is flushed");
    });

    // The client: the same capability a compute module holds, handed the TLS
    // tunnel the scanner derives from an `ssl/*` label.
    let manifest: DetectionManifest = toml::from_str(
        r#"
        id = "tls-speak"
        version = "1.0.0"
        title = "tls speak"
        [when]
        service = "http"
        [capabilities]
        class = "active-benign"
        speak = "target"
        max_bytes = 8192
        max_millis = 2000
        max_connections = 2
        "#,
    )
    .expect("the manifest parses");
    let grant = Grant::from_manifest(&manifest, &"0".repeat(64)).expect("the manifest resolves");

    let mut caps = LiveCapabilities::new(addr, Protocol::Tcp, Some(Tunnel::Tls), &grant.budget);
    let reply = caps
        .speak(b"PING")
        .expect("the exchange completes through the tunnel");

    assert_eq!(reply, b"PONG", "the reply came back decrypted");
    server.join().expect("the server thread finished cleanly");
}

/// The Tier-1 counterpart of the test above: a caller outside the crate running
/// one flow against one port, without a scan.
///
/// [`flow::run`] takes a [`Probe`](zond_engine::detect::flow::Probe), and until
/// [`SocketProbe`] was published the crate shipped no way to satisfy it against a
/// real socket. This is the loop that made publishing it worth doing: write a
/// detection, [`check`](zond_engine::detect::flow::check) it, run it, read what
/// it found.
#[test]
fn a_caller_runs_one_flow_against_one_port_without_a_scan() {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;
    use zond_engine::detect::compute::Budget;
    use zond_engine::detect::flow::schema::FlowDetection;
    use zond_engine::detect::flow::{self, FlowSeed, SocketProbe};

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback listener");
    let addr = listener.local_addr().expect("the listener's address");

    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("an inbound connection");
        let _ = socket.read(&mut [0u8; 64]);
        socket
            .write_all(b"# Server\r\nredis_version:7.2.4\r\n")
            .expect("the reply is written");
    });

    // A detection written here rather than taken from the corpus, which is the
    // case that matters: a caller's own, run the moment it was written.
    let source = r#"
        [detection]
        id      = "redis-version"
        version = "1.0.0"
        title   = "Redis reports its version"

        [detection.when]
        service  = "redis"
        protocol = "tcp"

        [detection.capabilities]
        class            = "active-benign"
        speak            = "target"
        max_bytes        = 4096
        max_millis       = 2000
        max_connections  = 1

        [[step]]
        send   = "INFO server\r\n"
        expect = ["redis_version:[0-9.]+"]
        bind   = { version = "redis_version:(?<version>[0-9.]+)" }
          [[step.finding]]
          when     = "matched"
          severity = "info"
          summary  = "Redis named its own version, {version}"
          detail   = "The server answered INFO with a version string."
    "#;

    let detection: FlowDetection = toml::from_str(source).expect("the detection parses");
    assert!(
        flow::check(&detection).is_empty(),
        "the detection is structurally valid"
    );

    let budget = Budget::new(0, Duration::from_secs(2))
        .with_max_bytes(4096)
        .with_max_connections(1);
    let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget);

    let seed = FlowSeed::new(addr.ip().to_string(), addr.port());
    let findings = flow::run(&detection, "redis", &seed, &mut probe);

    server.join().expect("the server thread finished cleanly");

    assert_eq!(findings.len(), 1, "the flow matched the reply it drew");
    assert!(
        findings[0].title().contains("7.2.4"),
        "the version the reply named reached the finding: {}",
        findings[0].title()
    );
}
