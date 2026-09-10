// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Tier 4: real software, in containers
//!
//! Every other tier proves the engine is consistent with itself: a signature
//! matches the example beside it, a parser returns on any bytes, a simulated
//! network answers the way a stack would. None of it asks a real application
//! what it serves, so all of it can pass while the engine identifies nothing.
//!
//! This tier starts the real thing from a pinned image, scans it through
//! `scanner::scan`, and holds the verdict to `containers.toml`. Going through
//! the public API is the point: reaching into the analyzers would test the parts
//! and leave the wiring between them, which is where the defects live.
//!
//! Needs a container runtime and pulls images, so both passes are `#[ignore]`d.
//!
//! ```text
//! cargo test --test containers -- --ignored --test-threads=1
//! cargo test --test containers -- --ignored --test-threads=1 --nocapture report
//! ```
//!
//! The first asserts the manifest. The second asserts nothing and prints what
//! each target yields, which is how an expectation is written and how a stale
//! corpus digest is found.

#[path = "../support/mod.rs"]
mod support;

mod runtime;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::runtime::Runtime;
use crate::support::*;
use serde::Deserialize;
use zond_engine::fingerprint::SignatureDb;
use zond_engine::model::port::Protocol;

/// How long an image may take to pull and a server to answer.
///
/// Generous, because the first run of a target pulls it. A container that has not
/// answered by then is reported as unready rather than scanned, so a slow pull
/// reads as what it is instead of as an identification failure.
const READY_TIMEOUT: Duration = Duration::from_secs(180);

/// How often to ask whether it is up yet.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// ---------------------------------------------------------------------------
// The manifest
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Manifest {
    target: Vec<Target>,
}

/// Which transport a target is reached over.
///
/// TCP unless the manifest says otherwise, because that is what almost every
/// entry is and stating it on each would be noise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Transport {
    #[default]
    Tcp,
    Udp,
}

impl Transport {
    /// The engine's own name for this transport.
    fn protocol(self) -> Protocol {
        match self {
            Transport::Tcp => Protocol::Tcp,
            Transport::Udp => Protocol::Udp,
        }
    }

    /// How `-p` spells it on the runtime's command line.
    fn suffix(self) -> &'static str {
        match self {
            Transport::Tcp => "",
            Transport::Udp => "/udp",
        }
    }

    /// How a port is written in a scan's port specification.
    fn port_spec(self, port: u16) -> String {
        match self {
            Transport::Tcp => port.to_string(),
            Transport::Udp => format!("U:{port}"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Target {
    /// What this entry is called in a failure message.
    name: String,
    /// The image, pinned to a tag.
    image: String,
    /// The port the application listens on inside the container.
    port: u16,
    /// The transport it listens on. TCP unless stated.
    #[serde(default)]
    protocol: Transport,
    /// The port to publish it on, where the scan has to reach it on its
    /// registered number.
    ///
    /// A target is otherwise published on whatever port is free, which is right
    /// for anything the generic probe identifies and wrong for everything else:
    /// the corpus keys its probes on the port, so an LDAP server on a random
    /// high port is asked for a web page and says nothing. Pinning one risks a
    /// collision with whatever the developer is already running, which is why it
    /// is stated only where it is needed.
    ///
    /// A UDP target never gets the choice, and does not have to state it.
    /// TCP has the generic HTTP probe behind it, so a web application on a
    /// random port is still asked something it can answer; UDP has no such
    /// fallback, and a datagram service on a port the corpus registers no probe
    /// for is sent nothing at all and reports as `open|filtered`. So a UDP
    /// target is published on its own number, and a collision there is a runtime
    /// error the run prints rather than a silent identification failure.
    host_port: Option<u16>,
    /// What the engine should make of it. Absent means report-only, which is how
    /// a target is added before anybody has agreed what it should say.
    expect: Option<Expect>,
}

/// What a target's verdict must carry. A field left out is not checked.
#[derive(Debug, Default, Deserialize)]
struct Expect {
    service: Option<String>,
    product: Option<String>,
    vendor: Option<String>,
    version: Option<String>,
    extrainfo: Option<String>,
    /// Asserts that nothing is named, for software the corpus cannot identify
    /// yet. Pinned so that the day it can, this fails and somebody writes the
    /// expectation down.
    #[serde(default)]
    unidentified: bool,
}

fn manifest() -> Manifest {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/containers.toml"
    ))
    .expect("the manifest is beside this file");
    toml::from_str(&text).expect("the manifest parses")
}

// ---------------------------------------------------------------------------
// The runtime
// ---------------------------------------------------------------------------

/// A running container, removed when this is dropped.
///
/// The guard is the whole point: a panicking assertion must not leave a
/// container bound to a port, or the next run measures the last one's software.
struct Container {
    id: String,
    addr: SocketAddr,
    protocol: Transport,
}

impl Drop for Container {
    fn drop(&mut self) {
        if let Some(runtime) = Runtime::detect() {
            let _ = runtime.command().args(["rm", "-f", &self.id]).output();
        }
    }
}

/// Whether a container runtime is present and answering.
fn runtime_available() -> bool {
    Runtime::detect().is_some()
}

/// A port nothing is listening on, by asking the OS for one and letting it go.
///
/// Racy in principle and fine in practice: the window is microseconds and the
/// alternative is a fixed port that collides with whatever the developer is
/// already running.
fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("the OS has a spare port")
        .local_addr()
        .expect("a bound listener has an address")
        .port()
}

/// Which host port to publish `target` on: its own number over UDP, a free one
/// otherwise. See [`Target::host_port`] for why UDP has no choice.
fn publish_on(target: &Target) -> u16 {
    target.host_port.unwrap_or_else(|| match target.protocol {
        Transport::Udp => target.port,
        Transport::Tcp => free_port(),
    })
}

/// Starts `target` on a free loopback port and waits for it to answer.
///
/// Bound to `127.0.0.1` explicitly rather than to every interface: this starts
/// real, unconfigured, often unauthenticated software, and it has no business
/// being reachable from the network while a test runs.
fn start(target: &Target) -> Result<Container, String> {
    let host_port = publish_on(target);
    let runtime = Runtime::detect().ok_or("no container runtime is available")?;
    let out = runtime
        .command()
        .args([
            "run",
            "-d",
            "--rm",
            "-p",
            &format!(
                "127.0.0.1:{host_port}:{}{}",
                target.port,
                target.protocol.suffix()
            ),
            &Runtime::qualify(&target.image),
        ])
        .output()
        .map_err(|e| format!("{} run failed: {e}", runtime.binary()))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // A UDP target cannot be moved out of the way, so say that here rather
        // than leaving a reader to try the obvious fix. Publishing it somewhere
        // free is what breaks it: the corpus keys the probe on the number.
        let hint = match target.protocol == Transport::Udp && stderr.contains("already allocated") {
            true => format!(
                "\n    {} must be published on {} itself, so this needs whatever holds                  that port stopped. Ports below 1024 are often taken on a developer                  machine; a UDP entry on a high port does not run into this.",
                target.name, host_port
            ),
            false => runtime.privileged_port_hint(host_port, &stderr),
        };
        return Err(format!(
            "{} run {}: {}{hint}",
            runtime.binary(),
            target.image,
            stderr.trim()
        ));
    }

    let container = Container {
        id: String::from_utf8_lossy(&out.stdout).trim().to_string(),
        addr: SocketAddr::new(LOOPBACK, host_port),
        protocol: target.protocol,
    };

    match wait_until_ready(container.addr, target.protocol) {
        true => Ok(container),
        // The guard still removes it; returning the error rather than panicking
        // keeps a slow pull separate from a wrong verdict.
        false => Err(format!(
            "{} never answered on {} within {READY_TIMEOUT:?}",
            target.name, container.addr
        )),
    }
}

/// Waits until the application is serving, or the budget runs out.
///
/// Two signals, because neither alone covers what is in the manifest. Accepting a
/// connection is not serving: Jellyfin and Grafana bind their port seconds before
/// they answer anything, and a scan run in that window reports a port that is
/// open and says nothing, which reads exactly like an identification failure. But
/// answering an HTTP request is not general either: a directory server accepts
/// and serves immediately and will never reply to `GET /`, so holding it to that
/// reported it as never having started at all.
///
/// So an HTTP reply means ready at once, and a port that merely keeps accepting
/// is given [`SETTLE`] to start serving whatever it does speak before being
/// taken at its word.
fn wait_until_ready(addr: SocketAddr, protocol: Transport) -> bool {
    if protocol == Transport::Udp {
        return wait_until_answering_udp(addr);
    }

    let deadline = Instant::now() + READY_TIMEOUT;
    let mut accepting_since = None;

    while Instant::now() < deadline {
        match std::net::TcpStream::connect_timeout(&addr, POLL_INTERVAL) {
            Ok(stream) => {
                if answers_http(stream) {
                    return true;
                }
                let since = *accepting_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= SETTLE {
                    return true;
                }
            }
            // Not up yet, and any earlier run of accepts did not mean what it
            // looked like.
            Err(_) => accepting_since = None,
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    false
}

/// How long a port that accepts but speaks no HTTP is given to start serving.
const SETTLE: Duration = Duration::from_secs(2);

/// Waits until a UDP service answers the probe the corpus registers for it.
///
/// None of the TCP signals exist here. There is no handshake, so nothing
/// accepts; a datagram sent into a container that has not bound its socket yet
/// is discarded in silence, which is the same silence a bound-but-unready
/// service returns. The only evidence a UDP service is up is that it answered
/// something, so this asks it the question the scan will ask and waits for a
/// reply.
///
/// Asking with the corpus's own payload rather than an empty datagram is the
/// whole point: an application handed zero bytes almost always discards them
/// without a word, so a readiness check built on one would time out against a
/// perfectly healthy container and report it as never having started.
///
/// A port the corpus has no probe for is refused outright rather than waited
/// on. The scan would send that port nothing either, so the entry could only
/// ever fail, and it should fail saying why.
fn wait_until_answering_udp(addr: SocketAddr) -> bool {
    let Some(payload) = SignatureDb::global()
        .udp_probe_payloads(addr.port())
        .first()
        .cloned()
    else {
        eprintln!(
            "  the corpus registers no UDP probe for {}, so nothing would be sent",
            addr.port()
        );
        return false;
    };

    let deadline = Instant::now() + READY_TIMEOUT;
    while Instant::now() < deadline {
        if udp_answers(addr, &payload) {
            return true;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    false
}

/// One datagram out, one reply in, or `false`. Bound to an ephemeral loopback
/// port and connected, so the kernel drops anything from another address.
fn udp_answers(addr: SocketAddr, payload: &[u8]) -> bool {
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) else {
        return false;
    };
    if socket.connect(addr).is_err() || socket.set_read_timeout(Some(POLL_INTERVAL)).is_err() {
        return false;
    }
    let mut reply = [0u8; 2048];
    socket.send(payload).is_ok() && socket.recv(&mut reply).is_ok_and(|read| read > 0)
}

/// Whether the peer answers an HTTP request, which is the fast path for the web
/// applications that make up most of the manifest.
fn answers_http(mut stream: std::net::TcpStream) -> bool {
    use std::io::{Read, Write};

    if stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .is_err()
    {
        return false;
    }
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let mut reply = [0u8; 16];
    stream.write_all(request).is_ok() && stream.read(&mut reply).is_ok_and(|read| read > 0)
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// What a scan of one container concluded, in the terms the manifest states.
#[derive(Debug, Default)]
struct Verdict {
    service: Option<String>,
    product: Option<String>,
    vendor: Option<String>,
    version: Option<String>,
    extrainfo: Option<String>,
    cpes: Vec<String>,
}

impl Verdict {
    fn is_empty(&self) -> bool {
        self.product.is_none() && self.vendor.is_none()
    }

    /// Whether the scan named HTTP as what answers this port.
    fn speaks_http(&self) -> bool {
        self.service
            .as_deref()
            .is_some_and(|service| service == "http" || service == "https")
    }

    /// A line for the report, and for a failure message.
    fn summary(&self) -> String {
        let mut parts = Vec::new();
        for (label, value) in [
            ("service", &self.service),
            ("product", &self.product),
            ("vendor", &self.vendor),
            ("version", &self.version),
            ("extrainfo", &self.extrainfo),
        ] {
            if let Some(value) = value {
                parts.push(format!("{label}={value:?}"));
            }
        }
        if !self.cpes.is_empty() {
            parts.push(format!("cpe={:?}", self.cpes));
        }
        match parts.is_empty() {
            true => "nothing identified".to_string(),
            false => parts.join(" "),
        }
    }
}

/// Scans one container through the public API and reads the verdict off the port.
async fn scan(addr: SocketAddr, protocol: Transport) -> Verdict {
    let cfg = test_config();
    let spec = protocol.port_spec(addr.port());
    let outcome = run_scan(target_map(addr.ip(), &spec), &cfg).await;

    let Some(host) = outcome.host(addr.ip()) else {
        return Verdict::default();
    };
    // Matched on the transport as well as the number, because a host may hold
    // both: 137 is a name service over UDP and something else entirely over TCP,
    // and a verdict read off the wrong one would be attributed to this target.
    let Some(service) = host
        .ports()
        .find(|port| port.number() == addr.port() && port.protocol() == protocol.protocol())
        .and_then(|port| port.service())
    else {
        return Verdict::default();
    };

    Verdict {
        service: Some(service.name().to_string()),
        product: service.product().map(str::to_string),
        vendor: service.vendor().map(str::to_string),
        version: service.version().map(str::to_string),
        extrainfo: service.extrainfo().map(str::to_string),
        cpes: service.cpes().iter().map(|cpe| cpe.to_string()).collect(),
    }
}

/// Where the manifest and the verdict disagree, in the order the manifest states
/// its fields. Empty when they agree.
fn disagreements(expect: &Expect, found: &Verdict) -> Vec<String> {
    let mut out = Vec::new();

    if expect.unidentified && !found.is_empty() {
        out.push(format!(
            "expected nothing to be named, got {}",
            found.summary()
        ));
        return out;
    }

    for (label, wanted, got) in [
        ("service", &expect.service, &found.service),
        ("product", &expect.product, &found.product),
        ("vendor", &expect.vendor, &found.vendor),
        ("version", &expect.version, &found.version),
        ("extrainfo", &expect.extrainfo, &found.extrainfo),
    ] {
        let Some(wanted) = wanted else { continue };
        if got.as_deref() != Some(wanted.as_str()) {
            out.push(format!("{label}: expected {wanted:?}, got {got:?}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The tiers' two passes
// ---------------------------------------------------------------------------

/// Every target the manifest states an expectation for is identified as it says.
///
/// One container at a time, because several of these are memory-hungry and a
/// developer machine running five at once is measuring its own scheduler.
#[tokio::test]
#[ignore = "needs a container runtime and pulls images; run with --ignored"]
async fn every_target_is_identified_as_its_manifest_says() {
    if !runtime_available() {
        eprintln!("skipped: no container runtime is available");
        return;
    }

    let manifest = manifest();
    let mut failures: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut checked = 0;

    for target in &manifest.target {
        let Some(expect) = &target.expect else {
            eprintln!(
                "  {} has no expectation yet; see the report pass",
                target.name
            );
            continue;
        };

        let container = match start(target) {
            Ok(container) => container,
            Err(why) => {
                failures.insert(target.name.clone(), vec![why]);
                continue;
            }
        };

        let found = scan(container.addr, container.protocol).await;
        let against = disagreements(expect, &found);
        checked += 1;

        match against.is_empty() {
            true => eprintln!("  ok   {:<12} {}", target.name, found.summary()),
            false => {
                eprintln!("  FAIL {:<12} {}", target.name, found.summary());
                failures.insert(target.name.clone(), against);
            }
        }
    }

    assert!(
        checked > 0,
        "no target could be started, so this asserted nothing"
    );
    assert!(
        failures.is_empty(),
        "{} of {checked} targets disagree with the manifest:\n{}",
        failures.len(),
        failures
            .iter()
            .map(|(name, why)| format!("  {name}:\n    {}", why.join("\n    ")))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Prints what every target yields, asserting nothing.
///
/// Two jobs. It is how an expectation is written for a new entry, and it is how a
/// corpus hash is found to have gone stale: the digest printed here is the one a
/// scan computes, so a product that is not identified and whose digest is absent
/// from the corpus is a rule waiting to be written rather than a defect.
#[tokio::test]
#[ignore = "needs a container runtime and pulls images; run with --ignored"]
async fn report() {
    if !runtime_available() {
        eprintln!("skipped: no container runtime is available");
        return;
    }

    for target in &manifest().target {
        let container = match start(target) {
            Ok(container) => container,
            Err(why) => {
                println!("{:<12} could not start: {why}", target.name);
                continue;
            }
        };

        let found = scan(container.addr, container.protocol).await;
        // A favicon is fetched over HTTP, so it is worth asking for only where
        // the scan just said HTTP is what answers. Transport is the wrong
        // question: `openldap` is TCP and speaks a directory protocol, and
        // asking it for a page costs the whole fetch budget to learn nothing.
        // This is the same gate `Favicon::interested` applies.
        let digest = match found.speaks_http() {
            true => zond_engine::fingerprint::favicon_digest(container.addr).await,
            false => None,
        };

        println!("{:<12} {}", target.name, found.summary());
        match digest {
            Some(digest) => {
                let known = corpus_holds(&digest);
                println!(
                    "             icon md5 {digest} ({})",
                    match known {
                        true => "in the corpus",
                        false => "NOT in the corpus",
                    }
                );
            }
            None if found.speaks_http() => println!("             icon    none served"),
            None => println!(
                "             icon    not asked, {}",
                match found.service.as_deref() {
                    Some(service) => format!("service is {service}"),
                    None => "no service was named".to_string(),
                }
            ),
        }
    }
}

/// Whether any shipped signature is written against this digest.
///
/// Read from the asset tree rather than from the compiled database, because the
/// question is what somebody would have to edit, and the answer is a file.
fn corpus_holds(digest: &str) -> bool {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/fingerprinting");
    fn walk(dir: &std::path::Path, needle: &str) -> bool {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if walk(&path, needle) {
                    return true;
                }
            } else if path.extension().is_some_and(|e| e == "toml")
                && std::fs::read_to_string(&path).is_ok_and(|text| text.contains(needle))
            {
                return true;
            }
        }
        false
    }
    walk(std::path::Path::new(root), digest)
}

/// The manifest is data the other two read, so a mistake in it should not read as
/// a defect in the engine. Costs nothing and needs no Docker.
#[test]
fn the_manifest_is_well_formed() {
    let manifest = manifest();
    assert!(!manifest.target.is_empty(), "the manifest names no target");

    let mut names = std::collections::BTreeSet::new();
    let mut names_a_second_time = std::collections::BTreeSet::new();
    for target in &manifest.target {
        assert!(
            names.insert(target.name.clone()),
            "two targets are called {:?}",
            target.name
        );
        assert!(
            target.image.contains(':'),
            "{}: the image is not pinned to a tag, so a run is not repeatable",
            target.name
        );
        if let Some(port) = target.host_port {
            assert!(
                names_a_second_time.insert(port),
                "{}: two targets are published on port {port}",
                target.name
            );
        }
        if let Some(expect) = &target.expect {
            let states_a_field = [
                &expect.service,
                &expect.product,
                &expect.vendor,
                &expect.version,
                &expect.extrainfo,
            ]
            .iter()
            .any(|field| field.is_some());
            assert!(
                expect.unidentified != states_a_field,
                "{}: an expectation either names fields or says nothing is named",
                target.name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// What the manifest means, without Docker
// ---------------------------------------------------------------------------

/// The rules a UDP entry is published and scanned under, checked directly.
///
/// These run everywhere, unlike the two passes above. The transport decides
/// three separate things: how the port is published, which number it is
/// published on, and how the scan asks for it. Each is a place a UDP entry could
/// be silently scanned as TCP. That failure would not look like a failure:
/// the container would start, the scan would find nothing, and the entry would
/// read as software the corpus cannot identify.
#[test]
fn a_udp_target_is_published_and_scanned_over_udp() {
    let manifest: Manifest = toml::from_str(
        r#"
        [[target]]
        name = "tcp-by-default"
        image = "example/one:1.0"
        port = 8080

        [[target]]
        name = "over-udp"
        image = "example/two:2.0"
        port = 1900
        protocol = "udp"
        "#,
    )
    .expect("the manifest parses");

    let [tcp, udp] = &manifest.target[..] else {
        panic!("two targets");
    };

    assert_eq!(tcp.protocol, Transport::Tcp, "TCP unless stated");
    assert_eq!(udp.protocol, Transport::Udp);

    assert_eq!(
        udp.protocol.suffix(),
        "/udp",
        "the runtime publishes it as UDP"
    );
    assert_eq!(tcp.protocol.suffix(), "");

    assert_eq!(
        publish_on(udp),
        1900,
        "a UDP target keeps its own number, or the corpus sends it no probe"
    );
    assert_ne!(
        publish_on(tcp),
        8080,
        "a TCP target takes a free port, so a developer's own 8080 is left alone"
    );

    assert_eq!(udp.protocol.port_spec(1900), "U:1900");
    assert_eq!(tcp.protocol.port_spec(8080), "8080");
}

/// A stated `host_port` still wins over the UDP default, so an entry that has to
/// avoid a collision can say so.
#[test]
fn a_stated_host_port_wins() {
    let manifest: Manifest = toml::from_str(
        r#"
        [[target]]
        name = "pinned"
        image = "example/three:3.0"
        port = 1900
        protocol = "udp"
        host_port = 11900
        "#,
    )
    .expect("parses");
    assert_eq!(publish_on(&manifest.target[0]), 11900);
}

/// Every UDP entry names a port the corpus has a probe for.
///
/// Without one the scan sends nothing, the container answers nothing, and the
/// entry fails for a reason that has nothing to do with the software it started.
/// Caught here, where it costs no image pull, rather than three minutes into a
/// run.
#[test]
fn every_udp_target_names_a_port_the_corpus_probes() {
    for target in &manifest().target {
        if target.protocol != Transport::Udp {
            continue;
        }
        assert!(
            !SignatureDb::global()
                .udp_probe_payloads(target.port)
                .is_empty(),
            "{} is scanned over UDP on {}, which the corpus registers no probe for",
            target.name,
            target.port
        );
    }
}
