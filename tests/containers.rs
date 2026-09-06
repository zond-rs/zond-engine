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
//! Needs Docker and pulls images, so both passes are `#[ignore]`d.
//!
//! ```text
//! cargo test --test containers -- --ignored --test-threads=1
//! cargo test --test containers -- --ignored --test-threads=1 --nocapture report
//! ```
//!
//! The first asserts the manifest. The second asserts nothing and prints what
//! each target yields, which is how an expectation is written and how a stale
//! corpus digest is found.

mod common;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::time::{Duration, Instant};

use common::*;
use serde::Deserialize;

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

#[derive(Debug, Deserialize)]
struct Target {
    /// What this entry is called in a failure message.
    name: String,
    /// The image, pinned to a tag.
    image: String,
    /// The port the application listens on inside the container.
    port: u16,
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
        "/tests/containers.toml"
    ))
    .expect("the manifest is beside this file");
    toml::from_str(&text).expect("the manifest parses")
}

// ---------------------------------------------------------------------------
// Docker
// ---------------------------------------------------------------------------

/// A running container, removed when this is dropped.
///
/// The guard is the whole point: a panicking assertion must not leave a
/// container bound to a port, or the next run measures the last one's software.
struct Container {
    id: String,
    addr: SocketAddr,
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).output();
    }
}

/// Whether Docker is present and answering.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .is_ok_and(|out| out.status.success())
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

/// Starts `target` on a free loopback port and waits for it to answer.
///
/// Bound to `127.0.0.1` explicitly rather than to every interface: this starts
/// real, unconfigured, often unauthenticated software, and it has no business
/// being reachable from the network while a test runs.
fn start(target: &Target) -> Result<Container, String> {
    let host_port = free_port();
    let out = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "-p",
            &format!("127.0.0.1:{host_port}:{}", target.port),
            &target.image,
        ])
        .output()
        .map_err(|e| format!("docker run failed: {e}"))?;

    if !out.status.success() {
        return Err(format!(
            "docker run {}: {}",
            target.image,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    let container = Container {
        id: String::from_utf8_lossy(&out.stdout).trim().to_string(),
        addr: SocketAddr::new(LOOPBACK, host_port),
    };

    match wait_until_ready(container.addr) {
        true => Ok(container),
        // The guard still removes it; returning the error rather than panicking
        // keeps a slow pull separate from a wrong verdict.
        false => Err(format!(
            "{} never answered on {} within {READY_TIMEOUT:?}",
            target.name, container.addr
        )),
    }
}

/// Polls until the application answers a request, or the budget runs out.
///
/// Accepting a connection is not the same as serving one, and the difference is
/// not a detail: Jellyfin and Grafana both bind their port seconds before they
/// answer anything, and a scan run in that window reports a port that is open and
/// says nothing. Read as an identification failure, which is exactly how it first
/// read here, that is a harness defect wearing a corpus defect's clothes.
///
/// So readiness is a real request drawing a real reply.
fn wait_until_ready(addr: SocketAddr) -> bool {
    use std::io::{Read, Write};

    let deadline = Instant::now() + READY_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(mut stream) = std::net::TcpStream::connect_timeout(&addr, POLL_INTERVAL) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            let mut reply = [0u8; 16];
            if stream.write_all(request).is_ok()
                && stream.read(&mut reply).is_ok_and(|read| read > 0)
            {
                return true;
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    false
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
async fn scan(addr: SocketAddr) -> Verdict {
    let cfg = test_config();
    let outcome = run_scan(target_map(addr.ip(), &addr.port().to_string()), &cfg).await;

    let Some(host) = outcome.host(addr.ip()) else {
        return Verdict::default();
    };
    let Some(service) = host
        .ports()
        .find(|port| port.number() == addr.port())
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
#[ignore = "needs Docker and pulls images; run with --ignored"]
async fn every_target_is_identified_as_its_manifest_says() {
    if !docker_available() {
        eprintln!("skipped: Docker is not available");
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

        let found = scan(container.addr).await;
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
#[ignore = "needs Docker and pulls images; run with --ignored"]
async fn report() {
    if !docker_available() {
        eprintln!("skipped: Docker is not available");
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

        let found = scan(container.addr).await;
        let digest = zond_engine::fingerprint::favicon_digest(container.addr).await;

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
            None => println!("             icon    none served"),
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
