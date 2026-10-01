// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Running a flow
//!
//! Walks a [`FlowDetection`]'s steps once, front to back, exchanging bytes with
//! a [`Probe`], matching replies, binding variables, and emitting
//! [`Finding`]s. With a bounded probe count and no jumps, it needs no fuel
//! meter.
//!
//! ## The variable environment is forward-only
//!
//! A step sees what earlier steps bound. A `for_each` step runs each item in an
//! environment of its own, so one iteration's binds do not leak into the next.
//!
//! ## Guards decide the branches
//!
//! Both kinds of `when` are written in the [guard grammar](super::expr) and
//! answered by [`eval`]. A step's `when` is checked against the environment
//! before the step runs; false skips it. A finding's `when` also sees its
//! step's match result. An absent guard always holds; an unparseable one never
//! does.

use std::net::IpAddr;

use crate::detect::patterns;
use crate::fingerprint::{MAX_COMPILED_REGEX_BYTES, pattern, unescape};
use crate::model::confidence::Confidence;
use crate::model::finding::{DetectionId, Excerpt, Finding, Version};
use crate::model::ip::Exposure;
use crate::record::wire;

use crate::detect::manifest::GroupSpec;

use super::schema::{FindingSpec, FlowDetection, MatchSpec, OnNoMatch, Step};
use super::schema::{MAX_FLOW_STEPS, MAX_LOOP_ITEMS, SEED_VAR_HOST, SEED_VAR_PORT};
use super::{Env, eval};

/// Why an exchange was refused before it happened: a declared budget spent, or
/// no socket left to give. Kept apart from a silent port in reports.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeRefusal {
    /// The byte budget across the flow's exchanges is spent.
    Bytes,
    /// The connection budget is spent.
    Connections,
    /// The wall-clock budget is spent.
    Deadline,
    /// The process had no file descriptor for the exchange's socket within the
    /// flow's time. Raise the process's descriptor limit.
    Descriptors,
    /// The scan stopped, or the host's time ran out, while the exchange waited
    /// for its pacing slot, so nothing was sent.
    Withheld,
}

/// The one capability a flow reaches the world through: send bytes to the scanned
/// socket and read its reply. A test supplies a canned one; a scan supplies the
/// real socket.
///
/// [`Send`], because a port's flows run several at a time, each with its own
/// probe.
pub trait Probe: Send {
    /// Sends `bytes` and returns the reply, or [`None`] if the socket said
    /// nothing.
    fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>>;

    /// Whether the most recent [`speak`](Self::speak) reply was read to a clean,
    /// self-terminating end (a TCP close or a UDP datagram) and not cut short by
    /// a budget. Only a complete reply is shared between flows. Defaults to
    /// `true`.
    fn reply_complete(&self) -> bool {
        true
    }

    /// Told, before a flow's first exchange, the most exchanges the flow will
    /// make: one for each step that sends, and one per item for a `for_each`.
    ///
    /// Over UDP no reply is often the answer, so a probe that waits on silence
    /// can share the flow's time among the exchanges. An upper bound: a step
    /// whose guard is false sends nothing. The default ignores it.
    fn plan(&mut self, exchanges: u32) {
        let _ = exchanges;
    }

    /// The pattern marking where the next [`speak`](Self::speak)'s reply ends,
    /// or [`None`] to let it end at a close or the port falling silent.
    ///
    /// For a service that greets and then pauses before answering a pipelined
    /// command, such as an FTP server delaying a failed login: the read waits
    /// through the pause for this line. Set before each `speak`; the default
    /// ignores it.
    fn reads_until(&mut self, pattern: Option<&str>) {
        let _ = pattern;
    }

    /// Why the most recent [`speak`](Self::speak) returned [`None`], if it was
    /// refused. [`None`] for a silent port, and by default.
    fn last_refusal(&self) -> Option<ProbeRefusal> {
        None
    }
}

/// Whether the flow should keep running after a step.
#[derive(PartialEq, Eq)]
enum Flow {
    Continue,
    Halt,
}

/// The port under probe, seeded into the environment as `host` and `port`
/// before the first step, for a flow to name in a `send` or a `{var}`.
///
/// `host` is the address the scan connected to, so a flow cannot address a
/// machine the scan never looked at. A scan sends a `Host` naming that address,
/// or `localhost`, as the name the target was reached by, since a server
/// routing by name would otherwise answer with the wrong site.
///
/// Both are fixed for the endpoint, so matching stays a pure function of the
/// replies. A `bind` may shadow either name.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct FlowSeed {
    /// The address the flow reached, seeded as `{host}`: the scanned IP as
    /// text, whatever name a target reached it by.
    pub host: String,
    /// The port the flow reached it on, seeded as `{port}`.
    pub port: u16,
    /// Who else can reach [`host`](Self::host), which a per-rung severity is
    /// graded against. Derived from `host` by [`new`](Self::new), so the two
    /// cannot disagree.
    pub exposure: Exposure,
}

impl FlowSeed {
    /// A seed for the endpoint at `host` on `port`.
    ///
    /// `host` is an address as text, and the [`exposure`](Self::exposure) is
    /// read off it. A `host` that is not an address is
    /// [`Internet`](Exposure::Internet), so every finding is rated as its
    /// detection wrote it.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        let host = host.into();
        let exposure = host
            .parse::<IpAddr>()
            .map_or(Exposure::Internet, Exposure::of);
        Self {
            host,
            port,
            exposure,
        }
    }

    /// Writes the seed into a fresh environment, under the names the validator
    /// reserves in [`SEED_VARS`](super::schema::SEED_VARS).
    fn seed(&self, env: &mut Env) {
        env.insert(SEED_VAR_HOST.to_string(), self.host.clone());
        env.insert(SEED_VAR_PORT.to_string(), self.port.to_string());
    }
}

/// Runs `flow` against `probe`, returning the findings it produced.
///
/// `content_hash` is the flow body's content address, stamped on every finding's
/// [`DetectionId`] as provenance. `seed` supplies `{host}` and `{port}`; see
/// [`FlowSeed`].
pub fn run(
    flow: &FlowDetection,
    content_hash: &str,
    seed: &FlowSeed,
    probe: &mut dyn Probe,
) -> Vec<Finding> {
    let mut env = Env::new();
    seed.seed(&mut env);
    let mut findings = Vec::new();
    probe.plan(exchanges(flow));

    // Clamped here too, for a flow that never went through the validator.
    for step in flow.step.iter().take(MAX_FLOW_STEPS) {
        match &step.for_each {
            Some(for_each) => {
                for item in for_each.items.iter().take(MAX_LOOP_ITEMS) {
                    let mut local = env.clone();
                    local.insert(for_each.var.clone(), item.clone());
                    if run_step(
                        flow,
                        content_hash,
                        seed,
                        step,
                        &mut local,
                        probe,
                        &mut findings,
                    ) == Flow::Halt
                    {
                        return findings;
                    }
                }
            }
            None => {
                if run_step(
                    flow,
                    content_hash,
                    seed,
                    step,
                    &mut env,
                    probe,
                    &mut findings,
                ) == Flow::Halt
                {
                    return findings;
                }
            }
        }
    }
    findings
}

/// How many exchanges `flow` makes when every step runs: one for each step that
/// sends, and one per item for a `for_each`, clamped where [`run`] clamps them.
///
/// An upper bound: a step whose guard is false sends nothing.
pub(crate) fn exchanges(flow: &FlowDetection) -> u32 {
    let sends: usize = flow
        .step
        .iter()
        .take(MAX_FLOW_STEPS)
        .filter(|step| step.send.is_some())
        .map(|step| {
            step.for_each
                .as_ref()
                .map_or(1, |for_each| for_each.items.len().min(MAX_LOOP_ITEMS))
        })
        .sum();
    u32::try_from(sends).unwrap_or(u32::MAX)
}

/// Runs one step and says whether the flow goes on.
///
/// In order: a false `when` guard skips the step whole; a `send` is interpolated and
/// exchanged for a reply; the reply's `bind` captures are read into the environment;
/// the step "matches" when every `expect` rule holds (or, with no reply, when it
/// asked for none); and each finding whose own `when` the match result satisfies is
/// emitted. Returns [`Flow::Halt`] when the step did not match and its `on_no_match`
/// says to stop, [`Flow::Continue`] otherwise.
fn run_step(
    flow: &FlowDetection,
    content_hash: &str,
    seed: &FlowSeed,
    step: &Step,
    env: &mut Env,
    probe: &mut dyn Probe,
    findings: &mut Vec<Finding>,
) -> Flow {
    // `matched` is out of scope in a step's guard.
    if !eval::holds(step.when.as_deref(), env, None) {
        return Flow::Continue;
    }

    // A step with no `send` has no reply to match against.
    let response = match &step.send {
        Some(send) => match interpolate(send, env) {
            // Decoded byte-for-byte, so a binary pattern such as `\xa2` matches
            // the byte it names.
            Some(text) => {
                probe.reads_until(step.until.as_deref());
                probe.speak(&unescape(&text)).map(|reply| latin1(&reply))
            }
            // A send whose template names an unbound variable cannot run.
            None => return on_no_match(step),
        },
        None => None,
    };

    // Best-effort, and before the gate, so a finding may read a value even from
    // a step that does not match.
    if let Some(response) = &response {
        for (name, spec) in &step.bind {
            if let Some(value) = capture(spec, response, name) {
                env.insert(name.clone(), value);
            }
        }
    }

    // `expect` is the hard gate: every rule must match for the step to "match".
    let matched = match &response {
        Some(response) => step.expect.iter().all(|rule| matches(rule, response)),
        None => step.expect.is_empty(),
    };

    if !matched && step.on_no_match == OnNoMatch::Halt {
        return Flow::Halt;
    }

    for spec in &step.finding {
        if eval::holds(spec.when.as_deref(), env, Some(matched))
            && let Some(finding) =
                build_finding(flow, content_hash, seed, spec, env, response.as_deref())
        {
            findings.push(finding);
        }
    }

    Flow::Continue
}

/// What a step's `on_no_match` says to do when it ends without a match.
fn on_no_match(step: &Step) -> Flow {
    match step.on_no_match {
        OnNoMatch::Halt => Flow::Halt,
        OnNoMatch::Continue => Flow::Continue,
    }
}

/// Whether `spec`'s pattern matches `text`. A pattern that will not compile
/// matches nothing.
fn matches(spec: &MatchSpec, text: &str) -> bool {
    let group = spec.version_group();
    patterns::matching(spec.pattern(), |compiled| {
        compiled.identify(text, group).is_some()
    })
    .unwrap_or(false)
}

/// Compiles every pattern a flow will match on, refusing one that will not
/// compile or that a bind can never capture from.
///
/// The runtime reads an uncompilable pattern as no match. Shipped flows are
/// checked at build by `validate_flow_patterns`; the builder runs this over a
/// caller's flow, since `check` holds no pattern engine.
pub(crate) fn check_patterns(flow: &FlowDetection) -> Result<(), String> {
    for (index, step) in flow.step.iter().enumerate() {
        for spec in &step.expect {
            pattern::compile(spec.pattern(), MAX_COMPILED_REGEX_BYTES).map_err(|error| {
                format!("step {index} `expect` has a pattern that will not compile: {error}")
            })?;
        }
        if let Some(until) = &step.until {
            pattern::compile(until, MAX_COMPILED_REGEX_BYTES).map_err(|error| {
                format!("step {index} `until` has a pattern that will not compile: {error}")
            })?;
        }
        for (var, spec) in &step.bind {
            let compiled =
                pattern::compile(spec.pattern(), MAX_COMPILED_REGEX_BYTES).map_err(|error| {
                    format!(
                        "step {index} bind `{var}` has a pattern that will not compile: {error}"
                    )
                })?;
            let named = compiled.capture_names().iter().any(|name| name == var);
            let numbered = spec
                .version_group()
                .is_some_and(|group| (group as usize) < compiled.captures_len());
            if !named && !numbered {
                return Err(format!(
                    "step {index} binds `{var}`, but its pattern has no (?<{var}>…) group and \
                     no valid version_group, so it can never capture"
                ));
            }
        }
    }
    Ok(())
}

/// The value `spec` binds out of `text` for a variable named `name`: a named
/// capture group of that name, or the numeric `version_group` an imported pattern
/// numbers instead.
fn capture(spec: &MatchSpec, text: &str, name: &str) -> Option<String> {
    let group = spec.version_group();
    patterns::matching(spec.pattern(), |compiled| {
        compiled.capture(text, name).or_else(|| {
            group.and_then(|group| compiled.identify(text, Some(group)).and_then(|m| m.version))
        })
    })
    .flatten()
}

/// Builds the finding a [`FindingSpec`] describes, resolving its `{var}`
/// templates against the environment. [`None`] if a template names an unbound
/// variable.
fn build_finding(
    flow: &FlowDetection,
    content_hash: &str,
    seed: &FlowSeed,
    spec: &FindingSpec,
    env: &Env,
    response: Option<&str>,
) -> Option<Finding> {
    let version = flow
        .detection
        .version
        .parse()
        .unwrap_or(Version::new(0, 0, 0));
    let detection = DetectionId::new(flow.detection.id.clone(), version, content_hash).ok()?;

    let title = interpolate(spec.title.as_deref().unwrap_or(spec.summary.as_str()), env)?;
    // Graded by the seed's exposure; see `SeveritySpec`.
    let severity = spec.severity.into_model_at(seed.exposure);
    let confidence = spec
        .confidence
        .as_deref()
        .and_then(wire::confidence)
        .unwrap_or(Confidence::Certain);
    let class = flow.detection.capabilities.class.into_model();

    let mut finding = Finding::new(detection, title, severity, confidence, class).ok()?;

    // A group comes from the manifest: it spans detections.
    if let Some(group) = flow.detection.group.as_ref().and_then(GroupSpec::to_model) {
        finding = finding.with_group(group);
    }

    // The excerpt: an explicit source, the interpolated detail, or the reply.
    let excerpt = match spec.excerpt_from.as_deref() {
        Some("$response") => response.map(str::to_owned),
        Some(name) => env.get(name).cloned(),
        None => match &spec.detail {
            Some(detail) => interpolate(detail, env),
            None => response.map(str::to_owned),
        },
    };
    if let Some(excerpt) = excerpt {
        finding = finding.with_excerpt(Excerpt::new(excerpt));
    }

    for reference in &spec.references {
        if let Some(reference) = reference.to_model() {
            finding = finding.with_reference(reference);
        }
    }
    if let Some(remediation) = &spec.remediation {
        finding = finding.with_remediation(remediation.clone());
    }

    Some(finding)
}

/// Substitutes each `{ident}` in `template` for the variable's value. `{{` and
/// `}}` stand for a literal `{` and `}`, for a body such as a JSON payload.
/// [`None`] if a name is unbound or a `{` opens no `{ident}`. A lone `}` is
/// literal.
fn interpolate(template: &str, env: &Env) -> Option<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(brace) = rest.find(['{', '}']) {
        out.push_str(&rest[..brace]);
        let this = rest.as_bytes()[brace];
        let after = &rest[brace + 1..];
        if after.as_bytes().first() == Some(&this) {
            out.push(this as char);
            rest = &after[1..];
        } else if this == b'{' {
            let close = after.find('}')?;
            out.push_str(env.get(&after[..close])?);
            rest = &after[close + 1..];
        } else {
            out.push('}');
            rest = after;
        }
    }
    out.push_str(rest);
    Some(out)
}

/// Decodes bytes as Latin-1, each byte its own code point, so a byte-oriented
/// pattern can match the reply losslessly.
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| byte as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::finding::{Reference, Severity};

    /// The shipped flow with this id, as the crate embeds it.
    fn flow(id: &str) -> FlowDetection {
        crate::detect::flow::db::shipped_flow(id)
    }

    /// A seed for a stand-in endpoint, for the flows that never read `{host}`.
    fn seed() -> FlowSeed {
        FlowSeed::new("192.0.2.10", 80)
    }

    /// A probe that answers every send with the same canned reply.
    struct Canned(Vec<u8>);
    impl Probe for Canned {
        fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
            Some(self.0.clone())
        }
    }

    /// A probe that records the exact bytes it was asked to send, so a test can
    /// assert what a `{host}`/`{port}` template resolved to on the wire.
    struct Echo {
        sent: Vec<Vec<u8>>,
        reply: Vec<u8>,
    }
    impl Probe for Echo {
        fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
            self.sent.push(bytes.to_vec());
            Some(self.reply.clone())
        }
    }

    /// **A flow matches its `expect` and its `bind` on the patterns kept for
    /// the process**, not on fresh compiles per reply.
    #[test]
    fn a_flow_matches_its_expect_and_bind_on_the_kept_patterns() {
        const EXPECT: &str = "^KEPT-EXPECT ok";
        const BIND: &str = "build (?<build>[0-9]+)";
        let toml = format!(
            r#"
            [detection]
            id = "kept-patterns"
            version = "1.0.0"
            title = "kept patterns"
            [detection.when]
            service = "http"
            [detection.capabilities]
            class = "active-benign"
            speak = "target"
            [[step]]
            send = "HELLO\r\n"
            expect = '{EXPECT}'
            bind = {{ build = '{BIND}' }}
            "#
        );
        let flow: FlowDetection = toml::from_str(&toml).expect("a valid flow");

        run(
            &flow,
            "",
            &seed(),
            &mut Canned(b"KEPT-EXPECT ok, build 42".to_vec()),
        );

        for source in [EXPECT, BIND] {
            assert!(
                crate::detect::patterns::matched_as_kept(source),
                "`{source}` was matched on a copy of its own"
            );
        }
    }

    #[test]
    fn a_send_template_resolves_the_seeded_host_and_port() {
        // The test is about the bytes the probe was handed.
        let toml = r#"
            [detection]
            id = "seed-echo"
            version = "1.0.0"
            title = "seed echo"
            [detection.when]
            service = "http"
            [detection.capabilities]
            class = "active-benign"
            speak = "target"
            [[step]]
            send = "GET / HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            expect = "200 OK"
        "#;
        let flow: FlowDetection = toml::from_str(toml).expect("a valid flow");
        let mut probe = Echo {
            sent: Vec::new(),
            reply: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
        };

        run(&flow, "", &FlowSeed::new("198.51.100.7", 8443), &mut probe);

        assert_eq!(
            probe.sent.first().map(|bytes| latin1(bytes)),
            Some("GET / HTTP/1.1\r\nHost: 198.51.100.7:8443\r\n\r\n".to_string()),
            "the seeded host and port replaced the template, not a fixed localhost"
        );
    }

    /// The shipped Phase-1 flows, each against a canned reply that should
    /// confirm it.
    #[test]
    fn the_phase_one_flows_fire_on_a_confirming_reply() {
        let cases: &[(&str, &[u8], Severity)] = &[
            (
                "memcached-unauth",
                b"STAT pid 1234\r\nSTAT version 1.6.21\r\nEND\r\n",
                Severity::High,
            ),
            (
                "couchdb-open",
                COUCHDB_ALL_DBS,
                Severity::High,
            ),
            (
                "elasticsearch-open",
                b"HTTP/1.1 200 OK\r\n\r\n{\"cluster_name\":\"prod\",\"version\":{\"number\":\"8.11.0\"}}",
                Severity::High,
            ),
            (
                "http-git-exposed",
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nref: refs/heads/main\n",
                Severity::High,
            ),
            (
                "http-server-status",
                b"HTTP/1.1 200 OK\r\n\r\n<html><head><title>Apache Server Status for host</title>",
                Severity::Medium,
            ),
            (
                "http-dotenv-exposed",
                b"HTTP/1.1 200 OK\r\n\r\nAPP_KEY=base64:abcd\nDB_PASSWORD=hunter2\n",
                Severity::High,
            ),
            (
                "mongodb-unauth",
                // Only the field the flow matches matters.
                b"\x00\x00\x00\x00...sizeOnDisk\x00...admin\x00",
                Severity::High,
            ),
            (
                "http-spring-actuator",
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"_links\":{\"self\":{\"href\":\"http://h/actuator\"},\"env\":{\"href\":\"http://h/actuator/env\"}}}",
                Severity::High,
            ),
            (
                "http-dir-listing",
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<title>Index of /</title><h1>Index of /</h1>",
                Severity::Low,
            ),
            (
                "anonymous-ftp",
                b"220 Zond FTP\r\n331 Please specify the password.\r\n230 Login successful.\r\n221 Goodbye.\r\n",
                Severity::Medium,
            ),
            (
                "ldap-anonymous-bind",
                // BindResponse, messageID 1, resultCode success: 0x61 len 0x0a 0x01 0x00.
                b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00",
                Severity::Medium,
            ),
            (
                "vnc-noauth",
                // RFB 3.8 banner, then one security type: None (0x01).
                b"RFB 003.008\n\x01\x01",
                Severity::Critical,
            ),
            (
                "dns-version-bind",
                // A two-byte TCP length prefix, then: id 0x1337 echoed, response
                // flags, one question, one answer.
                b"\x00\x2c\x13\x37\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03\xc0\x0c\x00\x10\x00\x03\x00\x00\x00\x00\x00\x0d\x0c9.16.1-Debian",
                Severity::Info,
            ),
            (
                "docker-api-unauth",
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"Version\":\"24.0.6\",\"ApiVersion\":\"1.43\",\"Os\":\"linux\"}",
                Severity::Critical,
            ),
            (
                "k8s-api-anonymous",
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"kind\":\"NamespaceList\",\"items\":[{\"metadata\":{\"name\":\"default\"}}]}",
                Severity::High,
            ),
            (
                "jenkins-unauth",
                b"HTTP/1.1 200 OK\r\nX-Jenkins: 2.426.1\r\nContent-Type: application/json\r\n\r\n{\"_class\":\"hudson.model.Hudson\"}",
                Severity::High,
            ),
            (
                "phpmyadmin-exposed",
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>phpMyAdmin</title></head></html>",
                Severity::Medium,
            ),
            (
                "etcd-unauth",
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"etcdserver\":\"3.5.9\",\"etcdcluster\":\"3.5.0\"}",
                Severity::High,
            ),
            (
                "consul-no-acl",
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"consul\":[],\"redis\":[\"primary\"]}",
                Severity::High,
            ),
            (
                "influxdb-noauth",
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"results\":[{\"statement_id\":0,\"series\":[{\"name\":\"databases\",\"values\":[[\"_internal\"]]}]}]}",
                Severity::High,
            ),
            (
                "nomad-no-acl",
                b"HTTP/1.1 200 OK\r\nX-Nomad-Index: 42\r\nContent-Type: application/json\r\n\r\n[]",
                Severity::High,
            ),
            (
                "docker-registry-catalog",
                REGISTRY_CATALOG,
                Severity::High,
            ),
            (
                "kubelet-pods-exposed",
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"kind\":\"PodList\",\"items\":[]}",
                Severity::High,
            ),
            (
                "clickhouse-noauth",
                b"HTTP/1.1 200 OK\r\nX-ClickHouse-Query-Id: q1\r\nContent-Type: text/tab-separated-values\r\n\r\n1\n",
                Severity::High,
            ),
            (
                "prometheus-open",
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"success\",\"data\":{\"activeTargets\":[]}}",
                Severity::Medium,
            ),
            (
                "kibana-open",
                b"HTTP/1.1 200 OK\r\nkbn-name: kibana\r\nContent-Type: application/json\r\n\r\n{\"status\":{\"overall\":{}}}",
                Severity::Medium,
            ),
            (
                "riak-open",
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"riak_kv_version\":\"3.0.0\",\"ring_members\":[\"riak@127.0.0.1\"]}",
                Severity::High,
            ),
            (
                "rsync-exposed",
                b"@RSYNCD: 31.0\ndata\tproject files\nbackup\tnightly dumps\n@RSYNCD: EXIT\n",
                Severity::Medium,
            ),
            (
                "zookeeper-4lw",
                b"Zookeeper version: 3.8.0-abc, built on 2024-01-01\nClients:\n /192.0.2.9:52111[1]\nMode: standalone\n",
                Severity::Medium,
            ),
            (
                "mqtt-anonymous",
                // CONNACK: no session present, return code 0x00 (accepted).
                b"\x20\x02\x00\x00",
                Severity::High,
            ),
        ];

        for (name, reply, severity) in cases {
            let flow = flow(name);
            let findings = run(&flow, "", &seed(), &mut Canned(reply.to_vec()));
            assert_eq!(
                findings.len(),
                1,
                "{name} drew no finding on a confirming reply"
            );
            assert_eq!(findings[0].severity(), *severity, "{name} graded wrong");
        }
    }

    /// No shipped flow fires on a bare 404. Per-service denials are tested
    /// below.
    #[test]
    fn no_flow_fires_on_a_generic_404() {
        let quiet = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<html><body>not found</body></html>";
        for flow in crate::detect::flow::db::FlowDb::global().flows() {
            let findings = flow.run(&seed(), &mut Canned(quiet.to_vec()));
            assert!(
                findings.is_empty(),
                "{} fired on a bare 404",
                flow.flow().detection.id
            );
        }
    }

    /// No shipped flow fires on a web app that answers every path with its
    /// index page, whatever path the flow asked for.
    #[test]
    fn no_flow_fires_on_an_app_answering_every_path_with_its_index() {
        for flow in crate::detect::flow::db::FlowDb::global().flows() {
            let findings = flow.run(&seed(), &mut Canned(CATCH_ALL_INDEX.to_vec()));
            assert!(
                findings.is_empty(),
                "{} fired on an app's index page",
                flow.flow().detection.id
            );
        }
    }

    /// A Jenkins or Kubernetes API that answers anonymous reads with a 403 still
    /// identifies itself, and must not fire: the finding is anonymous *access*.
    #[test]
    fn a_panel_that_requires_authentication_does_not_fire() {
        let cases: &[(&str, &[u8])] = &[
            (
                "jenkins-unauth",
                b"HTTP/1.1 403 Forbidden\r\nX-Jenkins: 2.426.1\r\nContent-Type: text/html\r\n\r\nAuthentication required",
            ),
            (
                "k8s-api-anonymous",
                b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"kind\":\"Status\",\"status\":\"Failure\",\"reason\":\"Forbidden\"}",
            ),
        ];
        for (name, reply) in cases {
            let flow = flow(name);
            let findings = run(&flow, "", &seed(), &mut Canned(reply.to_vec()));
            assert!(
                findings.is_empty(),
                "{name} fired on a 403 that denied access"
            );
        }
    }

    /// What CouchDB 3 answers `GET /_all_dbs` with on a node with no admin, its
    /// headers as `chttpd` writes them.
    const COUCHDB_ALL_DBS: &[u8] = b"HTTP/1.1 200 OK\r\n\
        Cache-Control: must-revalidate\r\n\
        Content-Length: 25\r\n\
        Content-Type: application/json\r\n\
        Date: Thu, 01 Oct 2026 09:00:00 GMT\r\n\
        Server: CouchDB/3.3.3 (Erlang OTP/24)\r\n\
        X-Couch-Request-ID: 5d1c3a0b7e\r\n\
        X-CouchDB-Body-Time: 0\r\n\r\n\
        [\"_replicator\",\"_users\"]\n";

    /// A single-page app's index, which such an app serves with a 200 for any
    /// path it does not route, as Uptime Kuma and Nginx Proxy Manager do. Its
    /// inline script carries a JSON array and the word `repositories`, and a
    /// wrapped tag puts `href=` at the start of a line.
    const CATCH_ALL_INDEX: &[u8] = b"HTTP/1.1 200 OK\r\n\
        Content-Type: text/html; charset=utf-8\r\n\
        Content-Length: 512\r\n\r\n\
        <!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
        <title>Home Lab</title>\n\
        <link rel=\"stylesheet\"\nhref=\"/assets/index-4f2a.css\">\n\
        <script>window.__APP__ = {\"routes\":[\"/\",\"/settings\"],\
        \"features\":{\"repositories\":true}};</script>\n\
        <script type=\"module\" src=\"/assets/index-9c1e.js\"></script>\n\
        </head>\n<body><div id=\"app\"></div></body>\n</html>\n";

    /// CouchDB is told apart from a web app that answers every path: a 200
    /// with a bracket somewhere in it is not a database list.
    #[test]
    fn couchdb_open_fires_on_couchdb_and_not_on_an_app_answering_every_path() {
        let couchdb = flow("couchdb-open");
        let fires =
            |reply: &[u8]| !run(&couchdb, "", &seed(), &mut Canned(reply.to_vec())).is_empty();

        assert!(
            !fires(CATCH_ALL_INDEX),
            "couchdb-open read an app's index page as a database list"
        );

        // A node behind a proxy that rewrote `Server`, still listing its own.
        assert!(fires(
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/json\r\n\
              Transfer-Encoding: chunked\r\n\r\n19\r\n[\"_replicator\",\"_users\"]\n\r\n0\r\n\r\n"
        ));
        // A fresh node with no databases, named by its header.
        assert!(fires(
            b"HTTP/1.1 200 OK\r\nServer: CouchDB/3.3.3 (Erlang OTP/24)\r\n\r\n[]\n"
        ));
        // A JSON array from something that is not CouchDB.
        assert!(!fires(
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/json\r\n\r\n[\"a\",\"b\"]"
        ));
        // CouchDB requiring an admin.
        assert!(!fires(
            b"HTTP/1.1 401 Unauthorized\r\nServer: CouchDB/3.3.3 (Erlang OTP/24)\r\n\r\n\
              {\"error\":\"unauthorized\",\"reason\":\"You are not a server admin.\"}\n"
        ));
    }

    /// The CouchDB write proof reads CouchDB's own answer to the PUT, not any
    /// 201 that happens to hold the letters `ok`.
    #[test]
    fn couchdb_writable_fires_on_couchdb_and_not_on_another_server_that_creates() {
        let writable = flow("couchdb-writable");
        let fires =
            |reply: &[u8]| !run(&writable, "", &seed(), &mut Canned(reply.to_vec())).is_empty();

        assert!(fires(
            b"HTTP/1.1 201 Created\r\nLocation: http://192.0.2.10:5984/zond-canary\r\n\
              Server: CouchDB/3.3.3 (Erlang OTP/24)\r\nContent-Type: application/json\r\n\r\n\
              {\"ok\":true}\n"
        ));
        assert!(
            !fires(
                b"HTTP/1.1 201 Created\r\nServer: Apache/2.4.62\r\n\
                  Set-Cookie: lang=en; path=/\r\nContent-Type: text/html\r\n\r\n\
                  <html><body><h1>Created</h1><p>Resource /zond-canary has been created.</p></body></html>"
            ),
            "couchdb-writable read a WebDAV share's 201 as CouchDB"
        );
    }

    /// What the `registry:2` distribution server answers `GET /v2/_catalog`
    /// with when it has no auth configured.
    const REGISTRY_CATALOG: &[u8] = b"HTTP/1.1 200 OK\r\n\
        Content-Type: application/json; charset=utf-8\r\n\
        Docker-Distribution-Api-Version: registry/2.0\r\n\
        X-Content-Type-Options: nosniff\r\n\
        Date: Thu, 01 Oct 2026 09:00:00 GMT\r\n\
        Content-Length: 36\r\n\r\n\
        {\"repositories\":[\"alpine\",\"nginx\"]}\n";

    /// A registry is told apart from a web app that answers every path and
    /// happens to say `repositories`.
    #[test]
    fn docker_registry_catalog_fires_on_a_registry_and_not_on_an_app_answering_every_path() {
        let registry = flow("docker-registry-catalog");
        let fires =
            |reply: &[u8]| !run(&registry, "", &seed(), &mut Canned(reply.to_vec())).is_empty();

        assert!(fires(REGISTRY_CATALOG));
        assert!(
            !fires(CATCH_ALL_INDEX),
            "docker-registry-catalog read an app's index page as a catalogue"
        );
        // A registry requiring a token.
        assert!(!fires(
            b"HTTP/1.1 401 Unauthorized\r\nDocker-Distribution-Api-Version: registry/2.0\r\n\
              WWW-Authenticate: Bearer realm=\"https://auth.example.com/token\"\r\n\r\n\
              {\"errors\":[{\"code\":\"UNAUTHORIZED\"}]}\n"
        ));
    }

    /// A served `.env` is told apart from a page that merely has a line
    /// starting `name=`: the key is uppercase, and the body opens with it.
    #[test]
    fn http_dotenv_exposed_fires_on_a_dotenv_body_and_not_on_a_page() {
        let dotenv = flow("http-dotenv-exposed");
        let fires =
            |reply: &[u8]| !run(&dotenv, "", &seed(), &mut Canned(reply.to_vec())).is_empty();

        // A Laravel `.env` as nginx serves a dotfile it was not told to deny.
        assert!(fires(
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/octet-stream\r\n\r\n\
              APP_NAME=Laravel\nAPP_ENV=production\nAPP_KEY=base64:c2VjcmV0\nDB_PASSWORD=hunter2\n"
        ));
        assert!(
            !fires(CATCH_ALL_INDEX),
            "http-dotenv-exposed read a wrapped `href=` in an app's index page as an assignment"
        );
        // A commented file that exports its keys.
        assert!(fires(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n# production\n\nexport SECRET_KEY=abc\n"
        ));
        // An uppercase assignment inside a page is still a page.
        assert!(!fires(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><pre>\nAPP_ENV=local\n</pre></body></html>"
        ));
    }

    /// The four enumeration flows against a same-protocol denial: FTP refusing
    /// anonymous, a rejected LDAP bind, VNC offering only a password, and DNS
    /// returning no answer. None may fire.
    #[test]
    fn the_enumeration_flows_stay_quiet_when_the_service_denies_access() {
        let cases: &[(&str, &[u8])] = &[
            // 530: the login was refused.
            (
                "anonymous-ftp",
                b"220 Zond FTP\r\n331 Please specify the password.\r\n530 Login incorrect.\r\n",
            ),
            // BindResponse resultCode 0x30 (48, inappropriateAuthentication).
            (
                "ldap-anonymous-bind",
                b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x30\x04\x00\x04\x00",
            ),
            // RFB 3.8 banner offering one type: VNC auth (0x02), no None.
            ("vnc-noauth", b"RFB 003.008\n\x01\x02"),
            // A TCP-framed DNS reply with zero answers (the header's ANCOUNT is 0x0000).
            (
                "dns-version-bind",
                b"\x00\x1e\x13\x37\x84\x05\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
            ),
        ];

        for (name, reply) in cases {
            let flow = flow(name);
            let findings = run(&flow, "", &seed(), &mut Canned(reply.to_vec()));
            assert!(
                findings.is_empty(),
                "{name} fired on a service that denied access"
            );
        }
    }

    #[test]
    fn the_redis_flow_runs_and_produces_a_finding() {
        let redis = flow("redis-unauth-access");
        let mut probe = Canned(b"# Server\r\nredis_version:7.2.4\r\nrun_id:abc".to_vec());

        let findings = run(&redis, "", &seed(), &mut probe);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];

        assert_eq!(finding.detection().id(), "redis-unauth-access");
        assert_eq!(finding.severity(), Severity::High);
        assert_eq!(
            finding.title(),
            "Redis answered INFO without authentication"
        );
        // The `{version}` in `detail` resolved from the bound capture.
        assert_eq!(
            finding.excerpt().as_str(),
            "Server version 7.2.4 is reachable without a password."
        );
        assert!(
            finding
                .references()
                .any(|r| matches!(r, Reference::Cwe(306)))
        );
    }

    #[test]
    fn a_gate_that_does_not_match_halts_and_emits_nothing() {
        let redis = flow("redis-unauth-access");
        // No "# Server" line, so the step's `expect` gate fails and the flow halts.
        let mut probe = Canned(b"-ERR NOAUTH Authentication required".to_vec());

        assert!(run(&redis, "", &seed(), &mut probe).is_empty());
    }

    /// An SNMP agent that accepts only the `public` community: a well-formed
    /// GetRequest for sysDescr with it draws a GetResponse (`\xa2`), anything
    /// else a report PDU (`\xa3`).
    struct Snmp;
    impl Probe for Snmp {
        fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
            let sys_descr_oid: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
            let well_formed = bytes.first() == Some(&0x30) && contains(bytes, sys_descr_oid);
            let community_public = contains(bytes, b"\x04\x06public");
            if well_formed && community_public {
                let mut reply = vec![0xa2];
                reply.extend_from_slice(b" sysDescr: Linux router 6.1");
                Some(reply)
            } else {
                Some(b"\xa3 wrong community".to_vec())
            }
        }
    }

    #[test]
    fn the_snmp_flow_probes_each_community_and_flags_the_one_that_answers() {
        let snmp = flow("snmp-default-community");
        let findings = run(&snmp, "", &seed(), &mut Snmp);

        // Only `public` was accepted, so one finding, and it names that community.
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity(), Severity::High);
        assert!(
            finding.title().contains("public"),
            "the finding should name the community that answered, got {:?}",
            finding.title()
        );
        // The excerpt is the GetResponse the agent returned.
        assert!(finding.excerpt().as_str().contains("Linux router 6.1"));
    }

    /// Whether `haystack` contains `needle` as a contiguous run.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// A probe standing in for a Grafana server. The identify step's `/login`
    /// GET draws `banner`; the exploit step's traversal draws `leak`, which is
    /// only ever sent when the conditional guard let the step run.
    struct Grafana {
        banner: &'static [u8],
        leak: &'static [u8],
    }
    impl Probe for Grafana {
        fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
            if contains(bytes, b"/login") {
                Some(self.banner.to_vec())
            } else if contains(bytes, b"etc/passwd") {
                Some(self.leak.to_vec())
            } else {
                None
            }
        }
    }

    #[test]
    fn the_conditional_step_confirms_a_leak_on_a_vulnerable_server() {
        let grafana = flow("grafana-path-traversal");
        // An affected version, and a traversal that reads the file: the step
        // runs and the leak confirms.
        let mut probe = Grafana {
            banner: b"HTTP/1.1 200 OK\r\nX-Grafana: Grafana v8.2.0\r\n\r\n",
            leak: b"HTTP/1.1 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash\n",
        };

        let findings = run(&grafana, "", &seed(), &mut probe);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity(), Severity::Critical);
        // `excerpt_from = "$response"` carried the leaked bytes onto the finding.
        assert!(
            finding.excerpt().as_str().contains("root:x:0:0:"),
            "the excerpt is the leaked passwd line, got {:?}",
            finding.excerpt().as_str()
        );
        assert!(
            finding
                .references()
                .any(|r| matches!(r, Reference::Cve(id) if id == "CVE-2021-43798"))
        );
    }

    #[test]
    fn an_affected_version_whose_leak_is_blocked_is_still_flagged() {
        let grafana = flow("grafana-path-traversal");
        // Affected version, but the traversal is refused: the step runs, its
        // `expect` fails, and the `not matched and bound(version)` finding fires.
        let mut probe = Grafana {
            banner: b"HTTP/1.1 200 OK\r\nX-Grafana: Grafana v8.2.0\r\n\r\n",
            leak: b"HTTP/1.1 403 Forbidden\r\n\r\n",
        };

        let findings = run(&grafana, "", &seed(), &mut probe);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity(), Severity::Medium);
    }

    #[test]
    fn a_patched_or_unrelated_server_never_reaches_the_exploit_step() {
        let grafana = flow("grafana-path-traversal");

        // 8.10.0 is newer than 8.3.1, which a lexical `<` would misread.
        let mut patched = Grafana {
            banner: b"HTTP/1.1 200 OK\r\nX-Grafana: Grafana v8.10.0\r\n\r\n",
            leak: b"root:x:0:0:should-never-be-sent",
        };
        assert!(run(&grafana, "", &seed(), &mut patched).is_empty());

        // Not Grafana: `bound(version)` is false.
        let mut other = Grafana {
            banner: b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
            leak: b"root:x:0:0:should-never-be-sent",
        };
        assert!(run(&grafana, "", &seed(), &mut other).is_empty());
    }

    /// **A flow's severity is graded against who can reach the endpoint.**
    ///
    /// One flow run against a private and a public address reports the same
    /// claim at two ratings.
    #[test]
    fn a_severity_stated_per_rung_is_graded_by_the_seeds_exposure() {
        let toml = r#"
            [detection]
            id = "resolver"
            version = "1.0.0"
            title = "A resolver that recurses"
            [detection.when]
            service = "dns"
            [detection.capabilities]
            class = "active-benign"
            speak = "target"
            [[step]]
            send = "q"
            expect = 'recursed'
            [[step.finding]]
            when = "matched"
            severity = { internet = "high", internal = "info" }
            summary = "the resolver recursed for an external name"
        "#;
        let flow: FlowDetection = toml::from_str(toml).expect("a parseable flow");

        let graded = |host: &str| {
            let findings = run(
                &flow,
                "",
                &FlowSeed::new(host, 53),
                &mut Echo {
                    sent: Vec::new(),
                    reply: b"recursed".to_vec(),
                },
            );
            findings.first().expect("the flow matched").severity()
        };

        assert_eq!(graded("198.51.100.7"), Severity::High);
        assert_eq!(graded("192.168.0.1"), Severity::Info);
        assert_eq!(graded("127.0.0.1"), Severity::Info, "unstated `local`");
    }

    /// A flow stating one severity reports it at every rung, as nearly every
    /// shipped flow does.
    #[test]
    fn a_flat_severity_is_the_same_rating_wherever_the_endpoint_is() {
        let redis = flow("redis-unauth-access");
        for host in ["198.51.100.7", "192.168.0.10", "127.0.0.1"] {
            let findings = run(
                &redis,
                "",
                &FlowSeed::new(host, 6379),
                &mut Echo {
                    sent: Vec::new(),
                    reply: b"# Server\r\nredis_version:7.0.11\r\n".to_vec(),
                },
            );
            assert_eq!(
                findings.first().expect("the flow matched").severity(),
                Severity::High,
                "{host}"
            );
        }
    }

    /// A seed whose host is not an address rates at the widest audience.
    #[test]
    fn a_host_that_is_not_an_address_rates_at_the_widest_audience() {
        assert_eq!(
            FlowSeed::new("scanme.example.invalid", 53).exposure,
            Exposure::Internet
        );
    }

    /// **A flow's group reaches every finding it produces.**
    #[test]
    fn a_flow_stamps_its_group_on_what_it_finds() {
        let toml = r#"
            [detection]
            id = "ssh-weak-mac"
            version = "1.0.0"
            title = "SSH offers a weak MAC"
            [detection.group]
            id = "ssh-weak-algorithms"
            summary = "weak SSH algorithms offered"
            [detection.when]
            service = "ssh"
            [detection.capabilities]
            class = "active-benign"
            speak = "target"
            [[step]]
            send = "SSH-2.0-zond\r\n"
            expect = '(hmac-md5)'
            [[step.finding]]
            when = "matched"
            severity = "medium"
            summary = "SSH offered an MD5 or truncated MAC"
        "#;
        let flow: FlowDetection = toml::from_str(toml).expect("a parseable flow");

        let findings = run(
            &flow,
            "",
            &seed(),
            &mut Echo {
                sent: Vec::new(),
                reply: b"SSH-2.0-OpenSSH_6.6.1p1 hmac-md5".to_vec(),
            },
        );

        let group = findings
            .first()
            .expect("the flow matched")
            .group()
            .expect("the detection declared one");
        assert_eq!(group.id(), "ssh-weak-algorithms");
        assert_eq!(group.summary(), "weak SSH algorithms offered");
    }

    /// A detection that declares no group produces findings that belong to none.
    #[test]
    fn a_flow_without_a_group_stamps_none() {
        let toml = r#"
            [detection]
            id = "solitary"
            version = "1.0.0"
            title = "solitary"
            [detection.when]
            service = "http"
            [detection.capabilities]
            class = "active-benign"
            speak = "target"
            [[step]]
            send = "GET / HTTP/1.0\r\n\r\n"
            expect = '(200)'
            [[step.finding]]
            when = "matched"
            severity = "low"
            summary = "answered"
        "#;
        let flow: FlowDetection = toml::from_str(toml).expect("a parseable flow");

        let findings = run(
            &flow,
            "",
            &seed(),
            &mut Echo {
                sent: Vec::new(),
                reply: b"HTTP/1.1 200 OK".to_vec(),
            },
        );

        assert!(
            findings
                .first()
                .expect("the flow matched")
                .group()
                .is_none()
        );
    }

    #[test]
    fn run_does_not_probe_past_the_step_ceiling() {
        // `run` is public, so it must clamp an unvalidated flow too.
        let mut probes = 0usize;
        struct Counting<'a>(&'a mut usize);
        impl Probe for Counting<'_> {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                *self.0 += 1;
                Some(b"x".to_vec())
            }
        }

        let mut source = String::from(
            "[detection]\nid = \"x\"\nversion = \"1.0.0\"\ntitle = \"x\"\n\
             [detection.when]\n[detection.capabilities]\nclass = \"active-benign\"\nspeak = \"target\"\n",
        );
        for _ in 0..(MAX_FLOW_STEPS + 50) {
            source.push_str("[[step]]\nsend = \"p\"\non_no_match = \"continue\"\n");
        }
        let flow: FlowDetection = toml::from_str(&source).expect("a parseable flow");

        run(&flow, "", &seed(), &mut Counting(&mut probes));
        assert_eq!(
            probes, MAX_FLOW_STEPS,
            "run probed a flow past the {MAX_FLOW_STEPS}-step ceiling"
        );
    }
}
