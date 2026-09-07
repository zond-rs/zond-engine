// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Running a flow
//!
//! Walks a [`FlowDetection`](super::schema::FlowDetection)'s steps front to back,
//! once, there is no instruction that revisits a step, exchanging bytes with a
//! [`Probe`], matching replies, binding variables, and emitting the
//! [`Finding`]s its findings imply. The bound total probe count and the absence
//! of any jump are what let it run without a fuel meter: it cannot loop forever
//! and cannot exceed its declared budget by construction.
//!
//! ## The variable environment is forward-only
//!
//! A step sees what earlier steps bound, never what a later one will. An ordinary
//! step's binds propagate to the steps after it; a `for_each` step runs each item
//! in an environment of its own, so one iteration's binds never leak into the
//! next.
//!
//! ## Guards decide the branches
//!
//! Two kinds of `when` clause steer a flow, both written in the [guard
//! grammar](super::expr) and answered by [`eval`](super::eval). A step's `when`
//! is checked against the environment before the step runs, a false guard
//! skips the step and moves on, so a step may be made conditional on what an
//! earlier one bound. A finding's `when` is checked against the environment and
//! its step's match result, so a finding fires only in the case it names. An
//! absent guard always holds; an unparseable one never does.

use crate::fingerprint::{MAX_COMPILED_REGEX_BYTES, pattern, unescape};
use crate::model::confidence::Confidence;
use crate::model::finding::{DetectionId, Excerpt, Finding, Version};
use crate::record::wire;

use super::schema::{FindingSpec, FlowDetection, MatchSpec, OnNoMatch, Step};
use super::schema::{MAX_FLOW_STEPS, MAX_LOOP_ITEMS, SEED_VAR_HOST, SEED_VAR_PORT};
use super::{Env, eval};

/// Why an exchange a flow asked for was refused before it happened, rather than
/// simply going unanswered: a budget the detection declared, now spent. A silent
/// port and a spent budget both leave a step without a reply, and a report needs
/// to tell them apart.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeRefusal {
    /// The byte budget across the flow's exchanges is spent.
    Bytes,
    /// The connection budget is spent.
    Connections,
    /// The wall-clock budget is spent.
    Deadline,
}

/// The one capability a flow reaches the world through: send bytes to the scanned
/// socket and read its reply. A test supplies a canned one; a scan supplies the
/// real socket.
pub trait Probe {
    /// Sends `bytes` and returns the reply, or [`None`] if the socket said
    /// nothing.
    fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>>;

    /// Whether the most recent [`speak`](Self::speak) reply was read to a clean,
    /// self-terminating end, a TCP peer that closed the connection or a UDP
    /// datagram, rather than cut short by a byte or time budget. A reply cut
    /// short cannot stand in for one a larger budget would have read in full, so
    /// only a complete one is safe to share between flows. The default is `true`:
    /// a canned probe hands back a whole reply.
    fn reply_complete(&self) -> bool {
        true
    }

    /// Why the most recent [`speak`](Self::speak) returned [`None`], if a budget
    /// refused the exchange rather than the port merely going silent. The default
    /// is [`None`]: a probe with no budget of its own never refuses, it only goes
    /// unanswered. The live socket probe overrides this, so a flow cut short by its
    /// own budget is recorded rather than mistaken for a silent port.
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

/// The facts about the port under probe that a flow may name in a `send` or a
/// `{var}` but has no other way to know: the address it reached and the number it
/// reached it on, seeded into the environment as `host` and `port` before the
/// first step.
///
/// A flow that sends HTTP needs to name the host it is talking to, a `Host:`
/// header, a redirect it follows, and without this it can only hard-code
/// `localhost`, which a virtual-host-routed server, most of the web, answers with
/// the wrong site or a redirect away. These two variables are the host it
/// reached, not one it chose: the address the scan resolved and connected to, so
/// a flow still cannot address a machine the scan never looked at.
///
/// The environment otherwise holds only what a `bind` captured off the wire,
/// which is what lets a flow's matching stay a pure function of the bytes it was
/// answered with. `host` and `port` do not weaken that: they are the fixed
/// identity of the endpoint, recorded on the run like every reply, not ambient
/// state that could differ on a re-run, which is the line that still keeps a
/// clock out. A `bind` may shadow either name, and doing so only rebinds a
/// template variable.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct FlowSeed {
    /// The address the flow reached, seeded as `{host}`. The scanned IP as text;
    /// no hostname is available by the time a detection runs.
    pub host: String,
    /// The port the flow reached it on, seeded as `{port}`.
    pub port: u16,
}

impl FlowSeed {
    /// A seed for the endpoint at `host` on `port`.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Writes the seeded identity into a fresh environment, under the same names
    /// the validator reserves in [`SEED_VARS`](super::schema::SEED_VARS), so what
    /// a flow may reference and what it is handed cannot disagree.
    fn seed(&self, env: &mut Env) {
        env.insert(SEED_VAR_HOST.to_string(), self.host.clone());
        env.insert(SEED_VAR_PORT.to_string(), self.port.to_string());
    }
}

/// Runs `flow` against `probe`, returning the findings it produced.
///
/// `content_hash` is the flow body's content address, stamped on every finding's
/// [`DetectionId`] as provenance, the loader that sourced the flow computes it
/// from the flow's bytes. Everything else, the id, version, severity and
/// references, is the flow's own. `seed` supplies the `{host}` and `{port}` a
/// probe template may name; see [`FlowSeed`].
pub fn run(
    flow: &FlowDetection,
    content_hash: &str,
    seed: &FlowSeed,
    probe: &mut dyn Probe,
) -> Vec<Finding> {
    let mut env = Env::new();
    seed.seed(&mut env);
    let mut findings = Vec::new();

    // The step ceiling is enforced here, not only in the build-time validator, so
    // a flow handed straight to `run` by a caller that never validated it cannot
    // probe past the bound the corpus is held to. The validator rejects a longer
    // flow outright; this clamps one, the same way the loop below clamps a
    // `for_each` at `MAX_LOOP_ITEMS`.
    for step in flow.step.iter().take(MAX_FLOW_STEPS) {
        match &step.for_each {
            Some(for_each) => {
                for item in for_each.items.iter().take(MAX_LOOP_ITEMS) {
                    let mut local = env.clone();
                    local.insert(for_each.var.clone(), item.clone());
                    if run_step(flow, content_hash, step, &mut local, probe, &mut findings)
                        == Flow::Halt
                    {
                        return findings;
                    }
                }
            }
            None => {
                if run_step(flow, content_hash, step, &mut env, probe, &mut findings) == Flow::Halt
                {
                    return findings;
                }
            }
        }
    }
    findings
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
    step: &Step,
    env: &mut Env,
    probe: &mut dyn Probe,
    findings: &mut Vec<Finding>,
) -> Flow {
    // A step's guard is checked before it runs: a false guard skips the step,
    // its probe, its binds, its findings, and the flow proceeds to the next.
    // `matched` is out of scope here, nothing having matched yet, so the guard
    // reads only what earlier steps bound.
    if !eval::holds(step.when.as_deref(), env, None) {
        return Flow::Continue;
    }

    // The probe exchange. A step with no `send` reads nothing new, for now it
    // has no reply to match against.
    let response = match &step.send {
        Some(send) => match interpolate(send, env) {
            // Decoded byte-for-byte, so a binary pattern such as `\xa2` matches
            // the byte it names rather than a lossy replacement character.
            Some(text) => probe.speak(&unescape(&text)).map(|reply| latin1(&reply)),
            // A send whose template names an unbound variable cannot run.
            None => return on_no_match(step),
        },
        None => None,
    };

    // `bind` is best-effort: a capture that does not match leaves its variable
    // unbound. Run it before the gate so a finding may read a value even from a
    // step that then only continues.
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
            && let Some(finding) = build_finding(flow, content_hash, spec, env, response.as_deref())
        {
            findings.push(finding);
        }
    }

    Flow::Continue
}

/// The flow's fate, halt or continue, that a step's `on_no_match` names for when
/// the step ends without a match, such as a `send` whose template names an unbound
/// variable and so cannot run.
fn on_no_match(step: &Step) -> Flow {
    match step.on_no_match {
        OnNoMatch::Halt => Flow::Halt,
        OnNoMatch::Continue => Flow::Continue,
    }
}

/// Whether `spec`'s pattern matches `text`.
fn matches(spec: &MatchSpec, text: &str) -> bool {
    pattern::compile(spec.pattern(), MAX_COMPILED_REGEX_BYTES)
        .is_ok_and(|compiled| compiled.identify(text, spec.version_group()).is_some())
}

/// Compiles every pattern a flow will match on, refusing one that will not
/// compile or that a bind can never capture from.
///
/// The runtime reads an uncompilable pattern as a clean negative, so a shipped
/// flow's patterns are compiled at build by `validate_flow_patterns`. `check` cannot
/// do the same: it is a pure structural pass that holds no pattern engine. So the
/// builder runs this over a caller's flow, mirroring that build check, rather than
/// letting a bad pattern read as "no match" against a live target.
pub(crate) fn check_patterns(flow: &FlowDetection) -> Result<(), String> {
    for (index, step) in flow.step.iter().enumerate() {
        for spec in &step.expect {
            pattern::compile(spec.pattern(), MAX_COMPILED_REGEX_BYTES).map_err(|error| {
                format!("step {index} `expect` has a pattern that will not compile: {error}")
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
    let compiled = pattern::compile(spec.pattern(), MAX_COMPILED_REGEX_BYTES).ok()?;
    compiled.capture(text, name).or_else(|| {
        spec.version_group()
            .and_then(|group| compiled.identify(text, Some(group)).and_then(|m| m.version))
    })
}

/// Builds the finding a [`FindingSpec`] describes, resolving its `{var}`
/// templates against the environment. [`None`] if a template names a variable
/// nothing bound, a finding that would lie about what it found is dropped, not
/// emitted half-built.
fn build_finding(
    flow: &FlowDetection,
    content_hash: &str,
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

    // The finding's one-line title is its own `title`, or its `summary` when it
    // names none.
    let title = interpolate(spec.title.as_deref().unwrap_or(spec.summary.as_str()), env)?;
    let severity = spec.severity.into_model();
    let confidence = spec
        .confidence
        .as_deref()
        .and_then(wire::confidence)
        .unwrap_or(Confidence::Certain);
    let class = flow.detection.capabilities.class.into_model();

    let mut finding = Finding::new(detection, title, severity, confidence, class).ok()?;

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

/// Substitutes each `{ident}` in `template` for the variable's value. [`None`] if
/// a name is unbound, or the braces are unbalanced, the caller drops the field
/// rather than emit a half-built one.
fn interpolate(template: &str, env: &Env) -> Option<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let close = after.find('}')?;
        out.push_str(env.get(&after[..close])?);
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// Decodes bytes as Latin-1, each byte its own code point, so a probe reply is
/// a string a byte-oriented pattern can match without a lossy conversion eating
/// the bytes it looks for.
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| byte as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::finding::{Reference, Severity};

    fn flow(name: &str) -> FlowDetection {
        let path = format!("assets/detect/{name}.toml");
        let toml = std::fs::read_to_string(&path).expect("the example flow file");
        toml::from_str(&toml).expect("a valid flow")
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

    #[test]
    fn a_send_template_resolves_the_seeded_host_and_port() {
        // A one-step flow whose probe interpolates both seeded variables. The
        // reply confirms the version bind, so the flow reaches its finding; the
        // point of the test is the bytes the probe was handed, not the finding.
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

    /// The Phase-1 corpus, each flow against a reply that should confirm it. It
    /// loads the shipped file rather than a fixture, so the assertion is about the
    /// detection that ships, and it drives the interpreter directly with a canned
    /// reply, so a service that is awkward to stand up (memcached, CouchDB,
    /// Elasticsearch) is covered the same way a web one is.
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
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[\"_users\",\"_replicator\"]",
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
                // The bytes of an OP_MSG listDatabases reply matter only in that
                // they carry the field the flow matches.
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
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"repositories\":[\"alpine\",\"nginx\"]}",
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
                b"Zookeeper version: 3.8.0-abc, built on 2024-01-01\nClients:\n /10.0.0.9:52111[1]\nMode: standalone\n",
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

    /// No shipped flow may fire on a bare 404: a nothing-page confirms nothing,
    /// and a flow whose `expect` fails halts with nothing. Checked over the whole
    /// corpus rather than a named list, so the property holds for every flow and a
    /// new one is covered without editing this test. The tailored per-service
    /// denials, a 530 or a rejected bind or a 403, are their own tests below,
    /// because each needs a reply shaped like the service it denies.
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

    /// The two panel checks that turn on a 200 against a server that authenticates
    /// instead: a Jenkins that redirects anonymous reads to a 403 still stamps its
    /// X-Jenkins header, and a Kubernetes API that denies system:anonymous answers
    /// 403 with a Status body that still names the kind. Neither may fire, because
    /// the finding is anonymous *access*, not the mere presence of the software.
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

    /// The four request-response enumeration flows against a same-protocol reply
    /// that denies rather than a bare 404: a server that refuses anonymous FTP, an
    /// LDAP bind rejected, a VNC server offering only a password, and a DNS server
    /// that returns no answer. None may fire, because a password-guarded service
    /// read as open is the false positive that would make the set unsafe by
    /// default.
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
        let redis = flow("redis-unauth");
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
        let redis = flow("redis-unauth");
        // No "# Server" line, so the step's `expect` gate fails and the flow halts.
        let mut probe = Canned(b"-ERR NOAUTH Authentication required".to_vec());

        assert!(run(&redis, "", &seed(), &mut probe).is_empty());
    }

    /// A probe standing in for an SNMP agent that accepts only the `public`
    /// community. It answers a well-formed GetRequest carrying the sysDescr OID and
    /// the `public` community with a GetResponse (PDU tag `\xa2`); every other
    /// probe gets a report PDU (`\xa3`), which the `\xa2` gate rejects. The check
    /// is on the packet decoding, not on a substring, so a malformed probe that
    /// merely mentioned a community would not be answered.
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

        // 8.10.0 is newer than 8.3.1, a lexical `<` would misread it as
        // affected (10 < 3 as strings) and probe a patched server; the
        // version-compare guard skips the step, so no finding and no traversal.
        let mut patched = Grafana {
            banner: b"HTTP/1.1 200 OK\r\nX-Grafana: Grafana v8.10.0\r\n\r\n",
            leak: b"root:x:0:0:should-never-be-sent",
        };
        assert!(run(&grafana, "", &seed(), &mut patched).is_empty());

        // Not Grafana at all: `bound(version)` is false, so the guard skips the
        // step before the version comparison is even reached.
        let mut other = Grafana {
            banner: b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
            leak: b"root:x:0:0:should-never-be-sent",
        };
        assert!(run(&grafana, "", &seed(), &mut other).is_empty());
    }

    #[test]
    fn run_does_not_probe_past_the_step_ceiling() {
        // The validator rejects a flow over the ceiling at build, but `run` is
        // public and a caller can hand it one that never went through the
        // validator. It must still refuse to probe past the bound.
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
