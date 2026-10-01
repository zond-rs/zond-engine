// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Running compute detections over a port
//!
//! The Tier-2 detection stage, beside [`flow::stage`](crate::detect::flow). For a
//! port, every detection whose class the
//! [envelope](crate::config::DetectionEnvelope) permits and whose `when` rule
//! fits (see [`gate`](crate::detect::gate)) is instantiated under its
//! [grant](Grant) and run.
//!
//! ## Capabilities per port
//!
//! `caps_for` yields the [`Capabilities`] for a grant: a live socket in a scan,
//! a recorded one in a test or replay.
//!
//! ## An abnormal end is not a finding
//!
//! A detection that trapped on a budget, was denied a call, or faulted is
//! returned as an [`InconclusiveRun`], never as a finding.

use std::time::Duration;

use tracing::debug;

use crate::config::DetectionEnvelope;
use crate::detect::manifest::DetectionManifest;
use crate::fingerprint::PortContext;
use crate::model::finding::{DetectionId, Finding};
use crate::model::port::Protocol;

use super::budget::{Budget, RunOutcome};
use super::capability::{Capabilities, Grant};
use super::db::ReplayError;
use super::replay::{CapTape, RecordedCapabilities, RecordingCapabilities};
use super::runtime::ComputeRuntime;

/// A compute detection that did not finish cleanly: which detection, and why.
/// Returned beside the findings, since such a run did not clear the port.
pub(crate) struct InconclusiveRun {
    /// The detection whose run did not complete.
    pub(crate) detection: DetectionId,
    /// Why it did not complete.
    pub(crate) outcome: RunOutcome,
    /// The bounds it ran under, so a report can say how large the one it hit
    /// was.
    pub(crate) budget: Budget,
}

/// What a port's compute detections produced: the findings, and the runs that did
/// not finish cleanly.
pub(crate) struct PortDetections {
    /// The findings the detections drew.
    pub(crate) findings: Vec<Finding>,
    /// The runs that ended abnormally.
    pub(crate) inconclusive: Vec<InconclusiveRun>,
}

/// A compute detection compiled and ready to run: its [`DetectionManifest`],
/// its compiled module, and the content hash of the body it came from, which
/// its findings are stamped with as provenance.
pub struct LoadedDetection<M> {
    manifest: DetectionManifest,
    module: M,
    content_hash: String,
}

impl<M> LoadedDetection<M> {
    /// A loaded detection from its parts. The `content_hash` is the body's content
    /// address, computed by whatever sourced it.
    pub fn new(manifest: DetectionManifest, module: M, content_hash: impl Into<String>) -> Self {
        Self {
            manifest,
            module,
            content_hash: content_hash.into(),
        }
    }

    /// The content hash of the detection body: its provenance, and the key
    /// replay matches a journalled run by.
    pub(crate) fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// What the detection declares, for corpus listings and tests.
    pub(crate) fn manifest(&self) -> &DetectionManifest {
        &self.manifest
    }
}

/// Runs `detections` over one port, returning the findings they produce.
///
/// `service` is the port's identified service, which the `when` rule may gate on;
/// `ctx` carries the port number, protocol, and address a running detection sees;
/// `responses` are the bytes the scan already gathered. `caps_for` yields the
/// [`Capabilities`] a detection is served under the grant it will run, or [`None`]
/// to skip it. A detection the envelope forbids or whose gate does not fit never
/// instantiates.
///
/// Every run's [`CapTape`] is handed to `record` when it ends, for a later
/// replay.
///
/// A run that ends abnormally is returned in [`PortDetections::inconclusive`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn detect_port<R: ComputeRuntime>(
    runtime: &R,
    detections: &[LoadedDetection<R::Module>],
    envelope: &DetectionEnvelope,
    service: Option<&str>,
    ctx: &PortContext,
    responses: &[&[u8]],
    mut caps_for: impl FnMut(&Grant) -> Option<Box<dyn Capabilities>>,
    mut record: impl FnMut(&Grant, CapTape),
) -> PortDetections {
    let mut findings = Vec::new();
    let mut inconclusive = Vec::new();
    for detection in detections {
        let Some(grant) = Grant::from_manifest(&detection.manifest, &detection.content_hash) else {
            continue;
        };
        if !envelope.permits(grant.class)
            || !detection
                .manifest
                .when
                .applies(service, ctx.port, ctx.protocol)
        {
            continue;
        }

        let mut instance = match runtime.instantiate(&detection.module, &grant) {
            Ok(instance) => instance,
            Err(error) => {
                debug!(
                    detection = grant.detection.id(),
                    ?error,
                    "a compute detection could not be instantiated"
                );
                continue;
            }
        };
        let Some(caps) = caps_for(&grant) else {
            continue;
        };
        let mut recording = RecordingCapabilities::new(caps);

        match runtime.run(&mut instance, ctx, responses, &mut recording) {
            Ok(produced) => findings.extend(produced),
            Err(outcome) => {
                debug!(
                    detection = grant.detection.id(),
                    ?outcome,
                    "a compute detection ended without a clean result"
                );
                inconclusive.push(InconclusiveRun {
                    detection: grant.detection.clone(),
                    outcome,
                    budget: grant.budget,
                });
            }
        }
        record(&grant, recording.into_tape());
    }
    PortDetections {
        findings,
        inconclusive,
    }
}

/// Replays one detection over a recorded [`CapTape`], reproducing the findings the
/// recorded run produced with no network.
///
/// Serves the tape where [`detect_port`] serves a live socket. Does not gate on
/// the envelope, since the live run already passed it.
pub(crate) fn replay_over_tape<R: ComputeRuntime>(
    runtime: &R,
    detection: &LoadedDetection<R::Module>,
    ctx: &PortContext,
    responses: &[&[u8]],
    tape: CapTape,
) -> Result<Vec<Finding>, ReplayError> {
    let Some(mut grant) = Grant::from_manifest(&detection.manifest, &detection.content_hash) else {
        return Err(ReplayError::GrantFailed);
    };
    // No wall-clock deadline offline, so a slow replay host cannot trap a run the
    // recording did not. Fuel still bounds it.
    grant.budget.deadline = Duration::from_secs(86_400);
    let mut instance = runtime
        .instantiate(&detection.module, &grant)
        .map_err(ReplayError::Instantiate)?;
    let mut caps = RecordedCapabilities::from_tape(tape);
    let findings = runtime
        .run(&mut instance, ctx, responses, &mut caps)
        .map_err(ReplayError::Run)?;
    // Reading past the tape's end means the replay diverged.
    if caps.diverged() {
        return Err(ReplayError::Diverged);
    }
    Ok(findings)
}

/// Whether any loaded detection the envelope permits gates onto a port with these
/// facts, so a caller can skip a port no compute detection would run over.
pub(crate) fn interested<M>(
    detections: &[LoadedDetection<M>],
    envelope: &DetectionEnvelope,
    service: Option<&str>,
    number: u16,
    protocol: Protocol,
    require_speak: bool,
) -> bool {
    detections.iter().any(|detection| {
        Grant::from_manifest(&detection.manifest, &detection.content_hash).is_some_and(|grant| {
            envelope.permits(grant.class)
                && (!require_speak || grant.speak)
                && detection.manifest.when.applies(service, number, protocol)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::compute::{CapError, ModuleBody, RhaiRuntime, ScanInstant};
    use crate::detect::manifest::{CapabilitySpec, Class, Rule, Speak};
    use crate::model::finding::{DetectionClass, Severity};
    use crate::model::port::Protocol;
    use std::net::IpAddr;

    /// A stand-in socket that answers every probe with one banner.
    struct StubCaps;
    impl Capabilities for StubCaps {
        fn speak(&mut self, _bytes: &[u8]) -> Result<Vec<u8>, CapError> {
            Ok(b"# Server".to_vec())
        }
        fn resolve(&mut self, _name: &str) -> Result<Vec<IpAddr>, CapError> {
            Ok(Vec::new())
        }
        fn now(&mut self) -> ScanInstant {
            ScanInstant::from_millis(0)
        }
    }

    /// A passive detection that fires whenever it runs.
    const ALWAYS: &str = r#"
        fn analyze(ctx, responses) {
            [ #{ severity: "medium", summary: "port " + ctx.port } ]
        }
    "#;

    fn loaded(
        runtime: &RhaiRuntime,
        id: &str,
        service: &str,
        class: Class,
        source: &str,
    ) -> LoadedDetection<<RhaiRuntime as ComputeRuntime>::Module> {
        let manifest = DetectionManifest {
            group: None,
            id: id.to_string(),
            version: "1.0.0".to_string(),
            title: id.to_string(),
            when: Rule {
                service: Some(service.to_string()),
                services: Vec::new(),
                port: None,
                ports: Vec::new(),
                protocol: None,
                speaks: None,
            },
            capabilities: CapabilitySpec {
                class,
                speak: Some(Speak::Target),
                resolve: false,
                max_bytes: None,
                max_millis: None,
                max_connections: None,
            },
        };
        let module = runtime
            .load(&ModuleBody::Rhai(source.to_string()))
            .expect("the module compiles");
        LoadedDetection::new(manifest, module, "hash")
    }

    fn ctx(port: u16) -> PortContext {
        PortContext {
            port,
            protocol: Protocol::Tcp,
            addr: None,
            tunnel: None,
            speaks_http: false,
            detection: crate::config::ServiceDetection::default(),
            host_name: None,
        }
    }

    #[test]
    fn only_the_detection_whose_gate_fits_the_port_runs() {
        let runtime = RhaiRuntime::new();
        let detections = vec![
            loaded(&runtime, "redis-check", "redis", Class::Passive, ALWAYS),
            loaded(&runtime, "http-check", "http", Class::Passive, ALWAYS),
        ];

        let findings = detect_port(
            &runtime,
            &detections,
            &DetectionEnvelope::default(),
            Some("redis"),
            &ctx(6379),
            &[],
            |_grant| Some(Box::new(StubCaps)),
            |_, _| {},
        )
        .findings;

        assert_eq!(findings.len(), 1, "only the redis gate fit the port");
        assert_eq!(findings[0].detection().id(), "redis-check");
    }

    #[test]
    fn the_envelope_decides_whether_an_intrusive_detection_runs() {
        let runtime = RhaiRuntime::new();
        let detections = vec![loaded(&runtime, "exploit", "redis", Class::Exploit, ALWAYS)];

        // The exploit class is above the default ceiling.
        let withheld = detect_port(
            &runtime,
            &detections,
            &DetectionEnvelope::default(),
            Some("redis"),
            &ctx(6379),
            &[],
            |_grant| Some(Box::new(StubCaps)),
            |_, _| {},
        )
        .findings;
        assert!(
            withheld.is_empty(),
            "an exploit ran under the default envelope"
        );

        // Raised to it, the detection runs.
        let permitted = detect_port(
            &runtime,
            &detections,
            &DetectionEnvelope::up_to(DetectionClass::Exploit),
            Some("redis"),
            &ctx(6379),
            &[],
            |_grant| Some(Box::new(StubCaps)),
            |_, _| {},
        )
        .findings;
        assert_eq!(permitted.len(), 1, "an opted-in exploit did not run");
    }

    #[test]
    /// The envelope is set explicitly: the default permits no connections.
    fn an_active_detection_is_served_its_socket_and_decides_on_the_reply() {
        let runtime = RhaiRuntime::new();
        // Fires only on the stub's answer.
        let source = r#"
            fn analyze(ctx, responses) {
                let reply = speak(blob(1, 0x41));
                if reply.len() > 0 {
                    [ #{ severity: "high", summary: "the port answered" } ]
                } else {
                    []
                }
            }
        "#;
        let detections = vec![loaded(
            &runtime,
            "active",
            "redis",
            Class::ActiveBenign,
            source,
        )];

        let findings = detect_port(
            &runtime,
            &detections,
            &DetectionEnvelope::up_to(DetectionClass::ActiveBenign),
            Some("redis"),
            &ctx(6379),
            &[],
            |_grant| Some(Box::new(StubCaps)),
            |_, _| {},
        )
        .findings;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity(), Severity::High);
    }

    #[test]
    fn a_passive_detection_that_reaches_for_speak_produces_nothing() {
        // A passive body naming `speak` faults and emits nothing.
        let runtime = RhaiRuntime::new();
        let source = r#"
            fn analyze(ctx, responses) {
                speak(blob(1, 0x41));
                [ #{ severity: "high", summary: "should never be reached" } ]
            }
        "#;
        let detections = vec![loaded(&runtime, "sneaky", "redis", Class::Passive, source)];

        let findings = detect_port(
            &runtime,
            &detections,
            &DetectionEnvelope::default(),
            Some("redis"),
            &ctx(6379),
            &[],
            |_grant| Some(Box::new(StubCaps)),
            |_, _| {},
        )
        .findings;

        assert!(
            findings.is_empty(),
            "a passive detection reached the network"
        );
    }

    #[test]
    /// The envelope is set explicitly, as above.
    fn a_run_is_recorded_and_its_tape_handed_back() {
        // An active detection that speaks once; the tape holds the exchange.
        let runtime = RhaiRuntime::new();
        let source = r#"
            fn analyze(ctx, responses) {
                let reply = speak(blob(1, 0x41));
                if reply.len() > 0 {
                    [ #{ severity: "high", summary: "the port answered" } ]
                } else {
                    []
                }
            }
        "#;
        let detections = vec![loaded(
            &runtime,
            "active",
            "redis",
            Class::ActiveBenign,
            source,
        )];

        let mut tapes = Vec::new();
        let findings = detect_port(
            &runtime,
            &detections,
            &DetectionEnvelope::up_to(DetectionClass::ActiveBenign),
            Some("redis"),
            &ctx(6379),
            &[],
            |_grant| Some(Box::new(StubCaps)),
            |_grant, tape| tapes.push(tape),
        )
        .findings;

        assert_eq!(findings.len(), 1);
        assert_eq!(tapes.len(), 1, "the run's tape was not handed back");
        assert_eq!(tapes[0].speaks.len(), 1, "the speak was not recorded");
        assert_eq!(
            tapes[0].speaks[0].reply,
            Ok(b"# Server".to_vec()),
            "the recorded reply is not what the socket returned"
        );
    }

    #[test]
    fn a_recorded_run_replays_an_active_detection_offline() {
        // An active detection reproduced from its tape alone.
        use crate::detect::compute::SpeakExchange;

        let runtime = RhaiRuntime::new();
        let source = r#"
            fn analyze(ctx, responses) {
                let reply = speak(blob(1, 0x41));
                if reply.len() > 0 {
                    [ #{ severity: "high", summary: "the port answered" } ]
                } else {
                    []
                }
            }
        "#;
        let detection = loaded(&runtime, "active", "redis", Class::ActiveBenign, source);
        let tape = CapTape {
            speaks: vec![SpeakExchange {
                sent: vec![0x41],
                reply: Ok(b"# Server".to_vec()),
            }],
            ..Default::default()
        };

        let findings = replay_over_tape(&runtime, &detection, &ctx(6379), &[], tape)
            .expect("the recorded run replays");
        assert_eq!(findings.len(), 1, "the recorded run did not replay");
        assert_eq!(findings[0].severity(), Severity::High);
    }

    #[test]
    fn a_replay_over_a_short_tape_reports_divergence_rather_than_a_finding() {
        // A module speaking twice against a one-entry tape diverges.
        use crate::detect::compute::SpeakExchange;
        let runtime = RhaiRuntime::new();
        let source = r#"
            fn analyze(ctx, responses) {
                let a = speak(blob(1, 0x41));
                let b = speak(blob(1, 0x42));
                if a.len() > 0 && b.len() > 0 {
                    [ #{ severity: "high", summary: "both answered" } ]
                } else {
                    []
                }
            }
        "#;
        let detection = loaded(&runtime, "two-speaks", "redis", Class::ActiveBenign, source);
        let short = CapTape {
            speaks: vec![SpeakExchange {
                sent: vec![0x41],
                reply: Ok(b"yes".to_vec()),
            }],
            ..Default::default()
        };

        let outcome = replay_over_tape(&runtime, &detection, &ctx(6379), &[], short);
        assert_eq!(
            outcome,
            Err(ReplayError::Diverged),
            "a short tape must report divergence, not a clean empty run"
        );
    }

    #[test]
    fn a_faulting_detection_is_returned_as_inconclusive_not_a_finding() {
        // A module that throws is returned as an inconclusive run.
        let runtime = RhaiRuntime::new();
        let source = r#"
            fn analyze(ctx, responses) {
                throw "deliberate fault";
            }
        "#;
        let detections = vec![loaded(&runtime, "faulty", "redis", Class::Passive, source)];

        let result = detect_port(
            &runtime,
            &detections,
            &DetectionEnvelope::default(),
            Some("redis"),
            &ctx(6379),
            &[],
            |_grant| Some(Box::new(StubCaps)),
            |_, _| {},
        );

        assert!(
            result.findings.is_empty(),
            "a fault must not be reported as a finding"
        );
        assert_eq!(result.inconclusive.len(), 1, "the fault was not surfaced");
        assert_eq!(result.inconclusive[0].detection.id(), "faulty");
        assert!(
            matches!(result.inconclusive[0].outcome, RunOutcome::Faulted(_)),
            "the outcome was not a fault: {:?}",
            result.inconclusive[0].outcome
        );
    }
}
