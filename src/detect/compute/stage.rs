// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Running compute detections over a port
//!
//! The Tier-2 detection stage, the sibling of [`flow::stage`](crate::detect::flow)
//! and the active counterpart to the [CVE correlator](crate::cve). For a port,
//! every loaded detection whose class the [envelope](crate::config::DetectionEnvelope)
//! permits and whose `when` rule fits is instantiated under its
//! [grant](Grant) and run, and the findings it returns are recorded. It gates on
//! exactly the two questions the [`gate`](crate::detect::gate) module answers, so
//! a compute detection and a flow select ports the same way.
//!
//! ## The capabilities are supplied per port
//!
//! Like the flow stage, this holds no socket of its own: `caps_for` yields the
//! [`Capabilities`] a running detection is served, given the grant it will run
//! under, so a scan hands it a live socket bound to the port and a test hands it a
//! recorded one — the module cannot tell, which is the whole of replay.
//!
//! ## An abnormal end is not a finding
//!
//! A detection that trapped on a budget, was denied a call, or faulted did not
//! *clear* the port — it did not finish. That outcome is logged and dropped, never
//! turned into a finding, so a reader never mistakes "ran out of fuel" for "found
//! nothing wrong."

use tracing::debug;

use crate::config::DetectionEnvelope;
use crate::detect::manifest::DetectionManifest;
use crate::fingerprint::PortContext;
use crate::model::finding::Finding;
use crate::model::port::Protocol;

use super::capability::{Capabilities, Grant};
use super::replay::{CapTape, RecordedCapabilities, RecordingCapabilities};
use super::runtime::ComputeRuntime;

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

    /// The content hash of the detection body, its provenance and the key a
    /// journalled run is matched back to for replay.
    pub(crate) fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// What the detection declares. Used by tests to find a shipped detection by
    /// name; the live path matches a run to its detection by content hash instead.
    #[cfg(test)]
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
/// to skip it. A detection the envelope forbids or whose gate does not fit the
/// port never instantiates.
///
/// Every run is recorded, and its [`CapTape`] is handed to `record` once the run
/// ends, clean or not, so a caller can keep it for a later replay. A caller that
/// does not want the tapes ignores them.
// Eight inputs: the whole per-port situation plus both capability seams. Bundling
// them into a request type is a later cleanup shared with the flow stage.
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
) -> Vec<Finding> {
    let mut findings = Vec::new();
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
            Err(outcome) => debug!(
                detection = grant.detection.id(),
                ?outcome,
                "a compute detection ended without a clean result"
            ),
        }
        record(&grant, recording.into_tape());
    }
    findings
}

/// Replays one detection over a recorded [`CapTape`], reproducing the findings the
/// recorded run produced with no network.
///
/// Where [`detect_port`] serves a live socket, this serves the tape, so the same
/// module reads the same bytes and reaches the same verdict offline. It does not
/// gate on the envelope: the run already happened and passed the gate live, so this
/// reproduces it rather than deciding again.
pub(crate) fn replay_over_tape<R: ComputeRuntime>(
    runtime: &R,
    detection: &LoadedDetection<R::Module>,
    ctx: &PortContext,
    responses: &[&[u8]],
    tape: CapTape,
) -> Vec<Finding> {
    let Some(grant) = Grant::from_manifest(&detection.manifest, &detection.content_hash) else {
        return Vec::new();
    };
    let Ok(mut instance) = runtime.instantiate(&detection.module, &grant) else {
        return Vec::new();
    };
    let mut caps = RecordedCapabilities::from_tape(tape);
    runtime
        .run(&mut instance, ctx, responses, &mut caps)
        .unwrap_or_default()
}

/// Whether any loaded detection the envelope permits gates onto a port with these
/// facts, so a caller can skip a port no compute detection would run over.
pub(crate) fn interested<M>(
    detections: &[LoadedDetection<M>],
    envelope: &DetectionEnvelope,
    service: Option<&str>,
    number: u16,
    protocol: Protocol,
) -> bool {
    detections.iter().any(|detection| {
        Grant::from_manifest(&detection.manifest, &detection.content_hash).is_some_and(|grant| {
            envelope.permits(grant.class)
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

    /// A stand-in socket that answers every probe with one banner, so an active
    /// detection has something to decide on and a passive one ignores it.
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

    /// A passive detection that fires whenever it runs, so a finding is proof the
    /// stage chose to run it.
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
            id: id.to_string(),
            version: "1.0.0".to_string(),
            title: id.to_string(),
            when: Rule {
                service: Some(service.to_string()),
                port: None,
                ports: Vec::new(),
                protocol: None,
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
        );

        assert_eq!(findings.len(), 1, "only the redis gate fit the port");
        assert_eq!(findings[0].detection().id(), "redis-check");
    }

    #[test]
    fn the_envelope_decides_whether_an_intrusive_detection_runs() {
        let runtime = RhaiRuntime::new();
        let detections = vec![loaded(&runtime, "exploit", "redis", Class::Exploit, ALWAYS)];

        // Off by default: the exploit class is above the default ceiling.
        let withheld = detect_port(
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
            withheld.is_empty(),
            "an exploit ran under the default envelope"
        );

        // The operator raises the ceiling to it, and the same detection runs.
        let permitted = detect_port(
            &runtime,
            &detections,
            &DetectionEnvelope::up_to(DetectionClass::Exploit),
            Some("redis"),
            &ctx(6379),
            &[],
            |_grant| Some(Box::new(StubCaps)),
            |_, _| {},
        );
        assert_eq!(permitted.len(), 1, "an opted-in exploit did not run");
    }

    #[test]
    fn an_active_detection_is_served_its_socket_and_decides_on_the_reply() {
        let runtime = RhaiRuntime::new();
        // Speaks, and fires only because the stub answered.
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
            &DetectionEnvelope::default(),
            Some("redis"),
            &ctx(6379),
            &[],
            |_grant| Some(Box::new(StubCaps)),
            |_, _| {},
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity(), Severity::High);
    }

    #[test]
    fn a_passive_detection_that_reaches_for_speak_produces_nothing() {
        // The grant gives a passive detection no `speak`, so a passive body that
        // names it faults and emits nothing — the class enforced at the stage.
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
        );

        assert!(
            findings.is_empty(),
            "a passive detection reached the network"
        );
    }

    #[test]
    fn a_run_is_recorded_and_its_tape_handed_back() {
        // An active detection that speaks once. The tape the stage captures must
        // hold that exchange, so a later replay can reproduce the run.
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
            &DetectionEnvelope::default(),
            Some("redis"),
            &ctx(6379),
            &[],
            |_grant| Some(Box::new(StubCaps)),
            |_grant, tape| tapes.push(tape),
        );

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
        // The offline replay: an active detection that decides on a socket reply is
        // reproduced from its tape alone, no network. The recorded reply drives the
        // finding exactly as the live one did.
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

        let findings = replay_over_tape(&runtime, &detection, &ctx(6379), &[], tape);
        assert_eq!(findings.len(), 1, "the recorded run did not replay");
        assert_eq!(findings[0].severity(), Severity::High);
    }
}
