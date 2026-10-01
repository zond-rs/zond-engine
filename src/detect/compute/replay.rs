// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Recording a run, and replaying it
//!
//! A module reaches the world only through its [`Capabilities`], so a run is a
//! pure function of what they returned. A [`CapTape`] captures every return:
//! [`RecordingCapabilities`] writes one around a live set, and
//! [`RecordedCapabilities`] serves it back offline, reproducing the findings
//! exactly. That allows offline re-analysis, deterministic tests, and showing
//! the exact bytes a detection decided on.
//!
//! ## What is captured
//!
//! Each verb in call order: [`speak`](Capabilities::speak) with bytes sent and
//! reply (or error), [`resolve`](Capabilities::resolve) with name and result,
//! and [`now`](Capabilities::now) ticks. Replay serves each verb from its own
//! queue in order. The bytes a `speak` sent are kept for provenance; positional
//! replay does not compare them.
//!
//! The journal form is in the sibling `record` module.

use std::net::IpAddr;

use super::capability::{CapError, Capabilities, ScanInstant};

/// One [`speak`](Capabilities::speak) as it happened: the bytes the module sent and
/// the reply it got back, error included.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeakExchange {
    /// The bytes the module sent. Kept for provenance; positional replay does not
    /// compare them.
    pub sent: Vec<u8>,
    /// The reply the module received, returned verbatim on replay.
    pub reply: Result<Vec<u8>, CapError>,
}

/// One [`resolve`](Capabilities::resolve) as it happened: the name asked and the
/// addresses (or error) returned.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveExchange {
    /// The name the module asked to resolve. Kept for provenance.
    pub name: String,
    /// The result the module received, returned verbatim on replay.
    pub result: Result<Vec<IpAddr>, CapError>,
}

/// Every capability interaction of one run, in call order per verb.
///
/// Everything a run read from the world; a [`RecordedCapabilities`] built from
/// it reproduces the run exactly.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapTape {
    /// Each `speak`, in the order the module made them.
    pub speaks: Vec<SpeakExchange>,
    /// Each `resolve`, in order.
    pub resolves: Vec<ResolveExchange>,
    /// Each `now` tick the module read, in order, as milliseconds on the run's clock.
    pub nows: Vec<u64>,
}

/// A live capability set that writes a [`CapTape`] as it serves.
///
/// Forwards every call to the wrapped [`Capabilities`] and appends what crossed
/// the seam to the tape. Wrap [`LiveCapabilities`](super::LiveCapabilities) to
/// capture a real scan.
pub struct RecordingCapabilities<C: Capabilities> {
    inner: C,
    tape: CapTape,
}

impl<C: Capabilities> RecordingCapabilities<C> {
    /// A recorder wrapping `inner`, starting from an empty tape.
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            tape: CapTape::default(),
        }
    }

    /// The tape written so far, without ending the recording.
    pub fn tape(&self) -> &CapTape {
        &self.tape
    }

    /// Consume the recorder and take the tape, once the run is done.
    pub fn into_tape(self) -> CapTape {
        self.tape
    }
}

impl<C: Capabilities> Capabilities for RecordingCapabilities<C> {
    fn speak(&mut self, bytes: &[u8]) -> Result<Vec<u8>, CapError> {
        let reply = self.inner.speak(bytes);
        self.tape.speaks.push(SpeakExchange {
            sent: bytes.to_vec(),
            reply: reply.clone(),
        });
        reply
    }

    fn resolve(&mut self, name: &str) -> Result<Vec<IpAddr>, CapError> {
        let result = self.inner.resolve(name);
        self.tape.resolves.push(ResolveExchange {
            name: name.to_string(),
            result: result.clone(),
        });
        result
    }

    fn now(&mut self) -> ScanInstant {
        let instant = self.inner.now();
        self.tape.nows.push(instant.millis());
        instant
    }
}

/// A capability set that serves a finished [`CapTape`] with no network.
///
/// Each verb draws from its own queue in call order. No budget is enforced; the
/// tape holds the outcomes the live budget produced.
///
/// A call past the end of a queue means the run diverged. It returns a benign
/// default (an empty reply, a zero tick), and `diverged` reports it afterwards.
pub struct RecordedCapabilities {
    tape: CapTape,
    speak_cursor: usize,
    resolve_cursor: usize,
    now_cursor: usize,
    diverged: bool,
}

impl RecordedCapabilities {
    /// A replay of `tape`.
    pub fn from_tape(tape: CapTape) -> Self {
        Self {
            tape,
            speak_cursor: 0,
            resolve_cursor: 0,
            now_cursor: 0,
            diverged: false,
        }
    }

    /// The tape being replayed, for a caller that wants to read what it holds.
    pub fn tape(&self) -> &CapTape {
        &self.tape
    }

    /// Whether the replay read past the end of the tape at any verb.
    pub fn diverged(&self) -> bool {
        self.diverged
    }
}

impl Capabilities for RecordedCapabilities {
    fn speak(&mut self, _bytes: &[u8]) -> Result<Vec<u8>, CapError> {
        let exchange = self.tape.speaks.get(self.speak_cursor);
        self.speak_cursor += 1;
        match exchange {
            Some(exchange) => exchange.reply.clone(),
            None => {
                self.diverged = true;
                Ok(Vec::new())
            }
        }
    }

    fn resolve(&mut self, _name: &str) -> Result<Vec<IpAddr>, CapError> {
        let exchange = self.tape.resolves.get(self.resolve_cursor);
        self.resolve_cursor += 1;
        match exchange {
            Some(exchange) => exchange.result.clone(),
            None => {
                self.diverged = true;
                Ok(Vec::new())
            }
        }
    }

    fn now(&mut self) -> ScanInstant {
        let millis = self.tape.nows.get(self.now_cursor).copied();
        self.now_cursor += 1;
        match millis {
            Some(millis) => ScanInstant::from_millis(millis),
            None => {
                self.diverged = true;
                ScanInstant::from_millis(0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::compute::{
        Budget, ComputeRuntime, Grant, LiveCapabilities, ModuleBody, RhaiRuntime,
    };
    use crate::fingerprint::PortContext;
    use crate::model::finding::{DetectionClass, DetectionId, Severity, Version};
    use crate::model::port::Protocol;
    use crate::testing::loopback::from_this_process;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    fn budget() -> Budget {
        Budget {
            fuel: 1_000_000,
            deadline: Duration::from_secs(2),
            max_memory: 65_536,
            max_bytes: 8_192,
            max_connections: 4,
        }
    }

    fn grant() -> Grant {
        Grant {
            group: None,
            detection: DetectionId::new("replay-test", Version::new(1, 0, 0), "hash").unwrap(),
            class: DetectionClass::ActiveBenign,
            budget: budget(),
            speak: true,
            resolve: false,
        }
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
    fn a_live_run_replays_byte_identically_from_its_tape() {
        // A loopback that answers with a banner.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Some(mut sock) = from_this_process(&listener).next() {
                let mut probe = [0u8; 64];
                let _ = sock.read(&mut probe);
                let _ = sock.write_all(b"redis_version:7.2.4");
            }
        });

        // The finding depends on both the reply and the clock.
        let source = r#"
            fn analyze(ctx, responses) {
                let reply = speak(blob(4, 0x41));
                [ #{
                    severity: "medium",
                    summary: "answered " + text(reply) + " at " + now(),
                } ]
            }
        "#;

        let runtime = RhaiRuntime::new();
        let module = runtime
            .load(&ModuleBody::Rhai(source.to_string()))
            .expect("the module compiles");

        // Live, recording.
        let mut recording =
            RecordingCapabilities::new(LiveCapabilities::new(addr, Protocol::Tcp, None, &budget()));
        let mut instance = runtime
            .instantiate(&module, &grant())
            .expect("instantiates");
        let live = runtime
            .run(&mut instance, &ctx(addr.port()), &[], &mut recording)
            .expect("a clean live run");
        let tape = recording.into_tape();

        assert_eq!(tape.speaks.len(), 1, "the speak was not recorded");
        assert!(!tape.nows.is_empty(), "the clock read was not recorded");

        // From the tape alone.
        let mut replayed_caps = RecordedCapabilities::from_tape(tape);
        let mut instance = runtime
            .instantiate(&module, &grant())
            .expect("instantiates");
        let replayed = runtime
            .run(&mut instance, &ctx(addr.port()), &[], &mut replayed_caps)
            .expect("a clean replay");

        assert_eq!(
            live, replayed,
            "the replay did not reproduce the live findings"
        );
    }

    #[test]
    fn a_recorded_now_tick_replays_from_the_tape() {
        // Replay serves the recorded tick, not a fresh clock.
        let tape = CapTape {
            nows: vec![4242],
            ..CapTape::default()
        };
        let source = r#"
            fn analyze(ctx, responses) {
                [ #{ severity: "info", summary: "read at " + now() } ]
            }
        "#;

        let runtime = RhaiRuntime::new();
        let module = runtime
            .load(&ModuleBody::Rhai(source.to_string()))
            .expect("the module compiles");
        let mut instance = runtime
            .instantiate(&module, &grant())
            .expect("instantiates");
        let mut caps = RecordedCapabilities::from_tape(tape);

        let findings = runtime
            .run(&mut instance, &ctx(80), &[], &mut caps)
            .expect("a clean run");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].title().contains("4242"),
            "the clock tick was not served from the tape: {}",
            findings[0].title()
        );
    }

    #[test]
    fn a_recorded_error_reply_replays_as_the_same_error() {
        // A recorded refusal takes the module's error branch again.
        let tape = CapTape {
            speaks: vec![SpeakExchange {
                sent: b"x".to_vec(),
                reply: Err(CapError::ConnectionRefused),
            }],
            ..CapTape::default()
        };

        // In Rhai `try`/`catch` is a statement evaluating to unit, so the finding
        // is built after it.
        let source = r#"
            fn analyze(ctx, responses) {
                let severity = "low";
                let summary = "the port answered";
                try {
                    speak(blob(1, 0x78));
                } catch (err) {
                    severity = "high";
                    summary = "the port refused the probe";
                }
                [ #{ severity: severity, summary: summary } ]
            }
        "#;

        let runtime = RhaiRuntime::new();
        let module = runtime
            .load(&ModuleBody::Rhai(source.to_string()))
            .expect("the module compiles");
        let mut instance = runtime
            .instantiate(&module, &grant())
            .expect("instantiates");
        let mut caps = RecordedCapabilities::from_tape(tape);

        let findings = runtime
            .run(&mut instance, &ctx(6379), &[], &mut caps)
            .expect("a clean run");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity(),
            Severity::High,
            "the module did not see the recorded error"
        );
    }
}
