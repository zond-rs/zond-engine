// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Recording a run, and replaying it
//!
//! A compute module reaches the world only through its [`Capabilities`], so a run
//! is a pure function of what those capabilities returned. Capture every return
//! and the run can be re-executed later with no network at all, producing the same
//! findings byte for byte. That capture is a [`CapTape`], and the two types here
//! are its ends. [`RecordingCapabilities`] wraps a live capability set and writes a
//! tape as the module runs. [`RecordedCapabilities`] serves a finished tape back so
//! the module runs again offline.
//!
//! ## What a faithful recording buys
//!
//! - Offline re-analysis: a new detection can run against a tape captured last
//!   week, whether or not the target still exists or still answers.
//! - Deterministic tests: a detection's test becomes a tape and the findings it
//!   should produce, with no live socket to flake.
//! - An answer to "why did it fire": replaying the exact bytes a detection saw
//!   shows the evidence it decided on.
//!
//! ## What is captured, and what replay does with it
//!
//! Each verb is recorded in call order: every [`speak`](Capabilities::speak) with
//! the bytes sent and the reply returned, every [`resolve`](Capabilities::resolve)
//! with its name and result, and every [`now`](Capabilities::now) tick. Replay
//! serves each verb from its own queue in order, so the same module, which makes
//! the same sequence of calls, reads back the same value at each one. A recorded
//! reply carries its error too, so a module that branches on a timeout or a refusal
//! takes the same branch on replay. The bytes a `speak` sent are kept for
//! provenance and for a future strict replay that checks them; positional replay
//! does not match on them yet.
//!
//! The tape lives in memory for now. Writing it into the journal, so a whole scan's
//! detections replay from a saved run, is the next step; the wire form the journal
//! needs will live beside the model's other recorded types.

use std::net::IpAddr;

use super::capability::{CapError, Capabilities, ScanInstant};

/// One [`speak`](Capabilities::speak) as it happened: the bytes the module sent and
/// the reply it got back, error included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeakExchange {
    /// The bytes the module sent. Kept for provenance and for a later strict replay;
    /// positional replay does not compare against it.
    pub sent: Vec<u8>,
    /// The reply the module received, which replay returns verbatim so a module that
    /// branches on an error branches the same way offline.
    pub reply: Result<Vec<u8>, CapError>,
}

/// One [`resolve`](Capabilities::resolve) as it happened: the name asked and the
/// addresses (or error) returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveExchange {
    /// The name the module asked to resolve. Kept for provenance; positional replay
    /// does not compare against it.
    pub name: String,
    /// The result the module received, returned verbatim on replay.
    pub result: Result<Vec<IpAddr>, CapError>,
}

/// Every capability interaction of one run, in call order per verb.
///
/// This is the whole of what a run read from the world. Build a
/// [`RecordedCapabilities`] from it and the run reproduces exactly, because there
/// is nothing else a module can read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapTape {
    /// Each `speak`, in the order the module made them.
    pub speaks: Vec<SpeakExchange>,
    /// Each `resolve`, in order.
    pub resolves: Vec<ResolveExchange>,
    /// Each `now` tick the module read, in order, as milliseconds on the scan clock.
    pub nows: Vec<u64>,
}

/// A live capability set that writes a [`CapTape`] as it serves.
///
/// It wraps any [`Capabilities`] and forwards every call to it, appending what
/// crossed the seam to the tape. Wrap [`LiveCapabilities`](super::LiveCapabilities)
/// with it to capture a real scan for later replay; the module it serves cannot
/// tell it is being recorded, because every return is the inner set's own.
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
/// Each verb draws from its own queue in call order, so a module that makes the
/// same sequence of calls it made when the tape was recorded reads back the same
/// value at each one. It enforces no budget: the tape already holds the outcomes a
/// budget produced live, so replay reproduces them rather than deriving them again.
///
/// A call past the end of a queue means the run diverged from the one recorded,
/// which a faithful same-module replay never does. For now that returns a benign
/// default (an empty reply, a zero tick) rather than an error; surfacing divergence
/// is a later refinement.
pub struct RecordedCapabilities {
    tape: CapTape,
    speak_cursor: usize,
    resolve_cursor: usize,
    now_cursor: usize,
}

impl RecordedCapabilities {
    /// A replay of `tape`.
    pub fn from_tape(tape: CapTape) -> Self {
        Self {
            tape,
            speak_cursor: 0,
            resolve_cursor: 0,
            now_cursor: 0,
        }
    }

    /// The tape being replayed, for a caller that wants to read what it holds.
    pub fn tape(&self) -> &CapTape {
        &self.tape
    }
}

impl Capabilities for RecordedCapabilities {
    fn speak(&mut self, _bytes: &[u8]) -> Result<Vec<u8>, CapError> {
        let exchange = self.tape.speaks.get(self.speak_cursor);
        self.speak_cursor += 1;
        match exchange {
            Some(exchange) => exchange.reply.clone(),
            None => Ok(Vec::new()),
        }
    }

    fn resolve(&mut self, _name: &str) -> Result<Vec<IpAddr>, CapError> {
        let exchange = self.tape.resolves.get(self.resolve_cursor);
        self.resolve_cursor += 1;
        match exchange {
            Some(exchange) => exchange.result.clone(),
            None => Ok(Vec::new()),
        }
    }

    fn now(&mut self) -> ScanInstant {
        let millis = self.tape.nows.get(self.now_cursor).copied();
        self.now_cursor += 1;
        ScanInstant::from_millis(millis.unwrap_or(0))
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
        }
    }

    #[test]
    fn a_live_run_replays_byte_identically_from_its_tape() {
        // A loopback that answers the module's probe with a banner, standing in for
        // the service a detection reads.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut probe = [0u8; 64];
                let _ = sock.read(&mut probe);
                let _ = sock.write_all(b"redis_version:7.2.4");
            }
        });

        // The finding depends on both the reply and the clock, so the tape must
        // carry both for the replay to reproduce it.
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

        // Run once, live, recording every call as it goes.
        let mut recording =
            RecordingCapabilities::new(LiveCapabilities::new(addr, Protocol::Tcp, &budget()));
        let mut instance = runtime
            .instantiate(&module, &grant())
            .expect("instantiates");
        let live = runtime
            .run(&mut instance, &ctx(addr.port()), &[], &mut recording)
            .expect("a clean live run");
        let tape = recording.into_tape();

        // The tape captured the one probe and at least one clock read.
        assert_eq!(tape.speaks.len(), 1, "the speak was not recorded");
        assert!(!tape.nows.is_empty(), "the clock read was not recorded");

        // Run again from the tape alone, with no socket.
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
        // A tape with a distinctive clock reading. Replay must serve that exact
        // tick, not a fresh clock, or a finding that names the time would come out
        // different offline than it did live.
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
        // A tape whose one speak was refused. A module that catches the error and
        // reports on it must take that branch again on replay, which only holds if
        // the error itself was recorded and returned.
        let tape = CapTape {
            speaks: vec![SpeakExchange {
                sent: b"x".to_vec(),
                reply: Err(CapError::ConnectionRefused),
            }],
            ..CapTape::default()
        };

        // The array is the function's return value, not something inside the
        // `try`: in Rhai a `try`/`catch` is a statement that evaluates to unit, so
        // the branch sets the verdict and the finding is built after.
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
