// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The on-disk form of a capability tape
//!
//! A [`CapTape`] written down as data a journal can hold, so a scan's recorded runs
//! survive to be replayed later. This is the compute tier's parallel to the model's
//! record layer: the tape itself stays free of `serde`, and this module is the one
//! place its wire shape and the names of its errors are defined. A record is built
//! from a tape through [`From`] and read back through
//! [`rebuild`](CapTapeRecord::rebuild).
//!
//! ## How the pieces are written
//!
//! Bytes become lowercase hex, the encoding the engine already uses for a content
//! hash: compact enough, identical across two runs so a journal stays comparable
//! with itself, and needing no dependency. Each exchange records either its reply
//! or its error, never both, so a run that branched on a refusal replays that branch
//! from the file. Following the model records, a value that will not parse reads
//! back as the least it could mean rather than failing the whole tape: an
//! undecodable byte string reads empty, and an unknown error kind reads as a reset.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::capability::CapError;
use super::replay::{CapTape, ResolveExchange, SpeakExchange};
use crate::record::DetectionIdRecord;

/// One detection run, as the journal holds it: which detection ran over which
/// subject, and the tape of what it read. This is the line the journal writes per
/// run, so a recorded scan can be replayed offline, detection by detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionRunRecord {
    /// The address the detection ran against.
    pub host: String,
    /// The port it ran over.
    pub port: u16,
    /// The transport, by wire name.
    pub protocol: String,
    /// Which detection ran, to which version, from which bytes.
    pub detection: DetectionIdRecord,
    /// What it read from its capabilities, kept for replay.
    pub tape: CapTapeRecord,
}

/// A capability tape, as a file holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapTapeRecord {
    /// Each recorded `speak`, in call order.
    #[serde(default)]
    pub speaks: Vec<SpeakExchangeRecord>,
    /// Each recorded `resolve`, in call order.
    #[serde(default)]
    pub resolves: Vec<ResolveExchangeRecord>,
    /// Each `now` tick, in call order, as milliseconds on the scan clock.
    #[serde(default)]
    pub nows: Vec<u64>,
}

/// One recorded `speak`: the bytes sent, and either the reply or the error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeakExchangeRecord {
    /// The bytes the module sent, as hex.
    pub sent: String,
    /// The reply as hex, present when the exchange succeeded.
    #[serde(default)]
    pub reply: Option<String>,
    /// The error, present when it failed.
    #[serde(default)]
    pub error: Option<CapErrorRecord>,
}

/// One recorded `resolve`: the name asked, and either the addresses or the error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveExchangeRecord {
    /// The name the module asked to resolve.
    pub name: String,
    /// The addresses returned, as strings, present when resolution succeeded.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// The error, present when it failed.
    #[serde(default)]
    pub error: Option<CapErrorRecord>,
}

/// A capability error, by wire name, with the reason a denial carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapErrorRecord {
    /// The error kind, by wire name.
    pub kind: String,
    /// Why, for a denial. Absent for every other kind.
    #[serde(default)]
    pub reason: Option<String>,
}

impl From<&CapTape> for CapTapeRecord {
    fn from(tape: &CapTape) -> Self {
        Self {
            speaks: tape.speaks.iter().map(SpeakExchangeRecord::from).collect(),
            resolves: tape
                .resolves
                .iter()
                .map(ResolveExchangeRecord::from)
                .collect(),
            nows: tape.nows.clone(),
        }
    }
}

impl CapTapeRecord {
    /// Rebuilds the tape this record holds.
    pub fn rebuild(&self) -> CapTape {
        CapTape {
            speaks: self
                .speaks
                .iter()
                .map(SpeakExchangeRecord::rebuild)
                .collect(),
            resolves: self
                .resolves
                .iter()
                .map(ResolveExchangeRecord::rebuild)
                .collect(),
            nows: self.nows.clone(),
        }
    }
}

impl From<&SpeakExchange> for SpeakExchangeRecord {
    fn from(exchange: &SpeakExchange) -> Self {
        let (reply, error) = match &exchange.reply {
            Ok(bytes) => (Some(to_hex(bytes)), None),
            Err(error) => (None, Some(CapErrorRecord::from(error))),
        };
        Self {
            sent: to_hex(&exchange.sent),
            reply,
            error,
        }
    }
}

impl SpeakExchangeRecord {
    fn rebuild(&self) -> SpeakExchange {
        let reply = match &self.error {
            Some(error) => Err(error.rebuild()),
            None => Ok(from_hex(self.reply.as_deref().unwrap_or(""))),
        };
        SpeakExchange {
            sent: from_hex(&self.sent),
            reply,
        }
    }
}

impl From<&ResolveExchange> for ResolveExchangeRecord {
    fn from(exchange: &ResolveExchange) -> Self {
        let (addresses, error) = match &exchange.result {
            Ok(addresses) => (addresses.iter().map(IpAddr::to_string).collect(), None),
            Err(error) => (Vec::new(), Some(CapErrorRecord::from(error))),
        };
        Self {
            name: exchange.name.clone(),
            addresses,
            error,
        }
    }
}

impl ResolveExchangeRecord {
    fn rebuild(&self) -> ResolveExchange {
        let result = match &self.error {
            Some(error) => Err(error.rebuild()),
            None => Ok(self
                .addresses
                .iter()
                .filter_map(|address| address.parse().ok())
                .collect()),
        };
        ResolveExchange {
            name: self.name.clone(),
            result,
        }
    }
}

impl From<&CapError> for CapErrorRecord {
    fn from(error: &CapError) -> Self {
        Self {
            kind: cap_error_kind_name(error).to_owned(),
            reason: match error {
                CapError::Denied(reason) => Some(reason.clone()),
                _ => None,
            },
        }
    }
}

impl CapErrorRecord {
    fn rebuild(&self) -> CapError {
        cap_error(&self.kind, self.reason.as_deref())
    }
}

/// The wire name of a capability error.
fn cap_error_kind_name(error: &CapError) -> &'static str {
    match error {
        CapError::ByteBudgetExhausted => "byte-budget-exhausted",
        CapError::ConnectionBudgetExhausted => "connection-budget-exhausted",
        CapError::Denied(_) => "denied",
        CapError::TimedOut => "timed-out",
        CapError::ConnectionRefused => "connection-refused",
        CapError::Reset => "reset",
    }
}

/// The capability error a wire name and its reason name. An unknown kind reads as a
/// reset, the most generic failure, rather than dropping the exchange.
fn cap_error(kind: &str, reason: Option<&str>) -> CapError {
    match kind {
        "byte-budget-exhausted" => CapError::ByteBudgetExhausted,
        "connection-budget-exhausted" => CapError::ConnectionBudgetExhausted,
        "denied" => CapError::Denied(reason.unwrap_or_default().to_owned()),
        "timed-out" => CapError::TimedOut,
        "connection-refused" => CapError::ConnectionRefused,
        _ => CapError::Reset,
    }
}

/// Bytes as lowercase hex, the engine's content-hash convention.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Bytes from lowercase hex. A malformed string reads back empty rather than
/// failing, since a machine wrote it and a corrupt tape is a degraded replay, not a
/// crash.
fn from_hex(hex: &str) -> Vec<u8> {
    if !hex.len().is_multiple_of(2) {
        return Vec::new();
    }
    (0..hex.len())
        .step_by(2)
        .map(|start| u8::from_str_radix(&hex[start..start + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::compute::{
        Budget, CapError, ComputeRuntime, Grant, LiveCapabilities, ModuleBody,
        RecordedCapabilities, RecordingCapabilities, RhaiRuntime,
    };
    use crate::fingerprint::PortContext;
    use crate::model::finding::{DetectionClass, DetectionId, Version};
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
            detection: DetectionId::new("record-test", Version::new(1, 0, 0), "hash").unwrap(),
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
    fn a_tape_survives_json_and_still_replays_identically() {
        // The whole persistence guarantee: capture a live run, write the tape to
        // JSON and read it back, and the replay from that JSON reproduces the live
        // findings exactly. This is what the journal will do.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut probe = [0u8; 64];
                let _ = sock.read(&mut probe);
                // A reply with a non-ASCII byte, so a lossy encoding would corrupt it.
                let _ = sock.write_all(&[0x52, 0x45, 0x44, 0x49, 0x53, 0xff]);
            }
        });

        let source = r#"
            fn analyze(ctx, responses) {
                let reply = speak(blob(4, 0x41));
                [ #{
                    severity: "medium",
                    summary: "answered " + reply.len() + " bytes at " + now(),
                } ]
            }
        "#;

        let runtime = RhaiRuntime::new();
        let module = runtime
            .load(&ModuleBody::Rhai(source.to_string()))
            .expect("the module compiles");

        // Capture a live run.
        let mut recording =
            RecordingCapabilities::new(LiveCapabilities::new(addr, Protocol::Tcp, &budget()));
        let mut instance = runtime
            .instantiate(&module, &grant())
            .expect("instantiates");
        let live = runtime
            .run(&mut instance, &ctx(addr.port()), &[], &mut recording)
            .expect("a clean live run");
        let tape = recording.into_tape();

        // Round-trip the tape through JSON, as a journal writes and reads it.
        let json = serde_json::to_string(&CapTapeRecord::from(&tape)).expect("serializes");
        let restored = serde_json::from_str::<CapTapeRecord>(&json)
            .expect("deserializes")
            .rebuild();
        assert_eq!(
            restored, tape,
            "the tape did not survive the JSON round-trip"
        );

        // Replay from the restored tape and compare to the live findings.
        let mut caps = RecordedCapabilities::from_tape(restored);
        let mut instance = runtime
            .instantiate(&module, &grant())
            .expect("instantiates");
        let replayed = runtime
            .run(&mut instance, &ctx(addr.port()), &[], &mut caps)
            .expect("a clean replay");

        assert_eq!(
            live, replayed,
            "the findings did not survive the journal round-trip"
        );
    }

    #[test]
    fn every_error_kind_is_named_and_read_back() {
        // A name that does not parse back to its own variant would silently rewrite a
        // recorded error on read, turning a refusal into something else.
        let errors = [
            CapError::ByteBudgetExhausted,
            CapError::ConnectionBudgetExhausted,
            CapError::Denied("out of scope".to_string()),
            CapError::TimedOut,
            CapError::ConnectionRefused,
            CapError::Reset,
        ];
        for error in errors {
            let rebuilt = CapErrorRecord::from(&error).rebuild();
            assert_eq!(
                rebuilt, error,
                "an error kind did not survive its wire name"
            );
        }
    }
}
