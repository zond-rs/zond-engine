// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The on-disk form of a capability tape
//!
//! A [`CapTape`] as journal data, so recorded runs can be replayed later. The
//! tape itself has no `serde`; this module defines its wire shape. Build a
//! record with [`From`] and read it back with
//! [`rebuild`](CapTapeRecord::rebuild).
//!
//! ## Encoding
//!
//! Bytes are lowercase hex, as content hashes are. Each exchange records its
//! reply or its error, so a run that branched on a refusal replays that branch.
//! As in the model records, an unparsable value reads as the least it could
//! mean: undecodable bytes read empty, and an unknown error kind reads as a
//! reset.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::capability::CapError;
use super::replay::{CapTape, ResolveExchange, SpeakExchange};
use crate::record::DetectionIdRecord;

/// One detection run, as the journal holds it: which detection ran over which
/// subject, and the tape of what it read.
///
/// `#[non_exhaustive]`, so the format can gain fields.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionRunRecord {
    /// The address the detection ran against.
    pub host: String,
    /// The name a target reached that address by, where it named a host: the
    /// module's `ctx.hostname`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    /// The port it ran over.
    pub port: u16,
    /// The transport, by wire name.
    pub protocol: String,
    /// Which detection ran, to which version, from which bytes.
    pub detection: DetectionIdRecord,
    /// The responses the scan had gathered and handed the detection.
    #[serde(default)]
    pub responses: Vec<String>,
    /// What it read from its capabilities, kept for replay.
    pub tape: CapTapeRecord,
}

/// The runs over one port that read the same responses, as one line of a
/// journal: the port and its responses once, then each run's detection and
/// tape.
///
/// A dozen passive detections may read one HTTP port's kilobytes of responses,
/// so the responses are written once per port. Runs are still read back as
/// [`DetectionRunRecord`]s.
///
/// An engine that only knows one run per line cannot parse this and refuses
/// the file.
#[cfg(feature = "journal-format")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PortRunsRecord {
    host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_name: Option<String>,
    port: u16,
    protocol: String,
    responses: Vec<String>,
    runs: Vec<PortRunRecord>,
}

/// One run of a [`PortRunsRecord`]: what ran, and what it read from its
/// capabilities.
#[cfg(feature = "journal-format")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PortRunRecord {
    detection: DetectionIdRecord,
    tape: CapTapeRecord,
}

#[cfg(feature = "journal-format")]
impl PortRunsRecord {
    /// `runs` as the lines a journal writes them in: one for each port and
    /// set of responses, in the order each first appears, holding its runs in
    /// the order given.
    pub(crate) fn grouping(runs: &[DetectionRunRecord]) -> Vec<Self> {
        let mut lines: Vec<Self> = Vec::new();
        for run in runs {
            let line = lines.iter_mut().find(|line| {
                (
                    line.port,
                    &line.host,
                    &line.host_name,
                    &line.protocol,
                    &line.responses,
                ) == (
                    run.port,
                    &run.host,
                    &run.host_name,
                    &run.protocol,
                    &run.responses,
                )
            });
            let run_record = PortRunRecord {
                detection: run.detection.clone(),
                tape: run.tape.clone(),
            };
            match line {
                Some(line) => line.runs.push(run_record),
                None => lines.push(Self {
                    host: run.host.clone(),
                    host_name: run.host_name.clone(),
                    port: run.port,
                    protocol: run.protocol.clone(),
                    responses: run.responses.clone(),
                    runs: vec![run_record],
                }),
            }
        }
        lines
    }
}

/// A line of a journal's detection runs, in either shape it has been written
/// in.
///
/// Untagged: a port's line is told apart by its runs, and a line naming a
/// single run is read as one.
#[cfg(feature = "journal-format")]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub(crate) enum DetectionLine {
    /// A port's runs, sharing its responses.
    Port(PortRunsRecord),
    /// One run, carrying its own copy of what it read.
    Run(DetectionRunRecord),
}

#[cfg(feature = "journal-format")]
impl DetectionLine {
    /// The runs this line holds, each with the responses it read.
    pub(crate) fn into_runs(self) -> Vec<DetectionRunRecord> {
        match self {
            Self::Run(run) => vec![run],
            Self::Port(line) => line
                .runs
                .into_iter()
                .map(|run| DetectionRunRecord {
                    host: line.host.clone(),
                    host_name: line.host_name.clone(),
                    port: line.port,
                    protocol: line.protocol.clone(),
                    detection: run.detection,
                    responses: line.responses.clone(),
                    tape: run.tape,
                })
                .collect(),
        }
    }
}

/// A capability tape, as a file holds it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapTapeRecord {
    /// Each recorded `speak`, in call order.
    #[serde(default)]
    pub speaks: Vec<SpeakExchangeRecord>,
    /// Each recorded `resolve`, in call order.
    #[serde(default)]
    pub resolves: Vec<ResolveExchangeRecord>,
    /// Each `now` tick, in call order, as milliseconds on the run's clock.
    #[serde(default)]
    pub nows: Vec<u64>,
}

/// One recorded `speak`: the bytes sent, and either the reply or the error.
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
        CapError::OutOfDescriptors => "out-of-descriptors",
        CapError::Withheld => "withheld",
        CapError::TimedOut => "timed-out",
        CapError::ConnectionRefused => "connection-refused",
        CapError::Reset => "reset",
    }
}

/// The capability error a wire name and its reason name. An unknown kind reads as a
/// reset, the most generic failure.
fn cap_error(kind: &str, reason: Option<&str>) -> CapError {
    match kind {
        "byte-budget-exhausted" => CapError::ByteBudgetExhausted,
        "connection-budget-exhausted" => CapError::ConnectionBudgetExhausted,
        "denied" => CapError::Denied(reason.unwrap_or_default().to_owned()),
        "out-of-descriptors" => CapError::OutOfDescriptors,
        "withheld" => CapError::Withheld,
        "timed-out" => CapError::TimedOut,
        "connection-refused" => CapError::ConnectionRefused,
        _ => CapError::Reset,
    }
}

/// Bytes as lowercase hex, the engine's content-hash convention.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Bytes from lowercase hex. A malformed string, an odd length, or a non-hex or
/// non-ASCII byte reads back empty. Indexing is over bytes, so a multi-byte
/// character cannot split a slice.
fn from_hex(hex: &str) -> Vec<u8> {
    let hex = hex.as_bytes();
    if !hex.len().is_multiple_of(2) {
        return Vec::new();
    }
    (0..hex.len())
        .step_by(2)
        .map(|start| {
            let hi = (hex[start] as char).to_digit(16)?;
            let lo = (hex[start + 1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect::<Option<Vec<u8>>>()
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
            speaks_http: false,
            detection: crate::config::ServiceDetection::default(),
            host_name: None,
        }
    }

    #[test]
    fn a_tape_survives_json_and_still_replays_identically() {
        // A live run's tape, through JSON and back, replays to the same findings.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Some(mut sock) = from_this_process(&listener).next() {
                let mut probe = [0u8; 64];
                let _ = sock.read(&mut probe);
                // A non-ASCII byte, which a lossy encoding would corrupt.
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

        let mut recording =
            RecordingCapabilities::new(LiveCapabilities::new(addr, Protocol::Tcp, None, &budget()));
        let mut instance = runtime
            .instantiate(&module, &grant())
            .expect("instantiates");
        let live = runtime
            .run(&mut instance, &ctx(addr.port()), &[], &mut recording)
            .expect("a clean live run");
        let tape = recording.into_tape();

        // Through JSON and back.
        let json = serde_json::to_string(&CapTapeRecord::from(&tape)).expect("serializes");
        let restored = serde_json::from_str::<CapTapeRecord>(&json)
            .expect("deserializes")
            .rebuild();
        assert_eq!(
            restored, tape,
            "the tape did not survive the JSON round-trip"
        );

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

    /// `ctx.hostname` survives the journal; a line without one reads as `None`.
    #[test]
    fn a_runs_host_name_survives_the_journal_line() {
        let detection = DetectionId::new("d", Version::new(1, 0, 0), "h").expect("an id");
        let run = |host_name: Option<&str>| DetectionRunRecord {
            host: "192.0.2.1".to_string(),
            host_name: host_name.map(str::to_string),
            port: 443,
            protocol: "tcp".to_string(),
            detection: DetectionIdRecord::from(&detection),
            responses: Vec::new(),
            tape: CapTapeRecord::from(&CapTape::default()),
        };
        let runs = vec![run(Some("box.example")), run(None)];

        let read: Vec<DetectionRunRecord> = PortRunsRecord::grouping(&runs)
            .into_iter()
            .map(|line| serde_json::to_string(&line).expect("serializes"))
            .flat_map(|json| {
                serde_json::from_str::<DetectionLine>(&json)
                    .expect("deserializes")
                    .into_runs()
            })
            .collect();
        assert_eq!(read, runs);

        let unnamed = serde_json::to_string(&run(None)).expect("serializes");
        assert!(!unnamed.contains("host_name"), "{unnamed}");
    }

    #[test]
    fn every_error_kind_is_named_and_read_back() {
        // Every error kind's name parses back to its own variant.
        let errors = [
            CapError::ByteBudgetExhausted,
            CapError::ConnectionBudgetExhausted,
            CapError::Denied("out of scope".to_string()),
            CapError::OutOfDescriptors,
            CapError::Withheld,
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

    #[test]
    fn a_tape_with_non_ascii_hex_reads_back_empty_rather_than_panicking() {
        // A planted journal may hold multi-byte characters of even byte length in
        // a hex field; reading must not slice mid-character.
        let record = CapTapeRecord {
            speaks: vec![SpeakExchangeRecord {
                sent: "€€".to_string(),
                reply: Some(" zz not hex".to_string()),
                error: None,
            }],
            resolves: Vec::new(),
            nows: Vec::new(),
        };

        let tape = record.rebuild();
        assert_eq!(tape.speaks.len(), 1);
        assert_eq!(tape.speaks[0].sent, Vec::<u8>::new());
        assert_eq!(tape.speaks[0].reply, Ok(Vec::new()));
    }
}
