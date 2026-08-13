// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A network scanner, as a library.
//!
//! Give it addresses and it tells you which hosts are alive; give it hosts and
//! ports and it tells you which of those ports are open and what is listening on
//! them. Everything a front end needs is here — the scanning, the domain model,
//! the report and the file formats — so that a CLI, a web service and an
//! embedded consumer produce the same results and the same documents.
//!
//! # Two phases
//!
//! [`discover`] establishes which hosts exist. [`scan`] classifies the ports of
//! hosts already known. They are separate calls because they cost very different
//! amounts: a sweep of a `/24` is a few hundred packets, and port-scanning all of
//! it is a few hundred thousand. Run the cheap one first and spend the expensive
//! one only on what answered.
//!
//! Both are unprivileged-safe. With root they use raw sockets — ARP and ICMPv6
//! on the local segment, raw TCP and UDP elsewhere — and without it they fall
//! back to ordinary TCP connect attempts. The phase records which it was, so a
//! result can be read for what it is worth.
//!
//! # Live results, and the record afterwards
//!
//! Each call returns a pair. [`ScanSession`] is the live view: hosts appear in
//! its [`HostStore`] as they are found, and each change fires a [`ScanEvent`],
//! so a caller can render a scan in progress instead of waiting for it. The
//! [`ScanTask`] resolves when everything has finished and yields a
//! [`ScanReport`] — the durable record of what was asked for, what came back,
//! what failed on the way, and under which settings.
//!
//! The two answer different questions and both are needed. A bare list of hosts
//! cannot say whether the network is empty or the raw scanner never started;
//! only the report can.
//!
//! ```no_run
//! use zond_engine::{ScanEvent, ZondConfig, discover};
//! use zond_engine::core::parse::ip::to_set;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let targets = to_set(&["192.168.1.0/24"], None)?;
//! let (mut session, task) = discover(targets, &ZondConfig::default()).await?;
//!
//! // Hosts arrive as they are found.
//! while let Some(event) = session.events().recv().await {
//!     if let ScanEvent::HostUpdated(ip) = event
//!         && let Some(host) = session.hosts().get(&ip)
//!     {
//!         println!("{host}");
//!     }
//! }
//!
//! // And the record of the sweep once it is over.
//! let report = task.join().await?;
//! println!("{} hosts up", report.summary().hosts_alive);
//! # Ok(())
//! # }
//! ```
//!
//! # Reports out, targets in
//!
//! [`export`] writes a finished report as JSON, JSONL, CSV, a self-contained
//! HTML page, or nmap-compatible XML. [`import`] reads targets back — from a
//! plain list, a CSV, this engine's own JSON, or an nmap XML file somebody else
//! produced — and reads layered settings from TOML. Each format sits behind a
//! cargo feature; `export-json` is the only one on by default.
//!
//! Neither module opens a file or touches standard input. Export writes to a
//! `Write`, import reads from a `BufRead`, and choosing where the bytes come
//! from or go is the caller's business.
//!
//! # Layout
//!
//! The names most consumers need are re-exported here at the root. The modules
//! below are the whole of it:
//!
//! - [`scanner`] — the two entry points and the strategies behind them.
//! - [`core`] — the domain model ([`Host`], [`Port`], [`IpSet`], [`TargetMap`]),
//!   the configuration, the live session and the finished report.
//! - [`fingerprinting`] — identifying the service behind an open port.
//! - [`export`], [`import`] — the file formats.
//! - [`protocols`], [`network`] — packet building and parsing, and the raw send
//!   and capture transports beneath them. Public because crafting a packet is a
//!   reasonable thing to want on its own; nothing in the two phases above
//!   requires touching them.
//! - [`system`] — interfaces, routing, and whether the process may open raw
//!   sockets. The one place the engine asks the host about itself.
//!
//! # Platforms
//!
//! Linux and macOS. Windows is not currently supported.

pub mod core;
pub mod export;
pub mod fingerprinting;
pub mod import;
pub mod network;
pub mod protocols;
pub mod scanner;
pub mod system;

// The names a consumer reaches for, at the root rather than four modules deep.
//
// Deliberately a short list. Everything here stays reachable at its full path as
// well, so this is a convenience and never the only way to name a type; what it
// costs is that each name is a commitment, which is why the crate's whole
// vocabulary is not re-exported wholesale.
pub use crate::core::config::{SendMode, ZondConfig};
pub use crate::core::handle::ScanHandle;
pub use crate::core::models::host::{Host, HostStatus};
pub use crate::core::models::ip::set::IpSet;
pub use crate::core::models::port::{Port, PortSet, PortState, Protocol, Service};
pub use crate::core::models::retry::{RetryConfig, ScanEffort};
pub use crate::core::models::target::{Target, TargetMap, TargetSet};
pub use crate::core::models::technique::TcpScanTechnique;
pub use crate::core::report::{ScanReport, ScanSummary};
pub use crate::core::session::{HostStore, ScanEvent, ScanEvents, ScanSession};
pub use crate::scanner::{ScanError, ScanTask, StrategyError, discover, scan};

// The engine's own diagnostic macros, reachable as `crate::info!` and friends
// from anywhere in the crate. They are deliberately not part of the public API;
// see `core::logging` for what exporting them would cost a consumer.
pub(crate) use crate::core::logging::{error, info, success, warn};
