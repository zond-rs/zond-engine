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
//! use zond_engine::{Resolver, ScanEvent, ZondConfig, discover, resolve};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // One call: the address grammar, this host's interface table for `lan` and
//! // `%en0`, any hostnames, and whether a segment sweep was asked for.
//! let resolver = Resolver::from_system();
//! let targets = resolve::for_discovery(&["192.168.1.0/24"], Some(&resolver)).await?;
//!
//! let mut cfg = ZondConfig::default();
//! targets.apply_to(&mut cfg);
//!
//! let (mut session, task) = discover(targets.into_ips(), &cfg).await?;
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
//! # Wrapping the engine, or being the orchestrator
//!
//! The example above is the whole API for a front end that wants results:
//! targets in, hosts and a report out, with privilege, interfaces, fallbacks and
//! retries all decided for it. Most callers want exactly that and should not
//! have to learn anything below it.
//!
//! Some callers want to be the one deciding. For them the same machinery is
//! available a layer at a time, and none of it is behind a cargo feature:
//!
//! - **The vocabulary alone.** [`model`] parses targets, holds hosts and ports,
//!   and does arithmetic on address sets, without scanning anything. A caller
//!   with their own probing code can use it as a domain model and stop there.
//! - **The plan.** [`scanner::plan`] works out which strategies would run
//!   against a set of targets on this host, opening nothing. Inspect it, drop
//!   steps, reorder them, or print it as a dry run.
//! - **One strategy at a time.** [`scanner::strategy`] holds every scanner the
//!   engine uses behind two small traits, each constructible directly and each
//!   able to run over a transport the caller opened. Aim one at one segment and
//!   read the results out of a [`ScanSession`] you made yourself.
//!
//! The `test-support` feature is *not* the way in to any of this. It gates the
//! synthetic transports the crate's own tests use to fake a network, and nothing
//! else.
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
//! The list is an order, not a set: each module depends only on the ones above
//! it, and that is a property the crate is arranged to keep rather than an
//! observation about how it happens to look today.
//!
//! - [`model`] — the vocabulary every other module names: [`Host`], [`Port`],
//!   [`IpSet`], [`TargetMap`], and the grammars that construct them from what a
//!   person wrote. It depends on nothing else here.
//! - [`config`] — what a caller asks for before a scan starts, including the
//!   effort a scan is worth spending. Separate from [`model`] because a request
//!   is not a finding, and separate from [`scanner`] because a report has to
//!   record what was asked for whether or not a scan ever ran.
//! - [`protocols`] — building and parsing packets, as bytes and nothing else.
//! - [`transport`] — the sockets and captures that carry those bytes. Kept apart
//!   from [`protocols`] because one half needs a NIC and root and the other half
//!   needs neither, and a packet that cannot be built without a socket open is a
//!   packet nobody can test. Both are public because crafting a probe is a
//!   reasonable thing to want on its own; nothing in the two phases above
//!   requires touching them.
//! - [`system`] — interfaces, routing, and whether the process may open raw
//!   sockets. The one place the engine asks the host about itself.
//! - [`resolve`] — turning the names a person writes into the addresses a scan
//!   probes, over unicast DNS and multicast DNS. It runs before a scan, deciding
//!   what it covers; the reverse direction, naming hosts a scan has found, is the
//!   scanner's own [`resolver`](scanner::resolver).
//!   [`resolve::for_discovery`] is the one call a front end makes: it is where
//!   the grammar, this host's interface table, hostname lookup and the
//!   segment-sweep question are answered together, rather than being four things
//!   for every consumer to remember separately.
//! - [`fingerprint`] — identifying the service behind an open port.
//! - [`scanner`] — the two entry points, the [`plan`](scanner::plan) behind
//!   them, and the [`strategy`](scanner::strategy) implementations behind that,
//!   together with what running one produces: the live
//!   [`session`](scanner::session), the [`handle`](scanner::handle) that stops
//!   it, and the [`report`](scanner::report) it leaves behind. Those are the
//!   scanner's output rather than a foundation under it, and they live with it
//!   for that reason.
//! - [`format`](mod@crate::format) — what a reader and a writer of the same document have to agree
//!   on, and nothing else. It sits below both so that reading a format never
//!   requires compiling the code that writes it.
//! - [`export`], [`import`] — the file formats themselves, which sit above the
//!   report because they describe it and it does not know they exist.
//!
//! # Platforms
//!
//! Linux and macOS. Windows is not currently supported.

pub mod config;
pub mod export;
pub mod fingerprint;
pub mod format;
pub mod import;
pub mod journal;
pub mod model;
pub mod protocols;
pub mod record;
pub mod resolve;
pub mod scanner;
pub mod system;
pub mod transport;

// Nothing here is public: it is the five macros the engine emits its own
// diagnostics through, and a library that exported those would shadow
// `tracing`'s and `log`'s macros of the same names in any consumer that
// glob-imported it. See the module for the rest of the argument.
pub(crate) mod logging;

// The names a consumer reaches for, at the root rather than four modules deep.
//
// Deliberately a short list. Everything here stays reachable at its full path as
// well, so this is a convenience and never the only way to name a type; what it
// costs is that each name is a commitment, which is why the crate's whole
// vocabulary is not re-exported wholesale.
pub use crate::config::{RetryConfig, ScanEffort, SendMode, ZondConfig};
pub use crate::model::exclusion::Exclusions;
pub use crate::model::host::{Host, HostStatus};
pub use crate::model::ip::set::IpSet;
pub use crate::model::port::{Port, PortSet, PortState, Protocol, Service};
pub use crate::model::target::{Target, TargetMap, TargetSet};
pub use crate::model::technique::TcpScanTechnique;
pub use crate::resolve::{ResolveConfig, Resolver};
pub use crate::scanner::handle::ScanHandle;
pub use crate::scanner::report::{ScanReport, ScanSummary};
pub use crate::scanner::session::{HostStore, ScanEvent, ScanEvents, ScanSession};
pub use crate::scanner::strategy::StrategyError;
pub use crate::scanner::{ScanError, ScanTask, discover, scan};

// The engine's own diagnostic macros, reachable as `crate::info!` and friends
// from anywhere in the crate. They are deliberately not part of the public API;
// see `logging` for what exporting them would cost a consumer.
pub(crate) use crate::logging::{error, info, success, warn};
