// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A network scanner, as a library.
//!
//! Give it addresses and it reports which hosts are alive; give it hosts and ports and it
//! reports which ports are open and what is listening on them. The scanning, the domain
//! model, the report and the file formats all live here, so a CLI, a web service and an
//! embedded consumer produce the same results and the same documents.
//!
//! # Three phases
//!
//! [`discover`] finds which hosts exist. [`scan`] classifies the ports of hosts already
//! known. [`listen`] sends nothing and reads what a link already carries: for networks the
//! other two may not touch, and for things no probe can learn, such as which switch port
//! this machine is on, which VLANs a link carries, or what a device says about itself while
//! asking for an address.
//!
//! The first two are jobs and finish on their own. A listener is a service and runs until
//! it is told to stop.
//!
//! [`discover`] and [`scan`] are separate because their costs differ by orders of
//! magnitude: sweeping a `/24` is a few hundred packets, port-scanning all of it a few
//! hundred thousand. Run the cheap one first and spend the expensive one on what answered.
//!
//! Both work unprivileged. With root they use raw sockets, ARP and ICMPv6 on the local
//! segment and raw TCP and UDP elsewhere; without it they fall back to TCP connect
//! attempts. Each phase records which path it took, so a result can be weighed accordingly.
//! [`listen`] has no fallback: reading a link needs capture access.
//!
//! # Live results, and the record afterwards
//!
//! Each call returns a pair. [`ScanSession`] is the live view: hosts appear in its
//! [`HostStore`] as they are found and each change fires a [`ScanEvent`], so a caller can
//! render a scan in progress. The [`ScanTask`] resolves when everything has finished and
//! yields a [`ScanReport`]: what was asked for, what came back, what failed on the way, and
//! under which settings.
//!
//! Both are needed. A list of hosts alone cannot say whether the network is empty or the
//! raw scanner never started; the report can.
//!
//! ```no_run
//! use zond_engine::{Resolver, ScanEvent, ZondConfig, discover, resolve};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // The address grammar, this host's interface table for `lan` and `%en0`, any
//! // hostnames, and whether a segment sweep was asked for, in one call.
//! let resolver = Resolver::from_system();
//! let targets = resolve::for_discovery(&["192.0.2.0/24"], Some(&resolver)).await?;
//!
//! let mut cfg = ZondConfig::default();
//! targets.apply_to(&mut cfg);
//!
//! let (mut session, task) = discover(targets.into_ips(), &cfg).await?;
//!
//! // Hosts arrive as they are found.
//! while let Some(event) = session.events().recv().await {
//!     if let ScanEvent::HostUpdated(address) = event
//!         && let Some(host) = session.hosts().get(&address)
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
//! The example above is the whole API for a front end that wants results: targets in,
//! hosts and a report out, with privilege, interfaces, fallbacks and retries decided for
//! it. Most callers need nothing below it.
//!
//! Callers who want to make those decisions themselves can use the same machinery a layer
//! at a time, none of it behind a cargo feature:
//!
//! - **The vocabulary alone.** [`model`] parses targets, holds hosts and ports, and does
//!   arithmetic on address sets without scanning anything. A caller with their own probing
//!   code can use it as a domain model and stop there.
//! - **The plan.** [`scanner::plan`] works out which strategies would run against a set of
//!   targets on this host, opening nothing. Inspect it, drop or reorder steps, or print it
//!   as a dry run.
//! - **One strategy at a time.** [`scanner::strategy`] holds every scanner the engine uses
//!   behind two small traits. Each can be constructed directly and run over a transport the
//!   caller opened, with results read from a [`ScanSession`] the caller opened.
//!
//! The `test-support` feature only gates the synthetic transports the crate's own tests use
//! to fake a network.
//!
//! # Reports out, targets in
//!
//! [`export`] writes a finished report as JSON, JSONL, CSV, a self-contained HTML page, or
//! nmap-compatible XML. [`import`] reads targets from a plain list, a CSV, this engine's
//! own JSON, or an nmap XML file, and reads layered settings from TOML. Each format sits
//! behind a cargo feature; `export-json` is the only one on by default.
//!
//! `import::report` reads the same documents back as a [`ScanReport`] of what the scan
//! found, which is what lets [`diff`] compare an archived file, this engine's or nmap's,
//! against a scan that just finished. (Unlinked because the module exists only in builds
//! with a report format enabled.)
//!
//! Neither module opens files or touches standard input. Export writes to a `Write`, import
//! reads from a `BufRead`, and where the bytes go is up to the caller.
//!
//! # What changed since last time
//!
//! [`diff`] compares two [`ScanReport`]s and says what moved: a new host, a port that
//! opened, a service that changed version, a certificate that rotated or is about to lapse.
//! It is the other half of scanning a network on a schedule, and either side can be a scan
//! that just ran, a report read back out of a [`journal`], or one built from another
//! scanner's output.
//!
//! Every appearance and disappearance carries what the other scan says about whether it
//! covered that target at all, so a narrowed scan does not read as a network that emptied.
//!
//! # What several scans add up to
//!
//! [`merge`] folds any number of [`ScanReport`]s into one: a `/16` scanned in eight chunks,
//! one range seen from inside the perimeter and from outside, or a year of archived nmap
//! files plus tonight's run. The result holds every phase each source walked.
//!
//! A later source overrides only where it made a claim, so a host missing from tonight's
//! scan has not gone away and an endpoint nothing listed has not closed. Where two sources
//! genuinely disagree the newer one wins, which lets a merged report record a port closing.
//!
//! The result is itself a `ScanReport`, so it exports through every writer, compares
//! through [`diff`], and merges again.
//!
//! # Layout
//!
//! The names most consumers need are re-exported at the root.
//!
//! The modules are layered: each depends only on those below it, and
//! `tests/hygiene/architecture.rs` reads every `crate::` path in the library, including
//! those inside expressions, and fails if that stops being true. `ORDER` in that test is
//! the layering itself. The list below is ordered for someone meeting the crate, starting
//! with the vocabulary and ending with the file formats.
//!
//! - [`model`]: the vocabulary every other module names: [`Host`], [`Port`], [`IpSet`],
//!   [`TargetMap`], and the grammars that build them from what a person wrote. It depends
//!   on nothing else here.
//! - [`config`]: what a caller asks for before a scan starts, including how much effort a
//!   scan is worth. A report records it whether or not a scan ever ran.
//! - [`protocols`]: building and parsing packets, as bytes.
//! - [`transport`]: the sockets and captures that carry those bytes. Separate from
//!   [`protocols`] because one half needs a NIC and root and the other needs neither, which
//!   keeps packet code testable. Both are public for callers who want to craft probes; the
//!   phases above never require touching them.
//! - [`system`]: interfaces, routing, and whether the process may open raw sockets. The one
//!   place the engine asks the host about itself.
//! - [`evasion`]: what a scan may change about the packets it sends, and which of those a
//!   given strategy can honour. A profile is checked before any packet is built and refused
//!   up front when no scan could carry it.
//! - [`resolve`]: turning names a person writes into addresses a scan probes, over unicast
//!   and multicast DNS. It runs before a scan; naming hosts a scan has found is the
//!   scanner's own [`rdns`](scanner::rdns). [`resolve::for_discovery`] is the one call a
//!   front end makes: grammar, interface table, hostname lookup and the segment-sweep
//!   question answered together.
//! - [`fingerprint`]: identifying the service behind an open port.
//! - [`report`]: what a scan was and what it found: [`ScanReport`],
//!   [`ScanPhase`](report::ScanPhase), the settings it ran under and the counters it kept.
//!   Below [`scanner`] because a report outlives its scan: it is journalled, read back
//!   offline, compared, merged and exported without a scanner involved.
//! - [`cve`]: joining what a scan identified against known vulnerabilities. A step, not a
//!   phase: it sends nothing, so it works as well on a host read from a file as on one a
//!   scan just found.
//! - [`detect`]: running a detection over what a scan has already established, and
//!   recording what it read so the run can be replayed offline. Also a step.
//! - [`record`]: the same information in a shape that survives a file.
//! - [`journal`]: what a scan writes down as it runs, so an unfinished one can be
//!   continued. It holds the plan, how far the scan got, and what it found, all written in
//!   [`record`] shapes.
//! - [`scanner`]: the entry points, the [`plan`](scanner::plan) behind them and the
//!   [`strategy`](scanner::strategy) implementations behind that, plus the live
//!   [`session`](scanner::session), the [`handle`](scanner::handle) that stops it, the
//!   [`recorder`](scanner::recorder) that closes a phase into a [`ScanReport`], and the
//!   [`checkpoint`](scanner::checkpoint) timer that carries a running scan into a
//!   [`journal`].
//! - [`diff`]: what changed between two scans. It compares reports, so where either came
//!   from does not matter.
//! - [`merge`]: several scans as one report. Above [`diff`] because it folds hosts under
//!   the same [`HostIdentity`](diff::HostIdentity) a comparison pairs them by.
//! - [`format`](mod@crate::format): what a reader and a writer of the same document have to
//!   agree on. It sits below both, so reading a format never compiles the code that writes
//!   it.
//! - [`export`], [`import`]: the file formats themselves.
//! - [`signature`](mod@crate::signature): detached Ed25519 signatures. An [`export`] signs
//!   bytes on the way out, and [`detect`] checks a signature on bytes coming in before it
//!   compiles them.
//! - `fetch`: downloading data the engine reasons with but does not ship, starting with
//!   the distributions' security feeds, into a directory the caller names. Behind the
//!   `fetch` feature and run only when called, since it is the one part of the crate that
//!   contacts hosts nobody asked it to scan. It follows [`journal`]'s rules for creating
//!   files in the invoking user's home under `sudo`. (Unlinked because it exists only in
//!   builds with the feature.)
//! - [`error`](mod@crate::error): the stable code carried by every error a public entry
//!   point returns, as one trait over all of them. Last, because it names each module's
//!   error type.
//!
//! # What the public surface promises
//!
//! Every public item is a commitment, so the surface follows five rules, and
//! `tests/hygiene/surface.rs` checks each against the published API listing.
//!
//! - **Machinery stays inside.** What a strategy is built from (its retry ledger, adaptive
//!   deadline, congestion window, probe pool, and the loop the raw port scanners share) is
//!   private. A caller builds a strategy through its constructor, which takes the settings
//!   that tune all of it. Opening any of it later is an addition; withdrawing it would be a
//!   break.
//! - **Structs can grow.** A struct with public fields is `#[non_exhaustive]` and built
//!   through a constructor or `Default`, with fields set afterwards. The exceptions are
//!   types a caller writes out whole on purpose: the interchange shapes in [`record`], the
//!   `*Parts` structs that mirror what they rebuild, and packet headers, whose fields the
//!   protocol fixes. A public function takes such a struct only where a caller can obtain
//!   one, from a constructor, `Default`, a conversion or another function's return value.
//! - **Enums can grow.** A vocabulary is `#[non_exhaustive]`, and its `ALL` is a slice,
//!   because an array's length is part of its type and the next variant would be a break.
//! - **Lists can grow.** Every other public constant that lists something (ports,
//!   protocols, bounds, characters) is a slice for the same reason, and a public field
//!   holding one is a `Vec`. The remaining arrays are values whose length is their
//!   definition, such as the byte-order mark or a fixed-width header field.
//! - **Other crates' types stay out.** Public signatures name this crate's types, the
//!   standard library's, and two dependencies that cannot usefully be hidden: `tokio`,
//!   whose runtime every scan runs on, and `serde`, whose derives are the file formats.
//!   Everything else, including the packet library and the capture binding, is converted
//!   at the boundary.
//!
//! # Platforms
//!
//! Linux, macOS and Windows.
//!
//! On Windows, raw scanning goes through [Npcap](https://npcap.com), whose `wpcap.dll` must
//! be installed for a program built on this crate to start. Windows refuses raw TCP
//! sockets, so an elevated process sends whole Ethernet frames through Npcap and uses
//! connect for what a frame cannot reach; an unelevated one takes the connect path.
//! Journals live under `%LOCALAPPDATA%`. The IPv6 neighbour table is not read there, so a
//! sweep learns IPv6 neighbours only from what answers it.

// A public item without a doc comment is a gap in the crate's contract.
#![warn(missing_docs)]
// Labels feature-gated items on the rendered docs. Nightly-only, so it is set for the
// docs.rs build alone; see `Cargo.toml`.
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod config;
pub mod cve;
pub mod detect;
pub mod diff;
pub mod error;
pub mod evasion;
pub mod export;
#[cfg(feature = "fetch")]
pub mod fetch;
pub mod fingerprint;
pub mod format;
pub mod import;
pub mod journal;
pub mod merge;
pub mod model;
pub mod protocols;
pub mod record;
pub mod report;
pub mod resolve;
pub mod scanner;
pub mod signature;
pub mod system;
pub mod transport;
pub(crate) mod version;

// Fixtures the tests share, such as loopback services that hear only this process.
#[cfg(test)]
pub(crate) mod testing;

// The engine's diagnostic macros. Private because exporting them would shadow `tracing`'s
// and `log`'s macros of the same names in any consumer that glob-imported this crate.
pub(crate) mod logging;

// The names a consumer reaches for most. Kept short because each name here is a
// commitment; everything stays reachable at its full path too.
pub use crate::config::{RetryConfig, ScanEffort, ScanPace, ZondConfig};
pub use crate::error::Coded;
pub use crate::evasion::EvasionProfile;
pub use crate::model::exclusion::Exclusions;
pub use crate::model::host::{Host, HostStatus};
pub use crate::model::ip::scoped::{ScopedIp, Zone, ZoneMap};
pub use crate::model::ip::set::IpSet;
pub use crate::model::port::{Port, PortSet, PortState, Protocol, Service};
pub use crate::model::target::{Target, TargetMap, TargetSet};
pub use crate::model::technique::TcpScanTechnique;
pub use crate::report::{ScanReport, ScanSummary};
pub use crate::resolve::{ResolveConfig, Resolver};
pub use crate::scanner::handle::ScanHandle;
pub use crate::scanner::session::{HostStore, Progress, ScanEvent, ScanEvents, ScanSession, Stage};
pub use crate::scanner::strategy::StrategyError;
pub use crate::scanner::{ListenScope, ScanError, ScanTask, Until, discover, listen, scan};
#[cfg(feature = "journal-format")]
pub use crate::scanner::{discover_with_journal, listen_with_journal, scan_with_journal};
pub use crate::transport::probe::SendMode;

// Reachable as `crate::info!` and friends from anywhere in the crate.
//
// `error!` is imported from `logging` where it is used. At the root it would share a name
// with the `error` module, so `use crate::error;` would bring in both, and
// `tests/hygiene/architecture.rs` would read it as a dependency on the module.
pub(crate) use crate::logging::{counted, info, success, warn};
