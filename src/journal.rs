// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The scan journal
//!
//! What a scan writes down as it runs, so that a scan which did not finish can be
//! continued.
//!
//! ## The journal records a position, not probes
//!
//! A scan is millions of probes and a write per probe would dominate it, so nothing here
//! writes per probe.
//!
//! [`Dispatcher`](crate::scanner::dispatcher) walks its units in order and shuffles only
//! within a fixed batch, and a [`TargetSet`](crate::model::target::TargetSet) is canonical
//! and immutable from construction, so `unit.iter()` yields the same sequence on every run
//! over the same set. A target's identity in a plan is its position in that enumeration.
//!
//! What is written is a cursor: a watermark below which everything has settled, plus the
//! positions above it that settled out of order. Its size follows how far out of order the
//! scan is settling, not how large the scan is, so a `/8` on a thousand ports checkpoints in
//! what a `/24` does. It is rewritten on a timer. See [`cursor`](mod@cursor) for the sparse
//! form and the bound on the out-of-order set. Findings append at the rate hosts are
//! discovered, orders of magnitude below the rate they are probed.
//!
//! ## What "settled" means
//!
//! A position is settled when its target has a verdict or its retry budget is spent. A
//! target still inside its retry budget is outstanding, and the watermark stalls behind it.
//! A watermark that advanced over an unsettled position would produce a resumed scan that
//! skips targets and reports success.
//!
//! ## A resumed scan is two phases
//!
//! [`ScanReport::merge`](crate::report::ScanReport::merge) folds a later phase of the same
//! job into a report: phases append, hosts combine, the engine version stays the first
//! one's. A resumed report therefore carries one [`ScanPhase`](crate::report::ScanPhase)
//! per sitting, each with its own settings, timings and probe statistics, and does not claim
//! to be one continuous scan.
//!
//! ## What lives here
//!
//! [`paths`] computes where a journal goes: a state directory, and the invoking user's when
//! a scan runs under `sudo`. It creates nothing.
//!
//! [`format`](mod@format) is the on-disk shape: the framing, the versioning and the
//! vocabulary it shares with the export path. It sits behind the `journal-format` feature as
//! the one part that needs `serde_json`. [`paths`] is always present, so a front end can
//! list and locate journals without compiling the reader.
//!
//! [`settle`] is what a resume may skip: the outcome of each target, kept apart from its
//! verdict, because the engine gives an exhausted probe and one it never sent the same
//! verdict.
//!
//! [`cursor`] is how far a scan got: a position in the plan below which everything is
//! settled, plus the few positions above it that settled out of order.
//!
//! [`lock`] tells a running scan from one that crashed, so a live journal is never resumed
//! underneath its writer and a dead one is not left locked behind a reissued process id.
//!
//! [`manifest`] is what the journal is a journal of: the plan, fingerprinted so a resume can
//! prove it has not moved, and which of the engine's two phases counted it.
//! [`Plan`](manifest::Plan) is how a caller says which.
//!
//! [`Journal`] is the whole of it on disk: a directory holding the manifest, the cursor, the
//! findings and the lock. [`store::list`] enumerates journals, [`store::report`] reads one
//! back as the report its scan produced, and [`store::prune`] applies a
//! [`Retention`](store::Retention) policy so a state directory does not grow without bound.
//!
//! ## Both phases journal, and they count different things
//!
//! [`scan_with_journal`](crate::scanner::scan_with_journal) counts address-and-port pairs;
//! [`discover_with_journal`](crate::scanner::discover_with_journal) counts addresses. A
//! journal records which phase it holds, and continuing one as the other is refused.
//!
//! A port settles when it answers or its retry budget runs out. An address settles when it
//! answers, by a reply to a probe or an advertisement overheard on the segment, or when
//! every probe aimed at it has been sent as often as the policy allows without an answer.
//! An address whose frames never left is not armed and never settles, so it is asked again.
//!
//! A sweep of an IPv6 range settles less than one of an IPv4 range. The all-nodes
//! solicitation goes to the segment, not to an address, so it settles nothing by itself and
//! only the addresses probed individually settle. A position is also a `u64`, which an IPv6
//! range can exceed; see [`Positions`](crate::model::ip::set::Positions), which numbers what
//! fits and leaves the rest to be asked again. Neither loses coverage; both mean a resumed
//! IPv6 sweep repeats more than a resumed IPv4 one.
//!
//! ## What survives what
//!
//! A journal is flushed but not `fsync`ed. Every failure below except power loss is a
//! process death, and the page cache outlives a process.
//!
//! | Failure | Survives | What is lost |
//! |---|---|---|
//! | `SIGINT`, `SIGTERM` | yes | nothing: the scan finishes its last checkpoint |
//! | A dropped session, `SIGHUP` | yes | at most one checkpoint interval |
//! | An out-of-memory kill, a panic | yes | at most one checkpoint interval |
//! | The machine losing power | mostly | one interval, plus whatever the page cache had not flushed |
//! | A disk filling mid-write | yes | nothing: the cursor is replaced by rename, so the previous one stands |
//!
//! An interval is [`CHECKPOINT_EVERY`](crate::scanner::checkpoint::CHECKPOINT_EVERY).
//! Losing one means the targets settled within it are probed again; none is skipped.
//!
//! ## Journalling is opt-in per scan
//!
//! A scan journals when a caller hands it a journal. The engine writes only to a filesystem
//! it was pointed at. A front end that wants every scan resumable opens a journal for every
//! scan.

/// The version of the on-disk journal format this build writes.
///
/// Lives outside [`format`](mod@format) because a [`manifest`] is written and checked
/// whether or not this build compiled the reader.
///
/// Bump on any change an older build could misread: changing what an existing field means,
/// what a position refers to, or how [`PlanFingerprint`](manifest::PlanFingerprint) is
/// derived. Adding a field a reader may ignore does not need a bump.
pub const JOURNAL_VERSION: u32 = 1;

pub mod cursor;
/// How a journal's files are created: the mode and the ownership, together.
#[cfg(feature = "journal-format")]
mod file;
#[cfg(feature = "journal-format")]
pub mod format;
#[cfg(feature = "journal-format")]
pub mod store;

#[cfg(feature = "journal-format")]
pub use store::Journal;
pub mod lock;
pub mod manifest;
#[cfg(any(feature = "journal-format", feature = "import-settings"))]
pub(crate) mod ownership;
pub mod paths;
pub mod settle;
