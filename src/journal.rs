// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The scan journal
//!
//! What a scan writes down as it runs, so that a scan which did not finish can
//! be continued rather than restarted.
//!
//! ## Why it is always on
//!
//! Nmap's `--resume` requires `-oN` or `-oG` to have been passed *at launch*.
//! That is a bet a user has to place before the information needed to place it
//! exists: nobody knows at the start of a six-hour scan whether the SSH session
//! will survive it. Almost nobody wins that bet, which is why almost nobody
//! resumes an nmap scan — by the time the feature is wanted, it was needed an
//! hour ago.
//!
//! So this journals every scan, without being asked, and a caller resumes one
//! that already exists. The design that makes that affordable is below.
//!
//! ## The journal records a position, not probes
//!
//! The objection to always-on persistence is that a scan is millions of probes
//! and a write per probe would dominate. That is true and does not apply,
//! because nothing here writes per probe.
//!
//! [`Dispatcher`](crate::scanner::dispatcher) walks its units in order and
//! shuffles only *within* a fixed batch, and a
//! [`TargetSet`](crate::model::target::TargetSet) is canonical and immutable
//! from construction — so `unit.iter()` yields the same sequence on every run
//! over the same set. A target's identity in a plan is therefore its position
//! in that enumeration, and a position needs no address stored to name it.
//!
//! What is written is a cursor: a watermark, which is the position below which
//! everything has settled, and the positions above it that settled out of order.
//! Its size follows how far out of order the scan is settling and not how large
//! the scan is, so a `/8` on a thousand ports checkpoints in what a `/24` does,
//! and it is rewritten on a timer rather than on an event. See
//! [`cursor`](mod@cursor), which argues for the sparse form over a bitmap and
//! bounds what the out-of-order set can grow to. The findings themselves append
//! at the rate hosts are *discovered*, which is orders of magnitude below the
//! rate they are probed.
//!
//! ## What "settled" has to mean
//!
//! [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort) documents
//! that a resumed scan "would have a gap in the middle that nothing in the
//! report could describe". That is correct about the mechanism it describes —
//! resuming *in-process state*, where probes were in flight and their targets
//! have no verdict — and it is the failure this module must not reproduce.
//!
//! The rule that avoids it: **a position is settled when its target has a
//! verdict or its retry budget is spent.** Not when a probe was sent, and not
//! when one attempt went unanswered. A target still inside its retry budget is
//! outstanding, and the watermark stalls behind it, which is what the window
//! exists for. A watermark that advances over an unsettled position produces a
//! resumed scan that silently skips targets and reports success, which is the
//! one failure mode worse than not having the feature.
//!
//! ## A resumed scan is two phases, and says so
//!
//! [`ScanReport::merge`](crate::report::ScanReport::merge) already
//! folds "a later phase of the same job" into a report: phases append, hosts
//! combine, the engine version stays the first one's. So a resumed report
//! carries one [`ScanPhase`](crate::report::ScanPhase) per sitting,
//! each with its own settings, timings and probe statistics.
//!
//! **That is a property to preserve rather than smooth over.** A resumed scan
//! is not one continuous scan, and a report that presented it as one would be
//! claiming a coverage story it cannot support. Collapsing the phases would
//! make this feature start lying, which is the same argument
//! [`ScannerFailure`](crate::report::ScannerFailure) and
//! [`TargetScope`](crate::report::TargetScope) already make about
//! their own fields.
//!
//! ## What lives here
//!
//! [`paths`] computes where a journal goes — a state directory rather than a
//! configuration one, and the invoking user's rather than root's when a scan is
//! run under `sudo`. It creates nothing; a caller that means to write asks it
//! where and then writes.
//!
//! [`format`](mod@format) is the on-disk shape: the framing, the version bargain, and the
//! vocabulary it shares with the export path. It is behind the `journal-format`
//! feature because it is the one part that needs `serde_json`; [`paths`] needs
//! nothing and is always present, so a front end can list and locate journals
//! without compiling the reader.
//!
//! [`settle`] is what a resume is allowed to skip: the outcome of each target,
//! kept apart from the verdict it received, because the engine gives an
//! exhausted probe and one it never sent the same verdict on purpose.
//!
//! [`cursor`] is how far a scan got: a position in the plan below which
//! everything is settled, plus the few positions above it that settled out of
//! order. It is what a resumed scan subtracts from the plan.
//!
//! [`lock`] tells a scan that is running from one that crashed, so a live
//! journal is never resumed underneath its writer and a dead one never stays
//! locked behind a process id that has been reissued.
//!
//! [`manifest`] is what the journal is a journal *of*: the plan, fingerprinted
//! so a resume can prove it has not moved, and which of the engine's two phases
//! counted it. [`Plan`](manifest::Plan) is how a caller says which.
//!
//! [`Journal`] is the whole of it on disk: a directory holding the manifest, the
//! cursor, the findings and the lock, created for a scan and reopened to
//! continue one. [`store::list`] enumerates them,
//! [`store::report`] reads one back as the report its scan
//! produced, and [`store::prune`] applies a
//! [`Retention`](store::Retention) policy, so a state directory nobody looks at
//! does not grow without bound.
//!
//! ## Both phases journal, and they count different things
//!
//! [`scan_with_journal`](crate::scanner::scan_with_journal) counts
//! address-and-port pairs; [`discover_with_journal`](crate::scanner::discover_with_journal)
//! counts addresses. Position 400 means the four-hundredth of one or the
//! four-hundredth of the other, never both, so a journal records which phase it
//! holds and continuing one as the other is refused by name.
//!
//! What settles differs with the unit. A port settles when it answers or its
//! retry budget runs out. An address settles when it answers — a reply to a
//! probe, or an advertisement overheard on the segment, since either is a
//! verdict — or when every probe aimed at it has been sent as many times as the
//! policy allows and none of them answered. An address whose frames never left
//! is not armed and never settles, which is the fail-safe direction: it is asked
//! again rather than written off unasked.
//!
//! **A sweep of an IPv6 range settles less than one of an IPv4 range.** The
//! all-nodes solicitation is put to the segment rather than to an address, so it
//! earns no address a verdict of its own; only the addresses probed individually
//! settle. And a position is a `u64`, which an IPv6 range can exceed — see
//! [`Positions`](crate::model::ip::set::Positions), which numbers what fits and
//! leaves the rest to be asked again. Neither loses coverage; both mean a
//! resumed IPv6 sweep repeats more than a resumed IPv4 one.
//!
//! ## What survives what
//!
//! A journal is written as the scan runs and flushed but not `fsync`ed, because
//! every failure below except the last is a *process* death, and the page cache
//! outlives a process. Paying a flush on every checkpoint would buy protection
//! against one case at a cost on every scan that does not need it.
//!
//! | Failure | Survives | What is lost |
//! |---|---|---|
//! | `SIGINT`, `SIGTERM` | yes | nothing: the scan finishes its last checkpoint |
//! | A dropped session, `SIGHUP` | yes | at most one checkpoint interval |
//! | An out-of-memory kill, a panic | yes | at most one checkpoint interval |
//! | The machine losing power | mostly | one interval, plus whatever the page cache had not flushed |
//! | A disk filling mid-write | yes | nothing: the cursor is replaced by rename, so the previous one stands |
//!
//! An interval is [`CHECKPOINT_EVERY`](crate::scanner::checkpoint::CHECKPOINT_EVERY). Losing one
//! costs the targets settled within it being probed again, never a target being
//! skipped: what a cursor does not claim is re-probed.
//!
//! ## Journalling is something a caller asks for
//!
//! There is no setting that turns it on, because there is nothing to turn off: a
//! scan journals when a caller hands it a journal and does not when they do not.
//! The engine never writes to a filesystem it was not pointed at — see
//! `import::settings`, which draws that boundary and explains it — so declining
//! is the default and asking is the deliberate act.
//!
//! A front end that wants every scan resumable opens a journal for every scan,
//! and one that wants a standing "not on this machine" keeps that preference in
//! its own configuration. Neither is the engine's business.

/// The version of the on-disk journal format this build writes.
///
/// Lives here rather than beside the reader in [`format`](mod@format), because it identifies
/// the format whether or not this build compiled a reader for it: a
/// [`manifest`] is written and checked either way.
///
/// Bump on any change an older build could misread. Adding a field a reader may
/// ignore is not such a change; changing what an existing field means, what a
/// position refers to, or how
/// [`PlanFingerprint`](manifest::PlanFingerprint) is derived, is.
///
/// Version 2 is the third of those. Version 1 derived the fingerprint through
/// `DefaultHasher`, whose output the standard library declines to keep stable
/// across compiler releases, so the value a version 1 journal recorded is not one
/// this build can reproduce. Such a journal still reads: [`store::report`] and
/// [`store::list`] work on it exactly as before. Only continuing one is refused,
/// by [`store::OpenError::VersionTooOld`], because a fingerprint that cannot be
/// recomputed cannot prove the plan has not moved.
pub const JOURNAL_VERSION: u32 = 2;

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
pub mod paths;
pub mod settle;
