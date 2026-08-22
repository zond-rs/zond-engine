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
//! What is written is a watermark — the position below which everything has
//! settled — a bitmap over the window of positions above it that settled out of
//! order, and a spill list for anything outstanding longer than the window is
//! wide. That is a few kilobytes, fixed, whether the scan is a `/24` or a `/8`,
//! rewritten on a timer rather than on an event. The findings themselves append
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
//! [`ScanReport::merge`](crate::scanner::report::ScanReport::merge) already
//! folds "a later phase of the same job" into a report: phases append, hosts
//! combine, the engine version stays the first one's. So a resumed report
//! carries one [`ScanPhase`](crate::scanner::report::ScanPhase) per sitting,
//! each with its own settings, timings and probe statistics.
//!
//! **That is a property to preserve rather than smooth over.** A resumed scan
//! is not one continuous scan, and a report that presented it as one would be
//! claiming a coverage story it cannot support. Collapsing the phases would
//! make this feature start lying, which is the same argument
//! [`ScannerFailure`](crate::scanner::report::ScannerFailure) and
//! [`TargetScope`](crate::scanner::report::TargetScope) already make about
//! their own fields.
//!
//! ## What lives here
//!
//! [`paths`] computes where a journal goes — a state directory rather than a
//! configuration one, and the invoking user's rather than root's when a scan is
//! run under `sudo`. It creates nothing; a caller that means to write asks it
//! where and then writes.
//!
//! [`format`] is the on-disk shape: the framing, the version bargain, and the
//! vocabulary it shares with the export path. It is behind the `journal-format`
//! feature because it is the one part that needs `serde_json`; [`paths`] needs
//! nothing and is always present, so a front end can list and locate journals
//! without compiling the reader.

//! [`settle`] is what a resume is allowed to skip: the fate of each target, kept
//! apart from the verdict it received, because the engine gives an exhausted
//! probe and one it never sent the same verdict on purpose. It needs no feature
//! — the distinction has to hold whether or not anything is written down.

//! [`cursor`] is how far a scan got: a position in the plan below which
//! everything is settled, plus the few positions above it that settled out of
//! order. It is what a resumed scan subtracts from the plan.
//!
//! [`lock`] tells a scan that is running from one that crashed, so a live
//! journal is never resumed underneath its writer and a dead one never stays
//! locked behind a process id that has been reissued.

//! [`manifest`] is what a journal is a journal *of*: the plan its positions are
//! counted in, fingerprinted, so a resume against an edited plan is refused
//! rather than scanning the wrong targets and reporting success.

/// The version of the on-disk journal format this build writes.
///
/// Lives here rather than beside the reader in [`format`], because it identifies
/// the format whether or not this build compiled a reader for it: a
/// [`manifest`] is written and checked either way.
///
/// Bump on any change an older build could misread. Adding a field a reader may
/// ignore is not such a change; changing what an existing field means, or what a
/// position refers to, is.
pub const JOURNAL_VERSION: u32 = 1;

pub mod cursor;
#[cfg(feature = "journal-format")]
pub mod format;
pub mod lock;
pub mod manifest;
pub mod paths;
pub mod settle;
