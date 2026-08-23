// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a scanning strategy is
//!
//! Two traits, one per phase, and the error a strategy fails with. Everything in
//! [`crate::scanner::strategy`]'s submodules implements one of them, and
//! [`discover`](crate::scanner::discover) and [`scan`](crate::scanner::scan)
//! know nothing about any strategy beyond these methods.
//!
//! ## Findings go to the context, not to the return value
//!
//! Neither trait returns what it found. A strategy writes hosts and ports into
//! the [`ScanContext`] it was built with, and its run method reports only
//! whether the attempt itself got to the end. That is what makes an ARP sweep,
//! a raw SYN scan and a plain TCP connect interchangeable to a caller: build
//! one, run it, read the store — and it is what lets several unrelated
//! strategies write into a single live view while they are still running, which
//! a return value cannot do.
//!
//! It also draws the line between the two ways a scan goes wrong. A target that
//! did not answer is a *finding*, and it lands in the store. A strategy that
//! could not open its socket is a *failure*, and it comes back as
//! [`StrategyError`]. Only the second is an `Err`, because only the second means
//! the absence of hosts proves nothing.
//!
//! ## The two traits are deliberately the same shape
//!
//! Both carry a [`kind`](HostScanner::kind), both take `&mut self`, both return
//! `Result<(), StrategyError>`. Where they differ they differ for a reason:
//! a [`PortScanner`] is fed its targets on a channel and declares which
//! protocols it covers, because several of them run at once and something has
//! to route each target to one that can take it; a [`HostScanner`] owns its
//! targets from construction, because a sweep is aimed at a segment rather than
//! dispatched a target at a time.
//!
//! Neither consumes `self`. A strategy runs once in practice, but taking
//! `self: Box<Self>` to say so would force every caller to box a scanner it
//! already owns, and the orchestrator is not the only caller any more.

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::model::port::Protocol;
use crate::model::target::PlannedTarget;
use crate::scanner::session::{ScanContext, ScannerKind};

/// Why one scanning strategy could not start, or could not finish.
///
/// **This is not how a scan fails.** A scan runs several strategies and carries
/// on with whatever survives, so one of these is recorded in the report's
/// [`failures`](crate::scanner::report::ScanReport::failures) and announced on
/// the event stream rather than returned from
/// [`discover`](crate::scanner::discover) or [`scan`](crate::scanner::scan). It
/// reaches a caller directly when they build and run a strategy themselves.
///
/// The variants are the layers a strategy is assembled from, because that is
/// what determines whether anything can be done about it. A [`Transport`] or
/// [`Channel`] failure is almost always missing privileges and the same
/// unprivileged fallback answers all of them; an [`Interface`] failure is about
/// one interface and the scan of every other one is unaffected.
///
/// [`Transport`]: StrategyError::Transport
/// [`Channel`]: StrategyError::Channel
/// [`Interface`]: StrategyError::Interface
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum StrategyError {
    /// The raw probe transport could not be opened.
    #[error(transparent)]
    Transport(#[from] crate::transport::probe::TransportError),

    /// The link-layer channel a local sweep needs could not be opened.
    #[error(transparent)]
    Channel(#[from] crate::transport::channel::ChannelError),

    /// The interface this strategy was given cannot be probed from.
    #[error("{interface} cannot be probed from: {reason}")]
    Interface {
        /// The interface in question.
        interface: String,
        /// What is missing.
        reason: &'static str,
    },

    /// The strategy's probes could not be built. A bug or an impossible target
    /// rather than an environment problem, since a probe is built from values
    /// this engine chose.
    #[error("the probes for this strategy could not be built: {0}")]
    Probe(String),

    /// A strategy panicked.
    ///
    /// Always a bug in the engine, never a fact about the network, and reported
    /// rather than swallowed: the task it killed would otherwise take the
    /// evidence with it, and the scan would look merely empty.
    #[error("the {scanner:?} scanner panicked: {detail}")]
    Panicked {
        /// Which strategy went down.
        scanner: ScannerKind,
        /// What the runtime said about it.
        detail: String,
    },
}

/// A strategy that finds which hosts, among the targets it was built with, are
/// reachable.
///
/// The discovery half of the pair. Implementations differ entirely in how they
/// ask — ARP and ICMPv6 on a local segment, raw TCP SYN through a gateway, an
/// ordinary connect attempt where neither is possible — and not at all in what a
/// caller does with them.
#[async_trait]
pub trait HostScanner: Send {
    /// Identifies the strategy, so a failure can be attributed to it in the
    /// report and on the event stream.
    fn kind(&self) -> ScannerKind;

    /// Probes every target this strategy owns and records what answered in the
    /// shared store.
    ///
    /// Returns `Ok` when the run reached its end, including an end forced by
    /// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort), and
    /// `Err` only when the strategy itself could not do its job.
    async fn discover_hosts(&mut self) -> Result<(), StrategyError>;
}

/// A strategy that classifies the ports of targets handed to it one at a time.
///
/// The port-scan half of the pair. Where a [`HostScanner`] is aimed at a segment
/// it owns, this consumes the shuffled [`PlannedTarget`] stream a
/// [`Dispatcher`](crate::scanner::dispatcher::Dispatcher) produces, so that
/// several strategies can share one stream of work and none of them has to know
/// how the targets were ordered.
#[async_trait]
pub trait PortScanner: Send {
    /// Identifies the strategy, so a failure can be attributed to it in the
    /// report and on the event stream.
    fn kind(&self) -> ScannerKind;

    /// The transport protocols this strategy can actually probe.
    ///
    /// Read when a scan is assembled, to decide which protocols still need an
    /// unprivileged fallback, and again by
    /// [`CompositePortScanner`](crate::scanner::strategy::composite::CompositePortScanner)
    /// to route each target — so a strategy that under-reports its coverage is
    /// simply never given that work, rather than given it and failing.
    fn supported_protocols(&self) -> Vec<Protocol>;

    /// Probes every target arriving on `targets` and records each port's state
    /// in the shared store.
    ///
    /// Returns `Ok` when the run reached its end, including an end forced by
    /// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort), and
    /// `Err` only when the strategy itself could not do its job.
    async fn scan(&mut self, targets: mpsc::Receiver<PlannedTarget>) -> Result<(), StrategyError>;

    /// Second-pass service identification, run once after a successful
    /// [`scan`](PortScanner::scan) that was not aborted.
    ///
    /// A raw strategy classifies port state from a single exchange and never
    /// holds a connection to fingerprint through, so it opens one here for each
    /// open port. A connect strategy fingerprints inline while it still holds
    /// the live stream, and takes the default no-op. Putting this on the trait
    /// keeps "does this strategy need a second pass?" in the type rather than in
    /// a branch at every call site.
    async fn detect_services(&mut self, _ctx: &ScanContext) {}
}

pub mod composite;
pub mod connect;
pub mod local;
pub mod routed;
