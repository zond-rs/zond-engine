// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a scanning strategy is
//!
//! Two traits, one per phase, and the error a strategy fails with.
//! [`discover`](crate::scanner::discover) and [`scan`](crate::scanner::scan)
//! know nothing about any strategy beyond these methods.
//!
//! ## How the submodules are arranged
//!
//! By the phase a strategy serves, the same axis
//! [`ScanKind`](crate::report::ScanKind) and
//! [`PhaseRecorder`](crate::scanner::recorder::PhaseRecorder) use. Transport and
//! privilege vary inside a category, because abstracting over them is what the two
//! traits are for.
//!
//! | module | what it is |
//! |---|---|
//! | [`local`], [`routed`], [`connect`] | which hosts are there: at the link layer, through a gateway, or by ordinary connect |
//! | [`ports`] | which ports are open |
//! | [`identify`] | what a machine is, asked of hosts already found |
//! | [`topology`] | what is between here and a host |
//! | [`passive`] | what a link already carries, having sent nothing |
//! | [`composite`] | routes each target to a strategy that covers its protocol |
//! | `raw`, `frames`, `icmp_error`, `sweep` | internal: what strategies are built from, what they read, and what they all keep track of |
//!
//! ## Findings go to the context
//!
//! Neither trait returns what it found. A strategy writes hosts and ports into the
//! [`ScanContext`] it was built with, and its run method reports only whether the
//! attempt got to the end. That makes an ARP sweep, a raw SYN scan and a TCP connect
//! interchangeable to a caller (build one, run it, read the store), and lets several
//! strategies write into one live view while they run.
//!
//! A target that did not answer is a finding and lands in the store. A strategy that
//! could not open its socket is a failure and comes back as [`StrategyError`]: then
//! the absence of hosts proves nothing.
//!
//! ## Shape of the traits
//!
//! Both carry a [`kind`](HostScanner::kind), take `&mut self` and return
//! `Result<(), StrategyError>`. A [`PortScanner`] is fed its targets on a channel and
//! declares which protocols it covers, because several run at once and each target
//! must be routed to one that can take it. A [`HostScanner`] owns its targets from
//! construction, because a sweep is aimed at a whole segment.
//!
//! Neither consumes `self`: taking `self: Box<Self>` would force every caller to box
//! a scanner it already owns.

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::journal::settle::Outcome;
use crate::model::port::{PortState, Protocol};
use crate::model::target::PlannedTarget;
use crate::report::ScannerKind;
use crate::scanner::session::ScanContext;

/// Why one scanning strategy could not start, or could not finish.
///
/// A scan runs several strategies and carries on with whatever survives, so
/// [`discover`](crate::scanner::discover) and [`scan`](crate::scanner::scan) record
/// one of these in the report's [`failures`](crate::report::ScanReport::failures)
/// and announce it on the event stream. It reaches a caller directly only when they
/// build and run a strategy themselves.
///
/// The variants are the layers a strategy is assembled from. A [`Transport`],
/// [`Channel`] or [`Capture`] failure is most often missing privileges, which a
/// scan's unprivileged fallback covers; the underlying error says which. An
/// [`Interface`] failure concerns one interface and leaves the others unaffected.
///
/// [`Transport`]: StrategyError::Transport
/// [`Channel`]: StrategyError::Channel
/// [`Capture`]: StrategyError::Capture
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

    /// Nothing could be captured on the links a listener was given.
    ///
    /// The capture's own error, which names each link and what refused it.
    #[error(transparent)]
    Capture(#[from] crate::transport::capture::CaptureError),

    /// The interface this strategy was given cannot be probed from.
    #[error("{interface} cannot be probed from: {reason}")]
    Interface {
        /// The interface in question.
        interface: String,
        /// What is missing.
        reason: &'static str,
    },

    /// The transport a port scan was handed was opened for another kind of
    /// probe, so its capture would admit none of the scan's answers.
    ///
    /// Refused because a scan that hears nothing files every port as silent,
    /// which looks exactly like a network that drops everything. Every port it was
    /// handed is recorded as unasked.
    #[error(
        "{} transport cannot hear {} port scan's answers",
        .kind.spoken(),
        spoken_protocol(*.protocol)
    )]
    MismatchedTransport {
        /// The kind the transport was opened for.
        kind: crate::transport::probe::ProbeKind,
        /// The protocol of the port scan it was handed to.
        protocol: crate::model::port::Protocol,
    },

    /// The strategy's probes could not be built. A bug or an impossible target,
    /// since a probe is built from values this engine chose.
    #[error("the probes for this strategy could not be built: {0}")]
    Probe(String),

    /// A strategy panicked.
    ///
    /// Always an engine bug. Reported so the scan does not look merely empty.
    #[error("the {scanner:?} scanner panicked: {detail}")]
    Panicked {
        /// Which strategy went down.
        scanner: ScannerKind,
        /// What the runtime said about it.
        detail: String,
    },
}

/// A port scan's protocol in words, with its article, as
/// [`StrategyError::MismatchedTransport`] names the scan it was handed.
const fn spoken_protocol(protocol: crate::model::port::Protocol) -> &'static str {
    use crate::model::port::Protocol;
    match protocol {
        Protocol::Tcp => "a TCP",
        Protocol::Udp => "a UDP",
        Protocol::Sctp => "an SCTP",
    }
}

/// A strategy that finds which hosts, among the targets it was built with, are
/// reachable.
///
/// The discovery half of the pair. Implementations differ in how they ask: ARP and
/// ICMPv6 on a local segment, raw TCP SYN through a gateway, or an ordinary connect
/// where neither is possible.
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
/// The port-scan half of the pair. It consumes the shuffled [`PlannedTarget`]
/// stream a [`Dispatcher`](crate::scanner::dispatcher::Dispatcher) produces, so
/// several strategies can share one stream of work without knowing how it was
/// ordered.
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
    /// to route each target. A strategy that under-reports its coverage is never
    /// given that work.
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
    /// A raw strategy holds no connection to fingerprint through, so it opens one
    /// here for each open port. A connect strategy fingerprints inline while it
    /// holds the live stream, and takes the default no-op.
    async fn detect_services(&mut self, _ctx: &ScanContext) {}
}

/// Records `target`, which no scanner asked about, as a port nobody asked
/// about: on its host as [`PortState::Unasked`], and owed to a resume.
///
/// Used by whoever leaves a port unprobed: a scanner stopped with it still queued,
/// a scanner that refused its whole plan, and a router with no scanner left to hand
/// it to. Without it a truncated port list reads like a complete one, an unreached
/// host is missing from the report, and a diff against another scan shows the
/// network moving. The outcome carries no position, so a resume asks the question.
pub(crate) fn record_unasked(ctx: &ScanContext, target: &PlannedTarget) {
    let port =
        crate::fingerprint::baseline_port(target.port(), target.protocol(), PortState::Unasked);
    ctx.update_host(target.ip(), |host| {
        host.add_port(port);
    });
    ctx.record_outcome(Outcome::Unasked);
}

pub mod composite;
pub mod connect;
// ICMP error parsing shared by the UDP port scan (a port's verdict) and the trace
// (a router's identity).
pub(crate) mod icmp_error;
// Frame readers shared by the local sweep, for replies to its probes, and the
// passive listener, for unsolicited frames.
pub(crate) mod frames;
pub mod local;
// What a machine is, asked of hosts already in the store.
pub mod identify;
pub mod passive;
// Which ports are open, and the machinery all four raw port scanners share.
pub mod ports;
// Which IP protocols a host accepts. Runs after the port scan, only against hosts
// that answered.
pub mod protocols;
// What every raw strategy is built from: how a probe reaches the wire, and the
// timings a probe over a routed path is held to.
pub(crate) mod raw;
pub mod routed;
// What the three probing sweeps keep track of in common.
pub(crate) mod sweep;
// What is between here and a host. Runs after the port scan, because the ports
// that reach a host decide how to probe the path to it.
pub mod topology;
