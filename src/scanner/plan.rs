// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Deciding what a scan will do, before it does any of it
//!
//! A plan is the set of strategies a scan intends to run, worked out from the
//! targets and the host's own network configuration, with nothing opened and
//! nothing sent. [`discover`](crate::scanner::discover) and
//! [`scan`](crate::scanner::scan) build one and immediately execute it. A caller
//! orchestrating their own scan can build one, look at it, change it, and run
//! the parts they want.
//!
//! ## Why planning is separated from running at all
//!
//! Deciding is where every interesting judgement in a scan lives. Which
//! interface reaches a target, whether a `/64` can be walked, whether a
//! link-local address without a zone can be probed at all, whether a sweep may
//! take leads from the host's neighbour table, which protocols still need an
//! unprivileged fallback: all of that is settled before a single socket is
//! opened, and none of it needs a socket to settle.
//!
//! Fused into the code that spawns tasks, those judgements are unreachable: they
//! cannot be inspected without running a scan, cannot be tested without a host
//! that happens to have the right interfaces, and cannot be adjusted at all.
//! Split out, a plan is a value. `zond --dry-run` is a plan printed instead of
//! run. A caller who wants to sweep two of their five links drops three steps
//! and runs the rest. A test asserts on what *would* happen against a
//! hand-written interface table.
//!
//! ## What a plan costs to build
//!
//! No packets and no sockets. Building one does read the machine's own
//! configuration, the interface list, the routing table, and for a sweep the
//! IPv6 neighbour table, because which strategy reaches a target is a fact
//! about this host and cannot be guessed. Those are ordinary reads of local
//! state, they open nothing, and they are the same reads
//! [`crate::system::interface`] performs for any caller.
//!
//! ## What a plan does not promise
//!
//! That every step will run. A step becomes a strategy through
//! [`DiscoveryStep::into_scanner`], and that is where sockets are opened and
//! where the environment gets its say: a capture that cannot be opened, an
//! interface that disappeared between planning and running. Those surface as a
//! [`StrategyError`] per step, and the scan continues with the rest. A plan is
//! what the engine means to do, not a guarantee about a machine it does not
//! control.

use std::collections::HashMap;
use std::net::IpAddr;

use tokio::sync::mpsc::UnboundedSender;

use crate::config::limits;
use crate::config::{ProbeTuning, ZondConfig};
use crate::model::exclusion::Exclusions;
use crate::model::ip::range::{IpRange, Ipv6Range};
use crate::model::ip::scoped::ZoneMap;
use crate::model::ip::set::IpSet;
use crate::model::port::Protocol;
use crate::model::technique::TcpScanTechnique;
use crate::report::ScannerKind;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::connect::{
    ConnectPortScanner, ConnectScanner, ConnectUdpPortScanner,
};
use crate::scanner::strategy::local::{LocalScanner, Scope};
use crate::scanner::strategy::ports::{
    IdlePortScanner, SctpPortScanner, TcpPortScanner, UdpPortScanner,
};
use crate::scanner::strategy::routed::{RoutedScanner, SynPorts};
use crate::scanner::strategy::{HostScanner, PortScanner, StrategyError};
use crate::system::interface::Link;
use crate::system::interface::{self, RoutedTarget};
use crate::system::neighbor_cache;
use crate::system::privilege::Privilege;
use crate::{counted, info, warn};

/// Something the scan will not do, decided at planning time.
///
/// A refusal is not a failure of the network and not an address that went
/// unanswered: it was never probed, and the reason is knowable before anything
/// is sent. It is carried out of the plan rather than dropped because the one
/// thing a scanner may never do is stay quiet about ground it did not cover: a
/// caller has to be able to tell "nothing is there" from "nobody looked", and
/// only one of those is visible in a host count.
#[derive(Debug, Clone)]
pub struct RefusedStep {
    /// The strategy that would have taken this work.
    pub scanner: ScannerKind,
    /// What cannot be done, and what the caller could write instead.
    pub reason: String,
}

impl RefusedStep {
    /// The TCP half left undone because `technique` cannot be expressed without
    /// raw sockets.
    ///
    /// A connect scan completes handshakes, so it answers roughly the question
    /// a SYN scan asks. It cannot send a FIN, a flagless segment or a bare ACK,
    /// so it cannot answer what any of those were asked, and substituting it
    /// silently would hand back verdicts from a technique nobody chose.
    ///
    /// Written once because it is reached from two places, and they are not
    /// redundant: [`PortScanPlan::build`] refuses ahead of time when there are
    /// no raw sockets to be had, while the scan's own coverage check refuses
    /// after the fact when a raw socket was expected and would not open. Same
    /// cause, same words, two moments at which it becomes knowable.
    pub fn technique_needs_raw_sockets(technique: TcpScanTechnique) -> Self {
        Self {
            scanner: ScannerKind::for_raw_tcp(technique),
            reason: format!(
                "the {technique} technique needs raw sockets, which this process does \
                 not have, and a connect scan answers a different question - so no TCP \
                 port was probed"
            ),
        }
    }

    /// SCTP ports were named by a scan with no raw sockets to probe them with.
    ///
    /// There is no unprivileged form of an INIT scan: the kernel offers no way
    /// to send a chunk and read the answer without an SCTP stack and an
    /// association, and an association is the one thing this scan avoids
    /// completing. So the ports are refused rather than answered by something
    /// that asked a different question.
    pub fn sctp_needs_raw_sockets() -> Self {
        Self {
            scanner: ScannerKind::SctpPort,
            reason: "the sctp ports named for this scan need raw sockets, which this process \
                     does not have, and there is no unprivileged init probe - so no sctp port \
                     was probed"
                .to_string(),
        }
    }

    /// SCTP ports were named for a scan running as an idle scan, which probes
    /// through a third party and has no way to carry an INIT.
    ///
    /// The refusal is the point rather than a limitation. An INIT sent directly
    /// would leave this host's own address on the target, which is the one thing
    /// an idle scan exists to avoid.
    pub fn sctp_not_in_an_idle_scan() -> Self {
        Self {
            scanner: ScannerKind::SctpPort,
            reason: "an idle scan reads a third party's counter, which carries no sctp probe, \
                     and sending one directly would put this host's address on the target - so \
                     no sctp port was probed"
                .to_string(),
        }
    }

    /// UDP ports were named for a scan running as an idle scan, for the reason
    /// [`sctp_not_in_an_idle_scan`](Self::sctp_not_in_an_idle_scan) gives:
    /// the zombie's counter moves only for the TCP segments it answers, so a
    /// datagram has no way to be read through it, and one sent directly would
    /// put this host's address on the target.
    pub fn udp_not_in_an_idle_scan() -> Self {
        Self {
            scanner: ScannerKind::UdpPort,
            reason: "an idle scan reads a third party's counter, which carries no udp probe, \
                     and sending one directly would put this host's address on the target - so \
                     no udp port was probed"
                .to_string(),
        }
    }

    /// The TCP half left undone on the targets a frames-only run cannot reach.
    ///
    /// [`technique_needs_raw_sockets`](Self::technique_needs_raw_sockets) for
    /// part of a scan: the process sends every other target the probe asked for,
    /// and these, which only the kernel can carry, get no connect standing in
    /// for a technique it does not express.
    pub(crate) fn technique_beyond_frames(technique: TcpScanTechnique, targets: u128) -> Self {
        Self {
            scanner: ScannerKind::for_raw_tcp(technique),
            reason: format!(
                "this process can send self-built frames and holds no raw socket, and {} \
                 out of a frame's reach; a connect scan answers a different question than \
                 the {technique} technique asks - so no TCP port on {} was probed",
                counted(targets, "target is", "targets are"),
                if targets == 1 { "it" } else { "them" },
            ),
        }
    }

    /// The SCTP ports on the targets a frames-only run cannot reach, for the
    /// reason [`sctp_needs_raw_sockets`](Self::sctp_needs_raw_sockets) gives.
    pub(crate) fn sctp_beyond_frames(targets: u128) -> Self {
        Self {
            scanner: ScannerKind::SctpPort,
            reason: format!(
                "this process can send self-built frames and holds no raw socket, and {} \
                 out of a frame's reach; there is no unprivileged init probe - so no sctp \
                 port on {} was probed",
                counted(targets, "target is", "targets are"),
                if targets == 1 { "it" } else { "them" },
            ),
        }
    }

    /// A pass that sends its own segments to a host, left undone on the hosts a
    /// frames-only run cannot reach.
    ///
    /// Nothing stands in for these passes: each reads something only a packet it
    /// built can ask, which is what a connect cannot send. `pass` names the pass
    /// the way a reader would.
    pub(crate) fn pass_beyond_frames(scanner: ScannerKind, pass: &str, hosts: u128) -> Self {
        Self {
            scanner,
            reason: format!(
                "this process can send self-built frames and holds no raw socket, and {} \
                 out of a frame's reach - so {pass} left {} alone",
                counted(hosts, "host is", "hosts are"),
                if hosts == 1 { "it" } else { "them" },
            ),
        }
    }

    /// A pass that would send the target its own packets, asked for under an
    /// idle scan.
    ///
    /// An idle scan forges every probe from its zombie so the target never
    /// hears from this host; a pass that opens a connection to the target or
    /// sends it a probe from here is the one thing the technique exists to
    /// avoid. So a pass the caller asked for that would do it is refused rather
    /// than run in the open, on the same reasoning
    /// [`idle_needs_privilege`](Self::idle_needs_privilege) refuses the scan
    /// itself. `pass` names it the way a reader would, and `scanner` is the
    /// strategy the report files the refusal under.
    pub(crate) fn pass_not_in_an_idle_scan(scanner: ScannerKind, pass: &str) -> Self {
        Self {
            scanner,
            reason: format!(
                "an idle scan sends the target nothing from this host, and {pass} would \
                 contact it directly - so it was not run"
            ),
        }
    }

    /// An idle scan was asked for through a zombie the exclusions forbid.
    ///
    /// The scan reads the zombie's counter by probing it again and again, so
    /// running it would send an excluded address the most traffic of anything
    /// in the scan. There is no fallback, for the reason
    /// [`idle_needs_privilege`](Self::idle_needs_privilege) gives.
    pub(crate) fn idle_zombie_excluded(zombie: IpAddr) -> Self {
        Self {
            scanner: ScannerKind::Idle,
            reason: format!(
                "the idle scan's zombie {zombie} is excluded, and the scan reads its counter \
                 by probing it again and again - and scanning the target under this host's \
                 own address instead would betray the scan, so no TCP port was probed"
            ),
        }
    }

    /// An idle scan was asked for without the privilege it needs.
    ///
    /// The forged source address of an idle scan's probe can only ride a
    /// self-built frame, which needs privilege. There is no
    /// fallback: scanning the target under this host's own address is the one
    /// thing an idle scan exists to avoid, so the whole of it is refused rather
    /// than run in the open.
    pub fn idle_needs_privilege() -> Self {
        Self {
            scanner: ScannerKind::Idle,
            reason: "an idle scan forges the source address of its probes, which needs \
                     a self-built frame this process cannot open without privilege - and \
                     scanning the target under this host's own address instead would \
                     betray the scan, so no TCP port was probed"
                .to_owned(),
        }
    }

    /// A routed IPv6 range with more addresses than any strategy can walk.
    ///
    /// See [`MAX_ENUMERABLE_ADDRESSES`](crate::system::interface::MAX_ENUMERABLE_ADDRESSES)
    /// for why there is a ceiling at all.
    pub fn routed_range_not_enumerable(range: &Ipv6Range) -> Self {
        Self {
            scanner: ScannerKind::Routed,
            reason: format!(
                "{}: too large to probe one address at a time, and routed IPv6 has \
                 no other strategy yet. Give specific addresses or a smaller prefix.",
                describe(range)
            ),
        }
    }

    /// The same range, refused by an unprivileged scan.
    ///
    /// Separate wording from [`routed_range_not_enumerable`](Self::routed_range_not_enumerable)
    /// because the remedy is different and it is the more useful half of the
    /// message: a range this size *is* reachable on the local segment with raw
    /// sockets, through the all-nodes echo, which sweeps a `/64` in one packet
    /// rather than walking it. A user told only "too large" would go and narrow
    /// a prefix that root would have covered whole.
    pub fn unprivileged_range_not_enumerable(range: &Ipv6Range) -> Self {
        Self {
            scanner: ScannerKind::Connect,
            reason: format!(
                "{}: too large to probe one address at a time, and an unprivileged \
                 scan has no other strategy. Run with root to sweep a segment this \
                 size, or give specific addresses or a smaller prefix.",
                describe(range)
            ),
        }
    }

    /// A port target that is link-local and names no interface.
    ///
    /// `fe80::1` names a different machine on every segment, and every interface
    /// holds an `fe80::/64`, so there is nothing to choose between them. Written
    /// `fe80::1%en0` it names one, and the scan sends from that interface.
    ///
    /// [`RoutedTargets::ambiguous`](crate::system::interface::RoutedTargets)
    /// refuses the same target on the discovery path.
    pub fn link_local_port_target_needs_an_interface(range: &Ipv6Range) -> Self {
        let target = name(range);
        Self {
            scanner: ScannerKind::SynPort,
            reason: format!(
                "{target} is link-local and names no interface, so it names a \
                 different machine on every segment this host is on. Say which: \
                 {}%en0, naming the interface the segment is reached through.",
                range.start_addr()
            ),
        }
    }

    /// One link-local address given on two interfaces in a single scan.
    ///
    /// Each is a different machine, and a port scan records its verdicts under
    /// the address it probed, so the two sets of answers would land on one host
    /// with nothing to say which segment either came from.
    pub fn link_local_port_target_names_two_segments(range: &Ipv6Range) -> Self {
        let target = name(range);
        Self {
            scanner: ScannerKind::SynPort,
            reason: format!(
                "{target} was named on two interfaces at once, and each is a \
                 different machine. Scan one segment at a time."
            ),
        }
    }

    /// An on-link IPv6 range too large to walk, in a scan that will not sweep
    /// the segment it is on.
    ///
    /// The one range this engine can reach and declines to. A local segment is
    /// covered by the all-nodes solicitation, which is a single packet whatever
    /// the prefix length, so the remedy is a sweep rather than a smaller
    /// prefix. A [`Scope::Sweep`] step already sends that packet and refuses
    /// nothing.
    ///
    /// Walking it instead would fail silently: the address count overflows the
    /// deadline's target count, the sweep is budgeted as though it had no
    /// targets at all, and it stops a couple of thousand solicitations into a
    /// space of eighteen quintillion having reported the range covered.
    pub fn local_range_needs_a_sweep(range: &Ipv6Range) -> Self {
        Self {
            scanner: ScannerKind::Local,
            reason: format!(
                "{}: too large to probe one address at a time, and this scan is \
                 not sweeping the segment. The all-nodes solicitation reaches a \
                 prefix this size in one packet - scan the segment rather than \
                 the range, or give specific addresses.",
                describe(range)
            ),
        }
    }
}

/// Takes the IPv6 ranges out of `targets` that are too large to probe one
/// address at a time, leaving the rest.
///
/// The same test the routed path applies, applied where the local path needed
/// it: [`is_enumerable`](interface::is_enumerable) asks it of a range rather
/// than of a set, so a set holding a `/64` and three literal addresses keeps
/// the three.
///
/// IPv4 is untouched, on the same reasoning that leaves it untouched
/// everywhere else: every IPv4 range is finite in a way a person can reason
/// about.
fn withhold_unwalkable(targets: &mut IpSet) -> Vec<Ipv6Range> {
    let unwalkable: Vec<Ipv6Range> = targets
        .v6()
        .iter()
        .filter(|range| !interface::is_enumerable(range))
        .copied()
        .collect();

    if unwalkable.is_empty() {
        return unwalkable;
    }

    let mut kept = IpSet::new();
    for range in targets.v4() {
        kept.push_v4_range(*range);
    }
    for range in targets.v6() {
        if interface::is_enumerable(range) {
            kept.push_v6_range(*range);
        }
    }
    kept.canonicalize();
    *targets = kept;

    unwalkable
}

impl From<RefusedStep> for crate::report::Refusal {
    /// The recorded form of a refusal a plan carries.
    ///
    /// One direction only. A plan's refusal knows how it was decided, and a
    /// recorded one is what a reader is handed afterwards; going back would mean
    /// inventing the decision from the words.
    fn from(step: RefusedStep) -> Self {
        Self::new(step.scanner, step.reason)
    }
}

/// A range as a person wrote it: one address when it covers one, and the span
/// otherwise.
fn name(range: &Ipv6Range) -> String {
    match range.start_addr() == range.end_addr() {
        true => range.start_addr().to_string(),
        false => format!("{}-{}", range.start_addr(), range.end_addr()),
    }
}

/// The opening both refusals above share: which range, and how big it is.
///
/// The size is quoted because it is the argument. "Too large" invites the reader
/// to disagree; "18446744073709551616 addresses" does not.
fn describe(range: &Ipv6Range) -> String {
    format!(
        "{}-{} is {} addresses",
        range.start_addr(),
        range.end_addr(),
        range.len()
    )
}

/// One strategy a discovery sweep intends to run.
///
/// Each variant names a way of reaching a target and the targets it was given.
/// Turning one into a running strategy is [`into_scanner`](Self::into_scanner);
/// until then it is inert.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DiscoveryStep {
    /// ARP and ICMPv6 across one interface's own segment, for targets that share
    /// it. The cheapest and most informative of the three: it is the only one
    /// that yields a MAC address, and the only one that can find a neighbour
    /// nobody named.
    Local {
        /// The interface to sweep from.
        interface: Box<Link>,
        /// The addresses on its segment. May be empty for a
        /// [`Scope::Sweep`], whose most important probe is addressed to nobody.
        targets: IpSet,
        /// Whether this sweep may find hosts nobody asked about.
        scope: Scope,
    },
    /// Raw TCP SYN to targets reached through a gateway, each already paired
    /// with the source address the host would route it from.
    Routed {
        /// The destinations, with their source addresses.
        targets: Vec<RoutedTarget>,
        /// The ports every target is asked about. The common five unless
        /// [`DiscoveryPlan::asking_tcp`] said otherwise.
        ports: SynPorts,
    },
    /// Raw SCTP INIT to the same routed targets, for a scan whose ports name
    /// SCTP.
    ///
    /// Runs beside [`Routed`](Self::Routed) rather than instead of it. A host
    /// answers whichever transport reaches it, and one that answers only SCTP is
    /// reported down by a SYN sweep and never has its ports probed at all, since
    /// the port phase covers what discovery found.
    RoutedSctp {
        /// The destinations, with their source addresses.
        targets: Vec<RoutedTarget>,
        /// The port every INIT is aimed at.
        port: u16,
    },
    /// Ordinary TCP connect attempts, for targets with no route and no segment:
    /// loopback, or anything the OS declined to resolve. Needs no privileges.
    ///
    /// For a process whose raw strategies send frames and nothing else, also
    /// whatever a frame cannot reach, which the scan moves here from the steps
    /// that would have framed it.
    Connect {
        /// The addresses to try.
        targets: IpSet,
        /// The ports every address is asked about, the same set a routed step
        /// asks. The common five unless [`DiscoveryPlan::asking_tcp`] said
        /// otherwise.
        ports: SynPorts,
    },
}

impl DiscoveryStep {
    /// Which strategy this step becomes.
    pub fn kind(&self) -> ScannerKind {
        match self {
            Self::Local { .. } => ScannerKind::Local,
            Self::Routed { .. } => ScannerKind::Routed,
            Self::RoutedSctp { .. } => ScannerKind::RoutedSctp,
            Self::Connect { .. } => ScannerKind::Connect,
        }
    }

    /// How many addresses this step covers.
    ///
    /// Zero is meaningful rather than empty: a [`Scope::Sweep`] step with no
    /// addresses still sends the all-nodes solicitation its whole segment may
    /// answer.
    pub fn target_count(&self) -> u128 {
        match self {
            Self::Local { targets, .. } | Self::Connect { targets, .. } => targets.len(),
            Self::Routed { targets, .. } | Self::RoutedSctp { targets, .. } => {
                targets.len() as u128
            }
        }
    }

    /// Opens whatever this step needs and hands back the strategy to run.
    ///
    /// This is where the plan stops being free. A local step opens a
    /// link-layer channel on its interface; a routed step opens a raw transport
    /// and a capture. Either can fail on an environment the plan could not see,
    /// and that is a [`StrategyError`] rather than a panic, so a caller can
    /// record it and carry on with the steps that did build.
    ///
    /// `dns_tx` is where a strategy posts addresses worth a reverse lookup;
    /// pass `None` to do no hostname resolution.
    pub fn into_scanner(
        self,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        tuning: ProbeTuning,
    ) -> Result<Box<dyn HostScanner>, StrategyError> {
        match self {
            Self::Local {
                interface,
                targets,
                scope,
            } => Ok(Box::new(LocalScanner::new(
                *interface,
                targets,
                ctx,
                dns_tx,
                scope,
                tuning.retry,
            )?)),
            Self::Routed { targets, ports } => Ok(Box::new(RoutedScanner::over_tcp(
                targets, ctx, dns_tx, tuning, ports,
            )?)),
            Self::RoutedSctp { targets, port } => Ok(Box::new(RoutedScanner::over_sctp(
                targets, ctx, dns_tx, tuning, port,
            )?)),
            Self::Connect { targets, ports } => Ok(Box::new(ConnectScanner::asking(
                targets,
                ctx,
                &tuning.evasion,
                ports,
            ))),
        }
    }
}

/// What a discovery sweep intends to do.
///
/// Build one with [`build`](Self::build), read it, change it, run it. See the
/// [module documentation](self) for why this is a value rather than a function
/// call.
#[derive(Debug, Clone)]
pub struct DiscoveryPlan {
    steps: Vec<DiscoveryStep>,
    refusals: Vec<RefusedStep>,
    ours: IpSet,
}

impl DiscoveryPlan {
    /// Works out which strategies would cover `targets`, opening nothing.
    ///
    /// `scope` decides whether the sweep may go beyond what it was given.
    /// [`Scope::Sweep`] earns a step for the link even when no address mapped to
    /// it, its all-nodes echo is one packet the whole segment may answer, and
    /// takes candidate addresses from the host's IPv6 neighbour table, which is
    /// the only source the engine has for an IPv6 address nobody named.
    /// [`Scope::Targeted`] does neither: probing addresses nobody asked about is
    /// defensible for `lan` and surprising for a scan of one named address.
    ///
    /// `exclusions` is what a sweep's own discoveries are held to. The target
    /// list has already been withheld against them by the time it arrives here,
    /// in `withhold_targets`, before anything is opened. A sweep then adds
    /// addresses the list never had, from the host's neighbour table, and those
    /// were never subtracted from anything. `seed_from_neighbor_table` is where
    /// they arrive.
    ///
    /// `forced` pins the source addresses off-link targets are probed from,
    /// empty for a scan that let the routing table choose.
    pub fn build(targets: IpSet, scope: Scope, exclusions: &Exclusions, forced: &[IpAddr]) -> Self {
        let mut steps = Vec::new();
        let mut refusals = Vec::new();

        let interface::RoutedTargets {
            mut local,
            routed,
            unmapped,
            ours,
            ambiguous,
            unenumerable,
        } = interface::map_ips_to_interfaces_forced(targets, forced);

        // A link-local target naming no interface. Refused rather than guessed
        // at: every interface has an `fe80::/64`, so probing the first one that
        // matches would scan an arbitrary segment and report the address absent
        // when it is present on another.
        for range in &ambiguous {
            refusals.push(RefusedStep {
                scanner: ScannerKind::Local,
                reason: format!(
                    "{} is link-local, so it names a different machine on every \
                     segment. Say which: {}%<interface>.",
                    range.start_addr(),
                    range.start_addr()
                ),
            });
        }

        // Ranges no strategy can take. A routed IPv6 prefix cannot be walked
        // (see `MAX_ENUMERABLE_ADDRESSES`), and with no discovery strategy that
        // searches a scope instead of a list, saying so is the whole of what
        // the engine can honestly do with one.
        for range in &unenumerable {
            refusals.push(RefusedStep::routed_range_not_enumerable(range));
        }

        // A sweep may probe addresses nobody named, so it may also take leads
        // from the host itself. A targeted run may not.
        if matches!(scope, Scope::Sweep) {
            include_swept_link(&mut local);
            seed_from_neighbor_table(&mut local, exclusions);
        }

        for (interface, mut targets) in local {
            // An on-link range too large to walk is dropped here rather than
            // handed on. `map_ips_to_interfaces` keeps such a range whole,
            // because the strategy for a segment is the all-nodes solicitation
            // and that is one packet whatever the prefix length - but the
            // solicitation is a sweep's, and the walk below it is what a
            // targeted run has. See `local_range_needs_a_sweep`.
            for range in withhold_unwalkable(&mut targets) {
                match scope {
                    // Covered: the sweep sends the one packet the whole segment
                    // answers, so nothing is lost by not walking the prefix.
                    Scope::Sweep => info!(
                        verbosity = 1,
                        "{} is swept by solicitation rather than walked",
                        describe(&range)
                    ),
                    Scope::Targeted => {
                        refusals.push(RefusedStep::local_range_needs_a_sweep(&range))
                    }
                }
            }

            // A sweep's link earns a step whether or not any address mapped to
            // it. A targeted run has nothing to send without targets.
            if targets.is_empty() && matches!(scope, Scope::Targeted) {
                continue;
            }
            // Said here, once, because this is where it is decided. The lookup
            // that found the link answers whoever asks, and is asked more than
            // once a run.
            if matches!(scope, Scope::Sweep) {
                info!(
                    verbosity = 1,
                    "sweeping {}: {}",
                    interface.name(),
                    match targets.len() {
                        0 => "IPv6 neighbours only, having no IPv4 range to walk".to_string(),
                        count => counted(count, "address", "addresses"),
                    }
                );
            }
            steps.push(DiscoveryStep::Local {
                interface: Box::new(interface),
                targets,
                scope,
            });
        }

        if !routed.is_empty() {
            steps.push(DiscoveryStep::Routed {
                targets: routed,
                ports: SynPorts::common(),
            });
        }

        if !unmapped.is_empty() {
            steps.push(DiscoveryStep::Connect {
                targets: unmapped,
                ports: SynPorts::common(),
            });
        }

        Self {
            steps,
            refusals,
            ours,
        }
    }

    /// Adds an SCTP sweep beside every routed step, asking `port`.
    ///
    /// Apart from [`build`](Self::build) for the reason
    /// [`PortScanPlan::cover_sctp`] is: what decides it is the
    /// port specification, which belongs to the targets and not to the addresses
    /// this plan was built from. A caller that never mentions SCTP sweeps with a
    /// SYN alone and opens no second socket.
    ///
    /// Only the routed steps gain one. A local segment is swept at the link
    /// layer, where ARP and neighbour discovery answer whatever the host speaks
    /// above them, and an unprivileged connect step has no raw socket to send an
    /// INIT through.
    pub fn also_over_sctp(&mut self, port: u16) {
        let sctp: Vec<DiscoveryStep> = self
            .steps
            .iter()
            .filter_map(|step| match step {
                DiscoveryStep::Routed { targets, .. } => Some(DiscoveryStep::RoutedSctp {
                    targets: targets.clone(),
                    port,
                }),
                _ => None,
            })
            .collect();
        self.steps.extend(sctp);
    }

    /// Asks every routed and connect target about `ports` in place of the
    /// common five.
    ///
    /// Apart from [`build`](Self::build) for the reason
    /// [`also_over_sctp`](Self::also_over_sctp) is: the ports a port scan is
    /// about belong to its targets, not to the addresses this plan was built
    /// from. A port scan's liveness pass passes [`SynPorts::for_scan`], so a
    /// host that drops a SYN to anything it does not serve is still asked about
    /// the ports the scan is about to ask it.
    ///
    /// The routed and the connect steps change alike, so which of the two
    /// reaches an address decides nothing about which ports it is asked on.
    /// A segment is swept at the link layer, where a host answers ARP and
    /// neighbour discovery whatever it filters above them, and is left as it
    /// was.
    pub fn asking_tcp(&mut self, ports: SynPorts) {
        for step in &mut self.steps {
            if let DiscoveryStep::Routed { ports: asked, .. }
            | DiscoveryStep::Connect { ports: asked, .. } = step
            {
                *asked = ports;
            }
        }
    }

    /// Takes `targets` out of every step that sends its own packets, and returns
    /// what was taken.
    ///
    /// For a process whose raw strategies put frames on the wire and hold
    /// nothing behind them. A frame reaches what has Ethernet in front of it;
    /// `targets` is the rest, as
    /// [`beyond_frames`](crate::system::interface::beyond_frames) worked it out
    /// for the segment sweep. Left in a routed step, a target the kernel routes
    /// through a tunnel is sent a frame out of the wrong interface, and loopback
    /// no frame at all.
    ///
    /// A step left with nothing to send is dropped, except a sweep's local step
    /// on a link that carries frames: its most important probe is addressed to
    /// nobody, and it still has a segment to send it on. The connect step is
    /// left alone, since connect is not a frame.
    pub(crate) fn withhold(&mut self, targets: &IpSet) -> IpSet {
        let mut taken = IpSet::new();
        if targets.is_empty() {
            return taken;
        }

        for step in &mut self.steps {
            match step {
                DiscoveryStep::Local { targets: held, .. } => {
                    let mut kept = held.clone();
                    kept.subtract(targets);
                    // What the subtraction removed, which is the part of this
                    // step's targets the set named.
                    let mut gone = held.clone();
                    gone.subtract(&kept);
                    for range in gone.v4() {
                        taken.push_v4_range(*range);
                    }
                    for range in gone.v6() {
                        taken.push_v6_range(*range);
                    }
                    *held = kept;
                }
                DiscoveryStep::Routed { targets: held, .. }
                | DiscoveryStep::RoutedSctp { targets: held, .. } => held.retain(|routed| {
                    let out = targets.contains(&routed.target);
                    if out {
                        taken.insert(routed.target);
                    }
                    !out
                }),
                DiscoveryStep::Connect { .. } => {}
            }
        }

        self.steps.retain(|step| match step {
            DiscoveryStep::Local {
                interface,
                targets,
                scope,
            } => {
                !targets.is_empty() || (matches!(scope, Scope::Sweep) && interface.carries_frames())
            }
            DiscoveryStep::Routed { targets, .. } | DiscoveryStep::RoutedSctp { targets, .. } => {
                !targets.is_empty()
            }
            DiscoveryStep::Connect { .. } => true,
        });

        taken.canonicalize();
        taken
    }

    /// [`withhold`](Self::withhold)s `targets` and hands what was taken to the
    /// connect step, adding one where the plan has none. Returns what moved.
    ///
    /// Connect is how an unprivileged sweep reaches a target, and so how a
    /// frames-only one reaches what its frames cannot.
    pub(crate) fn connect_instead(&mut self, targets: &IpSet) -> IpSet {
        let moved = self.withhold(targets);
        if moved.is_empty() {
            return moved;
        }

        let existing = self.steps.iter_mut().find_map(|step| match step {
            DiscoveryStep::Connect { targets, .. } => Some(targets),
            _ => None,
        });
        match existing {
            Some(held) => {
                for range in moved.v4() {
                    held.push_v4_range(*range);
                }
                for range in moved.v6() {
                    held.push_v6_range(*range);
                }
                held.canonicalize();
            }
            // Asking what the routed steps ask, since these are addresses a
            // routed step would have swept had a frame reached them.
            None => {
                let ports = self
                    .steps
                    .iter()
                    .find_map(|step| match step {
                        DiscoveryStep::Routed { ports, .. } => Some(*ports),
                        _ => None,
                    })
                    .unwrap_or_else(SynPorts::common);
                self.steps.push(DiscoveryStep::Connect {
                    targets: moved.clone(),
                    ports,
                });
            }
        }
        moved
    }

    /// The strategies this plan would run.
    pub fn steps(&self) -> &[DiscoveryStep] {
        &self.steps
    }

    /// The strategies this plan would run, to drop or reorder before running it.
    pub fn steps_mut(&mut self) -> &mut Vec<DiscoveryStep> {
        &mut self.steps
    }

    /// Ground this plan will not cover, and why.
    /// The targets that are this host's own addresses.
    ///
    /// Up by construction and covered by no step, because no strategy can
    /// establish one: the kernel routes traffic for an address this host holds
    /// through loopback, so a probe never reaches the link and nothing on the
    /// link answers for it. Were these handed to a strategy, scanning a machine
    /// by its own LAN address would report it down while `ping` to the same
    /// address succeeds.
    ///
    /// A caller running the plan itself records these up rather than probing
    /// them; [`orchestrator`](crate::scanner) does.
    pub fn ours(&self) -> &IpSet {
        &self.ours
    }

    /// Ground this plan will not cover, and why.
    pub fn refusals(&self) -> &[RefusedStep] {
        &self.refusals
    }

    /// Takes the steps out, leaving the plan empty.
    pub fn into_steps(self) -> Vec<DiscoveryStep> {
        self.steps
    }
}

/// One strategy a port scan intends to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PortScanStep {
    /// Raw TCP probes classified from a single exchange, without completing a
    /// handshake. Needs raw sockets.
    RawTcp {
        /// Which flags the probe carries, and so which question it asks.
        technique: TcpScanTechnique,
    },
    /// Raw UDP probes, classified from a direct reply or an ICMP unreachable.
    /// Needs raw sockets.
    RawUdp,
    /// Raw SCTP INIT probes, classified from the chunk that answers. Needs raw
    /// sockets, and has no unprivileged counterpart.
    RawSctp,
    /// A full TCP connect per target. Needs no privileges, and answers roughly
    /// the question a SYN scan asks.
    ConnectTcp,
    /// An unprivileged UDP probe.
    ConnectUdp,
    /// The idle (zombie) TCP scan: port states read off a third party's IP-ID
    /// counter, so the target is never addressed under this host's own address.
    /// Needs the self-built frame a forged source requires.
    Idle {
        /// The zombie whose counter is the side channel.
        zombie: IpAddr,
        /// The port on the zombie to read the counter from, or `None` for the
        /// scanner's default.
        zombie_port: Option<u16>,
    },
}

impl PortScanStep {
    /// Which strategy this step becomes.
    ///
    /// The raw TCP name depends on the technique, because
    /// [`ScannerKind::SynPort`] means a half-open connection attempt was made
    /// and the flag probes make none. [`ScannerKind::for_raw_tcp`] is where
    /// that rule lives, so a step and the scanner it builds cannot disagree.
    pub fn kind(&self) -> ScannerKind {
        match self {
            Self::RawTcp { technique } => ScannerKind::for_raw_tcp(*technique),
            Self::RawUdp => ScannerKind::UdpPort,
            Self::RawSctp => ScannerKind::SctpPort,
            Self::ConnectTcp => ScannerKind::Connect,
            Self::ConnectUdp => ScannerKind::ConnectUdp,
            Self::Idle { .. } => ScannerKind::Idle,
        }
    }

    /// The transport protocol this step probes.
    pub fn protocol(&self) -> Protocol {
        match self {
            Self::RawTcp { .. } | Self::ConnectTcp | Self::Idle { .. } => Protocol::Tcp,
            Self::RawUdp | Self::ConnectUdp => Protocol::Udp,
            Self::RawSctp => Protocol::Sctp,
        }
    }

    /// Whether this step needs raw sockets.
    ///
    /// Asked after a scan is assembled, to decide whether host enrichment is
    /// worth running: ARP, ICMPv6 and raw TCP are what yield a MAC and a round
    /// trip, and the connect fallbacks yield neither.
    ///
    /// A property of the step rather than of its [`kind`](Self::kind), because
    /// the two answer different questions. Read off the name instead, this
    /// would be wrong for every raw technique not called `syn_port`.
    pub fn is_raw(&self) -> bool {
        matches!(self, Self::RawTcp { .. } | Self::RawUdp | Self::RawSctp)
    }

    /// Opens whatever this step needs and hands back the strategy to run.
    ///
    /// `target_count` sizes the probe ledger; a raw scanner uses it to reserve
    /// correlation state up front rather than growing it under load.
    ///
    /// `zones` names the interface each of the scan's link-local targets was
    /// given on, which is where both families of scanner get the scope id they
    /// send under. It is empty for a scan that named none.
    pub fn into_scanner(
        self,
        ctx: ScanContext,
        target_count: usize,
        tuning: ProbeTuning,
        zones: ZoneMap,
    ) -> Result<Box<dyn PortScanner>, StrategyError> {
        match self {
            Self::RawTcp { technique } => Ok(Box::new(TcpPortScanner::new(
                interface::SourceResolver::from_system()
                    .with_zones(zones)
                    .with_forced(tuning.send_source.clone()),
                ctx,
                technique,
                target_count,
                tuning,
            )?)),
            Self::RawUdp => Ok(Box::new(UdpPortScanner::new(
                interface::SourceResolver::from_system()
                    .with_zones(zones)
                    .with_forced(tuning.send_source.clone()),
                ctx,
                target_count,
                tuning,
            )?)),
            Self::RawSctp => Ok(Box::new(SctpPortScanner::new(
                interface::SourceResolver::from_system()
                    .with_zones(zones)
                    .with_forced(tuning.send_source.clone()),
                ctx,
                target_count,
                tuning,
            )?)),
            Self::ConnectTcp => Ok(Box::new(
                ConnectPortScanner::new(
                    ctx,
                    limits::CONNECT_CONCURRENCY,
                    tuning.service_detection,
                    &tuning.evasion,
                )
                .with_zones(zones),
            )),
            Self::ConnectUdp => Ok(Box::new(
                ConnectUdpPortScanner::with_detection(
                    ctx,
                    limits::CONNECT_CONCURRENCY,
                    &tuning.evasion,
                    tuning.service_detection,
                )
                .with_zones(zones),
            )),
            Self::Idle {
                zombie,
                zombie_port,
            } => Ok(Box::new(IdlePortScanner::new(
                ctx,
                zombie,
                zombie_port,
                tuning,
            )?)),
        }
    }
}

/// What a port scan intends to do.
#[derive(Debug, Clone)]
pub struct PortScanPlan {
    steps: Vec<PortScanStep>,
    refusals: Vec<RefusedStep>,
    /// The protocol each of `refusals` leaves unprobed, kept beside them
    /// because a refusal is words and the scan has to act on it too: a target
    /// of a refused protocol still reaches the router, and has to be counted
    /// there as what the plan declined rather than as work a scanner lost.
    refused: Vec<Protocol>,
    technique: TcpScanTechnique,
    /// Whether this is an idle scan, whether or not its idle step survived.
    ///
    /// Kept apart from the steps because a refused idle scan has no idle step,
    /// and is still an idle scan: what the targets name on another transport is
    /// refused as one, rather than planned as the direct probe the caller chose
    /// an idle scan to avoid sending. Read from the steps instead, a privileged
    /// run through an excluded zombie would plan the target's SCTP ports as a
    /// direct probe from this host's own address.
    idle: bool,
}

impl PortScanPlan {
    /// Works out which strategies would probe the requested ports, opening
    /// nothing.
    ///
    /// `privilege` is which sockets the scan would run with. It is a parameter
    /// rather than something read here so a caller can plan for a privilege
    /// level they do not currently hold: asking "what would a root scan do?"
    /// is a reasonable question and needs no root to answer.
    ///
    /// ## The fallback is decided per protocol, not per scan
    ///
    /// A host can be able to build one raw scanner and not the other: the TCP
    /// scanner needs a raw TCP socket, the UDP scanner a raw UDP one, and a
    /// sandbox can permit one and refuse the other. A protocol left with no
    /// strategy at all is not a degraded scan but a silent one: nothing would
    /// route those targets anywhere, so they would never be probed and never be
    /// reported.
    ///
    /// ## A connect fallback substitutes for a SYN scan and for nothing else
    ///
    /// It completes handshakes, so it answers roughly the question a SYN scan
    /// asks. It cannot send a FIN, a flagless segment or a bare ACK, so it
    /// cannot answer what any of those were asked. Where the caller chose one of
    /// those and raw sockets are unavailable, the TCP half is refused and left
    /// undone: worse for the caller, and honest, where a silent substitution
    /// would hand back verdicts from a technique they did not choose with no
    /// field in the report saying so.
    pub fn build(cfg: &ZondConfig, privilege: Privilege) -> Self {
        let mut plan = Self {
            steps: Vec::new(),
            refusals: Vec::new(),
            refused: Vec::new(),
            technique: cfg.tcp_technique,
            idle: cfg.idle_scan.is_some(),
        };

        // An idle scan replaces the ordinary port scan wholesale. It is TCP-only
        // by nature, a UDP port has no counter to be read through, and probing
        // one directly would announce the scanner the technique exists to hide,
        // so no step covers UDP. The refusal that says so waits for the targets
        // to name a UDP port; see `cover_udp`.
        if let Some(idle) = &cfg.idle_scan {
            // Asked first: a policy refusal holds whatever the privilege, and
            // telling somebody to find root for a scan that would be refused
            // anyway sends them the wrong way. The zombie is named in settings
            // rather than in the target list, so nothing else withholds it.
            if cfg.exclusions.excludes(&idle.zombie) {
                plan.refuse(
                    Protocol::Tcp,
                    RefusedStep::idle_zombie_excluded(idle.zombie),
                );
            } else if privilege.is_raw() {
                plan.steps.push(PortScanStep::Idle {
                    zombie: idle.zombie,
                    zombie_port: idle.zombie_port,
                });
            } else {
                plan.refuse(Protocol::Tcp, RefusedStep::idle_needs_privilege());
            }
            return plan;
        }

        // Raw scanning needs both the privilege and an address to probe from.
        let raw = privilege.is_raw() && interface::SourceResolver::from_system().has_sources();
        if privilege.is_raw() && !raw {
            warn!("no usable network interface found; using TCP connect fallback");
        }

        if raw {
            plan.steps.push(PortScanStep::RawTcp {
                technique: cfg.tcp_technique,
            });
            plan.steps.push(PortScanStep::RawUdp);
        } else if cfg.tcp_technique.has_connect_fallback() {
            plan.steps.push(PortScanStep::ConnectTcp);
            plan.steps.push(PortScanStep::ConnectUdp);
        } else {
            plan.refuse(
                Protocol::Tcp,
                RefusedStep::technique_needs_raw_sockets(cfg.tcp_technique),
            );
            plan.steps.push(PortScanStep::ConnectUdp);
        }

        plan
    }

    /// Records that `protocol` will not be probed, and the refusal that says
    /// why.
    fn refuse(&mut self, protocol: Protocol, refusal: RefusedStep) {
        self.refusals.push(refusal);
        self.refused.push(protocol);
    }

    /// The TCP technique this plan was built for.
    ///
    /// Kept because it outlives the steps: if a raw step fails to open, whether
    /// a connect scanner may stand in for it depends on which question the
    /// technique asks, and by then the step is gone.
    pub fn technique(&self) -> TcpScanTechnique {
        self.technique
    }

    /// The strategies this plan would run.
    pub fn steps(&self) -> &[PortScanStep] {
        &self.steps
    }

    /// The strategies this plan would run, to drop or reorder before running it.
    pub fn steps_mut(&mut self) -> &mut Vec<PortScanStep> {
        &mut self.steps
    }

    /// Ports this plan will not probe, and why.
    pub fn refusals(&self) -> &[RefusedStep] {
        &self.refusals
    }

    /// Takes the steps out, leaving the plan empty.
    pub fn into_steps(self) -> Vec<PortScanStep> {
        self.steps
    }

    /// Adds the step that probes SCTP, or the refusal that says why it could
    /// not be added.
    ///
    /// Apart from [`build`](Self::build) because what decides it is not in the
    /// configuration. SCTP ports are named in a target's port specification,
    /// which the plan is built before reading, and no default port list holds
    /// one: a scan that never mentions SCTP opens no socket for it, where a step
    /// added unconditionally would cost every privileged run a raw socket and a
    /// capture for a transport nobody asked about.
    ///
    /// Called with the same `privilege` the plan was built for.
    pub fn cover_sctp(&mut self, privilege: Privilege) {
        if self.idle {
            self.refuse(Protocol::Sctp, RefusedStep::sctp_not_in_an_idle_scan());
            return;
        }

        // The same two conditions raw scanning is planned under in `build`:
        // the privilege, and an address to send from.
        if privilege.is_raw() && interface::SourceResolver::from_system().has_sources() {
            self.steps.push(PortScanStep::RawSctp);
        } else {
            self.refuse(Protocol::Sctp, RefusedStep::sctp_needs_raw_sockets());
        }
    }

    /// Adds the refusal that says why UDP ports go unprobed, where the plan
    /// holds no step for them.
    ///
    /// Only an idle scan plans none, and its refusal is apart from
    /// [`build`](Self::build) for the reason [`cover_sctp`](Self::cover_sctp)
    /// is: whether a UDP port was named is in the targets, which the plan is
    /// built before reading, and an idle scan of TCP ports alone refusing UDP
    /// would put a line in every such report about ground nobody asked for.
    /// Without it the targets that do name UDP reach the router with nothing
    /// to take them and no refusal to account for them, and are filed as ports
    /// the scan lost.
    ///
    /// Call it when the targets name a UDP port. On any other plan it does
    /// nothing, since every other plan already has a UDP step.
    pub fn cover_udp(&mut self) {
        if self.idle && !self.covers(Protocol::Udp) {
            self.refuse(Protocol::Udp, RefusedStep::udp_not_in_an_idle_scan());
        }
    }

    /// Whether one of [`refusals`](Self::refusals) leaves `protocol`
    /// unprobed.
    ///
    /// Not the same question as [`covers`](Self::covers) answered in the
    /// negative. A protocol no step covers and no refusal names is one the
    /// plan left out without saying so, and the scan reports its targets as
    /// lost; one a refusal names has already been reported, and its targets
    /// are what that refusal is about.
    pub(crate) fn refuses(&self, protocol: Protocol) -> bool {
        self.refused.contains(&protocol)
    }

    /// Whether any step covers `protocol`.
    ///
    /// Read after a caller has edited [`steps_mut`](Self::steps_mut): a plan
    /// with nothing for a protocol probes none of its ports and reports none of
    /// them, which is silence rather than a finding.
    pub fn covers(&self, protocol: Protocol) -> bool {
        self.steps.iter().any(|step| step.protocol() == protocol)
    }
}

/// Makes sure the link a sweep is about is among the links to be scanned, even
/// when no address mapped to it.
///
/// Mapping targets to interfaces can only ever produce interfaces some target
/// named, and the whole point of a sweep is the probe that names nobody. A link
/// addressed only in IPv6 resolves to no target list at all, a `/64` cannot be
/// enumerated and there is no IPv4 range to walk, so it maps to nothing, no
/// step is built for it, and the all-nodes echo that would have found its entire
/// segment is never sent. The scan reports an empty network and looks like it
/// worked.
///
/// Matching by name rather than by value: `map_ips_to_interfaces` and this both
/// read the platform's interface list, but a `NetworkInterface` compares on
/// every field, and being wrong here means scanning one link twice.
fn include_swept_link(local: &mut HashMap<Link, IpSet>) {
    let Some(link) = interface::lan_link() else {
        return;
    };

    if local.keys().any(|intf| intf.name() == link.link.name()) {
        return;
    }

    local.insert(link.link, IpSet::new());
}

/// Adds the addresses in this host's IPv6 neighbour table to the targets of
/// whichever interface each belongs to.
///
/// This is the only source the engine has for an IPv6 address nobody named. A
/// neighbor solicitation is the mandatory probe, and it can only be aimed at an
/// address someone already holds; the all-nodes echo produces addresses but is
/// optional to answer and draws only link-local ones, since it goes out from a
/// link-local source. The operating system's own table has been accumulating
/// both for as long as the machine has been running, at no cost in packets: on
/// the segment this was written against it holds fifteen global and unique-local
/// addresses the engine could not otherwise learn at all.
///
/// Three exclusions, each for its own reason:
///
/// - **Other interfaces' entries.** A neighbour on `en1` is not reachable
///   through `en0`, and the entry says which it belongs to.
/// - **This host's own addresses.** The table lists them too, and a scan that
///   reported the machine running it as a discovered neighbour would be wrong in
///   a way nobody would think to check.
/// - **Loopback and the unspecified address**, which name nothing on a segment.
///
/// Nothing seeded here is treated as a discovered host. Every entry is an
/// address that answered *once*, from a table that goes stale, so each becomes a
/// probe like any other and earns its place in the report by answering now.
fn seed_from_neighbor_table(local: &mut HashMap<Link, IpSet>, exclusions: &Exclusions) {
    let table = neighbor_cache::ipv6_neighbors();
    if !table.is_empty() {
        seed_from_neighbor_table_with(local, &table, exclusions);
    }
}

/// [`seed_from_neighbor_table`] against an explicit table, so the exclusions can
/// be tested without a host that happens to have the right neighbours.
fn seed_from_neighbor_table_with(
    local: &mut HashMap<Link, IpSet>,
    table: &[neighbor_cache::Neighbor],
    exclusions: &Exclusions,
) {
    for (intf, targets) in local.iter_mut() {
        let mut seeded = 0usize;
        for addr in candidates_for(intf, table) {
            // **The policy, not one of this function's own three filters.**
            //
            // `withhold_targets` subtracts excluded addresses from the list
            // before anything is opened, and that is the whole of the send-side
            // guarantee — but it can only subtract what the list had. These
            // addresses were never in it: they come from the host's own
            // neighbour table, which is exactly the case `Exclusions` names when
            // it says an exclusion that holds for the list and not for what the
            // sweep discovers is worse than no exclusion at all.
            //
            // Without this a swept segment would send a unicast solicitation to
            // an address somebody had been told would not be probed.
            // `write_host` would then drop the finding, so the *report* would
            // stay clean and the packet would still go out — which is the half
            // of the promise that cannot be checked from the report afterwards.
            if exclusions.excludes(&addr) {
                info!(
                    verbosity = 2,
                    "neighbour {addr} is excluded, so it is not taken as a candidate"
                );
                continue;
            }

            let IpAddr::V6(addr) = addr else { continue };
            // The zone matters for exactly the addresses that cannot be probed
            // without one, and is dropped for the rest for the reason
            // `ScopedIp` drops it: the same global address through two
            // interfaces is one address, not two.
            let zone = addr.is_unicast_link_local().then_some(intf.index());
            if let Ok(range) = Ipv6Range::scoped(addr, addr, zone) {
                targets.insert_range(IpRange::V6(range));
                seeded += 1;
            }
        }

        if seeded > 0 {
            targets.canonicalize();
            info!(
                verbosity = 1,
                "took {} from the neighbour table as candidates on {}",
                counted(seeded as u128, "IPv6 address", "IPv6 addresses"),
                intf.name()
            );
        }
    }
}

/// The neighbour-table addresses worth probing on `intf`, in table order.
fn candidates_for(link: &Link, table: &[neighbor_cache::Neighbor]) -> Vec<IpAddr> {
    let own: std::collections::HashSet<IpAddr> =
        link.addresses().iter().map(|held| held.address()).collect();

    table
        .iter()
        .filter(|entry| entry.interface_index == link.index())
        .filter(|entry| !own.contains(&entry.ip))
        .filter(|entry| match entry.ip {
            IpAddr::V6(addr) => !addr.is_loopback() && !addr.is_unspecified(),
            IpAddr::V4(_) => false,
        })
        .map(|entry| entry.ip)
        .collect()
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    fn interface_with(index: u32, name: &str, own: Vec<IpAddr>) -> Link {
        use crate::system::interface::LinkAddress;
        Link::new(name, index).with_addresses(
            own.into_iter()
                .map(|ip| LinkAddress::new(ip, if ip.is_ipv4() { 24 } else { 64 }))
                .collect(),
        )
    }

    fn entry(ip: &str, index: u32) -> neighbor_cache::Neighbor {
        neighbor_cache::Neighbor {
            ip: v6(ip),
            mac: None,
            interface_index: index,
        }
    }

    /// A link a frame can be put on, as against `interface_with`'s bare one.
    fn framed(index: u32, name: &str, own: Vec<IpAddr>) -> Link {
        interface_with(index, name, own)
            .with_mac(crate::model::mac::MacAddr::new(0x02, 0, 0, 0, 0, 0x10))
    }

    fn set_of(addresses: &[&str]) -> IpSet {
        let mut set = IpSet::new();
        for address in addresses {
            set.insert(v6(address));
        }
        set
    }

    /// What a frames-only sweep cannot reach leaves the steps that would have
    /// framed it and joins the connect step, which is how an unprivileged
    /// sweep reaches it. A local step left empty goes with it; one still
    /// holding a neighbour a frame reaches stays.
    #[test]
    fn what_a_frame_cannot_reach_moves_to_the_connect_step() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            steps: vec![
                DiscoveryStep::Local {
                    interface: Box::new(interface_with(20, "utun9", vec![v6("198.51.100.2")])),
                    targets: set_of(&["198.51.100.7"]),
                    scope: Scope::Targeted,
                },
                DiscoveryStep::Local {
                    interface: Box::new(framed(4, "en0", vec![v6("192.0.2.10")])),
                    targets: set_of(&["192.0.2.50"]),
                    scope: Scope::Targeted,
                },
                DiscoveryStep::Routed {
                    targets: vec![
                        RoutedTarget {
                            target: v6("203.0.113.23"),
                            source: v6("198.51.100.2"),
                        },
                        RoutedTarget {
                            target: v6("203.0.113.9"),
                            source: v6("192.0.2.10"),
                        },
                    ],
                    ports: SynPorts::common(),
                },
            ],
            refusals: Vec::new(),
        };

        let moved = plan.connect_instead(&set_of(&["198.51.100.7", "203.0.113.23"]));

        assert_eq!(moved.len(), 2);
        let kinds: Vec<ScannerKind> = plan.steps().iter().map(DiscoveryStep::kind).collect();
        assert_eq!(
            kinds,
            vec![
                ScannerKind::Local,
                ScannerKind::Routed,
                ScannerKind::Connect
            ],
            "the tunnel's local step is gone and a connect step has arrived"
        );
        match &plan.steps()[1] {
            DiscoveryStep::Routed { targets, .. } => {
                assert_eq!(targets.len(), 1);
                assert_eq!(targets[0].target, v6("203.0.113.9"));
            }
            other => panic!("expected the routed step, found {other:?}"),
        }
        match &plan.steps()[2] {
            DiscoveryStep::Connect { targets, .. } => assert_eq!(*targets, moved),
            other => panic!("expected the connect step, found {other:?}"),
        }
    }

    /// A sweep's own link keeps its step with nothing left to address, since
    /// its most important probe is addressed to nobody. A link that carries no
    /// frames has no such probe to send, and goes.
    #[test]
    fn a_sweeps_step_stays_on_a_framed_link_and_goes_on_a_tunnel() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            steps: vec![
                DiscoveryStep::Local {
                    interface: Box::new(framed(4, "en0", vec![v6("192.0.2.10")])),
                    targets: set_of(&["192.0.2.50"]),
                    scope: Scope::Sweep,
                },
                DiscoveryStep::Local {
                    interface: Box::new(interface_with(20, "utun9", vec![v6("198.51.100.2")])),
                    targets: set_of(&["198.51.100.7"]),
                    scope: Scope::Sweep,
                },
            ],
            refusals: Vec::new(),
        };

        plan.withhold(&set_of(&["192.0.2.50", "198.51.100.7"]));

        assert_eq!(plan.steps().len(), 1);
        match &plan.steps()[0] {
            DiscoveryStep::Local {
                interface, targets, ..
            } => {
                assert_eq!(interface.name(), "en0");
                assert!(targets.is_empty());
            }
            other => panic!("expected the sweep's own step, found {other:?}"),
        }
    }

    /// Withholding is about frames, and a connect step sends none: what it
    /// already holds stays, and nothing new arrives in it.
    #[test]
    fn withholding_leaves_the_connect_step_as_it_was() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            steps: vec![DiscoveryStep::Connect {
                targets: set_of(&["127.0.0.1"]),
                ports: SynPorts::common(),
            }],
            refusals: Vec::new(),
        };

        let taken = plan.withhold(&set_of(&["127.0.0.1"]));

        assert!(taken.is_empty(), "nothing was taken from a frame step");
        match &plan.steps()[0] {
            DiscoveryStep::Connect { targets, .. } => assert_eq!(*targets, set_of(&["127.0.0.1"])),
            other => panic!("expected the connect step, found {other:?}"),
        }
    }

    /// A port scan's liveness pass asks its routed targets about the scan's
    /// own ports, and a plan built for a sweep asks the common five until told
    /// otherwise.
    #[test]
    fn the_routed_steps_ask_the_ports_they_are_given() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            steps: vec![DiscoveryStep::Routed {
                targets: vec![RoutedTarget {
                    target: v6("198.51.100.1"),
                    source: v6("192.0.2.9"),
                }],
                ports: SynPorts::common(),
            }],
            refusals: Vec::new(),
        };
        let scan = SynPorts::for_scan(&"8443".try_into().expect("a port specification"));

        plan.asking_tcp(scan);

        assert!(matches!(
            plan.steps(),
            [DiscoveryStep::Routed { ports, .. }] if *ports == scan
        ));
    }

    /// The addresses a plan reaches by connect are asked the ports its routed
    /// addresses are. Asked fewer, a host behind a filter that serves only a
    /// port the scan names is found when a frame reaches it and missed when
    /// only a connect does, loopback and tunnels on every run and everything
    /// on an unprivileged one.
    #[test]
    fn the_connect_step_asks_the_ports_the_routed_steps_are_given() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            steps: vec![
                DiscoveryStep::Routed {
                    targets: vec![RoutedTarget {
                        target: v6("198.51.100.1"),
                        source: v6("192.0.2.9"),
                    }],
                    ports: SynPorts::common(),
                },
                DiscoveryStep::Connect {
                    targets: set_of(&["127.0.0.1"]),
                    ports: SynPorts::common(),
                },
            ],
            refusals: Vec::new(),
        };
        let scan = SynPorts::for_scan(&"8443".try_into().expect("a port specification"));

        plan.asking_tcp(scan);

        assert!(
            matches!(
                plan.steps(),
                [DiscoveryStep::Routed { .. }, DiscoveryStep::Connect { ports, .. }] if *ports == scan
            ),
            "the connect step asks {:?}",
            plan.steps()
        );
    }

    /// And a connect step made after the ports were chosen, for what a frame
    /// cannot reach, asks them too: the order a caller edits a plan in decides
    /// nothing about which ports an address is asked on.
    #[test]
    fn a_connect_step_made_for_what_frames_miss_asks_the_routed_ports() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            steps: vec![DiscoveryStep::Routed {
                targets: vec![
                    RoutedTarget {
                        target: v6("198.51.100.1"),
                        source: v6("192.0.2.9"),
                    },
                    RoutedTarget {
                        target: v6("198.51.100.2"),
                        source: v6("192.0.2.9"),
                    },
                ],
                ports: SynPorts::common(),
            }],
            refusals: Vec::new(),
        };
        let scan = SynPorts::for_scan(&"8443".try_into().expect("a port specification"));

        plan.asking_tcp(scan);
        plan.connect_instead(&set_of(&["198.51.100.2"]));

        assert!(
            matches!(
                plan.steps(),
                [DiscoveryStep::Routed { .. }, DiscoveryStep::Connect { ports, .. }] if *ports == scan
            ),
            "the connect step asks {:?}",
            plan.steps()
        );
    }

    /// An SCTP sweep runs beside each routed step and nowhere else: a segment
    /// is swept at the link layer, where ARP and neighbour discovery answer
    /// whatever the host speaks above them, and a connect step has no raw
    /// socket to send an INIT through.
    #[test]
    fn an_sctp_sweep_is_added_to_the_routed_steps_alone() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            steps: vec![
                DiscoveryStep::Routed {
                    targets: vec![RoutedTarget {
                        target: v6("192.0.2.1"),
                        source: v6("192.0.2.9"),
                    }],
                    ports: SynPorts::common(),
                },
                DiscoveryStep::Connect {
                    targets: IpSet::new(),
                    ports: SynPorts::common(),
                },
            ],
            refusals: Vec::new(),
        };

        plan.also_over_sctp(3868);

        let kinds: Vec<ScannerKind> = plan.steps().iter().map(DiscoveryStep::kind).collect();
        assert_eq!(
            kinds,
            vec![
                ScannerKind::Routed,
                ScannerKind::Connect,
                ScannerKind::RoutedSctp
            ]
        );
        assert!(matches!(
            plan.steps().last(),
            Some(DiscoveryStep::RoutedSctp { port: 3868, .. })
        ));
    }

    /// SCTP has no unprivileged form at all, so a scan that named SCTP ports
    /// without raw sockets is told those ports went unprobed rather than being
    /// handed a strategy that asked a different question.
    #[test]
    fn sctp_without_raw_sockets_is_refused_rather_than_substituted() {
        let mut plan = PortScanPlan::build(&ZondConfig::default(), Privilege::Connect);
        plan.cover_sctp(Privilege::Connect);

        assert!(!plan.covers(Protocol::Sctp));
        assert!(
            plan.refusals()
                .iter()
                .any(|refusal| refusal.scanner == ScannerKind::SctpPort),
            "the sctp ports went unprobed and nothing in the report said so"
        );
    }

    /// An idle scan reads a third party's counter and has no way to carry an
    /// INIT. Sending one directly would leave this host's address on the target,
    /// which is the one thing the technique exists to avoid, so the ports are
    /// refused with that as the reason.
    #[test]
    fn an_idle_scan_refuses_sctp_rather_than_probing_it_directly() {
        let cfg = ZondConfig {
            idle_scan: Some(crate::config::IdleScan::new(v6("192.0.2.9"))),
            ..ZondConfig::default()
        };
        let mut plan = PortScanPlan::build(&cfg, Privilege::Raw);
        plan.cover_sctp(Privilege::Raw);

        assert!(!plan.covers(Protocol::Sctp));
        let refusal = plan
            .refusals()
            .iter()
            .find(|refusal| refusal.scanner == ScannerKind::SctpPort)
            .expect("the sctp ports are accounted for");
        assert!(
            refusal.reason.contains("idle"),
            "the reason names something other than the idle scan: {}",
            refusal.reason
        );
    }

    /// A zombie the operator excluded is not scanned through. The idle scan
    /// reads its counter by sending it SYN+ACKs again and again, so naming it
    /// in a scan's settings would otherwise probe an address somebody was told
    /// would be left alone, and nothing in the target list could withhold it.
    ///
    /// Refused rather than replaced: probing the target directly instead would
    /// put this host's own address on it, which an idle scan exists to avoid,
    /// so no TCP port is planned at all.
    #[test]
    fn an_idle_scan_through_an_excluded_zombie_is_refused() {
        let zombie = v6("192.0.2.9");
        let mut forbidden = IpSet::new();
        forbidden.insert(zombie);
        let cfg = ZondConfig {
            idle_scan: Some(crate::config::IdleScan::new(zombie)),
            exclusions: Exclusions::new(forbidden),
            ..ZondConfig::default()
        };

        let plan = PortScanPlan::build(&cfg, Privilege::Raw);

        assert!(
            !plan
                .steps()
                .iter()
                .any(|step| matches!(step, PortScanStep::Idle { .. })),
            "an idle step would probe the excluded zombie"
        );
        assert!(
            !plan.covers(Protocol::Tcp),
            "and nothing stands in for it by probing the target directly"
        );
        let refusal = plan
            .refusals()
            .iter()
            .find(|refusal| refusal.scanner == ScannerKind::Idle)
            .expect("the refused scan is accounted for");
        assert!(
            refusal.reason.contains("192.0.2.9") && refusal.reason.contains("excluded"),
            "the reason names the zombie and the exclusion: {}",
            refusal.reason
        );
    }

    /// An idle scan the plan refused is still an idle scan, and what it names
    /// on other transports is refused as one. Neither SCTP nor UDP can be read
    /// through a zombie's counter, and a privileged plan that forgot the scan
    /// was an idle one once its idle step was gone would probe the target's
    /// SCTP ports from this host's own address: the one thing the caller chose
    /// an idle scan to avoid, done to the target the moment the zombie is
    /// excluded.
    #[test]
    fn a_refused_idle_scan_probes_no_other_transport_directly() {
        let zombie = v6("192.0.2.9");
        let mut forbidden = IpSet::new();
        forbidden.insert(zombie);
        let cfg = ZondConfig {
            idle_scan: Some(crate::config::IdleScan::new(zombie)),
            exclusions: Exclusions::new(forbidden),
            ..ZondConfig::default()
        };

        for privilege in [Privilege::Raw, Privilege::Connect] {
            let mut plan = PortScanPlan::build(&cfg, privilege);
            plan.cover_sctp(privilege);
            plan.cover_udp();

            assert!(
                plan.steps().is_empty(),
                "{privilege:?}: nothing is probed directly: {:?}",
                plan.steps()
            );
            for protocol in [Protocol::Sctp, Protocol::Udp] {
                assert!(plan.refuses(protocol), "{privilege:?}: {protocol:?}");
            }
            let reasons: Vec<&str> = plan.refusals().iter().map(|r| r.reason.as_str()).collect();
            for transport in ["sctp", "udp"] {
                assert!(
                    reasons
                        .iter()
                        .any(|reason| reason.contains(transport) && reason.contains("idle scan")),
                    "{privilege:?}: {transport} is refused as an idle scan's: {reasons:?}"
                );
            }
        }
    }

    /// An ordinary scan plans its UDP step whatever the targets name, so being
    /// told they name UDP changes nothing about it.
    #[test]
    fn covering_udp_changes_nothing_about_a_plan_that_already_does() {
        let mut plan = PortScanPlan::build(&ZondConfig::default(), Privilege::Connect);
        let steps = plan.steps().len();

        plan.cover_udp();

        assert_eq!(plan.steps().len(), steps);
        assert!(plan.covers(Protocol::Udp) && !plan.refuses(Protocol::Udp));
        assert!(plan.refusals().is_empty());
    }

    fn v6_set(cidr: &str) -> IpSet {
        crate::model::parse::ip::to_set(&[cidr], None, None).expect("a range")
    }

    /// A `/64` on the local segment is eighteen quintillion addresses, and the
    /// walk is what a targeted run does with a local range. It is withheld
    /// before a scanner is built from it, because the alternative was measured
    /// and is worse than useless: the count overflows `usize`, the sweep is
    /// budgeted as though it had no targets, and it stops two thousand
    /// solicitations in having reported the prefix covered.
    #[test]
    fn a_local_prefix_too_large_to_walk_is_withheld_from_the_targets() {
        let mut targets = v6_set("2001:db8:1:1::/64");
        assert_eq!(targets.len(), 1u128 << 64, "a /64, kept whole to here");

        let withheld = withhold_unwalkable(&mut targets);

        assert_eq!(withheld.len(), 1, "the prefix is taken out");
        assert!(targets.is_empty(), "and nothing is left to walk");
    }

    /// Asked of a range and not of a set, so a prefix beside three literal
    /// addresses costs the prefix and not the three.
    #[test]
    fn withholding_a_prefix_keeps_the_addresses_named_beside_it() {
        let mut targets = crate::model::parse::ip::to_set(
            &["2001:db8:1:1::/64", "2001:db8:2::1", "192.0.2.7"],
            None,
            None,
        )
        .expect("a mixed set");

        let withheld = withhold_unwalkable(&mut targets);

        assert_eq!(withheld.len(), 1);
        assert_eq!(targets.len(), 2, "the literal and the IPv4 address survive");
    }

    /// A range small enough to walk is left exactly as it was, so the ordinary
    /// case pays nothing.
    #[test]
    fn a_walkable_prefix_is_untouched() {
        let mut targets = v6_set("2001:db8::/120");
        let before = targets.len();

        assert!(withhold_unwalkable(&mut targets).is_empty());
        assert_eq!(targets.len(), before);
    }

    /// The three entries that must never become targets, each wrong in its own
    /// way: another interface's neighbour is not reachable through this one,
    /// this host would be reported as a discovered neighbour of itself, and
    /// loopback names nothing on a segment.
    #[test]
    fn seeding_skips_other_interfaces_our_own_addresses_and_loopback() {
        let own = v6("2001:db8::50");
        let intf = interface_with(7, "en0", vec![own]);
        let table = vec![
            entry("2001:db8::aa", 7),
            entry("fe80::bb", 7),
            entry("2001:db8::cc", 9),
            entry("2001:db8::50", 7),
            entry("::1", 7),
        ];

        let seeded = candidates_for(&intf, &table);

        assert_eq!(seeded, vec![v6("2001:db8::aa"), v6("fe80::bb")]);
    }

    /// A link-local candidate carries the interface it came from, because it
    /// cannot be probed without one. A global address does not, for the reason
    /// `ScopedIp` drops it: the same address through two interfaces is one
    /// address.
    #[test]
    fn a_seeded_link_local_keeps_its_interface_and_a_global_does_not() {
        let intf = interface_with(7, "en0", Vec::new());
        let table = vec![entry("fe80::bb", 7), entry("2001:db8::aa", 7)];
        let mut local = std::collections::HashMap::from([(intf, IpSet::new())]);

        seed_from_neighbor_table_with(&mut local, &table, &Exclusions::none());

        let targets = local.into_values().next().unwrap();
        let zones: Vec<Option<u32>> = targets.v6().iter().map(|range| range.zone()).collect();
        assert!(
            zones.contains(&Some(7)),
            "the link-local needs its interface"
        );
        assert!(
            zones.contains(&None),
            "the global address needs no interface"
        );
    }

    /// An unprivileged plan still covers both protocols. A protocol with no step
    /// is not a degraded scan but a silent one: nothing routes those targets, so
    /// they are never probed and never reported.
    #[test]
    fn an_unprivileged_plan_covers_both_protocols() {
        let plan = PortScanPlan::build(&ZondConfig::default(), Privilege::Connect);

        assert!(plan.covers(Protocol::Tcp));
        assert!(plan.covers(Protocol::Udp));
        assert!(plan.refusals().is_empty());
    }

    /// A connect scan substitutes for a SYN scan and for nothing else. Asked for
    /// a technique it cannot express, an unprivileged plan has to leave the TCP
    /// half out and say why - a silent substitution would promise verdicts from
    /// a technique nobody chose, with no field in the report saying so.
    #[test]
    fn a_technique_the_fallback_cannot_express_is_refused_at_planning_time() {
        let cfg = ZondConfig {
            tcp_technique: TcpScanTechnique::Fin,
            ..ZondConfig::default()
        };
        let plan = PortScanPlan::build(&cfg, Privilege::Connect);

        assert!(
            !plan.covers(Protocol::Tcp),
            "a connect scan cannot send a FIN and must not plan to"
        );
        assert!(plan.covers(Protocol::Udp), "the UDP half is unaffected");

        assert_eq!(plan.refusals().len(), 1, "the caller has to be told");
        assert_eq!(plan.refusals()[0].scanner, ScannerKind::TcpPort);
        assert!(
            plan.refusals()[0].reason.contains("fin"),
            "the refusal has to name the technique: {}",
            plan.refusals()[0].reason
        );
        assert!(
            plan.refuses(Protocol::Tcp) && !plan.refuses(Protocol::Udp),
            "and which protocol it leaves unprobed, for the router to count"
        );
    }

    /// A step and the scanner it becomes have to answer to the same name, or a
    /// failure lands in the report under one strategy and the same scanner's
    /// later failures under another.
    ///
    /// [`ScannerKind::SynPort`] is the one that matters. It is documented to
    /// mean a half-open connection attempt was made, and a plan that called
    /// every raw TCP step by that name would attribute a FIN scan's socket
    /// failure to `syn_port` when no SYN was ever sent.
    #[test]
    fn a_step_reports_under_the_same_name_as_the_scanner_it_builds() {
        use crate::scanner::session::ScanSession;
        use crate::scanner::strategy::ports::TcpPortScanner;
        use crate::transport::probe::{Emission, ProbeSender, ProbeTransport, SendError};

        struct Unsendable;
        impl ProbeSender for Unsendable {
            fn send(
                &self,
                _: &[u8],
                _: IpAddr,
                _: IpAddr,
                _: Option<u32>,
                _emission: Emission,
            ) -> Result<(), SendError> {
                Ok(())
            }
        }

        let (_session, ctx) = ScanSession::new();
        for technique in TcpScanTechnique::ALL {
            let (_tx, rx) = tokio::sync::mpsc::channel(1024);
            let scanner = TcpPortScanner::with_transport(
                interface::SourceResolver::from_links(&[]),
                ctx.clone(),
                technique,
                ProbeTransport::from_parts(Box::new(Unsendable), rx),
                1,
            );

            assert_eq!(
                PortScanStep::RawTcp { technique }.kind(),
                scanner.kind(),
                "a {technique} step and its scanner disagree about what to call themselves"
            );
        }
    }

    /// Host enrichment runs beside a raw scan because the raw paths are what
    /// yield a MAC and an RTT. Which technique the raw TCP scanner carries has
    /// no bearing on that, so every one of them has to count as raw.
    #[test]
    fn every_raw_step_is_recognisable_as_one() {
        for technique in TcpScanTechnique::ALL {
            assert!(PortScanStep::RawTcp { technique }.is_raw(), "{technique}");
        }
        assert!(PortScanStep::RawUdp.is_raw());
        assert!(!PortScanStep::ConnectTcp.is_raw());
        assert!(!PortScanStep::ConnectUdp.is_raw());
    }

    /// The technique outlives the steps, because whether a connect scanner may
    /// stand in for a raw one that failed to open is a question asked after the
    /// step is gone.
    #[test]
    fn a_plan_remembers_the_technique_it_was_built_for() {
        let cfg = ZondConfig {
            tcp_technique: TcpScanTechnique::Ack,
            ..ZondConfig::default()
        };
        assert_eq!(
            PortScanPlan::build(&cfg, Privilege::Connect).technique(),
            TcpScanTechnique::Ack
        );
    }

    /// A plan is a value a caller may edit, and editing it changes what would
    /// run. The guard against editing it into silence is `covers`.
    #[test]
    fn dropping_a_step_is_visible_in_what_the_plan_covers() {
        let mut plan = PortScanPlan::build(&ZondConfig::default(), Privilege::Connect);
        plan.steps_mut()
            .retain(|step| step.protocol() != Protocol::Udp);

        assert!(plan.covers(Protocol::Tcp));
        assert!(!plan.covers(Protocol::Udp));
    }

    /// **A sweep does not take an excluded neighbour as a candidate.**
    ///
    /// The target list is withheld against the exclusions before a plan is
    /// built, and that is the whole of the send-side guarantee — but a sweep
    /// adds addresses the list never had, from the host's own neighbour table,
    /// and those were never subtracted from anything. `Exclusions` names exactly
    /// this case: an exclusion that holds for the list and not for what the
    /// sweep discovers is worse than no exclusion at all.
    ///
    /// The recording gate at `write_host` would drop the finding, so the report
    /// stays clean either way. What it cannot undo is the packet, and that is
    /// the half of the promise a reader cannot check afterwards.
    #[test]
    fn a_swept_plan_does_not_take_an_excluded_neighbour_as_a_candidate() {
        let intf = interface_with(7, "en0", Vec::new());
        let table = vec![entry("2001:db8::aa", 7), entry("2001:dead::bb", 7)];
        let mut local = std::collections::HashMap::from([(intf, IpSet::new())]);

        let mut forbidden = IpSet::new();
        forbidden.insert_range("2001:db8::/64".parse().expect("a valid range"));
        seed_from_neighbor_table_with(&mut local, &table, &Exclusions::new(forbidden));

        let targets = local.into_values().next().expect("the one interface");
        let carried: Vec<std::net::Ipv6Addr> = targets
            .v6()
            .iter()
            .map(|range| range.start_addr())
            .collect();

        assert!(
            !carried.contains(&"2001:db8::aa".parse().expect("literal")),
            "an excluded neighbour must not become a target"
        );
        assert!(
            carried.contains(&"2001:dead::bb".parse().expect("literal")),
            "and everything else still is"
        );
    }
}
