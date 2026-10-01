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
//! Planning settles which interface reaches a target, whether a `/64` can be
//! walked, whether a link-local address without a zone can be probed, whether a
//! sweep may take leads from the host's neighbour table, and which protocols need an
//! unprivileged fallback. As a value, a plan can be printed for a dry run, trimmed
//! (sweep two of five links), or asserted on in a test against a hand-written
//! interface table.
//!
//! ## What a plan costs to build
//!
//! No packets and no sockets. Building one reads the interface list, the routing
//! table and, for a sweep, the IPv6 neighbour table, the same reads
//! [`crate::system::interface`] performs for any caller.
//!
//! ## What a plan does not promise
//!
//! That every step will run. A step becomes a strategy through
//! [`DiscoveryStep::into_scanner`], which opens sockets and can fail: a capture that
//! cannot be opened, an interface that disappeared since planning. Those surface as
//! a [`StrategyError`] per step, and the scan continues with the rest.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use tokio::sync::mpsc::UnboundedSender;

use crate::config::limits;
use crate::config::{ProbeTuning, ZondConfig};
use crate::model::exclusion::Exclusions;
use crate::model::ip::range::{IpRange, Ipv6Range};
use crate::model::ip::scoped::ZoneMap;
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;
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
/// The ground was never probed, for a reason knowable before anything is sent. It
/// is reported so a caller can tell "nothing is there" from "nobody looked".
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct RefusedStep {
    /// The strategy that would have taken this work.
    pub scanner: ScannerKind,
    /// One short line: the ground, then the reason and any remedy in brief. The
    /// full reasoning is on the function that builds each refusal.
    pub reason: String,
}

impl RefusedStep {
    /// The TCP half left undone because `technique` cannot be expressed without
    /// raw sockets.
    ///
    /// A connect scan answers roughly what a SYN scan asks, but cannot send a FIN,
    /// a flagless segment or a bare ACK, so it cannot stand in for those.
    ///
    /// Reached from [`PortScanPlan::build`] when there are no raw sockets, and from
    /// the scan's coverage check when a raw socket was expected and would not open.
    pub fn technique_needs_raw_sockets(technique: TcpScanTechnique) -> Self {
        Self {
            scanner: ScannerKind::for_raw_tcp(technique),
            reason: format!("tcp ports: {technique} scan needs raw sockets (sudo)"),
        }
    }

    /// SCTP ports were named by a scan with no raw sockets to probe them with.
    ///
    /// There is no unprivileged INIT scan: the kernel offers no way to send a chunk
    /// and read the answer without completing an association.
    pub fn sctp_needs_raw_sockets() -> Self {
        Self {
            scanner: ScannerKind::SctpPort,
            reason: "sctp ports: init scan needs raw sockets (sudo)".to_string(),
        }
    }

    /// SCTP ports were named for a scan running as an idle scan, which probes
    /// through a third party and has no way to carry an INIT.
    ///
    /// An INIT sent directly would leave this host's own address on the target.
    pub fn sctp_not_in_an_idle_scan() -> Self {
        Self {
            scanner: ScannerKind::SctpPort,
            reason: "sctp ports: not probed in an idle scan".to_string(),
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
            reason: "udp ports: not probed in an idle scan".to_string(),
        }
    }

    /// The TCP half left undone on the targets a frames-only run cannot reach.
    ///
    /// [`technique_needs_raw_sockets`](Self::technique_needs_raw_sockets) for part
    /// of a scan: the targets only the kernel can carry.
    pub(crate) fn technique_beyond_frames(technique: TcpScanTechnique, targets: u128) -> Self {
        Self {
            scanner: ScannerKind::for_raw_tcp(technique),
            reason: format!(
                "tcp ports on {}: {technique} scan needs a raw socket (sudo)",
                counted(targets, "target", "targets"),
            ),
        }
    }

    /// The SCTP ports on the targets a frames-only run cannot reach, for the
    /// reason [`sctp_needs_raw_sockets`](Self::sctp_needs_raw_sockets) gives.
    pub(crate) fn sctp_beyond_frames(targets: u128) -> Self {
        Self {
            scanner: ScannerKind::SctpPort,
            reason: format!(
                "sctp ports on {}: init scan needs a raw socket (sudo)",
                counted(targets, "target", "targets"),
            ),
        }
    }

    /// A pass that sends its own segments to a host, left undone on the hosts a
    /// frames-only run cannot reach.
    ///
    /// No connect can stand in, since each pass reads something only a packet it
    /// built can ask. `pass` names the pass for a reader.
    pub(crate) fn pass_beyond_frames(scanner: ScannerKind, pass: &str, hosts: u128) -> Self {
        Self {
            scanner,
            reason: format!(
                "{pass} on {}: needs a raw socket (sudo)",
                counted(hosts, "host", "hosts"),
            ),
        }
    }

    /// A pass that would send the target its own packets, asked for under an
    /// idle scan.
    ///
    /// An idle scan forges every probe from its zombie so the target never hears
    /// from this host, as with
    /// [`idle_needs_privilege`](Self::idle_needs_privilege). `pass` names it
    /// briefly for a reader, and `scanner` is the strategy the report files the
    /// refusal under. The words say what was not run, as
    /// [`udp_not_in_an_idle_scan`](Self::udp_not_in_an_idle_scan)'s do.
    pub(crate) fn pass_not_in_an_idle_scan(scanner: ScannerKind, pass: &str) -> Self {
        Self {
            scanner,
            reason: format!("{pass}: not run in an idle scan"),
        }
    }

    /// An idle scan was asked for through a zombie the exclusions forbid.
    ///
    /// The scan probes the zombie repeatedly, so it would send an excluded address
    /// the most traffic of anything in the scan. No fallback, as with
    /// [`idle_needs_privilege`](Self::idle_needs_privilege).
    pub(crate) fn idle_zombie_excluded(zombie: IpAddr) -> Self {
        Self {
            scanner: ScannerKind::Idle,
            reason: format!("idle scan: zombie {zombie} is excluded"),
        }
    }

    /// An idle scan was asked for without the privilege it needs.
    ///
    /// The forged source address can only ride a self-built frame, which needs
    /// privilege. There is no fallback, since scanning under this host's own
    /// address defeats an idle scan.
    pub fn idle_needs_privilege() -> Self {
        Self {
            scanner: ScannerKind::Idle,
            reason: "idle scan: needs raw sockets (sudo)".to_owned(),
        }
    }

    /// A routed IPv6 range with more addresses than any strategy can walk.
    ///
    /// See [`MAX_ENUMERABLE_ADDRESSES`](crate::system::interface::MAX_ENUMERABLE_ADDRESSES)
    /// for the ceiling.
    pub fn routed_range_not_enumerable(range: &Ipv6Range) -> Self {
        Self {
            scanner: ScannerKind::Routed,
            reason: format!(
                "{}: too large to walk (give addresses or a smaller prefix)",
                describe(range)
            ),
        }
    }

    /// A TCP sweep left with no port to ask, every one it would ask being
    /// excluded.
    ///
    /// A sweep asking nothing would report every address silent. What it would have
    /// reached by TCP is left unasked; a link-layer sweep is unaffected. `scanner`
    /// is the sweep refused.
    pub(crate) fn every_discovery_port_excluded(scanner: ScannerKind) -> Self {
        Self {
            scanner,
            reason: "tcp liveness: every port it asks is excluded".to_owned(),
        }
    }

    /// A port target range with more addresses than a port scan can walk.
    ///
    /// Whatever the privilege: the multicast that sweeps a segment's `/64` finds
    /// hosts, not their ports, so the remedy is the addresses a sweep found.
    /// `scanner` is the port strategy the phase runs under.
    pub(crate) fn port_range_not_enumerable(range: &Ipv6Range, scanner: ScannerKind) -> Self {
        Self {
            scanner,
            reason: format!(
                "{}: too large to walk (give addresses or a smaller prefix)",
                describe(range)
            ),
        }
    }

    /// The same range, refused by an unprivileged scan.
    ///
    /// Worded apart from
    /// [`routed_range_not_enumerable`](Self::routed_range_not_enumerable) because
    /// the remedy differs: on the local segment, raw sockets reach a range this size
    /// through the all-nodes echo, one packet per `/64`.
    pub fn unprivileged_range_not_enumerable(range: &Ipv6Range) -> Self {
        Self {
            scanner: ScannerKind::Connect,
            reason: format!(
                "{}: too large to walk (sudo sweeps a segment)",
                describe(range)
            ),
        }
    }

    /// A port target that is link-local and names no interface.
    ///
    /// Every interface holds an `fe80::/64`, so `fe80::1` names a different machine
    /// on each. Written as `fe80::1%en0`, it names one. The reason suggests the
    /// target with an interface this host has: up, able to broadcast and holding a
    /// link-local address, preferring the default route's.
    ///
    /// [`RoutedTargets::ambiguous`](crate::system::interface::RoutedTargets)
    /// refuses the same target on the discovery path.
    pub fn link_local_port_target_needs_an_interface(range: &Ipv6Range) -> Self {
        let target = name(range);
        Self {
            scanner: ScannerKind::SynPort,
            reason: format!("{target}: {}", name_an_interface(range)),
        }
    }

    /// One link-local address given on two interfaces in a single scan.
    ///
    /// Each is a different machine, but a port scan records verdicts under the
    /// address, so both sets of answers would land on one host.
    pub fn link_local_port_target_names_two_segments(range: &Ipv6Range) -> Self {
        let target = name(range);
        Self {
            scanner: ScannerKind::SynPort,
            reason: format!("{target}: named on two interfaces (scan one at a time)"),
        }
    }

    /// An on-link IPv6 range too large to walk, in a scan that will not sweep
    /// the segment it is on.
    ///
    /// A local segment is covered by the all-nodes solicitation, one packet
    /// whatever the prefix length, so the remedy is a sweep. A [`Scope::Sweep`] step
    /// sends that packet and refuses nothing.
    ///
    /// Walking the range would fail silently: the address count overflows the
    /// deadline's target count, and the sweep stops a couple of thousand
    /// solicitations in having reported the range covered.
    pub fn local_range_needs_a_sweep(range: &Ipv6Range) -> Self {
        Self {
            scanner: ScannerKind::Local,
            reason: format!(
                "{}: too large to walk (sweep the segment instead)",
                describe(range)
            ),
        }
    }
}

/// Takes the IPv6 ranges out of `targets` that are too large to probe one
/// address at a time, leaving the rest.
///
/// The routed path's test, applied per range by
/// [`is_enumerable`](interface::is_enumerable), so a set holding a `/64` and three
/// literal addresses keeps the three. IPv4 is untouched.
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
    /// One direction only: a recorded refusal keeps the words, not the decision.
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
/// The size is quoted because it is the argument: "18446744073709551616
/// addresses" says more than "too large".
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
    /// it. The cheapest and most informative of the three: the only one that
    /// yields a MAC address or finds a neighbour nobody named.
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
    /// Runs beside [`Routed`](Self::Routed). A host that answers only SCTP would be
    /// reported down by a SYN sweep and never have its ports probed.
    RoutedSctp {
        /// The destinations, with their source addresses.
        targets: Vec<RoutedTarget>,
        /// The port every INIT is aimed at.
        port: u16,
    },
    /// Ordinary TCP connect attempts, for targets with no route and no segment:
    /// loopback, or anything the OS declined to resolve. Needs no privileges.
    ///
    /// For a process whose raw strategies send only frames, also whatever a frame
    /// cannot reach.
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
    /// Zero is meaningful: a [`Scope::Sweep`] step with no addresses still sends
    /// the all-nodes solicitation its whole segment may answer.
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
    /// A local step opens a link-layer channel on its interface; a routed step
    /// opens a raw transport and a capture. Either can fail with a
    /// [`StrategyError`], and a caller can record it and carry on with the steps
    /// that did build.
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
/// [module documentation](self).
#[derive(Debug, Clone)]
pub struct DiscoveryPlan {
    steps: Vec<DiscoveryStep>,
    refusals: Vec<RefusedStep>,
    ours: IpSet,
    /// The neighbours this host's routing table refuses, left to the connect
    /// step.
    refused_by_route: IpSet,
    /// The neighbour-table candidates the exclusions kept from a sweep.
    withheld: IpSet,
}

impl DiscoveryPlan {
    /// Works out which strategies would cover `targets`, opening nothing.
    ///
    /// `scope` decides whether the sweep may go beyond what it was given.
    /// [`Scope::Sweep`] earns a step for the link even when no address mapped to
    /// it (its all-nodes echo is one packet the whole segment may answer), and
    /// takes candidate addresses from the host's IPv6 neighbour table, the only
    /// source of IPv6 addresses nobody named. [`Scope::Targeted`] does neither.
    ///
    /// `exclusions` applies to addresses a sweep adds from the neighbour table, in
    /// `seed_from_neighbor_table`. The target list was already withheld against
    /// them in `withhold_targets`.
    ///
    /// `forced` pins the source addresses off-link targets are probed from,
    /// empty for a scan that let the routing table choose.
    pub fn build(targets: IpSet, scope: Scope, exclusions: &Exclusions, forced: &[IpAddr]) -> Self {
        let mut steps = Vec::new();
        let mut refusals = Vec::new();
        let mut refused_by_route = IpSet::new();

        let interface::RoutedTargets {
            mut local,
            routed,
            mut unmapped,
            ours,
            ambiguous,
            unenumerable,
        } = interface::map_ips_to_interfaces_forced(targets, forced);

        // A link-local target naming no interface: every interface has an
        // `fe80::/64`, so guessing would scan an arbitrary segment.
        for range in &ambiguous {
            refusals.push(RefusedStep {
                scanner: ScannerKind::Local,
                reason: format!("{}: {}", range.start_addr(), name_an_interface(range)),
            });
        }

        // A routed IPv6 prefix cannot be walked (see `MAX_ENUMERABLE_ADDRESSES`).
        for range in &unenumerable {
            refusals.push(RefusedStep::routed_range_not_enumerable(range));
        }

        // Only a sweep takes leads from the host itself.
        let mut withheld = IpSet::new();
        if matches!(scope, Scope::Sweep) {
            include_swept_link(&mut local);
            withheld = seed_from_neighbor_table(&mut local, exclusions);
        }

        for (interface, mut targets) in local {
            // `map_ips_to_interfaces` keeps an on-link range too large to walk
            // whole, for the sweep's all-nodes solicitation. A targeted run
            // would walk it, so it is dropped here. See
            // `local_range_needs_a_sweep`.
            for range in withhold_unwalkable(&mut targets) {
                match scope {
                    // Covered by the sweep's all-nodes packet.
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

            // A neighbour the routing table refuses is not framed, which would
            // bypass the table. The connect step gets it, the kernel refuses
            // the connect, and the address is filed as unreachable. The port
            // scan does the same; see `SourceResolver::resolve`.
            let refused = interface::refused_neighbours(&interface, &targets);
            if !refused.is_empty() {
                targets.subtract(&refused);
                for address in refused.iter() {
                    unmapped.insert(address);
                    refused_by_route.insert(address);
                }
                info!(
                    verbosity = 1,
                    "{} on {} refused by a route, not asked by frame",
                    counted(refused.len(), "address", "addresses"),
                    interface.name()
                );
            }

            // A sweep's link earns a step whether or not any address mapped to
            // it. A targeted run has nothing to send without targets.
            if targets.is_empty() && matches!(scope, Scope::Targeted) {
                continue;
            }
            // Logged here, where it is decided; the lookup that found the link
            // runs more than once a run.
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
            refused_by_route,
            withheld,
        }
    }

    /// The addresses from this host's IPv6 neighbour table that a plan
    /// [built](Self::build) from the same arguments would take as sweep
    /// candidates and the exclusions withhold, read without planning or logging.
    ///
    /// A scan counts these among the addresses its policy withheld, so a caller
    /// stating that count before the scan has them to add. Empty for
    /// [`Scope::Targeted`]. Only a run holding raw sockets or the link layer sweeps
    /// this way; a run without either withholds none.
    pub fn withheld_neighbours(
        targets: IpSet,
        scope: Scope,
        exclusions: &Exclusions,
        forced: &[IpAddr],
    ) -> IpSet {
        if !matches!(scope, Scope::Sweep) {
            return IpSet::new();
        }
        let mut local = interface::map_ips_to_interfaces_forced(targets, forced).local;
        include_swept_link(&mut local);
        let table = neighbor_cache::ipv6_neighbors();
        let machines = machines_named(exclusions, &table);
        let mut withheld = IpSet::new();
        for intf in local.keys() {
            for candidate in candidates_on(intf, &table, exclusions, &machines) {
                if candidate.withheld {
                    withheld.insert_range(candidate.range);
                }
            }
        }
        withheld.canonicalize();
        withheld
    }

    /// The neighbours this host's routing table refuses, which the plan left
    /// to the connect step; see
    /// [`refused_neighbours`](interface::refused_neighbours).
    pub(crate) fn refused_by_route(&self) -> &IpSet {
        &self.refused_by_route
    }

    /// The neighbour-table candidates the exclusions kept from this plan's
    /// sweep, which its phase counts among the addresses its policy withheld;
    /// see [`withheld_neighbours`](Self::withheld_neighbours).
    pub(crate) fn withheld(&self) -> &IpSet {
        &self.withheld
    }

    /// Adds an SCTP sweep beside every routed step, asking `port`.
    ///
    /// Separate from [`build`](Self::build), like [`PortScanPlan::cover_sctp`],
    /// because the port specification decides it. A caller that never mentions
    /// SCTP opens no second socket.
    ///
    /// Only the routed steps gain one. ARP and neighbour discovery answer whatever
    /// the host speaks above them, and a connect step has no raw socket for an
    /// INIT.
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
    /// Separate from [`build`](Self::build), like
    /// [`also_over_sctp`](Self::also_over_sctp). A port scan's liveness pass passes
    /// [`SynPorts::for_scan`], so a host that drops SYNs to anything it does not
    /// serve is still asked about the ports the scan will probe.
    ///
    /// The routed and connect steps change alike. A link-layer sweep is left as it
    /// was.
    ///
    /// An empty set removes and refuses the routed and connect steps; see
    /// `RefusedStep::every_discovery_port_excluded`.
    pub fn asking_tcp(&mut self, ports: SynPorts) {
        if ports.is_empty() {
            let refusals = &mut self.refusals;
            self.steps.retain(|step| match step {
                DiscoveryStep::Routed { .. } | DiscoveryStep::Connect { .. } => {
                    refusals.push(RefusedStep::every_discovery_port_excluded(step.kind()));
                    false
                }
                _ => true,
            });
            return;
        }
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
    /// For a process whose raw strategies only send frames. A frame reaches what
    /// has Ethernet in front of it; `targets` is the rest, as
    /// [`beyond_frames`](crate::system::interface::beyond_frames) computed it. Left
    /// in a routed step, a tunnelled target would get a frame out of the wrong
    /// interface, and loopback none at all.
    ///
    /// A step left with nothing to send is dropped, except a sweep's local step on
    /// a link that carries frames, whose most important probe is addressed to
    /// nobody. The connect step is left alone.
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
                    // What the subtraction removed.
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
    /// How a frames-only sweep reaches what its frames cannot.
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
            // The routed steps' ports, since a routed step would have swept these.
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

    /// The targets that are this host's own addresses.
    ///
    /// Up by construction and covered by no step: the kernel routes traffic for
    /// an address this host holds through loopback, so a probe never reaches the
    /// link and nothing there answers for it.
    ///
    /// A caller running the plan itself records these as up without probing them,
    /// as [`orchestrator`](crate::scanner) does.
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
    /// [`ScannerKind::SynPort`] means a half-open connection attempt was made and
    /// the flag probes make none. [`ScannerKind::for_raw_tcp`] holds that rule, so
    /// a step and the scanner it builds agree.
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
    /// Decides whether host enrichment is worth running: ARP, ICMPv6 and raw TCP
    /// yield a MAC and a round trip, the connect fallbacks neither. Not derivable
    /// from [`kind`](Self::kind), which differs per raw technique.
    pub fn is_raw(&self) -> bool {
        matches!(self, Self::RawTcp { .. } | Self::RawUdp | Self::RawSctp)
    }

    /// Opens whatever this step needs and hands back the strategy to run.
    ///
    /// `target_count` sizes the probe ledger, so a raw scanner reserves
    /// correlation state up front.
    ///
    /// `zones` names the interface each link-local target was given on, which
    /// supplies the scope id both families of scanner send under. Empty for a scan
    /// that named none.
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
    /// The protocol each of `refusals` leaves unprobed. A target of a refused
    /// protocol still reaches the router, which counts it as declined by the plan.
    refused: Vec<Protocol>,
    technique: TcpScanTechnique,
    /// Whether this is an idle scan, whether or not its idle step survived.
    ///
    /// Kept apart from the steps because a refused idle scan has no idle step but
    /// must still refuse other transports. Read from the steps, a privileged run
    /// through an excluded zombie would plan SCTP ports as a direct probe from this
    /// host's own address.
    idle: bool,
}

impl PortScanPlan {
    /// Works out which strategies would probe the requested ports, opening
    /// nothing.
    ///
    /// `privilege` is which sockets the scan would run with, so a caller can plan
    /// for a privilege level they do not hold.
    ///
    /// ## The fallback is decided per protocol
    ///
    /// A sandbox can permit a raw TCP socket and refuse a raw UDP one. A protocol
    /// left with no strategy would never be probed or reported.
    ///
    /// ## A connect fallback substitutes only for a SYN scan
    ///
    /// It answers roughly what a SYN scan asks, but cannot send a FIN, a flagless
    /// segment or a bare ACK. Where the caller chose one of those and raw sockets
    /// are unavailable, the TCP half is refused.
    pub fn build(cfg: &ZondConfig, privilege: Privilege) -> Self {
        let mut plan = Self {
            steps: Vec::new(),
            refusals: Vec::new(),
            refused: Vec::new(),
            technique: cfg.tcp_technique,
            idle: cfg.idle_scan.is_some(),
        };

        // An idle scan replaces the ordinary port scan. It is TCP-only, so no
        // step covers UDP; the refusal waits for the targets to name a UDP port
        // (see `cover_udp`).
        if let Some(idle) = &cfg.idle_scan {
            // Checked before privilege, which would be the wrong remedy. The
            // zombie is named in settings, not the target list, so nothing else
            // withholds it.
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
        let raw = Self::raw_scanning(privilege);
        if privilege.is_raw() && !raw {
            warn!("no usable network interface found; using TCP connect fallback");
        }

        // The TCP step alone. UDP is added by [`cover_udp`] when the targets
        // name a UDP port, as SCTP is by [`cover_sctp`].
        if raw {
            plan.steps.push(PortScanStep::RawTcp {
                technique: cfg.tcp_technique,
            });
        } else if cfg.tcp_technique.has_connect_fallback() {
            plan.steps.push(PortScanStep::ConnectTcp);
        } else {
            plan.refuse(
                Protocol::Tcp,
                RefusedStep::technique_needs_raw_sockets(cfg.tcp_technique),
            );
        }

        plan
    }

    /// Whether this host can raw-scan: it holds the privilege and has an address
    /// to probe from. Shared by the TCP step in [`build`](Self::build) and the UDP
    /// step, so the two agree.
    fn raw_scanning(privilege: Privilege) -> bool {
        privilege.is_raw() && interface::SourceResolver::from_system().has_sources()
    }

    /// Records that `protocol` will not be probed, and the refusal that says
    /// why.
    fn refuse(&mut self, protocol: Protocol, refusal: RefusedStep) {
        self.refusals.push(refusal);
        self.refused.push(protocol);
    }

    /// The TCP technique this plan was built for.
    ///
    /// Outlives the steps: if a raw step fails to open, whether a connect scanner
    /// may stand in depends on the technique.
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
    /// Separate from [`build`](Self::build) because SCTP ports are named in a
    /// target's port specification, which the plan is built before reading, and no
    /// default port list holds one. A scan that never mentions SCTP opens no raw
    /// socket or capture for it.
    ///
    /// Called with the same `privilege` the plan was built for.
    pub fn cover_sctp(&mut self, privilege: Privilege) {
        if self.idle {
            self.refuse(Protocol::Sctp, RefusedStep::sctp_not_in_an_idle_scan());
            return;
        }

        // The same two conditions as raw scanning in `build`.
        if privilege.is_raw() && interface::SourceResolver::from_system().has_sources() {
            self.steps.push(PortScanStep::RawSctp);
        } else {
            self.refuse(Protocol::Sctp, RefusedStep::sctp_needs_raw_sockets());
        }
    }

    /// Adds the step that probes UDP, or the refusal that says why it could not
    /// be added.
    ///
    /// Separate from [`build`](Self::build), like [`cover_sctp`](Self::cover_sctp),
    /// so a TCP-only scan opens no UDP scanner and an idle scan of TCP ports
    /// carries no UDP refusal. Called only when the targets name a UDP port, it
    /// adds the connect or raw step the run's privilege calls for, or under an idle
    /// scan the refusal.
    ///
    /// Called with the same `privilege` the plan was built for, so the UDP step
    /// is raw exactly where the TCP step is.
    pub fn cover_udp(&mut self, privilege: Privilege) {
        if self.covers(Protocol::Udp) {
            return;
        }
        if self.idle {
            self.refuse(Protocol::Udp, RefusedStep::udp_not_in_an_idle_scan());
        } else if Self::raw_scanning(privilege) {
            self.steps.push(PortScanStep::RawUdp);
        } else {
            self.steps.push(PortScanStep::ConnectUdp);
        }
    }

    /// Whether one of [`refusals`](Self::refusals) leaves `protocol`
    /// unprobed.
    ///
    /// Differs from a negated [`covers`](Self::covers): a protocol no step covers
    /// and no refusal names was left out silently, and the scan reports its
    /// targets as lost; one a refusal names has already been reported.
    pub(crate) fn refuses(&self, protocol: Protocol) -> bool {
        self.refused.contains(&protocol)
    }

    /// Whether any step covers `protocol`.
    ///
    /// Check after editing [`steps_mut`](Self::steps_mut): a plan with nothing for a
    /// protocol probes and reports none of its ports.
    pub fn covers(&self, protocol: Protocol) -> bool {
        self.steps.iter().any(|step| step.protocol() == protocol)
    }
}

/// Makes sure the link a sweep is about is among the links to be scanned, even
/// when no address mapped to it.
///
/// Mapping targets to interfaces only produces interfaces some target named. A
/// link addressed only in IPv6 maps to nothing (a `/64` cannot be enumerated and
/// there is no IPv4 range), so without this its all-nodes echo is never sent and the
/// scan reports an empty network.
///
/// Matched by name: a `NetworkInterface` compares on every field, and a mismatch
/// here would scan one link twice.
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
/// The only source of IPv6 addresses nobody named. A neighbor solicitation can
/// only be aimed at a known address, and the all-nodes echo is optional to answer
/// and draws only link-local addresses. The OS table accumulates global and
/// unique-local ones at no cost in packets: on one test segment it held fifteen the
/// engine could not otherwise learn.
///
/// Three exclusions:
///
/// - **Other interfaces' entries.** A neighbour on `en1` is not reachable
///   through `en0`.
/// - **This host's own addresses**, which the table also lists.
/// - **Loopback and the unspecified address**, which name nothing on a segment.
///
/// Entries come from a table that goes stale, so each becomes a probe like any
/// other and appears in the report only if it answers now.
///
/// Returns the candidates `exclusions` kept from the sweep, which the phase
/// counts among the addresses its policy withheld.
fn seed_from_neighbor_table(local: &mut HashMap<Link, IpSet>, exclusions: &Exclusions) -> IpSet {
    let table = neighbor_cache::ipv6_neighbors();
    if table.is_empty() {
        return IpSet::new();
    }
    let machines = machines_named(exclusions, &table);
    seed_from_neighbor_table_with(local, &table, exclusions, &machines)
}

/// The machines `exclusions` name, by hardware address, read off both
/// neighbour tables, `v6_table` among them: an excluded IPv4 address is tied
/// to its machine's IPv6 ones by nothing but the hardware address they share.
fn machines_named(
    exclusions: &Exclusions,
    v6_table: &[neighbor_cache::Neighbor],
) -> BTreeSet<MacAddr> {
    if exclusions.is_empty() {
        return BTreeSet::new();
    }
    let v4 = neighbor_cache::ipv4_neighbors();
    exclusions.hardware_in(v4.iter().chain(v6_table).map(|entry| (entry.ip, entry.mac)))
}

/// [`seed_from_neighbor_table`] against an explicit table, for tests.
///
/// `machines` are the hardware addresses of the machines the exclusions name,
/// and an entry answering from one is held to the policy as its excluded
/// address is; see [`Exclusions::hardware_in`].
fn seed_from_neighbor_table_with(
    local: &mut HashMap<Link, IpSet>,
    table: &[neighbor_cache::Neighbor],
    exclusions: &Exclusions,
    machines: &BTreeSet<MacAddr>,
) -> IpSet {
    let mut withheld = IpSet::new();
    for (intf, targets) in local.iter_mut() {
        let mut seeded = 0usize;
        for candidate in candidates_on(intf, table, exclusions, machines) {
            // The exclusion policy. `withhold_targets` only subtracted from the
            // target list, and these addresses come from the neighbour table.
            // Without this a sweep would solicit an excluded address; `write_host`
            // would drop the finding, but the packet would already be sent.
            if candidate.withheld {
                info!(
                    verbosity = 2,
                    "neighbour {} is excluded, so it is not taken as a candidate",
                    candidate.address
                );
                withheld.insert_range(candidate.range);
                continue;
            }
            targets.insert_range(candidate.range);
            seeded += 1;
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
    withheld.canonicalize();
    withheld
}

/// One neighbour-table address a sweep of a link would take as a candidate.
struct Candidate {
    /// The address as the table lists it.
    address: IpAddr,
    /// What a sweep probes for it: the address, with the link's interface
    /// where the address is link-local.
    range: IpRange,
    /// Whether the exclusions keep it from the sweep: they name it, or it is
    /// listed under the hardware of a machine they name.
    withheld: bool,
}

/// The neighbour-table candidates on `intf`, in table order, each with
/// whether `exclusions` keep it from a sweep; see [`candidates_for`] for which
/// entries are candidates at all.
fn candidates_on(
    intf: &Link,
    table: &[neighbor_cache::Neighbor],
    exclusions: &Exclusions,
    machines: &BTreeSet<MacAddr>,
) -> Vec<Candidate> {
    let tied: HashSet<IpAddr> = table
        .iter()
        .filter(|entry| entry.mac.is_some_and(|mac| machines.contains(&mac)))
        .map(|entry| entry.ip)
        .collect();
    candidates_for(intf, table)
        .into_iter()
        .filter_map(|address| {
            let IpAddr::V6(v6) = address else {
                return None;
            };
            // Zoned only where it cannot be probed without one; as in `ScopedIp`,
            // a global address through two interfaces is one address.
            let zone = v6.is_unicast_link_local().then_some(intf.index());
            let range = IpRange::V6(Ipv6Range::scoped(v6, v6, zone).ok()?);
            Some(Candidate {
                address,
                range,
                withheld: exclusions.excludes(&address) || tied.contains(&address),
            })
        })
        .collect()
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

/// The remedy for a link-local target that names no interface: the target
/// written with an interface this host has, from its own table.
///
/// An example shows how to name the interface, using a name the reader has. Where
/// the host has no link to suggest, the instruction alone.
fn name_an_interface(range: &Ipv6Range) -> String {
    match link_local_example(&crate::system::interface::interfaces_or_none()) {
        Some(link) => format!(
            "link-local, name the interface ({}%{})",
            range.start_addr(),
            link.name()
        ),
        None => "link-local, name the interface".to_owned(),
    }
}

/// The link a link-local target is most likely meant on: one that is up, can
/// broadcast and holds a link-local address of its own, which is a segment
/// `fe80::/64` means something on. The default route's is preferred, otherwise
/// the first in system order.
fn link_local_example(links: &[Link]) -> Option<&Link> {
    let segment = |link: &&Link| {
        link.is_up()
            && link.is_broadcast()
            && !link.is_loopback()
            && link
                .ipv6()
                .any(|(address, _)| address.is_unicast_link_local())
    };
    links
        .iter()
        .filter(segment)
        .find(|link| link.carries_default_route())
        .or_else(|| links.iter().find(segment))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The link-local hint names an interface this host has**, one that is
    /// up, broadcasts and holds a link-local address, the default route's
    /// first, and suggests none where the host has no such link.
    #[test]
    fn the_link_local_hint_names_an_interface_this_host_has() {
        use crate::system::interface::{Addressing, LinkAddress};
        use std::net::Ipv6Addr;

        let link_local =
            LinkAddress::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 64);
        let global = LinkAddress::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            64,
        );
        let link = |name: &str, addresses: Vec<LinkAddress>| {
            Link::new(name, 1)
                .with_link_up(true)
                .with_addressing(Addressing::Broadcast)
                .with_addresses(addresses)
        };

        let links = [
            link("tun0", vec![link_local]).with_addressing(Addressing::PointToPoint),
            link("eth1", vec![global]),
            link("eth2", vec![link_local]).with_link_up(false),
            link("eth0", vec![link_local]),
            link("wlan0", vec![link_local]).with_default_route(true),
        ];
        assert_eq!(link_local_example(&links).map(Link::name), Some("wlan0"));
        assert_eq!(
            link_local_example(&links[..4]).map(Link::name),
            Some("eth0")
        );
        assert!(link_local_example(&links[..3]).is_none());
    }

    /// The port a raw TCP scanner built here probes from. Its transport sends
    /// nothing, so which one does not matter.
    const SRC_PORT: u16 = 54_321;

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

    /// A link a frame can be put on, unlike `interface_with`'s bare one.
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

    /// What a frames-only sweep cannot reach moves to the connect step. A local
    /// step left empty is dropped; one still holding a framable neighbour stays.
    #[test]
    fn what_a_frame_cannot_reach_moves_to_the_connect_step() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            refused_by_route: IpSet::new(),
            withheld: IpSet::new(),
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

    /// A sweep's own link keeps its step with nothing left to address. A link
    /// that carries no frames is dropped.
    #[test]
    fn a_sweeps_step_stays_on_a_framed_link_and_goes_on_a_tunnel() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            refused_by_route: IpSet::new(),
            withheld: IpSet::new(),
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

    /// Withholding leaves the connect step as it was.
    #[test]
    fn withholding_leaves_the_connect_step_as_it_was() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            refused_by_route: IpSet::new(),
            withheld: IpSet::new(),
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
            refused_by_route: IpSet::new(),
            withheld: IpSet::new(),
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

    /// Connect addresses are asked the same ports as routed ones, so a filtered
    /// host serving only a port the scan names is found either way.
    #[test]
    fn the_connect_step_asks_the_ports_the_routed_steps_are_given() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            refused_by_route: IpSet::new(),
            withheld: IpSet::new(),
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

    /// A plan whose every TCP port is excluded refuses its routed and connect
    /// steps, which would otherwise file every address as silent.
    #[test]
    fn a_plan_left_no_tcp_port_refuses_its_tcp_steps() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            refused_by_route: IpSet::new(),
            withheld: IpSet::new(),
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
        let everything = "1-65535".try_into().expect("a port specification");

        plan.asking_tcp(SynPorts::common().excluding(&everything));

        assert!(plan.steps().is_empty(), "left {:?}", plan.steps());
        let refused: Vec<ScannerKind> = plan.refusals().iter().map(|r| r.scanner).collect();
        assert_eq!(refused, [ScannerKind::Routed, ScannerKind::Connect]);
    }

    /// A connect step made after the ports were chosen asks them too.
    #[test]
    fn a_connect_step_made_for_what_frames_miss_asks_the_routed_ports() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            refused_by_route: IpSet::new(),
            withheld: IpSet::new(),
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

    /// An SCTP sweep runs beside each routed step and nowhere else.
    #[test]
    fn an_sctp_sweep_is_added_to_the_routed_steps_alone() {
        let mut plan = DiscoveryPlan {
            ours: IpSet::new(),
            refused_by_route: IpSet::new(),
            withheld: IpSet::new(),
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

    /// SCTP has no unprivileged form, so without raw sockets its ports are
    /// refused.
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

    /// An idle scan cannot carry an INIT, and sending one directly would expose
    /// this host, so SCTP ports are refused.
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

    /// A zombie the operator excluded is not scanned through, since the idle scan
    /// sends it SYN+ACKs repeatedly. No direct probe replaces it, so no TCP port is
    /// planned.
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

    /// A refused idle scan still refuses other transports. Otherwise a privileged
    /// plan would probe the target's SCTP ports from this host's own address once
    /// the zombie was excluded.
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
            plan.cover_udp(privilege);

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

    /// An ordinary scan plans no UDP step until the targets name a UDP port.
    #[test]
    fn a_udp_step_is_planned_only_when_the_targets_name_udp() {
        for privilege in [Privilege::Raw, Privilege::Connect] {
            let plan = PortScanPlan::build(&ZondConfig::default(), privilege);
            assert!(
                !plan.covers(Protocol::Udp),
                "{privilege:?}: a plan built before the targets are read names no UDP step, so \
                 a TCP-only scan opens no UDP scanner to probe nothing"
            );
        }

        let mut plan = PortScanPlan::build(&ZondConfig::default(), Privilege::Connect);
        plan.cover_udp(Privilege::Connect);
        assert!(plan.covers(Protocol::Udp) && !plan.refuses(Protocol::Udp));
        assert!(plan.refusals().is_empty());
    }

    fn v6_set(cidr: &str) -> IpSet {
        crate::model::parse::ip::to_set(&[cidr], None, None).expect("a range")
    }

    /// A local `/64` is withheld from a targeted run. Walked, its count overflows
    /// `usize` and the sweep stops two thousand solicitations in, having reported
    /// the prefix covered.
    #[test]
    fn a_local_prefix_too_large_to_walk_is_withheld_from_the_targets() {
        let mut targets = v6_set("2001:db8:1:1::/64");
        assert_eq!(targets.len(), 1u128 << 64, "a /64, kept whole to here");

        let withheld = withhold_unwalkable(&mut targets);

        assert_eq!(withheld.len(), 1, "the prefix is taken out");
        assert!(targets.is_empty(), "and nothing is left to walk");
    }

    /// Tested per range, so a prefix beside three literal addresses keeps the
    /// three.
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

    /// A range small enough to walk is left as it was.
    #[test]
    fn a_walkable_prefix_is_untouched() {
        let mut targets = v6_set("2001:db8::/120");
        let before = targets.len();

        assert!(withhold_unwalkable(&mut targets).is_empty());
        assert_eq!(targets.len(), before);
    }

    /// Another interface's neighbour, this host's own address and loopback never
    /// become targets.
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

    /// A link-local candidate carries its interface; a global one does not, as in
    /// `ScopedIp`.
    #[test]
    fn a_seeded_link_local_keeps_its_interface_and_a_global_does_not() {
        let intf = interface_with(7, "en0", Vec::new());
        let table = vec![entry("fe80::bb", 7), entry("2001:db8::aa", 7)];
        let mut local = std::collections::HashMap::from([(intf, IpSet::new())]);

        seed_from_neighbor_table_with(&mut local, &table, &Exclusions::none(), &BTreeSet::new());

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

    /// An unprivileged plan still covers both protocols.
    #[test]
    fn an_unprivileged_plan_covers_both_protocols() {
        let mut plan = PortScanPlan::build(&ZondConfig::default(), Privilege::Connect);
        plan.cover_udp(Privilege::Connect);

        assert!(plan.covers(Protocol::Tcp));
        assert!(plan.covers(Protocol::Udp));
        assert!(plan.refusals().is_empty());
    }

    /// A connect scan substitutes only for a SYN scan. For another technique, an
    /// unprivileged plan leaves the TCP half out and says why.
    #[test]
    fn a_technique_the_fallback_cannot_express_is_refused_at_planning_time() {
        let cfg = ZondConfig {
            tcp_technique: TcpScanTechnique::Fin,
            ..ZondConfig::default()
        };
        let mut plan = PortScanPlan::build(&cfg, Privilege::Connect);
        plan.cover_udp(Privilege::Connect);

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

    /// A step and the scanner it becomes share a name, so failures are filed
    /// under one strategy. In particular a FIN scan is not called
    /// [`ScannerKind::SynPort`], which means a half-open connection was attempted.
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
        for &technique in TcpScanTechnique::ALL {
            let (_tx, rx) = tokio::sync::mpsc::channel(1024);
            let scanner = TcpPortScanner::with_transport(
                interface::SourceResolver::from_links(&[]),
                ctx.clone(),
                technique,
                ProbeTransport::from_parts(Box::new(Unsendable), rx),
                1,
                SRC_PORT,
            );

            assert_eq!(
                PortScanStep::RawTcp { technique }.kind(),
                scanner.kind(),
                "a {technique} step and its scanner disagree about what to call themselves"
            );
        }
    }

    /// Every raw TCP technique counts as raw for host enrichment.
    #[test]
    fn every_raw_step_is_recognisable_as_one() {
        for &technique in TcpScanTechnique::ALL {
            assert!(PortScanStep::RawTcp { technique }.is_raw(), "{technique}");
        }
        assert!(PortScanStep::RawUdp.is_raw());
        assert!(!PortScanStep::ConnectTcp.is_raw());
        assert!(!PortScanStep::ConnectUdp.is_raw());
    }

    /// The technique outlives the steps.
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

    /// Editing a plan changes what would run; `covers` reports a protocol edited
    /// out.
    #[test]
    fn dropping_a_step_is_visible_in_what_the_plan_covers() {
        let mut plan = PortScanPlan::build(&ZondConfig::default(), Privilege::Connect);
        plan.steps_mut()
            .retain(|step| step.protocol() != Protocol::Udp);

        assert!(plan.covers(Protocol::Tcp));
        assert!(!plan.covers(Protocol::Udp));
    }

    /// **A sweep takes no candidate from the machine an exclusion names.** An
    /// excluded IPv4 address and the same machine's IPv6 addresses share only the
    /// hardware address the neighbour tables list them under.
    ///
    /// What the sweep kept back is returned, since the phase counts it as
    /// withheld.
    #[test]
    fn a_swept_plan_takes_no_candidate_from_an_excluded_machine() {
        let machine = MacAddr::new(0x02, 0, 0, 0, 0, 0x30);
        let other = MacAddr::new(0x02, 0, 0, 0, 0, 0x31);
        let at = |ip: &str, mac| neighbor_cache::Neighbor {
            mac: Some(mac),
            ..entry(ip, 7)
        };
        let v4 = neighbor_cache::Neighbor {
            ip: "192.0.2.30".parse().expect("literal"),
            mac: Some(machine),
            interface_index: 7,
        };
        let v6_table = vec![at("2001:db8::30", machine), at("2001:db8::31", other)];

        let mut forbidden = IpSet::new();
        forbidden.insert(v4.ip);
        let exclusions = Exclusions::new(forbidden);
        let mut both = vec![v4];
        both.extend(v6_table.iter().cloned());
        let machines = exclusions.hardware_in(both.iter().map(|entry| (entry.ip, entry.mac)));

        let intf = interface_with(7, "en0", Vec::new());
        let mut local = std::collections::HashMap::from([(intf, IpSet::new())]);
        let withheld = seed_from_neighbor_table_with(&mut local, &v6_table, &exclusions, &machines);

        let targets = local.into_values().next().expect("the one interface");
        assert!(
            !targets.contains(&v6("2001:db8::30")),
            "the excluded machine's IPv6 address became a target"
        );
        assert_eq!(
            withheld.iter().collect::<Vec<_>>(),
            vec![v6("2001:db8::30")],
            "what the sweep kept back went uncounted"
        );
        assert!(
            targets.contains(&v6("2001:db8::31")),
            "and its neighbour did"
        );
    }

    /// **A sweep does not take an excluded neighbour as a candidate.**
    ///
    /// A sweep adds addresses from the host's neighbour table, which were never in
    /// the withheld target list. `write_host` would drop the finding, but not the
    /// packet already sent.
    #[test]
    fn a_swept_plan_does_not_take_an_excluded_neighbour_as_a_candidate() {
        let intf = interface_with(7, "en0", Vec::new());
        let table = vec![entry("2001:db8::aa", 7), entry("2001:dead::bb", 7)];
        let mut local = std::collections::HashMap::from([(intf, IpSet::new())]);

        let mut forbidden = IpSet::new();
        forbidden.insert_range("2001:db8::/64".parse().expect("a valid range"));
        seed_from_neighbor_table_with(
            &mut local,
            &table,
            &Exclusions::new(forbidden),
            &BTreeSet::new(),
        );

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
