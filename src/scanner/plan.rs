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
//! unprivileged fallback — all of that is settled before a single socket is
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
//! configuration — the interface list, the routing table, and for a sweep the
//! IPv6 neighbour table — because which strategy reaches a target is a fact
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

use pnet::datalink::NetworkInterface;
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{ProbeTuning, ZondConfig};
use crate::model::ip::range::{IpRange, Ipv6Range};
use crate::model::ip::set::IpSet;
use crate::model::port::Protocol;
use crate::model::technique::TcpScanTechnique;
use crate::scanner::pacing::limits;
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::scanner::strategy::connect::{
    ConnectPortScanner, ConnectScanner, ConnectUdpPortScanner,
};
use crate::scanner::strategy::local::{LocalScanner, Scope};
use crate::scanner::strategy::routed::{RoutedScanner, TcpPortScanner, UdpPortScanner};
use crate::scanner::strategy::{HostScanner, PortScanner, StrategyError};
use crate::system::interface::{self, RoutedTarget};
use crate::system::neighbors;
use crate::{info, warn};

/// Something the scan will not do, decided at planning time.
///
/// A refusal is not a failure of the network and not an address that went
/// unanswered — it was never probed, and the reason is knowable before anything
/// is sent. It is carried out of the plan rather than dropped because the one
/// thing a scanner may never do is stay quiet about ground it did not cover: a
/// caller has to be able to tell "nothing is there" from "nobody looked", and
/// only one of those is visible in a host count.
#[derive(Debug, Clone)]
pub struct Refusal {
    /// The strategy that would have taken this work.
    pub scanner: ScannerKind,
    /// What cannot be done, and what the caller could write instead.
    pub reason: String,
}

impl Refusal {
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
        interface: Box<NetworkInterface>,
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
    },
    /// Ordinary TCP connect attempts, for targets with no route and no segment —
    /// loopback, or anything the OS declined to resolve. Needs no privileges.
    Connect {
        /// The addresses to try.
        targets: IpSet,
    },
}

impl DiscoveryStep {
    /// Which strategy this step becomes.
    pub fn kind(&self) -> ScannerKind {
        match self {
            Self::Local { .. } => ScannerKind::Local,
            Self::Routed { .. } => ScannerKind::Routed,
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
            Self::Local { targets, .. } | Self::Connect { targets } => targets.len(),
            Self::Routed { targets } => targets.len() as u128,
        }
    }

    /// Opens whatever this step needs and hands back the strategy to run.
    ///
    /// **This is where the plan stops being free.** A local step opens a
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
            Self::Routed { targets } => {
                Ok(Box::new(RoutedScanner::new(targets, ctx, dns_tx, tuning)?))
            }
            Self::Connect { targets } => Ok(Box::new(ConnectScanner::new(targets, ctx))),
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
    refusals: Vec<Refusal>,
}

impl DiscoveryPlan {
    /// Works out which strategies would cover `targets`, opening nothing.
    ///
    /// `scope` decides whether the sweep may go beyond what it was given.
    /// [`Scope::Sweep`] earns a step for the link even when no address mapped to
    /// it — its all-nodes echo is one packet the whole segment may answer — and
    /// takes candidate addresses from the host's IPv6 neighbour table, which is
    /// the only source the engine has for an IPv6 address nobody named.
    /// [`Scope::Targeted`] does neither: probing addresses nobody asked about is
    /// defensible for `lan` and surprising for `zond <address>`.
    pub fn build(targets: IpSet, scope: Scope) -> Self {
        let mut steps = Vec::new();
        let mut refusals = Vec::new();

        let interface::RoutedTargets {
            mut local,
            routed,
            unmapped,
            ambiguous,
            unenumerable,
        } = interface::map_ips_to_interfaces(targets);

        // A link-local target naming no interface. Refused rather than guessed
        // at: every interface has an `fe80::/64`, so probing the first one that
        // matches would scan an arbitrary segment and report the address absent
        // when it is present on another.
        for range in &ambiguous {
            refusals.push(Refusal {
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
        // (see `MAX_ENUMERABLE_ADDRESSES`), and until discovery gains a strategy
        // that searches a scope instead of a list, saying so is the whole of
        // what the engine can honestly do with one.
        for range in &unenumerable {
            refusals.push(Refusal::routed_range_not_enumerable(range));
        }

        // A sweep may probe addresses nobody named, so it may also take leads
        // from the host itself. A targeted run may not.
        if matches!(scope, Scope::Sweep) {
            include_swept_link(&mut local);
            seed_from_neighbor_table(&mut local);
        }

        for (interface, targets) in local {
            // A sweep's link earns a step whether or not any address mapped to
            // it. A targeted run has nothing to send without targets.
            if targets.is_empty() && matches!(scope, Scope::Targeted) {
                continue;
            }
            steps.push(DiscoveryStep::Local {
                interface: Box::new(interface),
                targets,
                scope,
            });
        }

        if !routed.is_empty() {
            steps.push(DiscoveryStep::Routed { targets: routed });
        }

        if !unmapped.is_empty() {
            steps.push(DiscoveryStep::Connect { targets: unmapped });
        }

        Self { steps, refusals }
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
    pub fn refusals(&self) -> &[Refusal] {
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
    /// A full TCP connect per target. Needs no privileges, and answers roughly
    /// the question a SYN scan asks.
    ConnectTcp,
    /// An unprivileged UDP probe.
    ConnectUdp,
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
            Self::ConnectTcp => ScannerKind::Connect,
            Self::ConnectUdp => ScannerKind::ConnectUdp,
        }
    }

    /// The transport protocol this step probes.
    pub fn protocol(&self) -> Protocol {
        match self {
            Self::RawTcp { .. } | Self::ConnectTcp => Protocol::Tcp,
            Self::RawUdp | Self::ConnectUdp => Protocol::Udp,
        }
    }

    /// Whether this step needs raw sockets.
    ///
    /// Asked after a scan is assembled, to decide whether host enrichment is
    /// worth running: ARP, ICMPv6 and raw TCP are what yield a MAC and a round
    /// trip, and the connect fallbacks yield neither.
    ///
    /// A property of the step rather than of its [`kind`](Self::kind), because
    /// the two answer different questions. Read off the name instead, this went
    /// wrong the moment a technique stopped being called `syn_port`.
    pub fn is_raw(&self) -> bool {
        matches!(self, Self::RawTcp { .. } | Self::RawUdp)
    }

    /// Opens whatever this step needs and hands back the strategy to run.
    ///
    /// `target_count` sizes the probe ledger; a raw scanner uses it to reserve
    /// correlation state up front rather than growing it under load.
    pub fn into_scanner(
        self,
        ctx: ScanContext,
        target_count: usize,
        tuning: ProbeTuning,
    ) -> Result<Box<dyn PortScanner>, StrategyError> {
        match self {
            Self::RawTcp { technique } => Ok(Box::new(TcpPortScanner::new(
                interface::SourceResolver::from_system(),
                ctx,
                technique,
                target_count,
                tuning,
            )?)),
            Self::RawUdp => Ok(Box::new(UdpPortScanner::new(
                interface::SourceResolver::from_system(),
                ctx,
                target_count,
                tuning,
            )?)),
            Self::ConnectTcp => Ok(Box::new(ConnectPortScanner::new(
                ctx,
                limits::CONNECT_CONCURRENCY,
                tuning.service_detection,
            ))),
            Self::ConnectUdp => Ok(Box::new(ConnectUdpPortScanner::new(
                ctx,
                limits::CONNECT_CONCURRENCY,
            ))),
        }
    }
}

/// What a port scan intends to do.
#[derive(Debug, Clone)]
pub struct PortScanPlan {
    steps: Vec<PortScanStep>,
    refusals: Vec<Refusal>,
    technique: TcpScanTechnique,
}

impl PortScanPlan {
    /// Works out which strategies would probe the requested ports, opening
    /// nothing.
    ///
    /// `privileged` is whether raw sockets are available. It is a parameter
    /// rather than something read here so a caller can plan for a privilege
    /// level they do not currently hold — asking "what would a root scan do?"
    /// is a reasonable question and needs no root to answer.
    ///
    /// ## The fallback is decided per protocol, not per scan
    ///
    /// A host can be able to build one raw scanner and not the other — the TCP
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
    /// undone — worse for the caller, and honest, where a silent substitution
    /// would hand back verdicts from a technique they did not choose with no
    /// field in the report saying so.
    pub fn build(cfg: &ZondConfig, privileged: bool) -> Self {
        let mut steps = Vec::new();
        let mut refusals = Vec::new();

        // Raw scanning needs both the privilege and an address to probe from.
        let raw = privileged && interface::SourceResolver::from_system().has_sources();
        if privileged && !raw {
            warn!("No usable network interface found; using TCP connect fallback");
        }

        if raw {
            steps.push(PortScanStep::RawTcp {
                technique: cfg.tcp_technique,
            });
            steps.push(PortScanStep::RawUdp);
        } else if cfg.tcp_technique.finds_open_ports() {
            steps.push(PortScanStep::ConnectTcp);
            steps.push(PortScanStep::ConnectUdp);
        } else {
            refusals.push(Refusal::technique_needs_raw_sockets(cfg.tcp_technique));
            steps.push(PortScanStep::ConnectUdp);
        }

        Self {
            steps,
            refusals,
            technique: cfg.tcp_technique,
        }
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
    pub fn refusals(&self) -> &[Refusal] {
        &self.refusals
    }

    /// Takes the steps out, leaving the plan empty.
    pub fn into_steps(self) -> Vec<PortScanStep> {
        self.steps
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
/// addressed only in IPv6 resolves to no target list at all — a `/64` cannot be
/// enumerated and there is no IPv4 range to walk — so it maps to nothing, no
/// step is built for it, and the all-nodes echo that would have found its entire
/// segment is never sent. The scan reports an empty network and looks like it
/// worked.
///
/// Matching by name rather than by value: `map_ips_to_interfaces` and this both
/// read the platform's interface list, but a `NetworkInterface` compares on
/// every field, and being wrong here means scanning one link twice.
fn include_swept_link(local: &mut HashMap<NetworkInterface, IpSet>) {
    let Ok(Some(link)) = interface::get_lan_link() else {
        return;
    };

    if local.keys().any(|intf| intf.name == link.interface.name) {
        return;
    }

    info!(
        verbosity = 1,
        "Sweeping {} for IPv6 neighbours; it has no IPv4 range to walk", link.interface.name
    );
    local.insert(link.interface, IpSet::new());
}

/// Adds the addresses in this host's IPv6 neighbour table to the targets of
/// whichever interface each belongs to.
///
/// This is the only source the engine has for an IPv6 address nobody named. A
/// neighbor solicitation is the mandatory probe, and it can only be aimed at an
/// address someone already holds; the all-nodes echo produces addresses but is
/// optional to answer and draws only link-local ones, since it goes out from a
/// link-local source. The operating system's own table has been accumulating
/// both for as long as the machine has been running, at no cost in packets — on
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
fn seed_from_neighbor_table(local: &mut HashMap<NetworkInterface, IpSet>) {
    let table = neighbors::ipv6_neighbors();
    if !table.is_empty() {
        seed_from_neighbor_table_with(local, &table);
    }
}

/// [`seed_from_neighbor_table`] against an explicit table, so the exclusions can
/// be tested without a host that happens to have the right neighbours.
fn seed_from_neighbor_table_with(
    local: &mut HashMap<NetworkInterface, IpSet>,
    table: &[neighbors::Neighbor],
) {
    for (intf, targets) in local.iter_mut() {
        let mut seeded = 0usize;
        for addr in candidates_for(intf, table) {
            let IpAddr::V6(addr) = addr else { continue };
            // The zone matters for exactly the addresses that cannot be probed
            // without one, and is dropped for the rest for the reason
            // `ScopedIp` drops it: the same global address through two
            // interfaces is one address, not two.
            let zone = addr.is_unicast_link_local().then_some(intf.index);
            if let Ok(range) = Ipv6Range::scoped(addr, addr, zone) {
                targets.insert_range(IpRange::V6(range));
                seeded += 1;
            }
        }

        if seeded > 0 {
            targets.canonicalize();
            info!(
                verbosity = 1,
                "Took {seeded} IPv6 address(es) from the neighbour table as candidates on {}",
                intf.name
            );
        }
    }
}

/// The neighbour-table addresses worth probing on `intf`, in table order.
fn candidates_for(intf: &NetworkInterface, table: &[neighbors::Neighbor]) -> Vec<IpAddr> {
    let own: std::collections::HashSet<IpAddr> = intf.ips.iter().map(|net| net.ip()).collect();

    table
        .iter()
        .filter(|entry| entry.interface_index == intf.index)
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

    fn interface_with(
        index: u32,
        name: &str,
        own: Vec<IpAddr>,
    ) -> pnet::datalink::NetworkInterface {
        use pnet::ipnetwork::{IpNetwork, Ipv6Network};
        pnet::datalink::NetworkInterface {
            name: name.to_string(),
            description: String::new(),
            index,
            mac: None,
            ips: own
                .into_iter()
                .map(|ip| match ip {
                    IpAddr::V6(v6) => IpNetwork::V6(Ipv6Network::new(v6, 64).unwrap()),
                    IpAddr::V4(_) => unreachable!("test uses v6 only"),
                })
                .collect(),
            flags: 0,
        }
    }

    fn entry(ip: &str, index: u32) -> neighbors::Neighbor {
        neighbors::Neighbor {
            ip: v6(ip),
            mac: None,
            interface_index: index,
        }
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

        seed_from_neighbor_table_with(&mut local, &table);

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
        let plan = PortScanPlan::build(&ZondConfig::default(), false);

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
        let plan = PortScanPlan::build(&cfg, false);

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
    }

    /// A step and the scanner it becomes have to answer to the same name, or a
    /// failure lands in the report under one strategy and the same scanner's
    /// later failures under another.
    ///
    /// [`ScannerKind::SynPort`] is the one that matters. It is documented to
    /// mean a half-open connection attempt was made, and a plan that called
    /// every raw TCP step by that name attributed a FIN scan's socket failure
    /// to `syn_port` when no SYN was ever sent.
    #[test]
    fn a_step_reports_under_the_same_name_as_the_scanner_it_builds() {
        use crate::scanner::session::ScanSession;
        use crate::scanner::strategy::routed::TcpPortScanner;
        use crate::transport::probe::{Emission, ProbeSender, ProbeTransport, SendError};

        struct Unsendable;
        impl ProbeSender for Unsendable {
            fn send(
                &self,
                _: &[u8],
                _: IpAddr,
                _: IpAddr,
                _emission: Emission,
            ) -> Result<(), SendError> {
                Ok(())
            }
        }

        let (_session, ctx) = ScanSession::new();
        for technique in TcpScanTechnique::ALL {
            let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let scanner = TcpPortScanner::with_transport(
                interface::SourceResolver::from_interfaces(&[]),
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
            PortScanPlan::build(&cfg, false).technique(),
            TcpScanTechnique::Ack
        );
    }

    /// A plan is a value a caller may edit, and editing it changes what would
    /// run. The guard against editing it into silence is `covers`.
    #[test]
    fn dropping_a_step_is_visible_in_what_the_plan_covers() {
        let mut plan = PortScanPlan::build(&ZondConfig::default(), false);
        plan.steps_mut()
            .retain(|step| step.protocol() != Protocol::Udp);

        assert!(plan.covers(Protocol::Tcp));
        assert!(!plan.covers(Protocol::Udp));
    }
}
