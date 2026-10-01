// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Scan Reports
//!
//! The finished record of a scan: what was asked for, what came back, what went
//! wrong on the way, and under which settings.
//!
//! During a scan a caller watches [`ScanSession`](crate::scanner::session::ScanSession),
//! a live store and event stream that keep no history. A [`ScanReport`] is produced once
//! the scan is over and answers the questions asked afterwards: how long the sweep
//! took, whether a strategy failed part way, how many addresses were in scope, which
//! retry budget produced these hosts.
//!
//! "Nine hosts on a /24" means one thing after a
//! [`Thorough`](crate::config::ScanEffort::Thorough) privileged sweep and another after
//! an unprivileged connect fallback that lost its routed scanner to a permissions
//! error. Only the report tells them apart.
//!
//! ## Phases
//!
//! Discovery and port scanning are separate calls, but a caller running both describes
//! one job. A report holds a list of [`ScanPhase`] records, and [`ScanReport::merge`]
//! folds the second call into the first: hosts merge by [`Host::merge`] and phases
//! append in the order they ran.
//!
//! ## Findings and instrumentation
//!
//! Hosts and ports are findings *about the network*. The [`ProbeStats`] a raw scanner
//! files are measurements *about the scan* (probes sent, segments received, why the
//! loop stopped) that bound how far the findings can be trusted. A sweep that stopped
//! on [`StopReason::DeadlineExpired`] while replies were still arriving found fewer
//! hosts than the network holds, and the host list cannot show it.
//!
//! ## Stored and derived
//!
//! Only measurements are stored. Counts such as hosts up, open ports and services
//! identified are computed from the hosts by [`ScanReport::summary`], so they cannot
//! drift.
//!
//! Hosts are held in a [`BTreeMap`] keyed by primary IP, so two scans of the
//! same network serialize in the same order and their outputs can be diffed.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::config::DetectionEnvelope;
use crate::config::RetryConfig;
use crate::config::{IdleScan, OsDetection, ServiceDetection, ZondConfig};
use crate::evasion::EvasionProfile;
use crate::model::capture::CaptureCounts;
use crate::model::exclusion::Exclusions;
use crate::model::host::{Host, HostStatus};
use crate::model::ip::range::{IpRange, Ipv4Range, Ipv6Range};
use crate::model::ip::scoped::{ScopedIp, Zone};
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;
use crate::model::port::{PortSet, PortState, Protocol};
use crate::model::target::{TargetMap, TargetSet};
use crate::model::technique::{SctpScanTechnique, TcpScanTechnique};
use crate::system::privilege::Privilege;
use crate::transport::probe::SendMode;

/// The version of the engine that produced a report.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

// --------------------------------------------------------------------------
// What a scan was asked to do
// --------------------------------------------------------------------------
//
// The request as the report records it: range, ports, technique, patience.

/// Which of the two scan phases a [`ScanPhase`] records.
///
/// The engine's entry points ([`discover`](crate::scanner::discover),
/// [`scan`](crate::scanner::scan), and listening), not the strategies each spawns; see
/// [`ScannerKind`] for those.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScanKind {
    /// Establishing which hosts in a target range are alive.
    Discovery,
    /// Classifying the ports of a known set of hosts.
    PortScan,
    /// Reading what a link already carries, having sent nothing.
    ///
    /// Covers no address; see [`TargetScope::listening_on`]. It can raise a claim but
    /// never lower one, since silence proves nothing when nothing was sent.
    Listen,
}

impl ScanKind {
    /// Every phase kind this build knows, in declaration order.
    ///
    /// The export conformance suite checks this against the published schema.
    pub const ALL: &'static [Self] = &[Self::Discovery, Self::PortScan, Self::Listen];
}

impl fmt::Display for ScanKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanKind::Discovery => write!(f, "discovery"),
            ScanKind::PortScan => write!(f, "port scan"),
            ScanKind::Listen => write!(f, "listen"),
        }
    }
}

/// Why a port phase ran with no liveness pass in front of it.
///
/// A port scan ordinarily runs a liveness pass first, recorded as its own
/// [`Discovery`](ScanKind::Discovery) phase. A phase carrying one of these ran without
/// it. The first two probed every address on trust; the third read the probes' answers
/// as the liveness answer, since asking first would have cost as much.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LivenessSkip {
    /// The caller declined the pass, and asked for every address to be probed
    /// as a host that is there.
    AssumeUp,
    /// The scan was an [idle scan](ScanSettings::idle_scan), which forges every
    /// probe from its zombie, and a liveness pass would have been this host
    /// asking the target directly.
    IdleScan,
    /// The scan named no more ports per address than the pass would have asked. An
    /// answer on any port found a host, and an address that answered on none is in the
    /// phase's [`silent`](ScanPhase::silent) list.
    PortsNoDearer,
}

impl LivenessSkip {
    /// Every reason this build records, in declaration order. Checked against the
    /// published schema, as [`ScanKind::ALL`] is.
    pub const ALL: &'static [Self] = &[Self::AssumeUp, Self::IdleScan, Self::PortsNoDearer];
}

/// A pass a scan runs over what its probes found, named for what a stop can
/// cut short.
///
/// The passes that run after a phase's probes, each asking something the caller chose:
/// services, detections, TLS acceptance, operating system, route, filter, IP protocols.
/// A scan stopped after its probes leaves unfinished passes with nothing to say, and the
/// report names them so the ports do not read as having nothing more to tell. See
/// [`ScanPhase::passes_cut`].
///
/// In the order a scan runs them.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Pass {
    /// Identifying what is listening behind each open port.
    Services,
    /// Running the detection corpus over the services identified.
    Detections,
    /// Asking each TLS port which versions and suites it accepts.
    Tls,
    /// Asking each host what it runs, beyond what its replies already said.
    Os,
    /// Tracing the path to each host.
    Traceroute,
    /// Characterising the filter in front of each host.
    Filters,
    /// Asking each host which IP protocols its stack takes.
    IpProtocols,
}

impl Pass {
    /// Every pass this build names, in the order a scan runs them. Checked against the
    /// published schema, as [`ScanKind::ALL`] is.
    pub const ALL: &'static [Self] = &[
        Self::Services,
        Self::Detections,
        Self::Tls,
        Self::Os,
        Self::Traceroute,
        Self::Filters,
        Self::IpProtocols,
    ];
}

impl fmt::Display for Pass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Pass::Services => "service detection",
            Pass::Detections => "detections",
            Pass::Tls => "TLS enumeration",
            Pass::Os => "OS detection",
            Pass::Traceroute => "traceroute",
            Pass::Filters => "filter characterisation",
            Pass::IpProtocols => "IP protocol scan",
        })
    }
}

/// Which ports a phase walked, and whether it walked the same ones everywhere.
///
/// A scope records the addresses a phase covered; for a port scan, an address is
/// covered *for some ports*, and this says which.
///
/// [`Every`](Self::Every) against [`Mixed`](Self::Mixed): `192.0.2.0/24:80,443`
/// alongside `198.51.100.0/24:8080` has no single set true of every address, so the
/// union is labelled as one, and a consumer will not conclude `192.0.2.5` was probed
/// on 8080.
///
/// [`NoPorts`](Self::NoPorts) against [`Unstated`](Self::Unstated): a discovery sweep
/// walked no ports, which is a fact; a record that does not say is an absence of one.
/// This engine never builds `Unstated`; reports from other tools, or records without
/// the field, read back as it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PortScope {
    /// The record does not say which ports were walked.
    ///
    /// Nothing may be concluded about any endpoint. The default, for a record that does
    /// not carry this field.
    #[default]
    Unstated,
    /// The phase paired no ports with its addresses, which is what a discovery
    /// sweep does. Its probes are the strategy's choice rather than the
    /// caller's, and no endpoint was probed.
    NoPorts,
    /// Every address the phase walked was walked for these ports.
    ///
    /// The ordinary case for a port scan, and the only variant from which a consumer
    /// may conclude that an endpoint of a covered address was probed.
    Every(PortSet),
    /// Addresses were walked for differing sets of ports, and this is their
    /// union.
    ///
    /// A port here was walked for at least one address, not necessarily any given one.
    /// A port *not* here was walked for none.
    Mixed(PortSet),
}

impl PortScope {
    /// The ports the phase walked, over all of its addresses.
    ///
    /// `None` where there are none to report or none recorded. Read this to
    /// describe what a scan reached; read [`covers`](Self::covers) to ask about
    /// one endpoint.
    pub fn ports(&self) -> Option<&PortSet> {
        match self {
            PortScope::Unstated | PortScope::NoPorts => None,
            PortScope::Every(ports) | PortScope::Mixed(ports) => Some(ports),
        }
    }

    /// Whether the phase walked `port` on `protocol`, for every address it
    /// covered.
    ///
    /// `None` means the record cannot say (no ports recorded, or a mixed scope including
    /// this port). `Some(false)` is a real negative.
    pub fn covers(&self, port: u16, protocol: Protocol) -> Option<bool> {
        match self {
            PortScope::Unstated => None,
            PortScope::NoPorts => Some(false),
            PortScope::Every(ports) => Some(ports.contains(port, protocol)),
            PortScope::Mixed(ports) => {
                if ports.contains(port, protocol) {
                    None
                } else {
                    Some(false)
                }
            }
        }
    }

    /// The scope of a set of units, which is [`Every`](Self::Every) when they
    /// agree and [`Mixed`](Self::Mixed) when they do not.
    fn of<'a>(units: impl Iterator<Item = &'a PortSet>) -> Self {
        let mut units = units;
        let Some(first) = units.next().cloned() else {
            return PortScope::NoPorts;
        };

        let mut united = first.clone();
        let mut agreed = true;
        for ports in units {
            agreed &= *ports == first;
            united = united.union(ports);
        }

        if united.is_empty() {
            PortScope::NoPorts
        } else if agreed {
            PortScope::Every(united)
        } else {
            PortScope::Mixed(united)
        }
    }
}

/// What a phase was asked to cover, and what it was forbidden to.
///
/// The ranges are the merged form the engine iterated, so `addresses` counts distinct
/// addresses and a report saying a sweep covered 254 hosts can be trusted.
///
/// [`ranges`](Self::ranges) is what was walked after the exclusion policy, and
/// [`excluded`](Self::excluded) is the policy. Together they make the report evidence
/// of scope: no host in it may fall inside the excluded ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetScope {
    ranges: Vec<IpRange>,
    links: Vec<Zone>,
    /// Links whose traffic was read without anything being sent to them.
    ///
    /// Separate from [`links`](Self::links), which means *swept*: everything on the link
    /// had to answer, so a missing host was not there. A machine that said nothing while
    /// a listener ran may still be there.
    ///
    /// Recorded to show where the phase stood; never counted as coverage.
    listened: Vec<Zone>,
    addresses: u128,
    probes: Option<u128>,
    ports: PortScope,
    protocols: Vec<Protocol>,
    excluded: Vec<IpRange>,
    withheld: u128,
}

impl TargetScope {
    /// The scope of a discovery sweep, which has no port dimension.
    ///
    /// Canonicalizes the set, so the recorded ranges are the merged ones the sweep
    /// iterates.
    ///
    /// `ips` comes back with everything `exclusions` forbids removed, and the scope
    /// records what that cost. Applying and recording are one call (hence `&mut`) so
    /// neither can happen without the other.
    ///
    /// Pass [`Exclusions::none`] where no policy is in force.
    pub fn from_ip_set(ips: &mut IpSet, exclusions: &Exclusions) -> Self {
        let withheld = exclusions.withhold(ips);
        ips.canonicalize();

        let ranges = ip_set_ranges(ips);
        let addresses = ips.len();

        Self {
            listened: Vec::new(),
            ranges,
            links: Vec::new(),
            addresses,
            probes: None,
            ports: PortScope::NoPorts,
            protocols: Vec::new(),
            excluded: exclusions.ranges(),
            withheld,
        }
    }

    /// The scope of a phase that sent nothing and read what `links` carried.
    ///
    /// Covers no address: a listener sent nothing, so it can report no address as empty,
    /// and a comparison will not read a quiet host as one that disappeared. The links
    /// are recorded as [`listened`](Self::listened), not [`links`](Self::links).
    ///
    /// `exclusions` is recorded to show the policy; it is enforced where findings are
    /// recorded.
    pub fn listening_on(links: Vec<Zone>, exclusions: &Exclusions) -> Self {
        Self {
            ranges: Vec::new(),
            links: Vec::new(),
            listened: links,
            addresses: 0,
            probes: None,
            ports: PortScope::NoPorts,
            protocols: Vec::new(),
            excluded: exclusions.ranges(),
            withheld: 0,
        }
    }

    /// The scope of a port scan, which pairs addresses with ports.
    ///
    /// `probes` counts address, port and protocol combinations, or is `None` when the
    /// count overflows.
    ///
    /// `targets` comes back narrowed, as in [`from_ip_set`](Self::from_ip_set); a unit
    /// left with no address is dropped.
    pub fn from_target_map(targets: &mut TargetMap, exclusions: &Exclusions) -> Self {
        let withheld = exclusions.withhold_targets(targets);

        let mut ranges = Vec::new();
        let mut protocols = Vec::new();
        for unit in &targets.units {
            ranges.extend(ip_set_ranges(unit.ips()));
            for (_, protocol) in unit.ports().iter() {
                if !protocols.contains(&protocol) {
                    protocols.push(protocol);
                }
            }
        }
        ranges.sort_by_key(|range| (range.start_addr(), range.end_addr()));
        ranges.dedup();
        protocols.sort();

        let addresses = targets.gross_ips().unwrap_or(0);
        let probes = targets.gross_targets().ok();
        let ports = PortScope::of(targets.units.iter().map(TargetSet::ports));

        Self {
            listened: Vec::new(),
            ranges,
            links: Vec::new(),
            addresses,
            probes,
            ports,
            protocols,
            excluded: exclusions.ranges(),
            withheld,
        }
    }

    /// The address ranges covered, in ascending order.
    pub fn ranges(&self) -> &[IpRange] {
        &self.ranges
    }

    /// How many distinct addresses were in scope.
    pub fn addresses(&self) -> u128 {
        self.addresses
    }

    /// How many address/port/protocol combinations were in scope, or `None` for
    /// a discovery sweep and for a target set too large to count.
    pub fn probes(&self) -> Option<u128> {
        self.probes
    }

    /// The links this phase swept whole, by the interface each is on.
    ///
    /// A sweep of a local segment covers more than [`ranges`](Self::ranges): every IPv6
    /// neighbour must answer an all-nodes solicitation, including hosts nobody could
    /// name in advance.
    ///
    /// Recorded by interface, since `fe80::/64` in `ranges` would make
    /// [`addresses`](Self::addresses) read eighteen quintillion.
    ///
    /// Empty for every port scan and every sweep of a routed range.
    pub fn links(&self) -> &[Zone] {
        &self.links
    }

    /// The links this phase read traffic from without probing them.
    ///
    /// Never coverage. See [`listening_on`](Self::listening_on).
    pub fn listened(&self) -> &[Zone] {
        &self.listened
    }

    /// Whether this phase swept the link a host was found on.
    ///
    /// Asked of the link, not the address: a host answering an all-nodes solicitation is
    /// often keyed under a global address.
    ///
    /// `zone` is the interface the host was found on. A host with no zone was not found
    /// on a link and is not claimed.
    pub fn swept(&self, zone: Option<&Zone>) -> bool {
        let Some(zone) = zone else {
            return false;
        };

        self.links.iter().any(|link| link.name() == zone.name())
    }

    /// Records that this phase swept a link whole.
    ///
    /// Called once a phase is over, since which links were reached is only known then.
    /// See [`PhaseRecorder::finish`](crate::scanner::recorder::PhaseRecorder::finish).
    pub(crate) fn record_sweeps(&mut self, links: Vec<Zone>) {
        for link in links {
            if !self.links.iter().any(|held| held.name() == link.name()) {
                self.links.push(link);
            }
        }
    }

    /// Records what this phase's policy withheld beyond the targets it was
    /// handed: `machines`, the other addresses of a machine it names, which
    /// the neighbour tables tied to it or which answered from its hardware
    /// during the phase; and `neighbours`, the neighbour-table addresses it
    /// kept from a sweep that would have taken them as candidates. See
    /// [`Exclusions::hardware_in`](crate::model::exclusion::Exclusions::hardware_in).
    ///
    /// Called once a phase is over, like [`record_sweeps`](Self::record_sweeps). Both
    /// join [`excluded`](Self::excluded). [`withheld`](Self::withheld) gains each
    /// address not already counted: every neighbour kept from the sweep, and every
    /// address heard from an excluded machine's hardware during the phase. Addresses
    /// tied before the phase began were counted with the targets.
    pub(crate) fn record_withheld(&mut self, machines: Vec<IpAddr>, neighbours: Vec<IpAddr>) {
        let mut excluded = IpSet::new();
        for range in self.excluded.drain(..) {
            excluded.insert_range(range);
        }
        excluded.canonicalize();
        let mut beyond: std::collections::BTreeSet<IpAddr> = neighbours.iter().copied().collect();
        beyond.extend(
            machines
                .iter()
                .copied()
                .filter(|address| !excluded.contains(address)),
        );
        self.withheld += beyond.len() as u128;
        for address in machines.into_iter().chain(neighbours) {
            excluded.insert(address);
        }
        excluded.canonicalize();
        self.excluded = ip_set_ranges(&excluded);
    }

    /// Which ports the phase walked, and whether it walked the same ones for
    /// every address.
    ///
    /// [`probes`](Self::probes) counts the combinations; this says which ports they
    /// were.
    pub fn ports(&self) -> &PortScope {
        &self.ports
    }

    /// The transport protocols the phase was asked about, deduplicated and in
    /// ascending [`Protocol`] order, which puts TCP before UDP.
    ///
    /// Empty for a discovery sweep, whose probes the strategy chooses.
    pub fn protocols(&self) -> &[Protocol] {
        &self.protocols
    }

    /// The address ranges the phase was forbidden to probe, in ascending order.
    ///
    /// The exclusion policy in force, merged. Empty means no policy was set; a policy
    /// that withheld nothing shows as [`withheld`](Self::withheld) returning zero.
    ///
    /// No host in the report may fall inside these ranges, which a reader can check.
    ///
    /// Also holds other addresses of an excluded machine heard during the phase; see
    /// [the machine an address names](crate::model::exclusion#an-address-names-a-machine).
    pub fn excluded(&self) -> &[IpRange] {
        &self.excluded
    }

    /// How many addresses the exclusion policy took out of this phase.
    ///
    /// The overlap between the policy and what this phase would have asked: targets the
    /// policy names or ties to an excluded machine, neighbour-table candidates it kept
    /// from a sweep, and addresses heard from an excluded machine's hardware. Each is
    /// among the excluded or the targets, so the count and the list agree. Zero for a
    /// policy naming ground the phase would never walk, or for input an earlier phase
    /// already narrowed.
    ///
    /// Tells a policy that was applied from one merely configured.
    pub fn withheld(&self) -> u128 {
        self.withheld
    }
}

/// Returns every range of a set as protocol-agnostic [`IpRange`] values.
fn ip_set_ranges(ips: &IpSet) -> Vec<IpRange> {
    let v4 = ips.v4().iter().copied().map(IpRange::V4);
    let v6 = ips.v6().iter().copied().map(IpRange::V6);
    v4.chain(v6).collect()
}

/// What a scan changed about the packets it sent, to read a finding against.
///
/// Each field holds the value the scan used for one evasion technique, or `None` where
/// it kept the default. A port's state under a probe from source port 53 is a different
/// fact from the same state under an ordinary probe.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvasionRecord {
    /// The source port every probe left from, or `None` if the scan did not pin
    /// one.
    pub source_port: Option<u16>,
    /// The hop limit (IPv4 TTL / IPv6 hop limit) every ordinary probe carried,
    /// or `None` if the scan kept the default.
    pub ttl: Option<u8>,
    /// The number of random bytes appended to each probe's payload, or `None` if
    /// the scan padded nothing.
    pub padding: Option<u16>,
    /// Whether TCP probes carried a deliberately wrong checksum.
    pub bad_tcp_checksum: bool,
    /// The hardware address every frame claimed to come from, or `None` if the
    /// scan used the interface's own.
    pub spoof_mac: Option<MacAddr>,
    /// The largest each IP fragment a probe was split into, in bytes, or `None`
    /// if the scan sent probes whole.
    pub fragment: Option<u16>,
    /// The addresses probes were also sent from as decoys, or empty if the scan
    /// sent from this host alone.
    pub decoys: Vec<IpAddr>,
    /// The exact TCP flag byte every port probe carried in place of the
    /// technique's own, or `None` if the scan sent the technique's. The bits are
    /// those of [`crate::protocols::tcp::flags`].
    pub flags: Option<u8>,
}

impl EvasionRecord {
    /// The record of what an [`EvasionProfile`] changed, or `None` if it changed
    /// nothing.
    #[must_use]
    pub fn from_profile(profile: &EvasionProfile) -> Option<Self> {
        profile.is_active().then(|| Self {
            source_port: profile.source_port,
            ttl: profile.ttl,
            padding: profile.padding,
            bad_tcp_checksum: profile.bad_tcp_checksum,
            spoof_mac: profile.spoof_mac,
            fragment: profile.fragment,
            decoys: profile.decoys.clone(),
            flags: profile.flags,
        })
    }
}

/// The settings that shaped what a phase did.
///
/// The [`ZondConfig`] fields that change which packets went out and how long the engine
/// waited, which are what is needed to interpret or reproduce a result. A separate type,
/// so a new config field does not silently join every exported report.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct ScanSettings {
    /// How raw probes were placed on the wire.
    pub send_mode: SendMode,
    /// Which segment each TCP port probe carried, and so what its answers mean.
    ///
    /// Two `Closed` ports differ by this: one refused a connection attempt, the other
    /// reset a segment that was not one.
    pub tcp_technique: TcpScanTechnique,
    /// Which chunk each SCTP port probe carried, and so what its answers mean.
    ///
    /// An `OpenOrNoReply` SCTP port came from a COOKIE-ECHO scan, which cannot report
    /// open; an INIT scan would have settled it.
    pub sctp_technique: SctpScanTechnique,
    /// The retransmission budget and patience in force.
    pub retry: RetryConfig,
    /// The probe-rate ceiling, or `None` if the scanner's own default applied.
    pub max_probe_rate: Option<std::num::NonZeroU32>,
    /// The probe-rate floor, or `None` if the scan was free to settle wherever
    /// it liked.
    ///
    /// A scan that emitted more than its targets answered may have been told to finish;
    /// compare floors before concluding a network got noisier.
    pub min_probe_rate: Option<std::num::NonZeroU32>,
    /// The shortest gap kept between two probes at one host, or `None` if none
    /// was asked for.
    ///
    /// Bounds how long a phase took: a thousand addresses a tenth of a second apart take
    /// at least a hundred seconds.
    pub host_probe_interval: Option<Duration>,
    /// The shortest gap kept between any two probes the scan sent, or `None`
    /// if none was asked for.
    ///
    /// Like [`host_probe_interval`](Self::host_probe_interval): a thousand ports a second
    /// apart take at least a quarter of an hour.
    pub probe_interval: Option<Duration>,
    /// The wall-clock budget each host was given, or `None` if none was set.
    ///
    /// Bounds what a host's entry can say; which hosts ran out is
    /// [`ScanPhase::timed_out`].
    pub host_timeout: Option<Duration>,
    /// The wall-clock budget the whole phase was given, or `None` if none was
    /// set.
    ///
    /// Like [`host_timeout`](Self::host_timeout), one level up: a phase stopped by it
    /// covered less than asked.
    pub scan_timeout: Option<Duration>,
    /// Whether name resolution was permitted to generate traffic.
    pub dns_enabled: bool,
    /// Whether the caller asked for identifying detail to be masked.
    pub redact: bool,
    /// How far the phase went to identify the operating system behind each host.
    ///
    /// At [`OsDetection::Off`] nothing looked; at other levels something looked and
    /// found nothing conclusive. Also bounds the traffic the engine originated; see
    /// [`OsDetection::is_active`].
    pub os_detection: OsDetection,
    /// How far the phase went to identify what was listening behind each open
    /// port.
    ///
    /// At [`ServiceDetection::Off`] nothing asked; at other levels something asked and
    /// could not tell. Also says whether connections were completed, which a target's
    /// application logs would record.
    pub service_detection: ServiceDetection,

    /// How intrusive a detection the phase was permitted to run over the services
    /// it identified.
    ///
    /// Decides which findings could appear, so a clean port can be read as probed or
    /// spared.
    pub detection: DetectionEnvelope,

    /// Whether the phase measured the route to each host that answered.
    ///
    /// Tells a host with no path because nobody looked from one where nothing came back.
    pub traceroute: bool,

    /// Whether the phase characterised the filter in front of each host that
    /// answered.
    ///
    /// As with [`traceroute`](Self::traceroute), tells not looking from finding nothing.
    pub characterise: bool,

    /// Which IP protocols the phase asked each host that answered about,
    /// ascending.
    ///
    /// Per protocol, so a host with no verdict for 47 can be read as never asked.
    pub ip_protocols: Vec<u8>,

    /// Whether the phase established what each TLS port accepts.
    ///
    /// Tells a port that was never enumerated from one that refused every offer.
    pub tls_enumeration: bool,

    /// The TCP ports the phase connected to and listened on and sent nothing,
    /// ascending.
    ///
    /// An open port here with only its number's name was left unprobed on purpose. See
    /// [`ZondConfig::listen_only_ports`] and [`listened_only_to`](Self::listened_only_to).
    pub listen_only_ports: Vec<u16>,

    /// The ports the phase sent nothing to on any target, empty where none
    /// were excluded.
    ///
    /// Recorded as the policy, since the scope cannot tell a port never named from one
    /// excluded, and it also covers ports a phase picked itself. See
    /// [`ZondConfig::excluded_ports`].
    pub excluded_ports: PortSet,

    /// What the scan changed about the packets it sent, or `None` if nothing; see
    /// [`EvasionRecord`].
    pub evasion: Option<EvasionRecord>,

    /// The zombie a TCP port scan read its verdicts through, or `None`. Its presence
    /// means the ports were inferred from a third party's counter. See [`IdleScan`].
    pub idle_scan: Option<IdleScan>,

    /// Whether the capture kept ICMP errors for a technique that did not need
    /// them for its verdict.
    ///
    /// Without it, a [`NoReply`](crate::model::port::PortState::NoReply) port may be one
    /// a filter refused; with it, that port would read
    /// [`Blocked`](crate::model::port::PortState::Blocked).
    pub icmp_evidence: bool,
}

impl ScanSettings {
    /// Whether the phase only listened on `number` over `protocol`, sending it
    /// nothing, so that what the port reports is what it volunteered and no
    /// more.
    ///
    /// ```
    /// use zond_engine::ZondConfig;
    /// use zond_engine::model::port::Protocol;
    /// use zond_engine::report::ScanSettings;
    ///
    /// let settings = ScanSettings::from(&ZondConfig::default());
    /// assert!(settings.listened_only_to(9100, Protocol::Tcp));
    /// assert!(!settings.listened_only_to(9100, Protocol::Udp));
    /// assert!(!settings.listened_only_to(80, Protocol::Tcp));
    /// ```
    #[must_use]
    pub fn listened_only_to(&self, number: u16, protocol: Protocol) -> bool {
        protocol == Protocol::Tcp && self.listen_only_ports.contains(&number)
    }
}

impl From<&ZondConfig> for ScanSettings {
    /// What a phase records about the request behind it.
    ///
    /// Destructured with every field named, as for
    /// [`ProbeTuning`](crate::config::ProbeTuning), so a new [`ZondConfig`] field fails
    /// to compile here until it is handled.
    fn from(cfg: &ZondConfig) -> Self {
        let ZondConfig {
            send_mode,
            tcp_technique,
            sctp_technique,
            retry,
            max_probe_rate,
            min_probe_rate,
            host_probe_interval,
            probe_interval,
            host_timeout,
            scan_timeout,
            no_dns,
            redact,
            os_detection,
            service_detection,
            detection,
            traceroute,
            characterise,
            ip_protocols,
            tls_enumeration,
            listen_only_ports,
            excluded_ports,
            evasion,
            idle_scan,
            icmp_evidence,

            // Recorded elsewhere. The exclusion policy and segment sweep are
            // coverage, `TargetScope`'s to say; `assume_up` shows as a missing
            // discovery phase.
            exclusions: _,
            segment_sweep: _,
            assume_up: _,
            // The hosts' names record it; the journal keeps it with the options.
            target_names: _,

            // Not recorded: transport plumbing naming host-specific addresses.
            send_source: _,
        } = cfg;

        Self {
            send_mode: *send_mode,
            tcp_technique: *tcp_technique,
            sctp_technique: *sctp_technique,
            retry: *retry,
            max_probe_rate: *max_probe_rate,
            min_probe_rate: *min_probe_rate,
            host_probe_interval: *host_probe_interval,
            probe_interval: *probe_interval,
            host_timeout: *host_timeout,
            scan_timeout: *scan_timeout,
            dns_enabled: !no_dns,
            redact: *redact,
            os_detection: *os_detection,
            service_detection: *service_detection,
            detection: *detection,
            traceroute: *traceroute,
            characterise: *characterise,
            ip_protocols: ip_protocols.iter().copied().collect(),
            tls_enumeration: *tls_enumeration,
            listen_only_ports: listen_only_ports.iter().copied().collect(),
            excluded_ports: excluded_ports.clone(),
            evasion: EvasionRecord::from_profile(evasion),
            idle_scan: *idle_scan,
            icmp_evidence: *icmp_evidence,
        }
    }
}

// --------------------------------------------------------------------------
// What a scan measured about itself
// --------------------------------------------------------------------------
//
// Instrumentation, not findings: these bound how far the host list can be trusted.

/// Upper bounds, in milliseconds, of the discovery-time histogram buckets in
/// [`ProbeStats::found_at`]. A final bucket catches everything later than the
/// last bound.
///
/// These measure how far into the run a host was first credited, **not** its round
/// trip: a host found at 700 ms because its third attempt went out at 690 ms has a
/// 10 ms round trip. Round trips are reported per host.
///
/// Roughly logarithmic, spanning a same-segment reply under a millisecond, an internet
/// round trip in the tens, and a late retry in the hundreds.
pub const BUCKET_BOUNDS_MS: &[u64] = &[1, 2, 5, 10, 25, 50, 100, 250, 1_000];

/// How many attempts [`ProbeStats::answered_on`] counts separately before the
/// rest are lumped together.
///
/// Above the largest budget any path runs (five, under
/// [`ScanEffort::Thorough`](crate::config::ScanEffort)), so a hand-raised budget still
/// has somewhere to land.
pub const ATTEMPTS_COUNTED: usize = 6;

/// Why a scanner's receive loop stopped.
///
/// The most informative field in an audit: a run ending in
/// [`AllResponded`](StopReason::AllResponded) was not cut short, and one ending in
/// [`DeadlineExpired`](StopReason::DeadlineExpired) with replies still arriving almost
/// certainly was.
///
/// A scan loop breaks with its reason, so every exit path names one.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StopReason {
    /// The caller aborted the scan through the scan handle.
    Aborted,
    /// Every target answered.
    AllResponded,
    /// Every target either answered or was asked as often as the retry budget allows.
    /// Like [`AllResponded`](StopReason::AllResponded), the scan finished.
    AttemptsSpent,
    /// The adaptive deadline expired: either the hard budget ran out or the
    /// silence tolerance did.
    DeadlineExpired,
    /// The capture stream closed underneath the scanner.
    StreamClosed,
    /// The wall-clock budget the caller set on the whole scan ran out, and
    /// every strategy wound down where it stood. See
    /// [`ZondConfig::scan_timeout`](crate::config::ZondConfig::scan_timeout).
    ///
    /// Unlike [`Aborted`](StopReason::Aborted), nobody stopped it: the scan was given
    /// less time than the network needed. Unlike
    /// [`DeadlineExpired`](StopReason::DeadlineExpired), which is one receive loop's
    /// own pacing, this is about the whole run.
    TimedOut,
}

impl StopReason {
    /// Every reason a receive loop stops, in declaration order. Checked against the
    /// published schema.
    pub const ALL: &'static [Self] = &[
        Self::Aborted,
        Self::AllResponded,
        Self::AttemptsSpent,
        Self::DeadlineExpired,
        Self::StreamClosed,
        Self::TimedOut,
    ];

    /// Whether the loop stopped because it had nothing left to do, rather than
    /// because something cut it short.
    ///
    /// A complete run found everything it was going to; waiting longer could not have
    /// changed it.
    pub fn is_complete(&self) -> bool {
        matches!(self, StopReason::AllResponded | StopReason::AttemptsSpent)
    }
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            StopReason::Aborted => "aborted by the caller",
            StopReason::AllResponded => "every target answered",
            StopReason::AttemptsSpent => "attempts spent",
            StopReason::DeadlineExpired => "deadline expired",
            StopReason::StreamClosed => "capture stream closed",
            StopReason::TimedOut => "scan budget spent",
        };
        f.write_str(text)
    }
}

/// `sends` over `elapsed`, per second, or `None` where no time passed.
///
/// Shared by [`achieved_send_rate`](ProbeStats::achieved_send_rate) and a scanner's
/// audit line, so they agree.
pub(crate) fn send_rate(sends: u64, elapsed: Duration) -> Option<f64> {
    let seconds = elapsed.as_secs_f64();
    (seconds > 0.0).then(|| sends as f64 / seconds)
}

/// What one raw scanner observed about its own run.
///
/// A short sweep has three possible causes with different fixes: probes or replies
/// were lost (retransmission's job); replies arrived after the scan **stopped** (the
/// deadline is wrong); or replies arrived and went **unrecognized** (more time or
/// packets will not help).
///
/// These counters separate them. [`sends_attempted`](Self::sends_attempted)
/// against [`segments_seen`](Self::segments_seen) bounds the first,
/// [`stop_reason`](Self::stop_reason) against
/// [`last_reply`](Self::last_reply) bounds the second, and
/// [`segments_off_target`](Self::segments_off_target) with
/// [`replies_without_rtt`](Self::replies_without_rtt) bounds the third.
///
/// A reply the kernel discards because the capture buffer was full reaches no counter
/// here, so [`capture`](Self::capture) is carried to tell receive-path loss from
/// network loss.
///
/// Instrumentation about the scan; nothing here changes what is reported about a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeStats {
    // `pub(crate)` for `ProbeAudit` in another module; consumers read through the
    // accessors and cannot edit a measurement.
    pub(crate) scanner: ScannerKind,
    pub(crate) targets: u128,
    pub(crate) stop_reason: StopReason,
    pub(crate) elapsed: Duration,
    pub(crate) sends_attempted: u64,
    pub(crate) sends_failed: u64,
    pub(crate) sends_witnessed: u64,
    pub(crate) segments_seen: u64,
    pub(crate) segments_off_target: u64,
    pub(crate) replies_without_rtt: u64,
    pub(crate) refusals_unattributed: u64,
    pub(crate) hosts_found: u64,
    pub(crate) answered_on: [u64; ATTEMPTS_COUNTED],
    pub(crate) answered_unattributed: u64,
    pub(crate) first_reply: Option<Duration>,
    pub(crate) last_reply: Option<Duration>,
    pub(crate) found_at: [u64; BUCKET_BOUNDS_MS.len() + 1],
    pub(crate) capture: Option<CaptureCounts>,
    pub(crate) window: Option<WindowSummary>,
}

impl ProbeStats {
    /// The strategy these counters belong to.
    pub fn scanner(&self) -> ScannerKind {
        self.scanner
    }

    /// How many targets this scanner owned: addresses for a discovery sweep,
    /// `(address, port)` probes for a port scan.
    pub fn targets(&self) -> u128 {
        self.targets
    }

    /// Why the receive loop stopped.
    pub fn stop_reason(&self) -> StopReason {
        self.stop_reason
    }

    /// How long the scanner ran.
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Probes the scanner tried to put on the wire.
    pub fn sends_attempted(&self) -> u64 {
        self.sends_attempted
    }

    /// Probes per second the scanner put on the wire over its whole run:
    /// [`sends_attempted`](Self::sends_attempted) over
    /// [`elapsed`](Self::elapsed). `None` for a run with no time to divide by.
    ///
    /// Compare with the configured rate. The send timer never makes up a missed tick,
    /// since catching up would be a burst, so a busy run sends slower than asked.
    pub fn achieved_send_rate(&self) -> Option<f64> {
        send_rate(self.sends_attempted, self.elapsed)
    }

    /// Of those, ones that never left this host: the sender refused them or could not
    /// reach their address. Unreachable addresses are in the phase's
    /// [`unroutable`](ScanPhase::unroutable) list.
    pub fn sends_failed(&self) -> u64 {
        self.sends_failed
    }

    /// How many probes were watched leaving on the wire. Read against
    /// [`sends_attempted`](Self::sends_attempted), and only when non-zero: the
    /// gap is probes the OS took and dropped. Zero means no egress capture.
    pub fn sends_witnessed(&self) -> u64 {
        self.sends_witnessed
    }

    /// Segments the capture handed up, before any of the scanner's own checks.
    pub fn segments_seen(&self) -> u64 {
        self.segments_seen
    }

    /// What this run's congestion window did, for a scanner paced by one.
    ///
    /// Tells "these ports drop probes" from "this scan was outrun". A run whose window
    /// bottomed out with most probes unanswered could not ask, which says nothing about
    /// a firewall.
    ///
    /// `None` for a scanner that paces itself some other way.
    pub fn window(&self) -> Option<WindowSummary> {
        self.window
    }

    /// Segments from an address outside this scan's target set. Expected to be
    /// small; a large count means the capture filter is admitting other traffic.
    pub fn segments_off_target(&self) -> u64 {
        self.segments_off_target
    }

    /// In-set replies that answered no outstanding probe, so they proved a host
    /// alive but yielded no round-trip sample. Duplicates land here, and so does
    /// a correlation bug.
    pub fn replies_without_rtt(&self) -> u64 {
        self.replies_without_rtt
    }

    /// ICMP refusals among [`replies_without_rtt`](Self::replies_without_rtt)
    /// that quoted too little of the probe to name its attempt.
    ///
    /// Anyone who knows the source port can forge a refusal naming the ports, so one
    /// that cannot name the attempt settles nothing, and the port keeps what its retries
    /// conclude. This counts them. A sender quoting only the eight bytes RFC 792
    /// guarantees omits an ACK, window or Maimon scan's nonce, and every INIT's.
    pub fn refusals_unattributed(&self) -> u64 {
        self.refusals_unattributed
    }

    /// Targets a reply resolved, counted once each.
    ///
    /// In the unit of [`targets`](Self::targets): a host for a discovery sweep, an
    /// `(address, port)` probe for a port scan.
    ///
    /// Against `targets` it is coverage; against [`stop_reason`](Self::stop_reason) and
    /// [`last_reply`](Self::last_reply) it says whether the run was still finding things
    /// when it ended.
    pub fn hosts_found(&self) -> u64 {
        self.hosts_found
    }

    /// Found hosts by the attempt whose reply revealed them.
    ///
    /// Index `i` counts hosts answered on attempt `i + 1`; the last slot counts
    /// attempt [`ATTEMPTS_COUNTED`] *or later*, so a hand-raised retry budget
    /// still has somewhere to land.
    ///
    /// Shows whether retransmission earns its traffic.
    pub fn answered_on(&self) -> &[u64] {
        &self.answered_on
    }

    /// Found hosts whose reply named no attempt: it arrived after the probe had
    /// been written off, or carried nothing to match against.
    pub fn answered_unattributed(&self) -> u64 {
        self.answered_unattributed
    }

    /// How far into the run the first host was credited.
    pub fn first_reply(&self) -> Option<Duration> {
        self.first_reply
    }

    /// How far into the run the last host was credited. Close to
    /// [`elapsed`](Self::elapsed) on a run that stopped for
    /// [`DeadlineExpired`](StopReason::DeadlineExpired) means the scan was still
    /// finding hosts when it ran out of time.
    pub fn last_reply(&self) -> Option<Duration> {
        self.last_reply
    }

    /// Hosts by how far into the run they were credited, bucketed by
    /// [`BUCKET_BOUNDS_MS`]. Index `i` counts hosts found at or under
    /// `BUCKET_BOUNDS_MS[i]` milliseconds; the final slot counts everything
    /// later than the last bound.
    pub fn found_at(&self) -> &[u64] {
        &self.found_at
    }

    /// What the kernel capture reported. `None` for a synthetic receive stream.
    pub fn capture(&self) -> Option<CaptureCounts> {
        self.capture
    }
}

// --------------------------------------------------------------------------
// What a scan did not cover
// --------------------------------------------------------------------------
//
// A strategy that could not run is a `ScannerFailure`; ground the engine declined
// before sending anything is a `Refusal`. Both narrow a result; only one is a fault.

/// Ground a scan decided not to cover, and why.
///
/// Nothing broke: before sending anything, the engine found part of the request had no
/// strategy behind it. A raw socket that would not open is a [`ScannerFailure`]; an
/// SCTP port named by a scan with no way to probe one is this. A failure might clear
/// next time; a refusal will recur until the scan changes.
///
/// The recorded form of [`RefusedStep`](crate::scanner::plan::RefusedStep), as
/// [`ScannerFailure`] is of [`StrategyError`](crate::scanner::strategy::StrategyError).
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    scanner: ScannerKind,
    reason: String,
}

impl Refusal {
    /// Records that `scanner`'s work was declined, for `reason`.
    pub fn new(scanner: ScannerKind, reason: impl Into<String>) -> Self {
        Self {
            scanner,
            reason: reason.into(),
        }
    }

    /// The strategy that would have taken this work.
    pub fn scanner(&self) -> ScannerKind {
        self.scanner
    }

    /// What was not done, and what the caller could ask for instead.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// A scanning strategy that did not run to completion.
///
/// A scan continues with the remaining strategies when one fails, so a report with
/// failures still has narrower results. This tells an empty network from a sweep whose
/// raw scanner never started.
///
/// [`is_cut_short`](Self::is_cut_short) tells two kinds apart. A failure met a fault
/// (a socket that would not open, a capture that closed, a panic). A cut-short strategy
/// stopped against a limit (a budget, the file limit, a pinned source port in use).
/// Both leave ground unanswered, so [`ScanReport::is_partial`] counts both, but the
/// remedies differ.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerFailure {
    scanner: ScannerKind,
    reason: String,
    at: SystemTime,
    cut_short: bool,
}

impl ScannerFailure {
    /// Records a failure as having happened now.
    pub fn new(scanner: ScannerKind, reason: impl Into<String>) -> Self {
        Self {
            scanner,
            reason: reason.into(),
            at: SystemTime::now(),
            cut_short: false,
        }
    }

    /// Records, as having happened now, work `scanner` stopped short of because a limit
    /// was reached. `reason` names the limit.
    pub fn cut_short(scanner: ScannerKind, reason: impl Into<String>) -> Self {
        Self {
            cut_short: true,
            ..Self::new(scanner, reason)
        }
    }

    /// Whether this is work a limit cut short rather than a fault stopped.
    ///
    /// False for a record from a document without the distinction, which reads every
    /// entry as a failure.
    pub fn is_cut_short(&self) -> bool {
        self.cut_short
    }

    /// The strategy that failed.
    pub fn scanner(&self) -> ScannerKind {
        self.scanner
    }

    /// A human-readable description of the failure.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Restores the time this failure was recorded.
    ///
    /// For a failure restored from a journal; [`new`](Self::new) stamps the current
    /// time.
    pub fn recorded_at(mut self, at: SystemTime) -> Self {
        self.at = at;
        self
    }

    /// When the failure was observed.
    pub fn at(&self) -> SystemTime {
        self.at
    }

    /// Whether the failure cost the scan ground it set out to cover.
    ///
    /// Every strategy's does. A [`Journal`](ScannerKind::Journal) that could not be
    /// written did not: it probed nothing and costs only what a resume would ask again.
    /// Nor does a failed [`Resolver`](ScannerKind::Resolver), which costs only names.
    pub(crate) fn narrows_coverage(&self) -> bool {
        !matches!(self.scanner, ScannerKind::Journal | ScannerKind::Resolver)
    }
}

impl fmt::Display for ScannerFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outcome = if self.cut_short {
            "cut short"
        } else {
            "failed"
        };
        write!(f, "{:?} scanner {outcome}: {}", self.scanner, self.reason)
    }
}

// --------------------------------------------------------------------------
// Rebuilding what was recorded
// --------------------------------------------------------------------------
//
// Each `*Parts` struct is followed by the `from_parts` that consumes it, so the path
// a report takes back off disk reads in one place. Hence `impl ScanPhase` before
// `struct ScanPhase`, and second impl blocks for `TargetScope` and `ProbeStats`.

/// Everything a [`TargetScope`] holds, for rebuilding one that was recorded.
///
/// A struct, since two `u128` counts and two range lists are easy to swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeParts {
    /// The ranges that were walked, after exclusions.
    pub ranges: Vec<IpRange>,
    /// The links swept whole, by the interface each is on.
    pub links: Vec<Zone>,
    /// The links read from without being probed, which are never coverage.
    pub listened: Vec<Zone>,
    /// How many distinct addresses those ranges hold.
    pub addresses: u128,
    /// How many probes the scope implies, where ports were known.
    pub probes: Option<u128>,
    /// Which ports were walked, and whether uniformly.
    pub ports: PortScope,
    /// The transports the scope covered.
    pub protocols: Vec<Protocol>,
    /// The ranges the policy withheld.
    pub excluded: Vec<IpRange>,
    /// How many addresses that withheld.
    pub withheld: u128,
}

impl TargetScope {
    /// Rebuilds a scope from what was recorded of it.
    ///
    /// Applies no policy, unlike [`from_ip_set`](Self::from_ip_set): the exclusions
    /// were applied when the scope was first computed.
    pub fn from_parts(parts: ScopeParts) -> Self {
        Self {
            listened: parts.listened,
            ranges: parts.ranges,
            links: parts.links,
            addresses: parts.addresses,
            probes: parts.probes,
            ports: parts.ports,
            protocols: parts.protocols,
            excluded: parts.excluded,
            withheld: parts.withheld,
        }
    }
}

/// Everything a [`ProbeStats`] holds, for rebuilding one that was recorded.
///
/// The two distributions are lists, since their lengths ([`ATTEMPTS_COUNTED`] and one
/// more than [`BUCKET_BOUNDS_MS`]) may grow. [`ProbeStats::from_parts`] reads each for
/// the slots this build counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeStatsParts {
    /// Which strategy this describes.
    pub scanner: ScannerKind,
    /// How many targets it was given.
    pub targets: u128,
    /// Why its receive loop stopped.
    pub stop_reason: StopReason,
    /// How long it ran.
    pub elapsed: Duration,
    /// How many sends it attempted.
    pub sends_attempted: u64,
    /// How many of those never left this host, refused or unable to reach
    /// their address.
    pub sends_failed: u64,
    /// How many of those were seen leaving on the wire.
    pub sends_witnessed: u64,
    /// How many segments its capture handed it.
    pub segments_seen: u64,
    /// Where its congestion window ended up.
    pub window: Option<WindowSummary>,
    /// How many captured segments belonged to something else.
    pub segments_off_target: u64,
    /// How many replies could not be attributed to one attempt.
    pub replies_without_rtt: u64,
    /// How many of those were ICMP refusals too short to name an attempt.
    pub refusals_unattributed: u64,
    /// How many hosts it found.
    pub hosts_found: u64,
    /// How many answers arrived on each attempt, one slot per counted attempt,
    /// as [`ProbeStats::answered_on`] gives them.
    pub answered_on: Vec<u64>,
    /// How many answers named no attempt.
    pub answered_unattributed: u64,
    /// When the first reply arrived, from the start of the run.
    pub first_reply: Option<Duration>,
    /// When the last one did.
    pub last_reply: Option<Duration>,
    /// How many hosts were found in each time bucket, one slot per bound plus
    /// the tail, as [`ProbeStats::found_at`] gives them.
    pub found_at: Vec<u64>,
    /// What the capture reported about its own losses.
    pub capture: Option<CaptureCounts>,
}

impl ProbeStats {
    /// Rebuilds probe statistics from what was recorded of them.
    ///
    /// Each distribution is read for the slots this build counts: extra slots are
    /// dropped and missing ones read as zero, so a record from a build with more slots
    /// still reads. A caller building these by hand sizes them from the two constants.
    pub fn from_parts(parts: ProbeStatsParts) -> Self {
        Self {
            scanner: parts.scanner,
            targets: parts.targets,
            stop_reason: parts.stop_reason,
            elapsed: parts.elapsed,
            sends_attempted: parts.sends_attempted,
            sends_failed: parts.sends_failed,
            sends_witnessed: parts.sends_witnessed,
            segments_seen: parts.segments_seen,
            window: parts.window,
            segments_off_target: parts.segments_off_target,
            replies_without_rtt: parts.replies_without_rtt,
            refusals_unattributed: parts.refusals_unattributed,
            hosts_found: parts.hosts_found,
            answered_on: fitted(&parts.answered_on),
            answered_unattributed: parts.answered_unattributed,
            first_reply: parts.first_reply,
            last_reply: parts.last_reply,
            found_at: fitted(&parts.found_at),
            capture: parts.capture,
        }
    }
}

/// As much of `from` as `N` slots hold, the rest zero. See
/// [`ProbeStats::from_parts`].
fn fitted<const N: usize>(from: &[u64]) -> [u64; N] {
    let mut into = [0u64; N];
    for (slot, value) in into.iter_mut().zip(from) {
        *slot = *value;
    }
    into
}

// --------------------------------------------------------------------------
// One phase of a scan
// --------------------------------------------------------------------------
//
// A phase is one engine call: a sweep, a port scan, a watch. A report holds a list
// of them, since discovery then a port scan is one job.

/// Which switch port the machine running a phase was plugged into.
///
/// A relation between *this* machine and the equipment it is plugged into, learned
/// from an unprompted announcement (see [`crate::protocols::lldp`] and
/// [`crate::protocols::cdp`]). It answers **where, physically, this was run from.**
///
/// On the phase, like [`PhaseOrigin`], because a [`merge`](crate::merge) may fold
/// phases run from several vantage points, each with its own true answer.
///
/// A phase may carry several: one per link it captured on, and another whenever the
/// answer changed, as when someone moves a cable during a long listen.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    link: Zone,
    source: AttachmentSource,
    device_mac: Option<MacAddr>,
    device_name: Option<String>,
    port: Option<String>,
    native_vlan: Option<u16>,
    management: Option<IpAddr>,
    observed_at: SystemTime,
}

/// Which protocol an [`Attachment`] was read from.
///
/// Cisco equipment runs CDP by default and LLDP only when enabled, so which one a
/// network answers on says something about it. The two also carry fields such as the
/// VLAN in different places.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AttachmentSource {
    /// IEEE 802.1AB, which anything may speak.
    Lldp,
    /// Cisco Discovery Protocol.
    Cdp,
}

impl AttachmentSource {
    /// Every announcement protocol this build knows, in declaration order. Checked
    /// against the published schema.
    pub const ALL: &'static [Self] = &[Self::Lldp, Self::Cdp];
}

impl Attachment {
    /// An attachment on `link`, read from `source`, with nothing established
    /// about it yet.
    pub fn new(link: Zone, source: AttachmentSource, observed_at: SystemTime) -> Self {
        Self {
            link,
            source,
            device_mac: None,
            device_name: None,
            port: None,
            native_vlan: None,
            management: None,
            observed_at,
        }
    }

    /// Names the device by the hardware address it identified its chassis with.
    ///
    /// Ties this attachment to a [`Host`] in the same report, which a name may not.
    pub fn with_device_mac(mut self, mac: MacAddr) -> Self {
        self.device_mac = Some(mac);
        self
    }

    /// Names the device as it names itself.
    pub fn with_device_name(mut self, name: impl Into<String>) -> Self {
        self.device_name = Some(name.into());
        self
    }

    /// Names the port, as the device calls it in its own configuration.
    pub fn with_port(mut self, port: impl Into<String>) -> Self {
        self.port = Some(port.into());
        self
    }

    /// Records the VLAN untagged traffic on this port lands in.
    pub fn with_native_vlan(mut self, vlan: u16) -> Self {
        self.native_vlan = Some(vlan);
        self
    }

    /// Records an address the device is managed at.
    pub fn with_management_address(mut self, address: IpAddr) -> Self {
        self.management = Some(address);
        self
    }

    /// Which of this machine's interfaces the announcement arrived on.
    pub fn link(&self) -> &Zone {
        &self.link
    }

    /// Which protocol said so.
    pub fn source(&self) -> AttachmentSource {
        self.source
    }

    /// The hardware address the device identified its chassis with.
    pub fn device_mac(&self) -> Option<MacAddr> {
        self.device_mac
    }

    /// What the device calls itself, which on managed equipment is its
    /// hostname.
    pub fn device_name(&self) -> Option<&str> {
        self.device_name.as_deref()
    }

    /// What the device calls the port this machine is plugged into.
    pub fn port(&self) -> Option<&str> {
        self.port.as_deref()
    }

    /// The VLAN untagged traffic on this port lands in, where the device said.
    pub fn native_vlan(&self) -> Option<u16> {
        self.native_vlan
    }

    /// An address the device is managed at, where it advertised one.
    pub fn management_address(&self) -> Option<IpAddr> {
        self.management
    }

    /// When the announcement this was read from arrived.
    ///
    /// Separate from the phase's span, so changes during a long phase can be ordered.
    pub fn observed_at(&self) -> SystemTime {
        self.observed_at
    }
}

/// Which document a phase came from, for a report folded out of several.
///
/// A report merged from an archived nmap file, last night's journal and a fresh scan
/// holds all their phases; this says which document each came from.
///
/// `None` on a phase this process measured.
///
/// The label is the caller's (a path, a record id, a bucket key), since the engine
/// opens no files. Only [`merge`](crate::merge) writes a `PhaseOrigin`, taking the
/// version from the source report's own attribution.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseOrigin {
    label: Option<Arc<str>>,
    engine_version: Arc<str>,
}

impl PhaseOrigin {
    /// An origin attributing a phase to `engine_version`, unnamed.
    pub fn new(engine_version: impl Into<Arc<str>>) -> Self {
        Self {
            label: None,
            engine_version: engine_version.into(),
        }
    }

    /// Names the document the phase was read from.
    pub fn with_label(mut self, label: impl Into<Arc<str>>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// What the caller called the document, if it said.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// What produced the phase, as that scanner attributed itself: `nmap 7.94` for a
    /// report read from nmap's XML.
    pub fn engine_version(&self) -> &str {
        &self.engine_version
    }
}

/// Everything a [`ScanPhase`] holds, for rebuilding one that was recorded.
///
/// Mirrors the phase field for field, without a default, so a field added to
/// [`ScanPhase`] fails to compile everywhere one is built until it is handled.
#[derive(Debug, Clone)]
pub struct PhaseParts {
    /// Which entry point the phase recorded.
    pub kind: ScanKind,
    /// When it began.
    pub started_at: SystemTime,
    /// How long it ran.
    pub elapsed: Duration,
    /// Which sockets the phase had, or `None` where this engine did not measure
    /// it and cannot say.
    pub privilege: Option<Privilege>,
    /// What it was asked to cover, and what it was forbidden.
    pub targets: TargetScope,
    /// The settings it ran under.
    pub settings: ScanSettings,
    /// The strategies that could not do their job.
    pub failures: Vec<ScannerFailure>,
    /// Ground the phase declined before sending anything.
    pub refusals: Vec<Refusal>,
    /// Addresses this host could not reach, so no probe was sent to them.
    pub unroutable: Vec<IpAddr>,
    /// The addresses among `unroutable` that this host's routing table
    /// refuses. See [`ScanPhase::refused_by_route`].
    pub refused_by_route: Vec<IpAddr>,
    /// Addresses whose per-host budget ran out before the phase finished with
    /// them.
    pub timed_out: Vec<IpAddr>,
    /// Addresses whose ICMP errors the phase found rate-limited. See
    /// [`ScanPhase::icmp_rate_limited`].
    pub icmp_rate_limited: Vec<IpAddr>,
    /// Addresses a raw phase reached by TCP connect. See
    /// [`ScanPhase::reached_by_connect`].
    pub reached_by_connect: Vec<IpRange>,
    /// Addresses in scope the phase reached no verdict on. See
    /// [`ScanPhase::undecided`].
    pub undecided: Vec<IpRange>,
    /// Why a port phase ran with no liveness pass in front of it. See
    /// [`ScanPhase::liveness_skipped`].
    pub liveness_skipped: Option<LivenessSkip>,
    /// Addresses a port phase standing in for its liveness pass asked on every
    /// port and heard nothing from. See [`ScanPhase::silent`].
    pub silent: Vec<IpRange>,
    /// Why the scan was stopped while the phase was running, or `None`. See
    /// [`ScanPhase::stopped`].
    pub stopped: Option<StopReason>,
    /// The passes over what the probes found that a stop skipped or cut
    /// short. See [`ScanPhase::passes_cut`].
    pub passes_cut: Vec<Pass>,
    /// How many of a port phase's targets it never asked and holds on no
    /// host. See [`ScanPhase::unreached`].
    pub unreached: u128,
    /// How many of a port phase's targets it asked at the addresses it lists
    /// no host at. See [`ScanPhase::unheard_probes`].
    pub unheard_probes: u128,
    /// What each strategy recorded about its own run.
    pub probes: Vec<ProbeStats>,
    /// Which document the phase came from, for one folded in from elsewhere.
    pub origin: Option<PhaseOrigin>,
    /// Which switch ports the machine running the phase was plugged into.
    pub attachments: Vec<Attachment>,
    /// Whether this is the phase as it stood before it closed. See
    /// [`ScanPhase::is_open`].
    pub open: bool,
}

impl ScanPhase {
    /// Rebuilds a phase from what was recorded of it.
    ///
    /// For restoring an earlier sitting of a resumed scan. A running phase comes from
    /// [`PhaseRecorder`](crate::scanner::recorder::PhaseRecorder).
    pub fn from_parts(parts: PhaseParts) -> Self {
        Self {
            kind: parts.kind,
            started_at: parts.started_at,
            elapsed: parts.elapsed,
            privilege: parts.privilege,
            targets: parts.targets,
            settings: parts.settings,
            failures: parts.failures,
            refusals: parts.refusals,
            unroutable: parts.unroutable,
            refused_by_route: parts.refused_by_route,
            timed_out: parts.timed_out,
            icmp_rate_limited: parts.icmp_rate_limited,
            reached_by_connect: parts.reached_by_connect,
            undecided: parts.undecided,
            liveness_skipped: parts.liveness_skipped,
            silent: parts.silent,
            stopped: parts.stopped,
            passes_cut: {
                let mut passes = parts.passes_cut;
                passes.sort_unstable();
                passes.dedup();
                passes
            },
            unreached: parts.unreached,
            unheard_probes: parts.unheard_probes,
            probes: parts.probes,
            origin: parts.origin,
            attachments: parts.attachments,
            open: parts.open,
        }
    }

    /// Attributes this phase to the document it was read from.
    ///
    /// Used by [`merge`](crate::merge), which knows the document's name and producer.
    pub fn attribute(&mut self, origin: PhaseOrigin) {
        self.origin = Some(origin);
    }
}

/// One completed call into the engine.
#[derive(Debug, Clone)]
pub struct ScanPhase {
    kind: ScanKind,
    started_at: SystemTime,
    elapsed: Duration,
    privilege: Option<Privilege>,
    targets: TargetScope,
    settings: ScanSettings,
    failures: Vec<ScannerFailure>,
    /// Addresses this host could not reach, so no probe was sent to them: no
    /// route or source address led to them, or they are neighbours on a local
    /// segment that never answered address resolution.
    ///
    /// Distinct from a host that answered nothing: scanning an unreachable address on
    /// trust cannot help.
    unroutable: Vec<IpAddr>,
    /// The addresses among `unroutable` that this host's routing table
    /// refuses. See [`refused_by_route`](Self::refused_by_route).
    refused_by_route: Vec<IpAddr>,
    /// Ground this phase declined before sending anything, and why.
    ///
    /// Not a failure; see [`Refusal`].
    refusals: Vec<Refusal>,
    /// Addresses the phase stopped working on because their own budget ran out.
    ///
    /// Not a failure. Without it, a host left early looks the same as one that stayed
    /// silent.
    timed_out: Vec<IpAddr>,
    /// Addresses whose ICMP errors the phase found rate-limited.
    ///
    /// See [`icmp_rate_limited`](Self::icmp_rate_limited).
    icmp_rate_limited: Vec<IpAddr>,
    /// Addresses this phase reached by TCP connect although it held the
    /// privilege its raw strategies need.
    ///
    /// See [`reached_by_connect`](Self::reached_by_connect).
    reached_by_connect: Vec<IpRange>,
    /// Addresses in scope whose presence the phase reached no verdict on.
    ///
    /// See [`undecided`](Self::undecided).
    undecided: Vec<IpRange>,
    /// Why this port phase ran with no liveness pass in front of it, or `None`.
    /// See [`liveness_skipped`](Self::liveness_skipped).
    liveness_skipped: Option<LivenessSkip>,
    /// Addresses asked on every port that answered none, and so no host. See
    /// [`silent`](Self::silent).
    silent: Vec<IpRange>,
    /// Why the scan was stopped while this phase ran. See
    /// [`stopped`](Self::stopped).
    stopped: Option<StopReason>,
    /// The passes a stop skipped or cut short, in the order a scan runs them.
    /// See [`passes_cut`](Self::passes_cut).
    passes_cut: Vec<Pass>,
    /// Targets it never asked and holds on no host. See
    /// [`unreached`](Self::unreached).
    unreached: u128,
    /// Targets asked at addresses the phase lists no host at. See
    /// [`unheard_probes`](Self::unheard_probes).
    unheard_probes: u128,
    probes: Vec<ProbeStats>,
    /// Which document this phase was folded in from, for a merged report.
    origin: Option<PhaseOrigin>,
    /// Which switch ports the machine running this phase was plugged into.
    attachments: Vec<Attachment>,
    /// Whether this is the phase as it stood before it closed. See
    /// [`is_open`](Self::is_open).
    open: bool,
}

impl ScanPhase {
    /// Which document this phase came from, for one folded into a merged report
    /// from elsewhere. `None` for a phase this process measured.
    pub fn origin(&self) -> Option<&PhaseOrigin> {
        self.origin.as_ref()
    }

    /// Where the machine running this phase was plugged in, as the equipment on
    /// the far end of the cable announced itself.
    ///
    /// Empty for a phase that heard no announcement, as on an unmanaged network.
    pub fn attachments(&self) -> &[Attachment] {
        &self.attachments
    }

    /// Which entry point this phase records.
    pub fn kind(&self) -> ScanKind {
        self.kind
    }

    /// When the phase began.
    pub fn started_at(&self) -> SystemTime {
        self.started_at
    }

    /// How long the phase ran, measured monotonically.
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Whether the engine held the privileges its raw strategies need. An
    /// unprivileged phase reached its targets over plain TCP connect attempts,
    /// which see less and are more visible to the target.
    ///
    /// `None` for a phase this engine did not measure, such as one imported from
    /// another scanner's report.
    pub fn privilege(&self) -> Option<Privilege> {
        self.privilege
    }

    /// What the phase was asked to cover.
    pub fn targets(&self) -> &TargetScope {
        &self.targets
    }

    /// The settings the phase ran under.
    pub fn settings(&self) -> &ScanSettings {
        &self.settings
    }

    /// Addresses this host could not reach, so no probe was sent to them,
    /// ascending: no route or source address led to them, or they are
    /// neighbours on a local segment that never answered address resolution.
    ///
    /// Not [`failures`](Self::failures), and not counted as partial. An address here was
    /// never probed.
    pub fn unroutable(&self) -> &[IpAddr] {
        &self.unroutable
    }

    /// The addresses among [`unroutable`](Self::unroutable) that this host's
    /// own routing table refuses, ascending.
    ///
    /// A `prohibit`, `blackhole` or `unreachable` route, or a VPN kill switch's rules,
    /// is host policy that every program honours, so the engine sends such an address
    /// nothing. Named apart because the remedy is on this machine.
    ///
    /// Named where the engine can tell: a neighbour on one of this host's segments,
    /// whose connected route only a policy overrides; and any address the kernel
    /// refuses with an error only a policy produces (permission denied for `prohibit`,
    /// invalid argument for `blackhole`, on Linux). An `unreachable` route elsewhere
    /// looks like a missing route and is not named here.
    pub fn refused_by_route(&self) -> &[IpAddr] {
        &self.refused_by_route
    }

    /// Addresses the phase left before it had finished with them, because the
    /// per-host budget in
    /// [`ScanSettings::host_timeout`](ScanSettings::host_timeout) ran out.
    ///
    /// A host named here still carries every port the phase managed to ask.
    pub fn timed_out(&self) -> &[IpAddr] {
        &self.timed_out
    }

    /// Addresses whose ICMP errors this phase found rate-limited, ascending.
    ///
    /// A closed UDP port is known only by its host's ICMP port unreachable, which hosts
    /// ration (Linux: a burst, then about one a second). On a host here most closed ports
    /// read `OpenOrNoReply`, so its open-or-no-reply ports are mostly closed.
    ///
    /// Inferred from the host's answers: a port answered closed only when asked again,
    /// after others answered at once, while more ports stayed silent than answered,
    /// which a filter does not produce.
    ///
    /// Needs a port asked more than once, so only raw-socket scans name hosts here.
    pub fn icmp_rate_limited(&self) -> &[IpAddr] {
        &self.icmp_rate_limited
    }

    /// Addresses this phase reached by TCP connect although it held the
    /// privilege its raw strategies need, ascending.
    ///
    /// Some addresses are beyond a raw probe whatever the privilege: loopback, and
    /// anything with no route. A process that can inject frames but holds no raw socket
    /// (an unprivileged macOS run with BPF access) also cannot reach this host's own
    /// addresses, anything routed through a tunnel, or, for port probes, an IPv6
    /// neighbour. Those were probed by connect, so their evidence is connect evidence
    /// although [`privilege`](Self::privilege) reads raw, and the configured technique
    /// was not used.
    ///
    /// An address no probe could leave for is [unroutable](Self::unroutable) instead.
    ///
    /// Empty for most phases, and for every [`Privilege::Connect`] phase.
    pub fn reached_by_connect(&self) -> &[IpRange] {
        &self.reached_by_connect
    }

    /// Addresses in this phase's scope whose presence it reached no verdict on,
    /// ascending.
    ///
    /// A discovery phase settles an address when something answers or the retry budget
    /// is spent. An address here is neither: the phase stopped before or while asking,
    /// had no strategy that could ask, was refused the range, or ran out the address's
    /// time budget. None is a host found down; a port scan leaves their ports unsettled
    /// and a resumed job asks again. Without this list, an address never asked would
    /// look like one that stayed silent.
    ///
    /// Disjoint from [`unroutable`](Self::unroutable). An address can be here and in
    /// [`timed_out`](Self::timed_out), which says why.
    ///
    /// A port phase standing in for a dropped liveness pass (see
    /// [`LivenessSkip::PortsNoDearer`]) names here addresses it heard nothing from
    /// without finishing asking; the report lists no host for them and a resumed job
    /// asks their ports again. If such a phase never closed, it names every address it
    /// had not yet decided.
    ///
    /// Empty for other port scans, which settle ports rather than presence, and for
    /// listeners.
    pub fn undecided(&self) -> &[IpRange] {
        &self.undecided
    }

    /// Why this port phase ran with no liveness pass in front of it.
    ///
    /// `None` when a liveness pass preceded it (recorded as its own
    /// [`Discovery`](ScanKind::Discovery) phase), and for every phase that is not a
    /// [`PortScan`](ScanKind::PortScan). The reasons differ in what the findings mean;
    /// see [`LivenessSkip`].
    pub fn liveness_skipped(&self) -> Option<LivenessSkip> {
        self.liveness_skipped
    }

    /// Addresses this port phase asked on every port it named and heard
    /// nothing from at all, ascending.
    ///
    /// Filled only where the phase stood in for a dropped liveness pass; see
    /// [`LivenessSkip::PortsNoDearer`]. An address that drew no open port, closed port
    /// or ICMP error is named here, not listed as a host. Its ports were asked, so it is
    /// not [`undecided`](Self::undecided), and a comparison reads it as covered and
    /// quiet.
    ///
    /// Empty for every other phase. With [`ZondConfig::assume_up`] every address is a
    /// host.
    pub fn silent(&self) -> &[IpRange] {
        &self.silent
    }

    /// Why the scan was stopped while this phase was running: the caller
    /// asked ([`Aborted`](StopReason::Aborted)), or the scan's own budget ran
    /// out ([`TimedOut`](StopReason::TimedOut)).
    ///
    /// `None` for a phase that ended on its own, and for every
    /// [`Listen`](ScanKind::Listen) phase, which always ends by being stopped.
    ///
    /// A marker, not a verdict: what a stop cut shows as [`unreached`](Self::unreached)
    /// targets, unasked ports, undecided addresses and
    /// [`passes_cut`](Self::passes_cut), which [`ScanReport::is_partial`] reads. This
    /// adds the reason.
    pub fn stopped(&self) -> Option<StopReason> {
        self.stopped
    }

    /// The passes over what the probes found that a stop skipped or cut
    /// short, in the order a scan runs them. Empty for a phase no stop cut,
    /// and for one stopped before any pass had work to do.
    ///
    /// Only passes the scan was asked to run and had work for: with TLS enumeration
    /// off, or no TLS port found, no TLS pass is named. [`ScanReport::is_partial`]
    /// counts these.
    ///
    /// A pass cut short on some ports by a detection's budget or the file limit is a
    /// [failure](Self::failures) marked cut short, naming the port.
    pub fn passes_cut(&self) -> &[Pass] {
        &self.passes_cut
    }

    /// Whether this is the phase as it stood before it closed: a record kept as it ran,
    /// for a sitting killed outright.
    ///
    /// From a journal, an open phase was killed or still running when read. It records
    /// what the phase opened with, how long it ran and what failed, but nothing only its
    /// close establishes (no [stop](Self::stopped), [unreached](Self::unreached) target
    /// or [pass cut](Self::passes_cut)), so [`ScanReport::is_partial`] counts it.
    ///
    /// Not a [`StopReason`]: nothing running names a kill.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// How many of this port phase's targets it never asked and holds on no
    /// host: the ones its walk never reached because the scan was stopped
    /// first, the ones it passed for an address its liveness pass reached no
    /// verdict on, and the ones left unasked at an address it then listed no
    /// host at, being [`undecided`](Self::undecided).
    ///
    /// A count, since a permuted walk scatters what a stop leaves across every address,
    /// and a `/16` on every port stopped a minute in would list billions. Every target
    /// the phase was handed was probed (counted by its hosts and
    /// [`unheard_probes`](Self::unheard_probes)), is on its host
    /// [`Unasked`](crate::model::port::PortState::Unasked), is counted here, or was
    /// settled without a probe (silent, unreachable, or excluded).
    ///
    /// A resumed job asks every one of them. Zero for a phase that asked everything,
    /// and for every non-[`PortScan`](ScanKind::PortScan) phase. See
    /// [`ScanReport::unreached`] for several sittings.
    pub fn unreached(&self) -> u128 {
        self.unreached
    }

    /// How many of this port phase's targets it asked at the addresses it
    /// lists no host at: every port of the ones it names
    /// [`silent`](Self::silent), and the ports it reached of the ones it names
    /// [`undecided`](Self::undecided).
    ///
    /// Those addresses' records are dropped, so a count of probed ports read off the
    /// hosts comes up short by exactly this. The scope cannot supply it, since a mixed
    /// scope records a union and an undecided address was asked only part of its ports.
    ///
    /// Each sitting of a resumed job counts its own, and the counts add up. A phase that
    /// never closed counts the probes of its silent addresses; the sitting that decides
    /// the undecided ones counts theirs. Zero for every phase that did not stand in for
    /// a liveness pass, and in a record without the count.
    pub fn unheard_probes(&self) -> u128 {
        self.unheard_probes
    }

    /// The strategies in this phase that could not do their job.
    pub fn failures(&self) -> &[ScannerFailure] {
        &self.failures
    }

    /// Ground this phase declined to cover, and why.
    ///
    /// With [`failures`](Self::failures), everything the phase did not answer. See
    /// [`Refusal`].
    pub fn refusals(&self) -> &[Refusal] {
        &self.refusals
    }

    /// What each instrumented scanner observed about its own run.
    ///
    /// Empty where no strategy carries instrumentation; the TCP-connect fallback has no
    /// capture to audit.
    pub fn probe_stats(&self) -> &[ProbeStats] {
        &self.probes
    }
}

// --------------------------------------------------------------------------
// The report itself
// --------------------------------------------------------------------------
//
// What the phases and hosts add up to. Counts are computed from the hosts on demand.

/// Counts derived from a report's hosts.
///
/// Computed on demand by [`ScanReport::summary`].
///
/// `hosts_alive` and `ports_open` each come with a full distribution, since a blocked
/// port is evidence of a firewall and a closed one of a live host, and neither is
/// silence.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanSummary {
    /// Hosts recorded, whatever their status.
    pub hosts_total: usize,
    /// Hosts confirmed to be on the network, either responding or blocked.
    pub hosts_alive: usize,
    /// How many hosts fell into each status.
    pub hosts_by_status: BTreeMap<HostStatus, usize>,
    /// Port records across all hosts.
    pub ports_total: usize,
    /// Ports found accepting connections.
    pub ports_open: usize,
    /// How many ports fell into each state.
    pub ports_by_state: BTreeMap<PortState, usize>,
    /// Ports whose service was identified by fingerprinting.
    ///
    /// A name read off the port number is not counted (see
    /// [`Service::is_inferred`](crate::model::port::Service::is_inferred)).
    pub services_identified: usize,
    /// How many hosts were reachable at an IPv4 address, at an IPv6 one, and at
    /// both.
    ///
    /// Per host. The three overlap and do not sum to
    /// [`hosts_total`](Self::hosts_total): a dual-stack host counts in all three.
    pub hosts_by_family: FamilyCounts,
}

/// Hosts counted by the address families they answered at.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FamilyCounts {
    /// Hosts with at least one IPv4 address.
    pub ipv4: usize,
    /// Hosts with at least one IPv6 address.
    pub ipv6: usize,
    /// Hosts with both, counted again here.
    pub dual_stack: usize,
}

/// Everything known about a completed scan.
///
/// Obtained from [`ScanTask::join`](crate::scanner::ScanTask::join) once a scan
/// finishes. See the [module documentation](self) for how it relates to the
/// live [`ScanSession`](crate::scanner::session::ScanSession).
#[derive(Debug, Clone)]
#[must_use = "a report is the record of the scan that just ran; dropping it discards it"]
pub struct ScanReport {
    /// Which build produced the findings. Borrowed for a scan this build ran, owned for
    /// one read back.
    engine_version: Cow<'static, str>,
    phases: Vec<ScanPhase>,
    /// Keyed by [`ScopedIp`], since `fe80::1` names a different machine on every segment.
    /// The zone is dropped from addresses that do not need one, so ordering is by
    /// address with the zone breaking ties. [`pairing`](crate::diff::pairing) draws the
    /// same distinction.
    hosts: BTreeMap<ScopedIp, Host>,
}

impl ScanReport {
    /// Builds a single-phase report over the hosts a scan produced.
    ///
    /// Hosts are keyed by their reported address (with interface where needed), so a host
    /// with several addresses appears once and two link-locals on different segments stay
    /// two.
    pub fn new(phase: ScanPhase, hosts: impl IntoIterator<Item = Host>) -> Self {
        let mut report = Self {
            engine_version: Cow::Borrowed(ENGINE_VERSION),
            phases: vec![phase],
            hosts: index(hosts),
        };
        report.forget_the_silent();
        report
    }

    /// A report over the phases of a job that ran in more than one sitting.
    ///
    /// For a resumed scan, whose earlier sittings are restored from a journal. `phases`
    /// is kept in the order given.
    ///
    /// Attributed to this build, which is continuing the job. Use
    /// [`recorded`](Self::recorded) to rebuild a report nothing is continuing.
    pub fn from_phases(phases: Vec<ScanPhase>, hosts: impl IntoIterator<Item = Host>) -> Self {
        Self::attributed(Cow::Borrowed(ENGINE_VERSION), phases, hosts)
    }

    /// A report rebuilt from what an earlier scan wrote down, attributed to the
    /// engine that ran it.
    ///
    /// For reading a finished scan back from a journal or an exported report. The
    /// version comes from the record, so a scan run by 0.11 still says 0.11 when 0.12
    /// reads it.
    pub fn recorded(
        engine_version: impl Into<String>,
        phases: Vec<ScanPhase>,
        hosts: impl IntoIterator<Item = Host>,
    ) -> Self {
        Self::attributed(Cow::Owned(engine_version.into()), phases, hosts)
    }

    fn attributed(
        engine_version: Cow<'static, str>,
        phases: Vec<ScanPhase>,
        hosts: impl IntoIterator<Item = Host>,
    ) -> Self {
        let mut report = Self {
            engine_version,
            phases,
            hosts: index(hosts),
        };
        report.forget_the_silent();
        report
    }

    /// The engine version that produced this report.
    pub fn engine_version(&self) -> &str {
        &self.engine_version
    }

    /// The phases that contributed to this report, in the order they ran.
    ///
    /// A report a scan produced has at least one. One rebuilt with
    /// [`recorded`](Self::recorded) can have none, if the scan stopped before writing
    /// a phase.
    pub fn phases(&self) -> &[ScanPhase] {
        &self.phases
    }

    /// Whether this report was folded out of documents rather than measured by
    /// one run.
    ///
    /// True when any phase carries a [`PhaseOrigin`], which only
    /// [`merge`](crate::merge) writes.
    ///
    /// For a merged report [`elapsed`](Self::elapsed) sums several scanners' working
    /// time and is not the duration of anything; the span is
    /// [`finished_at`](Self::finished_at) less [`started_at`](Self::started_at).
    pub fn is_merged(&self) -> bool {
        self.phases.iter().any(|phase| phase.origin().is_some())
    }

    /// Every host recorded, ordered by primary IP.
    pub fn hosts(&self) -> impl Iterator<Item = &Host> {
        self.hosts.values()
    }

    /// Every host recorded, to be changed in place.
    ///
    /// Crate-private, since a report is a record. Used by
    /// [`cve::correlate_report`](crate::cve::correlate_report), which adds conclusions
    /// from what the scan already knew.
    pub(crate) fn hosts_mut(&mut self) -> impl Iterator<Item = &mut Host> {
        self.hosts.values_mut()
    }

    /// The number of hosts recorded.
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// Looks up a host by the address it is reported under.
    ///
    /// For two link-locals with the same number on different segments, this answers
    /// with the first; [`host_scoped`](Self::host_scoped) can tell them apart.
    pub fn host(&self, ip: &IpAddr) -> Option<&Host> {
        self.hosts
            .range(ScopedIp::unscoped(*ip)..)
            .next()
            .filter(|(key, _)| key.addr() == *ip)
            .map(|(_, host)| host)
    }

    /// Looks up a host by the address it is reported under, together with the
    /// interface that address is valid on.
    ///
    /// The exact lookup, for a link-local: `fe80::1%en0` and `fe80::1%en1` are two
    /// hosts.
    pub fn host_scoped(&self, ip: &ScopedIp) -> Option<&Host> {
        self.hosts.get(ip)
    }

    /// Takes this report's phases, consuming it.
    ///
    /// For assembling a new report out of several. Read the hosts through
    /// [`hosts`](Self::hosts) first.
    pub fn into_phases(self) -> Vec<ScanPhase> {
        self.phases
    }

    /// When the earliest phase began.
    pub fn started_at(&self) -> SystemTime {
        self.phases
            .iter()
            .map(ScanPhase::started_at)
            .min()
            .unwrap_or_else(SystemTime::now)
    }

    /// When the latest phase stopped looking.
    ///
    /// The moment the findings are *as of*, for judging them against a clock: a
    /// certificate's remaining validity, staleness, which report is later. Each phase
    /// ends at its own `started_at + elapsed`.
    ///
    /// A phase whose end cannot be represented is placed at its start. An imported
    /// document's `elapsed` (nmap's is unbounded decimal seconds) may exceed what a
    /// [`SystemTime`] holds, and the checked addition avoids a panic; the understatement
    /// is safe.
    pub fn finished_at(&self) -> SystemTime {
        self.phases
            .iter()
            .map(|phase| {
                phase
                    .started_at()
                    .checked_add(phase.elapsed())
                    .unwrap_or_else(|| phase.started_at())
            })
            .max()
            .unwrap_or_else(SystemTime::now)
    }

    /// The moment this report is judged to have happened.
    ///
    /// [`finished_at`](Self::finished_at) for a report with phases. For a merged report,
    /// taking the earliest start would judge tonight's certificates against last
    /// quarter.
    ///
    /// A report without phases is placed by the latest time any host was seen.
    ///
    /// The clock [`merge`](crate::merge) and [`diff`](crate::diff) order documents by;
    /// public so a caller can order them the same way.
    pub fn observed_at(&self) -> SystemTime {
        if !self.phases.is_empty() {
            return self.finished_at();
        }

        self.hosts()
            .map(Host::last_seen)
            .max()
            .unwrap_or_else(SystemTime::now)
    }

    /// How long the engine spent scanning, summed over the phases.
    ///
    /// Working time, excluding whatever the caller did between phases. For the
    /// wall-clock span, use [`finished_at`](Self::finished_at) less
    /// [`started_at`](Self::started_at).
    pub fn elapsed(&self) -> Duration {
        self.phases.iter().map(ScanPhase::elapsed).sum()
    }

    /// Every strategy failure across all phases, in the order they were
    /// recorded.
    pub fn failures(&self) -> impl Iterator<Item = &ScannerFailure> {
        self.phases.iter().flat_map(ScanPhase::failures)
    }

    /// Every refusal, across all phases.
    pub fn refusals(&self) -> impl Iterator<Item = &Refusal> {
        self.phases.iter().flat_map(ScanPhase::refusals)
    }

    /// Every instrumented scanner's counters, across all phases.
    pub fn probe_stats(&self) -> impl Iterator<Item = &ProbeStats> {
        self.phases.iter().flat_map(ScanPhase::probe_stats)
    }

    /// Whether the findings are narrower than the caller asked for.
    ///
    /// True wherever part of the request went unanswered: a strategy that did not
    /// complete, a [refusal](Self::refusals), a host its budget left early that no
    /// phase finished ([`timed_out`](Self::timed_out)), an address with no verdict
    /// ([`undecided`](Self::undecided)), a port recorded
    /// [`Unasked`](crate::model::port::PortState::Unasked), a target never asked that
    /// no host holds ([`unreached`](Self::unreached)), a pass a stop left
    /// ([`passes_cut`](Self::passes_cut)), or a phase killed before it closed
    /// ([`ScanPhase::is_open`]).
    ///
    /// Read over the whole report: what one phase left open and another (a resumed
    /// sitting, a merged source) closed is closed. Failures and refusals always count,
    /// since neither says which ground it cost.
    ///
    /// Not counted: unreachable addresses ([`ScanPhase::unroutable`]) and their unasked
    /// ports, addresses an exclusion withheld, and a journal that could not be written,
    /// none of which is coverage that fell short.
    pub fn is_partial(&self) -> bool {
        self.phases.iter().any(|phase| {
            phase.failures.iter().any(ScannerFailure::narrows_coverage)
                || !phase.refusals.is_empty()
        }) || !self.timed_out().is_empty()
            || !self.undecided().is_empty()
            || self.left_ports_unasked()
            || self.unreached() > 0
            || !self.passes_cut().is_empty()
            || self.left_open()
    }

    /// Whether a phase here is [open](ScanPhase::is_open) and no later phase
    /// of its kind from the same account closed: the report of a job whose
    /// last sitting was killed, or is still running.
    ///
    /// On the terms [`passes_cut`](Self::passes_cut) gives.
    pub fn left_open(&self) -> bool {
        self.phases.iter().enumerate().any(|(at, phase)| {
            phase.open
                && !self.phases[at + 1..].iter().any(|later| {
                    later.kind == phase.kind && later.origin == phase.origin && !later.open
                })
        })
    }

    /// The passes a stop left that no later sitting of the same account ran,
    /// in the order a scan runs them.
    ///
    /// Stands until a later phase of the same kind from the same account, as with
    /// [`unreached`](Self::unreached): a resumed sitting runs the passes over every host
    /// the stopped one found. Across accounts a pass stands.
    pub fn passes_cut(&self) -> Vec<Pass> {
        let mut passes: Vec<Pass> = self
            .phases
            .iter()
            .enumerate()
            .filter(|(at, phase)| {
                !self.phases[at + 1..]
                    .iter()
                    .any(|later| later.kind == phase.kind && later.origin == phase.origin)
            })
            .flat_map(|(_, phase)| phase.passes_cut.iter().copied())
            .collect();
        passes.sort_unstable();
        passes.dedup();
        passes
    }

    /// How many port targets this report's phases never asked and hold on no
    /// host, and no later sitting of the same account took up.
    ///
    /// A phase's [`unreached`](ScanPhase::unreached) count is replaced by a later phase
    /// of the same kind from the same account, since a resumed sitting walks what the
    /// earlier one left. The account is the document a phase came from, or this engine's
    /// own run for a phase with no [`origin`](ScanPhase::origin).
    ///
    /// Across accounts a count stands, since it names no targets.
    pub fn unreached(&self) -> u128 {
        self.phases
            .iter()
            .enumerate()
            .filter(|(at, phase)| {
                phase.unreached > 0
                    && !self.phases[at + 1..]
                        .iter()
                        .any(|later| later.kind == phase.kind && later.origin == phase.origin)
            })
            .map(|(_, phase)| phase.unreached)
            .fold(0u128, u128::saturating_add)
    }

    /// The addresses whose presence this report reached no verdict on,
    /// ascending: named [`undecided`](ScanPhase::undecided) by some phase, and
    /// decided by none.
    ///
    /// An address is decided by a phase that walked it without naming it undecided, by
    /// a live host at it, or by some phase finding it unreachable. So a resumed sitting
    /// or a later merged sweep closes what an earlier one left open. Read by
    /// [`is_partial`](Self::is_partial) and comparisons.
    pub fn undecided(&self) -> Vec<IpRange> {
        let mut open = IpSet::new();
        let mut decided = IpSet::new();
        for phase in &self.phases {
            let mut left = IpSet::new();
            for range in &phase.undecided {
                left.insert_range(*range);
            }
            let mut walked = IpSet::new();
            for range in phase.targets.ranges() {
                walked.insert_range(*range);
            }
            walked.subtract(&left);
            append(&mut open, &left);
            append(&mut decided, &walked);
            for address in &phase.unroutable {
                decided.insert(*address);
            }
        }
        if open.is_empty() {
            return Vec::new();
        }
        open.subtract(&decided);
        open.canonicalize();

        // Last: only the live hosts' addresses still open can change the result.
        let alive = listed_within(self.hosts.values().filter(|host| host.is_alive()), &open);
        open.subtract(&alive);
        open.canonicalize();
        let v4 = open.v4().iter().copied().map(IpRange::V4);
        let v6 = open.v6().iter().copied().map(IpRange::V6);
        v4.chain(v6).collect()
    }

    /// The addresses a phase's own time budget left early and no phase
    /// finished, ascending.
    ///
    /// A phase of the same kind that walked an address without running out of time
    /// finishes it; a sweep says nothing about ports a port scan left unasked. Each
    /// phase keeps its own [`timed_out`](ScanPhase::timed_out) list.
    pub fn timed_out(&self) -> Vec<IpAddr> {
        let walked: Vec<IpSet> = self
            .phases
            .iter()
            .map(|phase| {
                let mut walked = IpSet::new();
                for range in phase.targets.ranges() {
                    walked.insert_range(*range);
                }
                walked.canonicalize();
                walked
            })
            .collect();

        let mut left: Vec<IpAddr> = self
            .phases
            .iter()
            .flat_map(|phase| phase.timed_out.iter().map(move |ip| (phase.kind, *ip)))
            .filter(|(kind, ip)| {
                !self.phases.iter().zip(&walked).any(|(other, walked)| {
                    other.kind == *kind && walked.contains(ip) && !other.timed_out.contains(ip)
                })
            })
            .map(|(_, ip)| ip)
            .collect();
        left.sort_unstable();
        left.dedup();
        left
    }

    /// Whether any host this report could reach carries a port recorded
    /// [`Unasked`](crate::model::port::PortState::Unasked): named by the scan,
    /// and never probed.
    ///
    /// A host whose every address a phase names unroutable is left out, as
    /// [`is_partial`](Self::is_partial) does not count it.
    ///
    /// Ports are read first, so a report with nothing unasked reads no addresses.
    pub(crate) fn left_ports_unasked(&self) -> bool {
        let mut unasked = self
            .hosts
            .values()
            .filter(|host| {
                host.ports()
                    .any(|port| port.state() == crate::model::port::PortState::Unasked)
            })
            .peekable();
        if unasked.peek().is_none() {
            return false;
        }

        let unroutable: std::collections::BTreeSet<&IpAddr> = self
            .phases
            .iter()
            .flat_map(|phase| phase.unroutable.iter())
            .collect();
        unasked.any(|host| host.ips().iter().any(|ip| !unroutable.contains(ip)))
    }

    /// Counts derived from the recorded hosts.
    pub fn summary(&self) -> ScanSummary {
        let mut summary = ScanSummary::default();

        for host in self.hosts.values() {
            summary.hosts_total += 1;
            if host.is_alive() {
                summary.hosts_alive += 1;
            }
            *summary.hosts_by_status.entry(host.status()).or_default() += 1;

            let v4 = host.ips().iter().any(IpAddr::is_ipv4);
            let v6 = host.ips().iter().any(IpAddr::is_ipv6);
            summary.hosts_by_family.ipv4 += usize::from(v4);
            summary.hosts_by_family.ipv6 += usize::from(v6);
            summary.hosts_by_family.dual_stack += usize::from(v4 && v6);

            for port in host.ports() {
                summary.ports_total += 1;
                if port.state() == PortState::Open {
                    summary.ports_open += 1;
                }
                *summary.ports_by_state.entry(port.state()).or_default() += 1;
                if port.service().is_some_and(|service| !service.is_inferred()) {
                    summary.services_identified += 1;
                }
            }
        }

        summary
    }

    /// The hosts this report found alive, as targets for a port scan.
    ///
    /// The join between the two phases: sweep a range cheaply, then port-scan only what
    /// answered.
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use zond_engine::{PortSet, ZondConfig, discover, scan};
    /// use zond_engine::detect::Detections;
    /// use zond_engine::model::parse::ip::to_set;
    ///
    /// let cfg = ZondConfig::default();
    /// let (_, sweep) = discover(to_set(&["192.0.2.0/24"], None, None)?, &cfg).await?;
    /// let mut report = sweep.join().await?;
    ///
    /// // The sweep established these hosts answer, so skip a second liveness pass.
    /// let mut scanning = cfg.clone();
    /// scanning.assume_up = true;
    /// let targets = report.alive_targets(PortSet::try_from("22,80,443")?);
    /// let (_, ports) = scan(targets, &scanning, Detections::embedded()).await?;
    /// report.merge(ports.join().await?);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Only hosts for which [`Host::is_alive`] holds, so [`Down`](HostStatus::Down) and
    /// [`Unknown`](HostStatus::Unknown) hosts are left out.
    ///
    /// One address per host, [`Host::primary_ip`], so a dual-stack host is scanned
    /// once. Build the set from [`Host::ips`] to scan every address.
    ///
    /// A link-local address carries the interface it was found on.
    pub fn alive_targets(&self, ports: PortSet) -> TargetMap {
        let mut ips = IpSet::new();

        for host in self.hosts.values().filter(|host| host.is_alive()) {
            match host.primary_ip() {
                IpAddr::V4(v4) => {
                    if let Ok(range) = Ipv4Range::new(v4, v4) {
                        ips.push_v4_range(range);
                    }
                }
                IpAddr::V6(v6) => {
                    // Kept only for addresses that need it, as `ScopedIp` does.
                    let zone = v6
                        .is_unicast_link_local()
                        .then(|| host.zone().and_then(Zone::index))
                        .flatten();
                    if let Ok(range) = Ipv6Range::scoped(v6, v6, zone) {
                        ips.push_v6_range(range);
                    }
                }
            }
        }

        ips.canonicalize();

        let mut targets = TargetMap::new();
        // No empty unit, or `scan` would report a phase that covered nothing.
        if !ips.is_empty() {
            targets.add_unit(TargetSet::new(ips, ports));
        }
        targets
    }

    /// Folds a later phase of the same job into this report.
    ///
    /// Hosts present in both are combined with [`Host::merge`], so a host
    /// discovered in the first phase keeps its MAC and telemetry when the second
    /// adds its ports. Phases and their failures are appended in call order.
    ///
    /// The engine version is left as this report's.
    pub fn merge(&mut self, other: ScanReport) {
        self.fold(other, Host::merge);
    }

    /// Folds `later`, a report closed against the same live hosts as this one
    /// and after it, into this report.
    ///
    /// For a scan that closes one phase and continues with the same store: a host in
    /// both reports is one host copied twice, and its round trips would count twice. So
    /// the later's round trips replace these; see [`Host::merge_later_account`].
    /// Everything else folds as [`merge`](Self::merge) does.
    pub(crate) fn merge_later_copy(&mut self, later: ScanReport) {
        self.fold(later, Host::merge_later_account);
    }

    /// Appends `other`'s phases and folds its hosts into these by `fold`.
    fn fold(&mut self, other: ScanReport, fold: fn(&mut Host, Host)) {
        self.phases.extend(other.phases);

        for (key, host) in other.hosts {
            match self.hosts.get_mut(&key) {
                Some(existing) => fold(existing, host),
                None => {
                    self.hosts.insert(key, host);
                }
            }
        }
        self.forget_the_silent();
    }

    /// Drops every host nothing was heard from at an address a phase names
    /// [`silent`](ScanPhase::silent).
    ///
    /// Applied wherever a report is assembled (scan, journal, merge), since a journal
    /// may already hold a record of an address later found silent. See [`Unheard`].
    fn forget_the_silent(&mut self) {
        let unheard = Unheard::of(&self.phases);
        if unheard.is_empty() {
            return;
        }
        self.hosts.retain(|_, host| !unheard.drops(host));
    }
}

/// The addresses a set of phases heard nothing from and lists no host at: what
/// a port phase standing in for a liveness pass named
/// [`silent`](ScanPhase::silent), and what it named
/// [`undecided`](ScanPhase::undecided).
///
/// Shared by every place such a record is dropped (report assembly, journal restore,
/// a journal's findings file at the end of a sitting), so they agree.
///
/// A discovery phase's undecided addresses are left alone.
pub(crate) struct Unheard(IpSet);

impl Unheard {
    /// The addresses `phases` heard nothing from.
    pub(crate) fn of<'a>(phases: impl IntoIterator<Item = &'a ScanPhase>) -> Self {
        Self::reading(phases, true)
    }

    /// The addresses `phases` heard nothing from, less those a phase that
    /// never closed has yet to decide: what a sitting continuing the job
    /// leaves out of what it restores.
    ///
    /// A killed port phase standing in for liveness names every undecided address; the
    /// next sitting restores those records and decides them. Silent addresses were
    /// decided and stay out.
    #[cfg(feature = "journal-format")]
    pub(crate) fn decided<'a>(phases: impl IntoIterator<Item = &'a ScanPhase>) -> Self {
        Self::reading(phases, false)
    }

    /// [`of`](Self::of), or [`decided`](Self::decided) where `pending` is
    /// false.
    fn reading<'a>(phases: impl IntoIterator<Item = &'a ScanPhase>, pending: bool) -> Self {
        let mut unheard = IpSet::new();
        for phase in phases {
            for range in &phase.silent {
                unheard.insert_range(*range);
            }
            if phase.kind == ScanKind::PortScan && (pending || !phase.open) {
                for range in &phase.undecided {
                    unheard.insert_range(*range);
                }
            }
        }
        unheard.canonicalize();
        Self(unheard)
    }

    /// Whether no phase heard nothing from anything, so nothing is dropped.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `host` is a record to drop: one still
    /// [`Unknown`](HostStatus::Unknown) at an address heard nothing from.
    ///
    /// A host that answered in any phase or merged document stays.
    pub(crate) fn drops(&self, host: &Host) -> bool {
        host.status() == HostStatus::Unknown && host.ips().iter().any(|ip| self.0.contains(ip))
    }
}

/// The addresses `hosts` are listed at that fall inside `within`.
///
/// Only these affect subtracting the hosts from `within`, and collecting every address
/// would copy the largest thing in the report. `within` should be merged.
fn listed_within<'h>(hosts: impl Iterator<Item = &'h Host>, within: &IpSet) -> IpSet {
    let mut listed = IpSet::new();
    if within.is_empty() {
        return listed;
    }
    for address in hosts.flat_map(Host::ips) {
        if within.contains(address) {
            listed.insert(*address);
        }
    }
    listed
}

/// Adds every range of `from` to `into`, leaving the merge for later.
fn append(into: &mut IpSet, from: &IpSet) {
    for range in from.v4() {
        into.push_v4_range(*range);
    }
    for range in from.v6() {
        into.push_v6_range(*range);
    }
}

/// Keys hosts by the address each is reported under.
///
/// Two records with the same key are folded, as the live store does.
fn index(hosts: impl IntoIterator<Item = Host>) -> BTreeMap<ScopedIp, Host> {
    let mut indexed: BTreeMap<ScopedIp, Host> = BTreeMap::new();

    for host in hosts {
        match indexed.get_mut(&host.scoped_ip()) {
            Some(existing) => existing.merge(host),
            None => {
                indexed.insert(host.scoped_ip(), host);
            }
        }
    }

    indexed
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

// --------------------------------------------------------------------------
// Naming the strategies
// --------------------------------------------------------------------------
//
// Which strategy a failure, refusal or set of counters belongs to.

/// Which scanning strategy a [`ScanEvent::ScannerFailed`](crate::scanner::session::ScanEvent::ScannerFailed) refers to.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerKind {
    /// Layer-2 discovery (ARP/NDP) on a local segment.
    Local,
    /// Reading a link's own traffic, having sent nothing.
    ///
    /// Sends nothing, so `sends_attempted` is always zero, and a quiet run means a quiet
    /// segment, not an absent host.
    Passive,
    /// Raw TCP SYN discovery for gateway-routed targets.
    Routed,
    /// The same sweep asking over SCTP: one INIT per address, for a scan whose
    /// ports name SCTP.
    ///
    /// Separate from [`Routed`](Self::Routed): a host behind a filter that passes SCTP
    /// and drops TCP answers only this.
    RoutedSctp,
    /// Raw TCP SYN port scanning (the port-scan phase, distinct from [`Routed`]
    /// host discovery).
    ///
    /// [`Routed`]: ScannerKind::Routed
    SynPort,
    /// Raw TCP port scanning with a probe that is not a SYN - a FIN, a flagless
    /// segment, a bare ACK.
    ///
    /// The same scanner as [`SynPort`], named apart because no half-open connection was
    /// attempted. The technique is in the phase's settings.
    ///
    /// [`SynPort`]: ScannerKind::SynPort
    TcpPort,
    /// Unprivileged TCP connect fallback, for both host discovery and port
    /// scanning.
    Connect,
    /// Unprivileged UDP fallback.
    ///
    /// Separate from [`Connect`], so a report says which half of an unprivileged scan
    /// failed.
    ///
    /// [`Connect`]: ScannerKind::Connect
    ConnectUdp,
    /// Privileged raw UDP port scanning.
    UdpPort,
    /// Privileged raw SCTP port scanning: an INIT chunk per port, classified by
    /// the chunk that answers it.
    ///
    /// No unprivileged fallback and no service pass, so its failure means the SCTP ports
    /// went unprobed.
    SctpPort,
    /// The active operating-system echo probe, sent at the hosts the passive
    /// sources could not name.
    ///
    /// Establishes no port state; it asks which stack answers the ping.
    OsEcho,
    /// The active operating-system series probe: one host asked the same
    /// question several times, so the policies behind its counters become
    /// visible.
    ///
    /// Sends the same segment as [`SynPort`] but revisits settled ports, and no reply
    /// changes a port's state.
    ///
    /// [`SynPort`]: ScannerKind::SynPort
    OsSeries,
    /// The active operating-system management probe: one SNMP `GetRequest` at a
    /// host whose kernel is not otherwise known.
    ///
    /// Establishes no port state; the answer is filed against the *host*.
    OsSnmp,
    /// The idle (zombie) TCP port scan: port states read off a third party's
    /// IP-ID counter rather than from any reply the target sent this scanner.
    ///
    /// Separate from [`SynPort`](Self::SynPort): verdicts are only `Open` or
    /// `ClosedOrNoReply`, and a run is refused without a suitable zombie or an Ethernet
    /// path.
    Idle,
    /// Composite scanner that delegates to protocol-specific scanners.
    Composite,
    /// The service-identification pass, which opens a connection to each open
    /// port a raw scan classified without ever holding one, and the same
    /// identification made inline over the connection a connect scan found a
    /// port open on, wherever what it left is about services rather than
    /// states.
    ///
    /// Separate from [`Connect`]: a connect failure loses port *states*; this losing
    /// work leaves states standing and services unidentified.
    ///
    /// [`Connect`]: ScannerKind::Connect
    Service,
    /// The detection pass, which runs the authored corpus over the services the
    /// scan identified.
    ///
    /// Separate from [`Service`], since it can fail alone and lose only findings.
    ///
    /// [`Service`]: ScannerKind::Service
    Detection,
    /// The journal a scan was writing itself into.
    ///
    /// Not a strategy; here because failures are the channel every consumer reads. A
    /// failed checkpoint costs only what a *resume* would have skipped.
    Journal,
    /// The hostname resolver a scan names its hosts with: the passive one
    /// that reads a link's DNS and mDNS, or the reverse lookups asked of the
    /// system's resolver.
    ///
    /// Loses only names; without this, missing hostnames would read as hosts that have
    /// none.
    Resolver,
}

/// What a `CongestionWindow` did over one run.
///
/// Says whether pacing engaged and how hard, which tells "this host is firewalled" from
/// "this host was asked too fast".
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowSummary {
    /// The window at the end of the run.
    pub capacity: usize,
    /// The largest it reached.
    pub peak: usize,
    /// How many times it was cut.
    pub reductions: u32,
    /// Whether it was allowed to move at all.
    pub adaptive: bool,
    /// Whether it finished cut back as far as it is permitted to go.
    ///
    /// The scan was still being outrun when it stopped, so recorded silence may be loss.
    /// The remedy is a narrower scan.
    pub at_floor: bool,
}

impl WindowSummary {
    /// A summary from what a window did: where it started, the widest it
    /// reached, how often it was cut, whether it could move at all, and
    /// whether it ended at its floor.
    pub const fn new(
        capacity: usize,
        peak: usize,
        reductions: u32,
        adaptive: bool,
        at_floor: bool,
    ) -> Self {
        Self {
            capacity,
            peak,
            reductions,
            adaptive,
            at_floor,
        }
    }
}

impl ScannerKind {
    /// Every strategy this build knows, in declaration order. Checked against the
    /// published schema.
    pub const ALL: &'static [Self] = &[
        Self::Local,
        Self::Passive,
        Self::Routed,
        Self::RoutedSctp,
        Self::SynPort,
        Self::TcpPort,
        Self::Connect,
        Self::ConnectUdp,
        Self::UdpPort,
        Self::SctpPort,
        Self::OsEcho,
        Self::OsSeries,
        Self::OsSnmp,
        Self::Idle,
        Self::Composite,
        Self::Service,
        Self::Detection,
        Self::Journal,
        Self::Resolver,
    ];

    /// What a raw TCP scan carrying `technique` reports itself as.
    ///
    /// Shared by the plan and the running scanner, so a strategy files its failures
    /// under one name.
    pub const fn for_raw_tcp(technique: TcpScanTechnique) -> Self {
        match technique {
            TcpScanTechnique::Syn => Self::SynPort,
            _ => Self::TcpPort,
        }
    }
}

impl fmt::Display for WindowSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.adaptive {
            return write!(f, "fixed {}", self.capacity);
        }
        write!(
            f,
            "{} (peak {}, cut {}x){}",
            self.capacity,
            self.peak,
            self.reductions,
            if self.at_floor { " at floor" } else { "" }
        )
    }
}

#[cfg(test)]
mod tests {

    /// A run with no elapsed time has no achieved rate.
    #[test]
    fn a_scanners_achieved_send_rate_is_its_sends_over_its_run() {
        let mut stats = crate::export::fixture::probe_stats();
        stats.sends_attempted = 500;
        stats.elapsed = Duration::from_millis(250);
        assert_eq!(stats.achieved_send_rate(), Some(2000.0));

        stats.elapsed = Duration::ZERO;
        assert_eq!(stats.achieved_send_rate(), None);
    }

    /// A phase counts every address its policy kept out, each once, including neighbours
    /// and addresses an excluded machine answered from.
    #[test]
    fn a_phase_counts_every_address_its_policy_withheld_once() {
        let address = |text: &str| -> IpAddr { text.parse().expect("literal") };
        let mut targets = IpSet::new();
        targets.insert_range("192.0.2.0/29".parse().expect("a valid range"));
        let mut named = IpSet::new();
        named.insert(address("192.0.2.5"));
        // The machine at .5, as the tables tied it before the phase began: its
        // global IPv6 address, which is no target of the phase.
        let policy = Exclusions::new(named).widened([address("2001:db8::5")]);

        let mut scope = TargetScope::from_ip_set(&mut targets, &policy);
        assert_eq!(scope.withheld(), 1, "the one target the policy names");

        scope.record_withheld(
            // Tied before the phase, and heard during it.
            vec![address("2001:db8::5"), address("fe80::5")],
            // Kept from the sweep's neighbour-table candidates.
            vec![address("2001:db8::5")],
        );

        assert_eq!(
            scope.withheld(),
            3,
            "the target, the neighbour kept from the sweep and the address heard"
        );
        let excluded: Vec<IpAddr> = scope
            .excluded()
            .iter()
            .map(|range| range.start_addr())
            .collect();
        assert_eq!(
            excluded,
            vec![
                address("192.0.2.5"),
                address("2001:db8::5"),
                address("fe80::5")
            ]
        );
    }

    /// A uniform port set can say an endpoint was probed; a mixed one cannot.
    #[test]
    fn a_scope_says_whether_its_addresses_agree_about_ports() {
        use crate::model::parse::ip::to_set;
        use crate::model::port::PortSet;
        use crate::model::target::TargetSet;

        let unit = |cidr: &str, ports: &str| {
            TargetSet::new(
                to_set(&[cidr], None, None).expect("a range"),
                PortSet::try_from(ports).expect("a port specification"),
            )
        };

        let mut same = TargetMap::new();
        same.add_unit(unit("192.0.2.0/30", "80,443"));
        same.add_unit(unit("198.51.100.0/30", "80,443"));
        let scope = TargetScope::from_target_map(&mut same, &Exclusions::none());
        assert_eq!(
            scope.ports().covers(443, Protocol::Tcp),
            Some(true),
            "every address was walked for it"
        );
        assert_eq!(scope.ports().covers(8080, Protocol::Tcp), Some(false));

        let mut differing = TargetMap::new();
        differing.add_unit(unit("192.0.2.0/30", "80,443"));
        differing.add_unit(unit("198.51.100.0/30", "8080"));
        let scope = TargetScope::from_target_map(&mut differing, &Exclusions::none());
        assert_eq!(
            scope.ports().covers(8080, Protocol::Tcp),
            None,
            "walked for one unit and not the other, so the scope cannot say"
        );
        assert_eq!(
            scope.ports().covers(9999, Protocol::Tcp),
            Some(false),
            "absent from the union means walked for no address at all"
        );
    }

    /// A sweep's scope is `NoPorts`, not `Unstated`.
    #[test]
    fn a_discovery_sweep_walked_no_ports_and_says_so() {
        let mut ips = crate::model::parse::ip::to_set(&["192.0.2.0/30"], None, None).unwrap();
        let scope = TargetScope::from_ip_set(&mut ips, &Exclusions::none());

        assert_eq!(*scope.ports(), PortScope::NoPorts);
        assert_eq!(scope.ports().covers(80, Protocol::Tcp), Some(false));
    }
    use super::*;
    use crate::model::ip::range::Ipv4Range;
    use crate::model::port::{Port, PortSet, Service};
    use crate::model::target::TargetSet;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    fn phase(kind: ScanKind) -> ScanPhase {
        ScanPhase {
            open: false,
            attachments: Vec::new(),
            kind,
            started_at: SystemTime::UNIX_EPOCH,
            elapsed: Duration::from_millis(500),
            privilege: Some(Privilege::Raw),
            targets: TargetScope::from_ip_set(&mut IpSet::new(), &Exclusions::none()),
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            refusals: Vec::new(),
            unroutable: Vec::new(),
            refused_by_route: Vec::new(),
            timed_out: Vec::new(),
            icmp_rate_limited: Vec::new(),
            reached_by_connect: Vec::new(),
            undecided: Vec::new(),
            liveness_skipped: None,
            silent: Vec::new(),
            stopped: None,
            passes_cut: Vec::new(),
            unreached: 0,
            unheard_probes: 0,
            probes: Vec::new(),
            origin: None,
        }
    }

    /// A port phase that stood in for a dropped liveness pass, naming `silent`
    /// the addresses it asked and heard nothing from.
    fn standing_in(silent: &[u8]) -> ScanPhase {
        let mut phase = phase(ScanKind::PortScan);
        phase.liveness_skipped = Some(LivenessSkip::PortsNoDearer);
        phase.silent = silent
            .iter()
            .map(|&last| {
                let v4 = Ipv4Addr::new(203, 0, 113, last);
                IpRange::V4(Ipv4Range::new(v4, v4).expect("a range"))
            })
            .collect();
        phase
    }

    /// A host the scanners filed at an address, and nothing heard from it.
    fn unheard(last: u8) -> Host {
        let mut host = Host::new(ip(last));
        host.add_port(Port::new(443, Protocol::Tcp, PortState::NoReply));
        host
    }

    /// **A live host inside an undecided range closes it, and only hosts inside are
    /// gathered.**
    #[test]
    fn only_a_live_host_inside_what_was_left_open_is_gathered_to_close_it() {
        use crate::model::ip::set::ranges_added;

        let mut sweep = phase(ScanKind::Discovery);
        let (first, last) = (Ipv4Addr::new(203, 0, 113, 0), Ipv4Addr::new(203, 0, 113, 9));
        sweep
            .undecided
            .push(IpRange::V4(Ipv4Range::new(first, last).expect("a range")));

        let alive = |ip: IpAddr| {
            let mut host = Host::new(ip);
            host.set_status(HostStatus::Up);
            host
        };
        let outside: Vec<Host> = (0..=255)
            .map(|last| alive(IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))))
            .collect();
        let inside = alive(ip(5));

        let mut open = IpSet::new();
        open.insert_range(sweep.undecided[0]);
        open.canonicalize();
        let hosts = [&inside].into_iter().chain(&outside);
        assert_eq!(listed_within(hosts, &open).len(), 1);

        let live_outside = outside.len();
        let report = ScanReport::new(sweep, outside.into_iter().chain([inside]));
        let v4 = |a, b| IpRange::V4(Ipv4Range::new(ip4(a), ip4(b)).expect("a range"));
        let before = ranges_added::so_far();
        assert_eq!(report.undecided(), [v4(0, 4), v4(6, 9)]);
        let added = ranges_added::so_far() - before;
        assert!(
            added < live_outside,
            "{added} ranges were gathered to close what was left open, beside \
             {live_outside} live hosts outside it"
        );
    }

    fn ip4(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    /// Unasked ports count only on hosts that some phase could route to.
    #[test]
    fn ports_left_unasked_count_only_on_a_host_the_scan_could_reach() {
        let unasked = |last| {
            let mut host = Host::new(ip(last));
            host.set_status(HostStatus::Up);
            host.add_port(Port::new(22, Protocol::Tcp, PortState::Unasked));
            host
        };
        let mut sweep = phase(ScanKind::Discovery);
        sweep.unroutable.push(ip(1));

        assert!(!ScanReport::new(sweep.clone(), [unasked(1)]).left_ports_unasked());
        assert!(ScanReport::new(sweep.clone(), [unasked(1), unasked(2)]).left_ports_unasked());

        let mut asked = Host::new(ip(3));
        asked.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        assert!(!ScanReport::new(sweep, [asked]).left_ports_unasked());
    }

    /// **A report with no port unasked reads no host addresses; one with some reads only
    /// the hosts holding one.**
    #[test]
    fn ports_left_unasked_are_looked_for_without_reading_every_host() {
        use crate::model::host::address_reads;

        let asked: Vec<Host> = (0..=255)
            .map(|last| {
                let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, last)));
                host.set_status(HostStatus::Up);
                host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
                host
            })
            .collect();
        let mut unasked = Host::new(ip(1));
        unasked.set_status(HostStatus::Up);
        unasked.add_port(Port::new(22, Protocol::Tcp, PortState::Unasked));

        let nothing_left = ScanReport::new(phase(ScanKind::PortScan), asked.clone());
        let before = address_reads::so_far();
        assert!(!nothing_left.left_ports_unasked());
        assert_eq!(
            address_reads::so_far() - before,
            0,
            "a report that left nothing unasked read its hosts' addresses"
        );

        let one_left = ScanReport::new(
            phase(ScanKind::PortScan),
            asked.into_iter().chain([unasked]),
        );
        let before = address_reads::so_far();
        assert!(one_left.left_ports_unasked());
        assert_eq!(
            address_reads::so_far() - before,
            1,
            "addresses were read beyond the one host with a port unasked"
        );
    }

    /// A silent or undecided address of a port phase standing in for liveness is not a
    /// host. A host that answered is kept, as is an unanswering one at an address the
    /// phase does not name, and a discovery phase's undecided addresses keep their
    /// records.
    #[test]
    fn a_host_nothing_answered_at_an_undecided_address_is_not_a_host() {
        let mut ports = standing_in(&[]);
        let mut sweep = phase(ScanKind::Discovery);
        for (phase, last) in [(&mut ports, 5), (&mut sweep, 9)] {
            let v4 = Ipv4Addr::new(203, 0, 113, last);
            phase
                .undecided
                .push(IpRange::V4(Ipv4Range::new(v4, v4).expect("a range")));
        }

        let report = ScanReport::new(ports, [unheard(5)]);
        assert!(
            report.host(&ip(5)).is_none(),
            "an undecided address is no host"
        );
        let report = ScanReport::new(sweep, [unheard(9)]);
        assert!(report.host(&ip(9)).is_some());
    }

    #[test]
    fn a_host_nothing_answered_at_a_silent_address_is_not_a_host() {
        let mut up = Host::new(ip(1));
        up.set_status(HostStatus::Up);

        let report = ScanReport::new(standing_in(&[5]), [up, unheard(5), unheard(9)]);

        assert!(report.host(&ip(5)).is_none(), "a silent address is no host");
        assert!(
            report.host(&ip(1)).is_some(),
            "a host that answered is kept"
        );
        assert!(
            report.host(&ip(9)).is_some(),
            "an address the phase does not name silent keeps its record"
        );
    }

    /// A journal record written before its address was found silent is still dropped.
    #[test]
    fn a_journalled_record_at_a_silent_address_is_dropped_on_read_back() {
        let resumed = ScanReport::from_phases(vec![standing_in(&[5])], [unheard(5)]);
        assert!(resumed.host(&ip(5)).is_none());

        let recorded = ScanReport::recorded("0.17.0", vec![standing_in(&[5])], [unheard(5)]);
        assert!(recorded.host(&ip(5)).is_none());
    }

    /// A host heard from elsewhere stays a host after a merge with a phase that found
    /// its address silent.
    #[test]
    fn a_host_heard_elsewhere_survives_a_phase_that_found_it_silent() {
        let mut up = Host::new(ip(5));
        up.set_status(HostStatus::Up);
        let mut earlier = ScanReport::new(phase(ScanKind::Discovery), [up]);

        earlier.merge(ScanReport::new(standing_in(&[5]), [unheard(5)]));

        assert!(
            earlier
                .host(&ip(5))
                .is_some_and(|host| host.status() == HostStatus::Up),
            "the merge kept the host an earlier phase heard"
        );
    }

    /// A phase whose end overflows `SystemTime` is placed at its start, without
    /// panicking. An nmap XML `elapsed="1222222222…"` is enough to reach it, through
    /// `ScanDiff::between`.
    #[test]
    fn a_phase_claiming_more_time_than_a_clock_holds_does_not_end_the_process() {
        let mut absurd = phase(ScanKind::PortScan);
        absurd.started_at = SystemTime::UNIX_EPOCH;
        absurd.elapsed = Duration::from_secs(u64::MAX);

        let ordinary = phase(ScanKind::Discovery);
        let ends_at = ordinary.started_at + ordinary.elapsed;

        let report = ScanReport::recorded("zond", vec![absurd, ordinary], Vec::new());

        assert_eq!(
            report.finished_at(),
            ends_at,
            "the phase that could be placed is the one that should place the report"
        );

        // The comparison that reads it.
        assert!(crate::diff::ScanDiff::between(&report, &report).is_empty());
    }

    fn ip_set(spec: &str) -> IpSet {
        let mut set = IpSet::new();
        set.insert_range(IpRange::from_str(spec).expect("valid range"));
        set
    }

    #[test]
    fn scope_merges_overlapping_ranges_before_counting() {
        let mut ips = ip_set("203.0.113.0/24");
        ips.insert_range(IpRange::from_str("203.0.113.128/25").expect("valid range"));

        let scope = TargetScope::from_ip_set(&mut ips, &Exclusions::none());

        // The second range is inside the first, so the scope is one /24.
        assert_eq!(scope.ranges().len(), 1);
        assert_eq!(scope.addresses(), 256);
        assert_eq!(scope.probes(), None);
        assert!(scope.protocols().is_empty());
    }

    #[test]
    fn port_scan_scope_counts_probes_not_addresses() {
        let ports = PortSet::from_iter([
            (80, Protocol::Tcp),
            (443, Protocol::Tcp),
            (53, Protocol::Udp),
        ]);

        let mut targets = TargetMap::new();
        targets.add_unit(TargetSet::new(ip_set("192.0.2.1-192.0.2.4"), ports));

        let scope = TargetScope::from_target_map(&mut targets, &Exclusions::none());

        assert_eq!(scope.addresses(), 4);
        assert_eq!(scope.probes(), Some(12));
        assert_eq!(scope.protocols(), &[Protocol::Tcp, Protocol::Udp]);
    }

    /// A run that put something different on the wire records different settings.
    #[test]
    fn settings_record_what_changed_the_scan() {
        let scanning = ZondConfig {
            no_dns: true,
            ..Default::default()
        };

        assert_ne!(
            ScanSettings::from(&scanning),
            ScanSettings::from(&ZondConfig::default())
        );
    }

    #[test]
    fn summary_counts_states_and_services() {
        let mut up = Host::new(ip(1));
        up.set_status(HostStatus::Up);
        up.add_port(
            Port::new(22, Protocol::Tcp, PortState::Open).with_service(Service::new("ssh", 90)),
        );
        up.add_port(Port::new(80, Protocol::Tcp, PortState::Open));
        up.add_port(Port::new(81, Protocol::Tcp, PortState::NoReply));

        let mut blocked = Host::new(ip(2));
        blocked.set_status(HostStatus::Blocked);

        let mut down = Host::new(ip(3));
        down.set_status(HostStatus::Down);

        let report = ScanReport::new(phase(ScanKind::PortScan), [up, blocked, down]);
        let summary = report.summary();

        assert_eq!(summary.hosts_total, 3);
        assert_eq!(summary.hosts_alive, 2);
        assert_eq!(summary.hosts_by_status[&HostStatus::Up], 1);
        assert_eq!(summary.hosts_by_status[&HostStatus::Down], 1);
        assert_eq!(summary.ports_total, 3);
        assert_eq!(summary.ports_open, 2);
        assert_eq!(summary.ports_by_state[&PortState::NoReply], 1);
        assert_eq!(summary.services_identified, 1);
    }

    /// Names inferred from port numbers are not counted as identified.
    #[test]
    fn summary_counts_no_name_read_off_a_port_number_as_identified() {
        let mut host = Host::new(ip(1));
        host.set_status(HostStatus::Up);
        host.add_port(
            Port::new(22, Protocol::Tcp, PortState::Open).with_service(Service::new("ssh", 90)),
        );
        host.add_port(
            Port::new(80, Protocol::Tcp, PortState::Open).with_service(Service::new("http", 0)),
        );
        host.add_port(
            Port::new(23, Protocol::Tcp, PortState::Closed).with_service(Service::new("telnet", 0)),
        );

        let summary = ScanReport::new(phase(ScanKind::PortScan), [host]).summary();

        assert_eq!(summary.services_identified, 1);
    }

    /// Only alive hosts become port-scan targets.
    #[test]
    fn only_hosts_that_answered_become_port_scan_targets() {
        let mut up = Host::new(ip(1));
        up.set_status(HostStatus::Up);
        let mut blocked = Host::new(ip(2));
        blocked.set_status(HostStatus::Blocked);
        let mut down = Host::new(ip(3));
        down.set_status(HostStatus::Down);
        let unknown = Host::new(ip(4));

        let report = ScanReport::new(phase(ScanKind::Discovery), [up, blocked, down, unknown]);

        let targets = report.alive_targets(PortSet::from_iter([(80, Protocol::Tcp)]));

        // Up and Blocked are alive; Down and Unknown are not.
        assert_eq!(targets.gross_ips().expect("countable"), 2);
        assert_eq!(targets.gross_targets().expect("countable"), 2);
    }

    /// A dual-stack host is scanned once, at its primary address.
    #[test]
    fn a_dual_stack_host_is_scanned_once() {
        let mut dual = Host::new(ip(1));
        dual.set_status(HostStatus::Up);
        dual.add_ip(IpAddr::from_str("2001:db8::1").unwrap());

        let report = ScanReport::new(phase(ScanKind::Discovery), [dual]);
        let targets = report.alive_targets(PortSet::from_iter([(80, Protocol::Tcp)]));

        assert_eq!(targets.gross_ips().expect("countable"), 1);
    }

    /// A link-local target carries the zone the sweep found it on.
    #[test]
    fn a_link_local_target_keeps_the_interface_it_was_found_on() {
        let lla: IpAddr = "fe80::10".parse().unwrap();
        let mut host = Host::new(lla);
        host.set_status(HostStatus::Up);
        host.set_zone(Zone::new(7, "en0"));

        let report = ScanReport::new(phase(ScanKind::Discovery), [host]);
        let targets = report.alive_targets(PortSet::from_iter([(80, Protocol::Tcp)]));

        let zones: Vec<Option<u32>> = targets
            .units
            .iter()
            .flat_map(|unit| unit.ips().v6().iter().map(|range| range.zone()))
            .collect();
        assert_eq!(zones, vec![Some(7)]);
    }

    /// A sweep that found nothing yields no units.
    #[test]
    fn a_sweep_that_found_nothing_yields_no_targets() {
        let report = ScanReport::new(phase(ScanKind::Discovery), [Host::new(ip(1))]);
        let targets = report.alive_targets(PortSet::from_iter([(80, Protocol::Tcp)]));

        assert!(targets.is_empty());
        assert!(targets.units.is_empty());
    }

    #[test]
    fn hosts_are_ordered_by_ip_regardless_of_discovery_order() {
        let scrambled = [Host::new(ip(30)), Host::new(ip(2)), Host::new(ip(17))];
        let report = ScanReport::new(phase(ScanKind::Discovery), scrambled);

        let order: Vec<IpAddr> = report.hosts().map(Host::primary_ip).collect();
        assert_eq!(order, vec![ip(2), ip(17), ip(30)]);
    }

    #[test]
    fn merge_combines_hosts_and_keeps_phase_order() {
        let mut discovered = Host::new(ip(1));
        discovered.set_status(HostStatus::Up);
        discovered.add_rtt(Duration::from_millis(3));
        let mut first = ScanReport::new(phase(ScanKind::Discovery), [discovered]);

        let mut scanned = Host::new(ip(1));
        scanned.add_port(Port::new(443, Protocol::Tcp, PortState::Open));
        let second = ScanReport::new(phase(ScanKind::PortScan), [scanned, Host::new(ip(9))]);

        first.merge(second);

        // The port scan's record of .1 has no status or telemetry; the merge keeps
        // discovery's.
        let host = first.host(&ip(1)).expect("host survives the merge");
        assert_eq!(host.status(), HostStatus::Up);
        assert_eq!(host.port_count(), 1);
        assert!(host.min_rtt().is_some());

        assert_eq!(first.host_count(), 2);
        assert_eq!(
            first
                .phases()
                .iter()
                .map(ScanPhase::kind)
                .collect::<Vec<_>>(),
            vec![ScanKind::Discovery, ScanKind::PortScan]
        );
        assert_eq!(first.elapsed(), Duration::from_secs(1));
    }

    #[test]
    fn failures_are_visible_across_phases() {
        let mut failed = phase(ScanKind::Discovery);
        failed.failures.push(ScannerFailure::new(
            ScannerKind::Routed,
            "raw socket unavailable",
        ));

        let clean = ScanReport::new(phase(ScanKind::PortScan), []);
        let mut report = ScanReport::new(failed, []);
        report.merge(clean);

        assert!(report.is_partial());
        assert_eq!(report.failures().count(), 1);
    }

    /// Work cut short by a limit makes the report partial, like a failure.
    #[test]
    fn work_a_limit_cut_short_narrows_the_report_as_a_failure_does() {
        let mut phase = phase(ScanKind::PortScan);
        phase.failures.push(ScannerFailure::cut_short(
            ScannerKind::Connect,
            "1 port left unasked: source port 53 still closing",
        ));
        let report = ScanReport::new(phase, []);

        assert!(report.is_partial());
        let failure = report.failures().next().expect("filed");
        assert!(failure.is_cut_short());
        assert!(!ScannerFailure::new(ScannerKind::Connect, "refused").is_cut_short());
    }

    /// A cut pass makes the report partial until a later sitting of the same job runs
    /// it; another document's scan does not close it.
    #[test]
    fn a_pass_a_stop_cut_makes_a_scan_partial_until_a_later_sitting_runs_it() {
        let stopped = |passes: Vec<Pass>, origin: Option<PhaseOrigin>| {
            let recorded = phase(ScanKind::PortScan);
            ScanPhase {
                passes_cut: passes,
                origin,
                ..recorded
            }
        };

        let cut = ScanReport::new(stopped(vec![Pass::Detections, Pass::Services], None), []);
        assert!(cut.is_partial());
        assert_eq!(cut.passes_cut(), [Pass::Services, Pass::Detections]);

        let mut resumed = cut.clone();
        resumed.merge(ScanReport::new(stopped(Vec::new(), None), []));
        assert!(!resumed.is_partial(), "the next sitting ran them");

        let mut merged = cut;
        merged.merge(ScanReport::new(
            stopped(
                Vec::new(),
                Some(PhaseOrigin::new("0.18").with_label("elsewhere")),
            ),
            [],
        ));
        assert!(merged.is_partial(), "another account says nothing of them");
    }

    /// A journal that could not be written is kept in the report and does not
    /// make a scan that covered everything read as partial.
    #[test]
    fn a_journal_that_could_not_be_written_does_not_make_a_scan_partial() {
        let mut phase = phase(ScanKind::PortScan);
        phase.failures.push(ScannerFailure::new(
            ScannerKind::Journal,
            "checkpoint failed: no space left on device",
        ));
        let report = ScanReport::new(phase, []);

        assert_eq!(report.failures().count(), 1, "the failure is kept");
        assert!(!report.is_partial());
    }

    /// **A rebuild reads each distribution for the slots this build counts**, dropping
    /// extra slots and zeroing missing ones.
    #[test]
    fn a_rebuild_fits_each_distribution_to_the_slots_this_build_counts() {
        let parts = |answered_on: Vec<u64>, found_at: Vec<u64>| ProbeStatsParts {
            scanner: ScannerKind::Composite,
            targets: 1,
            stop_reason: StopReason::AllResponded,
            elapsed: Duration::from_secs(1),
            sends_attempted: 0,
            sends_failed: 0,
            sends_witnessed: 0,
            segments_seen: 0,
            window: None,
            segments_off_target: 0,
            replies_without_rtt: 0,
            refusals_unattributed: 0,
            hosts_found: 0,
            answered_on,
            answered_unattributed: 0,
            first_reply: None,
            last_reply: None,
            found_at,
            capture: None,
        };

        let longer = ProbeStats::from_parts(parts(
            (1..=ATTEMPTS_COUNTED as u64 + 1).collect(),
            (1..=BUCKET_BOUNDS_MS.len() as u64 + 2).collect(),
        ));
        assert_eq!(
            longer.answered_on(),
            (1..=ATTEMPTS_COUNTED as u64).collect::<Vec<_>>()
        );
        assert_eq!(
            longer.found_at(),
            (1..=BUCKET_BOUNDS_MS.len() as u64 + 1).collect::<Vec<_>>()
        );

        let shorter = ProbeStats::from_parts(parts(vec![7], vec![3, 4]));
        assert_eq!(shorter.answered_on().len(), ATTEMPTS_COUNTED);
        assert_eq!(shorter.answered_on()[..2], [7, 0]);
        assert_eq!(shorter.found_at().len(), BUCKET_BOUNDS_MS.len() + 1);
        assert_eq!(shorter.found_at()[..3], [3, 4, 0]);
    }

    /// A phase without instrumentation reports no counters, not zeros.
    #[test]
    fn an_uninstrumented_phase_reports_no_probe_stats() {
        let report = ScanReport::new(phase(ScanKind::PortScan), []);

        assert!(report.phases()[0].probe_stats().is_empty());
        assert_eq!(report.probe_stats().count(), 0);
    }

    #[test]
    fn a_stop_reason_knows_whether_the_run_finished() {
        assert!(StopReason::AllResponded.is_complete());
        assert!(StopReason::AttemptsSpent.is_complete());
        assert!(!StopReason::DeadlineExpired.is_complete());
        assert!(!StopReason::Aborted.is_complete());
        assert!(!StopReason::StreamClosed.is_complete());
        assert!(!StopReason::TimedOut.is_complete());
    }

    /// **A run whose only host a time budget left early is partial.**
    #[test]
    fn a_run_that_left_a_host_early_is_partial() {
        let mut left = phase(ScanKind::PortScan);
        left.timed_out.push(ip(1));

        assert!(ScanReport::new(left, [Host::new(ip(1))]).is_partial());
    }

    /// **A port phase whose walk a stop cut short leaves its report partial**, though
    /// the unreached targets are on no host.
    #[test]
    fn a_phase_that_never_reached_part_of_its_plan_is_partial() {
        let mut stopped = phase(ScanKind::PortScan);
        stopped.stopped = Some(StopReason::Aborted);
        stopped.unreached = 6_600;

        let report = ScanReport::new(stopped, []);

        assert!(report.is_partial());
        assert_eq!(report.unreached(), 6_600);
    }

    /// A phase stopped after reaching everything is not partial.
    #[test]
    fn a_phase_stopped_with_nothing_left_unreached_is_not_partial() {
        let mut stopped = phase(ScanKind::PortScan);
        stopped.stopped = Some(StopReason::TimedOut);

        assert!(!ScanReport::new(stopped, []).is_partial());
    }

    /// **A later sitting of the same job replaces an earlier one's unreached count.**
    #[test]
    fn a_later_sitting_takes_up_what_an_earlier_one_never_reached() {
        let mut first = phase(ScanKind::PortScan);
        first.stopped = Some(StopReason::Aborted);
        first.unreached = 6_600;

        let mut finished = ScanReport::new(first.clone(), []);
        finished.merge(ScanReport::new(phase(ScanKind::Discovery), []));
        finished.merge(ScanReport::new(phase(ScanKind::PortScan), []));
        assert_eq!(finished.unreached(), 0);
        assert!(!finished.is_partial());

        let mut again = phase(ScanKind::PortScan);
        again.stopped = Some(StopReason::Aborted);
        again.unreached = 1_200;
        let mut stopped_twice = ScanReport::new(first, []);
        stopped_twice.merge(ScanReport::new(again, []));
        assert_eq!(stopped_twice.unreached(), 1_200);
    }

    /// Across documents an unreached count stands.
    #[test]
    fn another_documents_scan_does_not_take_up_a_count() {
        let mut first = phase(ScanKind::PortScan);
        first.unreached = 6_600;
        first.origin = Some(PhaseOrigin::new("0.18.0").with_label("monday.json"));
        let mut later = phase(ScanKind::PortScan);
        later.origin = Some(PhaseOrigin::new("0.18.0").with_label("tuesday.json"));

        let mut merged = ScanReport::new(first, []);
        merged.merge(ScanReport::new(later, []));

        assert_eq!(merged.unreached(), 6_600);
        assert!(merged.is_partial());
    }

    /// A port-scan phase that walked `walked` and left `left` early, begun
    /// `at` seconds into the epoch.
    fn walked(at: u64, walked: &str, left: &[IpAddr]) -> ScanPhase {
        let mut ips: IpSet = walked.parse().expect("a range");
        ScanPhase {
            started_at: SystemTime::UNIX_EPOCH + Duration::from_secs(at),
            targets: TargetScope::from_ip_set(&mut ips, &Exclusions::none()),
            timed_out: left.to_vec(),
            ..phase(ScanKind::PortScan)
        }
    }

    /// **A host a later sitting finished is not left early**, though the first sitting
    /// still names it.
    #[test]
    fn a_host_a_later_sitting_finished_is_not_left_early() {
        let mut report = ScanReport::new(walked(1, "203.0.113.1", &[ip(1)]), []);
        report.merge(ScanReport::new(walked(2, "203.0.113.1", &[]), []));
        assert!(report.timed_out().is_empty());
        assert!(!report.is_partial());

        let mut again = ScanReport::new(walked(1, "203.0.113.1", &[ip(1)]), []);
        again.merge(ScanReport::new(walked(2, "203.0.113.1", &[ip(1)]), []));
        assert_eq!(again.timed_out(), [ip(1)], "left early both times");
        assert!(again.is_partial());
    }

    /// Every shortfall makes a report partial; uncoverable ground does not.
    #[test]
    fn every_recorded_shortfall_is_partial_and_an_unreachable_address_is_not() {
        let refused = {
            let mut phase = phase(ScanKind::Discovery);
            phase
                .refusals
                .push(Refusal::new(ScannerKind::Connect, "too large to sweep"));
            ScanReport::new(phase, [])
        };
        assert!(
            refused.is_partial(),
            "ground declined is ground not covered"
        );

        let undecided = {
            let mut phase = phase(ScanKind::Discovery);
            phase.undecided.push(IpRange::V4(
                Ipv4Range::new(Ipv4Addr::new(192, 0, 2, 4), Ipv4Addr::new(192, 0, 2, 7))
                    .expect("a range"),
            ));
            ScanReport::new(phase, [])
        };
        assert!(undecided.is_partial(), "an address nobody decided");

        let mut unasked = Host::new(ip(1));
        unasked.add_port(Port::new(443, Protocol::Tcp, PortState::Unasked));
        let cut_short = ScanReport::new(phase(ScanKind::PortScan), [unasked.clone()]);
        assert!(cut_short.is_partial(), "a port named and never asked");

        let mut no_route = phase(ScanKind::PortScan);
        no_route.unroutable.push(ip(1));
        let unreachable = ScanReport::new(no_route, [unasked]);
        assert!(
            !unreachable.is_partial(),
            "a port unasked because nothing could reach its address was never coverable"
        );
    }

    #[test]
    fn a_clean_report_is_not_partial() {
        let report = ScanReport::new(phase(ScanKind::Discovery), []);

        assert!(!report.is_partial());
        assert_eq!(report.failures().count(), 0);
        assert_eq!(report.engine_version(), ENGINE_VERSION);
    }

    #[test]
    fn scope_ranges_cover_both_families() {
        let mut ips = ip_set("192.0.2.0/30");
        ips.insert_range(IpRange::from_str("fe80::/126").expect("valid range"));

        let scope = TargetScope::from_ip_set(&mut ips, &Exclusions::none());

        assert_eq!(scope.addresses(), 8);
        assert!(matches!(scope.ranges()[0], IpRange::V4(_)));
        assert!(matches!(scope.ranges()[1], IpRange::V6(_)));
    }

    #[test]
    fn ipv4_range_scope_reports_its_own_bounds() {
        let mut ips = IpSet::new();
        ips.push_v4_range(
            Ipv4Range::new(Ipv4Addr::new(192, 0, 2, 5), Ipv4Addr::new(192, 0, 2, 9))
                .expect("valid range"),
        );

        let scope = TargetScope::from_ip_set(&mut ips, &Exclusions::none());

        assert_eq!(scope.addresses(), 5);
        assert_eq!(
            scope.ranges()[0].start_addr(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5))
        );
    }

    /// A dual-stack host is one host, counted under both families.
    ///
    /// The counts do not sum to `hosts_total`.
    #[test]
    fn family_counts_record_a_dual_stack_host_under_both() {
        let mut dual = Host::new(ip(1));
        dual.add_ip(IpAddr::from_str("2001:db8::1").unwrap());
        let v6_only = Host::new(IpAddr::from_str("2001:db8::2").unwrap());

        let report = ScanReport::new(
            phase(ScanKind::Discovery),
            [dual, Host::new(ip(2)), v6_only],
        );

        let summary = report.summary();
        assert_eq!(summary.hosts_total, 3);
        assert_eq!(summary.hosts_by_family.ipv4, 2);
        assert_eq!(summary.hosts_by_family.ipv6, 2);
        assert_eq!(summary.hosts_by_family.dual_stack, 1);
    }
}
