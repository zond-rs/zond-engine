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
//! During a scan a caller watches [`ScanSession`](crate::scanner::session::ScanSession) -
//! a live store plus an event stream, both of which describe the present moment
//! and keep no history. A [`ScanReport`] is the other half of that pair. It is
//! produced once, when the scan is over, and it is the only thing that can
//! answer a question asked afterwards: how long the sweep took, whether a
//! strategy failed part way through, how many addresses were actually in scope,
//! which retry budget produced this particular set of hosts.
//!
//! That distinction matters because a bare list of hosts is not a result anyone
//! can act on. "Nine hosts on a /24" means one thing after a
//! [`Thorough`](crate::config::ScanEffort::Thorough) privileged
//! sweep and quite another after an unprivileged connect fallback that lost its
//! routed scanner to a permissions error. The hosts are identical in both; only
//! the report separates them.
//!
//! ## Phases
//!
//! Discovery and port scanning are separate engine calls, and a caller that
//! runs both is describing one job, not two. A report therefore holds a list of
//! [`ScanPhase`] records rather than a single set of metadata, and
//! [`ScanReport::merge`] folds the second call into the first: hosts are
//! merged by [`Host::merge`], phases are appended in the order they ran. A
//! single-phase report is simply the common case of that shape, not a different
//! type.
//!
//! ## Findings and instrumentation
//!
//! A phase carries two different kinds of record and they must not be read as
//! one. The hosts and their ports are findings *about the network*. The
//! [`ProbeStats`] a raw scanner files are measurements *about the scan* - how
//! many probes went out, how many segments came back, why the loop stopped -
//! and they exist to bound how much the findings can be trusted. A sweep that
//! stopped on [`StopReason::DeadlineExpired`] while replies were still arriving
//! found fewer hosts than the network holds, and nothing in the host list says
//! so.
//!
//! ## What is stored and what is derived
//!
//! Only measurements are stored. Every count a consumer might want - hosts up,
//! open ports, services identified - is computed by [`ScanReport::summary`] from
//! the hosts themselves, so a summary cannot drift out of step with the data it
//! describes.
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
use crate::config::{IdleScan, OsDetection, SendMode, ServiceDetection, ZondConfig};
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
use crate::model::technique::TcpScanTechnique;

/// The version of the engine that produced a report.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Which of the two scan phases a [`ScanPhase`] records.
///
/// These are the engine's two entry points, [`discover`](crate::scanner::discover)
/// and [`scan`](crate::scanner::scan), not the individual strategies each one
/// spawns. Which strategies ran is a property of the host and its privileges;
/// see [`ScannerKind`] for the granularity at which failures are reported.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScanKind {
    /// Establishing which hosts in a target range are alive.
    Discovery,
    /// Classifying the ports of a known set of hosts.
    PortScan,
    /// Reading what a link already carries, having sent nothing.
    ///
    /// Unlike the other two, this phase covers no address — see
    /// [`TargetScope::listening_on`]. It can raise a claim and never lower one:
    /// having sent nothing, it cannot have timed anything out, so silence from
    /// an address proves nothing about it.
    Listen,
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

/// Which ports a phase walked, and whether it walked the same ones everywhere.
///
/// A scope records the addresses a phase covered, and for a port scan that is
/// only half the answer: an address is covered *for some ports*, and a consumer
/// asking whether one endpoint was probed needs to know which. This is that
/// second half.
///
/// The four variants are the four honest answers, and the distinctions between
/// them are the whole reason this is not a bare `Option<PortSet>`.
///
/// [`Every`](Self::Every) against [`Mixed`](Self::Mixed): a phase can be given
/// different ports for different addresses — `10.0.0.0/24:80,443` alongside
/// `10.0.1.0/24:8080` is one job with two units — and there is no single set
/// that is true of every address in it. Publishing the union as though there
/// were would have a consumer conclude that `10.0.0.5` was probed on 8080, which
/// nothing did. So the union is published as a union and labelled one.
///
/// [`NoPorts`](Self::NoPorts) against [`Unstated`](Self::Unstated): a discovery
/// sweep walked no ports, which is a fact, and a record that does not say which
/// ports were walked is an absence of one. Only the first supports concluding
/// that an endpoint was not probed. Nothing this engine builds is `Unstated`;
/// it is what a report from another tool, or from a build older than this
/// field, reads back as.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PortScope {
    /// The record does not say which ports were walked.
    ///
    /// Nothing may be concluded about any endpoint. The default, because a
    /// scope rebuilt from a record that predates this field knows nothing about
    /// ports and must not pretend otherwise.
    #[default]
    Unstated,
    /// The phase paired no ports with its addresses, which is what a discovery
    /// sweep does. Its probes are the strategy's choice rather than the
    /// caller's, and no endpoint was probed.
    NoPorts,
    /// Every address the phase walked was walked for these ports.
    ///
    /// The ordinary case for a port scan, and the only variant from which a
    /// consumer may conclude that a particular endpoint of a covered address was
    /// probed.
    Every(PortSet),
    /// Addresses were walked for differing sets of ports, and this is their
    /// union.
    ///
    /// A port here was walked for at least one address and not necessarily for
    /// any given one. A port *not* here was walked for none, which is the one
    /// conclusion this variant does support.
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
    /// `None` is "the record cannot say", which is both a scope that recorded no
    /// ports and one whose addresses were walked for differing sets with this
    /// port among them. `Some(false)` is a real negative: no address in the
    /// phase was walked for this endpoint.
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
/// The ranges are the canonical, merged form the engine actually iterated, not
/// the text a user typed. Overlapping arguments have already been coalesced, so
/// `addresses` is a count of distinct addresses rather than a sum of what was
/// requested, and a report can be trusted when it says a sweep covered 254
/// hosts.
///
/// [`ranges`](Self::ranges) is what was walked *after* the exclusion policy was
/// applied, and [`excluded`](Self::excluded) is that policy. The two together
/// are what makes a report evidence of scope rather than a list of findings: one
/// says where the scan went, the other says where it was told not to, and no
/// host in the report may fall inside the second.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetScope {
    ranges: Vec<IpRange>,
    links: Vec<Zone>,
    /// Links whose traffic was read without anything being sent to them.
    ///
    /// Deliberately not [`links`](Self::links), which means *swept* — a probe
    /// went out that everything on the link was obliged to answer, so a host
    /// there and not in the report is a host that was not there. Nothing of the
    /// kind follows from having listened: a machine that said nothing during
    /// the window is indistinguishable from one that is absent, and there is no
    /// experiment that separates them.
    ///
    /// Recorded because a reader still wants to know where a phase was
    /// standing. It never contributes to coverage, which is what keeps a quiet
    /// host from reading as one that went away.
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
    /// Canonicalizes the set, so the recorded ranges are the merged ones the
    /// sweep iterates rather than the raw arguments it was built from.
    ///
    /// **`ips` comes back narrowed**, with everything `exclusions` forbids taken
    /// out of it, and the scope records what that cost. Applying the policy and
    /// recording it are one call because doing either without the other is the
    /// bug: a scope recorded before the subtraction overstates what was covered,
    /// and a subtraction with no scope to record it leaves a report that cannot
    /// show the exclusion was honoured. There is no way to write one and forget
    /// the other, which is the whole reason this takes `&mut`.
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
    /// **Covers no address, and says so.** A listener did not probe, so it
    /// cannot have timed anything out, so there is no address it can report as
    /// empty. The count is zero and the ranges are none — which is not a
    /// missing measurement but the honest one, and it is what stops a
    /// comparison reading a host that stayed quiet as a host that disappeared.
    ///
    /// The links are recorded as [`listened`](Self::listened) rather than as
    /// [`links`](Self::links), and the distinction is the whole of the above.
    ///
    /// `exclusions` is recorded so the report still shows the policy a passive
    /// phase was run under — it withholds nothing here, because nothing was
    /// enumerated for it to withhold, and it is enforced where it matters at
    /// the point findings are recorded.
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
    /// `probes` counts address/port/protocol combinations, the unit a port scan
    /// is actually billed in. It is `None` when the target map is large enough
    /// to overflow that count, which is a failure to measure and is reported as
    /// one rather than as a plausible-looking number.
    ///
    /// **`targets` comes back narrowed**, on the same terms and for the same
    /// reasons as [`from_ip_set`](Self::from_ip_set). A unit left holding no
    /// address at all is dropped.
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

    /// The transport protocols in scope, in ascending order. Empty for a
    /// discovery sweep, whose probes are chosen by the strategy rather than by
    /// the caller.
    /// The links this phase swept whole, by the interface each is on.
    ///
    /// [`ranges`](Self::ranges) is what a target set named, and for a sweep of a
    /// local segment that is only part of what was covered: an all-nodes
    /// solicitation is one probe every IPv6 neighbour on the link is required to
    /// answer, and it reaches hosts holding addresses nobody could have named in
    /// advance.
    ///
    /// **A link is not an address range and is deliberately not recorded as
    /// one.** `fe80::/64` would be the obvious thing to put in `ranges`, and it
    /// would make [`addresses`](Self::addresses) read eighteen quintillion —
    /// destroying the one property that type has, that a report saying it
    /// covered 254 hosts can be believed. A link is named by its interface, so
    /// that is what is recorded.
    ///
    /// Empty for a phase that swept no segment, which is every port scan and
    /// every sweep of a routed range.
    pub fn links(&self) -> &[Zone] {
        &self.links
    }

    /// The links this phase read traffic from without probing them.
    ///
    /// Never coverage. See the field's own documentation, and
    /// [`listening_on`](Self::listening_on).
    pub fn listened(&self) -> &[Zone] {
        &self.listened
    }

    /// Whether this phase swept the link a host was found on.
    ///
    /// **The question is about the link, not about the addresses on it.** An
    /// all-nodes solicitation reaches every IPv6 host on the segment whatever
    /// addresses it holds, and a host that answers one is routinely keyed under
    /// a global address — this engine prefers a routable address over a
    /// link-local one when both are known. Asking whether the *address* is
    /// link-local would then miss exactly the hosts this exists to cover.
    ///
    /// `zone` is the interface the host was found on, which a record carries
    /// whenever a local scanner put it there. A host with no zone was not found
    /// on a link and is not claimed.
    pub fn swept(&self, zone: Option<&Zone>) -> bool {
        let Some(zone) = zone else {
            return false;
        };

        self.links.iter().any(|link| link.name() == zone.name())
    }

    /// Records that this phase swept a link whole.
    ///
    /// Called once a phase is over, because which links its strategies reached
    /// is only knowable then — the scope itself is fixed before a probe goes
    /// out. See [`PhaseRecorder::finish`].
    pub(crate) fn record_sweeps(&mut self, links: Vec<Zone>) {
        for link in links {
            if !self.links.iter().any(|held| held.name() == link.name()) {
                self.links.push(link);
            }
        }
    }

    /// Which ports the phase walked, and whether it walked the same ones for
    /// every address.
    ///
    /// [`probes`](Self::probes) counts the address-and-port combinations in
    /// scope; this says which ports they were. The two are separate because a
    /// count survives a target set too large to enumerate and a set does not.
    pub fn ports(&self) -> &PortScope {
        &self.ports
    }

    pub fn protocols(&self) -> &[Protocol] {
        &self.protocols
    }

    /// The address ranges the phase was forbidden to probe, in ascending order.
    ///
    /// The exclusion policy that was in force, merged, whether or not it
    /// overlapped anything this phase would have covered. Empty means no policy
    /// was set — not that one was set and did nothing, which is
    /// [`withheld`](Self::withheld) returning zero and is a different fact.
    ///
    /// This is the half of the record a reader can check the engine against.
    /// Every range here is ground the report promises it did not cover, and no
    /// host in the report may fall inside one.
    pub fn excluded(&self) -> &[IpRange] {
        &self.excluded
    }

    /// How many addresses the exclusion policy took out of this phase.
    ///
    /// Measured against what the phase was handed, at the moment its scope was
    /// recorded — so it is the overlap between the policy and this phase's
    /// input, not the size of the policy. Zero from a policy that named ground
    /// this phase was never going to walk, and zero again from a phase whose
    /// input an earlier one had already narrowed.
    ///
    /// It is the difference between a scope document that was applied and one
    /// that was merely configured, and those look identical without it.
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
/// Each field holds the value the scan used for one evasion technique, or `None`
/// where it left the default alone: a scan that pinned a source port but not the
/// hop limit has [`source_port`](Self::source_port) set and [`ttl`](Self::ttl)
/// `None`. A port's state under a probe from source port 53 is a different fact
/// than the same state under an ordinary probe, and this is where a reader tells
/// the two apart.
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
/// A deliberate subset of [`ZondConfig`]: the fields here are the ones that
/// change which packets went out and how long the engine waited for answers, so
/// they are the ones needed to interpret - or reproduce - a result. The rest of
/// the config drives presentation (banner, verbosity, key handling) and has no
/// bearing on the finding, so recording it would only invite a reader to treat
/// a quieter terminal as a different scan.
///
/// Keeping this separate from [`ZondConfig`] also means the two can evolve
/// independently: a new interface knob does not silently become part of every
/// exported report.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanSettings {
    /// How raw probes were placed on the wire.
    pub send_mode: SendMode,
    /// Which segment each TCP port probe carried, and so what its answers mean.
    ///
    /// Two ports both reported `Closed` are different findings depending on
    /// this: one refused a connection attempt, the other reset a segment that
    /// was not one. A report without it cannot be read.
    pub tcp_technique: TcpScanTechnique,
    /// The retransmission budget and patience in force.
    pub retry: RetryConfig,
    /// The probe-rate ceiling, or `None` if the scanner's own default applied.
    pub max_probe_rate: Option<u32>,
    /// Whether name resolution was permitted to generate traffic.
    pub dns_enabled: bool,
    /// Whether the caller asked for identifying detail to be masked.
    pub redact: bool,
    /// How far the phase went to identify the operating system behind each host.
    ///
    /// A host reported without one is a different finding depending on this: at
    /// [`OsDetection::Off`] nothing looked, and at any other level something
    /// looked and found nothing conclusive. The level also bounds how much of
    /// this phase's traffic the engine originated — see
    /// [`OsDetection::is_active`].
    pub os_detection: OsDetection,
    /// How far the phase went to identify what was listening behind each open
    /// port.
    ///
    /// A port reported with no service is a different finding depending on
    /// this: at [`ServiceDetection::Off`] nothing asked, and at any other level
    /// something asked and could not tell. It also says whether the phase
    /// completed a connection to each open port at all, which is what a target's
    /// application logs would have recorded.
    pub service_detection: ServiceDetection,

    /// How intrusive a detection the phase was permitted to run over the services
    /// it identified.
    ///
    /// Recorded because it decides which findings could appear at all: a port
    /// with no vulnerability finding is one thing when the envelope permitted the
    /// detection that would have found one, and another when it withheld it. The
    /// report says which, so a reader is not left to guess whether a clean port
    /// was probed or spared.
    pub detection: DetectionEnvelope,

    /// Whether the phase measured the route to each host that answered.
    ///
    /// Recorded because a host with no path is two different findings: a scan
    /// that did not look, and a scan that looked and got nothing back. Only this
    /// separates them.
    pub traceroute: bool,

    /// Whether the phase characterised the filter in front of each host that
    /// answered.
    ///
    /// Recorded for the same reason as [`traceroute`](Self::traceroute): a host
    /// with no filtering finding is two things — a scan that did not look, and
    /// one that looked and the filter showed nothing — and only this tells them
    /// apart.
    pub characterise: bool,

    /// What the scan changed about the packets it sent, or `None` if it changed
    /// nothing. A filtered port found with a probe from a trusted source port is
    /// a different fact than the same port found with an ordinary probe; see
    /// [`EvasionRecord`].
    pub evasion: Option<EvasionRecord>,

    /// The zombie a TCP port scan read its verdicts through, or `None` for an
    /// ordinary scan. Its presence is what tells a reader the ports were inferred
    /// from a third party's counter rather than from the target's own replies —
    /// which changes what an `open` or a `closed_filtered` means. See
    /// [`IdleScan`].
    pub idle_scan: Option<IdleScan>,
}

impl From<&ZondConfig> for ScanSettings {
    fn from(cfg: &ZondConfig) -> Self {
        Self {
            send_mode: cfg.send_mode,
            tcp_technique: cfg.tcp_technique,
            retry: cfg.retry,
            max_probe_rate: cfg.max_probe_rate,
            dns_enabled: !cfg.no_dns,
            redact: cfg.redact,
            os_detection: cfg.os_detection,
            service_detection: cfg.service_detection,
            detection: cfg.detection,
            traceroute: cfg.traceroute,
            characterise: cfg.characterise,
            evasion: EvasionRecord::from_profile(&cfg.evasion),
            idle_scan: cfg.idle_scan,
        }
    }
}

/// Upper bounds, in milliseconds, of the discovery-time histogram buckets in
/// [`ProbeStats::found_at`]. A final bucket catches everything later than the
/// last bound.
///
/// These measure how far into the run a host was first credited, **not** its
/// round trip. The two diverge exactly where it matters: a host found at 700 ms
/// because its third attempt went out at 690 ms has a 10 ms round trip, and
/// reading the bucket as latency turns a retry schedule into an imaginary slow
/// path. Round trips are reported per host, not here.
///
/// Spaced roughly logarithmically because the question being asked spans three
/// orders of magnitude: a same-segment reply lands under a millisecond, a
/// healthy internet round trip in the tens, and a host recovered by a late
/// retry in the hundreds. A linear scale would put every interesting answer in
/// one bucket.
pub const BUCKET_BOUNDS_MS: [u64; 9] = [1, 2, 5, 10, 25, 50, 100, 250, 1_000];

/// How many attempts [`ProbeStats::answered_on`] counts separately before the
/// rest are lumped together.
///
/// Sized past the largest budget any path runs (five, under
/// [`ScanEffort::Thorough`](crate::config::ScanEffort)), so the
/// distribution is reported in full for every configuration that ships and a
/// hand-raised budget still has somewhere to land.
pub const ATTEMPTS_COUNTED: usize = 6;

/// Why a scanner's receive loop stopped.
///
/// This is the single most informative field in an audit: a run that ends in
/// [`AllResponded`](StopReason::AllResponded) was not cut short by anything, and
/// one that ends in [`DeadlineExpired`](StopReason::DeadlineExpired) with
/// replies still arriving near the end almost certainly was.
///
/// There is deliberately no "still running" variant. A scan loop yields its
/// reason as the value it breaks with, so every exit path has to name one and
/// the audit cannot report a reason the code never took.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StopReason {
    /// The caller aborted the scan through the scan handle.
    Aborted,
    /// Every target answered.
    AllResponded,
    /// Nothing is left outstanding: every target either answered or was asked
    /// as many times as the retry budget allows. Like
    /// [`AllResponded`](StopReason::AllResponded) this is a scan that finished
    /// rather than one that ran out of time, and waiting longer could not have
    /// changed what it found.
    AttemptsSpent,
    /// The adaptive deadline expired: either the hard budget ran out or the
    /// silence tolerance did.
    DeadlineExpired,
    /// The capture stream closed underneath the scanner.
    StreamClosed,
}

impl StopReason {
    /// Whether the loop stopped because it had nothing left to do, rather than
    /// because something cut it short.
    ///
    /// A run that ends complete found everything it was ever going to find;
    /// waiting longer or sending more could not have changed it. One that does
    /// not is a result with a known upper bound on its own trustworthiness.
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
        };
        f.write_str(text)
    }
}

/// What one raw scanner observed about its own run.
///
/// A host count on its own cannot say why a sweep came back short, and the three
/// possible answers call for opposite fixes. Probes or replies may have been
/// **lost**, which is what retransmission exists for; replies may have arrived
/// after the scan had already **stopped**, which makes the deadline wrong rather
/// than the network; or they may have arrived and gone **unrecognized**, which
/// no amount of extra time or extra packets would help.
///
/// These counters separate those. [`sends_attempted`](Self::sends_attempted)
/// against [`segments_seen`](Self::segments_seen) bounds the first,
/// [`stop_reason`](Self::stop_reason) against
/// [`last_reply`](Self::last_reply) bounds the second, and
/// [`segments_off_target`](Self::segments_off_target) with
/// [`replies_without_rtt`](Self::replies_without_rtt) bounds the third.
///
/// One bound is not measurable from inside a scanner at all: a reply the kernel
/// discards because the capture buffer was full never reaches any counter here,
/// so loss on the receive path and loss on the network read identically.
/// [`capture`](Self::capture) is carried for that reason - it is the only place
/// the difference is visible.
///
/// This is instrumentation about the scan, not a finding about the network.
/// Nothing here changes what a scan reports about a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeStats {
    // Written by `ProbeAudit`, which lives in another module and so cannot use
    // private fields. Read-only to the outside world through the accessors
    // below: a consumer must never be able to edit a measurement.
    pub(crate) scanner: ScannerKind,
    pub(crate) targets: u128,
    pub(crate) stop_reason: StopReason,
    pub(crate) elapsed: Duration,
    pub(crate) sends_attempted: u64,
    pub(crate) sends_failed: u64,
    pub(crate) segments_seen: u64,
    pub(crate) segments_off_target: u64,
    pub(crate) replies_without_rtt: u64,
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

    /// Of those, ones the sender refused. A non-zero count means the shortfall
    /// starts at home, before the network is implicated at all.
    pub fn sends_failed(&self) -> u64 {
        self.sends_failed
    }

    /// Segments the capture handed up, before any of the scanner's own checks.
    pub fn segments_seen(&self) -> u64 {
        self.segments_seen
    }

    /// What this run's congestion window did, for a scanner paced by one.
    ///
    /// The difference between "these ports are filtered" and "this scan was
    /// outrun and cannot tell". A run whose window bottomed out and still left
    /// most of its probes unanswered did not establish that anything is
    /// filtered; it established that it could not ask. Nothing else in these
    /// counters distinguishes the two, and a consumer that renders one as the
    /// other is publishing a claim about somebody's firewall that is really a
    /// claim about a saturated link.
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

    /// Targets a reply resolved, counted once each.
    ///
    /// The unit is whatever the scanner's targets are, which is also the unit of
    /// [`targets`](Self::targets), so the two read together as answered against
    /// asked: a host for a discovery sweep, an `(address, port)` probe for a port
    /// scan. Named for the first of those because discovery was the first
    /// strategy to carry an audit.
    ///
    /// This is the number a run is judged on. Read against `targets` it is
    /// coverage; read against [`stop_reason`](Self::stop_reason) and
    /// [`last_reply`](Self::last_reply) it says whether the run was still finding
    /// things when it ended.
    pub fn hosts_found(&self) -> u64 {
        self.hosts_found
    }

    /// Found hosts by the attempt whose reply revealed them.
    ///
    /// Index `i` counts hosts answered on attempt `i + 1`; the last slot counts
    /// attempt [`ATTEMPTS_COUNTED`] *or later*, so a hand-raised retry budget
    /// still has somewhere to land.
    ///
    /// This is what says whether retransmission is earning its traffic. A host
    /// found on its first attempt needed only for the scan to still be
    /// listening; one found on its third needed the packet to be sent again.
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

    /// What the kernel capture reported, where there was one to ask. A scanner
    /// driven by a synthetic receive stream has no kernel buffer, and reports
    /// `None` rather than a clean-looking zero.
    pub fn capture(&self) -> Option<CaptureCounts> {
        self.capture
    }
}

/// A scanning strategy that did not run to completion.
///
/// A scan continues with whatever strategies remain when one of them fails, so
/// a report that carries failures still carries results - just narrower ones
/// than the caller asked for. This is the record that lets a consumer tell a
/// genuinely empty network from a sweep whose raw scanner never started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerFailure {
    scanner: ScannerKind,
    reason: String,
    at: SystemTime,
}

impl ScannerFailure {
    /// Records a failure as having happened now.
    pub fn new(scanner: ScannerKind, reason: impl Into<String>) -> Self {
        Self {
            scanner,
            reason: reason.into(),
            at: SystemTime::now(),
        }
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
    /// [`new`](Self::new) stamps the current time, which is what a running scan
    /// wants. A failure restored from a journal happened when it happened, not
    /// when the record of it was read.
    pub fn recorded_at(mut self, at: SystemTime) -> Self {
        self.at = at;
        self
    }

    /// When the failure was observed.
    pub fn at(&self) -> SystemTime {
        self.at
    }
}

impl fmt::Display for ScannerFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} scanner failed: {}", self.scanner, self.reason)
    }
}

/// Everything a [`TargetScope`] holds, for rebuilding one that was recorded.
///
/// A plain struct rather than positional arguments: two `u128` counts and two
/// range lists sit next to each other, and nothing would diagnose them being
/// swapped.
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
    /// Unlike [`from_ip_set`](Self::from_ip_set), this applies no policy and
    /// narrows nothing: the exclusions were applied when the scope was first
    /// computed, and this restores the result rather than repeating the work.
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
    /// How many of those the host refused.
    pub sends_failed: u64,
    /// How many segments its capture handed it.
    pub segments_seen: u64,
    /// Where its congestion window ended up.
    pub window: Option<WindowSummary>,
    /// How many captured segments belonged to something else.
    pub segments_off_target: u64,
    /// How many replies could not be attributed to one attempt.
    pub replies_without_rtt: u64,
    /// How many hosts it found.
    pub hosts_found: u64,
    /// How many answers arrived on each attempt, one slot per counted attempt.
    pub answered_on: [u64; ATTEMPTS_COUNTED],
    /// How many answers named no attempt.
    pub answered_unattributed: u64,
    /// When the first reply arrived, from the start of the run.
    pub first_reply: Option<Duration>,
    /// When the last one did.
    pub last_reply: Option<Duration>,
    /// How many hosts were found in each time bucket, one slot per bound plus
    /// the tail.
    pub found_at: [u64; BUCKET_BOUNDS_MS.len() + 1],
    /// What the capture reported about its own losses.
    pub capture: Option<CaptureCounts>,
}

impl ProbeStats {
    /// Rebuilds probe statistics from what was recorded of them.
    pub fn from_parts(parts: ProbeStatsParts) -> Self {
        Self {
            scanner: parts.scanner,
            targets: parts.targets,
            stop_reason: parts.stop_reason,
            elapsed: parts.elapsed,
            sends_attempted: parts.sends_attempted,
            sends_failed: parts.sends_failed,
            segments_seen: parts.segments_seen,
            window: parts.window,
            segments_off_target: parts.segments_off_target,
            replies_without_rtt: parts.replies_without_rtt,
            hosts_found: parts.hosts_found,
            answered_on: parts.answered_on,
            answered_unattributed: parts.answered_unattributed,
            first_reply: parts.first_reply,
            last_reply: parts.last_reply,
            found_at: parts.found_at,
            capture: parts.capture,
        }
    }
}

/// Which switch port the machine running a phase was plugged into.
///
/// Not a finding about any host in the report — a relation between *this*
/// machine and somebody else's equipment, learned from an announcement the
/// equipment sends unprompted (see [`crate::protocols::lldp`] and
/// [`crate::protocols::cdp`]). No probe obtains it, and nothing else in a scan
/// answers the question it answers: **where, physically, was this run from.**
///
/// # Why it hangs on the phase
///
/// For the reason [`Origin`] does. A [`merge`](crate::merge) folds phases
/// measured from several vantage points into one report, and each of them ran
/// somewhere different. Recorded once for the whole report, two machines'
/// attachments would have to be arbitrated — a contest with no right answer,
/// since both are true. On the phase, each keeps the vantage it was actually
/// observed from and nothing has to be decided.
///
/// A phase may carry several: one per link it captured on, and another whenever
/// the answer changed while it ran, which for a listener running for days is a
/// cable somebody moved.
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
/// Carried because the two do not cover the same ground: Cisco equipment runs
/// CDP by default and LLDP only when somebody enables it, so a network that
/// answers on one and not the other is saying something about what it is made
/// of. It is also the honest answer to "why does this say VLAN 40" — the two
/// protocols carry that field in different places and not every device sends
/// either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AttachmentSource {
    /// IEEE 802.1AB, which anything may speak.
    Lldp,
    /// Cisco Discovery Protocol.
    Cdp,
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
    /// The field worth having above the name: it is what ties this attachment to
    /// a [`Host`] elsewhere in the same report, where a name is a string two
    /// devices may share.
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
    /// Worth recording separately from the phase's own span, because a phase
    /// that runs for days may see the answer change — which is somebody moving
    /// a cable, and is only legible if the two answers can be ordered.
    pub fn observed_at(&self) -> SystemTime {
        self.observed_at
    }
}

/// Which document a phase came from, for a report folded out of several.
///
/// A report merged from an archived nmap file, last night's journal and a scan
/// that just finished holds all of their phases, and each phase's scope, timing
/// and settings describe one of the three. This says which. Without it a merged
/// report states what it covered and cannot say on whose word.
///
/// `None` on a phase this process measured, which needs no attribution: it is
/// the report's own.
///
/// **The label is the caller's.** The engine opens no files and has no word for
/// one, so whoever read the document passes the name it used for it — a path, a
/// record id, a bucket key. [`merge`](crate::merge) is the only thing that
/// writes an `Origin`, and it takes the version from the source report's own
/// attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    label: Option<Arc<str>>,
    engine_version: Arc<str>,
}

impl Origin {
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

    /// What produced the phase, as that scanner attributed itself. `nmap 7.94`
    /// for a report read out of nmap's XML, and no evidence this crate ran
    /// anything.
    pub fn engine_version(&self) -> &str {
        &self.engine_version
    }
}

/// Everything a [`ScanPhase`] holds, for rebuilding one that was recorded.
///
/// Mirrors the phase field for field, deliberately and without a default: a
/// field added to [`ScanPhase`] is added here too, and every place that builds
/// one stops compiling until it says what the new field should be. That is what
/// keeps a journal from quietly losing what a phase gained.
#[derive(Debug, Clone)]
pub struct PhaseParts {
    /// Which entry point the phase recorded.
    pub kind: ScanKind,
    /// When it began.
    pub started_at: SystemTime,
    /// How long it ran.
    pub elapsed: Duration,
    /// Whether it held the privileges its raw strategies need, or `None` where
    /// this engine did not measure the phase and cannot say.
    pub privileged: Option<bool>,
    /// What it was asked to cover, and what it was forbidden.
    pub targets: TargetScope,
    /// The settings it ran under.
    pub settings: ScanSettings,
    /// The strategies that could not do their job.
    pub failures: Vec<ScannerFailure>,
    /// Addresses this host had no route to.
    pub unroutable: Vec<IpAddr>,
    /// What each strategy recorded about its own run.
    pub probes: Vec<ProbeStats>,
    /// Which document the phase came from, for one folded in from elsewhere.
    pub origin: Option<Origin>,
    /// Which switch ports the machine running the phase was plugged into.
    pub attachments: Vec<Attachment>,
}

impl ScanPhase {
    /// Rebuilds a phase from what was recorded of it.
    ///
    /// For restoring an earlier sitting of a resumed scan, so its report
    /// describes both rather than presenting the second as the whole job. A
    /// phase a scan is currently running comes from
    /// [`PhaseRecorder`](crate::scanner::recorder::PhaseRecorder) instead, which measures it.
    pub fn from_parts(parts: PhaseParts) -> Self {
        Self {
            kind: parts.kind,
            started_at: parts.started_at,
            elapsed: parts.elapsed,
            privileged: parts.privileged,
            targets: parts.targets,
            settings: parts.settings,
            failures: parts.failures,
            unroutable: parts.unroutable,
            probes: parts.probes,
            origin: parts.origin,
            attachments: parts.attachments,
        }
    }

    /// Attributes this phase to the document it was read from.
    ///
    /// Used by [`merge`](crate::merge) as it folds a source in, which is the one
    /// place that knows both the document's name and what produced it.
    pub fn attribute(&mut self, origin: Origin) {
        self.origin = Some(origin);
    }
}

/// One completed call into the engine.
#[derive(Debug, Clone)]
pub struct ScanPhase {
    kind: ScanKind,
    started_at: SystemTime,
    elapsed: Duration,
    privileged: Option<bool>,
    targets: TargetScope,
    settings: ScanSettings,
    failures: Vec<ScannerFailure>,
    /// Addresses this host had no route to, so nothing was sent to them.
    ///
    /// Distinct from a host that answered nothing, and the distinction is the
    /// whole reason it is recorded: an address that went unprobed because there
    /// is no path to it is not one that stayed silent, and the two call for
    /// different things from a reader. Telling somebody to scan an unreachable
    /// address on trust is advice that cannot work.
    unroutable: Vec<IpAddr>,
    probes: Vec<ProbeStats>,
    /// Which document this phase was folded in from, for a merged report.
    origin: Option<Origin>,
    /// Which switch ports the machine running this phase was plugged into.
    attachments: Vec<Attachment>,
}

impl ScanPhase {
    /// Which document this phase came from, for one folded into a merged report
    /// from elsewhere. `None` for a phase this process measured.
    pub fn origin(&self) -> Option<&Origin> {
        self.origin.as_ref()
    }

    /// Where the machine running this phase was plugged in, as the equipment on
    /// the far end of the cable announced itself.
    ///
    /// Empty for a phase that heard no such announcement, which is every phase
    /// on an unmanaged network and every phase this engine ran before it
    /// learned to listen for one. Never a claim that the machine is attached to
    /// nothing.
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
    /// **`None` for a phase this engine did not measure.** The question is about
    /// *these* strategies and the sockets *they* need, and a scan another
    /// program ran answers it about its own. Recording `false` there said an
    /// nmap sweep performed over ARP as root had no raw sockets — a claim about
    /// this engine that no document supports, printed under findings that
    /// plainly contradicted it.
    pub fn privileged(&self) -> Option<bool> {
        self.privileged
    }

    /// What the phase was asked to cover.
    pub fn targets(&self) -> &TargetScope {
        &self.targets
    }

    /// The settings the phase ran under.
    pub fn settings(&self) -> &ScanSettings {
        &self.settings
    }

    /// Strategies that did not run to completion.
    pub fn unroutable(&self) -> &[IpAddr] {
        &self.unroutable
    }

    /// Ground this phase did not cover, and why.
    pub fn failures(&self) -> &[ScannerFailure] {
        &self.failures
    }

    /// What each instrumented scanner observed about its own run.
    ///
    /// Empty where no strategy in this phase carries instrumentation, which is
    /// not the same as a phase whose scanners saw nothing. Only the raw paths
    /// count packets; the TCP-connect fallback has no capture to audit.
    pub fn probe_stats(&self) -> &[ProbeStats] {
        &self.probes
    }
}

/// Counts derived from a report's hosts.
///
/// Computed on demand by [`ScanReport::summary`] rather than stored, so it
/// cannot disagree with the hosts it describes.
///
/// Both headline counts are paired with a full distribution. `hosts_alive` and
/// `ports_open` are the numbers a person reads first, but collapsing the
/// remaining states into a single "not found" bucket would throw away the
/// distinction the scanner worked hardest to establish - a filtered port is
/// evidence of a firewall, a closed one is evidence of a live host, and neither
/// is silence.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanSummary {
    /// Hosts recorded, whatever their status.
    pub hosts_total: usize,
    /// Hosts confirmed to be on the network, either responding or filtered.
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
    pub services_identified: usize,
    /// How many hosts were reachable at an IPv4 address, at an IPv6 one, and at
    /// both.
    ///
    /// Counted per host rather than per address, and the three do not sum to
    /// [`hosts_total`](Self::hosts_total): a dual-stack host appears in
    /// `ipv4`, in `ipv6` and in `dual_stack`. That is what makes the numbers
    /// answer the question they are asked — "how much of this network did I see
    /// over IPv6" — where a partition into three would answer a different one.
    pub hosts_by_family: FamilyCounts,
}

/// Hosts counted by the address families they answered at.
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
    /// Which build produced the findings, rather than which build is holding
    /// them. A report read back from a journal carries the version recorded
    /// with it, so it is borrowed for a scan this build ran and owned for one
    /// it is only reading.
    engine_version: Cow<'static, str>,
    phases: Vec<ScanPhase>,
    /// Keyed by [`ScopedIp`] rather than by the bare address.
    ///
    /// A host is keyed by the address it is reported under, and for an IPv6
    /// link-local that address is not an identity on its own: `fe80::1` names a
    /// different machine on every segment, and a scanner watching two of them
    /// finds two hosts under one number. Keyed by the bare `IpAddr` the second
    /// silently replaced the first, so a report could hold fewer hosts than were
    /// found and say nothing about it.
    ///
    /// [`ScopedIp::scoped`] drops the zone from every address that does not need
    /// one, so this is the ordinary bare address for every host but that case,
    /// and the map still orders by address — the zone only breaks ties between
    /// identically-numbered link-locals. Iteration order is unchanged for every
    /// report that does not contain one.
    ///
    /// This is the same distinction [`pairing`](crate::diff::pairing) draws when
    /// it decides which records are one host, so a fold that correctly separates
    /// two link-locals now has somewhere to put them both.
    hosts: BTreeMap<ScopedIp, Host>,
}

impl ScanReport {
    /// Builds a single-phase report over the hosts a scan produced.
    ///
    /// Hosts are keyed by the address they are reported under, carrying the
    /// interface where that address needs one, so a host that gained addresses
    /// during the scan appears once rather than once per address and two
    /// link-locals on different segments stay two hosts.
    pub fn new(phase: ScanPhase, hosts: impl IntoIterator<Item = Host>) -> Self {
        Self {
            engine_version: Cow::Borrowed(ENGINE_VERSION),
            phases: vec![phase],
            hosts: index(hosts),
        }
    }

    /// A report over the phases of a job that ran in more than one sitting.
    ///
    /// The counterpart of [`new`](Self::new) for a resumed scan, whose earlier
    /// sittings are restored from a journal rather than measured. `phases` is
    /// kept in the order given, which is the order they ran.
    ///
    /// The report is attributed to this build, because this build is the one
    /// continuing the job. Use [`recorded`](Self::recorded) to rebuild a report
    /// nothing is continuing.
    pub fn from_phases(phases: Vec<ScanPhase>, hosts: impl IntoIterator<Item = Host>) -> Self {
        Self::attributed(Cow::Borrowed(ENGINE_VERSION), phases, hosts)
    }

    /// A report rebuilt from what an earlier scan wrote down, attributed to the
    /// engine that ran it.
    ///
    /// For reading a finished scan back — out of a journal, or out of a report
    /// this engine exported — where no new probing is happening. The version
    /// comes from the record rather than from this build, so a scan run by
    /// 0.11 still says 0.11 when 0.12 reads it. Every other constructor here
    /// describes a scan this build is part of, and names this build for that
    /// reason.
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
        Self {
            engine_version,
            phases,
            hosts: index(hosts),
        }
    }

    /// The engine version that produced this report.
    pub fn engine_version(&self) -> &str {
        &self.engine_version
    }

    /// The phases that contributed to this report, in the order they ran.
    ///
    /// A report a scan produced always has at least one, since a phase
    /// completing is what produces it. One rebuilt with
    /// [`recorded`](Self::recorded) can have none, which is what a scan that
    /// stopped before it wrote a phase down reads back as.
    pub fn phases(&self) -> &[ScanPhase] {
        &self.phases
    }

    /// Whether this report was folded out of documents rather than measured by
    /// one run.
    ///
    /// True when any phase carries an [`Origin`], which is what
    /// [`merge`](crate::merge) stamps on every phase it folds in and what
    /// nothing else writes.
    ///
    /// The distinction matters to anything that reads a report as an account of
    /// a single job, and to one thing in particular:
    /// [`elapsed`](Self::elapsed) is a sum over the phases, so for a merged
    /// report it is the working time of several scanners across arbitrary
    /// moments. That is a real quantity and it is not a length of time anything
    /// took, so presenting it as a duration would describe a scan that never
    /// ran. The span such a report draws on is
    /// [`finished_at`](Self::finished_at) less
    /// [`started_at`](Self::started_at) instead.
    pub fn is_merged(&self) -> bool {
        self.phases.iter().any(|phase| phase.origin().is_some())
    }

    /// Every host recorded, ordered by primary IP.
    pub fn hosts(&self) -> impl Iterator<Item = &Host> {
        self.hosts.values()
    }

    /// The number of hosts recorded.
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// Looks up a host by the address it is reported under.
    ///
    /// Where a report holds two link-locals at the same number on different
    /// segments this answers with the first, since a bare address cannot say
    /// which was meant. [`host_scoped`](Self::host_scoped) is the lookup that
    /// can.
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
    /// The exact lookup, and the one to use for a link-local: `fe80::1%en0` and
    /// `fe80::1%en1` are two hosts and this is what tells them apart.
    pub fn host_scoped(&self, ip: &ScopedIp) -> Option<&Host> {
        self.hosts.get(ip)
    }

    /// Takes this report's phases, consuming it.
    ///
    /// For a caller assembling a new report out of several, which needs the
    /// phases themselves rather than a copy of each. The hosts are read through
    /// [`hosts`](Self::hosts) before this is called, since folding them is what
    /// the new report is for.
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
    /// The moment this report's findings are *as of*, which is what anything
    /// judging them against a clock wants — a certificate's remaining validity,
    /// how stale a record is, which of two reports is the later word. A phase's
    /// end is its own `started_at + elapsed`, since `elapsed` is measured
    /// monotonically over that one phase; the report-wide
    /// [`elapsed`](Self::elapsed) is a sum and cannot be added to a start.
    ///
    /// Distinct from [`started_at`](Self::started_at), which answers when the
    /// job began. The two differ by a scan's duration for an ordinary report and
    /// by however long the sources span for a merged one.
    pub fn finished_at(&self) -> SystemTime {
        self.phases
            .iter()
            .map(|phase| phase.started_at() + phase.elapsed())
            .max()
            .unwrap_or_else(SystemTime::now)
    }

    /// The moment this report is judged to have happened.
    ///
    /// A report's findings are as of when it stopped looking, so a report with
    /// phases is placed by [`finished_at`](Self::finished_at) rather than by
    /// when its first phase began. For an ordinary scan the two differ by the
    /// scan's own duration, which no certificate threshold can notice. For a
    /// report merged out of several they differ by however long the sources
    /// span, and taking the earliest would judge tonight's certificates against
    /// last quarter.
    ///
    /// A report without phases — a foreign scanner's output, or a scan that
    /// ended before it wrote a phase down — is placed by the latest time any of
    /// its hosts was seen, which is the only other thing in the record that is a
    /// time the scan happened rather than the time it is being read.
    ///
    /// This is the clock [`merge`](crate::merge) folds sources by and
    /// [`diff`](crate::diff) places its two sides by, and it is public so that a
    /// caller can order documents the way those will before handing them over.
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
    /// This is time the engine was working, not the span from the first phase
    /// starting to the last one ending. The two differ by whatever the caller
    /// did between phases - rendering a table, waiting for a confirmation - and
    /// attributing that to the scan would make the engine look slower than it
    /// is. For the wall-clock span, take the difference between
    /// [`started_at`](Self::started_at) and the last phase's end.
    pub fn elapsed(&self) -> Duration {
        self.phases.iter().map(ScanPhase::elapsed).sum()
    }

    /// Every strategy failure across all phases, in the order they were
    /// recorded.
    pub fn failures(&self) -> impl Iterator<Item = &ScannerFailure> {
        self.phases.iter().flat_map(ScanPhase::failures)
    }

    /// Every instrumented scanner's counters, across all phases.
    pub fn probe_stats(&self) -> impl Iterator<Item = &ProbeStats> {
        self.phases.iter().flat_map(ScanPhase::probe_stats)
    }

    /// Whether any strategy failed to run to completion. A `true` here means
    /// the results are narrower than the caller asked for.
    pub fn is_partial(&self) -> bool {
        self.phases.iter().any(|phase| !phase.failures.is_empty())
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
                if port.service().is_some() {
                    summary.services_identified += 1;
                }
            }
        }

        summary
    }

    /// The hosts this report found alive, as targets for a port scan.
    ///
    /// The join between the engine's two phases, which is the whole economy of
    /// having two: sweep a range cheaply, then spend the expensive phase only on
    /// what answered. Without this a caller has to walk the hosts, filter them,
    /// and assemble four types by hand to say something the report already
    /// knows.
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use zond_engine::{PortSet, ZondConfig, discover, scan};
    /// use zond_engine::model::parse::ip::to_set;
    ///
    /// let cfg = ZondConfig::default();
    /// let (_, sweep) = discover(to_set(&["192.168.1.0/24"], None, None)?, &cfg).await?;
    /// let mut report = sweep.join().await?;
    ///
    /// // The sweep already established these hosts answer, so the scan is told
    /// // to take them on trust rather than probe for liveness a second time.
    /// let scanning = ZondConfig { assume_up: true, ..cfg.clone() };
    /// let targets = report.alive_targets(PortSet::try_from("22,80,443")?);
    /// let (_, ports) = scan(targets, &scanning).await?;
    /// report.merge(ports.join().await?);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// **Only hosts that answered.** [`Host::is_alive`] is the filter, so a host
    /// recorded as [`Down`](HostStatus::Down) — a router said it was
    /// unreachable — or [`Unknown`](HostStatus::Unknown) is left out. Probing an
    /// address nothing answered for costs a full port scan's worth of silence to
    /// learn what the sweep already established.
    ///
    /// **One address per host, the one it is reported under.** A dual-stack host
    /// is one machine and is scanned once, at the address
    /// [`Host::primary_ip`] picked; scanning both would report it twice, keyed
    /// separately, which is the outcome that ranking exists to prevent. A caller
    /// who does want every address can build the set from [`Host::ips`] instead.
    ///
    /// A link-local address carries the interface it was found on, because it is
    /// meaningless without one — `fe80::1` names a different machine on every
    /// segment, and the sweep that found it is the only thing that knows which.
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
                    // The zone is kept for exactly the addresses that cannot be
                    // reached without one, and dropped for the rest for the
                    // reason `ScopedIp` drops it: the same global address
                    // through two interfaces is one address, not two.
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
        // An empty unit is not the same as no unit: a `TargetMap` holding a set
        // with no addresses would have a port dimension and nothing to apply it
        // to, and `scan` would report a phase that covered nothing rather than
        // one there was nothing to do.
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
    /// The engine version is left as this report's. Two reports from different
    /// engine builds are not part of one job, and silently averaging their
    /// provenance would be worse than keeping the first.
    pub fn merge(&mut self, other: ScanReport) {
        self.phases.extend(other.phases);

        for (key, host) in other.hosts {
            match self.hosts.get_mut(&key) {
                Some(existing) => existing.merge(host),
                None => {
                    self.hosts.insert(key, host);
                }
            }
        }
    }
}

/// Keys hosts by the address each is reported under.
///
/// Folds rather than replaces where two records key the same, which is what a
/// caller means by handing over two records of one host: the live store already
/// folds them, and a caller assembling a report by hand should not lose a
/// finding for having done it in two pieces. Replacing was the previous
/// behaviour and it discarded whichever record arrived first, silently.
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

/// Which scanning strategy a [`ScanEvent::ScannerFailed`](crate::scanner::session::ScanEvent::ScannerFailed) refers to.
///
/// Marked `#[non_exhaustive]`: strategies are added as the engine learns to
/// probe in new ways, and a consumer matching on this enum should pay for that
/// with a recompile rather than a major version.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerKind {
    /// Layer-2 discovery (ARP/NDP) on a local segment.
    Local,
    /// Reading a link's own traffic, having sent nothing.
    ///
    /// The one strategy here that puts no packet on the wire, which changes
    /// what its counters mean. `sends_attempted` is zero for it and always
    /// will be; what it saw is bounded by what the network happened to carry
    /// rather than by anything this engine chose, so a quiet run says the
    /// segment was quiet and never that a host was absent.
    Passive,
    /// Raw TCP SYN discovery for gateway-routed targets.
    Routed,
    /// Raw TCP SYN port scanning (the port-scan phase, distinct from [`Routed`]
    /// host discovery).
    ///
    /// [`Routed`]: ScannerKind::Routed
    SynPort,
    /// Raw TCP port scanning with a probe that is not a SYN - a FIN, a flagless
    /// segment, a bare ACK.
    ///
    /// The same scanner as [`SynPort`], asking a different question. They are
    /// named apart because a report saying `syn_port` should mean a half-open
    /// connection attempt was made, and for these it was not; which technique
    /// ran is in the phase's settings.
    ///
    /// [`SynPort`]: ScannerKind::SynPort
    TcpPort,
    /// Unprivileged TCP connect fallback, for both host discovery and port
    /// scanning.
    Connect,
    /// Unprivileged UDP fallback.
    ///
    /// Named apart from [`Connect`] because a report has to be able to say which
    /// half of an unprivileged scan failed. The two send different datagrams,
    /// read different answers, and fail for different reasons — a host that
    /// refuses one may be perfectly happy with the other, and one name for both
    /// makes that indistinguishable.
    ///
    /// [`Connect`]: ScannerKind::Connect
    ConnectUdp,
    /// Privileged raw UDP port scanning.
    UdpPort,
    /// The active operating-system echo probe, sent at the hosts the passive
    /// sources could not name.
    ///
    /// Named apart from the port scanners because it answers a different
    /// question about a different dimension: not which ports a host has, but
    /// which stack answered the ping. A report attributing an echo probe to any
    /// other strategy would describe traffic nobody sent.
    OsEcho,
    /// The active operating-system series probe: one host asked the same
    /// question several times, so the policies behind its counters become
    /// visible.
    ///
    /// Named apart from [`SynPort`] though it sends the same segment, because
    /// what it is doing with the answers is a different activity and a report
    /// that filed it as a port scan would describe traffic nobody asked for:
    /// these probes revisit ports whose state is already settled, and none of
    /// their replies changes one.
    ///
    /// [`SynPort`]: ScannerKind::SynPort
    OsSeries,
    /// The active operating-system management probe: one SNMP `GetRequest` at a
    /// host whose kernel is not otherwise known.
    ///
    /// Named apart from the port scanners because it establishes no port state.
    /// It asks one question of one service and files the answer against the
    /// *host*; whether anything is listening on 161 is the port scan's to
    /// report, and this phase deliberately does not.
    OsSnmp,
    /// The idle (zombie) TCP port scan: port states read off a third party's
    /// IP-ID counter rather than from any reply the target sent this scanner.
    ///
    /// Named apart from [`SynPort`](Self::SynPort) though the forged probe is a
    /// SYN, because what it produces and what can go wrong are its own: a
    /// verdict is `Open` or `ClosedFiltered` and nothing finer, and a run is
    /// refused for want of a suitable zombie or an Ethernet path where a raw SYN
    /// scan would simply have proceeded.
    Idle,
    /// Composite scanner that delegates to protocol-specific scanners.
    Composite,
}

/// What a [`CongestionWindow`](crate::scanner::pacing::congestion::CongestionWindow) did over one run.
///
/// Instrumentation rather than telemetry: it says whether pacing engaged and how
/// hard, which is the difference between "this host is firewalled" and "this
/// host was asked too fast", and that difference is otherwise invisible in
/// everything else a scan reports.
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
    /// The controller having run out of room, which is the one state worth
    /// telling an operator about: it means the scan was still being outrun when
    /// it stopped, so what it recorded as silence may be loss rather than
    /// filtering, and the remedy is a narrower scan rather than a different
    /// setting.
    pub at_floor: bool,
}

impl ScannerKind {
    /// What a raw TCP scan carrying `technique` reports itself as.
    ///
    /// One function because the answer has to be the same everywhere it is
    /// asked, and it is asked twice: once by the plan, to attribute a step that
    /// could not open its socket, and once by the running scanner, to attribute
    /// anything that went wrong afterwards. Two spellings meant one strategy
    /// filed its failures under two names depending on when it failed, and the
    /// planning half called every technique [`SynPort`](Self::SynPort) whether
    /// or not a SYN was involved.
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

    /// A phase given one port set for every address can say a particular
    /// endpoint was probed. One given different sets cannot, and the union it
    /// publishes says so.
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
        same.add_unit(unit("10.0.0.0/30", "80,443"));
        same.add_unit(unit("10.0.1.0/30", "80,443"));
        let scope = TargetScope::from_target_map(&mut same, &Exclusions::none());
        assert_eq!(
            scope.ports().covers(443, Protocol::Tcp),
            Some(true),
            "every address was walked for it"
        );
        assert_eq!(scope.ports().covers(8080, Protocol::Tcp), Some(false));

        let mut differing = TargetMap::new();
        differing.add_unit(unit("10.0.0.0/30", "80,443"));
        differing.add_unit(unit("10.0.1.0/30", "8080"));
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

    /// A sweep walks addresses, and that is a fact about its endpoints rather
    /// than an absence of one.
    #[test]
    fn a_discovery_sweep_walked_no_ports_and_says_so() {
        let mut ips = crate::model::parse::ip::to_set(&["10.0.0.0/30"], None, None).unwrap();
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
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, last))
    }

    fn phase(kind: ScanKind) -> ScanPhase {
        ScanPhase {
            attachments: Vec::new(),
            kind,
            started_at: SystemTime::UNIX_EPOCH,
            elapsed: Duration::from_millis(500),
            privileged: Some(true),
            targets: TargetScope::from_ip_set(&mut IpSet::new(), &Exclusions::none()),
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            unroutable: Vec::new(),
            probes: Vec::new(),
            origin: None,
        }
    }

    fn ip_set(spec: &str) -> IpSet {
        let mut set = IpSet::new();
        set.insert_range(IpRange::from_str(spec).expect("valid range"));
        set
    }

    #[test]
    fn scope_merges_overlapping_ranges_before_counting() {
        let mut ips = ip_set("192.168.0.0/24");
        ips.insert_range(IpRange::from_str("192.168.0.128/25").expect("valid range"));

        let scope = TargetScope::from_ip_set(&mut ips, &Exclusions::none());

        // The second range is wholly inside the first, so the scope covers one
        // /24 rather than the 384 addresses the two arguments add up to.
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
        targets.add_unit(TargetSet::new(ip_set("10.0.0.1-10.0.0.4"), ports));

        let scope = TargetScope::from_target_map(&mut targets, &Exclusions::none());

        assert_eq!(scope.addresses(), 4);
        assert_eq!(scope.probes(), Some(12));
        assert_eq!(scope.protocols(), &[Protocol::Tcp, Protocol::Udp]);
    }

    /// A phase's settings are what a reader needs to interpret its findings, so
    /// a run that put something different on the wire has to record something
    /// different.
    ///
    /// The other half of this — that a run differing only in how it was
    /// *displayed* records the same settings — used to be asserted here against
    /// `no_banner`, `quiet` and `disable_input`. Those fields no longer exist on
    /// [`ZondConfig`]: presentation is the front end's, so there is nothing left
    /// that could leak into a report and nothing left for a test to catch.
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
        up.add_port(Port::new(81, Protocol::Tcp, PortState::Filtered));

        let mut filtered = Host::new(ip(2));
        filtered.set_status(HostStatus::Filtered);

        let mut down = Host::new(ip(3));
        down.set_status(HostStatus::Down);

        let report = ScanReport::new(phase(ScanKind::PortScan), [up, filtered, down]);
        let summary = report.summary();

        assert_eq!(summary.hosts_total, 3);
        assert_eq!(summary.hosts_alive, 2);
        assert_eq!(summary.hosts_by_status[&HostStatus::Up], 1);
        assert_eq!(summary.hosts_by_status[&HostStatus::Down], 1);
        assert_eq!(summary.ports_total, 3);
        assert_eq!(summary.ports_open, 2);
        assert_eq!(summary.ports_by_state[&PortState::Filtered], 1);
        assert_eq!(summary.services_identified, 1);
    }

    /// The whole economy of running discovery first: a host that never answered
    /// costs a full port scan's worth of silence to learn what the sweep already
    /// established.
    #[test]
    fn only_hosts_that_answered_become_port_scan_targets() {
        let mut up = Host::new(ip(1));
        up.set_status(HostStatus::Up);
        let mut filtered = Host::new(ip(2));
        filtered.set_status(HostStatus::Filtered);
        let mut down = Host::new(ip(3));
        down.set_status(HostStatus::Down);
        let unknown = Host::new(ip(4));

        let report = ScanReport::new(phase(ScanKind::Discovery), [up, filtered, down, unknown]);

        let targets = report.alive_targets(PortSet::from_iter([(80, Protocol::Tcp)]));

        // Up and Filtered are both alive - something is there, whether or not it
        // is answering for itself. Down and Unknown are not.
        assert_eq!(targets.gross_ips().expect("countable"), 2);
        assert_eq!(targets.gross_targets().expect("countable"), 2);
    }

    /// A dual-stack host is one machine. Scanning it at every address it holds
    /// would report it once per address, keyed separately - which is exactly
    /// what `consider_primary_ip`'s ranking exists to prevent.
    #[test]
    fn a_dual_stack_host_is_scanned_once() {
        let mut dual = Host::new(ip(1));
        dual.set_status(HostStatus::Up);
        dual.add_ip(IpAddr::from_str("2001:db8::1").unwrap());

        let report = ScanReport::new(phase(ScanKind::Discovery), [dual]);
        let targets = report.alive_targets(PortSet::from_iter([(80, Protocol::Tcp)]));

        assert_eq!(targets.gross_ips().expect("countable"), 1);
    }

    /// `fe80::1` names a different machine on every segment, and a socket cannot
    /// be opened to one without the interface's scope id. The sweep that found
    /// it is the only thing that knows which, so the target has to carry it or
    /// the port scan cannot reach the host discovery just found.
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

    /// A sweep that found nothing yields no work, not an empty unit carrying a
    /// port dimension with nothing to apply it to.
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

        // The port scan's record of .1 carried no status and no telemetry; the
        // merge must not let that erase what discovery established.
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

    /// A phase whose scanners carry no instrumentation reports no counters,
    /// which must not be confused with a scanner that measured zero.
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
        let mut ips = ip_set("10.0.0.0/30");
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
            Ipv4Range::new(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 9))
                .expect("valid range"),
        );

        let scope = TargetScope::from_ip_set(&mut ips, &Exclusions::none());

        assert_eq!(scope.addresses(), 5);
        assert_eq!(
            scope.ranges()[0].start_addr(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    /// A dual-stack host is one host, counted under both families.
    ///
    /// These counts answer "how much of this network did I see over IPv6",
    /// which is a different question from "how do the hosts partition" — so
    /// they deliberately do not sum to `hosts_total`, and a test that asserted
    /// they did would be pinning the wrong contract.
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
