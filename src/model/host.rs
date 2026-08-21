// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Hosts
//!
//! A [`Host`] is everything a scan learned about a single device. Nothing fills
//! one in at once. An ARP reply establishes that it is there and gives it a MAC,
//! a neighbour solicitation adds an IPv6 address, a port scan adds ports, and
//! service detection names what is behind them. Each of those arrives on its own
//! schedule, in an order nobody controls.
//!
//! The whole type is therefore built around accumulating evidence, under one
//! rule: later is not better. Status is promoted and never lowered, by
//! [`Host::record_evidence`]. The address a host is reported under is ranked
//! rather than overwritten, by [`Host::consider_primary_ip`]. A MAC is added to
//! those already seen rather than replacing them, by [`Host::record_mac`]. Where
//! two findings are equally good, the one already recorded wins.
//!
//! [`Host::set_hostname`] is the one exception, and says why.
//!
//! Without that rule a report would depend on which probe happened to finish
//! last, and the same scan of the same network would produce a different
//! document twice. [`Host::merge`] applies the same rules between two records of
//! one host, so folding one phase into another gives what a single phase
//! would.

use crate::fingerprint::os::{OsEvidence, OsSource};
use crate::model::ip::scoped::{ScopedIp, Zone};
use crate::model::mac::MacAddr;
use crate::model::port::{Port, Protocol};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    net::IpAddr,
    time::SystemTime,
};

pub mod hardware;
pub mod os;
pub mod status;
pub mod telemetry;

pub use hardware::HardwareInfo;
pub use os::OsFingerprint;
pub use status::{HostStatus, StatusProtocol, StatusReason};
pub use telemetry::HostTelemetry;

/// The most ports one host will have recorded against it.
///
/// A bound on what a single target can make this process allocate. Some devices
/// answer on every port asked, whether deliberately as a tarpit or by accident
/// as a misconfigured middlebox. Against a full 65 535-port scan that is a host
/// record two orders of magnitude larger than any real one, multiplied by
/// however many such devices sit on the segment.
///
/// A host that reaches the cap is marked [`NetworkRole::Tarpit`] and further
/// ports are dropped. The ports already recorded are real observations, and the
/// marking is what says the list is not complete.
pub const MAX_PORTS_PER_HOST: usize = 1000;

/// What a host turned out to be, beyond an address with ports on it.
///
/// A variant exists here only once something assigns it. A role nothing can
/// infer would promise every consumer that the engine looks for it, so an empty
/// `roles` array would mean "not one" when it really means "never asked".
/// Gateway, DHCP and DNS attributions all belong here once a strategy can
/// conclude them, and the enum is `#[non_exhaustive]` so that adding them costs
/// a recompile rather than a major version.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum NetworkRole {
    /// Answered on so many ports that the engine stopped recording them.
    ///
    /// This describes the *scan* rather than the host: it says the port list is
    /// truncated at [`MAX_PORTS_PER_HOST`] and must not be read as complete. A
    /// deliberate tarpit and a middlebox answering everything by accident are
    /// indistinguishable from here, and both make the ports recorded against
    /// this host meaningless.
    Tarpit,
}

/// A single machine, and what a scan established about it.
///
/// Identity first: the addresses it answers at, its name and its hardware. Then
/// what was found on it.
///
/// A host holds every address it is known by. A dual-stack machine answering at
/// three of them is one device, and reporting it as three is the failure this
/// type is shaped to avoid. See
/// [`consider_primary_ip`](Self::consider_primary_ip) for which address leads.
///
/// [`OsFingerprint`] is boxed. It is both the largest thing a host can carry and
/// one of the rarest, since most hosts in a scan never get one, so holding it by
/// reference keeps a `Host` cheap to move in collections of thousands.
#[derive(Debug, Clone)]
pub struct Host {
    /// The primary IP address used to target or identify this host.
    primary_ip: IpAddr,

    /// All known IP addresses for this host (multi-homed support).
    ips: BTreeSet<IpAddr>,

    /// The resolved hostname (FQDN or local network name).
    hostname: Option<String>,

    /// The current reachability status.
    status: HostStatus,

    /// Aggregated evidence explaining the current reachability status.
    reasons: HashSet<StatusReason>,

    /// Identified operating system metadata.
    os: Option<Box<OsFingerprint>>,

    /// What each source concluded about this host's operating system, kept so a
    /// later source can **corroborate** an earlier one instead of competing with
    /// it.
    ///
    /// The reason this is retained rather than collapsed on arrival: combining
    /// evidence is only meaningful over the evidence itself. A stack reading and
    /// a service banner are independent, and two independent sources agreeing on
    /// a family are worth more than either — that is the whole design of
    /// [`resolve`](crate::fingerprint::os::resolve). Keeping only the resulting
    /// [`OsFingerprint`] threw that away: the banner arrived after the stack
    /// reading, scored lower on its own, and was discarded whole, taking the
    /// release it alone could name with it.
    ///
    /// **One item per source, keeping the strongest.** Independence is claimed
    /// between kinds of source and never within one, so a host with forty open
    /// ports whose stack was read forty times contributes one stack reading, not
    /// forty. Without that, repeating an observation would manufacture certainty
    /// out of nothing — which is exactly what the arithmetic downstream cannot
    /// defend itself against. Bounded by the number of source kinds there are.
    os_evidence: BTreeMap<OsSource, OsEvidence>,

    /// Physical hardware (MAC) and vendor information.
    hardware: Option<HardwareInfo>,

    /// The interface this host was observed through, when one is known.
    ///
    /// Recorded by the strategies that work at the link layer, which are the
    /// only ones that can know it: a routed probe crosses whatever path the
    /// kernel chose and says nothing about which interface it left by.
    ///
    /// It is not decoration. An IPv6 link-local address is meaningless without
    /// it, because `fe80::1` names a different machine on every segment and a
    /// socket cannot be opened to one without the interface's scope id. This is
    /// what makes the addresses local discovery finds usable by everything that
    /// runs after it. See [`ScopedIp`].
    zone: Option<Zone>,

    /// Network performance and path telemetry.
    telemetry: HostTelemetry,

    /// Inferred roles based on network location or discovered services.
    network_roles: HashSet<NetworkRole>,

    /// The timestamp of the first discovery event for this host.
    first_seen: SystemTime,

    /// The timestamp of the most recent discovery or update event.
    last_seen: SystemTime,

    /// The ports found on this host, in a stable order, bounded by
    /// [`MAX_PORTS_PER_HOST`].
    ///
    /// Keyed on the number *and* the protocol, because a number names one
    /// endpoint per transport and a scan can be asked about both — `PortSet`
    /// spells the UDP half `u:53`, and the raw TCP and UDP scanners report into
    /// this map independently. Keyed on the number alone, whichever arrived
    /// second would be merged into the first and reported under its protocol.
    ///
    /// Ordered by number first, so a report lists a host's ports the way a
    /// reader expects to read them, with the two transports of one number
    /// adjacent.
    ports: BTreeMap<(u16, Protocol), Port>,
}

/// How well an address identifies the host holding it: lower leads.
///
/// The ordering behind [`Host::consider_primary_ip`], kept beside it as a free
/// function so the comparison is one expression rather than a branch that grows
/// a case each time a family is added.
///
/// Rank 1 is what the documentation there calls globally scoped: an address that
/// names the host from off its segment. That is
/// [`is_global_unicast`](crate::model::ip::is_global_unicast) and unique-local,
/// tested for rather than inferred from "not link-local" — the latter also
/// admits loopback, multicast and the unspecified address, none of which name
/// this host to anyone.
fn identity_rank(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 0,
        IpAddr::V6(v6) if crate::model::ip::is_global_unicast(v6) || is_unique_local(v6) => 1,
        IpAddr::V6(_) => 2,
    }
}

/// Whether `addr` is in `fc00::/7`, the range reserved for addresses that are
/// unique across an organization but not routed onto the internet.
///
/// Globally scoped for this purpose: it names one host wherever the
/// organization's routing reaches, which is what the ranking is asking.
fn is_unique_local(addr: &std::net::Ipv6Addr) -> bool {
    addr.octets()[0] & 0xfe == 0xfc
}

impl Host {
    /// Creates a new `Host` centered around a primary IP address.
    ///
    /// The initial status is always [`HostStatus::Unknown`].
    pub fn new(primary_ip: IpAddr) -> Self {
        let mut ips = BTreeSet::new();
        ips.insert(primary_ip);
        let now = SystemTime::now();

        Self {
            primary_ip,
            ips,
            hostname: None,
            status: HostStatus::Unknown,
            reasons: HashSet::new(),
            os: None,
            os_evidence: BTreeMap::new(),
            hardware: None,
            zone: None,
            telemetry: HostTelemetry::default(),
            network_roles: HashSet::new(),
            first_seen: now,
            last_seen: now,
            ports: BTreeMap::new(),
        }
    }

    /// Returns the primary IP address for this host.
    pub fn primary_ip(&self) -> IpAddr {
        self.primary_ip
    }

    /// Returns all known IP addresses for this host.
    pub fn ips(&self) -> &BTreeSet<IpAddr> {
        &self.ips
    }

    /// Returns the resolved hostname, if any.
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Returns the current reachability status.
    pub fn status(&self) -> HostStatus {
        self.status
    }

    /// Returns all aggregated evidence for the current status.
    pub fn reasons(&self) -> &HashSet<StatusReason> {
        &self.reasons
    }

    /// Returns the identified operating system, if any.
    pub fn os(&self) -> Option<&OsFingerprint> {
        self.os.as_deref()
    }

    /// Returns physical hardware information, if any.
    pub fn hardware(&self) -> Option<&HardwareInfo> {
        self.hardware.as_ref()
    }

    /// Returns the interface this host was observed through, if known.
    pub fn zone(&self) -> Option<&Zone> {
        self.zone.as_ref()
    }

    /// Records the interface this host was observed through.
    ///
    /// Only the first is kept. A host reachable through two interfaces is a
    /// real situation, and picking the earlier sighting is arbitrary but stable.
    /// Overwriting would make the address a scan reports depend on which
    /// strategy happened to finish last.
    pub fn set_zone(&mut self, zone: Zone) {
        self.zone.get_or_insert(zone);
        self.last_seen = SystemTime::now();
    }

    /// This host's primary address, carrying the interface it is valid on.
    ///
    /// The address to hand anything that intends to *reach* the host, rather
    /// than merely name it: [`ScopedIp::to_socket_addr`] refuses rather than
    /// building a socket address that cannot be connected to.
    pub fn scoped_ip(&self) -> ScopedIp {
        match &self.zone {
            Some(zone) => ScopedIp::scoped(self.primary_ip, zone.clone()),
            None => ScopedIp::unscoped(self.primary_ip),
        }
    }

    /// Returns network performance and path telemetry.
    pub fn telemetry(&self) -> &HostTelemetry {
        &self.telemetry
    }

    /// Returns inferred roles based on network location or discovered services.
    pub fn network_roles(&self) -> &HashSet<NetworkRole> {
        &self.network_roles
    }

    /// Returns the timestamp of the first discovery event.
    pub fn first_seen(&self) -> SystemTime {
        self.first_seen
    }

    /// Returns the timestamp of the most recent discovery or update event.
    pub fn last_seen(&self) -> SystemTime {
        self.last_seen
    }

    /// Offers `candidate` as the address this host is reported under, taking it
    /// only if it identifies the host better than the current one.
    ///
    /// Returns whether the primary address changed.
    ///
    /// **The rule, in one place.** A dual-stack host answers at several
    /// addresses and something has to choose which one names it. Left to
    /// whichever probe replied first, the same machine is reported under its
    /// IPv4 address on one run and its link-local on the next. For an inventory
    /// that is worse than an ugly address: it is one device appearing as two.
    ///
    /// So addresses are ranked, and the ranking only ever moves upward:
    ///
    /// 1. **IPv4**, because it is what a person recognises and types.
    /// 2. **Globally scoped IPv6**, meaning global unicast or unique-local,
    ///    which names the host from anywhere and needs nothing else to be
    ///    usable.
    /// 3. **Link-local IPv6**, which names a different machine on every segment
    ///    and is meaningless without the zone that
    ///    [`scoped_ip`](Self::scoped_ip) supplies.
    ///
    /// Ties keep the incumbent, so a host with two global addresses does not
    /// flip between them as replies arrive. Nothing is discarded either way:
    /// every address stays in [`ips`](Self::ips), and this decides only which
    /// one leads.
    pub fn consider_primary_ip(&mut self, candidate: IpAddr) -> bool {
        self.add_ip(candidate);

        if identity_rank(&candidate) >= identity_rank(&self.primary_ip) {
            return false;
        }

        self.primary_ip = candidate;
        self.last_seen = SystemTime::now();
        true
    }

    /// Adds a new IP address to the host's record and bumps `last_seen`.
    /// Returns `true` if the IP was newly added.
    pub fn add_ip(&mut self, ip: IpAddr) -> bool {
        let is_new = self.ips.insert(ip);
        self.last_seen = SystemTime::now();
        is_new
    }

    /// Adds multiple IP addresses to the host's record and bumps `last_seen`.
    pub fn extend_ips(&mut self, ips: impl IntoIterator<Item = IpAddr>) {
        self.ips.extend(ips);
        self.last_seen = SystemTime::now();
    }

    /// Records the name this host resolved to, replacing any already recorded.
    ///
    /// The one field that *is* overwritten, and the exception is deliberate:
    /// unlike a status or an address, a hostname has no ordering that says
    /// which of two answers knows more, and a caller passing `None` is clearing
    /// a name rather than declining to set one. [`merge`](Self::merge) keeps the
    /// incumbent instead, because there neither record is the later word — they
    /// are two accounts of the same host.
    pub fn set_hostname(&mut self, hostname: Option<String>) {
        self.hostname = hostname;
        self.last_seen = SystemTime::now();
    }

    /// Raises the reachability status to `status`, if that is an improvement.
    ///
    /// Promotes and never lowers, the same rule
    /// [`record_evidence`](Self::record_evidence) applies and for the same
    /// reason: probes answer in an order nobody controls, and a late ICMP
    /// unreachable must not overwrite proof the host answered for itself. This
    /// is the entry point for a caller that has a status and no
    /// [`StatusReason`] to attach to it; where there is a reason, prefer
    /// `record_evidence`, which keeps the audit trail as well.
    pub fn set_status(&mut self, status: HostStatus) {
        if status > self.status {
            self.status = status;
        }
        self.last_seen = SystemTime::now();
    }

    /// Adds a status reason and bumps `last_seen`.
    pub fn add_reason(&mut self, reason: StatusReason) {
        self.reasons.insert(reason);
        self.last_seen = SystemTime::now();
    }

    /// Records one piece of liveness evidence: the status it establishes, and
    /// the reason it establishes it.
    ///
    /// This is how scanners report what they saw, and it is deliberately the
    /// only such entry point. The status is **promoted, never lowered**, on the
    /// semantic ordering of [`HostStatus`]. [`Host::merge`](Host::merge)
    /// applies the same rule between two records of one host, for the same
    /// reason: a scan learns about a host from several probes arriving in an
    /// order nobody controls, and an ICMP unreachable from a router that happens
    /// to land after an ARP reply must not overwrite proof the host answered for
    /// itself.
    ///
    /// The reason is kept whether or not the status moved. A host that is
    /// already `Up` still gains the audit trail of everything else that saw it,
    /// which is the whole purpose of [`StatusReason`].
    ///
    /// Callers must only pass evidence backed by a received packet. Silence is
    /// not evidence and has no status to record; see [`HostStatus::Unknown`].
    pub fn record_evidence(&mut self, status: HostStatus, reason: StatusReason) {
        if status > self.status {
            self.status = status;
        }
        self.reasons.insert(reason);
        self.last_seen = SystemTime::now();
    }

    /// Sets the OS fingerprint and bumps `last_seen`.
    /// What each source has concluded about this host's operating system.
    ///
    /// The input [`resolve`](crate::fingerprint::os::resolve) is run over, and
    /// the reason a late-arriving source can raise a verdict rather than merely
    /// fail to displace it.
    pub fn os_evidence(&self) -> impl Iterator<Item = &OsEvidence> {
        self.os_evidence.values()
    }

    /// Files what one source concluded, keeping the strongest reading per
    /// source.
    ///
    /// Returns whether this changed what is on record, so a caller can tell a
    /// genuine new finding from the same one arriving again.
    ///
    /// **Per source, not per observation**, and that is what makes the
    /// arithmetic downstream safe: a stack read once and a stack read forty
    /// times — which is what a host with forty open ports produces — are the
    /// same single piece of evidence, and counting them separately would turn
    /// one observation into certainty.
    pub fn record_os_evidence(&mut self, evidence: OsEvidence) -> bool {
        match self.os_evidence.get(&evidence.source) {
            // Strictly better, so a repeat of the same reading is not a change.
            Some(existing) if existing.confidence >= evidence.confidence => false,
            _ => {
                self.os_evidence.insert(evidence.source, evidence);
                true
            }
        }
    }

    pub fn set_os(&mut self, os: OsFingerprint) {
        self.os = Some(Box::new(os));
        self.last_seen = SystemTime::now();
    }

    /// Replaces this host's hardware record wholesale.
    ///
    /// For a caller holding a complete [`HardwareInfo`], such as one read back
    /// from a report. A single sighting goes through [`record_mac`](Self::record_mac),
    /// which adds to the record instead of discarding what is already in it.
    pub fn set_hardware(&mut self, hardware: HardwareInfo) {
        self.hardware = Some(hardware);
        self.last_seen = SystemTime::now();
    }

    /// Builder method to record a MAC sighting and return Self.
    pub fn with_mac(mut self, mac: MacAddr) -> Self {
        self.record_mac(mac);
        self
    }

    /// Records a sighting of `mac` for this host, keeping every address seen.
    ///
    /// Works by reference, unlike [`with_mac`](Self::with_mac), so a host
    /// created by the port scanner, which has no MAC, can still be enriched by a
    /// scanner that learned one, whichever ran first.
    ///
    /// **Adds rather than replaces, and that is what [`HardwareInfo`] is for.**
    /// A device with two interfaces on one segment answers under two addresses,
    /// and a device randomizing its MAC answers under a series of them; both are
    /// one host, and which address it is currently using is a different question
    /// from which it has ever used. Overwriting would answer neither, since it
    /// leaves whichever probe replied last: [`most_recent_mac`] would report a
    /// sighting order rather than a timeline, and [`prune_stale_macs`] would
    /// have nothing to prune.
    ///
    /// Repeating a MAC already on record is not a no-op: it refreshes that
    /// address's last-seen time, which is what makes the two methods above mean
    /// anything.
    ///
    /// [`most_recent_mac`]: HardwareInfo::most_recent_mac
    /// [`prune_stale_macs`]: HardwareInfo::prune_stale_macs
    pub fn record_mac(&mut self, mac: MacAddr) {
        match &mut self.hardware {
            Some(hardware) => hardware.add_mac(mac),
            None => self.hardware = Some(HardwareInfo::new(mac)),
        }
        self.last_seen = SystemTime::now();
    }

    /// Adds a single RTT measurement and bumps `last_seen`.
    pub fn add_rtt(&mut self, rtt: std::time::Duration) {
        self.telemetry.add_rtt(rtt);
        self.last_seen = SystemTime::now();
    }

    /// Adds a round trip measured against a probe the whole segment was asked,
    /// which this host will report only if it produced no better sample.
    ///
    /// See [`RttSource`](crate::model::host::telemetry::RttSource) for
    /// why the two are kept apart.
    pub fn add_segment_wide_rtt(&mut self, rtt: std::time::Duration) {
        self.telemetry.add_segment_wide_rtt(rtt);
        self.last_seen = SystemTime::now();
    }

    /// Builder method to add a single RTT measurement and return Self.
    pub fn with_rtt(mut self, rtt: std::time::Duration) -> Self {
        self.add_rtt(rtt);
        self
    }

    /// Records several round-trip measurements at once.
    pub fn add_rtts(&mut self, rtts: impl IntoIterator<Item = std::time::Duration>) {
        for rtt in rtts {
            self.telemetry.add_rtt(rtt);
        }
        self.last_seen = SystemTime::now();
    }

    /// Adds a network role and bumps `last_seen`.
    pub fn add_network_role(&mut self, role: NetworkRole) {
        self.network_roles.insert(role);
        self.last_seen = SystemTime::now();
    }

    /// Returns the minimum recorded RTT.
    pub fn min_rtt(&self) -> Option<std::time::Duration> {
        self.telemetry.min_rtt()
    }

    /// Returns the maximum recorded RTT.
    pub fn max_rtt(&self) -> Option<std::time::Duration> {
        self.telemetry.max_rtt()
    }

    /// Returns the average recorded RTT.
    pub fn average_rtt(&self) -> Option<std::time::Duration> {
        self.telemetry.average_rtt()
    }

    /// Returns the median recorded RTT, a summary of typical latency that is
    /// robust against outliers. See [`HostTelemetry::median_rtt`].
    pub fn median_rtt(&self) -> Option<std::time::Duration> {
        self.telemetry.median_rtt()
    }

    /// Returns the most recent MAC address, if hardware info is available.
    pub fn mac(&self) -> Option<MacAddr> {
        self.hardware.as_ref().and_then(|h| h.most_recent_mac())
    }

    /// Returns the hardware vendor, if hardware info is available.
    pub fn vendor(&self) -> Option<&str> {
        self.hardware.as_ref().and_then(HardwareInfo::vendor)
    }

    /// Returns `true` if this host is confirmed to be on the network
    /// (either fully responding or filtered).
    pub fn is_alive(&self) -> bool {
        self.status.is_alive()
    }

    /// Returns an iterator over all discovered ports in sorted order.
    pub fn ports(&self) -> impl Iterator<Item = &Port> {
        self.ports.values()
    }

    /// Returns the total number of recorded ports for this host.
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Records a port finding, merging it with what is already known about that
    /// port.
    ///
    /// Returns whether the finding was recorded. `false` means the host is at
    /// [`MAX_PORTS_PER_HOST`] and has been marked [`NetworkRole::Tarpit`]; the
    /// caller is told rather than left to assume the port list is complete.
    pub fn add_port(&mut self, new_port: Port) -> bool {
        let key = (new_port.number(), new_port.protocol());

        if self.ports.len() >= MAX_PORTS_PER_HOST && !self.ports.contains_key(&key) {
            self.network_roles.insert(NetworkRole::Tarpit);
            return false;
        }

        self.ports
            .entry(key)
            .and_modify(|p| p.merge(new_port.clone()))
            .or_insert(new_port);

        self.last_seen = SystemTime::now();
        true
    }

    /// Folds another record of this host into this one.
    ///
    /// This is how findings from separate scan stages become a single record.
    /// Status is promoted and never lowered, telemetry and OS data merge by
    /// their own rules, and the port cap still applies.
    ///
    /// The address the merged record leads with is decided by
    /// [`consider_primary_ip`](Self::consider_primary_ip), not by which of the
    /// two happened to be `self`. Two records of one host are two probes'
    /// accounts of it, and the ranking exists precisely because the order they
    /// arrive in is nobody's to control. A merge that kept the incumbent address
    /// unconditionally would reintroduce between phases the same
    /// machine-reported-as-two that the ranking prevents within one.
    pub fn merge(&mut self, other: Host) {
        // Taken before anything else, and restored at the end.
        //
        // Every mutator below stamps `last_seen` with the current time, because
        // each of them is normally a scanner reporting something it just saw.
        // A merge is not a sighting: it folds two records that were each
        // observed earlier. Left alone, the stamps would overwrite both
        // records' observation times with the moment they happened to be folded
        // together, and `last_seen` would answer "when was this record last
        // touched" to a reader who asked when the host was last heard from.
        let first_seen = self.first_seen.min(other.first_seen);
        let last_seen = self.last_seen.max(other.last_seen);

        let other_primary = other.primary_ip;

        self.ips.extend(other.ips);
        self.consider_primary_ip(other_primary);

        if self.hostname.is_none() {
            self.hostname = other.hostname;
        }

        if other.status > self.status {
            self.status = other.status;
        }
        self.reasons.extend(other.reasons);

        if let Some(other_os) = other.os {
            if let Some(ref mut self_os) = self.os {
                self_os.merge(*other_os);
            } else {
                self.os = Some(other_os);
            }
        }

        if let Some(other_hw) = other.hardware {
            if let Some(ref mut self_hw) = self.hardware {
                self_hw.merge(other_hw);
            } else {
                self.hardware = Some(other_hw);
            }
        }

        if let Some(other_zone) = other.zone {
            self.zone.get_or_insert(other_zone);
        }

        self.telemetry.merge(other.telemetry);
        self.network_roles.extend(other.network_roles);

        for port in other.ports.into_values() {
            self.add_port(port);
        }

        self.first_seen = first_seen;
        self.last_seen = last_seen;
    }
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.primary_ip, self.status)?;
        if let Some(ref os) = self.os {
            write!(f, " - {}", os)?;
        }
        if self.network_roles.contains(&NetworkRole::Tarpit) {
            write!(f, " [TARPIT]")?;
        } else {
            write!(f, " [{}]", self.telemetry)?;
        }
        Ok(())
    }
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
    use crate::model::port::{Port, PortState, Protocol};
    use std::net::Ipv4Addr;

    static IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100));

    /// A status only ever improves. The rule lives on every entry point that
    /// can set one, not just on `record_evidence`, or a caller reaching for the
    /// plain setter quietly opts out of it.
    #[test]
    fn a_status_is_never_lowered_by_the_plain_setter() {
        let mut host = Host::new(IP_ADDR);

        host.set_status(HostStatus::Up);
        host.set_status(HostStatus::Down);
        assert_eq!(host.status(), HostStatus::Up);

        let mut climbing = Host::new(IP_ADDR);
        climbing.set_status(HostStatus::Down);
        climbing.set_status(HostStatus::Up);
        assert_eq!(climbing.status(), HostStatus::Up);
    }

    /// A port number names two endpoints, and a scan can be asked about both:
    /// `PortSet` spells the UDP half `u:53`, and the raw TCP and UDP scanners
    /// each report their findings here. Keyed on the number alone, the second
    /// arrival is merged into the first — so one result is lost and the
    /// survivor is reported under the other's protocol, with a state maximised
    /// across two unrelated questions.
    #[test]
    fn a_port_number_holds_one_endpoint_per_protocol() {
        let mut host = Host::new(IP_ADDR);
        host.add_port(Port::new(53, Protocol::Tcp, PortState::Closed));
        host.add_port(Port::new(53, Protocol::Udp, PortState::Open));

        let ports: Vec<_> = host.ports().collect();
        assert_eq!(ports.len(), 2, "TCP/53 and UDP/53 are two endpoints");
        assert_eq!(
            (ports[0].protocol(), ports[0].state()),
            (Protocol::Tcp, PortState::Closed)
        );
        assert_eq!(
            (ports[1].protocol(), ports[1].state()),
            (Protocol::Udp, PortState::Open),
            "neither finding was folded into the other"
        );

        // And a repeat of one of them still merges with its own protocol.
        host.add_port(Port::new(53, Protocol::Tcp, PortState::Open));
        assert_eq!(host.port_count(), 2);
        assert_eq!(
            host.ports().next().expect("tcp/53").state(),
            PortState::Open
        );
    }

    /// A dropped port is a truncated list, and the caller is the only one that
    /// can decide what to do about it.
    #[test]
    fn add_port_reports_whether_the_finding_was_recorded() {
        let mut host = Host::new(IP_ADDR);
        for i in 0..MAX_PORTS_PER_HOST {
            assert!(host.add_port(Port::new(i as u16, Protocol::Tcp, PortState::Open)));
        }

        assert!(!host.add_port(Port::new(9999, Protocol::Tcp, PortState::Open)));
        assert!(host.network_roles().contains(&NetworkRole::Tarpit));
    }

    /// The cap is exact: the host takes ports up to it and is marked only once
    /// one is actually refused. Marking a host at the boundary would label a
    /// complete port list as truncated.
    #[test]
    fn the_tarpit_marking_appears_only_once_a_port_is_refused() {
        let mut host = Host::new(IP_ADDR);
        for i in 0..MAX_PORTS_PER_HOST {
            host.add_port(Port::new(i as u16, Protocol::Tcp, PortState::Open));
        }
        assert!(!host.network_roles.contains(&NetworkRole::Tarpit));

        host.add_port(Port::new(9999, Protocol::Tcp, PortState::Open));
        assert!(host.network_roles.contains(&NetworkRole::Tarpit));
        assert_eq!(host.port_count(), MAX_PORTS_PER_HOST);
    }

    /// `last_seen` answers when the host was last heard from, so a merge — which
    /// hears from nothing — must not move it. Every mutator a merge runs stamps
    /// the current time, so without care both records' observation times are
    /// replaced by the moment they were folded together.
    ///
    /// Stamped by hand rather than by construction order: `SystemTime` is only
    /// as fine-grained as the platform makes it, and on Windows two
    /// constructions can land on the same tick.
    #[test]
    fn merging_two_records_keeps_the_span_they_were_observed_over() {
        let epoch = SystemTime::UNIX_EPOCH;
        let at = |secs| epoch + std::time::Duration::from_secs(secs);

        let mut early = Host::new(IP_ADDR);
        early.first_seen = at(10);
        early.last_seen = at(20);

        let mut late = Host::new(IP_ADDR);
        late.first_seen = at(30);
        late.last_seen = at(40);

        early.merge(late);

        assert_eq!(early.first_seen(), at(10), "the earlier sighting");
        assert_eq!(early.last_seen(), at(40), "and the later one");
    }

    /// Merge promotes on the same ordering the setters use, so folding one
    /// phase into another gives what a single phase would.
    #[test]
    fn merging_promotes_the_status_without_lowering_it() {
        let mut h1 = Host::new(IP_ADDR);
        h1.set_status(HostStatus::Down);

        let mut h2 = Host::new(IP_ADDR);
        h2.set_status(HostStatus::Filtered);

        h1.merge(h2);
        assert_eq!(h1.status(), HostStatus::Filtered);
    }

    /// Two records of one host are two probes' accounts of it, and which of
    /// them is `self` is an accident of arrival order. A merge that kept the
    /// incumbent address would report the same machine under its link-local on
    /// one run and its IPv4 on the next. That is the failure
    /// [`Host::consider_primary_ip`] exists to prevent, reintroduced one layer
    /// up where phases meet.
    #[test]
    fn merging_two_records_of_one_host_applies_the_same_address_ranking() {
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let lla: IpAddr = "fe80::10".parse().unwrap();

        let mut into_link_local = Host::new(lla);
        into_link_local.merge(Host::new(v4));
        assert_eq!(into_link_local.primary_ip(), v4);

        let mut into_v4 = Host::new(v4);
        into_v4.merge(Host::new(lla));
        assert_eq!(
            into_v4.primary_ip(),
            v4,
            "and the ranking never moves back down"
        );

        assert_eq!(into_link_local.ips().len(), 2, "nothing is discarded");
        assert_eq!(into_v4.ips().len(), 2);
    }

    /// A device with two interfaces on one segment, or one randomizing the
    /// address it answers under, is a single host with a history. That history
    /// is the whole of what [`HardwareInfo`] stores. Replacing on each sighting
    /// leaves whichever probe replied last, and makes
    /// [`HardwareInfo::most_recent_mac`] report an arrival order rather than a
    /// timeline.
    #[test]
    fn every_mac_a_host_answers_under_stays_on_its_record() {
        let first = MacAddr::new(0x02, 0, 0, 0, 0, 1);
        let second = MacAddr::new(0x02, 0, 0, 0, 0, 2);

        let mut host = Host::new(IP_ADDR);
        host.record_mac(first);
        host.record_mac(second);

        let hardware = host.hardware().expect("a sighting was recorded");
        assert_eq!(hardware.macs().len(), 2);
        assert!(hardware.macs().contains_key(&first));
        assert!(hardware.macs().contains_key(&second));
        assert_eq!(
            host.mac(),
            Some(second),
            "and the newest is the one the host leads with"
        );
    }

    #[test]
    fn merge_tarpit_collision_test() {
        let mut h1 = Host::new(IP_ADDR);
        for i in 0..600 {
            h1.add_port(Port::new(i, Protocol::Tcp, PortState::Open));
        }

        let mut h2 = Host::new(IP_ADDR);
        // Ports 500-1100. 100 overlap (0-indexed 500-599), 500 new ones.
        // Total should hit cap at 1000.
        for i in 500..1100 {
            h2.add_port(Port::new(i, Protocol::Tcp, PortState::Open));
        }

        h1.merge(h2);
        assert_eq!(h1.port_count(), MAX_PORTS_PER_HOST);
        assert!(h1.network_roles.contains(&NetworkRole::Tarpit));
    }

    /// The address a dual-stack host is reported under must not depend on which
    /// probe happened to answer first, or one machine is reported as two across
    /// consecutive runs of the same scan.
    #[test]
    fn the_address_a_host_leads_with_does_not_depend_on_reply_order() {
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let gua: IpAddr = "2001:db8::10".parse().unwrap();
        let lla: IpAddr = "fe80::10".parse().unwrap();

        // Every order the three replies could arrive in.
        for order in [
            [v4, gua, lla],
            [v4, lla, gua],
            [gua, v4, lla],
            [gua, lla, v4],
            [lla, v4, gua],
            [lla, gua, v4],
        ] {
            let mut host = Host::new(order[0]);
            for ip in order {
                host.consider_primary_ip(ip);
            }

            assert_eq!(
                host.primary_ip(),
                v4,
                "arrival order {order:?} must not change which address leads"
            );
            assert_eq!(host.ips().len(), 3, "and none of them is discarded");
        }
    }

    /// The ranking's middle tier is "names the host from off its segment", and
    /// only addresses that do belong in it. Written as "not link-local" it also
    /// admitted loopback, multicast and the unspecified address — none of which
    /// name this host to anybody, and each of which would have displaced a
    /// genuine link-local address that at least names it to its own segment.
    #[test]
    fn only_a_globally_scoped_address_outranks_a_link_local_one() {
        let lla: IpAddr = "fe80::10".parse().unwrap();

        for scoped in ["2001:db8::10", "fd00::10"] {
            let mut host = Host::new(lla);
            host.consider_primary_ip(scoped.parse().unwrap());
            assert_eq!(
                host.primary_ip().to_string(),
                scoped,
                "{scoped} names the host"
            );
        }

        for useless in ["::1", "::", "ff02::1"] {
            let mut host = Host::new(lla);
            host.consider_primary_ip(useless.parse().unwrap());
            assert_eq!(
                host.primary_ip(),
                lla,
                "{useless} does not identify the host to anyone"
            );
        }
    }

    /// Without IPv4, a globally scoped address leads over a link-local one: it
    /// names the host from anywhere, where `fe80::…` names a different machine
    /// on every segment.
    #[test]
    fn a_global_address_leads_over_a_link_local_one() {
        let gua: IpAddr = "2001:db8::10".parse().unwrap();
        let lla: IpAddr = "fe80::10".parse().unwrap();

        let mut from_lla = Host::new(lla);
        from_lla.consider_primary_ip(gua);
        assert_eq!(from_lla.primary_ip(), gua);

        let mut from_gua = Host::new(gua);
        from_gua.consider_primary_ip(lla);
        assert_eq!(
            from_gua.primary_ip(),
            gua,
            "and the ranking never moves back down"
        );
    }

    /// A tie keeps the incumbent, so a host with several equally good addresses
    /// does not flip between them as replies arrive.
    #[test]
    fn an_equally_good_address_does_not_displace_the_current_one() {
        let first: IpAddr = "2001:db8::1".parse().unwrap();
        let second: IpAddr = "2001:db8::2".parse().unwrap();

        let mut host = Host::new(first);
        assert!(!host.consider_primary_ip(second));
        assert_eq!(host.primary_ip(), first);
        assert!(
            host.ips().contains(&second),
            "it is still an address it has"
        );
    }
}
