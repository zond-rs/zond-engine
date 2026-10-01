// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Hosts
//!
//! A [`Host`] is everything a scan learned about a single device, filled in piece by
//! piece: an ARP reply establishes it is there and gives it a MAC, a neighbour
//! solicitation adds an IPv6 address, a port scan adds ports, and service detection
//! names what is behind them, in no fixed order.
//!
//! So the type accumulates evidence under one rule: later is not better. Status is
//! promoted and never lowered ([`Host::record_evidence`]). The reported address is
//! ranked ([`Host::consider_primary_ip`]). MACs accumulate ([`Host::record_mac`]).
//! Between equally good findings, the one already recorded wins. The one exception is
//! [`Host::set_hostname`].
//!
//! This keeps a report independent of which probe finished last. [`Host::merge`]
//! applies the same rules between two records of one host, so folding one phase into
//! another gives what a single phase would.

use crate::model::finding::{ClaimId, Finding, MAX_FINDINGS_PER_SUBJECT};
use crate::model::ip::scoped::{ScopedIp, Zone};
use crate::model::mac::MacAddr;
use crate::model::port::{Port, PortSet, PortState, Protocol};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    net::IpAddr,
    time::SystemTime,
};

pub mod hardware;
pub mod name;
pub mod os;
pub mod path;
pub mod protocol;
pub mod status;
pub mod telemetry;

/// How many times this thread has read a host's addresses, for a test that has
/// to know a walk over a report read them only where it needed to.
///
/// Counted per thread, so the tests running beside one never move its count.
#[cfg(test)]
pub(crate) mod address_reads {
    use std::cell::Cell;

    thread_local! {
        static READS: Cell<usize> = const { Cell::new(0) };
    }

    /// Counts one read.
    pub(super) fn note() {
        READS.with(|reads| reads.set(reads.get() + 1));
    }

    /// How many reads this thread has made.
    pub(crate) fn so_far() -> usize {
        READS.with(Cell::get)
    }
}

pub use hardware::{HardwareDescription, HardwareInfo};
pub use name::{HostName, NameKind, NameSource};
pub use os::{OsEvidence, OsFingerprint, OsSource};
pub use path::{Hop, NetworkPath};
pub use protocol::{IpProtocolState, ip_protocol_name};
pub use status::{EvidenceSource, HostStatus, StatusProtocol, StatusReason};
pub use telemetry::HostTelemetry;

/// The most ports one host will have recorded against it.
///
/// Every endpoint this build can probe: one whole port space for each transport in
/// [`Protocol::ALL`], so a new transport widens it.
///
/// Anything lower would truncate a scan somebody asked for: `1-1024` on a host that
/// answers records a thousand ports, closed ones included, and `1-65535,u:1-65535` is
/// one specification covering two port spaces.
///
/// A host that reaches it is marked [`NetworkRole::Truncated`] and further ports are
/// dropped. **No scan can reach it**, since the map's key space is exactly this size;
/// the check guards against a `Protocol` variant missing from [`Protocol::ALL`].
///
/// The key space is what bounds allocation per target. [`NetworkRole::Tarpit`] is the
/// separate claim about the host.
pub const MAX_PORTS_PER_HOST: usize = (u16::MAX as usize + 1) * Protocol::ALL.len();

/// How many **open** ports make a host implausible as a host.
///
/// No machine runs a thousand listening services. A tarpit answering every SYN, or a
/// middlebox doing it by accident, does, and every port it reports is a finding nobody
/// should act on.
///
/// Counts open ports only: sixty thousand *closed* ports is the ordinary result of a
/// wide scan against a live machine.
pub const TARPIT_OPEN_PORTS: usize = 1_000;

/// What a host turned out to be, beyond an address with ports on it.
///
/// Most variants name a function the network depends on (forwarding, naming,
/// addressing); the last three are claims about the record. A reader can act on either
/// without reading anything else about the host.
///
/// A role is never a port number restated: an open port 80 is
/// [`Port::service`](crate::model::port::Port::service), which carries a confidence.
/// Every role is concluded from evidence in its own protocol (an advertisement that
/// says it forwards, a DNS message that parses as a response, a DHCP server naming
/// itself), so it needs no confidence of its own.
///
/// A variant nothing assigns yet says so in its documentation, since an empty `roles`
/// array would otherwise read as "checked, none".
///
/// [`ALL`](Self::ALL) is the list to iterate.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum NetworkRole {
    /// Forwards traffic on behalf of other hosts.
    ///
    /// Three independent proofs, since no one of them covers a whole network:
    ///
    /// 1. A **neighbour advertisement with the R flag** set (RFC 4861 §4.4).
    ///    The host is answering an ordinary discovery probe and saying, in the
    ///    same message, that it routes.
    /// 2. A **router advertisement** (ICMPv6 type 134), sent unprompted every few
    ///    minutes while a segment sweep is listening.
    /// 3. **This machine's own routing table.** The address is a default gateway of
    ///    an interface the scan runs on. The only proof on an IPv4-only segment.
    ///
    /// Not called a gateway: a gateway is somebody's next hop, which is relational.
    /// These proofs establish only that the box forwards.
    Router,

    /// Answered a query on port 53 with a message that parses as a DNS
    /// response.
    ///
    /// The reply is the evidence, not the open port. The engine's UDP probe for port 53
    /// carries a real question, so a resolver ordinarily answers.
    ///
    /// mDNS and LLMNR (5353, 5355) do not count: nearly every laptop and printer
    /// answers them.
    DnsServer,

    /// Answered a DHCP message as a server.
    ///
    /// The engine sends a `DHCPINFORM`, which asks for configuration without asking for
    /// an address, and reads the server identifier (option 54) from the reply. The role
    /// goes on that address only when the reply also came from it; behind a relay agent
    /// the two differ.
    ///
    /// Port state cannot show it: UDP/67 is `OpenOrNoReply` on silence like any UDP
    /// port.
    DhcpServer,

    /// Answered with a valid NTP response, so it serves time.
    ///
    /// Nothing assigns this yet: the probe for port 123 goes out, but the reply is not
    /// yet read as NTP.
    NtpServer,

    /// Answered SNMP, so it is managed over it.
    ///
    /// Nothing assigns this yet: the reply to the probe for port 161 is parsed for
    /// operating-system evidence, but no strategy concludes the role from it.
    SnmpAgent,

    /// Answered a NetBIOS node-status request with a name table holding a
    /// suffix only a domain controller registers.
    ///
    /// `<1C>` is registered as a group name by every controller in a domain and nothing
    /// else, and `<1B>` as a unique name by the domain master browser. Either identifies
    /// the machine from one unauthenticated datagram.
    ///
    /// The reply is the evidence, as for [`DnsServer`](Self::DnsServer). A role because
    /// it is a fact about the machine, which also speaks SMB, LDAP and Kerberos as
    /// separate services.
    ///
    /// `<20>` (the server service) and `<00>` (every NetBIOS host) do not count.
    DomainController,

    /// Switches frames on behalf of the machines attached to it.
    ///
    /// Concluded from the device's own announcement (LLDP's bridge capability, or CDP's
    /// switch, transparent-bridge or source-route-bridge bits), and only where the
    /// capability is *enabled*. A switch with an unconfigured routing licence advertises
    /// routing as supported but not enabled; reading the wrong half would put a router
    /// on every access switch.
    ///
    /// Testimony, like [`DhcpServer`](Self::DhcpServer), where [`Router`](Self::Router)
    /// and [`DnsServer`](Self::DnsServer) are observed behaviour. Anything on a segment
    /// can send either, so neither is evidence about a distant machine; see
    /// [`crate::protocols::lldp`].
    ///
    /// Still worth having: a switch usually presents no open port and often holds no
    /// address, so a scan otherwise cannot see it.
    Switch,

    /// The machine this scan is running from.
    ///
    /// A sweep of the scanner's own segment reaches it, and its record is unusual:
    /// services answer over loopback, latency is not a network measurement, and no
    /// probe crossed a wire.
    ///
    /// Read from this machine's interface addresses, without sending anything.
    Origin,

    /// Reported more ports **open** than any machine plausibly runs services on.
    ///
    /// Past [`TARPIT_OPEN_PORTS`] the host is answering everything, so its open ports
    /// are not findings to act on. A deliberate tarpit and a middlebox answering by
    /// accident look the same from here.
    Tarpit,

    /// Answered on more ports than this record will hold, so the port list is
    /// incomplete.
    ///
    /// A claim about the *scan*: [`MAX_PORTS_PER_HOST`] was reached and later ports were
    /// dropped. Separate from [`Tarpit`](Self::Tarpit), which is about the host.
    ///
    /// No scan this build can run assigns it; see [`MAX_PORTS_PER_HOST`].
    Truncated,
}

impl NetworkRole {
    /// How a role is written for a person to read.
    ///
    /// Separate from [`network_role_name`](crate::record::wire::network_role_name), the
    /// wire spelling: this may be reworded, that may not.
    ///
    /// Acronyms are capitals and words are not, so a list reads `router, DNS, DHCP`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::DnsServer => "DNS",
            Self::DhcpServer => "DHCP",
            Self::NtpServer => "NTP",
            Self::SnmpAgent => "SNMP",
            // One token: roles are drawn into a space-separated list.
            Self::DomainController => "domain-controller",
            Self::Switch => "switch",
            Self::Origin => "origin",
            Self::Tarpit => "tarpit",
            Self::Truncated => "truncated",
        }
    }

    /// Every role this build knows, in declaration order, which is the order
    /// [`label`](Self::label) spells them in.
    ///
    /// Every round trip through [`wire`](crate::record::wire) is tested over this, so a
    /// new variant fails those tests until it is spelled everywhere.
    pub const ALL: &'static [Self] = &[
        Self::Router,
        Self::DnsServer,
        Self::DhcpServer,
        Self::NtpServer,
        Self::SnmpAgent,
        Self::DomainController,
        Self::Switch,
        Self::Origin,
        Self::Tarpit,
        Self::Truncated,
    ];
}

/// What the filter in front of a host was shown to be doing.
///
/// A conclusion about the *path to* a host, so separate from [`NetworkRole`]. Like a
/// role, each member is a proven fact, drawn from what a shaped probe demonstrated.
///
/// Positive claims only: the absence of a filter cannot be established.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum Filtering {
    /// An inline device answered on the host's behalf.
    ///
    /// Proven by a reply to a probe with a wrong TCP checksum. A conformant host drops
    /// such a segment unread, so the reply came from something in the path that did not
    /// validate: a firewall, an IPS, a transparent proxy, a load balancer. One reply is
    /// proof.
    InlineMiddlebox,

    /// A stateful filter: it passes a bare ACK but drops a SYN.
    ///
    /// Proven by an ACK probe drawing a RST ([`PortState::Reachable`]) from a port a SYN
    /// did not reach: the filter keeps connection state and admits no new connections.
    /// The SYN's fate is the port state already recorded; only the ACK is sent.
    StatefulFilter,

    /// A filter that trusts a source port.
    ///
    /// Proven by a SYN from a port such as 53, 20 or 88 reaching a port a SYN from an
    /// ephemeral port did not: an ACL written to let return traffic in. Compared
    /// against recorded port state, like [`StatefulFilter`](Self::StatefulFilter).
    PortTrustingAcl,

    /// A stateless filter: it matches on the first fragment and passes the rest.
    ///
    /// Proven by a *fragmented* SYN drawing an answer from a port a whole SYN did not
    /// reach: the filter judged only the first fragment, which holds the ports but not
    /// the flags, and does not reassemble. Compared against recorded port state, like
    /// [`StatefulFilter`](Self::StatefulFilter). Fragmented probes need a self-built
    /// Ethernet frame, so only hosts that path reaches are tested.
    StatelessFilter,
}

impl Filtering {
    /// Every conclusion this build knows, in declaration order, which is the
    /// order they are reported in.
    ///
    /// Sets are rendered in this order and the exported schema is built from it, so a
    /// conclusion missing here would vanish on the way to the report. A variant without
    /// a wire name in [`record::wire`](crate::record::wire) fails to compile, and that
    /// round trip is driven by this list; `model`'s test holds the order.
    pub const ALL: &'static [Self] = &[
        Self::InlineMiddlebox,
        Self::StatefulFilter,
        Self::PortTrustingAcl,
        Self::StatelessFilter,
    ];
}

/// What one source concluded, reduced to the parts that make it a *distinct*
/// claim.
///
/// Two readings saying the same thing are one claim, whatever produced them; two saying
/// different things are two, even from one kind of source.
///
/// Excludes the confidence (which varies with rule weighting) and the evidence line
/// (prose), so one claim cannot enter under several spellings.
type OsClaim = (
    OsSource,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The most distinct operating-system claims one host retains.
///
/// A host running many identifiable services can offer one claim each, and enough of
/// them combined approach a certainty none stated. Eight is above any host seen so far.
const MAX_OS_EVIDENCE: usize = 8;

/// The most names one host will have recorded against it.
///
/// A host states at most five names over NTLM, three over LDAP, a realm over Kerberos,
/// a domain over SMB1 and two in its NetBIOS table, the same way every time, so only a
/// peer inventing names per connection reaches this. Past it, new names are turned away
/// and held ones stay.
const MAX_NAMES: usize = 16;

/// A single machine, and what a scan established about it.
///
/// Identity first: the addresses it answers at, its name and its hardware. Then
/// what was found on it.
///
/// A host holds every address it is known by: a dual-stack machine answering at three
/// is one device. See [`consider_primary_ip`](Self::consider_primary_ip) for which
/// address leads.
#[must_use]
#[derive(Debug, Clone)]
pub struct Host {
    /// The primary IP address used to target or identify this host.
    primary_ip: IpAddr,

    /// All known IP addresses for this host (multi-homed support).
    ips: BTreeSet<IpAddr>,

    /// The resolved hostname (FQDN or local network name).
    hostname: Option<String>,

    /// The names the host gave for itself through its own services, each with the
    /// protocol it was given in. Separate from [`hostname`](Self::hostname); see
    /// [`name`]. Bounded by [`MAX_NAMES`].
    names: BTreeSet<HostName>,

    /// Names this record's text may contain without stating them as names: names a
    /// folded-in record knew the host by that the fold did not keep, such as a renamed
    /// machine's former name or one the ceiling turned away.
    ///
    /// For redaction only, which masks them in that text. Nothing exports, compares
    /// or writes them.
    set_aside_names: BTreeSet<String>,

    /// The current reachability status.
    status: HostStatus,

    /// Aggregated evidence explaining the current reachability status.
    reasons: HashSet<StatusReason>,

    /// Identified operating system metadata.
    ///
    /// Boxed: [`OsFingerprint`] is large and most hosts never get one.
    os: Option<Box<OsFingerprint>>,

    /// What each source concluded about this host's operating system, kept so a later
    /// source can **corroborate** an earlier one.
    ///
    /// Independent sources agreeing on a family are worth more than either; see
    /// [`resolve`](crate::fingerprint::os::resolve). Keeping only the resulting
    /// [`OsFingerprint`] would discard a later banner that scores lower on its own,
    /// along with the release only it could name.
    ///
    /// One item per distinct claim, not per source: an SSH banner naming `Debian 12`
    /// and an SNMP agent naming `kernel 6.1.0` are both `ServiceBanner` but two claims,
    /// while a stack read forty times (forty open ports) is one. Repeating an
    /// observation must never look like corroboration.
    ///
    /// Bounded by [`MAX_OS_EVIDENCE`].
    os_evidence: BTreeMap<OsClaim, OsEvidence>,

    /// Physical hardware (MAC) and vendor information.
    hardware: Option<HardwareInfo>,

    /// The interface this host was observed through, when one is known.
    ///
    /// Recorded by the link-layer strategies, the only ones that know it.
    ///
    /// An IPv6 link-local address needs it: `fe80::1` names a different machine on
    /// every segment, and a socket to one needs the interface's scope id. See
    /// [`ScopedIp`].
    zone: Option<Zone>,

    /// Network performance and path telemetry.
    telemetry: HostTelemetry,

    /// The routers between this machine and this host, when a trace ran.
    ///
    /// Empty unless a trace was asked for; see
    /// [`ZondConfig::traceroute`](crate::config::ZondConfig::traceroute).
    ///
    /// Not part of [`HostTelemetry`]: a path is a sequence of findings about *other*
    /// machines, each with its own provenance.
    path: NetworkPath,

    /// Inferred roles based on network location or discovered services.
    network_roles: HashSet<NetworkRole>,

    /// What the filter in front of this host was shown to be doing, if anything.
    filtering: HashSet<Filtering>,

    /// Which IP protocols the host's stack was shown to take delivery of.
    ///
    /// Empty unless a scan asked; see
    /// [`ZondConfig::ip_protocols`](crate::config::ZondConfig::ip_protocols). A protocol
    /// number is not a port; see [`protocol`].
    ip_protocols: BTreeMap<u8, IpProtocolState>,

    /// What a detection concluded was wrong with this host, keyed on the claim so
    /// that the same finding reached twice records once.
    ///
    /// Host-level findings are cross-cutting: a weakness inferred from several ports,
    /// or a correlation over the whole host. Per-port findings are on [`Port`]. Bounded
    /// by [`MAX_FINDINGS_PER_SUBJECT`], and keyed so a detection re-firing corroborates.
    findings: BTreeMap<ClaimId, Finding>,

    /// The timestamp of the first discovery event for this host.
    first_seen: SystemTime,

    /// The timestamp of the most recent discovery or update event.
    last_seen: SystemTime,

    /// The ports found on this host, in a stable order, bounded by
    /// [`MAX_PORTS_PER_HOST`].
    ///
    /// Keyed on number and protocol, since a number names one endpoint per transport
    /// and the TCP and UDP scanners report independently. Ordered by number first, so
    /// both transports of one number are adjacent.
    ports: BTreeMap<(u16, Protocol), Port>,

    /// How many of [`ports`](Self::ports) are [`PortState::Open`], maintained as
    /// they are recorded.
    ///
    /// [`add_port`](Self::add_port) is the only way a port enters or changes, and port
    /// state only promotes, so the count is kept incrementally; counting on demand
    /// would be quadratic on a wide scan.
    open_ports: usize,

    /// The ports recorded or given a finding since
    /// [`take_touched_ports`](Self::take_touched_ports) last emptied this.
    ///
    /// Lets a journal write down only what changed: a host scanned on every port holds
    /// tens of thousands, and a pass may touch a few. [`add_port`](Self::add_port) and
    /// [`add_port_finding`](Self::add_port_finding) are the only ways a port changes,
    /// so this sees every change.
    ///
    /// Bookkeeping, never written or read back. `None` until
    /// [`track_touched_ports`](Self::track_touched_ports) asks for it, which a scan's
    /// store does for its hosts.
    touched: Option<BTreeSet<(u16, Protocol)>>,
}

/// How well an address identifies the host holding it: lower leads.
///
/// The ordering behind [`Host::consider_primary_ip`].
///
/// Rank 1 is globally scoped: [`is_global_unicast`](crate::model::ip::is_global_unicast)
/// or unique-local, tested directly, since "not link-local" would also admit loopback,
/// multicast and the unspecified address.
fn identity_rank(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 0,
        IpAddr::V6(v6) if crate::model::ip::is_globally_scoped(v6) => 1,
        IpAddr::V6(_) => 2,
    }
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
            names: BTreeSet::new(),
            set_aside_names: BTreeSet::new(),
            status: HostStatus::Unknown,
            reasons: HashSet::new(),
            os: None,
            os_evidence: BTreeMap::new(),
            hardware: None,
            zone: None,
            telemetry: HostTelemetry::default(),
            path: NetworkPath::new(),
            network_roles: HashSet::new(),
            filtering: HashSet::new(),
            ip_protocols: BTreeMap::new(),
            findings: BTreeMap::new(),
            first_seen: now,
            last_seen: now,
            ports: BTreeMap::new(),
            open_ports: 0,
            touched: None,
        }
    }

    /// Returns the primary IP address for this host.
    pub fn primary_ip(&self) -> IpAddr {
        self.primary_ip
    }

    /// Returns all known IP addresses for this host.
    pub fn ips(&self) -> &BTreeSet<IpAddr> {
        #[cfg(test)]
        address_reads::note();
        &self.ips
    }

    /// Returns the resolved hostname, if any.
    ///
    /// What name resolution answered for the address, and the name a host is displayed
    /// under. The names a host gives for itself are [`names`](Self::names); see
    /// [`name`].
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// The names this host gave for itself, the machine's before its domain's.
    pub fn names(&self) -> impl Iterator<Item = &HostName> {
        self.names.iter()
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
    /// Only the first is kept, so the result does not depend on which strategy
    /// finished last.
    pub fn set_zone(&mut self, zone: Zone) {
        self.zone.get_or_insert(zone);
        self.last_seen = SystemTime::now();
    }

    /// This host's primary address, carrying the interface it is valid on.
    ///
    /// The address to use to *reach* the host: [`ScopedIp::to_socket_addr`] refuses to
    /// build a socket address that cannot be connected to.
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

    /// The routers between this machine and this host. Empty unless a trace ran.
    pub fn path(&self) -> &NetworkPath {
        &self.path
    }

    /// Records the hop counter a reply from this host arrived with.
    ///
    /// Every captured reply carries one, so keeping it saves a later probe.
    pub fn record_hop_counter(&mut self, arrived: u8) {
        self.telemetry.record_hop_counter(arrived);
    }

    /// Records one router on the way here.
    ///
    /// Additive and idempotent, as [`NetworkPath::record`] describes, so replies out of
    /// order or twice converge on the same path.
    pub fn record_hop(&mut self, hop: Hop) {
        self.path.record(hop);
        self.last_seen = SystemTime::now();
    }

    /// Returns inferred roles based on network location or discovered services.
    pub fn network_roles(&self) -> &HashSet<NetworkRole> {
        &self.network_roles
    }

    /// What the filter in front of this host was shown to be doing.
    pub fn filtering(&self) -> &HashSet<Filtering> {
        &self.filtering
    }

    /// What a scan concluded about each IP protocol it asked this host about,
    /// ascending by number.
    ///
    /// Empty for a scan that did not ask. A protocol at [`IpProtocolState::Unasked`]
    /// was named but not reached.
    pub fn ip_protocols(&self) -> &BTreeMap<u8, IpProtocolState> {
        &self.ip_protocols
    }

    /// Returns the timestamp of the first discovery event.
    pub fn first_seen(&self) -> SystemTime {
        self.first_seen
    }

    /// Returns the timestamp of the most recent discovery or update event.
    pub fn last_seen(&self) -> SystemTime {
        self.last_seen
    }

    /// Restores the times this host was first and last seen.
    ///
    /// For a host rebuilt from a record, whose times [`new`](Self::new) would otherwise
    /// stamp as now.
    ///
    /// Swapped if `first_seen` is after `last_seen`.
    pub fn restore_seen(&mut self, first_seen: SystemTime, last_seen: SystemTime) {
        let (first_seen, last_seen) = if first_seen <= last_seen {
            (first_seen, last_seen)
        } else {
            (last_seen, first_seen)
        };
        self.first_seen = first_seen;
        self.last_seen = last_seen;
    }

    /// Offers `candidate` as the address this host is reported under, taking it
    /// only if it identifies the host better than the current one.
    ///
    /// Returns whether the primary address changed.
    ///
    /// A dual-stack host answers at several addresses. Left to whichever probe replied
    /// first, the same machine would be reported under different addresses on
    /// different runs, which in an inventory looks like two devices. So addresses are
    /// ranked, and the ranking only moves upward:
    ///
    /// 1. **IPv4**, because it is what a person recognises and types.
    /// 2. **Globally scoped IPv6** (global unicast or unique-local), usable from
    ///    anywhere.
    /// 3. **Link-local IPv6**, meaningless without the zone
    ///    [`scoped_ip`](Self::scoped_ip) supplies.
    ///
    /// Ties keep the incumbent. Every address stays in [`ips`](Self::ips); this only
    /// decides which leads.
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

    /// Joins `ips`, a set built elsewhere, to the host's addresses, leaving
    /// `last_seen` where it is.
    ///
    /// For a reader that parsed a document's address list into a set, so the host holds
    /// that set and the document's timestamps stand.
    #[cfg(feature = "import-json")]
    pub(crate) fn adopt_ips(&mut self, ips: BTreeSet<IpAddr>) {
        let held = std::mem::replace(&mut self.ips, ips);
        self.ips.extend(held);
    }

    /// Drops every address `keep` refuses, and returns whether any is left.
    ///
    /// For the exclusion policy, which covers every address a host is known by. A
    /// refused primary is replaced by the best remaining address, ranked as in
    /// [`consider_primary_ip`](Self::consider_primary_ip).
    ///
    /// If every address is refused the host is left as it was and this returns
    /// `false`; the caller decides what to do with it.
    pub(crate) fn retain_ips(&mut self, keep: impl Fn(&IpAddr) -> bool) -> bool {
        if self.ips.iter().all(&keep) {
            return true;
        }
        let kept: BTreeSet<IpAddr> = self.ips.iter().copied().filter(&keep).collect();
        let Some(best) = kept.iter().copied().min_by_key(identity_rank) else {
            return false;
        };
        if !kept.contains(&self.primary_ip) {
            self.primary_ip = best;
        }
        self.ips = kept;
        true
    }

    /// Withholds the address of every router or middlebox this host's record
    /// names that `keep` refuses, and returns whether it withheld any.
    ///
    /// The exclusion policy's other half beside [`retain_ips`](Self::retain_ips). A
    /// refused intermediary goes unnamed but its finding stays, since it is a fact
    /// about this host: a router on the path keeps its distance ([`Hop::withheld`]),
    /// and the sender of second-hand evidence keeps its reason
    /// ([`EvidenceSource::Withheld`]).
    pub(crate) fn withhold_intermediaries(&mut self, keep: impl Fn(&IpAddr) -> bool) -> bool {
        let routers = self.path.withhold(&keep);

        // A reason is its own hash key, so one whose sender changes is taken out
        // and put back. Checked first because this runs on every finding and
        // nothing usually needs to move.
        let refused = |reason: &StatusReason| {
            reason
                .source
                .address()
                .is_some_and(|address| !keep(&address))
        };
        let senders = self.reasons.iter().any(refused);
        if senders {
            self.reasons = std::mem::take(&mut self.reasons)
                .into_iter()
                .map(|mut reason| {
                    reason.source.withhold(&keep);
                    reason
                })
                .collect();
        }

        routers || senders
    }

    /// Drops every port of this record that `ports` holds.
    ///
    /// For a record restored into a sitting that excludes those ports; kept, a port
    /// would be handed to every later pass, which would connect to it.
    pub(crate) fn withhold_ports(&mut self, ports: &PortSet) {
        if ports.is_empty() {
            return;
        }
        self.ports
            .retain(|&(number, protocol), _| !ports.contains(number, protocol));
        self.open_ports = self
            .ports
            .values()
            .filter(|port| port.state() == PortState::Open)
            .count();
    }

    /// Records the name this host resolved to, replacing any already recorded.
    ///
    /// The one field that is overwritten: a hostname has no ordering that says which
    /// answer knows more, and `None` clears the name. [`merge`](Self::merge) keeps the
    /// incumbent instead.
    pub fn set_hostname(&mut self, hostname: Option<String>) {
        self.hostname = hostname;
        self.last_seen = SystemTime::now();
    }

    /// Records a name the host gave for itself, returning whether it is one not
    /// already held.
    ///
    /// Accumulates: two services stating different names are two claims. Past a ceiling
    /// of sixteen names, a new one is turned away. Bumps `last_seen` either way.
    pub fn record_name(&mut self, name: HostName) -> bool {
        self.last_seen = SystemTime::now();
        self.admit_name(name).unwrap_or(false)
    }

    /// Records `name` unless the ceiling turns it away, returning whether it
    /// is new, or handing it back when it was turned away.
    fn admit_name(&mut self, name: HostName) -> Result<bool, HostName> {
        if self.names.len() >= MAX_NAMES && !self.names.contains(&name) {
            return Err(name);
        }
        Ok(self.names.insert(name))
    }

    /// The names this record's text may hold without stating them as names,
    /// which a fold of the host's records set aside, for redaction to mask
    /// there too.
    pub(crate) fn set_aside_names(&self) -> impl Iterator<Item = &str> {
        self.set_aside_names.iter().map(String::as_str)
    }

    /// Sets aside every name `account`, another record of this host whose text
    /// a fold keeps, knew the host by and this record does not state.
    pub(crate) fn set_aside_names_of(&mut self, account: &Host) {
        for name in account
            .hostname()
            .into_iter()
            .chain(account.names().map(HostName::name))
            .chain(account.set_aside_names())
        {
            self.set_aside(name);
        }
    }

    /// Sets `name` aside, unless this record states it.
    fn set_aside(&mut self, name: &str) {
        let stated = self.hostname.as_deref() == Some(name)
            || self.names.iter().any(|held| held.name() == name);
        if !stated && !self.set_aside_names.contains(name) {
            self.set_aside_names.insert(name.to_owned());
        }
    }

    /// Raises the reachability status to `status`, if that is an improvement.
    ///
    /// Promotes and never lowers, like [`record_evidence`](Self::record_evidence). For a
    /// caller with no [`StatusReason`]; otherwise prefer `record_evidence`, which keeps
    /// the audit trail.
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
    /// How a scanner reports what it saw: verdict and evidence together.
    /// ([`set_status`](Self::set_status) and [`add_reason`](Self::add_reason) do each
    /// half separately.) The status is **promoted, never lowered**, on the ordering of
    /// [`HostStatus`], as [`Host::merge`](Host::merge) does too: an ICMP unreachable
    /// from a router landing after an ARP reply must not overwrite proof the host
    /// answered.
    ///
    /// The reason is kept whether or not the status moved, so an `Up` host still gains
    /// the audit trail.
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

    /// What each source has concluded about this host's operating system.
    ///
    /// The input [`resolve`](crate::fingerprint::os::resolve) runs over, so a late
    /// source can raise a verdict.
    pub fn os_evidence(&self) -> impl Iterator<Item = &OsEvidence> {
        self.os_evidence.values()
    }

    /// This host's findings, in a stable order.
    ///
    /// Weaknesses of the host as a whole; a port's findings are on the [`Port`]. Ordered
    /// by claim.
    pub fn findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.values()
    }

    /// Files what one source concluded, keeping the strongest reading per
    /// source.
    ///
    /// Returns whether this changed what is on record, so a caller can tell a
    /// genuine new finding from the same one arriving again.
    ///
    /// One entry per claim, so a stack read forty times (forty open ports) counts once
    /// and cannot turn one observation into certainty.
    pub fn record_os_evidence(&mut self, evidence: OsEvidence) -> bool {
        let claim: OsClaim = (
            evidence.source,
            evidence.family.clone(),
            evidence.device.clone(),
            evidence.vendor.clone(),
            evidence.product.clone(),
            evidence.version.clone(),
            evidence.kernel.clone(),
        );

        // Read before borrowing the map; a claim already on record needs no room.
        let full = self.os_evidence.len() >= MAX_OS_EVIDENCE;

        match self.os_evidence.get_mut(&claim) {
            // The same claim, possibly by a different route (one reply versus a
            // series). Keep the strongest confidence and every distinct line.
            Some(existing) => {
                let joined = os::join_readings(&existing.evidence, &evidence.evidence);
                let changed = joined != existing.evidence;

                existing.evidence = joined;
                existing.confidence = existing.confidence.max(evidence.confidence);
                changed
            }
            // The ceiling only turns away something new.
            None if full => false,
            None => {
                self.os_evidence.insert(claim, evidence);
                true
            }
        }
    }

    /// Records a finding about this host, and reports whether it was new
    /// information: a claim not seen before, or a stronger reading of one that
    /// was.
    ///
    /// A finding reached again folds into the one on record through
    /// [`Finding::corroborate`]. The ceiling turns away only new claims, so a subject at
    /// the limit still updates what it holds.
    pub fn add_finding(&mut self, finding: Finding) -> bool {
        let claim = finding.claim_id();

        // Read before borrowing the map; a claim already on record needs no room.
        let full = self.findings.len() >= MAX_FINDINGS_PER_SUBJECT;

        match self.findings.get_mut(&claim) {
            Some(existing) => existing.corroborate(finding),
            None if full => false,
            None => {
                self.findings.insert(claim, finding);
                true
            }
        }
    }

    /// Records a finding about one of this host's ports, and reports whether it was
    /// new.
    ///
    /// For a report-level pass such as CVE correlation, which reads a port's service
    /// identification and hands a finding back to that port by number and protocol.
    ///
    /// `None` where this host has no such port; `Some(false)` where the port already
    /// has the claim or is at [`MAX_FINDINGS_PER_SUBJECT`].
    pub fn add_port_finding(
        &mut self,
        number: u16,
        protocol: Protocol,
        finding: Finding,
    ) -> Option<bool> {
        let key = (number, protocol);
        let port = self.ports.get_mut(&key)?;
        if let Some(touched) = &mut self.touched {
            touched.insert(key);
        }
        Some(port.add_finding(finding))
    }

    /// Replaces every correlation `detection` drew on the port at `number` and
    /// `protocol` with `findings`. See [`Port::replace_correlations`].
    ///
    /// `None` where this host has no such port, `Some(false)` where the port
    /// already held exactly these.
    pub(crate) fn replace_port_correlations(
        &mut self,
        number: u16,
        protocol: Protocol,
        detection: &str,
        findings: Vec<Finding>,
    ) -> Option<bool> {
        let key = (number, protocol);
        let port = self.ports.get_mut(&key)?;
        let changed = port.replace_correlations(detection, findings);
        if changed && let Some(touched) = &mut self.touched {
            touched.insert(key);
        }
        Some(changed)
    }

    /// Replaces this host's operating-system fingerprint outright, whatever was
    /// there before, and stamps the host as seen now.
    ///
    /// For a caller holding a complete [`OsFingerprint`], such as one read back from a
    /// report. To fold in a second opinion, use [`merge`](Self::merge).
    pub fn set_os(&mut self, os: OsFingerprint) {
        self.os = Some(Box::new(os));
        self.last_seen = SystemTime::now();
    }

    /// Withdraws this host's operating-system fingerprint.
    ///
    /// For a caller that re-resolved the evidence and found it no longer supports what
    /// is on record. A scan should not clear a finding just because a later phase did
    /// not re-derive it.
    pub fn clear_os(&mut self) {
        self.os = None;
        self.last_seen = SystemTime::now();
    }

    /// Replaces this host's hardware record wholesale.
    ///
    /// For a caller holding a complete [`HardwareInfo`], such as one read back from a
    /// report. A single sighting goes through [`record_mac`](Self::record_mac).
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
    /// Adds to the history [`HardwareInfo`] keeps: a device with two interfaces on one
    /// segment, or one randomizing its MAC, answers under several addresses and is one
    /// host. [`most_recent_mac`] and [`prune_stale_macs`] rely on the history.
    ///
    /// Repeating a MAC already on record refreshes its last-seen time.
    ///
    /// Bounded by [`MAX_MACS_PER_HOST`](hardware::MAX_MACS_PER_HOST), since a source
    /// address is just a field in a frame.
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

    /// The same, from a caller that knows which probe drew the reply.
    ///
    /// The probe decides what the figure measures: an ARP reply comes off the link
    /// layer, a SYN/ACK crosses the target's IP and TCP stacks.
    pub fn add_rtt_from(&mut self, rtt: std::time::Duration, protocol: StatusProtocol) {
        self.telemetry.add_rtt_from(rtt, protocol);
        self.last_seen = SystemTime::now();
    }

    /// Which probe this host's round trips were measured from, where they agree
    /// on one.
    ///
    /// See [`HostTelemetry::rtt_protocol`](crate::model::host::telemetry::HostTelemetry::rtt_protocol).
    #[must_use]
    pub fn rtt_protocol(&self) -> Option<StatusProtocol> {
        self.telemetry.rtt_protocol()
    }

    /// Adds a round trip measured against a probe the whole segment was asked,
    /// which this host will report only if it produced no better sample.
    ///
    /// See [`RttSource`](crate::model::host::telemetry::RttSource).
    pub fn add_segment_wide_rtt(&mut self, rtt: std::time::Duration) {
        self.telemetry.add_segment_wide_rtt(rtt);
        self.last_seen = SystemTime::now();
    }

    /// The same, from a caller that knows which probe drew the reply.
    pub fn add_segment_wide_rtt_from(
        &mut self,
        rtt: std::time::Duration,
        protocol: StatusProtocol,
    ) {
        self.telemetry.add_segment_wide_rtt_from(rtt, protocol);
        self.last_seen = SystemTime::now();
    }

    /// Adds a round trip timed from the first probe sent to a neighbour,
    /// which this host will report only if it produced no better sample: the
    /// probe may have waited on the neighbour's address resolution.
    ///
    /// See [`RttSource`](crate::model::host::telemetry::RttSource).
    pub fn add_first_to_neighbour_rtt_from(
        &mut self,
        rtt: std::time::Duration,
        protocol: StatusProtocol,
    ) {
        self.telemetry
            .add_first_to_neighbour_rtt_from(rtt, protocol);
        self.last_seen = SystemTime::now();
    }

    /// Builder method to add a single RTT measurement and return Self.
    pub fn with_rtt(mut self, rtt: std::time::Duration) -> Self {
        self.add_rtt(rtt);
        self
    }

    /// Adds a round-trip sample read back from a record; see
    /// [`HostTelemetry::restore_rtt`](crate::model::host::telemetry::HostTelemetry::restore_rtt).
    pub(crate) fn restore_rtt(
        &mut self,
        rtt: std::time::Duration,
        source: crate::model::host::telemetry::RttSource,
        protocol: Option<StatusProtocol>,
    ) {
        self.telemetry.restore_rtt(rtt, source, protocol);
    }

    /// Records several round-trip measurements at once.
    pub fn add_rtts(&mut self, rtts: impl IntoIterator<Item = std::time::Duration>) {
        for rtt in rtts {
            self.telemetry.add_rtt(rtt);
        }
        self.last_seen = SystemTime::now();
    }

    /// Records a role for this host, returning whether it is one the record did
    /// not already carry.
    ///
    /// The same evidence recurs (a router advertises on a timer, a name server answers
    /// every lookup), so the return says whether this is news. Bumps `last_seen` either
    /// way.
    pub fn add_network_role(&mut self, role: NetworkRole) -> bool {
        let is_new = self.network_roles.insert(role);
        self.last_seen = SystemTime::now();
        is_new
    }

    /// Records a filtering conclusion drawn about the path to this host,
    /// returning whether it is one not already held.
    ///
    /// Bumps `last_seen`, as [`add_network_role`](Self::add_network_role) does.
    pub fn add_filtering(&mut self, filtering: Filtering) -> bool {
        let is_new = self.filtering.insert(filtering);
        self.last_seen = SystemTime::now();
        is_new
    }

    /// Raises what is recorded about `number` to `state`, if that establishes
    /// more, and returns whether the record changed.
    ///
    /// Promotes and never lowers, on [`IpProtocolState`]'s ordering, as
    /// [`Port::set_state`] does. So [`Unasked`](IpProtocolState::Unasked) stands only
    /// where nothing else was recorded.
    ///
    /// Bumps `last_seen` only where the host itself answered, not on silence or a
    /// router's refusal.
    pub fn record_ip_protocol(&mut self, number: u8, state: IpProtocolState) -> bool {
        let recorded = match self.ip_protocols.get_mut(&number) {
            Some(held) if state > *held => {
                *held = state;
                true
            }
            Some(_) => false,
            // Recorded even at `Unasked`: named but not reached.
            None => {
                self.ip_protocols.insert(number, state);
                true
            }
        };

        if matches!(state, IpProtocolState::Open | IpProtocolState::Closed) {
            self.last_seen = SystemTime::now();
        }
        recorded
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
    /// (either responding for itself or blocked on its behalf).
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
    /// [`MAX_PORTS_PER_HOST`] and has been marked [`NetworkRole::Truncated`], which no
    /// scan reaches (see [`Truncated`](NetworkRole::Truncated)).
    ///
    /// A host past [`TARPIT_OPEN_PORTS`] open ports is marked [`NetworkRole::Tarpit`]
    /// and keeps recording, so a caller can still discard the ports itself.
    pub fn add_port(&mut self, new_port: Port) -> bool {
        let key = (new_port.number(), new_port.protocol());
        let existing = self.ports.get(&key);

        if existing.is_none() && self.ports.len() >= MAX_PORTS_PER_HOST {
            self.network_roles.insert(NetworkRole::Truncated);
            return false;
        }

        let was_open = existing.is_some_and(|port| port.state() == PortState::Open);

        // A match on the entry avoids cloning `new_port`, which `and_modify` with
        // `or_insert` would need; a `Port` is not cheap to copy.
        let recorded = match self.ports.entry(key) {
            std::collections::btree_map::Entry::Occupied(slot) => {
                let recorded = slot.into_mut();
                recorded.merge(new_port);
                recorded
            }
            std::collections::btree_map::Entry::Vacant(slot) => slot.insert(new_port),
        };
        if let Some(touched) = &mut self.touched {
            touched.insert(key);
        }

        // State only promotes, so this only counts up; see `open_ports`.
        if !was_open && recorded.state() == PortState::Open {
            self.open_ports += 1;
            if self.open_ports >= TARPIT_OPEN_PORTS {
                self.network_roles.insert(NetworkRole::Tarpit);
            }
        }

        self.last_seen = SystemTime::now();
        true
    }

    /// How many of this host's ports are open.
    pub fn open_port_count(&self) -> usize {
        self.open_ports
    }

    /// Starts keeping which ports are recorded or given a finding, for
    /// [`take_touched_ports`](Self::take_touched_ports) to hand over. Keeps
    /// what is kept already.
    pub(crate) fn track_touched_ports(&mut self) {
        self.touched.get_or_insert_with(BTreeSet::new);
    }

    /// The ports recorded or given a finding since this was last called,
    /// leaving none marked; `None` for a host nothing asked to track them.
    ///
    /// Touched, not changed: a port re-recorded with nothing new is still named. See
    /// `touched`.
    pub(crate) fn take_touched_ports(&mut self) -> Option<BTreeSet<(u16, Protocol)>> {
        self.touched.as_mut().map(std::mem::take)
    }

    /// A copy of this host carrying only the ports `keys` name, of those it
    /// holds, and tracking none.
    ///
    /// What a journal writes when a few ports of a wide host changed. Only ever
    /// written down, where its ports fold into what the file already holds.
    #[cfg(feature = "journal-format")]
    pub(crate) fn with_only_ports(&self, keys: &BTreeSet<(u16, Protocol)>) -> Self {
        // Destructured, so a new field fails to compile until it is copied.
        let Self {
            primary_ip,
            ips,
            hostname,
            names,
            set_aside_names,
            status,
            reasons,
            os,
            os_evidence,
            hardware,
            zone,
            telemetry,
            path,
            network_roles,
            filtering,
            ip_protocols,
            findings,
            first_seen,
            last_seen,
            ports,
            open_ports,
            touched: _,
        } = self;
        // Every port named (the first checkpoint after a wide port scan) copies
        // the map whole. Ports are never removed, so equal counts mean all.
        let (ports, open_ports) = if keys.len() == ports.len() {
            (ports.clone(), *open_ports)
        } else {
            let ports: BTreeMap<_, _> = keys
                .iter()
                .filter_map(|key| ports.get_key_value(key))
                .map(|(key, port)| (*key, port.clone()))
                .collect();
            let open = ports
                .values()
                .filter(|port| port.state() == PortState::Open)
                .count();
            (ports, open)
        };
        Self {
            primary_ip: *primary_ip,
            ips: ips.clone(),
            hostname: hostname.clone(),
            names: names.clone(),
            set_aside_names: set_aside_names.clone(),
            status: *status,
            reasons: reasons.clone(),
            os: os.clone(),
            os_evidence: os_evidence.clone(),
            hardware: hardware.clone(),
            zone: zone.clone(),
            telemetry: telemetry.clone(),
            path: path.clone(),
            network_roles: network_roles.clone(),
            filtering: filtering.clone(),
            ip_protocols: ip_protocols.clone(),
            findings: findings.clone(),
            first_seen: *first_seen,
            last_seen: *last_seen,
            ports,
            open_ports,
            touched: None,
        }
    }

    /// Folds `later`, an account of this host written after the one this
    /// holds, its round trips replacing these.
    ///
    /// For a journal record, which carries the whole window of round trips as it stood:
    /// a later one repeats every earlier sample, which would otherwise count twice. A
    /// later account with no round trips leaves these. Everything else folds as
    /// [`merge`](Self::merge) does.
    pub(crate) fn merge_later_account(&mut self, later: Host) {
        let window = later.telemetry.clone();
        self.merge(later);
        self.telemetry.take_window(window);
    }

    /// Folds another record of this host into this one.
    ///
    /// How findings from separate scan stages become one record. Status is promoted and
    /// never lowered, telemetry and OS data merge by their own rules, and the port cap
    /// still applies.
    ///
    /// The leading address is decided by
    /// [`consider_primary_ip`](Self::consider_primary_ip), whichever record is `self`.
    pub fn merge(&mut self, other: Host) {
        // Destructured, so a new field fails to compile until it is merged.
        let Host {
            primary_ip: other_primary,
            ips,
            hostname,
            names,
            set_aside_names,
            status,
            reasons,
            os,
            os_evidence,
            hardware,
            zone,
            telemetry,
            path,
            network_roles,
            filtering,
            ip_protocols,
            findings,
            first_seen: other_first_seen,
            last_seen: other_last_seen,
            ports,
            // Derived, and maintained by `add_port` as the ports below arrive.
            open_ports: _,
            // `add_port` marks the ports a merge touches; `other`'s marks do not
            // apply here.
            touched: _,
        } = other;

        // Taken first and restored at the end: the mutators below stamp
        // `last_seen` with now, but a merge is not a sighting.
        let first_seen = self.first_seen.min(other_first_seen);
        let last_seen = self.last_seen.max(other_last_seen);

        self.ips.extend(ips);
        self.consider_primary_ip(other_primary);

        // A name the fold does not keep is set aside, since the text folded in
        // below can hold it.
        if self.hostname.is_none() {
            self.hostname = hostname;
        } else if let Some(offered) = hostname {
            self.set_aside(&offered);
        }
        for name in names {
            if let Err(turned_away) = self.admit_name(name) {
                self.set_aside(turned_away.name());
            }
        }
        for name in &set_aside_names {
            self.set_aside(name);
        }

        if status > self.status {
            self.status = status;
        }
        self.reasons.extend(reasons);

        if let Some(other_os) = os {
            if let Some(ref mut self_os) = self.os {
                self_os.merge(*other_os);
            } else {
                self.os = Some(other_os);
            }
        }

        // Through `record_os_evidence`, so one claim keeps the strongest confidence
        // and every distinct line, and the ceiling turns away only what is new.
        for evidence in os_evidence.into_values() {
            self.record_os_evidence(evidence);
        }

        if let Some(other_hw) = hardware {
            if let Some(ref mut self_hw) = self.hardware {
                self_hw.merge(other_hw);
            } else {
                self.hardware = Some(other_hw);
            }
        }

        if let Some(other_zone) = zone {
            self.zone.get_or_insert(other_zone);
        }

        self.telemetry.merge(telemetry);

        // Hop by hop, so `NetworkPath::record` decides each distance: a
        // measurement beats an inference, an answer beats silence. A port scan
        // folds a liveness snapshot taken before the trace with one taken after,
        // so the earlier record has no path.
        for hop in path.hops() {
            self.path.record(*hop);
        }

        self.network_roles.extend(network_roles);

        // Only one of the two records may have run the comparative probe.
        self.filtering.extend(filtering);

        // Through the recorder, so a sitting cut short at `Unasked` cannot lower
        // a verdict another sitting reached.
        for (number, state) in ip_protocols {
            self.record_ip_protocol(number, state);
        }

        // A claim missing from one record is a detection that did not run there,
        // so a fold only adds. A claim on both corroborates through `add_finding`.
        for finding in findings.into_values() {
            self.add_finding(finding);
        }

        for port in ports.into_values() {
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

        // In `NetworkRole::ALL` order, since a `HashSet`'s order is not stable.
        let mut roles = NetworkRole::ALL
            .iter()
            .filter(|role| self.network_roles.contains(role))
            .peekable();
        if roles.peek().is_some() {
            write!(f, " [")?;
            for (n, role) in roles.enumerate() {
                if n > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}", role.label())?;
            }
            write!(f, "]")?;
        }

        // For a tarpit or truncated host, the marking replaces the latency.
        if !self.network_roles.contains(&NetworkRole::Tarpit)
            && !self.network_roles.contains(&NetworkRole::Truncated)
        {
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

    static IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100));

    /// Refusing the leading address hands the lead to the best remaining one, by the
    /// same ranking.
    #[test]
    fn a_refused_lead_passes_to_the_best_address_left() {
        let v4: IpAddr = "192.0.2.60".parse().expect("literal");
        let global: IpAddr = "2001:db8::5".parse().expect("literal");
        let link_local: IpAddr = "fe80::10".parse().expect("literal");

        let mut host = Host::new(link_local);
        host.add_ip(global);
        host.consider_primary_ip(v4);
        assert_eq!(host.primary_ip(), v4, "test premise");

        assert!(host.retain_ips(|ip| *ip != v4));
        assert_eq!(host.primary_ip(), global);
        assert_eq!(
            host.ips().iter().copied().collect::<Vec<_>>(),
            vec![global, link_local]
        );
    }

    /// A host with every address refused is handed back as it was.
    #[test]
    fn a_host_every_address_of_which_is_refused_is_left_as_it_was() {
        let mut host = Host::new(IP_ADDR);
        host.add_ip("192.0.2.61".parse().expect("literal"));
        let before = host.ips().clone();

        assert!(!host.retain_ips(|_| false));
        assert_eq!(host.primary_ip(), IP_ADDR);
        assert_eq!(*host.ips(), before);
    }

    /// A pass that only named a protocol cannot lower one that was reached.
    #[test]
    fn a_protocol_verdict_is_promoted_and_never_lowered() {
        use crate::model::host::IpProtocolState;

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));

        assert!(host.record_ip_protocol(47, IpProtocolState::Unasked));
        assert_eq!(
            host.ip_protocols().get(&47),
            Some(&IpProtocolState::Unasked)
        );

        assert!(host.record_ip_protocol(47, IpProtocolState::Closed));
        assert!(
            !host.record_ip_protocol(47, IpProtocolState::OpenOrNoReply),
            "a weaker verdict is not news"
        );
        assert_eq!(host.ip_protocols().get(&47), Some(&IpProtocolState::Closed));

        assert!(host.record_ip_protocol(47, IpProtocolState::Open));
        assert_eq!(host.ip_protocols().get(&47), Some(&IpProtocolState::Open));
    }

    /// The same rule across a fold.
    #[test]
    fn merging_keeps_the_stronger_protocol_verdict_from_either_side() {
        use crate::model::host::IpProtocolState;

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        let mut reached = Host::new(ip);
        reached.record_ip_protocol(47, IpProtocolState::Open);
        reached.record_ip_protocol(89, IpProtocolState::Unasked);

        let mut cut_short = Host::new(ip);
        cut_short.record_ip_protocol(47, IpProtocolState::Unasked);
        cut_short.record_ip_protocol(89, IpProtocolState::Closed);
        cut_short.record_ip_protocol(50, IpProtocolState::OpenOrNoReply);

        let mut folded = reached.clone();
        folded.merge(cut_short.clone());
        let mut other_way = cut_short;
        other_way.merge(reached);

        for host in [&folded, &other_way] {
            assert_eq!(host.ip_protocols().get(&47), Some(&IpProtocolState::Open));
            assert_eq!(host.ip_protocols().get(&89), Some(&IpProtocolState::Closed));
            assert_eq!(
                host.ip_protocols().get(&50),
                Some(&IpProtocolState::OpenOrNoReply),
                "a protocol only one side asked about survives the fold"
            );
        }
    }

    /// `filtering` and `os_evidence` from the record folded in survive the merge.
    #[test]
    fn a_merge_keeps_every_field_of_the_record_it_folds_in() {
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");
        let mut incumbent = Host::new(ip);
        let mut arriving = Host::new(ip);

        arriving.add_filtering(Filtering::StatefulFilter);
        arriving.add_filtering(Filtering::InlineMiddlebox);
        arriving.record_os_evidence(OsEvidence {
            source: OsSource::ServiceBanner,
            family: Some("Linux".to_string()),
            device: None,
            vendor: None,
            product: None,
            version: None,
            kernel: Some("6.1.0".to_string()),
            arch: None,
            cpe: None,
            confidence: 0.9,
            evidence: "ssh banner".to_string(),
        });

        incumbent.merge(arriving);

        assert_eq!(
            incumbent.filtering().len(),
            2,
            "a filtering conclusion is drawn by a comparative probe only one \
             record will have run, so dropping it loses the whole finding"
        );
        assert_eq!(
            incumbent.os_evidence().count(),
            1,
            "os evidence is what corroboration is computed over, and the \
             fold is where a second source's reading arrives"
        );
    }

    /// A host's own names accumulate across a merge, and a peer inventing names is held
    /// to [`MAX_NAMES`] without displacing those already held.
    #[test]
    fn names_accumulate_across_a_merge_up_to_the_ceiling() {
        let name = |kind, text: &str| HostName::new(kind, NameSource::Ntlm, text).expect("a name");

        let mut earlier = Host::new(IP_ADDR);
        earlier.record_name(name(NameKind::Host, "dc01.corp.example"));
        let mut later = Host::new(IP_ADDR);
        later.record_name(name(NameKind::Host, "dc01.corp.example"));
        later.record_name(name(NameKind::Domain, "corp.example"));
        earlier.merge(later);
        assert_eq!(
            earlier.names().map(HostName::name).collect::<Vec<_>>(),
            ["dc01.corp.example", "corp.example"],
            "the same name from both records is one claim"
        );

        let mut flooded = Host::new(IP_ADDR);
        for n in 0..MAX_NAMES {
            assert!(flooded.record_name(name(NameKind::NetbiosHost, &format!("HOST{n:02}"))));
        }
        assert!(!flooded.record_name(name(NameKind::NetbiosHost, "ONE-MORE")));
        assert!(
            !flooded.record_name(name(NameKind::NetbiosHost, "HOST00")),
            "a name already held is not news"
        );
        assert_eq!(flooded.names().count(), MAX_NAMES);
    }

    /// A merge keeps what only the later record knows, such as a path and hop counter
    /// measured after the liveness snapshot. Asserted with the lacking record on the
    /// left, as the port scan merges.
    #[test]
    fn a_merge_keeps_what_only_the_other_record_learned() {
        let mut earlier = Host::new(IP_ADDR);
        earlier.set_status(HostStatus::Up);

        let mut later = Host::new(IP_ADDR);
        later.record_hop_counter(59);
        later.record_hop(path::Hop::answered(
            1,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            None,
        ));
        later.record_hop(path::Hop::silent(2));

        earlier.merge(later);

        assert_eq!(
            earlier.path().hops().len(),
            2,
            "the trace ran between the two snapshots and only the later one has it"
        );
        assert_eq!(earlier.path().length(), Some(2));
        assert_eq!(earlier.telemetry().hop_counter(), Some(59));
    }

    /// Merging two paths settles each distance on its own terms.
    ///
    /// Two records can each know a different half, and an inferred distance yields to a
    /// measured one.
    #[test]
    fn merging_paths_keeps_the_stronger_claim_at_every_distance() {
        let router = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

        let mut inherited = Host::new(IP_ADDR);
        inherited.record_hop(path::Hop::answered(1, router, None).as_inferred());
        inherited.record_hop(path::Hop::silent(2));

        let mut measured = Host::new(IP_ADDR);
        measured.record_hop(path::Hop::answered(
            1,
            router,
            Some(std::time::Duration::from_millis(3)),
        ));

        inherited.merge(measured);

        let hops = inherited.path().hops();
        assert_eq!(hops.len(), 2, "the distance only one side knew survives");
        assert!(!hops[0].inferred(), "a measurement replaces an inference");
        assert_eq!(hops[0].rtt(), Some(std::time::Duration::from_millis(3)));
    }

    /// A status only improves, through every entry point that sets one.
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

    /// A port number names one endpoint per transport, and the two are kept apart.
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

        // A repeat still merges with its own protocol.
        host.add_port(Port::new(53, Protocol::Tcp, PortState::Open));
        assert_eq!(host.port_count(), 2);
        assert_eq!(
            host.ports().next().expect("tcp/53").state(),
            PortState::Open
        );
    }

    /// The role line is in a stable order, unlike the `HashSet` that holds the roles.
    #[test]
    fn a_host_prints_its_roles_in_one_order_however_they_were_recorded() {
        let expected = "203.0.113.100 (Up) [router, DNS, origin]";

        for order in [
            [
                NetworkRole::Router,
                NetworkRole::DnsServer,
                NetworkRole::Origin,
            ],
            [
                NetworkRole::Origin,
                NetworkRole::Router,
                NetworkRole::DnsServer,
            ],
            [
                NetworkRole::DnsServer,
                NetworkRole::Origin,
                NetworkRole::Router,
            ],
        ] {
            let mut host = Host::new(IP_ADDR);
            host.set_status(HostStatus::Up);
            for role in order {
                host.add_network_role(role);
            }

            let line = host.to_string();
            let (roles, _telemetry) = line.rsplit_once(" [").expect("telemetry follows the roles");
            assert_eq!(roles, expected, "recorded as {order:?}");
        }
    }

    /// For a tarpit or truncated host, the marking replaces the latency.
    #[test]
    fn a_tarpit_prints_the_marking_where_the_latency_would_be() {
        let mut host = Host::new(IP_ADDR);
        host.set_status(HostStatus::Up);
        host.add_network_role(NetworkRole::Tarpit);

        assert_eq!(host.to_string(), "203.0.113.100 (Up) [tarpit]");
    }

    /// The largest scan a person can write, recorded whole.
    ///
    /// `1-65535,u:1-65535` against a host answering on all of it is
    /// `MAX_PORTS_PER_HOST` endpoints, all kept, and the record is complete.
    #[test]
    fn a_full_scan_of_both_transports_is_recorded_whole() {
        let mut host = Host::new(IP_ADDR);

        for &protocol in Protocol::ALL {
            for port in u16::MIN..=u16::MAX {
                assert!(
                    host.add_port(Port::new(port, protocol, PortState::Closed)),
                    "{protocol:?}/{port} was refused by a scan that asked for it"
                );
            }
        }

        assert_eq!(host.port_count(), MAX_PORTS_PER_HOST);
        assert!(
            !host.network_roles().contains(&NetworkRole::Truncated),
            "a complete port list was reported as truncated"
        );
    }

    /// The cap sits exactly at what the map can hold, so no scan reaches it.
    ///
    /// The map is keyed on port number and transport, and the cap is derived from the
    /// same two.
    #[test]
    fn the_cap_is_what_the_port_map_can_hold() {
        let endpoints = (usize::from(u16::MAX) + 1) * Protocol::ALL.len();
        assert_eq!(MAX_PORTS_PER_HOST, endpoints);
    }

    /// A wide scan of an ordinary host is neither truncated nor a tarpit.
    #[test]
    fn a_wide_scan_of_an_ordinary_host_is_neither_truncated_nor_a_tarpit() {
        let mut host = Host::new(IP_ADDR);
        for port in 1..=1024u16 {
            let state = match port {
                53 | 80 => PortState::Open,
                _ => PortState::Closed,
            };
            assert!(host.add_port(Port::new(port, Protocol::Tcp, state)));
        }

        assert_eq!(host.port_count(), 1024, "every finding was kept");
        assert!(host.network_roles().is_empty(), "and nothing was inferred");
    }

    /// A thousand *open* ports marks a tarpit, and recording continues.
    #[test]
    fn a_host_answering_open_on_everything_is_called_what_it_is() {
        let mut host = Host::new(IP_ADDR);
        for port in 0..TARPIT_OPEN_PORTS {
            host.add_port(Port::new(port as u16, Protocol::Tcp, PortState::Open));
        }

        assert!(host.network_roles().contains(&NetworkRole::Tarpit));
        assert!(!host.network_roles().contains(&NetworkRole::Truncated));
        assert_eq!(host.open_port_count(), TARPIT_OPEN_PORTS);
    }

    /// The count follows promotions, not insertions. A port first met with silence
    /// and later answered is one more open port, and a second reply about a port
    /// already open is not.
    #[test]
    fn the_open_count_follows_what_the_ports_became() {
        let mut host = Host::new(IP_ADDR);

        host.add_port(Port::new(22, Protocol::Tcp, PortState::NoReply));
        assert_eq!(host.open_port_count(), 0);

        host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        assert_eq!(host.open_port_count(), 1, "promoted");

        host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        assert_eq!(host.open_port_count(), 1, "and counted once");
    }

    /// A merge is not a sighting, so it does not move `last_seen`.
    ///
    /// Stamped by hand: on Windows two constructions can land on the same
    /// `SystemTime` tick.
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
        h2.set_status(HostStatus::Blocked);

        h1.merge(h2);
        assert_eq!(h1.status(), HostStatus::Blocked);
    }

    /// The leading address after a merge follows [`Host::consider_primary_ip`],
    /// whichever record is `self`.
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

    /// MACs accumulate into a history, so [`HardwareInfo::most_recent_mac`] reports a
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

    /// A host kept by a scan's store names the ports each edit recorded or
    /// gave a finding, and a host built anywhere else keeps no such list.
    ///
    /// A journal copies these ports of a wide host, so a missed one would never be
    /// written.
    #[test]
    fn a_tracked_host_names_the_ports_an_edit_touched() {
        let mut host = Host::new(IP_ADDR);
        host.add_port(Port::new(22, Protocol::Tcp, PortState::Closed));
        assert_eq!(host.take_touched_ports(), None, "nothing asked to track");

        host.track_touched_ports();
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Open));
        let touched = host.take_touched_ports().expect("tracked");
        assert_eq!(
            touched.into_iter().collect::<Vec<_>>(),
            [(80, Protocol::Tcp)]
        );

        let _ = host.add_port_finding(22, Protocol::Tcp, a_finding("det-a"));
        let touched = host.take_touched_ports().expect("tracked");
        assert_eq!(
            touched.into_iter().collect::<Vec<_>>(),
            [(22, Protocol::Tcp)]
        );
        assert_eq!(host.take_touched_ports(), Some(BTreeSet::new()), "taken");

        let copy = host.with_only_ports(&[(80, Protocol::Tcp)].into_iter().collect());
        assert_eq!(copy.port_count(), 1);
        assert_eq!(copy.open_port_count(), 1);
        assert_eq!(copy.primary_ip(), host.primary_ip());
    }

    /// A merge folds one record's ports into another's through the same entry
    /// point, so an overlap is not two ports and an endpoint on the other
    /// transport is not a collision.
    ///
    /// A UDP endpoint folded into a record holding all of TCP is accepted.
    #[test]
    fn merging_two_records_keeps_the_union_of_their_ports() {
        // The whole of TCP, half of what the map can hold.
        let mut h1 = Host::new(IP_ADDR);
        for port in u16::MIN..=u16::MAX {
            h1.add_port(Port::new(port, Protocol::Tcp, PortState::Closed));
        }
        assert_eq!(h1.port_count(), usize::from(u16::MAX) + 1);
        assert!(!h1.network_roles.contains(&NetworkRole::Truncated));

        // An overlapping thousand adds nothing; one UDP endpoint adds one.
        let mut h2 = Host::new(IP_ADDR);
        for port in 0..1_000u16 {
            h2.add_port(Port::new(port, Protocol::Tcp, PortState::Closed));
        }
        h2.add_port(Port::new(53, Protocol::Udp, PortState::Open));

        h1.merge(h2);

        assert_eq!(
            h1.port_count(),
            usize::from(u16::MAX) + 2,
            "the union: the whole of TCP and one UDP endpoint"
        );
        assert!(
            !h1.network_roles.contains(&NetworkRole::Truncated),
            "nothing was dropped, so nothing here is truncated"
        );
        assert!(
            !h1.network_roles.contains(&NetworkRole::Tarpit),
            "one open port is not a tarpit"
        );
    }

    /// The address a dual-stack host is reported under does not depend on which probe
    /// answered first.
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

    /// Loopback, multicast and the unspecified address do not rank above a link-local
    /// address.
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

    /// Without IPv4, a globally scoped address leads over a link-local one.
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

    fn a_finding(detection_id: &str) -> Finding {
        use crate::model::confidence::Confidence;
        use crate::model::finding::{DetectionClass, DetectionId, Severity, Version};
        Finding::new(
            DetectionId::new(detection_id, Version::new(1, 0, 0), "hash").unwrap(),
            "A host-level finding",
            Severity::High,
            Confidence::Certain,
            DetectionClass::ActiveBenign,
        )
        .unwrap()
    }

    #[test]
    fn the_same_finding_recorded_twice_is_one() {
        let mut host = Host::new(IP_ADDR);
        assert!(host.add_finding(a_finding("det-a")), "the first is new");
        assert!(
            !host.add_finding(a_finding("det-a")),
            "an identical re-firing is not new information"
        );
        assert_eq!(host.findings().count(), 1);
    }

    #[test]
    fn a_merge_keeps_both_hosts_findings() {
        // A merge that forgot findings would report a clean host.
        let mut base = Host::new(IP_ADDR);
        base.add_finding(a_finding("det-a"));

        let mut other = Host::new(IP_ADDR);
        other.add_finding(a_finding("det-b"));

        base.merge(other);

        let ids: Vec<String> = base
            .findings()
            .map(|f| f.detection().id().to_string())
            .collect();
        assert_eq!(ids.len(), 2, "a merge must not drop the other's findings");
        assert!(ids.contains(&"det-a".to_string()));
        assert!(ids.contains(&"det-b".to_string()));
    }
}
