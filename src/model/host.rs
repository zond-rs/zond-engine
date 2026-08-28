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
use crate::model::port::{Port, PortState, Protocol};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    net::IpAddr,
    time::SystemTime,
};

pub mod hardware;
pub mod os;
pub mod path;
pub mod status;
pub mod telemetry;

pub use hardware::HardwareInfo;
pub use os::OsFingerprint;
pub use path::{Hop, NetworkPath};
pub use status::{HostStatus, StatusProtocol, StatusReason};
pub use telemetry::HostTelemetry;

/// The most ports one host will have recorded against it.
///
/// A bound on what a single target can make this process allocate. A host
/// answering on every endpoint of a full scan is a record two orders of
/// magnitude larger than any real one, multiplied by however many such devices
/// sit on the segment.
///
/// **It is one protocol's whole port space, because anything less truncates a
/// scan somebody deliberately asked for.** It used to be a thousand, which is a
/// number an ordinary scan reaches: probing `1-1024` on a host that answers —
/// and a closed port is an answer — recorded a thousand ports, dropped the last
/// twenty-four without a word, and marked a domestic router as a tarpit. The cap
/// has to sit above every port set a person would write, and the largest of
/// those is the whole of TCP.
///
/// A host that reaches it is marked [`NetworkRole::Truncated`] and further ports
/// are dropped. The ports already recorded are real observations, and the
/// marking is what says the list is not complete. That is a separate claim from
/// [`NetworkRole::Tarpit`], which is about what the host did rather than about
/// what this process would hold.
pub const MAX_PORTS_PER_HOST: usize = u16::MAX as usize + 1;

/// How many **open** ports make a host implausible as a host.
///
/// A machine running a thousand distinct listening services does not exist. What
/// does exist is a tarpit answering every SYN to waste a scanner's time, and a
/// middlebox doing the same by accident, and both are worth saying out loud
/// because every port they report is a finding nobody should act on.
///
/// Counted on open ports and nothing else, which is the whole of the difference
/// between this and [`MAX_PORTS_PER_HOST`]. A host with sixty thousand *closed*
/// ports is the ordinary result of a wide scan against a live machine; a host
/// with a thousand open ones is not answering questions, it is answering
/// everything.
pub const TARPIT_OPEN_PORTS: usize = 1_000;

/// What a host turned out to be, beyond an address with ports on it.
///
/// Two kinds of claim share the enum. Most of it names a function *the rest of
/// the network depends on* — forwarding, naming, addressing — and the last
/// three are claims about the record rather than about the machine. Both are
/// things a reader acts on without reading anything else about the host, which
/// is what a role is for.
///
/// **A role is never a port number restated.** A host with 80 open is not a web
/// server here; that is [`Port::service`](crate::model::port::Port::service),
/// which carries the confidence such an identification needs. Every role is
/// concluded from evidence in its own protocol — an advertisement that says "I
/// forward", a DNS message that parses as a response, a DHCP server naming
/// itself — so a consumer can act on one without asking how sure it is. Letting
/// in a weaker claim would cost the set that property, since a `HashSet` cannot
/// say which of its members was a guess.
///
/// A variant is meant to exist here only once something assigns it: a role
/// nothing can infer would promise every consumer that the engine looks for it,
/// so an empty `roles` array would mean "not one" when it really means "never
/// asked". Where that is not yet true the variant says so in its own
/// documentation, which is the sentence to delete when it stops being true.
///
/// The enum is `#[non_exhaustive]` so that adding one costs a recompile rather
/// than a major version; [`ALL`](Self::ALL) is the list to iterate instead of
/// writing one out.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum NetworkRole {
    /// Forwards traffic on behalf of other hosts.
    ///
    /// Three independent proofs, and the engine takes whichever the segment
    /// offers, because no one of them covers a whole network:
    ///
    /// 1. A **neighbour advertisement with the R flag** set (RFC 4861 §4.4).
    ///    The host is answering an ordinary discovery probe and saying, in the
    ///    same message, that it routes.
    /// 2. A **router advertisement** (ICMPv6 type 134). Routers send these
    ///    unprompted every few minutes, and a segment sweep is listening
    ///    anyway; it is the one role evidence that arrives without a probe.
    /// 3. **This machine's own routing table.** The address is a default
    ///    gateway of an interface the scan runs on. IPv4 has neither message
    ///    above, so on a v4-only segment this is the only proof available.
    ///
    /// Deliberately not called a gateway. A gateway is relational — somebody's
    /// next hop — and two hosts on one segment can each be one for a different
    /// neighbour. What every proof above establishes is the intrinsic half:
    /// this box forwards. Which of them is *your* way out is a question about
    /// your routing table, not about the network.
    Router,

    /// Answered a query on port 53 with a message that parses as a DNS
    /// response.
    ///
    /// The reply itself is the evidence, not the port: a resolver that answers
    /// is doing the thing, where an open 53 is a socket somebody bound. The
    /// engine's UDP probe for the port carries a real question (the corpus
    /// registers one beside the service's match rules), so an answer is the
    /// ordinary outcome rather than a lucky one.
    ///
    /// **Not mDNS or LLMNR.** Those answer on 5353 and 5355, and nearly every
    /// laptop and printer on a segment responds to them. Counting one as a name
    /// server would put the role on half a network and make it worthless on the
    /// half that deserves it.
    DnsServer,

    /// Answered a DHCP message as a server.
    ///
    /// Concluded from an exchange in DHCP's own protocol: the engine sends a
    /// `DHCPINFORM`, which asks for configuration without asking for an
    /// address, and reads the server identifier (option 54) out of the reply.
    /// A server names itself there, and the role goes on that address only when
    /// the reply also came from it — where a relay agent forwards for a server
    /// on another segment the two differ, and neither machine has then been
    /// shown to serve DHCP on this one.
    ///
    /// It cannot be concluded from port state. UDP/67 is `open|filtered` on
    /// silence like every other UDP port, and a DHCP server is found by
    /// broadcasting at the segment rather than by connecting to a listener.
    DhcpServer,

    /// Answered with a valid NTP response, so it serves time.
    ///
    /// **Nothing assigns this yet.** The probe already goes out — the corpus
    /// registers a client packet for port 123 — and what is missing is reading
    /// the reply as NTP instead of counting it as "something answered". Until
    /// that is wired, the variant is vocabulary rather than a finding.
    NtpServer,

    /// Answered SNMP, so it is managed over it.
    ///
    /// **Nothing assigns this yet**, for the reason [`NtpServer`](Self::NtpServer)
    /// gives: the probe for port 161 is sent and its reply is already parsed
    /// for operating-system evidence, but no strategy concludes the role from
    /// it.
    SnmpAgent,

    /// Switches frames on behalf of the machines attached to it.
    ///
    /// Concluded from the device's own announcement — LLDP's bridge capability
    /// or CDP's switch, transparent-bridge or source-route-bridge bits — and
    /// only where the device reports the capability as **enabled** rather than
    /// merely present. A switch with a routing licence nobody configured
    /// advertises routing as supported and not enabled, and reading the wrong
    /// half of that field puts a router on every access switch in a building.
    ///
    /// **This is testimony rather than observed behaviour**, which is unlike
    /// [`Router`](Self::Router) and unlike [`DnsServer`](Self::DnsServer), and
    /// like [`DhcpServer`](Self::DhcpServer): a DHCP server is believed because
    /// it named itself in a DHCP server's message, and a switch is believed
    /// because it named itself in the protocol switches announce themselves
    /// over. Anything on a segment can send either, which is why neither is
    /// evidence about a *distant* machine — see
    /// [`crate::protocols::lldp`] for what a group address does and does not
    /// prove.
    ///
    /// Worth a variant despite that, because it is the one role naming
    /// infrastructure that a scan generally cannot see at all: a switch usually
    /// presents no open port to the segment it serves, and often holds no
    /// address on it.
    Switch,

    /// The machine this scan is running from.
    ///
    /// A sweep of your own segment contains you, and the record it produces is
    /// unlike every other one in it: services answer over the loopback path
    /// that a neighbour would never reach, latency is not a network
    /// measurement, and no probe of ours ever crossed a wire. Saying so is
    /// cheaper than every consumer rediscovering it.
    ///
    /// Read from the addresses assigned to this machine's interfaces, so it is
    /// established without sending anything and holds for an address the scan
    /// never reached.
    Origin,

    /// Reported more ports **open** than any machine plausibly runs services on.
    ///
    /// A claim about the host: past [`TARPIT_OPEN_PORTS`] it is answering
    /// everything rather than answering questions, and every open port it
    /// reported is a finding nobody should act on. A
    /// deliberate tarpit and a middlebox answering everything by accident are
    /// indistinguishable from here, and both make the ports recorded against
    /// this host meaningless.
    Tarpit,

    /// Answered on more ports than this record will hold, so the port list is
    /// incomplete.
    ///
    /// A claim about the *scan* rather than about the host: it says only that
    /// [`MAX_PORTS_PER_HOST`] was reached and that findings past it were
    /// dropped. Kept apart from [`Tarpit`](Self::Tarpit) because the two used to
    /// be one thing and the conflation was wrong in both directions — an
    /// ordinary host probed widely enough was reported as a tarpit, and a real
    /// tarpit answering a narrow scan was reported as nothing at all.
    Truncated,
}

impl NetworkRole {
    /// Every role this build knows, in declaration order.
    ///
    /// The enum is `#[non_exhaustive]`, so nothing outside the crate can write
    /// an exhaustive list of its own and nothing inside should: a role added
    /// without a name on the wire, or without a place in the schema, is a
    /// finding that survives a scan and disappears on the way to the report.
    /// Every round trip through [`wire`](crate::record::wire) is tested over
    /// this, so a new variant fails those tests until it is spelled everywhere.
    /// How a role is written for a person to read.
    ///
    /// Separate from [`network_role_name`](crate::record::wire::network_role_name),
    /// which is the one place a role is spelled for a *machine*. A model that
    /// knew its own wire spelling would be a second vocabulary site, and the
    /// two answer to different masters: this one may be reworded whenever it
    /// reads better, and that one may never change at all.
    ///
    /// **An acronym is capitals and a word is not.** `DNS` is a name written in
    /// initials and `router` is an ordinary English noun, so capitalising the
    /// second to match the first is shouting rather than spelling — the same
    /// rule that makes `ICMP unreachable` the name of a thing and
    /// `ICMP_UNREACHABLE` a shout. A list mixing the two reads as what it is:
    /// `router, DNS, DHCP`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::DnsServer => "DNS",
            Self::DhcpServer => "DHCP",
            Self::NtpServer => "NTP",
            Self::SnmpAgent => "SNMP",
            Self::Switch => "switch",
            Self::Origin => "origin",
            Self::Tarpit => "tarpit",
            Self::Truncated => "truncated",
        }
    }

    pub const ALL: [NetworkRole; 9] = [
        Self::Router,
        Self::DnsServer,
        Self::DhcpServer,
        Self::NtpServer,
        Self::SnmpAgent,
        Self::Switch,
        Self::Origin,
        Self::Tarpit,
        Self::Truncated,
    ];
}

/// What the filter in front of a host was shown to be doing.
///
/// A conclusion about the *path to* a host rather than the host itself, which is
/// what keeps it a separate claim from [`NetworkRole`]: a filter sits between the
/// scanner and the machine, and saying a host "is" a middlebox the way it "is" a
/// name server would be a different, usually wrong claim. Like a role, every
/// member is a proven, confidence-free fact — held in a set, where there is
/// nowhere to record a maybe — drawn from what a deliberately-shaped probe
/// demonstrated, never from a port number.
///
/// Positive claims only. A probe that drew no reply, or was dropped like an
/// ordinary one, proves nothing; the absence of a filter is not something a scan
/// can establish, so it is never recorded.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum Filtering {
    /// An inline device answered on the host's behalf.
    ///
    /// Proven by a reply to a probe carrying a deliberately wrong TCP checksum.
    /// A conformant host drops such a segment unread, so a reply to one was not
    /// the host's — it was sent by something in the path that answered without
    /// validating: a firewall, an intrusion-prevention system, a transparent
    /// proxy, a load balancer. One reply is the whole proof, which is why this
    /// is the one filtering conclusion a single probe settles.
    InlineMiddlebox,

    /// A stateful filter: it passes a bare ACK but drops a SYN.
    ///
    /// Proven by an ACK probe reaching the stack — a RST, which is
    /// [`PortState::Unfiltered`](crate::model::port::PortState::Unfiltered) — for
    /// a port the scan found filtered to a SYN. A filter that lets an ACK through
    /// and refuses a SYN is keeping connection state and opening no new
    /// connections. Comparative: the SYN's fate is the port state the scan
    /// already recorded, and only the ACK is sent here.
    StatefulFilter,

    /// A filter that trusts a source port.
    ///
    /// Proven by a SYN from a port such as 53, 20 or 88 reaching a port the scan
    /// found filtered to a SYN from an ephemeral one. The filter is honouring an
    /// ACL written to let "returning" traffic back in — a door a chosen source
    /// port holds open. Comparative in the same way as
    /// [`StatefulFilter`](Self::StatefulFilter), and against the same recorded
    /// port state.
    PortTrustingAcl,

    /// A stateless filter: it matches on the first fragment and passes the rest.
    ///
    /// Proven by a *fragmented* SYN drawing an answer from a port the scan found
    /// filtered to a whole one. A filter that reassembled would have seen the
    /// same forbidden SYN either way; one that lets the fragments through has
    /// judged only the first, where the ports are but the flags are not yet, and
    /// so is matching without keeping the state reassembly needs. Comparative
    /// against the same recorded port state as
    /// [`StatefulFilter`](Self::StatefulFilter), and — because a fragmented probe
    /// can only be sent over a self-built Ethernet frame — drawn only for a host
    /// that path can reach; one it cannot simply goes without the conclusion,
    /// never against it.
    StatelessFilter,
}

impl Filtering {
    /// Every conclusion this build knows, in the order they are reported.
    ///
    /// The array's length is the compile-time check that a conclusion added to
    /// the enum was added here too: a set is rendered through this order, and a
    /// member missing from it would be silently dropped from every report.
    pub const ALL: [Filtering; 4] = [
        Self::InlineMiddlebox,
        Self::StatefulFilter,
        Self::PortTrustingAcl,
        Self::StatelessFilter,
    ];
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
/// What one source concluded, reduced to the parts that make it a *distinct*
/// claim.
///
/// The identity of a piece of operating-system evidence for the purpose of
/// counting it: two readings that say the same thing are one thing learned
/// twice, whatever produced them, and two that say different things are two
/// pieces of evidence even where one kind of source produced both.
///
/// Deliberately not the confidence or the evidence line. The first varies with
/// how a rule was weighted and the second is prose; neither changes what is
/// being claimed, and keying on either would let one claim in under several
/// spellings.
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
/// A host running many identifiable services can offer one claim each, and
/// combining enough of them approaches a certainty none of them stated. Eight is
/// past any host this has been seen on and short of where the arithmetic stops
/// meaning anything.
const MAX_OS_EVIDENCE: usize = 8;

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
    /// **One item per distinct claim**, which is not the same as one per source
    /// and the difference was worth a finding.
    ///
    /// Keyed per source, an SSH banner naming `Debian 12` and an SNMP agent
    /// naming `kernel 6.1.0` are both `ServiceBanner` — so the second evicted
    /// the first, and a host that had told this engine two different things
    /// about itself was reported from whichever arrived last. They are two
    /// services, on two ports, read from two protocols: two pieces of evidence
    /// by any reading.
    ///
    /// Keyed on the *claim*, a stack read forty times — which is what a host
    /// with forty open ports produces — is still forty identical claims and
    /// still collapses to one. That is the property that has to hold: repeating
    /// an observation must never look like corroboration, because the
    /// arithmetic downstream cannot tell the difference.
    ///
    /// Bounded by [`MAX_OS_EVIDENCE`], because a host running many distinct
    /// services can otherwise accumulate one item per service, and enough
    /// agreeing items approach a certainty no single source stated.
    os_evidence: BTreeMap<OsClaim, OsEvidence>,

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

    /// The routers between this machine and this host, when a trace ran.
    ///
    /// Empty unless [`OsDetection`]-style effort was spent on it deliberately:
    /// a path costs one probe per hop per host and nothing else in a scan needs
    /// one, so it is never gathered as a side effect. See
    /// [`ZondConfig::traceroute`](crate::config::ZondConfig::traceroute).
    ///
    /// Held here rather than on [`HostTelemetry`] beside the round-trip time,
    /// which is the tempting place for it. A telemetry reading is one number
    /// about this host, updated as replies arrive; a path is a sequence of
    /// findings about *other* machines, each with its own provenance, and the
    /// two have nothing in common but the word "path".
    path: NetworkPath,

    /// Inferred roles based on network location or discovered services.
    network_roles: HashSet<NetworkRole>,

    /// What the filter in front of this host was shown to be doing, if anything.
    filtering: HashSet<Filtering>,

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

    /// How many of [`ports`](Self::ports) are [`PortState::Open`], maintained as
    /// they are recorded rather than counted on demand.
    ///
    /// [`add_port`](Self::add_port) is the only way a port enters or changes
    /// here, and a port's state only ever promotes, so the count can be kept
    /// incrementally and can never drift downward. Counting on demand would be
    /// a walk of the map per recorded port, which on a wide scan is quadratic in
    /// the thing the walk exists to bound.
    open_ports: usize,
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
            path: NetworkPath::new(),
            network_roles: HashSet::new(),
            filtering: HashSet::new(),
            first_seen: now,
            last_seen: now,
            ports: BTreeMap::new(),
            open_ports: 0,
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

    /// The routers between this machine and this host. Empty unless a trace ran.
    pub fn path(&self) -> &NetworkPath {
        &self.path
    }

    /// Records the hop counter a reply from this host arrived with.
    ///
    /// Cheap and unconditional: every captured reply carries one, and the
    /// alternative to keeping it is a probe sent later purely to re-obtain it.
    pub fn record_hop_counter(&mut self, arrived: u8) {
        self.telemetry.record_hop_counter(arrived);
    }

    /// Records one router on the way here.
    ///
    /// Additive and idempotent in the way [`NetworkPath::record`] describes:
    /// what is known about a distance only ever gets stronger, so a trace whose
    /// replies arrive out of order, or twice, converges on the same path.
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
    /// Both are stamped by [`new`](Self::new) and moved forward as findings
    /// arrive, which is right for a host a scan is discovering and wrong for one
    /// being rebuilt from a record: a scan resumed the next morning would report
    /// having first seen every host that morning.
    ///
    /// Taken together rather than as two setters, since a `first_seen` after a
    /// `last_seen` describes nothing that could have happened. They are swapped
    /// if given that way.
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
        let claim: OsClaim = (
            evidence.source,
            evidence.family.clone(),
            evidence.device.clone(),
            evidence.vendor.clone(),
            evidence.product.clone(),
            evidence.version.clone(),
            evidence.kernel.clone(),
        );

        // The ceiling is read before the map is borrowed to edit, because a
        // claim already on record occupies room it does not have to ask for.
        let full = self.os_evidence.len() >= MAX_OS_EVIDENCE;

        match self.os_evidence.get_mut(&claim) {
            // The same claim, reached again — but not necessarily by the same
            // route. A stack read once off a port scan's reply and again as a
            // series of them concludes the identical thing and shows *different*
            // working for it, and the series reading is the one that cannot be
            // got back. So the claim is not new and the reading may be: keep the
            // strongest confidence and every distinct line behind it.
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

    pub fn set_os(&mut self, os: OsFingerprint) {
        self.os = Some(Box::new(os));
        self.last_seen = SystemTime::now();
    }

    /// Withdraws this host's operating-system fingerprint.
    ///
    /// For a caller that has re-resolved the evidence and found it no longer
    /// supports what is on record. Nothing else should reach for this: a scan
    /// that discards a finding it cannot currently reproduce would lose every
    /// answer a later phase happens not to re-derive.
    pub fn clear_os(&mut self) {
        self.os = None;
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

    /// Records a role for this host, returning whether it is one the record did
    /// not already carry.
    ///
    /// The return is what a caller announces on. A role is concluded from
    /// whatever evidence turns up, and the same evidence turns up repeatedly —
    /// a router advertises on a timer, a name server answers every lookup —
    /// so "recorded" and "learned" are different events and only the second is
    /// news. Bumps `last_seen` either way: the host was heard from.
    pub fn add_network_role(&mut self, role: NetworkRole) -> bool {
        let is_new = self.network_roles.insert(role);
        self.last_seen = SystemTime::now();
        is_new
    }

    /// Records a filtering conclusion drawn about the path to this host,
    /// returning whether it is one not already held.
    ///
    /// Bumps `last_seen`, as [`add_network_role`](Self::add_network_role) does
    /// and for the same reason: the host was heard from, whatever the evidence
    /// re-established.
    pub fn add_filtering(&mut self, filtering: Filtering) -> bool {
        let is_new = self.filtering.insert(filtering);
        self.last_seen = SystemTime::now();
        is_new
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
    /// [`MAX_PORTS_PER_HOST`] and has been marked [`NetworkRole::Truncated`];
    /// the caller is told rather than left to assume the port list is complete.
    ///
    /// A host that crosses [`TARPIT_OPEN_PORTS`] open ports is marked
    /// [`NetworkRole::Tarpit`] and keeps recording. That is a different claim
    /// from truncation and is deliberately not a reason to stop: the ports are
    /// still what the host said, and a caller that wants to discard them can,
    /// where a caller handed a silently shortened list cannot.
    pub fn add_port(&mut self, new_port: Port) -> bool {
        let key = (new_port.number(), new_port.protocol());
        let existing = self.ports.get(&key);

        if existing.is_none() && self.ports.len() >= MAX_PORTS_PER_HOST {
            self.network_roles.insert(NetworkRole::Truncated);
            return false;
        }

        let was_open = existing.is_some_and(|port| port.state() == PortState::Open);

        let recorded = self
            .ports
            .entry(key)
            .and_modify(|p| p.merge(new_port.clone()))
            .or_insert(new_port);

        // A state only ever promotes, so this counts up and never has to count
        // back down; see `open_ports`.
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

        // Hop by hop rather than by taking whichever path looks fuller, so the
        // "only ever gets stronger" rule in `NetworkPath::record` decides each
        // distance: a measurement beats an inference, an answer beats silence,
        // and neither side has to be the winner as a whole.
        //
        // **A merge is where a path is most easily lost.** A port scan snapshots
        // its hosts once for the liveness phase and again at the end, then folds
        // the two together — and the trace runs between those two moments, so
        // the earlier record has no path at all. Left out here, the empty half
        // wins and the scan reports a path it measured and then discarded.
        for hop in other.path.hops() {
            self.path.record(*hop);
        }

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

        // Listed in `NetworkRole::ALL` order rather than the set's, so two runs
        // that found the same things print the same line. A `HashSet` iterates
        // in whatever order its hashing produced.
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

        // A latency beside a host whose port list is meaningless invites the
        // reader to act on the rest of the line, so the two markings that say
        // "do not" take the space instead.
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

    static IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100));

    /// A merge folds in what only one side of it knows.
    ///
    /// **This is the shape of defect the test exists for.** A port scan
    /// snapshots its hosts twice — once for the liveness phase and once at the
    /// end — and folds the two together, so anything learned *between* those
    /// moments exists on only the later record. A field left out of `merge` is
    /// then silently discarded, and the scan reports having found nothing of
    /// something it measured in full. The path and the hop counter both shipped
    /// with exactly that bug: the trace ran, recorded every router, and the
    /// empty earlier snapshot won.
    ///
    /// Asserted in the direction the port scan actually merges — the record
    /// without the finding on the left — because that is the direction that
    /// loses it.
    #[test]
    fn a_merge_keeps_what_only_the_other_record_learned() {
        let mut earlier = Host::new(IP_ADDR);
        earlier.set_status(HostStatus::Up);

        let mut later = Host::new(IP_ADDR);
        later.record_hop_counter(59);
        later.record_hop(path::Hop::answered(
            1,
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
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
    /// Not "whichever path is longer wins": two records can each know a
    /// different half, and a distance one of them only inferred may be one the
    /// other actually measured. `NetworkPath::record` already holds that rule,
    /// so the merge has to go through it hop by hop rather than choosing a side.
    #[test]
    fn merging_paths_keeps_the_stronger_claim_at_every_distance() {
        let router = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));

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

    /// Roles are held in a `HashSet`, which iterates in whatever order its
    /// hashing produced — so a line built by walking it directly differs
    /// between two runs that found exactly the same things, and between two
    /// machines reading the same journal. A report a reader diffs by eye has to
    /// be stable.
    #[test]
    fn a_host_prints_its_roles_in_one_order_however_they_were_recorded() {
        let expected = "192.168.0.100 (Up) [router, DNS, origin]";

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

    /// A latency printed beside a host whose port list is meaningless invites
    /// the reader to act on the rest of the line, so the two markings that say
    /// not to take the space instead.
    #[test]
    fn a_tarpit_prints_the_marking_where_the_latency_would_be() {
        let mut host = Host::new(IP_ADDR);
        host.set_status(HostStatus::Up);
        host.add_network_role(NetworkRole::Tarpit);

        assert_eq!(host.to_string(), "192.168.0.100 (Up) [tarpit]");
    }

    /// A dropped port is a truncated list, and the caller is the only one that
    /// can decide what to do about it.
    #[test]
    fn add_port_reports_whether_the_finding_was_recorded() {
        let mut host = Host::new(IP_ADDR);
        for i in 0..MAX_PORTS_PER_HOST {
            assert!(host.add_port(Port::new(i as u16, Protocol::Tcp, PortState::Closed)));
        }

        assert!(!host.add_port(Port::new(1, Protocol::Udp, PortState::Closed)));
        assert!(host.network_roles().contains(&NetworkRole::Truncated));
    }

    /// The cap is exact: the host takes ports up to it and is marked only once
    /// one is actually refused. Marking a host at the boundary would label a
    /// complete port list as truncated.
    #[test]
    fn the_truncation_marking_appears_only_once_a_port_is_refused() {
        let mut host = Host::new(IP_ADDR);
        for i in 0..MAX_PORTS_PER_HOST {
            host.add_port(Port::new(i as u16, Protocol::Tcp, PortState::Closed));
        }
        assert!(!host.network_roles.contains(&NetworkRole::Truncated));

        host.add_port(Port::new(1, Protocol::Udp, PortState::Closed));
        assert!(host.network_roles.contains(&NetworkRole::Truncated));
        assert_eq!(host.port_count(), MAX_PORTS_PER_HOST);
    }

    /// The regression the two markings were split apart over.
    ///
    /// Probing the well-known range on a host that answers records a thousand
    /// ports, because a closed port is an answer. Under the old rule that was
    /// the cap: the last findings were dropped without a word and a domestic
    /// router came back labelled a tarpit. Nothing about a wide scan of an
    /// ordinary machine says either thing.
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

    /// A thousand *open* ports is not a machine, and saying so is the whole
    /// purpose of the role. It is a claim about the host, so recording does not
    /// stop: a caller handed the ports can discard them, where a caller handed a
    /// silently shortened list cannot.
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

    /// The count follows promotions, not insertions. A port first seen filtered
    /// and later answered is one more open port, and a second reply about a port
    /// already open is not.
    #[test]
    fn the_open_count_follows_what_the_ports_became() {
        let mut host = Host::new(IP_ADDR);

        host.add_port(Port::new(22, Protocol::Tcp, PortState::Filtered));
        assert_eq!(host.open_port_count(), 0);

        host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        assert_eq!(host.open_port_count(), 1, "promoted");

        host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        assert_eq!(host.open_port_count(), 1, "and counted once");
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

    /// A merge folds one record's ports into another's through the same
    /// entry point, so the cap and both markings apply there too — an overlap is
    /// not two ports, and the total that reaches the cap is the union.
    #[test]
    fn merging_two_records_applies_the_cap_to_their_union() {
        // The whole of TCP, which is exactly the cap and so is kept whole.
        let mut h1 = Host::new(IP_ADDR);
        for port in u16::MIN..=u16::MAX {
            h1.add_port(Port::new(port, Protocol::Tcp, PortState::Closed));
        }
        assert_eq!(h1.port_count(), MAX_PORTS_PER_HOST);
        assert!(!h1.network_roles.contains(&NetworkRole::Truncated));

        // An overlapping half, which adds nothing, and one endpoint that does.
        let mut h2 = Host::new(IP_ADDR);
        for port in 0..1_000u16 {
            h2.add_port(Port::new(port, Protocol::Tcp, PortState::Closed));
        }
        h2.add_port(Port::new(53, Protocol::Udp, PortState::Open));

        h1.merge(h2);

        assert_eq!(h1.port_count(), MAX_PORTS_PER_HOST, "the union, capped");
        assert!(h1.network_roles.contains(&NetworkRole::Truncated));
        assert!(
            !h1.network_roles.contains(&NetworkRole::Tarpit),
            "nothing that was kept is open, so nothing here is a tarpit"
        );
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
