// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Forward name resolution
//!
//! Turns the names a person writes, such as `example.com`, `raspberrypi.local`
//! and `nas`, into the addresses a scan can probe, before the scan starts. The
//! reverse half, which names hosts a scan has found, lives in
//! [`crate::scanner::rdns`] and uses the same sources: the hosts file first,
//! then the server the address's reverse zone is scoped to, or the global ones.
//!
//! ## Where a name is answered
//!
//! [`Resolver::resolve`] routes a name in the order the host's own lookups take:
//!
//! - The hosts file first, for every name. A name it lists is answered from it
//!   and asked of nobody, which is how a lab box with no DNS of its own gets a
//!   name, `.local` suffix or not; see `hosts` for why the engine reads the file
//!   itself.
//! - A `.local` name is a multicast name (RFC 6762) and is asked of the link
//!   over multicast DNS. A unicast lookup of one fails wherever the host has no
//!   mDNS-aware resolver, which on Linux is the common case, so the engine
//!   speaks mDNS itself. The exception is a `.local` domain a unicast server is
//!   configured to answer for, such as an Active Directory domain named
//!   `corp.local`: that name is asked of the server first, and of the link only
//!   if the server has no answer.
//! - Any other name goes to unicast DNS as the host has it configured: to the
//!   server a scoped resolver names for its domain, where there is one, and
//!   otherwise to the global resolvers with the host's search domains.
//! - A single-label name (`nas`) is tried unicast first and, if nothing answers
//!   and mDNS is enabled, again as `nas.local`, which on a home network is often
//!   what the author meant.
//!
//! The hosts file and the resolver configuration are read afresh at every
//! resolution pass, so a front end that runs for hours resolves a name the way
//! the host does at that moment. Nothing a pass learned, failures included, is
//! kept for the next.
//!
//! Every lookup leaves by the routing table. A scan forced to a source pins its
//! probes and connections, but not the lookups made before it starts; see
//! [`ZondConfig::send_source`](crate::config::ZondConfig::send_source).
//!
//! ## Relation to the parse hook
//!
//! [`crate::model::parse`] takes names through a
//! [`HostLookup`](crate::model::parse::target::HostLookup) supplied in a
//! [`TargetContext`](crate::model::parse::target::TargetContext). The target
//! grammar does not speak DNS itself; this module resolves the names and hands
//! the answers to that hook.
//!
//! ## Two passes
//!
//! The hook is synchronous and called once per name during parsing, while
//! resolution is asynchronous and slow, mDNS especially. Blocking inside the hook
//! would turn a file of two hundred names into two hundred sequential round
//! trips, so resolution takes two passes:
//!
//! 1. [`resolve_names`] finds every name in a set of target expressions and
//!    resolves them concurrently into a map.
//! 2. [`to_target_map`] and [`to_set`] then parse with a hook that reads the
//!    map, so the parse never waits on the network.
//!
//! [`Resolver::resolve`] resolves a single name; [`to_target_map`] and
//! [`to_set`] do the whole job for a caller assembling a scan.
//!
//! ## Policy left to the caller
//!
//! Whether a scan may resolve at all
//! ([`ZondConfig::no_dns`](crate::config::ZondConfig::no_dns)) is the caller's
//! decision. A front end that must not emit name queries resolves with
//! [`Resolver::hosts_file_only`], which answers the names the hosts file lists
//! and sends nothing, so a lab box listed there is still a target and any other
//! name is an unknown host. A caller that supplies no resolver at all has every
//! name refused with
//! [`NoHostLookup`](crate::model::parse::target::TargetParseError::NoHostLookup).

mod hosts;
mod links;
mod mdns;
mod targets;
mod unicast;

pub use links::{LinkError, for_listening, for_listening_on};
#[cfg(feature = "import-request")]
pub(crate) use targets::for_request;
pub use targets::{
    DiscoveryTargets, PortScanTargets, for_discovery, for_discovery_with, for_exclusion,
    for_exclusion_with, for_port_scan, resolve_names, to_set, to_target_map,
};

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use crate::warn;

pub(crate) use hosts::HostsTable;
pub(crate) use unicast::{
    DnsConfig, Reverse, ScopedServers, ServerPolicy, Unicast, covers, reverse_name,
};

/// The default mDNS reply window. See [`ResolveConfig::mdns_timeout`] for why it
/// is a whole second.
const DEFAULT_MDNS_TIMEOUT: Duration = Duration::from_secs(1);

/// The shortest window that can hear a conformant responder.
///
/// RFC 6762 §6.3 lets a responder defer a reply by up to half a second to
/// aggregate answers, so a shorter window closes while a correct responder is
/// still waiting to speak. A shorter request is raised to this. Nothing in a
/// [`ResolveConfig`] is carried into a report, so raising it misrecords nothing.
const MIN_MDNS_TIMEOUT: Duration = Duration::from_millis(500);

/// How a [`Resolver`] behaves, independent of the host it reads its unicast
/// configuration from.
///
/// Non-exhaustive and [`Default`]-constructed, like
/// [`ZondConfig`](crate::config::ZondConfig), so new settings are additive.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct ResolveConfig {
    /// Whether `.local` names are resolved over multicast, and whether a
    /// single-label name falls back to one.
    ///
    /// Off leaves a `.local` name to the hosts file and to a unicast server
    /// configured for its domain. For networks where multicast is filtered or
    /// unwanted, or where only global names are in play.
    pub mdns: bool,

    /// How long to listen for mDNS replies before accepting that a `.local`
    /// name has no answer on the segment.
    ///
    /// A responder may defer a reply by up to half a second to aggregate
    /// answers (RFC 6762 §6.3), and a busy or sleeping device can take longer,
    /// so the default is one second: short enough not to stall a scan, long
    /// enough to hear a slow device.
    ///
    /// A window shorter than half a second is raised to it, since a shorter one
    /// cannot hear a correct responder at all.
    pub mdns_timeout: Duration,
}

impl Default for ResolveConfig {
    fn default() -> Self {
        Self {
            mdns: true,
            mdns_timeout: DEFAULT_MDNS_TIMEOUT,
        }
    }
}

/// Resolves names to addresses from the hosts file, unicast DNS and multicast
/// DNS.
///
/// The hosts file and the resolver configuration are read at each resolution
/// pass, so one resolver kept for the life of a front end resolves as the host
/// does at the time. Cheap to clone, and shared across the concurrent lookups
/// [`resolve_names`] runs.
#[derive(Clone)]
pub struct Resolver {
    origin: Origin,
    config: ResolveConfig,
    /// Whether a lookup may put a question on the network, unicast or
    /// multicast, or is answered from the hosts file alone.
    asks: bool,
}

/// Where a resolver reads what the host says about names.
#[derive(Clone)]
enum Origin {
    /// The system's hosts file and resolver configuration.
    System,
    /// Supplied by a test, which decides what a pass reads and which servers
    /// it may ask.
    #[cfg(test)]
    Given(std::sync::Arc<dyn Fn() -> (String, DnsConfig) + Send + Sync>),
}

/// What the host says about names at one moment: the hosts file and the
/// unicast servers, read once and shared by every lookup of a pass.
pub(crate) struct Snapshot {
    hosts: HostsTable,
    /// `None` for a resolver that asks nobody, which reads no server
    /// configuration either.
    unicast: Option<Unicast>,
}

impl Resolver {
    /// Builds a resolver from the host's own configuration, with mDNS
    /// enabled.
    ///
    /// A host whose resolver configuration cannot be read, such as a container
    /// or a lab VM with no name server in `resolv.conf`, still resolves names
    /// in its hosts file and `.local` names. A name that needed a DNS server
    /// comes back empty, with a warning saying why.
    pub fn from_system() -> Self {
        Self::with_config(ResolveConfig::default())
    }

    /// Builds a resolver with an explicit [`ResolveConfig`].
    pub fn with_config(config: ResolveConfig) -> Self {
        Self {
            origin: Origin::System,
            config,
            asks: true,
        }
    }

    /// Builds a resolver that answers from the host's hosts file alone and
    /// puts nothing on the network: no unicast query and no multicast one.
    ///
    /// For a caller that must not send name queries, such as a scan under
    /// [`ZondConfig::no_dns`](crate::config::ZondConfig::no_dns). The hosts
    /// file is where a lab box reached over a VPN gets its name, and reading it
    /// sends nothing. A name the file does not list resolves to nothing, which
    /// the target functions report as an unknown host.
    pub fn hosts_file_only() -> Self {
        Self {
            origin: Origin::System,
            config: ResolveConfig::default(),
            asks: false,
        }
    }

    /// A resolver reading the hosts file text and unicast configuration
    /// `read` returns at each pass.
    #[cfg(test)]
    pub(crate) fn given(
        config: ResolveConfig,
        read: impl Fn() -> (String, DnsConfig) + Send + Sync + 'static,
    ) -> Self {
        Self {
            origin: Origin::Given(std::sync::Arc::new(read)),
            config,
            asks: true,
        }
    }

    /// Reads what the host currently says about names, for one resolution pass.
    ///
    /// A caller resolving many names reads it once and resolves them all
    /// against it with [`resolve_in`](Self::resolve_in), so every name in a
    /// target list sees the same file and the same servers.
    pub(crate) fn snapshot(&self) -> Snapshot {
        self.snapshot_asking(&mut ServerPolicy::every())
    }

    /// [`snapshot`](Self::snapshot), asking only the servers `policy` allows.
    pub(crate) fn snapshot_asking(&self, policy: &mut ServerPolicy<'_>) -> Snapshot {
        let (hosts, dns) = match &self.origin {
            Origin::System => (
                HostsTable::read_system(),
                self.asks.then(DnsConfig::read_system),
            ),
            #[cfg(test)]
            Origin::Given(read) => {
                let (hosts, dns) = read();
                (HostsTable::parse(&hosts), self.asks.then_some(dns))
            }
        };
        Snapshot {
            hosts,
            unicast: dns.map(|dns| Unicast::from_config(dns.withholding(policy))),
        }
    }

    /// Resolves one name to every address it stands for, in first-seen order.
    ///
    /// An empty result means nothing answered for the name. See the module
    /// documentation for where each kind of name is answered. Reads the host's
    /// configuration for this one name; a caller with many wants
    /// [`resolve_names`], which reads it once.
    pub async fn resolve(&self, name: &str) -> Vec<IpAddr> {
        self.resolve_in(&self.snapshot(), name).await
    }

    /// [`resolve`](Self::resolve), against a configuration already read.
    pub(crate) async fn resolve_in(&self, snapshot: &Snapshot, name: &str) -> Vec<IpAddr> {
        let name = name.trim_end_matches('.');

        if let Some(listed) = from_hosts(snapshot, name) {
            return listed;
        }
        let Some(unicast) = &snapshot.unicast else {
            return Vec::new();
        };

        if is_multicast_local(name) {
            return self.resolve_local(unicast, name).await;
        }

        let answered = unicast.lookup(name).await;
        if !answered.is_empty() || !is_single_label(name) {
            return answered;
        }

        // A bare `nas` that unicast could not place is most often `nas.local`.
        // Tried after unicast so a multicast answer cannot shadow a
        // search-domain match.
        let local = format!("{name}.local");
        if let Some(listed) = from_hosts(snapshot, &local) {
            return listed;
        }
        self.resolve_local(unicast, &local).await
    }

    /// A `.local` name the hosts file does not list: unicast first when a
    /// configured server answers for its domain, then the link.
    async fn resolve_local(&self, unicast: &Unicast, name: &str) -> Vec<IpAddr> {
        if unicast.claims(name) {
            let unicast = unicast.lookup(name).await;
            if !unicast.is_empty() {
                return unicast;
            }
        }
        self.resolve_mdns(name).await
    }

    /// The multicast half, honouring the config's mDNS switch.
    async fn resolve_mdns(&self, name: &str) -> Vec<IpAddr> {
        if !self.config.mdns {
            return Vec::new();
        }
        let window = self.config.mdns_timeout.max(MIN_MDNS_TIMEOUT);
        mdns::resolve(name, window).await
    }
}

impl Snapshot {
    /// Resolves `ip` back to a name from the same sources, and by the same
    /// routes, a name is resolved forward.
    ///
    /// An address the hosts file lists is answered from it alone: the file is
    /// authoritative in both directions, and asking a resolver somebody else
    /// operates about a lab box's address tells them what was found. A
    /// loopback address the file does not list is asked of nobody, since RFC
    /// 6761 section 6.3 keeps its reverse zone on the machine; the `localhost`
    /// a DNS library would invent for all of `127.0.0.0/8` is not a name the
    /// hosts file gave. Anything else goes to the server its reverse zone is
    /// scoped to, or the global ones; see [`Unicast::reverse`].
    pub(crate) async fn reverse(&self, ip: IpAddr) -> Reverse {
        if let Some(name) = self.hosts.name_of(ip) {
            return Reverse::Listed(name.to_owned());
        }
        match (&self.unicast, self.reverse_route(ip)) {
            (Some(unicast), ReverseRoute::Scoped(_) | ReverseRoute::Global) => {
                unicast.reverse(ip).await
            }
            _ => Reverse::Unasked,
        }
    }

    /// Which way [`reverse`](Self::reverse) takes `ip`, decided without
    /// asking anything.
    ///
    /// For a caller that tracks each server's silence separately: a global
    /// resolver that answers nothing says nothing about the server a VPN scopes
    /// to its reverse zone, and giving up on both leaves every address under
    /// that zone unnamed.
    pub(crate) fn reverse_route(&self, ip: IpAddr) -> ReverseRoute {
        match &self.unicast {
            _ if self.hosts.name_of(ip).is_some() => ReverseRoute::Local,
            Some(unicast) if !ip.is_loopback() => unicast
                .reverse_scope(ip)
                .map_or(ReverseRoute::Global, ReverseRoute::Scoped),
            _ => ReverseRoute::Local,
        }
    }
}

/// The way a reverse lookup of one address goes; see
/// [`Snapshot::reverse_route`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReverseRoute {
    /// Answered on the machine or not at all: from the hosts file, for a
    /// loopback address, or on a host with no server to ask.
    Local,
    /// The resolver scoped to a reverse zone, by its place among them.
    Scoped(usize),
    /// The global resolvers.
    Global,
}

/// What the hosts file answers for `name`, saying so when a later line for it
/// goes unused.
///
/// Warned at the default verbosity because it changes what is scanned: a stale
/// line above a new one for the same box sends the scan to the old address, and
/// only the user can say which line is right.
fn from_hosts(snapshot: &Snapshot, name: &str) -> Option<Vec<IpAddr>> {
    let answer = snapshot.hosts.lookup(name)?;
    for unused in &answer.shadowed {
        warn!("{name}: hosts line for {unused} ignored (earlier line wins)");
    }
    Some(answer.addresses)
}

impl fmt::Debug for Resolver {
    /// Says what this resolver reads and whether multicast is on.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let origin = match self.origin {
            Origin::System => "system",
            #[cfg(test)]
            Origin::Given(_) => "given",
        };
        f.debug_struct("Resolver")
            .field("origin", &origin)
            .field("config", &self.config)
            .field("asks", &self.asks)
            .finish()
    }
}

/// Whether `name` is resolved over multicast: a multi-label name whose last
/// label is `local`.
///
/// A bare `local` is a single-label name, which the fallback may try as
/// `local.local`.
fn is_multicast_local(name: &str) -> bool {
    name.contains('.')
        && name
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.eq_ignore_ascii_case("local"))
}

/// Whether `name` is a single label, and so a candidate for the `.local`
/// fallback once unicast has had its say.
fn is_single_label(name: &str) -> bool {
    !name.is_empty() && !name.contains('.')
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

    /// A misclassified name goes to a protocol that cannot answer it: a `.local`
    /// host to a unicast server, or a global name to the multicast group.
    #[test]
    fn only_a_dotted_local_name_is_a_multicast_name() {
        assert!(is_multicast_local("raspberrypi.local"));
        assert!(is_multicast_local("Printer.LOCAL"));
        assert!(is_multicast_local("host.sub.local"));

        assert!(!is_multicast_local("example.com"));
        assert!(!is_multicast_local("localhost"));
        // A bare `local` has no host part; it is a short name.
        assert!(!is_multicast_local("local"));
    }

    /// A window too short to hear a conformant responder is raised to the half
    /// second RFC 6762 §6.3 lets a responder defer its reply.
    ///
    /// Raised, where the overrides in [`RetryConfig`](crate::config::RetryConfig)
    /// are refused: nothing in a [`ResolveConfig`] is carried into a report, so
    /// the raised value misrecords nothing.
    #[test]
    fn a_window_shorter_than_the_protocol_allows_is_raised_to_it() {
        for asked in [Duration::ZERO, Duration::from_millis(1), MIN_MDNS_TIMEOUT] {
            assert_eq!(asked.max(MIN_MDNS_TIMEOUT), MIN_MDNS_TIMEOUT);
        }

        let generous = Duration::from_secs(5);
        assert_eq!(generous.max(MIN_MDNS_TIMEOUT), generous);
        assert_eq!(
            DEFAULT_MDNS_TIMEOUT.max(MIN_MDNS_TIMEOUT),
            DEFAULT_MDNS_TIMEOUT,
            "the default is above the floor, or the floor is the default"
        );
    }

    /// A resolver's debug output says what it reads and whether multicast is on.
    #[test]
    fn a_resolver_reports_what_it_reads_and_whether_multicast_is_on() {
        let rendered = format!("{:?}", Resolver::with_config(ResolveConfig::default()));

        assert!(rendered.starts_with("Resolver"), "{rendered}");
        assert!(rendered.contains("origin: \"system\""), "{rendered}");
        assert!(rendered.contains("mdns: true"), "{rendered}");
    }

    #[test]
    fn a_single_label_is_a_fallback_candidate_and_a_dotted_name_is_not() {
        assert!(is_single_label("nas"));
        assert!(!is_single_label("nas.local"));
        assert!(!is_single_label("example.com"));
        assert!(!is_single_label(""));
    }

    // ── Where a name is answered ────────────────────────────────────────────
    //
    // Each test hands a resolver its hosts file and fake servers on loopback,
    // which record what a lookup asks and of whom. mDNS is off throughout so no
    // multicast packet leaves the test.

    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
    use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
    use hickory_resolver::proto::rr::rdata::{A, PTR, SOA};
    use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};

    use crate::logging::logged;
    use unicast::ScopedServers;

    /// A name server on loopback that answers A queries for the names it
    /// holds, PTR queries for the addresses it names, and NXDOMAIN for any
    /// other, noting every question it is asked.
    ///
    /// Its NXDOMAIN carries the zone's SOA, as a real server's does, because
    /// that is what lets a client cache the failure; without it a client that
    /// holds failures across passes would go unnoticed.
    struct FakeDns {
        at: SocketAddr,
        records: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
        /// Hostnames keyed by the reverse name a PTR query asks.
        names: Arc<Mutex<HashMap<String, String>>>,
        asked: Arc<Mutex<Vec<String>>>,
        serving: tokio::task::JoinHandle<()>,
    }

    impl FakeDns {
        async fn start(records: &[(&str, Ipv4Addr)]) -> Self {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("a loopback socket binds");
            let at = socket.local_addr().expect("a bound socket has an address");
            let records = Arc::new(Mutex::new(
                records
                    .iter()
                    .map(|(name, ip)| (format!("{name}."), *ip))
                    .collect::<HashMap<_, _>>(),
            ));
            let asked = Arc::new(Mutex::new(Vec::new()));
            let names = Arc::new(Mutex::new(HashMap::new()));

            let (held, noted) = (Arc::clone(&records), Arc::clone(&asked));
            let reverse = Arc::clone(&names);
            let serving = tokio::spawn(async move {
                let mut buf = [0u8; 1500];
                while let Ok((len, from)) =
                    crate::testing::loopback::recv_from_this_process(&socket, &mut buf).await
                {
                    let Ok(query) = Message::from_vec(&buf[..len]) else {
                        continue;
                    };
                    let Some(question) = query.queries.first().cloned() else {
                        continue;
                    };
                    let name = question.name().to_ascii().to_ascii_lowercase();
                    noted
                        .lock()
                        .expect("unpoisoned")
                        .push(format!("{name} {}", question.query_type()));

                    let known = held.lock().expect("unpoisoned").get(&name).copied();
                    let named = reverse.lock().expect("unpoisoned").get(&name).cloned();
                    let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
                    reply.metadata.message_type = MessageType::Response;
                    reply.metadata.recursion_desired = query.metadata.recursion_desired;
                    reply.metadata.recursion_available = true;
                    reply.add_query(question.clone());
                    match known {
                        _ if question.query_type() == RecordType::PTR && named.is_some() => {
                            let host = named.expect("checked above");
                            reply.add_answer(Record::from_rdata(
                                question.name().clone(),
                                300,
                                RData::PTR(PTR(Name::from_ascii(&host).expect("a host name"))),
                            ));
                        }
                        Some(ip) if question.query_type() == RecordType::A => {
                            reply.add_answer(Record::from_rdata(
                                question.name().clone(),
                                300,
                                RData::A(A(ip)),
                            ));
                        }
                        Some(_) => {}
                        None => {
                            reply.metadata.response_code = ResponseCode::NXDomain;
                            let zone = Name::from_ascii("example.").expect("a zone name");
                            let soa =
                                SOA::new(zone.clone(), zone.clone(), 1, 3600, 600, 86400, 3600);
                            reply.add_authority(Record::from_rdata(zone, 3600, RData::SOA(soa)));
                        }
                    }
                    let bytes = reply.to_vec().expect("a reply encodes");
                    let _ = socket.send_to(&bytes, from).await;
                }
            });

            Self {
                at,
                records,
                names,
                asked,
                serving,
            }
        }

        /// Starts answering a reverse lookup of `ip` with `host`.
        fn name(&self, ip: IpAddr, host: &str) {
            self.names
                .lock()
                .expect("unpoisoned")
                .insert(format!("{}.", reverse_name(ip)), format!("{host}."));
        }

        /// The questions this server has been asked, as `name. TYPE`.
        fn asked(&self) -> Vec<String> {
            self.asked.lock().expect("unpoisoned").clone()
        }

        /// Starts answering for `name`.
        fn add(&self, name: &str, ip: Ipv4Addr) {
            self.records
                .lock()
                .expect("unpoisoned")
                .insert(format!("{name}."), ip);
        }

        /// A global configuration naming this server, with `search` as its
        /// search list.
        fn as_global(&self, search: &[&str]) -> (ResolverConfig, ResolverOpts) {
            let mut server = NameServerConfig::udp(self.at.ip());
            for connection in &mut server.connections {
                connection.port = self.at.port();
            }
            let search = search
                .iter()
                .map(|s| s.parse().expect("a search domain parses"))
                .collect();
            let mut opts = ResolverOpts::default();
            opts.attempts = 1;
            (ResolverConfig::from_parts(None, search, vec![server]), opts)
        }
    }

    impl Drop for FakeDns {
        fn drop(&mut self) {
            self.serving.abort();
        }
    }

    fn no_mdns() -> ResolveConfig {
        ResolveConfig {
            mdns: false,
            ..ResolveConfig::default()
        }
    }

    fn v4(s: &str) -> IpAddr {
        s.parse().expect("a test address parses")
    }

    /// A resolver reading `hosts`, asking `global`, and asking `scoped` for
    /// the names under their domains.
    fn resolver_over(
        hosts: &str,
        global: Result<(ResolverConfig, ResolverOpts), String>,
        scoped: Vec<ScopedServers>,
    ) -> Resolver {
        let hosts = hosts.to_owned();
        Resolver::given(no_mdns(), move || {
            (
                hosts.clone(),
                DnsConfig {
                    global: global.clone(),
                    scoped: scoped.clone(),
                },
            )
        })
    }

    /// A name the hosts file lists is answered from it and asked of no server,
    /// in either family.
    ///
    /// The file lists an A address. A lookup that consulted it per record type
    /// would still ask upstream for AAAA, telling a resolver somebody else
    /// operates which lab box is being scanned, and waiting out its timeout
    /// where that resolver is unreachable.
    #[tokio::test]
    async fn a_name_the_hosts_file_lists_is_answered_without_asking_dns() {
        let dns = FakeDns::start(&[]).await;
        let resolver = resolver_over(
            "198.51.100.7 box.example\n",
            Ok(dns.as_global(&[])),
            Vec::new(),
        );

        assert_eq!(
            resolver.resolve("box.example").await,
            vec![v4("198.51.100.7")]
        );
        assert_eq!(
            dns.asked(),
            Vec::<String>::new(),
            "the hosts name reached DNS"
        );
    }

    /// Of two hosts lines for one name, the first is scanned and the second is
    /// named in a warning.
    ///
    /// An old box and its replacement both left in the file is the usual way a
    /// name gets two lines. Scanning both covers a host nobody meant; the
    /// warning lets the user delete the right line.
    #[test]
    fn a_stale_hosts_line_for_a_name_is_neither_scanned_nor_silent() {
        let resolver = resolver_over(
            "198.51.100.23 box.example\n198.51.100.99 box.example\n",
            Err("none configured".into()),
            Vec::new(),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime builds");

        let mut resolved = Vec::new();
        let lines = logged(|| resolved = runtime.block_on(resolver.resolve("box.example")));

        assert_eq!(resolved, vec![v4("198.51.100.23")]);
        let warned: Vec<_> = lines.iter().filter(|l| l.verbosity == 0).collect();
        assert!(
            warned
                .iter()
                .any(|l| l.message.contains("box.example") && l.message.contains("198.51.100.99")),
            "no default-verbosity line names the unused address: {lines:?}"
        );
    }

    /// A `.local` name the hosts file lists resolves from it, as it does for
    /// `ping` and `ssh`.
    ///
    /// Lab domains such as `htb.local` exist only as hosts lines on the
    /// attacker's machine; asking the link for them finds nothing.
    #[tokio::test]
    async fn a_local_name_the_hosts_file_lists_resolves_from_it() {
        let resolver = resolver_over(
            "198.51.100.161 forest.corp.local corp.local\n",
            Err("none configured".into()),
            Vec::new(),
        );

        for name in ["forest.corp.local", "corp.local"] {
            assert_eq!(
                resolver.resolve(name).await,
                vec![v4("198.51.100.161")],
                "{name}"
            );
        }
    }

    /// A `.local` name under a domain the host's search list names is asked of
    /// unicast DNS, and one under no configured domain is not.
    ///
    /// An Active Directory domain named `corp.local` is answered by its domain
    /// controller, and a host joined to it searches that domain. A `.local`
    /// name nothing configured claims is a name on the link, and asking a
    /// unicast server about it only leaks it.
    #[tokio::test]
    async fn a_local_name_under_a_searched_domain_is_asked_of_unicast_dns() {
        let dns = FakeDns::start(&[("dc01.corp.local", Ipv4Addr::new(198, 51, 100, 10))]).await;
        let resolver = resolver_over("", Ok(dns.as_global(&["corp.local"])), Vec::new());

        assert_eq!(
            resolver.resolve("dc01.corp.local").await,
            vec![v4("198.51.100.10")]
        );

        let before = dns.asked().len();
        assert_eq!(
            resolver.resolve("printer.local").await,
            Vec::<IpAddr>::new()
        );
        assert_eq!(
            dns.asked().len(),
            before,
            "a link-only name reached unicast DNS"
        );
    }

    /// A name under a scoped resolver's domain is asked of that domain's server
    /// alone, and any other name of the global one.
    ///
    /// A VPN's match domain is served by the VPN's resolver. The global one
    /// cannot answer for it, and asking it would put a private name on the
    /// public path.
    #[tokio::test]
    async fn a_name_under_a_scoped_domain_is_asked_of_that_domains_server_alone() {
        let global = FakeDns::start(&[("www.example", Ipv4Addr::new(203, 0, 113, 80))]).await;
        let scoped =
            FakeDns::start(&[("host.corp.example", Ipv4Addr::new(198, 51, 100, 20))]).await;
        let resolver = resolver_over(
            "",
            Ok(global.as_global(&[])),
            vec![ScopedServers {
                domain: "corp.example".into(),
                servers: Ok(vec![scoped.at]),
            }],
        );

        assert_eq!(
            resolver.resolve("host.corp.example").await,
            vec![v4("198.51.100.20")]
        );
        assert!(
            global.asked().iter().all(|q| !q.contains("corp.example")),
            "the scoped name reached the global server: {:?}",
            global.asked()
        );

        assert_eq!(
            resolver.resolve("www.example").await,
            vec![v4("203.0.113.80")]
        );
        assert!(
            scoped.asked().iter().all(|q| !q.contains("www.example")),
            "a global name reached the scoped server: {:?}",
            scoped.asked()
        );
    }

    /// With no DNS server configured, the hosts file still answers, and a name
    /// that needed a server comes back empty with a warning saying why.
    ///
    /// A host-only lab VM often has a `resolv.conf` with no name server; its
    /// hosts file is then the only way its boxes have names at all.
    #[test]
    fn the_hosts_file_answers_when_no_dns_server_is_configured() {
        let resolver = resolver_over(
            "198.51.100.5 hostsonly\n",
            Err("no nameservers found in config".into()),
            Vec::new(),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime builds");

        let (mut listed, mut global) = (Vec::new(), Vec::new());
        let lines = logged(|| {
            listed = runtime.block_on(resolver.resolve("hostsonly"));
            global = runtime.block_on(resolver.resolve("www.example"));
        });

        assert_eq!(listed, vec![v4("198.51.100.5")]);
        assert_eq!(global, Vec::<IpAddr>::new());
        assert!(
            lines
                .iter()
                .any(|l| l.verbosity == 0 && l.message.contains("no DNS server configured")),
            "{lines:?}"
        );
    }

    /// One resolver kept across passes sees a hosts line added after it was
    /// built, and asks again for a name DNS did not answer before.
    ///
    /// A long-lived front end sees a box come up, its line go into the hosts
    /// file or its record into DNS, and then scans it. A resolver holding the
    /// file it read at construction, or a cached failure, would miss the box
    /// until the front end restarted.
    #[tokio::test]
    async fn a_kept_resolver_sees_names_that_appeared_after_it_was_built() {
        let dns = FakeDns::start(&[]).await;
        let hosts = Arc::new(Mutex::new(String::new()));
        let global = dns.as_global(&[]);
        let file = Arc::clone(&hosts);
        let resolver = Resolver::given(no_mdns(), move || {
            (
                file.lock().expect("unpoisoned").clone(),
                DnsConfig {
                    global: Ok(global.clone()),
                    scoped: Vec::new(),
                },
            )
        });

        assert_eq!(
            resolver.resolve("newbox.example").await,
            Vec::<IpAddr>::new()
        );
        assert_eq!(
            resolver.resolve("record.example").await,
            Vec::<IpAddr>::new()
        );

        *hosts.lock().expect("unpoisoned") = "198.51.100.44 newbox.example\n".into();
        dns.add("record.example", Ipv4Addr::new(198, 51, 100, 45));

        assert_eq!(
            resolver.resolve("record.example").await,
            vec![v4("198.51.100.45")]
        );
        assert_eq!(
            resolver.resolve("newbox.example").await,
            vec![v4("198.51.100.44")]
        );
    }

    // ── Where an address is answered ────────────────────────────────────────

    /// An address under a scoped reverse zone is asked of that zone's server
    /// alone, and any other address of the global one.
    ///
    /// A VPN that serves the reverse zone of its addresses installs a scoped
    /// resolver for it, as it does for its domain. Asked of the global resolver,
    /// the PTR fails and tells a resolver outside the VPN which private address
    /// the scan found.
    #[tokio::test]
    async fn an_address_under_a_scoped_reverse_zone_is_asked_of_that_zones_server_alone() {
        let global = FakeDns::start(&[]).await;
        global.name(v4("203.0.113.80"), "www.example");
        let scoped = FakeDns::start(&[]).await;
        scoped.name(v4("198.51.100.20"), "host.corp.example");
        let resolver = resolver_over(
            "",
            Ok(global.as_global(&[])),
            vec![ScopedServers {
                domain: "100.51.198.in-addr.arpa".into(),
                servers: Ok(vec![scoped.at]),
            }],
        );
        let snapshot = resolver.snapshot();

        // The route a caller tracks silence by matches the one the lookup takes.
        assert_eq!(
            snapshot.reverse_route(v4("198.51.100.20")),
            ReverseRoute::Scoped(0)
        );
        assert_eq!(
            snapshot.reverse_route(v4("203.0.113.80")),
            ReverseRoute::Global
        );
        assert_eq!(snapshot.reverse_route(v4("127.0.0.9")), ReverseRoute::Local);

        assert_eq!(
            snapshot.reverse(v4("198.51.100.20")).await,
            Reverse::Named("host.corp.example.".into())
        );
        assert_eq!(
            global.asked(),
            Vec::<String>::new(),
            "an address in the scoped zone reached the global resolver"
        );

        assert_eq!(
            snapshot.reverse(v4("203.0.113.80")).await,
            Reverse::Named("www.example.".into())
        );
        assert_eq!(
            scoped.asked(),
            vec!["20.100.51.198.in-addr.arpa. PTR".to_string()],
            "an address outside the zone reached its server"
        );
    }

    /// An address the hosts file lists is named by the first line listing it
    /// and asked of nobody, as a name the file lists is answered forward.
    ///
    /// The later of two lines gives a name the rest of the system does not use,
    /// and a query for a lab box's address tells a resolver somebody else
    /// operates what the scan found.
    #[tokio::test]
    async fn an_address_the_hosts_file_lists_is_named_by_its_first_line_and_asked_of_nobody() {
        let global = FakeDns::start(&[]).await;
        global.name(v4("198.51.100.23"), "from-dns.example");
        let resolver = resolver_over(
            "198.51.100.23 old-box.example\n198.51.100.23 new-box.example\n",
            Ok(global.as_global(&[])),
            Vec::new(),
        );

        assert_eq!(
            resolver.snapshot().reverse(v4("198.51.100.23")).await,
            Reverse::Listed("old-box.example".into())
        );
        assert_eq!(global.asked(), Vec::<String>::new());
    }

    /// A loopback address is named by the hosts file or not at all, and never
    /// asked of a server.
    ///
    /// RFC 6761 keeps loopback's reverse zone off the network, and the
    /// `localhost` a DNS library invents for all of `127.0.0.0/8` is a name no
    /// line gave the address.
    #[tokio::test]
    async fn a_loopback_address_is_named_by_the_hosts_file_or_not_at_all() {
        let global = FakeDns::start(&[]).await;
        let resolver = resolver_over(
            "127.0.0.1 localhost\n",
            Ok(global.as_global(&[])),
            Vec::new(),
        );
        let snapshot = resolver.snapshot();

        assert_eq!(
            snapshot.reverse(v4("127.0.0.1")).await,
            Reverse::Listed("localhost".into())
        );
        assert_eq!(snapshot.reverse(v4("127.0.0.9")).await, Reverse::Unasked);
        assert_eq!(snapshot.reverse(v4("::1")).await, Reverse::Unasked);
        assert_eq!(global.asked(), Vec::<String>::new());
    }

    /// With no DNS server configured, reverse lookups say so once, as forward
    /// ones do, and the hosts file still names what it lists.
    ///
    /// A lab VM with no name server in `resolv.conf` names its boxes only in its
    /// hosts file. Silence would leave every other host unnamed with no sign of
    /// why, and a warning per host would bury the scan.
    #[test]
    fn with_no_dns_server_configured_reverse_lookups_say_so_once() {
        let resolver = resolver_over(
            "198.51.100.5 hostsonly\n",
            Err("no nameservers found in config".into()),
            Vec::new(),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime builds");

        let mut answers = Vec::new();
        let lines = logged(|| {
            let snapshot = resolver.snapshot();
            for ip in ["198.51.100.5", "198.51.100.6", "198.51.100.7"] {
                answers.push(runtime.block_on(snapshot.reverse(v4(ip))));
            }
        });

        assert_eq!(
            answers,
            vec![
                Reverse::Listed("hostsonly".into()),
                Reverse::Unasked,
                Reverse::Unasked
            ]
        );
        let said: Vec<_> = lines
            .iter()
            .filter(|l| l.verbosity == 0 && l.message.contains("no DNS server configured"))
            .collect();
        assert_eq!(said.len(), 1, "{lines:?}");
    }

    /// A resolver confined to the hosts file answers the names it lists and
    /// asks nobody about any other.
    ///
    /// It is what a caller that must not send name queries resolves with: a lab
    /// box listed in the file is reachable without a query, and every other name
    /// stays on this machine.
    #[tokio::test]
    async fn a_hosts_file_only_resolver_answers_listed_names_and_asks_nobody() {
        let dns = FakeDns::start(&[("www.example", Ipv4Addr::new(203, 0, 113, 80))]).await;
        let mut resolver =
            resolver_over("198.51.100.9 box.htb\n", Ok(dns.as_global(&[])), Vec::new());
        resolver.asks = false;

        assert_eq!(resolver.resolve("box.htb").await, vec![v4("198.51.100.9")]);
        for name in ["www.example", "printer.local", "nas"] {
            assert_eq!(resolver.resolve(name).await, Vec::<IpAddr>::new(), "{name}");
        }
        assert_eq!(dns.asked(), Vec::<String>::new());
    }
}
