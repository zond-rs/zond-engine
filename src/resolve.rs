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
//! and `nas`, into the addresses a scan can probe. This is the half of
//! resolution that runs before a scan, deciding what it will cover. The reverse
//! half, which
//! attaches names to hosts a scan has already found, lives in
//! [`crate::scanner::rdns`] and answers the opposite question.
//!
//! ## Where a name is answered
//!
//! [`Resolver::resolve`] routes a name by how it is resolved, not by asking the
//! caller to know, in the order the host's own lookups take:
//!
//! - The hosts file first, for every name. A name it lists is answered from it
//!   and asked of nobody, which is how a lab box with no DNS of its own gets a
//!   name, `.local` suffix or not; see `hosts` for why the engine reads it
//!   rather than its DNS client.
//! - A `.local` name is a multicast name (RFC 6762): it is resolved by asking
//!   the link over multicast DNS. A unicast lookup of one fails everywhere the
//!   host has no mDNS-aware resolver, which on Linux is the common case, so the
//!   engine speaks mDNS itself rather than hoping the system does.
//! - Any other name goes to the system's unicast resolver, which applies the
//!   host's own search domains and returns A and AAAA records alike.
//! - A single-label name (`nas`) is tried unicast first, and if nothing answers
//!   and mDNS is enabled, again as `nas.local`, which on a home network is often
//!   what the author meant by it.
//!
//! The hosts file and the resolver configuration are read afresh at every
//! resolution pass, so a front end that runs for hours resolves a name the way
//! the host does now, and nothing a pass learned, a failure included, is kept
//! for the next.
//!
//! Every lookup leaves by the routing table. A scan forced to a source pins its
//! probes and connections, not the questions asked before it starts; see
//! [`ZondConfig::send_source`](crate::config::ZondConfig::send_source).
//!
//! ## Why a resolver, and not just the hook
//!
//! [`crate::model::parse`] already has the seam a name passes through: a
//! [`HostLookup`](crate::model::parse::target::HostLookup) supplied in a
//! [`TargetContext`](crate::model::parse::target::TargetContext). What it does
//! not have is anything to fill it with, because resolving a name means speaking
//! DNS and mDNS, which a target grammar must not do on its own behalf. This
//! module is what fills it, and it does so without the parse layer learning
//! anything about DNS: the engine resolves the names and hands the answers in.
//!
//! ## The synchronous seam, and the two passes
//!
//! That hook is synchronous, called once per name while a target expression is
//! parsed, and resolution is asynchronous and slow, mDNS especially so. Blocking
//! inside the hook would turn a file of two hundred
//! names into two hundred sequential round trips. So resolution is done in two
//! passes, and this module ships both rather than describing them:
//!
//! 1. [`resolve_names`] finds every name in a set of target expressions and
//!    resolves them concurrently into a map.
//! 2. [`to_target_map`] and [`to_set`] then build with a hook that reads the
//!    map, so the parse itself never waits on the network.
//!
//! A caller that only needs one name resolved can reach for [`Resolver::resolve`]
//! directly; a caller assembling a scan wants [`to_target_map`] or [`to_set`],
//! which do the whole of it.
//!
//! ## What it does not decide
//!
//! Whether a scan is allowed to resolve at all, which is what
//! [`ZondConfig::no_dns`](crate::config::ZondConfig::no_dns) means at request
//! time, is the caller's policy rather than this module's: a resolver that
//! refused to run would
//! be a strange thing to hold. A front end that must not emit DNS supplies no
//! resolver, and the parse layer then refuses a name with
//! [`NoHostLookup`](crate::model::parse::target::TargetParseError::NoHostLookup)
//! rather than covering less than its input said.

mod hosts;
mod links;
mod mdns;
mod targets;
mod unicast;

pub use links::{LinkError, for_listening, for_listening_on};
pub use targets::{
    DiscoveryTargets, for_discovery, for_discovery_with, for_exclusion, for_exclusion_with,
    resolve_names, to_set, to_target_map,
};

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use crate::warn;

use hosts::HostsTable;
use unicast::{DnsConfig, Unicast};

/// The default mDNS reply window. See [`ResolveConfig::mdns_timeout`] for why it
/// is a whole second.
const DEFAULT_MDNS_TIMEOUT: Duration = Duration::from_secs(1);

/// The shortest window that can hear a conformant responder.
///
/// RFC 6762 §6.3 permits a responder to defer a reply by up to half a second so
/// it can aggregate answers, so a window below that closes while a correct
/// implementation is still waiting to speak. A caller asking for less has asked
/// for a lookup that cannot succeed, and gets this instead: unlike the scan
/// settings in [`ZondConfig`](crate::config::ZondConfig), nothing here is
/// carried into a report, so raising a window costs nobody a record that says
/// one thing while the run did another.
const MIN_MDNS_TIMEOUT: Duration = Duration::from_millis(500);

/// How a [`Resolver`] behaves, independent of the host it reads its unicast
/// configuration from.
///
/// Non-exhaustive and [`Default`]-constructed, like
/// [`ZondConfig`](crate::config::ZondConfig): the next thing worth saying about
/// how a name is resolved is an additive change rather than a major version.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct ResolveConfig {
    /// Whether `.local` names are resolved over multicast, and whether a
    /// single-label name falls back to one.
    ///
    /// Off leaves a `.local` name to the hosts file, rather than sending it to
    /// a unicast server that will answer NXDOMAIN for it. For an environment
    /// where multicast is filtered or unwanted, or where the only names in
    /// play are global.
    pub mdns: bool,

    /// How long to listen for mDNS replies before accepting that a `.local`
    /// name has no answer on the segment.
    ///
    /// A responder may defer a reply by up to half a second to aggregate
    /// answers (RFC 6762 §6.3), and one on a busy or sleepy device can take
    /// longer, so the default is a whole second: short enough not to stall a
    /// scan, long enough that a device answering slowly is found rather than
    /// declared absent.
    ///
    /// A window shorter than the half second the RFC permits is raised to it.
    /// Below that the lookup cannot hear a correct responder at all, so it is a
    /// preference the protocol overrules rather than a value to refuse: zero,
    /// taken as written, would produce a listener that closes before it opens.
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
/// Holds no state of the host's: the hosts file and the resolver
/// configuration are read at each resolution pass, so one resolver kept for
/// the life of a front end resolves as the host does at the time. Cheap to
/// clone, and shared across the concurrent lookups [`resolve_names`] runs.
#[derive(Clone)]
pub struct Resolver {
    origin: Origin,
    config: ResolveConfig,
}

/// Where a resolver reads what the host says about names.
#[derive(Clone)]
enum Origin {
    /// The system's hosts file and resolver configuration.
    System,
    /// Given in their place, so a test decides what a pass reads and which
    /// servers it may ask, and no query leaves the machine.
    #[cfg(test)]
    Given(std::sync::Arc<dyn Fn() -> (String, DnsConfig) + Send + Sync>),
}

/// What the host says about names at one moment: the hosts file and the
/// unicast servers, read once and shared by every lookup of a pass.
pub(crate) struct Snapshot {
    hosts: HostsTable,
    unicast: Unicast,
}

impl Resolver {
    /// Builds a resolver from the host's own configuration, with mDNS
    /// enabled.
    ///
    /// A host whose resolver configuration cannot be read, as in a container
    /// or a lab VM with no name server in `resolv.conf`, still resolves: names
    /// in its hosts file and `.local` names answer as ever, and a name that
    /// needed a DNS server comes back empty, with a warning saying why. A
    /// scan that resolves fewer names is still a scan.
    pub fn from_system() -> Self {
        Self::with_config(ResolveConfig::default())
    }

    /// Builds a resolver with an explicit [`ResolveConfig`].
    pub fn with_config(config: ResolveConfig) -> Self {
        Self {
            origin: Origin::System,
            config,
        }
    }

    /// A resolver reading the hosts file text and unicast configuration
    /// `read` returns, at each pass, instead of the system's.
    #[cfg(test)]
    pub(crate) fn given(
        config: ResolveConfig,
        read: impl Fn() -> (String, DnsConfig) + Send + Sync + 'static,
    ) -> Self {
        Self {
            origin: Origin::Given(std::sync::Arc::new(read)),
            config,
        }
    }

    /// Reads what the host says about names now, for one resolution pass.
    ///
    /// A caller resolving many names reads it once and resolves them all
    /// against it with [`resolve_in`](Self::resolve_in), so every name in a
    /// target list sees the same file and the same servers.
    pub(crate) fn snapshot(&self) -> Snapshot {
        let (hosts, dns) = match &self.origin {
            Origin::System => (HostsTable::read_system(), DnsConfig::read_system()),
            #[cfg(test)]
            Origin::Given(read) => {
                let (hosts, dns) = read();
                (HostsTable::parse(&hosts), dns)
            }
        };
        Snapshot {
            hosts,
            unicast: Unicast::from_config(dns),
        }
    }

    /// Resolves one name to every address it stands for, in first-seen order.
    ///
    /// An empty result means nothing answered for the name, which a caller treats
    /// the same as a name that resolved to nothing, since both are a target that
    /// is not there. Routing is by name: see the module documentation for where
    /// each kind is answered. Reads the host's configuration for this one name;
    /// a caller with many wants [`resolve_names`], which reads it once.
    pub async fn resolve(&self, name: &str) -> Vec<IpAddr> {
        self.resolve_in(&self.snapshot(), name).await
    }

    /// [`resolve`](Self::resolve), against a configuration already read.
    pub(crate) async fn resolve_in(&self, snapshot: &Snapshot, name: &str) -> Vec<IpAddr> {
        let name = name.trim_end_matches('.');

        if let Some(listed) = from_hosts(snapshot, name) {
            return listed;
        }

        if is_multicast_local(name) {
            return self.resolve_mdns(name).await;
        }

        let unicast = snapshot.unicast.lookup(name).await;
        if !unicast.is_empty() || !is_single_label(name) {
            return unicast;
        }

        // A bare `nas` that unicast could not place is, on a home or office
        // segment, most often `nas.local`. Tried only after unicast so a real
        // search-domain match is never shadowed by a multicast one.
        let local = format!("{name}.local");
        if let Some(listed) = from_hosts(snapshot, &local) {
            return listed;
        }
        self.resolve_mdns(&local).await
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

/// What the hosts file answers for `name`, saying so when a later line for it
/// goes unused.
///
/// Said at the default verbosity because it changes what is scanned: a stale
/// line left above a new one for the same box sends the scan to the old
/// address, and only the user can say which line is right.
fn from_hosts(snapshot: &Snapshot, name: &str) -> Option<Vec<IpAddr>> {
    let answer = snapshot.hosts.lookup(name)?;
    for unused in &answer.shadowed {
        warn!("{name}: hosts line for {unused} ignored (earlier line wins)");
    }
    Some(answer.addresses)
}

impl fmt::Debug for Resolver {
    /// Says what this resolver reads and whether multicast is on, which with
    /// the host's own configuration decide where a name goes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let origin = match self.origin {
            Origin::System => "system",
            #[cfg(test)]
            Origin::Given(_) => "given",
        };
        f.debug_struct("Resolver")
            .field("origin", &origin)
            .field("config", &self.config)
            .finish()
    }
}

/// Whether `name` is resolved over multicast: a multi-label name whose last
/// label is `local`.
///
/// A bare `local` is not one. It is a single-label name the fallback path may try
/// as `local.local`, rather than a `.local` host in its own right.
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

    /// The routing predicate decides which protocol a name is resolved by, so a
    /// misclassification sends a `.local` host to a unicast server that cannot
    /// answer for it, or a global name to a multicast group that will not.
    #[test]
    fn only_a_dotted_local_name_is_a_multicast_name() {
        assert!(is_multicast_local("raspberrypi.local"));
        assert!(is_multicast_local("Printer.LOCAL"));
        assert!(is_multicast_local("host.sub.local"));

        assert!(!is_multicast_local("example.com"));
        assert!(!is_multicast_local("localhost"));
        // A bare `local` has no host part; it is a short name, not a `.local`
        // one.
        assert!(!is_multicast_local("local"));
    }

    /// A window too short to hear a conformant responder is raised to one that
    /// can, rather than producing a lookup that closes before it opens.
    ///
    /// RFC 6762 §6.3 lets a responder defer a reply half a second to aggregate
    /// answers, so half a second is the floor the protocol sets. Zero, taken as
    /// written, would reach the listener that way.
    ///
    /// Raised rather than refused, unlike the overrides in
    /// [`RetryConfig`](crate::config::RetryConfig): nothing in a
    /// [`ResolveConfig`] is carried into a report, so a window the engine
    /// overrules costs nobody a record claiming a run did something it did not.
    #[test]
    fn a_window_shorter_than_the_protocol_allows_is_raised_to_it() {
        for asked in [Duration::ZERO, Duration::from_millis(1), MIN_MDNS_TIMEOUT] {
            assert_eq!(asked.max(MIN_MDNS_TIMEOUT), MIN_MDNS_TIMEOUT);
        }

        // A window the caller meant is the window they get.
        let generous = Duration::from_secs(5);
        assert_eq!(generous.max(MIN_MDNS_TIMEOUT), generous);
        assert_eq!(
            DEFAULT_MDNS_TIMEOUT.max(MIN_MDNS_TIMEOUT),
            DEFAULT_MDNS_TIMEOUT,
            "the default is above the floor, or the floor is the default"
        );
    }

    /// A resolver says what it reads and whether multicast is on, which is
    /// what a caller debugging a resolution needs from it.
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
    // Each test below hands a resolver its hosts file and its servers, and the
    // servers are fakes on loopback, so what a lookup asks, and of whom, is
    // observed rather than sent anywhere. mDNS is off throughout: a `.local`
    // name that reached the link would be a multicast packet leaving the test.

    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
    use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
    use hickory_resolver::proto::rr::rdata::{A, SOA};
    use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};

    use crate::logging::logged;

    /// A name server on loopback that answers A queries for the names it
    /// holds and NXDOMAIN for any other, noting every question it is asked.
    ///
    /// Its NXDOMAIN carries the zone's SOA, as a real server's does, because
    /// that is what lets a client cache the failure: an answer without one
    /// would hide a client that holds failures across passes.
    struct FakeDns {
        at: SocketAddr,
        records: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
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

            let (held, noted) = (Arc::clone(&records), Arc::clone(&asked));
            let serving = tokio::spawn(async move {
                let mut buf = [0u8; 1500];
                while let Ok((len, from)) = socket.recv_from(&mut buf).await {
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
                    let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
                    reply.metadata.message_type = MessageType::Response;
                    reply.metadata.recursion_desired = query.metadata.recursion_desired;
                    reply.metadata.recursion_available = true;
                    reply.add_query(question.clone());
                    match known {
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
                asked,
                serving,
            }
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

    /// A resolver reading `hosts` and asking `global`.
    fn resolver_over(
        hosts: &str,
        global: Result<(ResolverConfig, ResolverOpts), String>,
    ) -> Resolver {
        let hosts = hosts.to_owned();
        Resolver::given(no_mdns(), move || {
            (
                hosts.clone(),
                DnsConfig {
                    global: global.clone(),
                },
            )
        })
    }

    /// A name the hosts file lists is answered from it and asked of no server,
    /// in either family.
    ///
    /// The file lists an A address; a lookup that consulted it per record type
    /// would still ask upstream for AAAA, telling a resolver somebody else
    /// operates which lab box is being scanned, and on a network where that
    /// resolver is unreachable, waiting out its whole timeout first.
    #[tokio::test]
    async fn a_name_the_hosts_file_lists_is_answered_without_asking_dns() {
        let dns = FakeDns::start(&[]).await;
        let resolver = resolver_over("198.51.100.7 box.example\n", Ok(dns.as_global(&[])));

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
    /// name gets two lines, and scanning both covers a host nobody meant; the
    /// warning is what lets the user delete the right one.
    #[test]
    fn a_stale_hosts_line_for_a_name_is_neither_scanned_nor_silent() {
        let resolver = resolver_over(
            "198.51.100.23 box.example\n198.51.100.99 box.example\n",
            Err("none configured".into()),
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
        );

        for name in ["forest.corp.local", "corp.local"] {
            assert_eq!(
                resolver.resolve(name).await,
                vec![v4("198.51.100.161")],
                "{name}"
            );
        }
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
    /// The loop a long-lived front end serves is: a box comes up, its line goes
    /// into the hosts file or its record into DNS, and the scan runs. A
    /// resolver holding the file it read at construction, or a cached failure,
    /// would miss the box until the front end restarted.
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
}
