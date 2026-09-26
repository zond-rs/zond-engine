// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reverse name resolution
//!
//! Attaches hostnames to discovered hosts without holding up the scan that found
//! them. Two independent paths live here, chosen by whether the scan is privileged.
//!
//! [`HostnameResolver`] drives the privileged path, which is both passive and
//! active at once. It sends reverse DNS (PTR) queries for each IP handed to it,
//! as many at a time as the other path asks, and, in parallel, sniffs raw UDP
//! traffic for DNS (port 53) and mDNS (port 5353) responses that other activity
//! on the network happens to surface.
//! Whatever it learns is cached until [`HostnameResolver::resolve_hosts`] folds
//! it into the shared host store.
//!
//! Every name learned here is tied to an address by the *question* it answers,
//! never by the transaction ID alone. The sniffing path sees traffic addressed
//! to other processes and other hosts, where an ID is somebody else's counter
//! and matching on it would file a stranger's answer against a scanned host.
//! The reverse name in the question is the only field that means the same thing
//! in a packet nobody sent us.
//!
//! [`resolve_hosts_async`] is the unprivileged fallback. With no raw socket to
//! sniff, it simply issues reverse lookups for every host that still lacks a
//! name.
//!
//! Both paths name a host from the sources forward resolution reads, in the
//! same order: the hosts file, which names an address it lists without a
//! query, then the servers a scoped resolver names for the address's reverse
//! zone, where the host has one, and otherwise the global ones. See
//! [`crate::resolve`] for why a name is routed that way; a reverse name is a
//! name like any other, and a VPN scopes its reverse zones as it scopes its
//! domains.
//!
//! Both paths ask by the routing table, whatever source a scan forced; see
//! [`ZondConfig::send_source`](crate::config::ZondConfig::send_source) for why
//! a lookup is not pinned.
//!
//! ## What answering proves
//!
//! Both paths above read DNS *responses*, and a machine that answers a DNS
//! question is a name server: [`NetworkRole::DnsServer`], concluded from the
//! protocol's own traffic rather than from a port being open. This is the only
//! place a scan that never touches a port can conclude it, and on a local
//! segment it is the usual place: the resolver a machine is configured with is
//! generally the router it is scanning.
//!
//! Recorded against hosts the scan already found and never against anything
//! else, so an upstream resolver nobody asked about does not appear in a report
//! as a host. The unprivileged fallback contributes nothing here: it asks
//! through the system resolver, which does not say which server answered.
//!
//! mDNS is not counted. It shares DNS's framing and answers on
//! 5353, and nearly every laptop and printer on a segment responds to it.

use hickory_resolver::config::ProtocolConfig;
use std::net::SocketAddr;
use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    net::IpAddr,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

use crate::logging::error;
use crate::model::host::NetworkRole;
use crate::protocols::{
    dns,
    mdns::{self, MdnsHost},
};
use crate::resolve::{
    DnsConfig, HostsTable, Reverse, ScopedServers, Snapshot, covers, reverse_name,
};
use crate::scanner::session::ScanContext;
use crate::{counted, info, model::ip, warn};
use pnet_packet::{Packet, udp::UdpPacket};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::Instant;

use crate::model::ip::scoped::Zone;
use crate::model::ip::set::IpSet;
use crate::transport::probe::{ProbeKind, ProbeTransport, TransportError};

/// Where a name server answers, and where this resolver both listens and asks.
const DNS_PORT: u16 = 53;
use crate::protocols::mdns::PORT as MDNS_PORT;

/// Largest reply worth reading off the query socket. A PTR answer is tiny, but
/// EDNS lets a server return up to this much and a truncated read would be
/// unparseable rather than merely incomplete.
const MAX_DNS_DATAGRAM: usize = 4096;

/// How long the resolver keeps listening after the last IP has been queried, so
/// replies still in flight are not thrown away with the scan that asked for them.
///
/// Once the stream of addresses has closed, it is also as long as any query
/// still unanswered holds its place among [`REVERSE_LOOKUPS_IN_FLIGHT`]: the
/// scan is waiting on the resolver then, and a query a resolver has let lie
/// that long is one it is not answering.
const REPLY_GRACE: Duration = Duration::from_millis(250);

/// How long a query holds its place among [`REVERSE_LOOKUPS_IN_FLIGHT`] while
/// the scan is still running, unanswered, before the place goes to the next
/// address.
///
/// A resolver answers a PTR in milliseconds from its leases or its cache, and
/// one that asks upstream within a second or so; past two, the question is
/// one it is not going to answer soon, and the addresses behind it should not
/// wait on it. Giving the place up is not giving the question up: its ID stays
/// outstanding, so an answer arriving later still names the address.
const QUERY_PATIENCE: Duration = Duration::from_secs(2);

/// A name as it came off the wire, already trimmed of its trailing root label.
type Hostname = String;

/// How a name reached this resolver, which is what decides between two names
/// for one address. Ordered by trust, so comparing two is the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Heard {
    /// Read off the wire, answering somebody else's question. Unauthenticated:
    /// anyone who can put a datagram from port 53 in front of the capture
    /// chooses both the address and the name.
    Overheard,
    /// A reply to one of this resolver's own queries: from a resolver it asked,
    /// carrying an ID it issued, about the address it asked about.
    Answered,
    /// The hosts file's name for the address, which the system's own lookups
    /// answer with before they ask anybody, and so is never asked here.
    Listed,
}

/// A name, with how it was heard.
#[derive(Debug, Clone)]
struct Named {
    hostname: Hostname,
    heard: Heard,
}
/// The transaction id a query carries, and the only thing tying a reply to the
/// question it answers.
type TransID = u16;

/// One resolver a reverse query is sent to, paired with the socket that can
/// reach it. The pairing is fixed at construction so the send path never has to
/// ask which address family a server belongs to.
struct QueryTarget {
    server: SocketAddr,
    /// The reverse zone this server is asked for, an index into the
    /// resolver's scopes, or `None` for a server asked about every address no
    /// scope claims.
    scope: Option<usize>,
    socket: Arc<UdpSocket>,
    /// Whether this resolver has answered any query, which is what keeps it
    /// asked however many others it let lie.
    answered: bool,
    /// How many of its queries gave up their place unanswered.
    unanswered: usize,
}

impl QueryTarget {
    /// Whether this resolver is still sent queries.
    ///
    /// Not once it has let a whole window of them, [`REVERSE_LOOKUPS_IN_FLIGHT`],
    /// give up their places without answering one: a resolver that has
    /// answered nothing by then is not answering, and asking it on would hold
    /// every address behind it for [`QUERY_PATIENCE`], or at the end of a scan
    /// for [`REPLY_GRACE`], window after window. The common case is a second
    /// resolver the host is configured with that is not there, beside a first
    /// that answers everything; one that answers slowly has answered, and is
    /// asked on.
    fn is_asked(&self) -> bool {
        self.answered || self.unanswered < REVERSE_LOOKUPS_IN_FLIGHT
    }
}

/// A query sent and not yet answered: the address it asks about, and which of
/// the resolver's [`QueryTarget`]s it went to.
#[derive(Debug, Clone, Copy)]
struct Query {
    ip: IpAddr,
    target: usize,
}

/// An address being asked about, holding one of the places
/// [`REVERSE_LOOKUPS_IN_FLIGHT`] allows.
#[derive(Debug)]
struct Asking {
    /// The IDs of its queries still unanswered, one per resolver asked.
    ids: Vec<TransID>,
    /// When it gives its place up, answered or not.
    until: Instant,
}

/// Passive-and-active hostname resolver for the privileged scan path.
///
/// It runs as its own task ([`HostnameResolver::run`]), taking IPs to resolve off
/// `dns_rx` as the scan discovers them, querying every configured resolver for
/// each, and sniffing the wire for any DNS or mDNS answers that pass by. The
/// names it gathers are held in its caches until [`HostnameResolver::resolve_hosts`]
/// writes them back to the host store at the end of the scan.
pub struct HostnameResolver {
    /// Raw UDP receiver used to sniff DNS and mDNS responses off the wire.
    transport: ProbeTransport,
    /// Every resolver a reverse query may go to, with the socket to send it
    /// on and the zone it is asked for.
    query_targets: Vec<QueryTarget>,
    /// The reverse zones a scoped resolver answers for, longest first.
    scopes: Vec<ReverseScope>,
    /// The hosts file, which names an address it lists without a query.
    hosts: HostsTable,
    /// Outstanding PTR queries, keyed by transaction ID so a reply can be matched
    /// back to the IP it was asked about and the resolver it was asked of.
    dns_map: HashMap<TransID, Query>,
    /// IPs already queried or waiting to be, so a host reported by more than
    /// one scanning strategy is asked about once rather than once per report.
    queried: HashSet<IpAddr>,
    /// IPs waiting for a place among [`REVERSE_LOOKUPS_IN_FLIGHT`], in the
    /// order they arrived.
    waiting: VecDeque<IpAddr>,
    /// The IPs being asked about, each holding a place.
    asking: HashMap<IpAddr, Asking>,
    /// mDNS records collected from sniffed traffic, each under every address
    /// it names. See [`file_mdns`](Self::file_mdns).
    mdns_cache: HashMap<IpAddr, MdnsHost>,
    /// Hostnames resolved so far, keyed by IP.
    hostname_map: HashMap<IpAddr, Named>,
    /// Addresses seen answering a DNS question, whoever asked it.
    ///
    /// Two sources, and neither costs a probe: a reply to one of this
    /// resolver's own queries, and a response sniffed off the wire that some
    /// other machine's lookup drew. Written into the store by
    /// [`resolve_hosts`](Self::resolve_hosts) alongside the names, since both
    /// are findings about hosts and the store is walked once.
    name_servers: HashSet<IpAddr>,
    /// Stream of IPs to resolve, fed by the discovery and scanning strategies.
    dns_rx: UnboundedReceiver<IpAddr>,
    /// Source of transaction IDs for outgoing queries.
    id_counter: AtomicU16,
}

/// Why a [`HostnameResolver`] could not be built.
///
/// Two ways, and they want different answers from a caller. Nothing to ask means
/// this host has no resolver a reverse query could reach, and a scan carries on
/// reporting addresses without names. A receive path that will not open is a
/// privilege problem, and it is the same one every raw path here has.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    /// No resolver could be reached, so there is nothing to ask.
    ///
    /// Raised where the caller named the resolvers to ask: none were named,
    /// or every socket that would carry a query refused to bind. Each refusal
    /// is warned about as it happens; this is what is left when none
    /// succeeded. A resolver built from the host's own configuration runs
    /// without one, naming hosts from the hosts file and the traffic it
    /// sniffs.
    #[error("no reachable DNS server to send reverse queries to")]
    NoServer,

    /// The capture the sniffing half reads through could not be opened.
    #[error("the resolver's receive path could not be opened: {0}")]
    Transport(#[from] TransportError),
}

impl HostnameResolver {
    /// Builds a resolver that reads IPs to resolve from `dns_rx`.
    ///
    /// It reads the hosts file and works out which resolvers can answer for
    /// the hosts being scanned (see `Routes`), binds a query socket for each
    /// address family they span, and opens the raw receiver used to sniff DNS
    /// and mDNS traffic.
    ///
    /// A host with no resolver to ask still gets a resolver: the hosts file
    /// and the traffic it sniffs name hosts without a query, and the missing
    /// configuration is said once, as forward resolution says it.
    pub fn new(dns_rx: UnboundedReceiver<IpAddr>) -> Result<Self, ResolverError> {
        let routes = Routes::from_system();
        let transport = ProbeTransport::open_receiver(ProbeKind::UdpResolve)?;
        Self::with_routes(dns_rx, transport, routes)
    }

    /// [`new`](Self::new), sniffing only on `links` and the links replies
    /// from the resolvers it queries arrive by.
    ///
    /// For a scan that knows its targets: an mDNS answer about one of them
    /// comes over the target's own link, and a unicast answer over the link
    /// toward the server that gives it. See
    /// [`capture_links_toward`](crate::transport::probe::capture_links_toward).
    pub(crate) fn capturing_on(
        dns_rx: UnboundedReceiver<IpAddr>,
        links: &[Zone],
    ) -> Result<Self, ResolverError> {
        let routes = Routes::from_system();
        let mut servers = IpSet::new();
        for (server, _) in &routes.servers {
            servers.insert(server.ip());
        }
        let mut links = links.to_vec();
        if !servers.is_empty() {
            for link in crate::transport::probe::capture_links_toward(&servers, &[]) {
                if !links.contains(&link) {
                    links.push(link);
                }
            }
        }
        let transport = ProbeTransport::open_receiver_capturing(ProbeKind::UdpResolve, &links)?;
        Self::with_routes(dns_rx, transport, routes)
    }

    /// Builds a resolver that queries `dns_servers` and sniffs through
    /// `transport`, rather than discovering both from the host.
    ///
    /// Both of `new`'s environmental dependencies are parameters here. That
    /// matters for testing: reading the host's resolver configuration gives a
    /// different answer on every machine and fails outright on some CI images,
    /// and the raw receiver needs privileges that a test runner does not have.
    /// Pointing this at a DNS server on loopback and a synthetic transport
    /// (`ProbeTransport::from_parts`, behind the `test-support` feature)
    /// exercises the PTR exchange and the sniffing path with neither.
    ///
    /// The query sockets are still real ones, bound to ephemeral ports in the
    /// families `dns_servers` spans. They need no privileges, and keeping them
    /// real is the point: the query and reply handling under test is the same
    /// code that runs in production.
    ///
    /// Every server in `dns_servers` is asked about every address, and no
    /// hosts file is read.
    pub fn with_transport(
        dns_rx: UnboundedReceiver<IpAddr>,
        transport: ProbeTransport,
        dns_servers: Vec<SocketAddr>,
    ) -> Result<Self, ResolverError> {
        let routes = Routes {
            hosts: HostsTable::default(),
            servers: dns_servers.into_iter().map(|at| (at, None)).collect(),
            scopes: Vec::new(),
        };
        let resolver = Self::with_routes(dns_rx, transport, routes)?;
        if resolver.query_targets.is_empty() {
            return Err(ResolverError::NoServer);
        }
        Ok(resolver)
    }

    /// Builds a resolver that asks and names by `routes`, sniffing through
    /// `transport`.
    fn with_routes(
        dns_rx: UnboundedReceiver<IpAddr>,
        transport: ProbeTransport,
        routes: Routes,
    ) -> Result<Self, ResolverError> {
        let query_targets = bind_query_targets(&routes.servers, &routes.scopes);

        Ok(Self {
            transport,
            query_targets,
            scopes: routes.scopes,
            hosts: routes.hosts,
            dns_map: HashMap::new(),
            queried: HashSet::new(),
            waiting: VecDeque::new(),
            asking: HashMap::new(),
            mdns_cache: HashMap::new(),
            hostname_map: HashMap::new(),
            name_servers: HashSet::new(),
            dns_rx,
            id_counter: AtomicU16::new(0),
        })
    }

    /// Runs the resolver's event loop until the IP stream closes and every
    /// address it carried has been asked about.
    ///
    /// On each turn it does one of four things: take a newly arrived IP, read a
    /// reply to a query it sent, absorb a DNS or mDNS packet sniffed off the
    /// wire, or give up the place of a query left unanswered too long. Between
    /// turns it asks about as many waiting IPs as there are places free, which
    /// is as many as the unprivileged path asks about at once. Once `dns_rx`
    /// closes, the queries still in flight have a short grace to be answered,
    /// and the IPs still waiting are asked in turn, before it returns itself,
    /// so the caller can hand the collected names to
    /// [`resolve_hosts`](Self::resolve_hosts).
    pub async fn run(mut self) -> Self {
        let (v4, v6) = self.reply_sockets();
        // Whether the capture still has anything to give. A closed stream is
        // ready forever, so its arm has to be switched off rather than polled:
        // left enabled it would spin the loop instead of waiting in it, and end
        // the reply window the moment it was entered.
        let mut sniffing = true;
        // Whether more IPs may arrive, switched off for the same reason.
        let mut arriving = true;

        loop {
            self.ask_waiting(arriving).await;
            if !arriving && self.waiting.is_empty() && self.asking.is_empty() {
                break;
            }
            let next_expiry = self.asking.values().map(|asking| asking.until).min();

            tokio::select! {
                res = self.dns_rx.recv(), if arriving => {
                    match res {
                        Some(ip) => self.enqueue(ip),
                        None => {
                            arriving = false;
                            self.hurry(Instant::now() + REPLY_GRACE);
                        }
                    }
                }
                (payload, from) = recv_reply(&v4) => self.absorb_reply(&payload, from),
                (payload, from) = recv_reply(&v6) => self.absorb_reply(&payload, from),
                pkt = self.transport.rx.recv(), if sniffing => {
                    match pkt {
                        Some(reply) => self.absorb_sniffed(&reply.bytes, reply.source),
                        None => sniffing = false,
                    }
                }
                () = tokio::time::sleep_until(next_expiry.unwrap_or_else(Instant::now)),
                    if next_expiry.is_some() => self.expire(Instant::now()),
            }
        }

        // Frames the capture lifted off the wire before the scan ended may still
        // be queued behind it. They cost nothing to read and were paid for
        // already, so take whatever is there rather than dropping names the
        // network has in fact already told us.
        while let Ok(reply) = self.transport.rx.try_recv() {
            self.absorb_sniffed(&reply.bytes, reply.source);
        }

        self
    }

    /// Puts `ip` in line to be asked about, unless it is one already asked
    /// about, one the hosts file names, or one no reverse lookup can answer
    /// for.
    ///
    /// An address the hosts file lists is named from it and asked of nobody,
    /// as the system's own lookups name it, and as forward resolution answers
    /// a name the file lists: see [`Snapshot::reverse`].
    fn enqueue(&mut self, ip: IpAddr) {
        if !self.queried.insert(ip) {
            return;
        }
        if let Some(hostname) = self.hosts.name_of(ip) {
            info!(verbosity = 2, "hosts file names {ip} {hostname}");
            self.hostname_map.insert(
                ip,
                Named {
                    hostname: hostname.to_owned(),
                    heard: Heard::Listed,
                },
            );
        } else if is_queryable(&ip) {
            self.waiting.push_back(ip);
        }
    }

    /// Asks about waiting IPs until every place is taken or none is left
    /// waiting, each given [`QUERY_PATIENCE`] to be answered while more IPs
    /// may be `arriving` and [`REPLY_GRACE`] once none will.
    ///
    /// With no resolver left that is still asked (see
    /// [`QueryTarget::is_asked`]), the waiting IPs are let go: there is nobody
    /// to ask.
    async fn ask_waiting(&mut self, arriving: bool) {
        if !self.query_targets.iter().any(QueryTarget::is_asked) {
            self.waiting.clear();
            return;
        }
        let patience = if arriving {
            QUERY_PATIENCE
        } else {
            REPLY_GRACE
        };
        while self.asking.len() < REVERSE_LOOKUPS_IN_FLIGHT
            && let Some(ip) = self.waiting.pop_front()
        {
            match self.send_dns_query(&ip).await {
                // Nobody to ask about this address: its zone's servers cannot
                // be reached, or have stopped being asked.
                Ok(ids) if ids.is_empty() => {}
                Ok(ids) => {
                    info!(
                        outgoing,
                        verbosity = 2,
                        "reverse query for {ip} sent to {}",
                        counted(ids.len() as u128, "resolver", "resolvers")
                    );
                    let until = Instant::now() + patience;
                    self.asking.insert(ip, Asking { ids, until });
                }
                Err(e) => error!("reverse query for {ip} failed: {e}"),
            }
        }
    }

    /// Brings every place's end forward to `until` where it is later, for
    /// the stream of IPs having closed: see [`REPLY_GRACE`].
    fn hurry(&mut self, until: Instant) {
        for asking in self.asking.values_mut() {
            asking.until = asking.until.min(until);
        }
    }

    /// Gives up the place of every IP whose time ran out by `now`, counting
    /// each query of it still unanswered against the resolver it went to.
    ///
    /// The queries themselves stay outstanding, so a late answer still names
    /// the address; see [`QUERY_PATIENCE`].
    fn expire(&mut self, now: Instant) {
        let expired: Vec<IpAddr> = self
            .asking
            .iter()
            .filter(|(_, asking)| asking.until <= now)
            .map(|(ip, _)| *ip)
            .collect();
        for ip in expired {
            let Some(asking) = self.asking.remove(&ip) else {
                continue;
            };
            for id in asking.ids {
                let Some(query) = self.dns_map.get(&id) else {
                    continue;
                };
                let target = &mut self.query_targets[query.target];
                let was_asked = target.is_asked();
                target.unanswered += 1;
                if was_asked && !target.is_asked() {
                    info!(
                        verbosity = 1,
                        "{} answered no reverse query; asking it no more", target.server
                    );
                }
            }
        }
    }

    /// Sends a reverse (PTR) query for `ip` to every resolver still asked for
    /// its zone and records each transaction ID, so the matching reply can
    /// later be tied back to this IP. Returns the IDs, one per resolver
    /// reached, and none when there is nobody to ask.
    ///
    /// The zone's resolvers are the servers of the longest scoped reverse zone
    /// covering the address, where one does, and only those, as the OS asks
    /// them; otherwise every global resolver and gateway (see [`Routes`]).
    /// Every one of them is asked rather than the first that answers, because
    /// a negative answer is not evidence that the name does not exist: a
    /// resolver that declines to serve a reverse zone answers exactly as fast,
    /// and exactly as confidently, as one that has looked and found nothing.
    async fn send_dns_query(&mut self, ip: &IpAddr) -> std::io::Result<Vec<TransID>> {
        let name = reverse_name(*ip);
        let scope = self
            .scopes
            .iter()
            .position(|scope| covers(&scope.domain, &name));
        if let Some(scope) = scope.map(|index| &mut self.scopes[index])
            && let Some(why) = &scope.unasked
        {
            if !scope.said {
                scope.said = true;
                warn!("DNS for {} not asked ({why})", scope.domain);
            }
            return Ok(Vec::new());
        }

        let mut sent = Vec::with_capacity(self.query_targets.len());
        let mut last_error = None;

        for (index, target) in self.query_targets.iter().enumerate() {
            if target.scope != scope || !target.is_asked() {
                continue;
            }
            let id = self.get_next_trans_id();
            let packet = dns::build_ptr_packet(*ip, id);
            match target.socket.send_to(&packet, target.server).await {
                Ok(_) => sent.push((id, index)),
                // The server is named here because the error will not say which
                // of several this was.
                Err(error) => {
                    last_error = Some(std::io::Error::new(
                        error.kind(),
                        format!("{}: {error}", target.server),
                    ));
                }
            }
        }

        if let (true, Some(error)) = (sent.is_empty(), last_error) {
            return Err(error);
        }

        for (id, target) in sent.iter().copied() {
            self.dns_map.insert(id, Query { ip: *ip, target });
        }

        Ok(sent.into_iter().map(|(id, _)| id).collect())
    }

    /// Handles a reply that arrived on a query socket.
    ///
    /// A reply counts only when it comes from the resolver a transaction ID
    /// still outstanding was sent to, *and* answers the question that ID was
    /// spent on. Both have to agree: the ID is a 16-bit counter and the socket
    /// is open to the whole network, so the question name is what makes a
    /// forged or stale reply fail to match rather than rename a host.
    fn absorb_reply(&mut self, payload: &[u8], from: SocketAddr) {
        if !self.query_targets.iter().any(|t| t.server == from) {
            return;
        }

        let response = match dns::parse_ptr_response(payload) {
            Ok(response) => response,
            Err(e) => {
                error!(verbosity = 2, "unreadable reply from resolver {from}: {e}");
                return;
            }
        };

        // It answered, which is the whole of the claim and is settled before the
        // checks below. Those decide whether this reply names *a host*; a
        // resolver that declines the question, or answers one we are no longer
        // waiting on, is a name server either way.
        self.name_servers.insert(from.ip());
        // One server can be asked for a scoped zone and for the rest alike, and
        // answering either says it answers.
        for target in self.query_targets.iter_mut().filter(|t| t.server == from) {
            target.answered = true;
        }

        let Some(Query { ip, target }) = self.dns_map.get(&response.id).copied() else {
            return;
        };
        if self.query_targets[target].server != from || response.subject != Some(ip) {
            return;
        }

        // The question has been answered, one way or the other; the other
        // resolvers asked about this IP are still outstanding on their own IDs,
        // and the IP holds its place until they have answered too.
        self.dns_map.remove(&response.id);
        if let Some(asking) = self.asking.get_mut(&ip) {
            asking.ids.retain(|id| *id != response.id);
            if asking.ids.is_empty() {
                self.asking.remove(&ip);
            }
        }

        match response.hostname {
            // A name that is the address written again is declined here rather
            // than filtered later: recorded, it would keep the mDNS answer below
            // from ever being asked for. See `restates`.
            Some(hostname) if restates(&hostname, ip) => info!(
                verbosity = 2,
                "{from} named {ip} after itself ({hostname}), so it has no name"
            ),
            Some(hostname) => match self.hostname_map.entry(ip) {
                // Two resolvers this scan asked, both checked the same way. The
                // first stands, so the name does not depend on which reply the
                // network happened to deliver last.
                Entry::Occupied(slot) if slot.get().heard >= Heard::Answered => info!(
                    verbosity = 2,
                    "{from} resolved {ip} to {hostname}; an earlier answer stands"
                ),
                // A name somebody else's lookup carried past is only a
                // placeholder until an answer arrives, however early it came.
                Entry::Occupied(mut slot) => {
                    info!(
                        incoming,
                        verbosity = 2,
                        "{from} resolved {ip} to {hostname}, over a name only overheard"
                    );
                    slot.insert(Named {
                        hostname,
                        heard: Heard::Answered,
                    });
                }
                Entry::Vacant(slot) => {
                    info!(
                        incoming,
                        verbosity = 2,
                        "{from} resolved {ip} to {hostname}"
                    );
                    slot.insert(Named {
                        hostname,
                        heard: Heard::Answered,
                    });
                }
            },
            None => info!(verbosity = 2, "{from} has no name for {ip}"),
        }
    }

    /// Routes a sniffed UDP segment to the DNS or mDNS handler by its source
    /// port, ignoring anything from another port.
    ///
    /// Nothing here is reported as a failure. Everything the capture yields is
    /// unsolicited third-party traffic - the host's own browsing, other
    /// machines' service discovery - so a segment that will not parse, or that
    /// concerns no address, is simply not ours. Logging each one would turn
    /// ordinary background traffic into a wall of scan errors.
    fn absorb_sniffed(&mut self, segment: &[u8], source: IpAddr) {
        let Some(udp_packet) = UdpPacket::new(segment) else {
            return;
        };

        match udp_packet.get_source() {
            DNS_PORT => {
                // Somebody else's lookup, answered in front of us. The name in
                // it may be about a host the scan never found; the machine that
                // sent it is one we can see, and it just served DNS.
                if dns::is_response(udp_packet.payload()) {
                    self.name_servers.insert(source);
                }
                self.absorb_sniffed_dns(udp_packet.payload());
            }
            MDNS_PORT => self.absorb_sniffed_mdns(udp_packet.payload()),
            _ => {}
        }
    }

    /// Caches the name in a DNS response that was never asked for.
    ///
    /// Somebody else's reverse lookup answers our question just as well, so the
    /// transaction ID is beside the point here - the response is matched purely
    /// on the address its question names. A name for a host the scan never found
    /// costs nothing: [`resolve_hosts`](Self::resolve_hosts) only applies what
    /// matches a host in the store.
    ///
    /// **It fills a gap, never displaces, and gives way.** Nothing authenticates
    /// a packet read off the wire: anyone who can put a datagram with source
    /// port 53 in front of the capture chooses both the address and the name.
    /// That is acceptable for an address nothing else has named - an overheard
    /// name is better than none, and the log line says which it was - and it is
    /// not acceptable against [`absorb_reply`](Self::absorb_reply), which took a
    /// reply from a resolver it had asked, carrying a transaction ID it had
    /// issued, over a question naming the address it had asked about.
    ///
    /// In either order: an answer already held is not displaced, and an answer
    /// arriving later replaces what was only overheard, so a forged reply sent
    /// ahead of the real one holds its place only until the real one comes. The
    /// engine ranks its evidence this way everywhere else:
    /// [`HostStatus`](crate::model::host::HostStatus) is ordered by how strong
    /// the evidence is and `record_evidence` refuses to lower it.
    fn absorb_sniffed_dns(&mut self, payload: &[u8]) {
        let Ok(response) = dns::parse_ptr_response(payload) else {
            return;
        };
        let (Some(ip), Some(hostname)) = (response.subject, response.hostname) else {
            return;
        };

        if restates(&hostname, ip) {
            return;
        }

        if let Entry::Vacant(slot) = self.hostname_map.entry(ip) {
            info!(verbosity = 2, "overheard {ip} named {hostname}");
            slot.insert(Named {
                hostname,
                heard: Heard::Overheard,
            });
        }
    }

    /// Caches the hosts a sniffed mDNS message names.
    ///
    /// A message may speak for several hosts, and each is filed on its own by
    /// [`file_mdns`](Self::file_mdns).
    fn absorb_sniffed_mdns(&mut self, payload: &[u8]) {
        let Ok(hosts) = mdns::extract_hosts(payload) else {
            return;
        };

        for host in hosts {
            self.file_mdns(host);
        }
    }

    /// Files what one mDNS record says under every address it names.
    ///
    /// Every one of them, because which of a device's addresses the store knows
    /// it by is not something the record can predict. The scan may have reached
    /// it at one address and never at another, or its exclusions may forbid one,
    /// and an excluded address never joins a host's record. Filed under only one
    /// of them, the name would be lost whenever that one is not among the
    /// host's, and the device reported at its other addresses without the name
    /// it announced for all of them.
    ///
    /// A later record naming an address replaces an earlier one there, since
    /// the latest announcement is the device's current word about it.
    fn file_mdns(&mut self, host: MdnsHost) {
        info!(
            verbosity = 2,
            "mDNS names {} as {}",
            host.ips
                .iter()
                .map(IpAddr::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            host.hostname
        );
        for ip in &host.ips {
            self.mdns_cache.insert(*ip, host.clone());
        }
    }

    /// Writes every collected name back into the host store.
    ///
    /// For each host it walks the IPs the host is known by and applies whatever
    /// the caches hold for them: a DNS hostname when the host has none yet, and
    /// any mDNS record, which can supply a hostname and additional IPs.
    /// Consumed entries are removed from the caches as they are applied.
    ///
    /// Every address is asked for a DNS name before any is asked for an mDNS
    /// record, so a name unicast DNS gave the host is preferred whichever of its
    /// addresses the record was found at. A record is filed under every address
    /// it names, and in a single pass one found at an address that sorts first
    /// would name the host before a resolver's answer about another address was
    /// read.
    ///
    /// Written through [`ScanContext::write_host`] like every other finding, so
    /// a name reaches the event stream as well as the store. Applied by
    /// iterating the map directly it would not, and a consumer watching a scan
    /// would see its hosts arrive unnamed and never hear they had been named.
    ///
    /// The addresses are collected before any of them is written. `write_host`
    /// takes the store's own lock, and taking it while iterating the map would
    /// deadlock against whichever shard the iterator is holding.
    pub fn resolve_hosts(&mut self, ctx: &ScanContext) {
        for key in ctx.host_addresses() {
            let (hostname_map, mdns_cache) = (&mut self.hostname_map, &mut self.mdns_cache);
            let name_servers = &self.name_servers;

            ctx.write_host(key, |host| {
                let mut named = false;
                let ips = host.ips().clone();

                for ip in &ips {
                    // Not `else`-chained with the names below: a resolver that
                    // answers about other hosts and has no name of its own is
                    // the ordinary case for a router.
                    if name_servers.contains(ip) {
                        named |= host.add_network_role(NetworkRole::DnsServer);
                    }

                    // Prefer a hostname learned over unicast DNS.
                    if host.hostname().is_none()
                        && let Some(Named { hostname, .. }) = hostname_map.remove(ip)
                    {
                        host.set_hostname(Some(hostname));
                        named = true;
                    }
                }

                for ip in &ips {
                    // An mDNS record can fill in a missing hostname and extra IPs.
                    if let Some(mdns_host) = mdns_cache.remove(ip) {
                        if host.hostname().is_none() {
                            host.set_hostname(Some(mdns_host.hostname));
                        }

                        host.extend_ips(mdns_host.ips);
                        named = true;
                    }
                }

                named
            });
        }
    }

    /// One socket per address family in use, for the receive arms of the event
    /// loop. Taken once up front so the loop borrows nothing of `self` to listen.
    fn reply_sockets(&self) -> (Option<Arc<UdpSocket>>, Option<Arc<UdpSocket>>) {
        let socket_for = |ipv4: bool| {
            self.query_targets
                .iter()
                .find(|t| t.server.is_ipv4() == ipv4)
                .map(|t| Arc::clone(&t.socket))
        };

        (socket_for(true), socket_for(false))
    }

    /// Hands out the next DNS transaction ID, wrapping around on overflow.
    fn get_next_trans_id(&self) -> u16 {
        self.id_counter.fetch_add(1, Ordering::Relaxed)
    }
}

/// Receives one datagram on `socket`.
///
/// Never resolves when the family has no socket, so the event loop can carry an
/// arm for both families whether or not both are in use. A socket that fails
/// goes quiet for the same reason: a failed socket keeps failing, and retrying
/// one in a `select!` arm would spin the loop rather than wait on it.
async fn recv_reply(socket: &Option<Arc<UdpSocket>>) -> (Vec<u8>, SocketAddr) {
    let socket = match socket {
        Some(socket) => socket,
        None => return std::future::pending().await,
    };

    let mut buf = [0u8; MAX_DNS_DATAGRAM];
    match socket.recv_from(&mut buf).await {
        Ok((len, from)) => (buf[..len].to_vec(), from),
        Err(e) => {
            error!("reverse query socket failed: {e}");
            std::future::pending().await
        }
    }
}

/// Binds a query socket for each address family `servers` spans and pairs every
/// server with the socket that can reach it and the zone it is asked for.
///
/// A family whose socket will not bind - a host with IPv6 disabled, say - loses
/// its servers rather than taking the whole resolver down with it; each
/// refusal is warned about as it happens.
fn bind_query_targets(
    servers: &[(SocketAddr, Option<usize>)],
    scopes: &[ReverseScope],
) -> Vec<QueryTarget> {
    let addresses: Vec<SocketAddr> = servers.iter().map(|(at, _)| *at).collect();
    let v4 = bind_family(&addresses, SocketAddr::is_ipv4, "0.0.0.0:0");
    let v6 = bind_family(&addresses, SocketAddr::is_ipv6, "[::]:0");

    let targets: Vec<QueryTarget> = servers
        .iter()
        .filter_map(|&(server, scope)| {
            let socket = if server.is_ipv4() { &v4 } else { &v6 };
            Some(QueryTarget {
                server,
                scope,
                socket: Arc::clone(socket.as_ref()?),
                answered: false,
                unanswered: 0,
            })
        })
        .collect();

    if !targets.is_empty() {
        info!(
            verbosity = 1,
            "reverse queries go to {}",
            targets
                .iter()
                .map(|t| match t.scope {
                    Some(scope) => format!("{} (for {})", t.server, scopes[scope].domain),
                    None => t.server.to_string(),
                })
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    targets
}

/// Binds an ephemeral UDP socket at `bind_addr`, or `None` when no server needs
/// that family or the host will not give us one.
fn bind_family(
    servers: &[SocketAddr],
    wanted: fn(&SocketAddr) -> bool,
    bind_addr: &str,
) -> Option<Arc<UdpSocket>> {
    if !servers.iter().any(wanted) {
        return None;
    }

    match bind_ephemeral(bind_addr) {
        Ok(socket) => Some(Arc::new(socket)),
        Err(e) => {
            warn!("could not bind {bind_addr} for reverse queries: {e}");
            None
        }
    }
}

/// Opens a UDP socket on an ephemeral port of `bind_addr`, for asking rather
/// than for listening.
fn bind_ephemeral(bind_addr: &str) -> std::io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(bind_addr)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

/// A reverse zone a scoped resolver answers for.
struct ReverseScope {
    /// Folded, as [`covers`] compares it.
    domain: String,
    /// Why none of the zone's servers can be asked, when none can. Its
    /// addresses are then asked of nobody, rather than of the global servers.
    unasked: Option<String>,
    /// Whether `unasked` has been said, which it is once.
    said: bool,
}

/// Where a privileged scan's reverse queries go, and what it names without
/// asking: the same sources forward resolution reads, in the same order.
struct Routes {
    /// The hosts file, which names an address it lists without a query.
    hosts: HostsTable,
    /// Every server a query may go to, each with the scope it is asked for,
    /// an index into `scopes`, or `None` for every address no scope claims.
    servers: Vec<(SocketAddr, Option<usize>)>,
    /// The scoped reverse zones, longest first, so the first that covers an
    /// address is the one the OS would ask.
    scopes: Vec<ReverseScope>,
}

impl Routes {
    /// The routes the host has now.
    fn from_system() -> Self {
        Self::of(
            HostsTable::read_system(),
            DnsConfig::read_system(),
            gateways(),
        )
    }

    /// The routes a hosts file, a resolver configuration and the interfaces'
    /// default gateways make.
    ///
    /// An address under a scoped reverse zone is asked of that zone's servers
    /// alone. A VPN that serves the reverse zone of its own addresses installs
    /// one, and a PTR for one of them asked of any other server fails there
    /// and tells it which private address the scan found.
    ///
    /// Every other address goes to the configured resolvers and to each
    /// interface's default gateway. The configured resolvers are not enough on
    /// their own. A LAN scan asks about private addresses, and RFC 6303 has a
    /// general-purpose resolver answer for those reverse zones itself rather
    /// than forward them - so a VPN's resolver, or any public one, returns
    /// NXDOMAIN for every host on the link no matter what names the local
    /// network actually has. The gateway is added because on a home or office
    /// LAN it is the DHCP server, and so the one host that can map a lease
    /// back to a name. Gateways are taken per interface rather than from the
    /// default route: with a VPN up the default route belongs to the tunnel,
    /// while the LAN being scanned hangs off a gateway that no route to the
    /// internet passes through - which is exactly the case where the
    /// configured resolver cannot help.
    fn of(hosts: HostsTable, dns: DnsConfig, gateways: Vec<SocketAddr>) -> Self {
        let mut servers = Vec::new();

        match &dns.global {
            Ok((config, _options)) => {
                for name_server in config.name_servers() {
                    if let Some(port) = udp_port(name_server) {
                        push_unique(&mut servers, (SocketAddr::new(name_server.ip, port), None));
                    }
                }
            }
            Err(why) if gateways.is_empty() => {
                warn!("DNS lookups skipped (no DNS server configured)");
                info!(
                    verbosity = 1,
                    "system resolver configuration unusable: {why}"
                );
            }
            Err(why) => info!(
                verbosity = 1,
                "system resolver configuration unusable: {why}; asking gateways"
            ),
        }
        for gateway in gateways {
            push_unique(&mut servers, (gateway, None));
        }

        // Only a reverse zone can cover an address's reverse name, so a
        // forward domain's resolver is left out rather than carried unused.
        let mut scoped: Vec<ScopedServers> = dns
            .scoped
            .into_iter()
            .filter(|scope| scope.domain.ends_with(".arpa"))
            .collect();
        // Stable, so of two resolvers for one zone the one listed first, which
        // the OS orders first, is the one asked.
        scoped.sort_by_key(|scope| std::cmp::Reverse(scope.domain.len()));

        let mut scopes = Vec::with_capacity(scoped.len());
        for (index, scope) in scoped.into_iter().enumerate() {
            let unasked = match scope.servers {
                Ok(zone_servers) => {
                    for at in zone_servers {
                        push_unique(&mut servers, (at, Some(index)));
                    }
                    None
                }
                Err(why) => Some(why),
            };
            scopes.push(ReverseScope {
                domain: scope.domain,
                unasked,
                said: false,
            });
        }

        Self {
            hosts,
            servers,
            scopes,
        }
    }
}

/// Each interface's default gateway, as a DNS server to ask; see
/// [`Routes::of`] for why.
fn gateways() -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    for gateway in crate::system::interface::host_table()
        .into_iter()
        .filter_map(|i| i.gateway)
    {
        for ip in &gateway.ipv4 {
            push_unique(&mut servers, SocketAddr::new(IpAddr::V4(*ip), DNS_PORT));
        }
        for ip in &gateway.ipv6 {
            // A link-local gateway is only reachable through the interface it
            // sits on, and a plain `SocketAddr` carries no scope to say which.
            if !ip.is_unicast_link_local() {
                push_unique(&mut servers, SocketAddr::new(IpAddr::V6(*ip), DNS_PORT));
            }
        }
    }
    servers
}

/// The port to send plain DNS to on `name_server`, or `None` when it offers
/// only encrypted transports this resolver cannot speak.
fn udp_port(name_server: &hickory_resolver::config::NameServerConfig) -> Option<u16> {
    if name_server.connections.is_empty() {
        return Some(DNS_PORT);
    }

    name_server
        .connections
        .iter()
        .find(|connection| matches!(connection.protocol, ProtocolConfig::Udp))
        .map(|connection| connection.port)
}

/// Adds `server` unless it is already listed.
///
/// A linear scan because the list is a handful of resolvers and order is worth
/// keeping: the platform lists them in the order it wants them tried.
fn push_unique<T: PartialEq>(servers: &mut Vec<T>, server: T) {
    if !servers.contains(&server) {
        servers.push(server);
    }
}

/// Active-only reverse resolution for the unprivileged scan path.
///
/// Without raw sockets there is nothing to sniff, so this looks up every host
/// that answered and still lacks a hostname, from the hosts file and the
/// servers forward resolution would ask. The lookups run concurrently, at
/// most thirty-two at a time so a wide range floods neither the resolver nor
/// the descriptor table, and each answer is written back through
/// [`ScanContext::write_host`] so it announces itself like any other finding.
/// A host with no DNS server configured still names what its hosts file
/// lists, and says once that the rest went unasked.
///
/// A host nothing was heard from, one still
/// [`Unknown`](crate::model::host::HostStatus::Unknown), is not looked up. It
/// is a record a port scan filed while asking an address, not a host anything
/// found, and a scan of one port over a wide range files one per silent
/// address: resolving them would send the resolver a query per address the
/// scan found nothing at, where naming the hosts it found needs one per host.
pub async fn resolve_hosts_async(ctx: &ScanContext) {
    resolve(ctx, Unheard::Skipped).await;
}

/// Whether a reverse lookup names the hosts nothing was heard from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unheard {
    /// Only hosts that answered are named, which is every scan but one below.
    Skipped,
    /// Every host is named, answered or not: a scan whose caller asked for
    /// every address listed as a host, with
    /// [`assume_up`](crate::config::ZondConfig::assume_up), lists these too,
    /// and a listed host is one worth a name.
    Named,
}

/// The hosts a reverse lookup asks about: every one still unnamed, less those
/// nothing was heard from unless `unheard` says to name them.
///
/// Keyed by the address the host is stored under rather than by `primary_ip`,
/// so the write that follows lands on the entry that was read. The two agree
/// for most hosts and not for one whose leading address changed after it was
/// first credited.
fn to_resolve(ctx: &ScanContext, unheard: Unheard) -> Vec<crate::model::ip::scoped::ScopedIp> {
    ctx.hosts_owed_passes()
        .into_iter()
        .filter(|key| {
            ctx.read_host(key, |host| {
                host.hostname().is_none()
                    && (unheard == Unheard::Named
                        || host.status() != crate::model::host::HostStatus::Unknown)
            })
            .unwrap_or(false)
        })
        .collect()
}

/// How many addresses a reverse lookup asks about at once, on either path.
///
/// One lookup per host found, or per address under a scan that lists every
/// address as a host, so a wide range asks tens of thousands, and all of them
/// at once would flood the one resolver the whole network shares. The resolver
/// on a home router forwards at most 150 queries at once for everyone behind
/// it by default, and this leaves it most of that. A resolver answers a PTR in
/// milliseconds, from its leases or its cache, so thirty-two in flight still
/// name thousands of hosts a second; only a resolver that answers nothing makes
/// the bound what a scan waits on.
///
/// Through the system resolver each lookup also holds a UDP socket for every
/// name server it asks in parallel, two by the resolver library's default, so
/// thirty-two hold sixty-four descriptors: inside the half of even a 256-file
/// limit the process keeps for itself, beside connections that may still be
/// open. Each waits out its ten seconds of retries on a resolver that does not
/// answer. [`HostnameResolver`] asks on one socket per family, and an address
/// it asks about gives its place up after [`QUERY_PATIENCE`], or stops being
/// asked of a resolver that answers nothing at all; see
/// [`QueryTarget::is_asked`].
const REVERSE_LOOKUPS_IN_FLIGHT: usize = 32;

/// [`resolve_hosts_async`], naming the hosts nothing was heard from where
/// `unheard` says to.
///
/// Reads the hosts file and the resolver configuration once, as a forward
/// resolution pass does, and asks every address of that one reading; see
/// [`Snapshot::reverse`] for where each is answered.
pub(crate) async fn resolve(ctx: &ScanContext, unheard: Unheard) {
    let snapshot = Arc::new(crate::resolve::Resolver::from_system().snapshot());
    resolve_from(ctx, unheard, snapshot).await;
}

/// [`resolve`], against a reading already taken.
async fn resolve_from(ctx: &ScanContext, unheard: Unheard, snapshot: Arc<Snapshot>) {
    let routing = Arc::clone(&snapshot);
    resolve_with(
        ctx,
        unheard,
        REVERSE_LOOKUPS_IN_FLIGHT,
        move |ip| routing.reverse_route(ip),
        move |ip| {
            let snapshot = Arc::clone(&snapshot);
            async move { snapshot.reverse(ip).await }
        },
    )
    .await;
}

/// [`resolve`], asking `lookup` for each address's name, at most `in_flight`
/// at a time.
///
/// Every lookup's answer is read, whatever order they finish in and whichever
/// of them found nothing: an address with no name says nothing about the next.
///
/// Two things end it before every address is asked. A stop, which it reads
/// while it waits rather than between answers, so a scan stopped in its tail
/// ends then and keeps the names already in; the lookups in flight are
/// dropped. And a resolver that has let a whole window, `in_flight`, go
/// unanswered without answering one, on the rule
/// [`QueryTarget::is_asked`] applies on the other path, so that until it
/// first answers it is asked no more than that window: each costs its full
/// retries, so asking on would cost one window of those for every
/// `in_flight` hosts found, and for a wide scan that is hours spent on a
/// resolver that is not there. One that answers slowly has answered, and is
/// asked on.
///
/// That rule is kept per `route`, the way each address's lookup goes, as the
/// other path keeps it per server: a global resolver that answers nothing
/// says nothing about the server a VPN scopes to its own reverse zone, and
/// the addresses under that zone are asked of it whatever the other does.
/// The bound on lookups in flight is shared, since it is there for the
/// descriptor table and the network as well as for any one resolver.
async fn resolve_with<R, F, Fut>(
    ctx: &ScanContext,
    unheard: Unheard,
    in_flight: usize,
    route: impl Fn(IpAddr) -> R,
    lookup: F,
) where
    R: PartialEq,
    F: Fn(IpAddr) -> Fut,
    Fut: Future<Output = Reverse> + Send + 'static,
{
    let in_flight = in_flight.max(1);
    let mut routes: Vec<(R, Route)> = Vec::new();
    for key in to_resolve(ctx, unheard) {
        let way = route(key.addr());
        match routes.iter_mut().find(|(known, _)| *known == way) {
            Some((_, route)) => route.waiting.push_back(key),
            None => routes.push((way, Route::holding(key))),
        }
    }
    let mut set = tokio::task::JoinSet::new();
    let mut spawned = std::collections::HashMap::new();
    let mut turn = 0;

    loop {
        // Round the routes in turn, so a slow one does not hold the others'
        // addresses back until its own are done.
        while set.len() < in_flight
            && let Some(index) = (0..routes.len())
                .map(|offset| (turn + offset) % routes.len())
                .find(|&index| routes[index].1.is_asked(in_flight))
        {
            turn = index + 1;
            let route = &mut routes[index].1;
            let Some(key) = route.waiting.pop_front() else {
                break;
            };
            route.in_flight += 1;
            // The query takes the address; the key comes back with the answer,
            // so the write below lands on the entry that was read.
            let asked = lookup(key.addr());
            let task = set.spawn(async move { (key, asked.await) });
            spawned.insert(task.id(), index);
        }
        let Some(Some(joined)) = ctx.handle.or_stopped(set.join_next_with_id()).await else {
            break;
        };
        let id = match &joined {
            Ok((id, _)) => *id,
            Err(error) => error.id(),
        };
        let Some(route) = spawned.remove(&id).map(|index| &mut routes[index].1) else {
            continue;
        };
        route.in_flight -= 1;
        let Ok((_, (key, reverse))) = joined else {
            continue;
        };
        let name = match reverse {
            // Read from the hosts file: nothing was asked, so it says nothing
            // about whether the resolver answers.
            Reverse::Listed(name) => name,
            Reverse::Named(name) => {
                route.answered = true;
                name
            }
            Reverse::Unnamed => {
                route.answered = true;
                continue;
            }
            Reverse::Unanswered => {
                route.unanswered += 1;
                continue;
            }
            Reverse::Unasked => continue,
        };

        name_host(ctx, key, &name);
    }

    // Whatever is left waits on a route that never answered: one that has
    // answered is asked until it has nothing left.
    let unasked: usize = routes.iter().map(|(_, route)| route.waiting.len()).sum();
    if unasked > 0 && !ctx.handle.should_stop() {
        info!(
            verbosity = 1,
            "{} not looked up (resolver not answering)",
            counted(unasked as u128, "name", "names")
        );
    }
}

/// Names the hosts a scan found from the hosts file alone, sending nothing.
///
/// For a scan forbidden to ask names of anybody. The hosts file is not a
/// query: reading it sends nothing, and it is where a lab box reached over a
/// VPN gets its name, the same file that scan's targets were resolved from.
/// A box named as a target is found under that name, and the same box found
/// by sweeping its range is found under it too.
pub(crate) fn name_from_hosts_file(ctx: &ScanContext, unheard: Unheard) {
    name_listed(ctx, unheard, &HostsTable::read_system());
}

/// [`name_from_hosts_file`], from a table already read.
fn name_listed(ctx: &ScanContext, unheard: Unheard, hosts: &HostsTable) {
    for key in to_resolve(ctx, unheard) {
        if let Some(name) = hosts.name_of(key.addr()) {
            let name = name.to_owned();
            name_host(ctx, key, &name);
        }
    }
}

/// Gives the host stored under `key` the name a lookup found for it, unless
/// the name only restates the address.
fn name_host(ctx: &ScanContext, key: crate::model::ip::scoped::ScopedIp, name: &str) {
    let name = name.trim_end_matches('.').to_string();
    if restates(&name, key.addr()) {
        info!(
            verbosity = 2,
            "{} was named after itself ({name}), so it has no name",
            key.addr()
        );
        return;
    }

    ctx.write_host(key, |host| {
        host.set_hostname(Some(name));
        true
    });
}

/// The addresses [`resolve_with`] has still to ask one way, and what that
/// way has answered so far.
struct Route {
    waiting: std::collections::VecDeque<crate::model::ip::scoped::ScopedIp>,
    /// Lookups this way has in flight.
    in_flight: usize,
    /// Whether any lookup this way has been answered.
    answered: bool,
    /// How many lookups this way went unanswered.
    unanswered: usize,
}

impl Route {
    /// A way with one address to ask.
    fn holding(key: crate::model::ip::scoped::ScopedIp) -> Self {
        Self {
            waiting: std::collections::VecDeque::from([key]),
            in_flight: 0,
            answered: false,
            unanswered: 0,
        }
    }

    /// Whether this way has an address to ask and may be asked it: until it
    /// has answered once, the lookups it let lie count against the window as
    /// well as those in flight, so the first window is all a silent one is
    /// asked.
    fn is_asked(&self, window: usize) -> bool {
        !self.waiting.is_empty() && (self.answered || self.unanswered + self.in_flight < window)
    }
}

/// Whether `name` is `ip` written out as a label rather than a name for it.
///
/// A resolver that answers a reverse lookup for every address in a range,
/// whether or not anything is there, does it by writing the address into the
/// label: `203.0.113.26` comes back as `203-0-113-26.lan`. Consumer routers do
/// this by default, and cloud providers do it deliberately.
///
/// That is not a name, and accepting it costs more than an empty column. It
/// carries nothing the address does not already carry, and it fills the one slot
/// a real name would take: this engine prefers a unicast answer to an mDNS one,
/// so a synthesised PTR does not merely sit beside the machine's actual name, it
/// keeps the scan from ever recording it.
///
/// The test is decidable, not a guess about shape. An address cannot appear
/// literally in a label, since its own separator is the label separator, so a
/// resolver writing one has to substitute: a dot becomes a dash or an underscore
/// and a colon becomes a dash. Each substitution is undone and the result read
/// back as an address, then compared against the very address the answer was
/// about. A machine genuinely called `10-4-good-buddy` is not an address and
/// keeps its name; one called `203-0-113-26` while answering at some other
/// address keeps its name too, because there the name says something the address
/// does not.
fn restates(name: &str, ip: IpAddr) -> bool {
    address_written_as_a_label(name) == Some(ip)
}

/// The address a label spells, where it spells one.
fn address_written_as_a_label(name: &str) -> Option<IpAddr> {
    let label = name.split('.').next()?;

    // A dot for IPv4 and a colon for IPv6, each in the two spellings a label is
    // allowed to carry. `fe80--1` is `fe80::1` under the second, which is the
    // same substitution applied twice and needs no special case.
    let substituted = [
        label.replace('-', "."),
        label.replace('_', "."),
        label.replace('-', ":"),
    ];

    if let Some(ip) = substituted
        .iter()
        .find_map(|spelling| spelling.parse().ok())
    {
        return Some(ip);
    }

    // The other shape: the address as leading labels of its own, `203.0.113.26`
    // in front of the domain rather than inside one label. Rarer, because it
    // needs the resolver to hand out a name four labels deep, and produced by
    // enough of them to be worth reading.
    let labels: Vec<&str> = name.split('.').collect();
    (2..=labels.len()).find_map(|take| labels[..take].join(".").parse().ok())
}

/// Whether it is worth sending a PTR query for `ip`.
///
/// IPv6 addresses are queried only when they are global unicast, since link-local
/// and other special-purpose addresses will not resolve. Every IPv4 address is
/// queried, private ranges included, except loopback: RFC 6761 section 6.3 has
/// its reverse zone answered on the machine and never sent to a server, so a
/// loopback address has the name the hosts file gives it or none.
fn is_queryable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(ipv6_addr) => ip::is_global_unicast(ipv6_addr),
        IpAddr::V4(ipv4_addr) => !ipv4_addr.is_loopback(),
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
    use crate::model::host::HostStatus;
    use crate::scanner::session::{ScanEvent, ScanSession};
    use crate::transport::probe::{Emission, ProbeSender, SendError};
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc::UnboundedSender;

    /// A reverse lookup names the hosts that answered and leaves the records
    /// nothing was heard from alone, unless the caller asked for every
    /// address listed as a host.
    ///
    /// A scan of one port over a wide range files one such record per silent
    /// address. Named, each would cost the resolver a query about an address
    /// the scan found nothing at: tens of thousands for a /16, where the hosts
    /// it found need one each.
    #[test]
    fn a_reverse_lookup_names_only_the_hosts_that_answered_unless_asked_for_all() {
        let (_session, ctx) = ScanSession::new();
        let at = |last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last));
        ctx.update_host(at(1), |host| host.set_status(HostStatus::Up));
        ctx.update_host(at(2), |_| {});
        ctx.update_host(at(3), |host| {
            host.set_status(HostStatus::Up);
            host.set_hostname(Some("named.example".to_string()));
        });

        let asked = |unheard| -> Vec<IpAddr> {
            let mut asked: Vec<IpAddr> = to_resolve(&ctx, unheard)
                .iter()
                .map(|key| key.addr())
                .collect();
            asked.sort_unstable();
            asked
        };
        assert_eq!(asked(Unheard::Skipped), [at(1)]);
        assert_eq!(asked(Unheard::Named), [at(1), at(2)]);
    }

    /// **Reverse lookups are bounded in flight, and every answer is read.**
    /// A scan listing every address as a host asks one lookup per address, and
    /// all at once they flood the network's one resolver and fill the
    /// process's descriptor table. And a lookup that found no name is one
    /// address without one, never the end of the answers: the ones still
    /// coming name hosts of their own.
    #[tokio::test]
    async fn reverse_lookups_are_bounded_in_flight_and_every_answer_is_read() {
        use std::sync::atomic::AtomicUsize;

        const BOUND: usize = 4;
        let (session, ctx) = ScanSession::new();
        let at = |last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last));
        for last in 1..=40 {
            ctx.update_host(at(last), |host| host.set_status(HostStatus::Up));
        }

        let in_flight = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        resolve_with(
            &ctx,
            Unheard::Skipped,
            BOUND,
            |_| (),
            |ip| {
                let (in_flight, most) = (Arc::clone(&in_flight), Arc::clone(&most));
                async move {
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    most.fetch_max(now, Ordering::SeqCst);
                    let IpAddr::V4(v4) = ip else {
                        return Reverse::Unnamed;
                    };
                    let last = v4.octets()[3];
                    // The unnamed answer first, so an early one ends nothing.
                    let wait = if last % 2 == 0 { 1 } else { 5 };
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    match last % 2 {
                        1 => Reverse::Named(format!("host{last}.example.")),
                        _ => Reverse::Unnamed,
                    }
                }
            },
        )
        .await;

        assert!(
            most.load(Ordering::SeqCst) <= BOUND,
            "{} lookups in flight at once",
            most.load(Ordering::SeqCst)
        );
        let named = (1..=40)
            .filter(|last| {
                session
                    .hosts()
                    .read(at(*last), |host| host.hostname().is_some())
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(named, 20, "every host with a name was named");
    }

    /// **A host with no DNS server configured still names what its hosts
    /// file lists.** A lab VM whose boxes have names only there would
    /// otherwise report every one by address, and the lookups reach no
    /// server, so none is waited on.
    #[tokio::test]
    async fn with_no_dns_server_configured_the_hosts_file_still_names_hosts() {
        let (_session, ctx) = ScanSession::new();
        for last in [1, 2] {
            ctx.update_host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), |host| {
                host.set_status(HostStatus::Up)
            });
        }
        let snapshot = crate::resolve::Resolver::given(Default::default(), || {
            (
                "192.0.2.1 box.example\n".to_string(),
                DnsConfig {
                    global: Err("no nameservers found in config".into()),
                    scoped: Vec::new(),
                },
            )
        })
        .snapshot();

        resolve_from(&ctx, Unheard::Skipped, Arc::new(snapshot)).await;

        let name = |last| {
            ctx.read_host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), |host| {
                host.hostname().map(str::to_owned)
            })
            .flatten()
        };
        assert_eq!(name(1).as_deref(), Some("box.example"));
        assert_eq!(name(2), None);
    }

    /// **Under no name queries, a host the scan found is still named from
    /// the hosts file.** Reading it sends nothing, and a lab box listed there
    /// is the target a VPN user names; found by sweeping its range it would
    /// otherwise be reported by address alone, where named as a target it is
    /// found under its name. A host nothing was heard from is left alone, as
    /// a lookup leaves it.
    #[test]
    fn the_hosts_file_names_found_hosts_without_a_query() {
        let (_session, ctx) = ScanSession::new();
        for last in [1, 2] {
            ctx.update_host(v4(192, 0, 2, last), |host| host.set_status(HostStatus::Up));
        }
        ctx.update_host(v4(192, 0, 2, 3), |_| {});
        let hosts = HostsTable::parse("192.0.2.1 box.example\n192.0.2.3 silent.example\n");

        name_listed(&ctx, Unheard::Skipped, &hosts);

        let name = |last| {
            ctx.read_host(v4(192, 0, 2, last), |host| {
                host.hostname().map(str::to_owned)
            })
            .flatten()
        };
        assert_eq!(name(1).as_deref(), Some("box.example"));
        assert_eq!(name(2), None, "an unlisted host was named");
        assert_eq!(name(3), None, "a host nothing was heard from was named");
    }

    /// **A stopped scan stops looking names up.** The lookups are the tail of
    /// every scan that resolves names, and one stopped there would otherwise
    /// wait out every lookup still to ask, each up to its full retries. The
    /// lookups here never answer, so the only way the call returns is the
    /// stop.
    #[tokio::test]
    async fn a_stopped_scan_stops_looking_names_up() {
        let (session, ctx) = ScanSession::new();
        for last in 1..=4 {
            ctx.update_host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), |host| {
                host.set_status(HostStatus::Up)
            });
        }
        let handle = session.handle().clone();
        let stopper = tokio::spawn(async move {
            tokio::task::yield_now().await;
            handle.abort();
        });

        // Generous, and only so a failure reads as one rather than as a hang.
        tokio::time::timeout(
            Duration::from_secs(60),
            resolve_with(
                &ctx,
                Unheard::Skipped,
                2,
                |_| (),
                |_| std::future::pending::<Reverse>(),
            ),
        )
        .await
        .expect("the stop ended the lookups");
        stopper.await.expect("the stop was asked for");
    }

    /// **A resolver that answers nothing is asked one window and no more.**
    /// Every lookup it lets lie costs its full retries, so asking it about
    /// every host a wide scan found would spend a window of those per
    /// window of hosts. One that has answered anything is asked on.
    #[tokio::test]
    async fn a_resolver_that_answers_nothing_is_asked_one_window() {
        use std::sync::atomic::AtomicUsize;

        const BOUND: usize = 4;
        let asked = |first_answers: bool| {
            let asked = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&asked);
            let (_session, ctx) = ScanSession::new();
            for last in 1..=40 {
                ctx.update_host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), |host| {
                    host.set_status(HostStatus::Up)
                });
            }
            async move {
                resolve_with(
                    &ctx,
                    Unheard::Skipped,
                    BOUND,
                    |_| (),
                    move |_| {
                        let n = counted.fetch_add(1, Ordering::SeqCst);
                        async move {
                            match (first_answers, n) {
                                (true, 0) => Reverse::Unnamed,
                                _ => Reverse::Unanswered,
                            }
                        }
                    },
                )
                .await;
                asked.load(Ordering::SeqCst)
            }
        };

        assert_eq!(asked(false).await, BOUND, "a silent resolver was asked on");
        assert_eq!(asked(true).await, 40, "one that answered was given up on");
    }

    /// **A silent resolver is given up on alone.** A VPN scopes a resolver to
    /// the reverse zone of its own addresses, and that one answers whether or
    /// not the global resolver does; giving up on both when the global one
    /// goes quiet leaves every address under the zone unnamed.
    #[tokio::test]
    async fn a_silent_global_resolver_leaves_a_scoped_zone_asked() {
        use std::sync::atomic::AtomicUsize;

        const BOUND: usize = 4;
        let (_session, ctx) = ScanSession::new();
        // Whichever order the addresses are asked in, one count shared by both
        // resolvers fails one of the two checks below: the scoped zone's
        // answers keep the silent one asked, or the silent one's window of
        // silence stops the scoped zone being asked.
        for last in 1..=20 {
            for network in [[192, 0, 2], [203, 0, 113]] {
                ctx.update_host(v4(network[0], network[1], network[2], last), |host| {
                    host.set_status(HostStatus::Up)
                });
            }
        }
        let scoped = |ip: IpAddr| matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 203);
        let asked_global = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&asked_global);

        resolve_with(&ctx, Unheard::Skipped, BOUND, scoped, move |ip| {
            if !scoped(ip) {
                counted.fetch_add(1, Ordering::SeqCst);
            }
            async move {
                if scoped(ip) {
                    Reverse::Named("box.corp.example.".into())
                } else {
                    Reverse::Unanswered
                }
            }
        })
        .await;

        let named = (1..=20)
            .filter(|&last| {
                ctx.read_host(v4(203, 0, 113, last), |host| host.hostname().is_some())
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(named, 20, "the scoped zone stopped being asked");
        assert_eq!(
            asked_global.load(Ordering::SeqCst),
            BOUND,
            "the silent resolver was asked past its window"
        );
    }

    // -----------------------------------------------------------------------
    // A name that is the address written again
    // -----------------------------------------------------------------------

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Every spelling a resolver reaches for when it has to put an address in a
    /// label, and the address it was answering about.
    #[test]
    fn an_address_written_into_a_label_is_recognised_as_one() {
        let subject = v4(203, 0, 113, 26);

        for name in [
            "203-0-113-26.lan",
            "203-0-113-26.fritz.box",
            "203_0_113_26.lan",
            "203.0.113.26.lan",
            "203-0-113-26",
        ] {
            assert!(
                restates(name, subject),
                "{name} was not read as its address"
            );
        }
    }

    /// IPv6, where the substitution is the same one applied to a colon.
    #[test]
    fn an_ipv6_address_written_into_a_label_is_recognised_too() {
        let subject: IpAddr = "2001:db8::1".parse().expect("an address");
        assert!(restates("2001-db8--1.lan", subject));

        let link_local: IpAddr = "fe80::1".parse().expect("an address");
        assert!(restates("fe80--1.example", link_local));
    }

    /// A name that is a name keeps it, dashes and all.
    ///
    /// The failure this guards against is a filter that reads shape rather than
    /// meaning: plenty of real names carry digits and dashes, and a rule about
    /// how a name *looks* would take them.
    #[test]
    fn a_real_name_is_not_mistaken_for_an_address() {
        let subject = v4(203, 0, 113, 26);

        for name in [
            "epson928262.lan",
            "10-4-good-buddy.lan",
            "gateway.local",
            "MacBook-Pro.local",
            "host-1.example",
            "203-0-113.lan",
        ] {
            assert!(!restates(name, subject), "{name} was taken for an address");
        }
    }

    /// An address that is not *this* address is a name, whatever it looks like.
    ///
    /// The test compares against the address the answer was about rather than
    /// asking whether the label is an address at all. A host at one address
    /// named after another is saying something the address does not, and this
    /// engine has no business deciding it is wrong.
    #[test]
    fn a_label_naming_some_other_address_is_left_alone() {
        assert!(!restates("198-51-100-1.lan", v4(203, 0, 113, 26)));
    }

    /// The point of the whole exercise: a synthesised name never reaches the
    /// map, so the mDNS answer that would otherwise have been passed over is
    /// still the one the host ends up with.
    ///
    /// Through the wire format rather than past it, because the guard is only
    /// worth anything where a real answer arrives.
    #[tokio::test]
    async fn a_synthesised_name_overheard_is_never_recorded() {
        let mut resolver = resolver_asking(vec![
            "127.0.0.1:53".parse().expect("a valid socket address"),
        ]);
        let ip = v4(203, 0, 113, 26);

        resolver.absorb_sniffed_dns(&overheard(ip, "203-0-113-26.lan"));
        assert!(
            !resolver.hostname_map.contains_key(&ip),
            "the address written again was recorded as a name"
        );

        resolver.absorb_sniffed_dns(&overheard(ip, "epson928262.lan"));
        assert_eq!(
            resolver
                .hostname_map
                .get(&ip)
                .map(|named| named.hostname.as_str()),
            Some("epson928262.lan"),
            "a real name overheard for the same address was refused too"
        );
    }

    /// A PTR response for `ip` naming it `name`, as it would arrive off the
    /// wire.
    fn overheard(ip: IpAddr, name: &str) -> Vec<u8> {
        let IpAddr::V4(v4) = ip else {
            unreachable!("this helper writes in-addr.arpa questions")
        };
        let octets = v4.octets();
        let question = format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        );

        crate::protocols::dns::tests::ptr_response(1, &question, Some(name))
    }

    struct Silent;
    impl ProbeSender for Silent {
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

    /// A resolver that would send its queries to `servers`, with no sockets
    /// behind it.
    fn resolver_asking(servers: Vec<SocketAddr>) -> HostnameResolver {
        let (_tx, dns_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
        HostnameResolver::with_transport(
            dns_rx,
            ProbeTransport::from_parts(Box::new(Silent), reply_rx),
            servers,
        )
        .expect("a query target binds")
    }

    /// A resolver holding one name for `ip`, with no sockets behind it.
    fn resolver_holding(ip: IpAddr, hostname: &str) -> HostnameResolver {
        // Never queried. `resolve_hosts` only folds the caches into the store,
        // but the constructor insists on somewhere to send to.
        let mut resolver = resolver_asking(vec![
            "127.0.0.1:53".parse().expect("a valid socket address"),
        ]);
        resolver.hostname_map.insert(
            ip,
            Named {
                hostname: hostname.to_string(),
                heard: Heard::Answered,
            },
        );
        resolver
    }

    /// A DNS *response* about `subject`, built from the query this engine sends
    /// so the message is one a real server could have produced.
    ///
    /// It carries no answer, which is deliberate: a server that has no name for
    /// an address, or declines to look, has still answered in DNS.
    fn dns_response(subject: IpAddr) -> Vec<u8> {
        let mut message = dns::build_ptr_packet(subject, 0x1234);
        message[2] |= 0b1000_0000; // QR: this is a response
        message
    }

    /// One UDP segment as it arrives off the wire, from `port`.
    fn from_port(port: u16, message: Vec<u8>) -> Vec<u8> {
        crate::protocols::craft::Udp::new(port, 40_000)
            .with_payload(message)
            .to_bytes(None)
            .expect("a datagram")
    }

    /// A host that answered a DNS question is a name server, and that is how a
    /// scan which never touches a port concludes it at all.
    ///
    /// On a local segment this is the *usual* way: the machine a scan asks for
    /// names is generally the router it is scanning, and the answer is proof in
    /// DNS's own protocol. Without this, a scan would come back with every
    /// hostname resolved and no idea what had resolved them.
    ///
    /// The second half is the trap on exactly those segments. mDNS shares DNS's
    /// framing and answers on 5353, and nearly every laptop and printer speaks
    /// it, so the identical message from that port must name nobody.
    #[tokio::test]
    async fn a_machine_that_answers_dns_is_a_name_server_and_an_mdns_responder_is_not() {
        let server = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
        let responder = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 60));
        let subject = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

        let (session, ctx) = ScanSession::new();
        for ip in [server, responder] {
            ctx.update_host(ip, |host| host.set_status(HostStatus::Up));
        }

        let mut resolver = resolver_holding(subject, "printer.local");
        resolver.absorb_sniffed(&from_port(DNS_PORT, dns_response(subject)), server);
        resolver.absorb_sniffed(&from_port(MDNS_PORT, dns_response(subject)), responder);
        resolver.resolve_hosts(&ctx);

        assert!(
            session
                .hosts()
                .get(server)
                .expect("the server is a scanned host")
                .network_roles()
                .contains(&NetworkRole::DnsServer),
            "it answered a lookup in front of us"
        );
        assert!(
            session
                .hosts()
                .get(responder)
                .expect("the responder is a scanned host")
                .network_roles()
                .is_empty(),
            "answering mDNS is not serving DNS"
        );
    }

    /// An mDNS record names every address its host answers at, and folding
    /// them into the host is how a scan learns a machine's other addresses. The
    /// ones the scan is forbidden to report are not among what it learns.
    #[tokio::test]
    async fn an_mdns_record_does_not_carry_an_excluded_address_into_a_host() {
        use crate::model::exclusion::Exclusions;

        let found = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 60));
        let excluded = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 61));

        let mut forbidden = crate::model::ip::set::IpSet::new();
        forbidden.insert(excluded);
        let (_session, ctx) = ScanSession::builder()
            .excluding(Exclusions::new(forbidden))
            .build();
        ctx.update_host(found, |host| host.set_status(HostStatus::Up));

        let mut resolver = resolver_asking(vec![
            "127.0.0.1:53".parse().expect("a valid socket address"),
        ]);
        resolver.mdns_cache.insert(
            found,
            mdns::MdnsHost {
                hostname: "tv.local".to_string(),
                ips: [found, excluded].into_iter().collect(),
            },
        );
        resolver.resolve_hosts(&ctx);

        let (hostname, ips) = ctx
            .read_host(found, |host| {
                (host.hostname().map(str::to_owned), host.ips().clone())
            })
            .expect("the host is in the store");
        assert_eq!(
            hostname.as_deref(),
            Some("tv.local"),
            "test premise: the record applied"
        );
        assert!(!ips.contains(&excluded), "{ips:?}");
    }

    /// A device whose IPv4 address the scan may not report is still named at
    /// the addresses it may.
    ///
    /// The excluded address is the forbidden fact, not the name the device
    /// announced beside it. A record is found by any address it names, so the
    /// one the policy keeps out of the store cannot take the name with it, and
    /// the policy still keeps that address off the host the name lands on.
    #[tokio::test]
    async fn a_device_named_at_an_excluded_address_keeps_its_name_at_the_others() {
        use crate::model::exclusion::Exclusions;

        let excluded = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 60));
        let link_local: IpAddr = "fe80::60".parse().expect("literal");

        let mut forbidden = crate::model::ip::set::IpSet::new();
        forbidden.insert(excluded);
        let (_session, ctx) = ScanSession::builder()
            .excluding(Exclusions::new(forbidden))
            .build();
        ctx.update_host(link_local, |host| host.set_status(HostStatus::Up));

        let mut resolver = resolver_asking(vec![
            "127.0.0.1:53".parse().expect("a valid socket address"),
        ]);
        resolver.file_mdns(mdns::MdnsHost {
            hostname: "tv.local".to_string(),
            ips: [excluded, link_local].into_iter().collect(),
        });
        resolver.resolve_hosts(&ctx);

        let (hostname, ips) = ctx
            .read_host(link_local, |host| {
                (host.hostname().map(str::to_owned), host.ips().clone())
            })
            .expect("the host is in the store");
        assert_eq!(hostname.as_deref(), Some("tv.local"));
        assert!(!ips.contains(&excluded), "{ips:?}");
    }

    /// A name unicast DNS gave a host is preferred to one its mDNS responder
    /// announced, whichever of the host's addresses each was found at.
    ///
    /// A record is found at every address it names, so it can turn up at an
    /// address that sorts before the one a resolver answered about. Read
    /// address by address in a single pass, the order the addresses sort in
    /// would decide which name the host keeps.
    #[tokio::test]
    async fn a_resolved_name_is_preferred_to_an_announced_one_at_any_address() {
        let announced_at = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 61));
        let resolved_at = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 62));

        let (_session, ctx) = ScanSession::new();
        ctx.update_host(announced_at, |host| {
            host.add_ip(resolved_at);
            host.set_status(HostStatus::Up);
        });

        let mut resolver = resolver_holding(resolved_at, "tv.example");
        resolver.file_mdns(mdns::MdnsHost {
            hostname: "tv.local".to_string(),
            ips: [announced_at].into_iter().collect(),
        });
        resolver.resolve_hosts(&ctx);

        let hostname = ctx
            .read_host(announced_at, |host| host.hostname().map(str::to_owned))
            .expect("the host is in the store");
        assert_eq!(hostname.as_deref(), Some("tv.example"));
    }

    /// The reply to our own reverse query proves the same thing, and only from
    /// a resolver we actually asked.
    ///
    /// The second half is what the socket needs: it is open to the whole
    /// network, so anything can send a DNS-shaped datagram to it, and a scan
    /// that named the sender a name server would be reporting whoever spoke
    /// last.
    #[tokio::test]
    async fn only_a_resolver_the_scan_asked_is_named_by_its_answer() {
        let asked = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
        let stranger = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
        let subject = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

        let (session, ctx) = ScanSession::new();
        for ip in [asked, stranger] {
            ctx.update_host(ip, |host| host.set_status(HostStatus::Up));
        }

        let mut resolver = resolver_asking(vec![SocketAddr::new(asked, DNS_PORT)]);
        resolver.absorb_reply(&dns_response(subject), SocketAddr::new(asked, DNS_PORT));
        resolver.absorb_reply(&dns_response(subject), SocketAddr::new(stranger, DNS_PORT));
        resolver.resolve_hosts(&ctx);

        let hosts = session.hosts();
        assert!(
            hosts
                .get(asked)
                .expect("scanned")
                .network_roles()
                .contains(&NetworkRole::DnsServer)
        );
        assert!(
            hosts
                .get(stranger)
                .expect("scanned")
                .network_roles()
                .is_empty(),
            "nothing was asked of it, so its datagram answers nothing"
        );
    }

    /// A hostname is a finding like any other, so attaching one has to announce
    /// itself. Writing straight into the map would bypass
    /// [`ScanContext::write_host`], which owns the lock-then-announce ordering,
    /// so a consumer watching the event stream would see a host appear without
    /// a name and never hear that it had gained one.
    #[tokio::test]
    async fn attaching_a_hostname_announces_it_like_any_other_finding() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let (mut session, ctx) = ScanSession::new();

        ctx.update_host(ip, |host| host.set_status(HostStatus::Up));
        while session.events().try_recv().is_some() {}

        resolver_holding(ip, "printer.local").resolve_hosts(&ctx);

        assert_eq!(
            session
                .hosts()
                .get(ip)
                .and_then(|h| h.hostname().map(String::from)),
            Some("printer.local".to_string())
        );
        assert!(
            matches!(session.events().try_recv(), Some(ScanEvent::HostUpdated(at)) if at.addr() == ip),
            "the name reached the store without reaching the stream"
        );
    }

    /// A resolver with nothing for a host must not announce a change it did not
    /// make, or every scan ends with one spurious event per host.
    #[tokio::test]
    async fn a_host_the_resolver_has_nothing_for_is_left_alone() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        let (mut session, ctx) = ScanSession::new();

        ctx.update_host(ip, |host| host.set_status(HostStatus::Up));
        while session.events().try_recv().is_some() {}

        resolver_holding(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)), "other").resolve_hosts(&ctx);

        assert!(
            session
                .hosts()
                .get(ip)
                .and_then(|h| h.hostname().map(String::from))
                .is_none()
        );
        assert!(session.events().try_recv().is_none(), "nothing changed");
    }

    /// A PTR response for `subject` carrying `name`, which the fixtures above
    /// have no way to build: `dns_response` deliberately answers nothing.
    fn named_response(subject: IpAddr, name: &str) -> Vec<u8> {
        answer(&dns::build_ptr_packet(subject, 0x1234), name)
    }

    /// `query` answered with `name`, as a name server answers it.
    fn answer(query: &[u8], name: &str) -> Vec<u8> {
        let mut message = query.to_vec();
        message[2] |= 0b1000_0000; // QR: a response
        message[6..8].copy_from_slice(&1u16.to_be_bytes()); // one answer

        message.extend_from_slice(&[0xC0, 0x0C]); // name: a pointer to the question
        message.extend_from_slice(&12u16.to_be_bytes()); // PTR
        message.extend_from_slice(&1u16.to_be_bytes()); // IN
        message.extend_from_slice(&300u32.to_be_bytes()); // TTL

        let mut rdata = Vec::new();
        for label in name.split('.') {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        message.extend_from_slice(&rdata);
        message
    }

    /// A resolver sending its queries to `server`, fed by the sender returned.
    fn resolver_fed(server: SocketAddr) -> (UnboundedSender<IpAddr>, HostnameResolver) {
        let (tx, dns_rx) = tokio::sync::mpsc::unbounded_channel();
        // Closed at once: nothing is sniffed, and the resolver stops listening.
        let (_, reply_rx) = tokio::sync::mpsc::channel(1);
        let resolver = HostnameResolver::with_transport(
            dns_rx,
            ProbeTransport::from_parts(Box::new(Silent), reply_rx),
            vec![server],
        )
        .expect("a query target binds");
        (tx, resolver)
    }

    /// A resolver asking and naming by `routes`, fed by the sender returned.
    fn resolver_routed(routes: Routes) -> (UnboundedSender<IpAddr>, HostnameResolver) {
        let (tx, dns_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_, reply_rx) = tokio::sync::mpsc::channel(1);
        let resolver = HostnameResolver::with_routes(
            dns_rx,
            ProbeTransport::from_parts(Box::new(Silent), reply_rx),
            routes,
        )
        .expect("the resolver builds");
        (tx, resolver)
    }

    /// The reverse names of the queries `server` holds unread.
    fn questions_held(server: &UdpSocket) -> Vec<String> {
        let mut buf = [0u8; MAX_DNS_DATAGRAM];
        std::iter::from_fn(|| {
            let (len, _) = server.try_recv_from(&mut buf).ok()?;
            Some(buf[..len].to_vec())
        })
        .filter_map(|datagram| {
            let message = hickory_resolver::proto::op::Message::from_vec(&datagram).ok()?;
            Some(message.queries.first()?.name().to_ascii())
        })
        .collect()
    }

    /// **An address under a scoped reverse zone is asked of that zone's
    /// servers alone, and one under a zone none of whose servers can be
    /// reached is asked of nobody.** A VPN that serves the reverse zone of its
    /// own addresses installs a resolver scoped to it; the same PTR sent to
    /// the global resolvers and gateways fails there and tells them which
    /// private address the scan found.
    #[tokio::test]
    async fn an_address_under_a_scoped_reverse_zone_is_asked_of_its_servers_alone() {
        let (global, global_at) = silent_server().await;
        let (scoped, scoped_at) = silent_server().await;
        let routes = Routes {
            hosts: HostsTable::default(),
            servers: vec![(global_at, None), (scoped_at, Some(0))],
            scopes: vec![
                ReverseScope {
                    domain: "100.51.198.in-addr.arpa".into(),
                    unasked: None,
                    said: false,
                },
                ReverseScope {
                    domain: "2.0.192.in-addr.arpa".into(),
                    unasked: Some("utun9 not found".into()),
                    said: false,
                },
            ],
        };
        let (tx, resolver) = resolver_routed(routes);
        for ip in [v4(198, 51, 100, 7), v4(203, 0, 113, 7), v4(192, 0, 2, 7)] {
            tx.send(ip).expect("the resolver is listening");
        }
        drop(tx);

        tokio::time::timeout(Duration::from_secs(60), resolver.run())
            .await
            .expect("the resolver finishes");

        assert_eq!(questions_held(&scoped), vec!["7.100.51.198.in-addr.arpa."]);
        assert_eq!(questions_held(&global), vec!["7.113.0.203.in-addr.arpa."]);
    }

    /// **An address the hosts file lists is named from it and asked of
    /// nobody, and a loopback address it does not list is not asked either.**
    /// The file is authoritative for what it lists, as it is forward, and a
    /// loopback address's reverse zone never leaves the machine (RFC 6761).
    #[tokio::test]
    async fn an_address_the_hosts_file_lists_is_named_without_a_query() {
        let (server, at) = silent_server().await;
        let routes = Routes {
            hosts: HostsTable::parse("198.51.100.23 box.example\n"),
            servers: vec![(at, None)],
            scopes: Vec::new(),
        };
        let (tx, resolver) = resolver_routed(routes);
        for ip in [v4(198, 51, 100, 23), v4(127, 0, 0, 9)] {
            tx.send(ip).expect("the resolver is listening");
        }
        drop(tx);

        let resolver = tokio::time::timeout(Duration::from_secs(60), resolver.run())
            .await
            .expect("the resolver finishes");

        assert_eq!(questions_held(&server), Vec::<String>::new());
        let named = resolver.hostname_map.get(&v4(198, 51, 100, 23));
        assert_eq!(
            named.map(|n| (n.hostname.as_str(), n.heard)),
            Some(("box.example", Heard::Listed))
        );
        assert!(!resolver.hostname_map.contains_key(&v4(127, 0, 0, 9)));
    }

    /// A name server on loopback that answers nothing, and where to reach it.
    async fn silent_server() -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a loopback socket binds");
        let at = socket.local_addr().expect("a bound socket has an address");
        (socket, at)
    }

    /// How many queries `server` holds unread.
    fn queries_held(server: &UdpSocket) -> usize {
        let mut buf = [0u8; MAX_DNS_DATAGRAM];
        std::iter::from_fn(|| server.try_recv_from(&mut buf).ok()).count()
    }

    /// The privileged resolver asks about as many addresses at once as the
    /// unprivileged path does and no more, however many the scan hands it.
    /// Every host a sweep finds is handed over as it is found, so a wide range
    /// would otherwise put a query per host in front of the one resolver the
    /// network shares, all at once.
    #[tokio::test]
    async fn the_privileged_resolver_asks_about_a_bounded_number_of_addresses_at_once() {
        let (server, at) = silent_server().await;
        let (tx, resolver) = resolver_fed(at);
        for last in 1..=100 {
            tx.send(v4(198, 51, 100, last))
                .expect("the resolver is listening");
        }
        let running = tokio::spawn(resolver.run());

        let mut buf = [0u8; MAX_DNS_DATAGRAM];
        for _ in 0..REVERSE_LOOKUPS_IN_FLIGHT {
            tokio::time::timeout(Duration::from_secs(30), server.recv_from(&mut buf))
                .await
                .expect("the first queries arrive")
                .expect("a query reads");
        }
        // Long enough for every query sent at once to have arrived, and far
        // inside the patience that would free a place.
        tokio::time::sleep(QUERY_PATIENCE / 10).await;
        assert_eq!(
            queries_held(&server),
            0,
            "more than {REVERSE_LOOKUPS_IN_FLIGHT} addresses were asked about at once"
        );

        drop(tx);
        tokio::time::timeout(Duration::from_secs(60), running)
            .await
            .expect("the resolver finishes")
            .expect("the resolver does not panic");
    }

    /// A resolver that answers nothing is asked one window of queries and then
    /// no more, and the scan's end waits on it no longer than the reply grace.
    /// A host configured with a second resolver that is not there would
    /// otherwise hold every address behind it in turn.
    #[tokio::test]
    async fn a_resolver_that_answers_nothing_is_asked_one_window_and_no_more() {
        let (server, at) = silent_server().await;
        let (tx, resolver) = resolver_fed(at);
        for last in 1..=100 {
            tx.send(v4(198, 51, 100, last))
                .expect("the resolver is listening");
        }
        drop(tx);

        tokio::time::timeout(Duration::from_secs(60), resolver.run())
            .await
            .expect("the resolver finishes");

        assert_eq!(queries_held(&server), REVERSE_LOOKUPS_IN_FLIGHT);
    }

    /// Every address waiting behind the bound is still asked about, and each
    /// answer names its own: a bound that let the addresses past the first
    /// window go would name thirty-two hosts of any scan.
    #[tokio::test]
    async fn every_address_behind_the_bound_is_asked_and_named() {
        let server = Arc::new(silent_server().await.0);
        let at = server.local_addr().expect("a bound socket has an address");
        let answering = Arc::clone(&server);
        let answerer = tokio::spawn(async move {
            let mut buf = [0u8; MAX_DNS_DATAGRAM];
            loop {
                let (len, from) = answering.recv_from(&mut buf).await.expect("a query reads");
                let reply = answer(&buf[..len], "host.example.com");
                answering
                    .send_to(&reply, from)
                    .await
                    .expect("a reply sends");
            }
        });
        let (tx, resolver) = resolver_fed(at);
        for last in 1..=100 {
            tx.send(v4(198, 51, 100, last))
                .expect("the resolver is listening");
        }
        drop(tx);

        let resolver = tokio::time::timeout(Duration::from_secs(60), resolver.run())
            .await
            .expect("the resolver finishes");
        answerer.abort();

        assert_eq!(resolver.hostname_map.len(), 100);
    }

    /// **An overheard name does not displace one a resolver answered for.**
    ///
    /// The sniffed path is unauthenticated by design and says so. What it may
    /// not do is outrank the path that checked the source, the transaction ID
    /// and the question - which a plain `insert` would let it do, in either
    /// order and without a word, because `insert` reports only the absence it
    /// replaced.
    #[tokio::test]
    async fn an_overheard_name_does_not_displace_a_resolved_one() {
        let ip = v4(203, 0, 113, 40);
        let mut resolver = resolver_holding(ip, "resolver-confirmed.example.com");

        resolver.absorb_sniffed(
            &from_port(DNS_PORT, named_response(ip, "attacker-chosen.example.com")),
            v4(198, 51, 100, 99),
        );

        assert_eq!(
            resolver
                .hostname_map
                .get(&ip)
                .map(|named| named.hostname.as_str()),
            Some("resolver-confirmed.example.com"),
            "a datagram off the wire outranked a resolver this scan asked"
        );
    }

    /// **Nor does it keep its place by arriving first.**
    ///
    /// The other order, and the one an attacker chooses: a forged answer sprayed
    /// across the target range as a scan starts reaches the capture before the
    /// resolver it imitates has replied. Kept for having arrived, it would block
    /// the resolver's name for good.
    #[tokio::test]
    async fn an_overheard_name_that_arrives_first_gives_way_to_the_resolver() {
        let ip = v4(203, 0, 113, 42);
        let server: SocketAddr = "127.0.0.1:53".parse().expect("a valid socket address");
        let (session, ctx) = ScanSession::new();
        ctx.update_host(ip, |host| host.set_status(HostStatus::Up));

        let mut resolver = resolver_asking(vec![server]);
        // The query this scan sent about `ip`, which `named_response` answers.
        resolver.dns_map.insert(0x1234, Query { ip, target: 0 });

        resolver.absorb_sniffed(
            &from_port(DNS_PORT, named_response(ip, "attacker-chosen.example.com")),
            v4(198, 51, 100, 99),
        );
        resolver.absorb_reply(
            &named_response(ip, "resolver-confirmed.example.com"),
            server,
        );
        resolver.resolve_hosts(&ctx);

        assert_eq!(
            session
                .hosts()
                .get(ip)
                .and_then(|host| host.hostname().map(str::to_owned))
                .as_deref(),
            Some("resolver-confirmed.example.com"),
            "a datagram that merely arrived first outranked the resolver this scan asked"
        );
    }

    /// Between two resolvers this scan asked, the first answer stands. Both
    /// passed the same checks, so neither outranks the other, and keeping the
    /// first is what keeps the name from depending on which reply the network
    /// delivered last.
    #[tokio::test]
    async fn between_two_resolvers_asked_the_first_answer_stands() {
        let ip = v4(203, 0, 113, 43);
        let first: SocketAddr = "127.0.0.1:53".parse().expect("a valid socket address");
        let second: SocketAddr = "127.0.0.2:53".parse().expect("a valid socket address");
        let mut resolver = resolver_asking(vec![first, second]);

        for (target, (server, name)) in
            [(first, "first.example.com"), (second, "second.example.com")]
                .into_iter()
                .enumerate()
        {
            // Each resolver was asked on its own ID; `named_response` answers one.
            resolver.dns_map.insert(0x1234, Query { ip, target });
            resolver.absorb_reply(&named_response(ip, name), server);
        }

        assert_eq!(
            resolver
                .hostname_map
                .get(&ip)
                .map(|named| named.hostname.as_str()),
            Some("first.example.com")
        );
    }

    /// And it still fills a gap, which is the whole reason the path exists.
    #[tokio::test]
    async fn an_overheard_name_still_names_an_address_nothing_else_has() {
        let ip = v4(203, 0, 113, 41);
        let mut resolver = resolver_asking(vec![
            "127.0.0.1:53".parse().expect("a valid socket address"),
        ]);

        resolver.absorb_sniffed(
            &from_port(DNS_PORT, named_response(ip, "overheard.example.com")),
            v4(198, 51, 100, 99),
        );

        assert_eq!(
            resolver
                .hostname_map
                .get(&ip)
                .map(|named| named.hostname.as_str()),
            Some("overheard.example.com")
        );
    }
}
