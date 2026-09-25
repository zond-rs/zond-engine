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
//! sniff, it simply issues reverse lookups through the system resolver for every
//! host that still lacks a name.
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
use hickory_resolver::system_conf::read_system_conf;
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
use crate::scanner::session::ScanContext;
use crate::{counted, info, model::ip, warn};
use pnet_packet::{Packet, udp::UdpPacket};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::Instant;

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
    /// Every resolver each reverse query goes to, with the socket to send it on.
    query_targets: Vec<QueryTarget>,
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
    /// Either the host is configured with none, or every socket that would
    /// carry a query refused to bind. Each refusal is warned about as it
    /// happens; this is what is left when none succeeded.
    #[error("no reachable DNS server to send reverse queries to")]
    NoServer,

    /// The capture the sniffing half reads through could not be opened.
    #[error("the resolver's receive path could not be opened: {0}")]
    Transport(#[from] TransportError),
}

impl HostnameResolver {
    /// Builds a resolver that reads IPs to resolve from `dns_rx`.
    ///
    /// It works out which resolvers can answer for the hosts being scanned
    /// (`dns_server_candidates`), binds a query socket for each address family
    /// they span, and opens the raw receiver used to sniff DNS and mDNS traffic.
    pub fn new(dns_rx: UnboundedReceiver<IpAddr>) -> Result<Self, ResolverError> {
        let dns_servers = dns_server_candidates();
        let transport = ProbeTransport::open_receiver(ProbeKind::UdpResolve)?;
        Self::with_transport(dns_rx, transport, dns_servers)
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
    pub fn with_transport(
        dns_rx: UnboundedReceiver<IpAddr>,
        transport: ProbeTransport,
        dns_servers: Vec<SocketAddr>,
    ) -> Result<Self, ResolverError> {
        let query_targets = bind_query_targets(&dns_servers)?;

        Ok(Self {
            transport,
            query_targets,
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

    /// Puts `ip` in line to be asked about, unless it is an address no reverse
    /// lookup can answer for or one already asked about.
    fn enqueue(&mut self, ip: IpAddr) {
        if is_queryable(&ip) && self.queried.insert(ip) {
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

    /// Sends a reverse (PTR) query for `ip` to every resolver still asked and
    /// records each transaction ID, so the matching reply can later be tied back
    /// to this IP. Returns the IDs, one per resolver reached.
    ///
    /// Every resolver is asked rather than the first that answers, because a
    /// negative answer is not evidence that the name does not exist: a resolver
    /// that declines to serve a reverse zone (see [`dns_server_candidates`])
    /// answers exactly as fast, and exactly as confidently, as one that has
    /// looked and found nothing.
    async fn send_dns_query(&mut self, ip: &IpAddr) -> std::io::Result<Vec<TransID>> {
        let mut sent = Vec::with_capacity(self.query_targets.len());
        let mut last_error = None;

        for (index, target) in self.query_targets.iter().enumerate() {
            if !target.is_asked() {
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

        if sent.is_empty() {
            return Err(last_error.unwrap_or_else(|| {
                std::io::Error::other("no resolver to send a reverse query to")
            }));
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
        let Some(asked) = self.query_targets.iter().position(|t| t.server == from) else {
            return;
        };

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
        self.query_targets[asked].answered = true;

        let Some(Query { ip, target }) = self.dns_map.get(&response.id).copied() else {
            return;
        };
        if target != asked || response.subject != Some(ip) {
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
                Entry::Occupied(slot) if slot.get().heard == Heard::Answered => info!(
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
/// server with the socket that can reach it.
///
/// A family whose socket will not bind - a host with IPv6 disabled, say - loses
/// its servers rather than taking the whole resolver down with it. Only having
/// no reachable server at all is fatal, since there is then nothing to ask.
fn bind_query_targets(servers: &[SocketAddr]) -> Result<Vec<QueryTarget>, ResolverError> {
    let v4 = bind_family(servers, SocketAddr::is_ipv4, "0.0.0.0:0");
    let v6 = bind_family(servers, SocketAddr::is_ipv6, "[::]:0");

    let targets: Vec<QueryTarget> = servers
        .iter()
        .filter_map(|server| {
            let socket = if server.is_ipv4() { &v4 } else { &v6 };
            Some(QueryTarget {
                server: *server,
                socket: Arc::clone(socket.as_ref()?),
                answered: false,
                unanswered: 0,
            })
        })
        .collect();

    if targets.is_empty() {
        return Err(ResolverError::NoServer);
    }

    info!(
        verbosity = 1,
        "reverse queries go to {}",
        targets
            .iter()
            .map(|t| t.server.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    Ok(targets)
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

/// Every resolver a reverse query is worth sending to: the ones the host is
/// configured with, then each interface's default gateway.
///
/// The configured resolvers are not enough on their own. A LAN scan asks about
/// private addresses, and RFC 6303 has a general-purpose resolver answer for
/// those reverse zones itself rather than forward them - so a VPN's resolver, or
/// any public one, returns NXDOMAIN for every host on the link no matter what
/// names the local network actually has. The gateway is added because on a home
/// or office LAN it is the DHCP server, and so the one host that can map a lease
/// back to a name.
///
/// Gateways are taken per interface rather than from the default route. With a
/// VPN up the default route belongs to the tunnel, while the LAN being scanned
/// hangs off a gateway that no route to the internet passes through - which is
/// exactly the case where the configured resolver cannot help.
fn dns_server_candidates() -> Vec<SocketAddr> {
    let mut servers = Vec::new();

    match read_system_conf() {
        Ok((config, _options)) => {
            for name_server in config.name_servers() {
                if let Some(port) = udp_port(name_server) {
                    push_unique(&mut servers, SocketAddr::new(name_server.ip, port));
                }
            }
        }
        Err(e) => warn!("could not read the system resolver configuration: {e}"),
    }

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
fn push_unique(servers: &mut Vec<SocketAddr>, server: SocketAddr) {
    if !servers.contains(&server) {
        servers.push(server);
    }
}

/// Active-only reverse resolution for the unprivileged scan path.
///
/// Without raw sockets there is nothing to sniff, so this issues a reverse
/// lookup through the system resolver for every host that answered and still
/// lacks a hostname. The lookups run concurrently, at most thirty-two at a
/// time so a wide range floods neither the resolver nor the descriptor table,
/// and each answer is written back through [`ScanContext::write_host`] so it
/// announces itself like any other finding. Any failure to build the resolver leaves the store untouched,
/// since a scan without hostnames is still a useful scan.
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
    ctx.host_addresses()
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
pub(crate) async fn resolve(ctx: &ScanContext, unheard: Unheard) {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::proto::rr::RData;

    let Ok(builder) = TokioResolver::builder_tokio() else {
        return;
    };
    let Ok(resolver) = builder.build() else {
        return;
    };

    resolve_with(ctx, unheard, REVERSE_LOOKUPS_IN_FLIGHT, move |ip| {
        let resolver = resolver.clone();
        async move {
            let lookup = resolver.reverse_lookup(ip).await.ok()?;
            lookup.answers().iter().find_map(|r| match &r.data {
                RData::PTR(ptr) => Some(ptr.to_string()),
                _ => None,
            })
        }
    })
    .await;
}

/// [`resolve`], asking `lookup` for each address's name, at most `in_flight`
/// at a time.
///
/// Every lookup's answer is read, whatever order they finish in and whichever
/// of them found nothing: an address with no name says nothing about the next.
async fn resolve_with<F, Fut>(ctx: &ScanContext, unheard: Unheard, in_flight: usize, lookup: F)
where
    F: Fn(IpAddr) -> Fut,
    Fut: Future<Output = Option<String>> + Send + 'static,
{
    let mut pending = to_resolve(ctx, unheard).into_iter();
    let mut set = tokio::task::JoinSet::new();

    loop {
        while set.len() < in_flight.max(1)
            && let Some(key) = pending.next()
        {
            // The query takes the address; the key comes back with the answer,
            // so the write below lands on the entry that was read.
            let asked = lookup(key.addr());
            set.spawn(async move { (key, asked.await) });
        }
        let Some(joined) = set.join_next().await else {
            break;
        };
        let Ok((key, Some(name))) = joined else {
            continue;
        };

        let name = name.trim_end_matches('.').to_string();
        if restates(&name, key.addr()) {
            info!(
                verbosity = 2,
                "{} was named after itself ({name}), so it has no name",
                key.addr()
            );
            continue;
        }

        ctx.write_host(key, |host| {
            host.set_hostname(Some(name));
            true
        });
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
/// queried, private ranges and localhost included.
fn is_queryable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(ipv6_addr) => ip::is_global_unicast(ipv6_addr),
        IpAddr::V4(_ipv4_addr) => true,
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
        resolve_with(&ctx, Unheard::Skipped, BOUND, |ip| {
            let (in_flight, most) = (Arc::clone(&in_flight), Arc::clone(&most));
            async move {
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                let IpAddr::V4(v4) = ip else { return None };
                let last = v4.octets()[3];
                // The unnamed answer first, so an early one ends nothing.
                let wait = if last % 2 == 0 { 1 } else { 5 };
                tokio::time::sleep(Duration::from_millis(wait)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                (last % 2 == 1).then(|| format!("host{last}.example."))
            }
        })
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
