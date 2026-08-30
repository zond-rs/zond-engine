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
//! active at once. It sends reverse DNS (PTR) queries for each IP handed to it
//! and, in parallel, sniffs raw UDP traffic for DNS (port 53) and mDNS (port
//! 5353) responses that other activity on the network happens to surface.
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
//! ## What answering proves
//!
//! Both paths above read DNS *responses*, and a machine that answers a DNS
//! question is a name server — [`NetworkRole::DnsServer`], concluded from the
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
//! mDNS is deliberately not counted. It shares DNS's framing and answers on
//! 5353, and nearly every laptop and printer on a segment responds to it.

use hickory_resolver::config::ProtocolConfig;
use hickory_resolver::system_conf::read_system_conf;
use std::net::SocketAddr;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

use crate::model::host::NetworkRole;
use crate::protocols::{
    dns,
    mdns::{self, MdnsHost},
};
use crate::scanner::session::ScanContext;
use crate::{error, info, model::ip, warn};
use anyhow::Context;
use pnet_packet::{Packet, udp::UdpPacket};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::transport::probe::{ProbeKind, ProbeTransport};

const DNS_PORT: u16 = 53;
use crate::protocols::mdns::PORT as MDNS_PORT;

/// Largest reply worth reading off the query socket. A PTR answer is tiny, but
/// EDNS lets a server return up to this much and a truncated read would be
/// unparseable rather than merely incomplete.
const MAX_DNS_DATAGRAM: usize = 4096;

/// How long the resolver keeps listening after the last IP has been queried, so
/// replies still in flight are not thrown away with the scan that asked for them.
const REPLY_GRACE: Duration = Duration::from_millis(250);

type Hostname = String;
type TransID = u16;

/// One resolver a reverse query is sent to, paired with the socket that can
/// reach it. The pairing is fixed at construction so the send path never has to
/// ask which address family a server belongs to.
struct QueryTarget {
    server: SocketAddr,
    socket: Arc<UdpSocket>,
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
    /// back to the IP it was asked about.
    dns_map: HashMap<TransID, IpAddr>,
    /// IPs already queried, so a host reported by more than one scanning strategy
    /// is asked about once rather than once per report.
    queried: HashSet<IpAddr>,
    /// mDNS records collected from sniffed traffic, keyed by IP.
    mdns_cache: HashMap<IpAddr, MdnsHost>,
    /// Hostnames resolved so far, keyed by IP.
    hostname_map: HashMap<IpAddr, Hostname>,
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

impl HostnameResolver {
    /// Builds a resolver that reads IPs to resolve from `dns_rx`.
    ///
    /// It works out which resolvers can answer for the hosts being scanned
    /// (`dns_server_candidates`), binds a query socket for each address family
    /// they span, and opens the raw receiver used to sniff DNS and mDNS traffic.
    pub fn new(dns_rx: UnboundedReceiver<IpAddr>) -> anyhow::Result<Self> {
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
    ) -> anyhow::Result<Self> {
        let query_targets = bind_query_targets(&dns_servers)?;

        Ok(Self {
            transport,
            query_targets,
            dns_map: HashMap::new(),
            queried: HashSet::new(),
            mdns_cache: HashMap::new(),
            hostname_map: HashMap::new(),
            name_servers: HashSet::new(),
            dns_rx,
            id_counter: AtomicU16::new(0),
        })
    }

    /// Runs the resolver's event loop until the IP stream closes.
    ///
    /// On each turn it does one of three things: send PTR queries for a newly
    /// arrived IP, read a reply to a query it sent, or absorb a DNS or mDNS packet
    /// sniffed off the wire. Once `dns_rx` closes, it waits `REPLY_GRACE` for any
    /// PTR queries still in flight before returning itself, so the caller can hand
    /// the collected names to [`resolve_hosts`](Self::resolve_hosts).
    pub async fn run(mut self) -> Self {
        let (v4, v6) = self.reply_sockets();
        // Whether the capture still has anything to give. A closed stream is
        // ready forever, so its arm has to be switched off rather than polled:
        // left enabled it would spin the loop instead of waiting in it, and end
        // the reply window the moment it was entered.
        let mut sniffing = true;

        loop {
            tokio::select! {
                res = self.dns_rx.recv() => {
                    match res {
                        Some(ip) => self.query(ip).await,
                        None => break,
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
            }
        }

        // The IP stream has closed, but replies to the last queries may still be
        // arriving. Give them a short window to land before giving up on them.
        if !self.dns_map.is_empty() {
            let _ = tokio::time::timeout(REPLY_GRACE, async {
                while !self.dns_map.is_empty() {
                    tokio::select! {
                        (payload, from) = recv_reply(&v4) => self.absorb_reply(&payload, from),
                        (payload, from) = recv_reply(&v6) => self.absorb_reply(&payload, from),
                        pkt = self.transport.rx.recv(), if sniffing => {
                            match pkt {
                                Some(reply) => self.absorb_sniffed(&reply.bytes, reply.source),
                                None => sniffing = false,
                            }
                        }
                    }
                }
            })
            .await;
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

    /// Queries every configured resolver about `ip`, unless it is an address no
    /// reverse lookup can answer for or one already asked about.
    async fn query(&mut self, ip: IpAddr) {
        if !is_queryable(&ip) || !self.queried.insert(ip) {
            return;
        }

        match self.send_dns_query(&ip).await {
            Ok(count) => info!(
                outgoing,
                verbosity = 1,
                "reverse query for {ip} sent to {count} resolver(s)"
            ),
            Err(e) => error!("reverse query for {ip} failed: {e}"),
        }
    }

    /// Sends a reverse (PTR) query for `ip` to every configured resolver and
    /// records each transaction ID, so the matching reply can later be tied back
    /// to this IP. Returns how many resolvers were reached.
    ///
    /// Every resolver is asked rather than the first that answers, because a
    /// negative answer is not evidence that the name does not exist: a resolver
    /// that declines to serve a reverse zone (see [`dns_server_candidates`])
    /// answers exactly as fast, and exactly as confidently, as one that has
    /// looked and found nothing.
    async fn send_dns_query(&mut self, ip: &IpAddr) -> anyhow::Result<usize> {
        let mut sent = Vec::with_capacity(self.query_targets.len());
        let mut last_error = None;

        for target in &self.query_targets {
            let id = self.get_next_trans_id();
            match dns::build_ptr_packet(ip, id) {
                Ok(packet) => match target.socket.send_to(&packet, target.server).await {
                    Ok(_) => sent.push(id),
                    Err(e) => last_error = Some(anyhow::Error::from(e).context(target.server)),
                },
                Err(e) => last_error = Some(e),
            }
        }

        if sent.is_empty() {
            return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no resolver to query")));
        }

        for id in sent.iter().copied() {
            self.dns_map.insert(id, *ip);
        }

        Ok(sent.len())
    }

    /// Handles a reply that arrived on a query socket.
    ///
    /// A reply counts only when it comes from a resolver that was asked, carries
    /// a transaction ID still outstanding, *and* answers the question that ID was
    /// spent on. All three have to agree: the ID is a 16-bit counter and the
    /// socket is open to the whole network, so the question name is what makes a
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

        let Some(ip) = self.dns_map.get(&response.id).copied() else {
            return;
        };
        if response.subject != Some(ip) {
            return;
        }

        // The question has been answered, one way or the other; the other
        // resolvers asked about this IP are still outstanding on their own IDs.
        self.dns_map.remove(&response.id);

        match response.hostname {
            // A name that is the address written again is declined here rather
            // than filtered later: recorded, it would keep the mDNS answer below
            // from ever being asked for. See `restates`.
            Some(hostname) if restates(&hostname, ip) => info!(
                verbosity = 2,
                "{from} named {ip} after itself ({hostname}), so it has no name"
            ),
            Some(hostname) => {
                info!(
                    incoming,
                    verbosity = 1,
                    "{from} resolved {ip} to {hostname}"
                );
                self.hostname_map.entry(ip).or_insert(hostname);
            }
            None => info!(verbosity = 2, "{from} has no name for {ip}"),
        }
    }

    /// Routes a sniffed UDP segment to the DNS or mDNS handler by its source
    /// port, ignoring anything from another port.
    ///
    /// Nothing here is reported as a failure. Everything the capture yields is
    /// unsolicited third-party traffic - the host's own browsing, other
    /// machines' service discovery - so a segment that will not parse, or that
    /// concerns no address, is simply not ours. Logging each one turned ordinary
    /// background traffic into a wall of scan errors.
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

        if self.hostname_map.insert(ip, hostname.clone()).is_none() {
            info!(verbosity = 1, "overheard {ip} named {hostname}");
        }
    }

    /// Caches the hosts an sniffed mDNS message names.
    ///
    /// A message may speak for several hosts, and each is filed under a single
    /// preferred address (see [`preferred_ip`]) so a later lookup by any of that
    /// host's known IPs has a consistent key to find.
    fn absorb_sniffed_mdns(&mut self, payload: &[u8]) {
        let Ok(hosts) = mdns::extract_hosts(payload) else {
            return;
        };

        for host in hosts {
            let Some(ip) = preferred_ip(&host) else {
                continue;
            };

            info!(verbosity = 1, "mDNS names {ip} as {}", host.hostname);
            self.mdns_cache.insert(ip, host);
        }
    }

    /// Writes every collected name back into the host store.
    ///
    /// For each host it walks the IPs the host is known by and applies whatever
    /// the caches hold for them: a DNS hostname when the host has none yet, and
    /// any mDNS record, which can supply a hostname and additional IPs.
    /// Consumed entries are removed from the caches as they are applied.
    ///
    /// Written through [`ScanContext::write_host`] like every other finding, so
    /// a name reaches the event stream as well as the store. Applied by
    /// iterating the map directly it did not, and a consumer watching a scan
    /// saw its hosts arrive unnamed and never heard they had been named.
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

                for ip in host.ips().clone() {
                    // Not `else`-chained with the names below: a resolver that
                    // answers about other hosts and has no name of its own is
                    // the ordinary case for a router.
                    if name_servers.contains(&ip) {
                        named |= host.add_network_role(NetworkRole::DnsServer);
                    }

                    // Prefer a hostname learned over unicast DNS.
                    if host.hostname().is_none()
                        && let Some(hostname) = hostname_map.remove(&ip)
                    {
                        host.set_hostname(Some(hostname));
                        named = true;
                    }

                    // An mDNS record can fill in a missing hostname and extra IPs.
                    if let Some(mdns_host) = mdns_cache.remove(&ip) {
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

/// The address an mDNS host is filed under: IPv4 first, then a link-local IPv6
/// address, then whatever else it advertised. Any single one will do, so long as
/// the choice is the same every time.
fn preferred_ip(host: &MdnsHost) -> Option<IpAddr> {
    host.ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| {
            host.ips.iter().find(|ip| match ip {
                IpAddr::V6(v6) => v6.is_unicast_link_local(),
                IpAddr::V4(_) => false,
            })
        })
        .or_else(|| host.ips.iter().next())
        .copied()
}

/// Binds a query socket for each address family `servers` spans and pairs every
/// server with the socket that can reach it.
///
/// A family whose socket will not bind - a host with IPv6 disabled, say - loses
/// its servers rather than taking the whole resolver down with it. Only having
/// no reachable server at all is fatal, since there is then nothing to ask.
fn bind_query_targets(servers: &[SocketAddr]) -> anyhow::Result<Vec<QueryTarget>> {
    let v4 = bind_family(servers, SocketAddr::is_ipv4, "0.0.0.0:0");
    let v6 = bind_family(servers, SocketAddr::is_ipv6, "[::]:0");

    let targets: Vec<QueryTarget> = servers
        .iter()
        .filter_map(|server| {
            let socket = if server.is_ipv4() { &v4 } else { &v6 };
            Some(QueryTarget {
                server: *server,
                socket: Arc::clone(socket.as_ref()?),
            })
        })
        .collect();

    if targets.is_empty() {
        anyhow::bail!("no reachable DNS server to send reverse queries to");
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

fn bind_ephemeral(bind_addr: &str) -> anyhow::Result<UdpSocket> {
    let socket =
        std::net::UdpSocket::bind(bind_addr).with_context(|| format!("binding {bind_addr}"))?;
    socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(socket)?)
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

    for gateway in netdev::get_interfaces()
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

fn push_unique(servers: &mut Vec<SocketAddr>, server: SocketAddr) {
    if !servers.contains(&server) {
        servers.push(server);
    }
}

/// Active-only reverse resolution for the unprivileged scan path.
///
/// Without raw sockets there is nothing to sniff, so this issues a reverse
/// lookup through the system resolver for every host that still lacks a
/// hostname. The lookups run concurrently, and each answer is written back
/// through [`ScanContext::write_host`] so it announces itself like any other
/// finding. Any failure to build the resolver leaves the store untouched, since
/// a scan without hostnames is still a useful scan.
pub async fn resolve_hosts_async(ctx: &ScanContext) {
    use hickory_resolver::TokioResolver;

    let Ok(builder) = TokioResolver::builder_tokio() else {
        return;
    };
    let Ok(resolver) = builder.build() else {
        return;
    };

    let mut set = tokio::task::JoinSet::new();

    // Keyed by the address the host is stored under rather than by
    // `primary_ip`, so the write below lands on the entry that was read. The
    // two agree for most hosts and not for one whose leading address changed
    // after it was first credited.
    let mut ips_to_resolve = Vec::new();
    for key in ctx.host_addresses() {
        let unnamed = ctx
            .read_host(&key, |host| host.hostname().is_none())
            .unwrap_or(false);
        if unnamed {
            ips_to_resolve.push(key);
        }
    }

    for key in ips_to_resolve {
        let resolver = resolver.clone();

        set.spawn(async move {
            use hickory_resolver::proto::rr::RData;

            // The query takes the address; the key comes back with the answer,
            // so the write below lands on the entry that was read.
            if let Ok(lookup) = resolver.reverse_lookup(key.addr()).await
                && let Some(name) = lookup.answers().iter().find_map(|r| match &r.data {
                    RData::PTR(ptr) => Some(ptr.to_string()),
                    _ => None,
                })
            {
                return (key, Some(name));
            }
            (key, None)
        });
    }

    while let Some(Ok((key, Some(name)))) = set.join_next().await {
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
/// label: `192.168.0.26` comes back as `192-168-0-26.lan`. Consumer routers do
/// this by default, and cloud providers do it deliberately.
///
/// **That is not a name, and accepting it costs more than an empty column.** It
/// carries nothing the address does not already carry, and it fills the one slot
/// a real name would take — this engine prefers a unicast answer to an mDNS one,
/// so a synthesised PTR does not merely sit beside the machine's actual name, it
/// keeps the scan from ever recording it.
///
/// **The test is decidable, not a guess about shape.** An address cannot appear
/// literally in a label, since its own separator is the label separator, so a
/// resolver writing one has to substitute: a dot becomes a dash or an underscore
/// and a colon becomes a dash. Each substitution is undone and the result read
/// back as an address, then compared against the very address the answer was
/// about. A machine genuinely called `10-4-good-buddy` is not an address and
/// keeps its name; one called `192-168-0-26` while answering at some other
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

    // The other shape: the address as leading labels of its own, `192.168.0.26`
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
/// queried for now; narrowing that to skip private ranges and localhost is left
/// for later.
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
        let subject = v4(192, 168, 0, 26);

        for name in [
            "192-168-0-26.lan",
            "192-168-0-26.fritz.box",
            "192_168_0_26.lan",
            "192.168.0.26.lan",
            "192-168-0-26",
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
        let subject = v4(192, 168, 0, 26);

        for name in [
            "epson928262.lan",
            "10-4-good-buddy.lan",
            "kabelbox.local",
            "MacBook-Pro.local",
            "host-1.example",
            "192-168-0.lan",
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
        assert!(!restates("10-0-0-1.lan", v4(192, 168, 0, 26)));
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
        let ip = v4(192, 168, 0, 26);

        resolver.absorb_sniffed_dns(&overheard(ip, "192-168-0-26.lan"));
        assert!(
            !resolver.hostname_map.contains_key(&ip),
            "the address written again was recorded as a name"
        );

        resolver.absorb_sniffed_dns(&overheard(ip, "epson928262.lan"));
        assert_eq!(
            resolver.hostname_map.get(&ip).map(String::as_str),
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
            _emission: Emission,
        ) -> Result<(), SendError> {
            Ok(())
        }
    }

    /// A resolver that would send its queries to `servers`, with no sockets
    /// behind it.
    fn resolver_asking(servers: Vec<SocketAddr>) -> HostnameResolver {
        let (_tx, dns_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
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
        resolver.hostname_map.insert(ip, hostname.to_string());
        resolver
    }

    /// A DNS *response* about `subject`, built from the query this engine sends
    /// so the message is one a real server could have produced.
    ///
    /// It carries no answer, which is deliberate: a server that has no name for
    /// an address, or declines to look, has still answered in DNS.
    fn dns_response(subject: IpAddr) -> Vec<u8> {
        let mut message = dns::build_ptr_packet(&subject, 0x1234).expect("a query");
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
    /// DNS's own protocol. Without this, a scan came back with every hostname
    /// resolved and no idea what had resolved them.
    ///
    /// The second half is the trap on exactly those segments. mDNS shares DNS's
    /// framing and answers on 5353, and nearly every laptop and printer speaks
    /// it — so the identical message from that port must name nobody.
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
    /// itself. Writing straight into the map bypassed
    /// [`ScanContext::write_host`], which owns the lock-then-announce ordering,
    /// so a consumer watching the event stream saw a host appear without a name
    /// and never heard that it had gained one.
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
}
