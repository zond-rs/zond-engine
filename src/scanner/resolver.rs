// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Hostname Resolution
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

use hickory_resolver::config::ProtocolConfig;
use hickory_resolver::system_conf::read_system_conf;
use std::net::SocketAddr;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

use crate::protocols::{
    dns,
    mdns::{self, MdnsHost},
};
use crate::{
    error, info,
    model::{host::Host, ip},
    warn,
};
use anyhow::Context;
use dashmap::DashMap;
use pnet::packet::{Packet, udp::UdpPacket};
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
                        Some(reply) => self.absorb_sniffed(&reply.bytes),
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
                                Some(reply) => self.absorb_sniffed(&reply.bytes),
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
            self.absorb_sniffed(&reply.bytes);
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
                "Reverse query for {ip} sent to {count} resolver(s)"
            ),
            Err(e) => error!("Reverse query for {ip} failed: {e}"),
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
            match dns::create_ptr_packet(ip, id) {
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
                error!(verbosity = 2, "Unreadable reply from resolver {from}: {e}");
                return;
            }
        };

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
    fn absorb_sniffed(&mut self, segment: &[u8]) {
        let Some(udp_packet) = UdpPacket::new(segment) else {
            return;
        };

        match udp_packet.get_source() {
            DNS_PORT => self.absorb_sniffed_dns(udp_packet.payload()),
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

        if self.hostname_map.insert(ip, hostname.clone()).is_none() {
            info!(verbosity = 1, "Overheard {ip} named {hostname}");
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
    /// For each host it walks the IPs the host is known by and applies whatever the
    /// caches hold for them: a DNS hostname when the host has none yet, and any
    /// mDNS record, which can supply a hostname and additional IPs. Consumed
    /// entries are removed from the caches as they are applied.
    pub fn resolve_hosts(&mut self, store: Arc<DashMap<IpAddr, Host>>) {
        for mut host_entry in store.iter_mut() {
            let host = host_entry.value_mut();
            let ips_to_check = host.ips().clone();

            for ip in ips_to_check {
                // Prefer a hostname learned over unicast DNS.
                if host.hostname().is_none()
                    && let Some(hostname) = self.hostname_map.remove(&ip)
                {
                    host.set_hostname(Some(hostname));
                }

                // An mDNS record can fill in a missing hostname and extra IPs.
                if let Some(mdns_host) = self.mdns_cache.remove(&ip) {
                    if host.hostname().is_none() {
                        host.set_hostname(Some(mdns_host.hostname));
                    }

                    host.extend_ips(mdns_host.ips);
                }
            }
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
            error!("Reverse query socket failed: {e}");
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
        "Reverse queries go to {}",
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
            warn!("Could not bind {bind_addr} for reverse queries: {e}");
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
        Err(e) => warn!("Could not read the system resolver configuration: {e}"),
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
/// Without raw sockets there is nothing to sniff, so this issues a reverse lookup
/// through the system resolver for every host in `store` that still lacks a
/// hostname. The lookups run concurrently, and each answer is written straight
/// back onto its host. Any failure to build the resolver leaves the store
/// untouched, since a scan without hostnames is still a useful scan.
pub async fn resolve_hosts_async(store: Arc<DashMap<IpAddr, Host>>) {
    use hickory_resolver::TokioResolver;

    let Ok(builder) = TokioResolver::builder_tokio() else {
        return;
    };
    let Ok(resolver) = builder.build() else {
        return;
    };

    let mut set = tokio::task::JoinSet::new();

    let mut ips_to_resolve = Vec::new();
    for host_entry in store.iter() {
        let host = host_entry.value();
        if host.hostname().is_none() {
            ips_to_resolve.push(host.primary_ip());
        }
    }

    for ip in ips_to_resolve {
        let resolver = resolver.clone();

        set.spawn(async move {
            use hickory_resolver::proto::rr::RData;

            if let Ok(lookup) = resolver.reverse_lookup(ip).await
                && let Some(name) = lookup.answers().iter().find_map(|r| match &r.data {
                    RData::PTR(ptr) => Some(ptr.to_string()),
                    _ => None,
                })
            {
                return (ip, Some(name));
            }
            (ip, None)
        });
    }

    while let Some(Ok((ip, Some(name)))) = set.join_next().await {
        if let Some(mut host_entry) = store.get_mut(&ip) {
            host_entry
                .value_mut()
                .set_hostname(Some(name.trim_end_matches('.').to_string()));
        }
    }
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
