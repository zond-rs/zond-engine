// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

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
//! [`resolve_hosts_async`] is the unprivileged fallback. With no raw socket to
//! sniff, it simply issues reverse lookups through the system resolver for every
//! host that still lacks a name.

use hickory_resolver::system_conf::read_system_conf;
use std::net::SocketAddr;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

use crate::protocols::{
    dns,
    mdns::{self, MdnsRecord},
};
use crate::{
    core::models::{host::Host, ip},
    error, info,
};
use anyhow::Context;
use dashmap::DashMap;
use pnet::packet::{Packet, udp::UdpPacket};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::network::probe::{ProbeKind, ProbeTransport};

const DNS_PORT: u16 = 53;
const MDNS_PORT: u16 = 5353;

type Hostname = String;
type TransID = u16;

/// Passive-and-active hostname resolver for the privileged scan path.
///
/// It runs as its own task ([`HostnameResolver::run`]), taking IPs to resolve off
/// `dns_rx` as the scan discovers them, querying the system resolver for each, and
/// sniffing the wire for any DNS or mDNS answers that pass by. The names it
/// gathers are held in its caches until [`HostnameResolver::resolve_hosts`] writes
/// them back to the host store at the end of the scan.
pub struct HostnameResolver {
    /// Raw UDP receiver used to sniff DNS and mDNS responses off the wire.
    transport: ProbeTransport,
    /// Socket the PTR queries are sent from, and where their replies arrive.
    std_socket: std::sync::Arc<tokio::net::UdpSocket>,
    /// Outstanding PTR queries, keyed by transaction ID so a reply can be matched
    /// back to the IP it was asked about.
    dns_map: HashMap<TransID, IpAddr>,
    /// mDNS records collected from sniffed traffic, keyed by IP.
    mdns_cache: HashMap<IpAddr, MdnsRecord>,
    /// Hostnames resolved so far, keyed by IP.
    hostname_map: HashMap<IpAddr, Hostname>,
    /// Stream of IPs to resolve, fed by the discovery and scanning strategies.
    dns_rx: UnboundedReceiver<IpAddr>,
    /// The system DNS server the PTR queries are sent to.
    dns_socket: SocketAddr,
    /// Source of transaction IDs for outgoing queries.
    id_counter: AtomicU16,
}

impl HostnameResolver {
    /// Builds a resolver that reads IPs to resolve from `dns_rx`.
    ///
    /// It reads the system's DNS configuration to find the server to query, binds
    /// a UDP socket in the matching address family for the PTR exchange, and opens
    /// the raw receiver used to sniff DNS and mDNS traffic.
    pub fn new(dns_rx: UnboundedReceiver<IpAddr>) -> anyhow::Result<Self> {
        let dns_socket = get_dns_server_socket()?;
        let bind_addr = match dns_socket {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let std_socket = std::net::UdpSocket::bind(bind_addr)?;
        std_socket.set_nonblocking(true)?;
        let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)?;

        Ok(Self {
            transport: ProbeTransport::open_receiver(ProbeKind::UdpResolve)?,
            std_socket: std::sync::Arc::new(tokio_socket),
            dns_map: HashMap::new(),
            mdns_cache: HashMap::new(),
            hostname_map: HashMap::new(),
            dns_rx,
            dns_socket,
            id_counter: AtomicU16::new(0),
        })
    }

    /// Runs the resolver's event loop until the IP stream closes.
    ///
    /// On each turn it does one of three things: send a PTR query for a newly
    /// arrived IP, read a reply to a query it sent, or absorb a DNS or mDNS packet
    /// sniffed off the wire. Once `dns_rx` closes, it waits briefly for any PTR
    /// queries still in flight before returning itself, so the caller can hand the
    /// collected names to [`resolve_hosts`](Self::resolve_hosts).
    pub async fn run(mut self) -> Self {
        let socket = self.std_socket.clone();
        let mut buf = [0u8; 2048];
        loop {
            tokio::select! {
                res = self.dns_rx.recv() => {
                    match res {
                        Some(ip) => {
                            if !is_queryable(&ip) {
                                continue;
                            }
                            match self.send_dns_query(&ip).await {
                                Ok(_) => info!(outgoing, verbosity = 1, "DNS query for {ip} sent!"),
                                Err(e) => error!("DNS query for {ip} failed: {e}")
                            }
                        }
                        None => break,
                    }
                }
                res = socket.recv_from(&mut buf) => {
                    if let Ok((len, addr)) = res
                        && addr == self.dns_socket {
                            let _ = self.process_dns_payload(&buf[..len]);
                        }
                }
                pkt = self.transport.rx.recv() => {
                    if let Some((bytes, _addr)) = pkt {
                        match self.process_udp_packets(&bytes) {
                            Ok(_) => {},
                            Err(e) => error!(verbosity = 1, "UDP packet processing failed: {e}")
                        }
                    }
                }
            }
        }

        // The IP stream has closed, but replies to the last queries may still be
        // arriving. Give them a short window to land before giving up on them.
        if !self.dns_map.is_empty() {
            let _ = tokio::time::timeout(Duration::from_millis(250), async {
                while !self.dns_map.is_empty() {
                    tokio::select! {
                        res = socket.recv_from(&mut buf) => {
                            if let Ok((len, addr)) = res
                                && addr == self.dns_socket {
                                    let _ = self.process_dns_payload(&buf[..len]);
                                }
                        }
                        pkt = self.transport.rx.recv() => {
                            if let Some((bytes, _addr)) = pkt {
                                let _ = self.process_udp_packets(&bytes);
                            }
                        }
                    }
                }
            })
            .await;
        }

        self
    }

    /// Sends a reverse (PTR) query for `ip` and records its transaction ID, so the
    /// matching reply can later be tied back to this IP.
    async fn send_dns_query(&mut self, ip: &IpAddr) -> anyhow::Result<()> {
        let id: u16 = self.get_next_trans_id();
        self.dns_map.insert(id, *ip);

        let bytes: Vec<u8> = dns::create_ptr_packet(ip, id)?;
        self.std_socket.send_to(&bytes, self.dns_socket).await?;

        Ok(())
    }

    /// Routes a sniffed UDP packet to the DNS or mDNS handler by its source port,
    /// ignoring anything from another port.
    fn process_udp_packets(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let udp_packet = UdpPacket::new(bytes).context("truncated or invalid UDP packet")?;
        match udp_packet.get_source() {
            DNS_PORT => self.process_dns_packet(udp_packet)?,
            MDNS_PORT => self.process_mdns_packet(udp_packet)?,
            _ => {}
        }
        Ok(())
    }

    /// Handles a DNS response sniffed off the wire by unwrapping its UDP payload.
    /// The direct socket path calls [`process_dns_payload`](Self::process_dns_payload)
    /// with the payload it already has.
    fn process_dns_packet(&mut self, packet: UdpPacket) -> anyhow::Result<()> {
        self.process_dns_payload(packet.payload())
    }

    /// Parses a DNS response and, when its transaction ID matches a query still on
    /// record, caches the hostname it carries against that IP.
    fn process_dns_payload(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        let (response_id, hostname) = dns::get_hostname(payload)?;
        if let Some(ip) = self.dns_map.remove(&response_id) {
            info!(incoming, verbosity = 1, "Received DNS response for {ip}");
            self.hostname_map.insert(ip, hostname);
        }
        Ok(())
    }

    /// Caches an mDNS record from a sniffed packet.
    ///
    /// A record may advertise several addresses. It is filed under a single
    /// preferred one, favouring IPv4, then a link-local IPv6 address, and finally
    /// whatever comes first, so a later lookup by any of the host's known IPs has a
    /// consistent key to find.
    fn process_mdns_packet(&mut self, packet: UdpPacket) -> anyhow::Result<()> {
        let mdns_record: MdnsRecord = mdns::extract_resource(packet.payload())?;

        let preferred_ip = mdns_record
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .or_else(|| {
                mdns_record.ips.iter().find(|ip| {
                    if let IpAddr::V6(v6) = ip {
                        v6.is_unicast_link_local()
                    } else {
                        false
                    }
                })
            })
            .or_else(|| mdns_record.ips.iter().next());

        if let Some(ip) = preferred_ip {
            info!(verbosity = 1, "Received MDNS response for {ip}");
            self.mdns_cache.insert(*ip, mdns_record);
        }

        Ok(())
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
                if let Some(mdns_record) = self.mdns_cache.remove(&ip) {
                    if host.hostname().is_none() && mdns_record.hostname.is_some() {
                        host.set_hostname(mdns_record.hostname.clone());
                    }

                    host.extend_ips(mdns_record.ips);
                }
            }
        }
    }

    /// Hands out the next DNS transaction ID, wrapping around on overflow.
    fn get_next_trans_id(&self) -> u16 {
        self.id_counter.fetch_add(1, Ordering::Relaxed)
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

/// Finds the DNS server to send queries to.
///
/// It takes the first name server from the system's resolver configuration, using
/// its configured port or 53 by default, and falls back to Cloudflare's `1.1.1.1`
/// when the system lists no name server.
fn get_dns_server_socket() -> anyhow::Result<SocketAddr> {
    let (config, _options) = read_system_conf()?;

    if let Some(ns) = config.name_servers().first() {
        let port = ns.connections.first().map(|c| c.port).unwrap_or(53);
        return Ok(SocketAddr::new(ns.ip, port));
    }

    Ok("1.1.1.1:53".parse()?)
}
