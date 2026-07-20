// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

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
use pnet::packet::{Packet, udp::UdpPacket};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::network::transport::{self, TransportHandle, TransportType};

const DNS_PORT: u16 = 53;
const MDNS_PORT: u16 = 5353;

type Hostname = String;
type TransID = u16;

pub struct HostnameResolver {
    udp_handle: TransportHandle,
    std_socket: std::sync::Arc<tokio::net::UdpSocket>,
    dns_map: HashMap<TransID, IpAddr>,
    mdns_cache: HashMap<IpAddr, MdnsRecord>,
    hostname_map: HashMap<IpAddr, Hostname>,
    dns_rx: UnboundedReceiver<IpAddr>,
    dns_socket: SocketAddr,
    id_counter: AtomicU16,
}

impl HostnameResolver {
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
            udp_handle: transport::start_packet_capture(TransportType::UdpLayer4)?,
            std_socket: std::sync::Arc::new(tokio_socket),
            dns_map: HashMap::new(),
            mdns_cache: HashMap::new(),
            hostname_map: HashMap::new(),
            dns_rx,
            dns_socket,
            id_counter: AtomicU16::new(0),
        })
    }

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
                pkt = self.udp_handle.rx.recv() => {
                    if let Some((bytes, _addr)) = pkt {
                        match self.process_udp_packets(&bytes) {
                            Ok(_) => {},
                            Err(e) => error!(verbosity = 1, "UDP packet processing failed: {e}")
                        }
                    }
                }
            }
        }

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
                        pkt = self.udp_handle.rx.recv() => {
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

    async fn send_dns_query(&mut self, ip: &IpAddr) -> anyhow::Result<()> {
        let id: u16 = self.get_next_trans_id();
        self.dns_map.insert(id, *ip);

        let bytes: Vec<u8> = dns::create_ptr_packet(ip, id)?;
        self.std_socket.send_to(&bytes, self.dns_socket).await?;

        Ok(())
    }

    fn process_udp_packets(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let udp_packet = UdpPacket::new(bytes).context("truncated or invalid UDP packet")?;
        match udp_packet.get_source() {
            DNS_PORT => self.process_dns_packet(udp_packet)?,
            MDNS_PORT => self.process_mdns_packet(udp_packet)?,
            _ => {}
        }
        Ok(())
    }

    fn process_dns_packet(&mut self, packet: UdpPacket) -> anyhow::Result<()> {
        self.process_dns_payload(packet.payload())
    }

    fn process_dns_payload(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        let (response_id, hostname) = dns::get_hostname(payload)?;
        if let Some(ip) = self.dns_map.remove(&response_id) {
            info!(incoming, verbosity = 1, "Received DNS response for {ip}");
            self.hostname_map.insert(ip, hostname);
        }
        Ok(())
    }

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

    pub fn resolve_hosts(&mut self, hosts: &mut Vec<Host>) {
        for host in hosts {
            let ips_to_check = host.ips().clone();

            for ip in ips_to_check {
                // Resolve DNS
                if host.hostname().is_none()
                    && let Some(hostname) = self.hostname_map.remove(&ip)
                {
                    host.set_hostname(Some(hostname));
                }

                // Resolve mDNS
                if let Some(mdns_record) = self.mdns_cache.remove(&ip) {
                    if host.hostname().is_none() && mdns_record.hostname.is_some() {
                        host.set_hostname(mdns_record.hostname.clone());
                    }

                    host.extend_ips(mdns_record.ips);
                }
            }
        }
    }

    fn get_next_trans_id(&self) -> u16 {
        self.id_counter.fetch_add(1, Ordering::Relaxed)
    }
}

pub async fn resolve_hosts_async(hosts: &mut [Host]) {
    use hickory_resolver::TokioResolver;

    let Ok(builder) = TokioResolver::builder_tokio() else {
        return;
    };
    let Ok(resolver) = builder.build() else {
        return;
    };

    let mut set = tokio::task::JoinSet::new();

    for (i, host) in hosts.iter().enumerate() {
        if host.hostname().is_none() {
            let primary_ip = host.primary_ip();
            let resolver = resolver.clone();

            set.spawn(async move {
                use hickory_resolver::proto::rr::RData;

                if let Ok(lookup) = resolver.reverse_lookup(primary_ip).await
                    && let Some(name) = lookup.answers().iter().find_map(|r| match &r.data {
                        RData::PTR(ptr) => Some(ptr.to_string()),
                        _ => None,
                    })
                {
                    return (i, Some(name));
                }
                (i, None)
            });
        }
    }

    while let Some(Ok((idx, Some(name)))) = set.join_next().await {
        hosts[idx].set_hostname(Some(name.trim_end_matches('.').to_string()));
    }
}

fn is_queryable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(ipv6_addr) => ip::is_global_unicast(ipv6_addr),
        IpAddr::V4(_ipv4_addr) => {
            // Future refinement: check for private ranges/localhost
            true
        }
    }
}

fn get_dns_server_socket() -> anyhow::Result<SocketAddr> {
    let (config, _options) = read_system_conf()?;

    if let Some(ns) = config.name_servers().first() {
        let port = ns.connections.first().map(|c| c.port).unwrap_or(53);
        return Ok(SocketAddr::new(ns.ip, port));
    }

    Ok("1.1.1.1:53".parse()?)
}
