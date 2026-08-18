// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostname resolution against real resolvers on loopback.
//!
//! [`HostnameResolver`] is driven exactly as a scan drives it - IPs in on a
//! channel, packets in on a transport, hostnames out into a host store - with
//! its two environmental dependencies replaced: the resolvers it queries are
//! `FakeResolver`s bound to loopback, and the traffic it sniffs is pushed onto a
//! synthetic capture stream. Everything between those ends, including the UDP
//! exchange itself, is the code that runs in production.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use pnet::packet::ip::IpNextHeaderProtocols;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use zond_engine::model::host::Host;
use zond_engine::scanner::resolver::HostnameResolver;
use zond_engine::scanner::session::{HostStore, ScanSession};
use zond_engine::transport::capture::CapturedSegment;
use zond_engine::transport::probe::{ProbeSender, ProbeTransport, SendError};

const ROUTER: &str = "192.168.0.1";
const PRINTER: &str = "192.168.0.30";
const PI: &str = "192.168.0.150";

/// The bug this whole path exists to avoid: the first resolver a host is
/// configured with need not be one that will answer for the network being
/// scanned. RFC 6303 has a general-purpose resolver answer for private reverse
/// zones itself rather than forward them, so behind a VPN every LAN host comes
/// back NXDOMAIN - and asking only that resolver means the LAN's own names are
/// never learned, though the gateway knows every one of them.
#[tokio::test]
async fn a_resolver_that_declines_a_reverse_zone_cannot_hide_a_name() {
    let declining = FakeResolver::spawn(Answer::NoSuchName).await;
    let gateway = FakeResolver::spawn(Answer::Name("kabelbox.local")).await;

    let store = resolve(
        vec![declining.addr, gateway.addr],
        &[ip(ROUTER)],
        Vec::new(),
    )
    .await;

    assert_eq!(hostname(&store, ROUTER), Some("kabelbox.local".to_string()));
    assert_eq!(
        declining.questions(),
        vec!["1.0.168.192.in-addr.arpa".to_string()],
        "the declining resolver should still have been asked"
    );
    assert_eq!(
        gateway.questions(),
        vec!["1.0.168.192.in-addr.arpa".to_string()],
    );
}

/// A resolver that answers negatively is answering, and a host with no reverse
/// record simply has no name. It must not acquire one.
#[tokio::test]
async fn a_host_no_resolver_has_a_name_for_stays_unnamed() {
    let resolver = FakeResolver::spawn(Answer::NoSuchName).await;

    let store = resolve(vec![resolver.addr], &[ip(PRINTER)], Vec::new()).await;

    assert_eq!(hostname(&store, PRINTER), None);
}

/// The same host reported by more than one scanning strategy is one host, and
/// costs one query per resolver rather than one per report.
#[tokio::test]
async fn a_host_reported_twice_is_queried_once() {
    let resolver = FakeResolver::spawn(Answer::Name("kabelbox.local")).await;

    let store = resolve(
        vec![resolver.addr],
        &[ip(ROUTER), ip(ROUTER), ip(ROUTER)],
        Vec::new(),
    )
    .await;

    assert_eq!(hostname(&store, ROUTER), Some("kabelbox.local".to_string()));
    assert_eq!(resolver.questions().len(), 1);
}

/// The capture admits every DNS response crossing any interface, so the sniffing
/// path reads answers to questions other processes asked. A transaction ID is
/// their counter, not ours, and a response that happens to reuse one of our IDs
/// must not rename the host that ID was spent on. The question is what decides.
#[tokio::test]
async fn a_stranger_reusing_our_transaction_id_renames_nothing() {
    let silent = FakeResolver::spawn(Answer::Nothing).await;

    // IDs are handed out from zero, so the very first query the resolver sends
    // carries ID 0 - which is exactly what an unrelated response is most likely
    // to collide with.
    let intruder = ptr_response(0, "150.0.168.192.in-addr.arpa", Some("raspberrypi.local"));

    let store = resolve(
        vec![silent.addr],
        &[ip(ROUTER), ip(PI)],
        vec![sniffed_dns(&intruder)],
    )
    .await;

    assert_eq!(
        hostname(&store, ROUTER),
        None,
        "a name answered for another address must not land on this host"
    );
    assert_eq!(
        hostname(&store, PI),
        Some("raspberrypi.local".to_string()),
        "it belongs to the address its question named"
    );
}

/// The point of sniffing: somebody else's reverse lookup answers our question
/// too, for a host we never got round to asking about.
#[tokio::test]
async fn a_reverse_lookup_overheard_on_the_wire_names_its_host() {
    let silent = FakeResolver::spawn(Answer::Nothing).await;
    let overheard = ptr_response(0x4321, "30.0.168.192.in-addr.arpa", Some("epson.local"));

    let store = resolve(vec![silent.addr], &[], vec![sniffed_dns(&overheard)]).await;

    assert_eq!(hostname(&store, PRINTER), Some("epson.local".to_string()));
}

/// mDNS names a host by the owner of its address record. The service PTRs in
/// the same message name instances of services, and reading one as a hostname
/// puts "Living Room._airplay._tcp.local" on a machine in the scan report.
#[tokio::test]
async fn an_mdns_response_names_the_owner_of_the_address_not_the_service() {
    let silent = FakeResolver::spawn(Answer::Nothing).await;

    let mut message = dns_header(0, 2);
    write_record(
        &mut message,
        "_airplay._tcp.local",
        Rdata::Ptr("Study._airplay._tcp.local"),
    );
    write_record(&mut message, "appletv.local", Rdata::A([192, 168, 0, 150]));

    let store = resolve(vec![silent.addr], &[], vec![sniffed_mdns(&message)]).await;

    assert_eq!(hostname(&store, PI), Some("appletv.local".to_string()));
}

// ── Driving the resolver ────────────────────────────────────────────────────

/// Runs a resolver over `targets` and `sniffed` and returns the host store it
/// wrote into, seeded with a host for every address the assertions look at.
async fn resolve(
    servers: Vec<SocketAddr>,
    targets: &[IpAddr],
    sniffed: Vec<CapturedSegment>,
) -> HostStore {
    let (dns_tx, dns_rx) = mpsc::unbounded_channel();
    let (capture_tx, capture_rx) = mpsc::unbounded_channel();
    let transport = ProbeTransport::from_parts(Box::new(SilentSender), capture_rx);

    let resolver = HostnameResolver::with_transport(dns_rx, transport, servers)
        .expect("a resolver over loopback servers");

    let (session, ctx) = ScanSession::new();
    for address in [ROUTER, PRINTER, PI] {
        ctx.update_host(ip(address), |host| *host = Host::new(ip(address)));
    }

    for segment in sniffed {
        capture_tx.send(segment).expect("queueing sniffed traffic");
    }
    for target in targets {
        dns_tx.send(*target).expect("queueing a target");
    }
    drop(dns_tx);
    drop(capture_tx);

    let mut resolver = resolver.run().await;
    resolver.resolve_hosts(&ctx);
    session.hosts().clone()
}

fn hostname(store: &HostStore, address: &str) -> Option<String> {
    store
        .get(&ip(address))
        .and_then(|host| host.hostname().map(str::to_string))
}

fn ip(address: &str) -> IpAddr {
    address.parse().expect("a literal address")
}

/// The resolver only listens; a probe sender it never calls still has to exist.
struct SilentSender;

impl ProbeSender for SilentSender {
    fn send(&self, _segment: &[u8], _src: IpAddr, _dst: IpAddr) -> Result<(), SendError> {
        panic!("the hostname resolver must not emit raw probes");
    }
}

// ── A DNS server on loopback ────────────────────────────────────────────────

/// What a [`FakeResolver`] does with a query.
#[derive(Clone, Copy)]
enum Answer {
    /// Reply with a PTR record carrying this name.
    Name(&'static str),
    /// Reply that the name does not exist, as a resolver declining to serve a
    /// private reverse zone does.
    NoSuchName,
    /// Read the query and say nothing, so a test's only input is what it sniffs.
    Nothing,
}

/// A DNS server bound to loopback, answering every reverse query the same way
/// and recording what it was asked.
struct FakeResolver {
    addr: SocketAddr,
    asked: Arc<Mutex<Vec<String>>>,
}

impl FakeResolver {
    async fn spawn(answer: Answer) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback resolver");
        let addr = socket.local_addr().expect("the bound address");
        let asked = Arc::new(Mutex::new(Vec::new()));

        let recorded = Arc::clone(&asked);
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                let query = &buf[..len];
                recorded
                    .lock()
                    .expect("the question log")
                    .push(question_name(query));

                let reply = match answer {
                    Answer::Name(name) => reply_to(query, Some(name)),
                    Answer::NoSuchName => reply_to(query, None),
                    Answer::Nothing => continue,
                };
                let _ = socket.send_to(&reply, from).await;
            }
        });

        Self { addr, asked }
    }

    /// The question of every query this resolver received, in order.
    fn questions(&self) -> Vec<String> {
        self.asked.lock().expect("the question log").clone()
    }
}

/// Turns a query into its response, echoing the question back the way a real
/// resolver does and appending a PTR answer when there is a name to give.
fn reply_to(query: &[u8], name: Option<&str>) -> Vec<u8> {
    let mut reply = query[..question_end(query)].to_vec();

    reply[2] |= 0x80; // QR: this is a response
    reply[3] = if name.is_some() { 0x80 } else { 0x83 }; // RA, and NXDOMAIN when empty
    reply[6..8].copy_from_slice(&u16::from(name.is_some()).to_be_bytes());

    if let Some(name) = name {
        let mut rdata = Vec::new();
        write_name(&mut rdata, name);
        reply.extend_from_slice(&[0xC0, 0x0C]); // owner: a pointer to the question
        reply.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
        reply.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        reply.extend_from_slice(&60u32.to_be_bytes()); // TTL
        reply.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        reply.extend_from_slice(&rdata);
    }

    reply
}

/// Where a query's single question ends. Queries carry no compression, so the
/// name is a plain run of labels.
fn question_end(query: &[u8]) -> usize {
    let mut offset = 12;
    while query[offset] != 0 {
        offset += 1 + query[offset] as usize;
    }
    offset + 1 + 4 // the root label, then QTYPE and QCLASS
}

fn question_name(query: &[u8]) -> String {
    let mut labels = Vec::new();
    let mut offset = 12;
    while query[offset] != 0 {
        let len = query[offset] as usize;
        labels.push(String::from_utf8_lossy(&query[offset + 1..offset + 1 + len]).to_string());
        offset += 1 + len;
    }
    labels.join(".")
}

// ── Building packets to sniff ───────────────────────────────────────────────

enum Rdata<'a> {
    A([u8; 4]),
    Ptr(&'a str),
}

/// A response as it arrives from the capture: a UDP datagram from port 53,
/// already stripped of its link and IP headers.
fn sniffed_dns(payload: &[u8]) -> CapturedSegment {
    sniffed(53, payload)
}

/// The same, from the mDNS port.
fn sniffed_mdns(payload: &[u8]) -> CapturedSegment {
    sniffed(5353, payload)
}

fn sniffed(source_port: u16, payload: &[u8]) -> CapturedSegment {
    let mut bytes = Vec::with_capacity(8 + payload.len());
    bytes.extend_from_slice(&source_port.to_be_bytes());
    bytes.extend_from_slice(&40_000u16.to_be_bytes()); // destination port
    bytes.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes()); // checksum, unchecked here
    bytes.extend_from_slice(payload);

    CapturedSegment::synthetic(ip("192.168.0.1"), IpNextHeaderProtocols::Udp, bytes)
}

/// A PTR response as it would appear on the wire, with its question intact.
fn ptr_response(id: u16, question: &str, answer: Option<&str>) -> Vec<u8> {
    let mut query = dns_header(id, 0);
    query[3] = 0x00;
    write_name(&mut query, question);
    query.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
    query.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    query[4..6].copy_from_slice(&1u16.to_be_bytes()); // one question

    reply_to(&query, answer)
}

/// A DNS header with `answers` answers and no questions.
fn dns_header(id: u16, answers: u16) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&id.to_be_bytes());
    header.extend_from_slice(&0x8400u16.to_be_bytes()); // response, authoritative
    header.extend_from_slice(&0u16.to_be_bytes()); // questions
    header.extend_from_slice(&answers.to_be_bytes());
    header.extend_from_slice(&0u16.to_be_bytes()); // authority
    header.extend_from_slice(&0u16.to_be_bytes()); // additional
    header
}

fn write_record(bytes: &mut Vec<u8>, owner: &str, data: Rdata<'_>) {
    write_name(bytes, owner);

    let (rtype, rdata) = match data {
        Rdata::A(octets) => (1u16, octets.to_vec()),
        Rdata::Ptr(target) => {
            let mut rdata = Vec::new();
            write_name(&mut rdata, target);
            (12u16, rdata)
        }
    };

    bytes.extend_from_slice(&rtype.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    bytes.extend_from_slice(&120u32.to_be_bytes()); // TTL
    bytes.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&rdata);
}

fn write_name(bytes: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
}
