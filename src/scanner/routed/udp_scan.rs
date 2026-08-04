// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # UDP Port Probing
//!
//! Implements the privileged UDP half of [`crate::scanner::scan`]. It probes
//! specific `(address, port)` pairs with raw UDP packets and classifies each
//! one by whether and how it responds.
//!
//! UDP scanning is harder than the SYN scan next door because UDP carries no
//! handshake to correlate against. A closed port answers with an ICMP Port
//! Unreachable, an open one answers with a UDP datagram *if* it understands
//! what was sent, and a filtered one says nothing at all - which is also what
//! an open port that ignored the probe does. So:
//!
//! - a direct UDP reply is [`PortState::Open`],
//! - an ICMP Port Unreachable is [`PortState::Closed`],
//! - silence until the deadline is [`PortState::OpenFiltered`], because it
//!   genuinely cannot distinguish the two.
//!
//! ## Tying a reply to its probe
//!
//! Every probe in a scan leaves from one fixed source port, chosen when the
//! scanner is built. That single port is what makes both answers correlatable:
//!
//! - A **direct reply** is addressed back to it, so the kernel's BPF filter
//!   admits this scan's replies and drops the rest of the host's UDP traffic
//!   ([`ProbeKind::UdpProbe`]).
//! - An **ICMP error** carries no ports of its own, but RFC 792 requires it to
//!   quote the datagram that caused it - IP header plus the first eight bytes,
//!   which is exactly a whole UDP header. That quotation names the probe: its
//!   source port proves the datagram was ours, and its destination address and
//!   port say *which* probe, so one error retires exactly one probe.
//!
//! Reading the quoted packet rather than the error's own source address also
//! keeps a router's error attributable: the ICMP comes from the router, but the
//! probe it refers to was aimed at the host behind it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pnet::packet::Packet;
use pnet::packet::icmp::destination_unreachable::{DestinationUnreachablePacket, IcmpCodes};
use pnet::packet::icmp::{IcmpCode, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::UdpPacket;
use tokio::sync::mpsc;

use crate::core::config::SendMode;
use crate::core::models::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::core::models::port::{PortState, Protocol};
use crate::core::models::target::Target;
use crate::core::models::timer::ScanBudget;
use crate::core::session::{ScanContext, ScannerKind};
use crate::error;
use crate::network::capture::CapturedSegment;
use crate::network::frame;
use crate::network::probe::{ProbeKind, ProbeTransport};
use crate::scanner::PortScanner;
use crate::system::interface::SourceResolver;

use super::send_udp;

/// The probe a reply refers to: the `(address, port)` it was sent to.
type ProbeTarget = (IpAddr, u16);

/// Outstanding probes, keyed by the target they were sent to.
type PendingProbes = HashMap<ProbeTarget, Instant>;

/// How long this scan runs and how it adapts.
///
/// Deliberately *not* the profile the SYN scanners share
/// ([`DEADLINE_CONFIG`](super::DEADLINE_CONFIG)), because the thing being
/// waited for is different in kind. A SYN probe is answered by the target's
/// TCP stack as fast as the link allows. A UDP probe's most informative answer
/// is an ICMP error, and hosts **rate-limit** those: Linux emits roughly one
/// destination-unreachable per second by default (`net.ipv4.icmp_ratelimit`),
/// and BSD does the same. Answers to a multi-port scan therefore arrive spread
/// over seconds no matter how fast the network is.
///
/// That reshapes every number here, but `silence_floor` most of all. The SYN
/// profile gives up after 150 ms of quiet, which is generous for a stack that
/// answers immediately and *meaningless* against a host allowed to speak once
/// per second: the scan would stop while its answers were still queued and
/// legally on their way, then report the ports it never heard about as
/// filtered. A floor above the rate-limit interval is what makes silence
/// evidence of anything at all.
const DEADLINE_CONFIG: AdaptiveDeadlineConfig = AdaptiveDeadlineConfig::new(
    // Hard ceiling: a UDP scan is inherently slow, but it still has to finish.
    ScanBudget::new(
        Duration::from_millis(2_000),
        Duration::from_millis(200),
        Duration::from_secs(45),
    ),
    // Minimum runtime, so a scan cannot conclude before the first rate-limited
    // answers have had time to arrive.
    ScanBudget::new(
        Duration::from_millis(500),
        Duration::from_millis(50),
        Duration::from_secs(10),
    ),
    // Silence floor: longer than one rate-limit interval, so quiet means
    // "nothing is coming" rather than "the host is not allowed to answer yet".
    Duration::from_millis(1_200),
    Duration::from_secs(5),
    4.0,
    20,
);

/// How long one probe waits for an answer before it is written off as
/// open-filtered.
///
/// This is what lets a verdict be reached *during* the scan rather than only
/// when the whole thing winds down: probes retire as they expire, so results
/// stream out to the caller and [`MAX_IN_FLIGHT`] has room to admit the next
/// target.
///
/// Generous on purpose. A reply arriving after its probe has expired finds
/// nothing outstanding to match and is dropped, leaving a genuinely open port
/// reported as open-filtered - so this bounds how slow a host may be before the
/// scan stops believing it. Three seconds is far beyond any healthy round trip
/// (the loopback and LAN measurements behind this are single-digit
/// milliseconds) while still keeping a fully silent host from pinning probes
/// for the entire run.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// The most probes left outstanding at once.
///
/// Two jobs: it bounds the memory a scan of a large address space can occupy,
/// and it keeps the send loop from emptying the dispatcher into the network as
/// fast as the socket accepts writes - a burst that outruns any rate-limited
/// host's ability to answer manufactures open-filtered verdicts.
///
/// The ceiling is global rather than per host because
/// [`Dispatcher`](crate::scanner::dispatcher::Dispatcher) already hands out
/// shuffled targets, so consecutive probes in a multi-host scan naturally land
/// on different hosts. A per-host cap on top of that would constrain something
/// the target stream has already spread out.
const MAX_IN_FLIGHT: usize = 512;

/// How often the loop revisits its own bookkeeping while probes are
/// outstanding, so an expiry is noticed promptly instead of waiting out the
/// deadline's much longer tick.
const PENDING_TICK: Duration = Duration::from_millis(50);

// The ICMPv6 Destination Unreachable codes this scanner acts on (RFC 4443
// §3.1). Spelled out here because `pnet` models ICMPv6 codes as a bare
// newtype, with no named constants the way it has for ICMPv4.
//
/// Code 4: the v6 counterpart of [`IcmpCodes::DestinationPortUnreachable`].
const ICMPV6_PORT_UNREACHABLE: Icmpv6Code = Icmpv6Code(4);
/// Code 1: communication with the destination administratively prohibited.
const ICMPV6_ADMIN_PROHIBITED: Icmpv6Code = Icmpv6Code(1);
/// Code 5: source address failed an ingress/egress policy.
const ICMPV6_INGRESS_EGRESS_POLICY: Icmpv6Code = Icmpv6Code(5);
/// Code 6: the route to the destination is a reject route.
const ICMPV6_REJECT_ROUTE: Icmpv6Code = Icmpv6Code(6);

/// The four unused bytes between an ICMPv6 Destination Unreachable header and
/// the packet it quotes (RFC 4443 §3.1).
///
/// `pnet` models ICMPv6 only as the generic type/code/checksum header, so its
/// payload still has these in front of the quoted packet. ICMPv4 needs no
/// equivalent constant: `pnet` models the Destination Unreachable header
/// itself, so [`DestinationUnreachablePacket::payload`] already starts at the
/// quotation.
const ICMPV6_UNUSED_LEN: usize = 4;

/// Probes specific `(address, port)` pairs with raw UDP packets.
pub struct UdpPortScanner {
    /// Resolves the source address to send each target's probe from, consulting
    /// on-link subnets and the kernel routing table.
    resolver: SourceResolver,
    /// Shared state (host store, event channel, abort signal) for the scan
    /// this prober is part of.
    ctx: ScanContext,
    /// Transport used to send raw UDP probes and receive replies (or ICMP errors).
    transport: ProbeTransport,
    /// Governs how long this scan keeps running, adapting to observed
    /// round-trip times.
    deadline: AdaptiveDeadline,
    /// Probes sent but not yet resolved into a classification.
    pending: PendingProbes,
    /// The source port every probe in this scan is sent from. It is the scan's
    /// identity on the wire: the capture filter narrows direct replies to it,
    /// and an ICMP error's quoted datagram is only believed when it names this
    /// port as its source. See the module documentation.
    src_port: u16,
}

impl UdpPortScanner {
    /// Builds a scanner that selects each probe's source via `resolver`, sized
    /// for a scan covering `target_count` `(address, port)` pairs.
    ///
    /// The scan's fixed source port is drawn from the high ephemeral range,
    /// where it is unlikely to collide with a listening service on this host,
    /// and the transport's capture filter is built around it.
    pub fn new(
        resolver: SourceResolver,
        ctx: ScanContext,
        target_count: usize,
        send_mode: SendMode,
    ) -> anyhow::Result<Self> {
        let src_port: u16 = rand::random_range(50_000..u16::MAX);
        let transport = ProbeTransport::open_with(
            ProbeKind::UdpProbe {
                reply_port: src_port,
            },
            send_mode,
        )?;
        let deadline = AdaptiveDeadline::new(DEADLINE_CONFIG, target_count);

        Ok(Self {
            resolver,
            ctx,
            transport,
            deadline,
            pending: PendingProbes::new(),
            src_port,
        })
    }

    fn send_probe(&mut self, target: Target) {
        if target.protocol != Protocol::Udp {
            return;
        }

        let Some(src_addr) = self.resolver.resolve(target.ip) else {
            error!(
                verbosity = 2,
                "No route to {}; skipping UDP probe to {}:{}", target.ip, target.ip, target.port
            );
            return;
        };

        if send_udp(
            self.transport.tx.as_ref(),
            self.src_port,
            src_addr,
            target.ip,
            target.port,
        )
        .is_some()
        {
            self.pending
                .insert((target.ip, target.port), Instant::now());
        }
    }

    /// Classifies one captured reply and, if it answers an outstanding probe,
    /// resolves that probe.
    fn handle_reply(&mut self, reply: &CapturedSegment) {
        let classified = match reply.protocol {
            IpNextHeaderProtocols::Udp => answering_probe(&reply.bytes, self.src_port)
                .map(|port| ((reply.source, port), PortState::Open)),
            IpNextHeaderProtocols::Icmp => quoted_by_icmpv4(&reply.bytes, self.src_port),
            IpNextHeaderProtocols::Icmpv6 => quoted_by_icmpv6(&reply.bytes, self.src_port),
            _ => None,
        };

        if let Some((target, state)) = classified {
            self.resolve_probe(target, state);
        }
    }

    /// Retires one outstanding probe with the state its reply established,
    /// crediting the round trip to the deadline.
    ///
    /// A reply that matches no pending probe is dropped: it is a duplicate of
    /// one already resolved, or a packet that reached us despite not answering
    /// anything this scan sent.
    fn resolve_probe(&mut self, (ip, port): ProbeTarget, state: PortState) {
        let Some(sent_at) = self.pending.remove(&(ip, port)) else {
            return;
        };

        self.deadline.mark_activity();
        self.deadline.record_rtt(sent_at.elapsed());
        self.record_port(ip, port, state);
    }

    /// Retires probes that have waited longer than [`PROBE_TIMEOUT`].
    ///
    /// Silence is a verdict in UDP, not an absence of one, so there is no
    /// reason to hold it until the end of the scan: expiring probes as they age
    /// streams results to the caller while the scan is still running, and frees
    /// room under [`MAX_IN_FLIGHT`] for the targets still queued behind them.
    ///
    /// An expiry is not activity - nothing answered - so the adaptive deadline
    /// is deliberately left untouched here.
    fn expire_stale_probes(&mut self) {
        let now = Instant::now();
        let stale: Vec<ProbeTarget> = self
            .pending
            .iter()
            .filter(|(_, sent_at)| now.duration_since(**sent_at) >= PROBE_TIMEOUT)
            .map(|(target, _)| *target)
            .collect();

        for target in stale {
            self.pending.remove(&target);
            self.record_port(target.0, target.1, PortState::OpenFiltered);
        }
    }

    /// Marks every probe still outstanding once the scan winds down as
    /// open-filtered. No ICMP error and no UDP reply arrived, which is equally
    /// consistent with a firewall dropping the probe and with a service that
    /// had nothing to say to it.
    ///
    /// [`expire_stale_probes`](Self::expire_stale_probes) retires most probes
    /// long before this runs; what reaches here are the ones still young when
    /// the scan's own deadline ran out.
    fn resolve_remaining_as_filtered(&mut self) {
        let remaining: Vec<ProbeTarget> = self.pending.drain().map(|(key, _)| key).collect();
        for (ip, port) in remaining {
            self.record_port(ip, port, PortState::OpenFiltered);
        }
    }

    /// How long the loop may sleep before it must look at its own state again.
    ///
    /// The adaptive deadline decides this while nothing is outstanding. With
    /// probes in flight the wait is additionally capped at [`PENDING_TICK`], so
    /// an expiry is acted on promptly rather than whenever the deadline
    /// happens to tick - which matters most in the case where *nothing* is
    /// arriving, since then no reply will wake the loop either.
    fn tick_delay(&self) -> Duration {
        let until_deadline_tick = self.deadline.time_until_next_tick();
        if self.pending.is_empty() {
            until_deadline_tick
        } else {
            until_deadline_tick.min(PENDING_TICK)
        }
    }

    fn record_port(&mut self, ip: IpAddr, port_num: u16, state: PortState) {
        let port = crate::fingerprinting::baseline_port(port_num, Protocol::Udp, state);
        self.ctx.update_host(ip, |host| host.add_port(port));
    }
}

/// The port a direct UDP reply answers for, if the datagram is addressed to
/// this scan's source port.
///
/// The capture filter already narrows the UDP half to `src_port`, but that is a
/// performance boundary rather than a guarantee: a transport can be built with
/// no filter at all (`ProbeTransport::from_parts`), and a filter that silently
/// stopped matching would otherwise turn into false `Open`s. The check is cheap
/// and it is the only thing making the reply *ours*.
fn answering_probe(bytes: &[u8], src_port: u16) -> Option<u16> {
    let udp = UdpPacket::new(bytes)?;
    if udp.get_destination() != src_port {
        return None;
    }
    Some(udp.get_source())
}

/// What an ICMPv4 Destination Unreachable code says about the port that
/// provoked it, or `None` if it says nothing usable.
///
/// Only "port unreachable" reports on the port itself: something received the
/// datagram, looked for a listener, and found none. The rest describe the
/// *path* - a filter, a routing failure, a policy - and prove only that the
/// probe did not arrive, which is [`PortState::Filtered`]. The remaining codes
/// (network unknown, fragmentation needed, source route failed) are neither,
/// and leave the probe outstanding to time out on its own.
fn icmpv4_verdict(code: IcmpCode) -> Option<PortState> {
    match code {
        IcmpCodes::DestinationPortUnreachable => Some(PortState::Closed),
        IcmpCodes::DestinationHostUnreachable
        | IcmpCodes::DestinationProtocolUnreachable
        | IcmpCodes::NetworkAdministrativelyProhibited
        | IcmpCodes::HostAdministrativelyProhibited
        | IcmpCodes::CommunicationAdministrativelyProhibited => Some(PortState::Filtered),
        _ => None,
    }
}

/// The ICMPv6 counterpart of [`icmpv4_verdict`] (RFC 4443 §3.1).
///
/// Code 4 is the port-unreachable equivalent. Codes 1, 5, and 6 are explicit
/// refusals by policy, so they read as filtered on the same reasoning as their
/// v4 counterparts. Codes 0, 2, and 3 (no route, beyond scope, address
/// unreachable) describe an unreachable *host* rather than a blocked probe, and
/// are deliberately left unclassified rather than guessed at.
fn icmpv6_verdict(code: Icmpv6Code) -> Option<PortState> {
    match code {
        ICMPV6_PORT_UNREACHABLE => Some(PortState::Closed),
        ICMPV6_ADMIN_PROHIBITED | ICMPV6_INGRESS_EGRESS_POLICY | ICMPV6_REJECT_ROUTE => {
            Some(PortState::Filtered)
        }
        _ => None,
    }
}

/// The probe an ICMPv4 Destination Unreachable refers to and what it says about
/// it, read from the datagram the error quotes.
///
/// `None` if it is some other ICMP message, carries a code that reports on
/// neither the port nor the path, or quotes a datagram this scan did not send.
fn quoted_by_icmpv4(bytes: &[u8], src_port: u16) -> Option<(ProbeTarget, PortState)> {
    let unreachable = DestinationUnreachablePacket::new(bytes)?;
    if unreachable.get_icmp_type() != IcmpTypes::DestinationUnreachable {
        return None;
    }
    let state = icmpv4_verdict(unreachable.get_icmp_code())?;
    Some((quoted_probe(unreachable.payload(), src_port)?, state))
}

/// The ICMPv6 counterpart of [`quoted_by_icmpv4`].
fn quoted_by_icmpv6(bytes: &[u8], src_port: u16) -> Option<(ProbeTarget, PortState)> {
    let unreachable = Icmpv6Packet::new(bytes)?;
    if unreachable.get_icmpv6_type() != Icmpv6Types::DestinationUnreachable {
        return None;
    }
    let state = icmpv6_verdict(unreachable.get_icmpv6_code())?;
    let quoted = unreachable.payload().get(ICMPV6_UNUSED_LEN..)?;
    Some((quoted_probe(quoted, src_port)?, state))
}

/// Identifies the probe quoted inside an ICMP error.
///
/// The quotation is an IP header followed by at least the first eight bytes of
/// the original datagram, which for UDP is the entire header. Its *source* port
/// is what this scan sent from, so it authenticates the error as answering us;
/// its destination address and port name the probe to retire. Both come from
/// the quotation rather than from the error's own header, so an error relayed
/// by a router still points at the host the probe was aimed at.
///
/// Every field here is chosen by a remote host, so nothing is assumed: the
/// quotation is parsed with the same bounds-checked path as a captured packet
/// ([`frame::parse_ip_segment`]), and a quotation that is truncated, is not
/// UDP, or names a different source port yields `None`.
fn quoted_probe(quoted_packet: &[u8], src_port: u16) -> Option<ProbeTarget> {
    let quoted = frame::parse_ip_segment(quoted_packet)?;
    if quoted.protocol != IpNextHeaderProtocols::Udp {
        return None;
    }

    let udp = UdpPacket::new(quoted.payload)?;
    if udp.get_source() != src_port {
        return None;
    }

    Some((quoted.destination, udp.get_destination()))
}

#[async_trait]
impl PortScanner for UdpPortScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::UdpPort
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        vec![Protocol::Udp]
    }

    /// Consumes `targets`, sending a UDP probe for each UDP target and classifying
    /// every reply (or ICMP error), until each probe has been resolved or the
    /// scan's deadline expires. Anything still outstanding when the loop ends is
    /// reported as OpenFiltered.
    ///
    /// New targets are admitted only while fewer than [`MAX_IN_FLIGHT`] probes
    /// are outstanding. That ceiling is what paces the scan: probes leave as
    /// earlier ones are answered or expire, so the send rate settles at the
    /// rate the network is actually resolving them instead of at the rate the
    /// dispatcher can produce them.
    async fn scan(&mut self, mut targets: mpsc::Receiver<Target>) -> anyhow::Result<()> {
        let mut sending_finished = false;

        loop {
            self.expire_stale_probes();

            if self.ctx.handle.should_stop() || self.deadline.has_expired() {
                break;
            }
            if sending_finished && self.pending.is_empty() {
                break;
            }

            // Both are read off `self` before the `select!`, which borrows the
            // receive half mutably for the duration of the statement.
            let admitting = !sending_finished && self.pending.len() < MAX_IN_FLIGHT;
            let tick = self.tick_delay();

            tokio::select! {
                target = targets.recv(), if admitting => {
                    match target {
                        Some(target) => self.send_probe(target),
                        None => sending_finished = true,
                    }
                }

                res = self.transport.rx.recv() => {
                    match res {
                        Some(reply) => self.handle_reply(&reply),
                        None => break,
                    }
                }

                // Wakes periodically so the checks above are re-evaluated
                // even when no further replies arrive.
                _ = tokio::time::sleep(tick) => {}
            }
        }

        self.resolve_remaining_as_filtered();
        Ok(())
    }

    // No `detect_services` override. The second pass in
    // [`service`](crate::scanner::service) opens a TCP connection to each open
    // port, so it identifies nothing this scanner found - and running it here
    // as well as from the SYN scanner beside us would fingerprint every open
    // *TCP* port twice, once per composite member. Identifying a UDP service
    // needs a UDP conversation, which is tracked separately (see
    // `docs/fingerprinting.md`, "UDP fingerprinting"); until that exists the
    // trait's no-op default is the honest implementation.
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
    use pnet::packet::icmp::IcmpCode;
    use pnet::packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket;
    use pnet::packet::icmpv6::MutableIcmpv6Packet;

    use crate::core::session::ScanSession;
    use crate::network::capture::CaptureGuard;
    use crate::network::probe::{MockSender, ProbeTransport};
    use crate::protocols::{ip, udp};

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
    const TARGET_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 200));
    /// A router between us and the target, which reports errors under its own
    /// address rather than the target's.
    const ROUTER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    /// This host's addresses, as the scanner's source resolver reports them.
    const LOCAL_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
    const LOCAL_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50));
    /// The fixed source port the scanner under test probes from.
    const SCAN_SRC_PORT: u16 = 54_321;

    fn on_link_interface() -> pnet::datalink::NetworkInterface {
        pnet::datalink::NetworkInterface {
            name: "test0".to_string(),
            description: String::new(),
            index: 0,
            mac: None,
            ips: vec![
                IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 50), 24).unwrap()),
                IpNetwork::V6(
                    Ipv6Network::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50), 64).unwrap(),
                ),
            ],
            flags: 0,
        }
    }

    fn scanner_with_mock() -> (UdpPortScanner, ScanSession) {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let transport = ProbeTransport::from_parts(
            Box::new(MockSender::default()),
            reply_rx,
            CaptureGuard::noop(),
        );
        let resolver = SourceResolver::from_interfaces(&[on_link_interface()]);

        let scanner = UdpPortScanner {
            resolver,
            ctx,
            transport,
            deadline: AdaptiveDeadline::new(DEADLINE_CONFIG, 8),
            pending: PendingProbes::new(),
            src_port: SCAN_SRC_PORT,
        };
        (scanner, session)
    }

    fn probe(scanner: &mut UdpPortScanner, ip: IpAddr, port: u16) {
        scanner.send_probe(Target {
            ip,
            port,
            protocol: Protocol::Udp,
        });
    }

    fn port_state(session: &ScanSession, ip: IpAddr, port: u16) -> Option<PortState> {
        session
            .store
            .get(&ip)
            .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
    }

    /// A reply as the capture layer would deliver it: bytes plus the protocol
    /// the IP header said they are.
    fn captured(
        source: IpAddr,
        protocol: pnet::packet::ip::IpNextHeaderProtocol,
        bytes: Vec<u8>,
    ) -> CapturedSegment {
        CapturedSegment {
            source,
            protocol,
            bytes,
        }
    }

    /// A direct UDP reply from `src_port`, addressed back to `dst_port`.
    fn udp_reply(src_port: u16, dst_port: u16) -> CapturedSegment {
        captured(
            TARGET,
            IpNextHeaderProtocols::Udp,
            udp::create_packet(&TARGET, &LOCAL_V4, src_port, dst_port, vec![]).unwrap(),
        )
    }

    /// The quoted datagram an ICMP error carries: the IP header of the probe
    /// plus its UDP header. Built with the very functions that build a real
    /// probe, so the test agrees with the wire by construction rather than by
    /// a hand-written byte array.
    fn quoted_probe_packet(from: IpAddr, to: IpAddr, src_port: u16, dst_port: u16) -> Vec<u8> {
        let datagram = udp::create_packet(&from, &to, src_port, dst_port, vec![]).unwrap();
        let len = datagram.len() as u16;
        let header = match (from, to) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                ip::create_ipv4_header(s, d, len, IpNextHeaderProtocols::Udp).unwrap()
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                ip::create_ipv6_header(s, d, len, IpNextHeaderProtocols::Udp).unwrap()
            }
            _ => panic!("IP version mismatch in test fixture"),
        };
        header.into_iter().chain(datagram).collect()
    }

    /// An ICMPv4 error of `code` from `from`, quoting a probe sent to
    /// `to:dst_port` from `src_port`.
    fn icmpv4_error(
        from: IpAddr,
        code: IcmpCode,
        to: IpAddr,
        src_port: u16,
        dst_port: u16,
    ) -> CapturedSegment {
        let quoted = quoted_probe_packet(LOCAL_V4, to, src_port, dst_port);
        let mut buf = vec![0u8; DestinationUnreachablePacket::minimum_packet_size() + quoted.len()];
        let mut packet = MutableDestinationUnreachablePacket::new(&mut buf).unwrap();
        packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
        packet.set_icmp_code(code);
        packet.set_payload(&quoted);
        captured(from, IpNextHeaderProtocols::Icmp, buf)
    }

    /// An ICMPv6 error of `code`, quoting a probe sent to `to:dst_port`.
    fn icmpv6_error(code: Icmpv6Code, to: IpAddr, src_port: u16, dst_port: u16) -> CapturedSegment {
        let quoted = quoted_probe_packet(LOCAL_V6, to, src_port, dst_port);
        let mut buf =
            vec![0u8; Icmpv6Packet::minimum_packet_size() + ICMPV6_UNUSED_LEN + quoted.len()];
        let mut packet = MutableIcmpv6Packet::new(&mut buf).unwrap();
        packet.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
        packet.set_icmpv6_code(code);
        // Four unused bytes precede the quotation (RFC 4443 §3.1).
        let mut payload = vec![0u8; ICMPV6_UNUSED_LEN];
        payload.extend_from_slice(&quoted);
        packet.set_payload(&payload);
        captured(to, IpNextHeaderProtocols::Icmpv6, buf)
    }

    #[test]
    fn direct_udp_reply_is_open() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(&udp_reply(53, SCAN_SRC_PORT));

        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Open));
        assert!(scanner.pending.is_empty());
    }

    /// A datagram from a pending port that is *not* addressed to this scan's
    /// source port answers some other conversation on the host, not our probe.
    #[test]
    fn udp_traffic_not_addressed_to_the_scan_is_ignored() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(&udp_reply(53, SCAN_SRC_PORT.wrapping_add(1)));

        assert_eq!(port_state(&session, TARGET, 53), None);
        assert_eq!(scanner.pending.len(), 1);
    }

    #[test]
    fn icmp_port_unreachable_is_closed() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(&icmpv4_error(
            TARGET,
            IcmpCodes::DestinationPortUnreachable,
            TARGET,
            SCAN_SRC_PORT,
            53,
        ));

        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Closed));
        assert!(scanner.pending.is_empty());
    }

    /// The regression guard for the classification bug this scanner shipped
    /// with: an unreachable message names one port in its quoted datagram, and
    /// must retire that probe alone. Every other probe to the same host is
    /// still outstanding and must stay that way.
    #[test]
    fn icmp_unreachable_closes_only_the_port_it_quotes() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);
        probe(&mut scanner, TARGET, 161);
        probe(&mut scanner, TARGET, 123);

        scanner.handle_reply(&icmpv4_error(
            TARGET,
            IcmpCodes::DestinationPortUnreachable,
            TARGET,
            SCAN_SRC_PORT,
            161,
        ));

        assert_eq!(port_state(&session, TARGET, 161), Some(PortState::Closed));
        assert_eq!(port_state(&session, TARGET, 53), None);
        assert_eq!(port_state(&session, TARGET, 123), None);
        assert_eq!(scanner.pending.len(), 2);
    }

    /// An error relayed by a router carries the router's address, but quotes a
    /// probe aimed at the host behind it. The quoted destination is what
    /// identifies the probe.
    #[test]
    fn unreachable_from_a_router_resolves_the_quoted_target() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(&icmpv4_error(
            ROUTER,
            IcmpCodes::DestinationPortUnreachable,
            TARGET,
            SCAN_SRC_PORT,
            53,
        ));

        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Closed));
        assert_eq!(port_state(&session, ROUTER, 53), None);
    }

    /// An unreachable quoting a datagram this scan never sent - a different
    /// source port - belongs to someone else's traffic.
    #[test]
    fn unreachable_quoting_a_foreign_probe_is_ignored() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(&icmpv4_error(
            TARGET,
            IcmpCodes::DestinationPortUnreachable,
            TARGET,
            SCAN_SRC_PORT.wrapping_add(1),
            53,
        ));

        assert_eq!(port_state(&session, TARGET, 53), None);
        assert_eq!(scanner.pending.len(), 1);
    }

    /// Only code 3 says a port answered. The codes that describe a blocked
    /// path prove the probe did not arrive, which is `Filtered` - a strictly
    /// better answer than letting the probe time out into `OpenFiltered`.
    #[test]
    fn administratively_prohibited_icmp_is_filtered() {
        for code in [
            IcmpCodes::DestinationHostUnreachable,
            IcmpCodes::DestinationProtocolUnreachable,
            IcmpCodes::NetworkAdministrativelyProhibited,
            IcmpCodes::HostAdministrativelyProhibited,
            IcmpCodes::CommunicationAdministrativelyProhibited,
        ] {
            let (mut scanner, session) = scanner_with_mock();
            probe(&mut scanner, TARGET, 53);

            scanner.handle_reply(&icmpv4_error(TARGET, code, TARGET, SCAN_SRC_PORT, 53));

            assert_eq!(
                port_state(&session, TARGET, 53),
                Some(PortState::Filtered),
                "ICMP code {code:?} should read as filtered"
            );
        }
    }

    /// A code that reports on neither the port nor the path leaves the probe
    /// outstanding, to time out into `OpenFiltered` like any other silence.
    #[test]
    fn uninformative_icmp_codes_leave_the_probe_outstanding() {
        for code in [
            IcmpCodes::DestinationNetworkUnknown,
            IcmpCodes::FragmentationRequiredAndDFFlagSet,
            IcmpCodes::SourceRouteFailed,
        ] {
            let (mut scanner, session) = scanner_with_mock();
            probe(&mut scanner, TARGET, 53);

            scanner.handle_reply(&icmpv4_error(TARGET, code, TARGET, SCAN_SRC_PORT, 53));

            assert_eq!(port_state(&session, TARGET, 53), None, "code {code:?}");
            assert_eq!(scanner.pending.len(), 1, "code {code:?}");
        }
    }

    #[test]
    fn icmpv6_policy_refusals_are_filtered() {
        for code in [
            ICMPV6_ADMIN_PROHIBITED,
            ICMPV6_INGRESS_EGRESS_POLICY,
            ICMPV6_REJECT_ROUTE,
        ] {
            let (mut scanner, session) = scanner_with_mock();
            probe(&mut scanner, TARGET_V6, 53);

            scanner.handle_reply(&icmpv6_error(code, TARGET_V6, SCAN_SRC_PORT, 53));

            assert_eq!(
                port_state(&session, TARGET_V6, 53),
                Some(PortState::Filtered),
                "ICMPv6 code {code:?} should read as filtered"
            );
        }
    }

    /// An ICMP error's first two bytes (type 3, code 3) read as the source port
    /// 771 if the segment is parsed as UDP. Carrying the protocol from the IP
    /// header is what stops that from becoming a false `Open`.
    #[test]
    fn icmp_error_is_never_read_as_a_udp_reply() {
        let (mut scanner, session) = scanner_with_mock();
        // 0x0303: what an ICMPv4 unreachable's type/code look like as a port.
        probe(&mut scanner, TARGET, 771);
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(&icmpv4_error(
            TARGET,
            IcmpCodes::DestinationPortUnreachable,
            TARGET,
            SCAN_SRC_PORT,
            53,
        ));

        assert_eq!(port_state(&session, TARGET, 771), None);
        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Closed));
    }

    #[test]
    fn icmpv6_port_unreachable_is_closed() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET_V6, 53);

        scanner.handle_reply(&icmpv6_error(
            ICMPV6_PORT_UNREACHABLE,
            TARGET_V6,
            SCAN_SRC_PORT,
            53,
        ));

        assert_eq!(port_state(&session, TARGET_V6, 53), Some(PortState::Closed));
        assert!(scanner.pending.is_empty());
    }

    /// ICMPv6 code 0 is "no route to destination" - a statement about the path.
    #[test]
    fn icmpv6_no_route_is_ignored() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET_V6, 53);

        scanner.handle_reply(&icmpv6_error(Icmpv6Code(0), TARGET_V6, SCAN_SRC_PORT, 53));

        assert_eq!(port_state(&session, TARGET_V6, 53), None);
        assert_eq!(scanner.pending.len(), 1);
    }

    /// A truncated or malformed reply must be dropped, never panic: every byte
    /// of it was chosen by a remote host.
    #[test]
    fn malformed_replies_are_dropped() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        for len in 0..48usize {
            let bytes = vec![0xFFu8; len];
            for protocol in [
                IpNextHeaderProtocols::Udp,
                IpNextHeaderProtocols::Icmp,
                IpNextHeaderProtocols::Icmpv6,
            ] {
                scanner.handle_reply(&captured(TARGET, protocol, bytes.clone()));
            }
        }

        assert_eq!(port_state(&session, TARGET, 53), None);
        assert_eq!(scanner.pending.len(), 1);
    }

    /// Checks the quoted-datagram parse against an ICMP error this machine's
    /// own kernel produced, rather than one this test module built. Every
    /// other test here agrees with the wire only as far as our own encoder
    /// does; this one closes that loop.
    ///
    /// It drives the real receive path - a `libpcap` capture with the same
    /// filter a scan uses - but sends its probe from an ordinary `UdpSocket`,
    /// so it needs capture access (root, or `access_bpf` membership on macOS)
    /// but not raw sockets. Ignored by default because that access is not
    /// something a test run can assume; run it with
    /// `cargo test -- --ignored real_kernel_icmp_error`.
    #[tokio::test]
    #[ignore = "needs libpcap capture access (root or access_bpf)"]
    async fn real_kernel_icmp_error_identifies_the_probe_that_caused_it() {
        use crate::network::capture;
        use std::time::Duration;

        let loopback = pnet::datalink::interfaces()
            .into_iter()
            .find(|iface| iface.is_loopback() && iface.is_up())
            .expect("a loopback interface to capture on");

        // Stands in for the scan's fixed source port: replies and errors are
        // matched against whatever port the probes went out from.
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let src_port = socket.local_addr().unwrap().port();

        // A port nothing listens on, so the kernel answers with an error:
        // bind one to learn a free number, then release it.
        let reserved = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let closed_port = reserved.local_addr().unwrap().port();
        drop(reserved);

        let filter = format!("icmp or icmp6 or (udp and dst port {src_port})");
        let (mut rx, _capture) = capture::start(&[loopback.name], &filter).unwrap();
        // The capture threads open their devices asynchronously; a probe sent
        // before they are listening would simply not be seen.
        tokio::time::sleep(Duration::from_millis(500)).await;

        socket
            .send_to(b"", ("127.0.0.1", closed_port))
            .await
            .unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("kernel produced no ICMP error within 3s")
            .expect("capture stream closed");

        assert_eq!(reply.protocol, IpNextHeaderProtocols::Icmp);
        assert_eq!(
            quoted_by_icmpv4(&reply.bytes, src_port),
            Some((
                (IpAddr::V4(Ipv4Addr::LOCALHOST), closed_port),
                PortState::Closed
            )),
            "a real ICMP error must name the exact probe that caused it",
        );
    }

    /// The companion to the ICMP check above, for the other half of the
    /// classification: a real reply from a real listener, arriving through the
    /// real capture filter.
    ///
    /// A filter that compiles but never matches would turn every open port
    /// into `OpenFiltered` - the scan would keep running and keep reporting,
    /// just never positively. Only live traffic can catch that.
    #[tokio::test]
    #[ignore = "needs libpcap capture access (root or access_bpf)"]
    async fn real_udp_reply_reaches_the_scan_through_the_capture_filter() {
        use crate::network::capture;
        use std::time::Duration;

        let loopback = pnet::datalink::interfaces()
            .into_iter()
            .find(|iface| iface.is_loopback() && iface.is_up())
            .expect("a loopback interface to capture on");

        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let src_port = socket.local_addr().unwrap().port();

        // A listener that answers once, so there is a genuine reply to catch.
        let service = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let service_port = service.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            if let Ok((_, from)) = service.recv_from(&mut buf).await {
                let _ = service.send_to(b"pong", from).await;
            }
        });

        let filter = format!("icmp or icmp6 or (udp and dst port {src_port})");
        let (mut rx, _capture) = capture::start(&[loopback.name], &filter).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        socket
            .send_to(b"ping", ("127.0.0.1", service_port))
            .await
            .unwrap();

        // The filter also admits ICMP, which loopback may carry for unrelated
        // reasons; take the first UDP segment rather than assuming it is first.
        let reply = tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(segment) = rx.recv().await {
                if segment.protocol == IpNextHeaderProtocols::Udp {
                    return segment;
                }
            }
            panic!("capture stream closed before a UDP reply arrived");
        })
        .await
        .expect("no UDP reply captured within 3s");

        assert_eq!(
            answering_probe(&reply.bytes, src_port),
            Some(service_port),
            "a real reply must resolve to the port that sent it",
        );
    }

    /// A probe older than [`PROBE_TIMEOUT`] is written off while the scan is
    /// still running, so results reach the caller as they are decided rather
    /// than all at once at the end.
    #[test]
    fn probes_older_than_the_timeout_expire_during_the_scan() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);
        probe(&mut scanner, TARGET, 161);

        // Age one probe past the timeout, leaving the other fresh.
        let aged = Instant::now() - PROBE_TIMEOUT - Duration::from_millis(1);
        scanner.pending.insert((TARGET, 53), aged);

        scanner.expire_stale_probes();

        assert_eq!(
            port_state(&session, TARGET, 53),
            Some(PortState::OpenFiltered)
        );
        assert_eq!(port_state(&session, TARGET, 161), None, "still waiting");
        assert_eq!(scanner.pending.len(), 1);
    }

    /// Expiring a probe is not activity: nothing answered, so the adaptive
    /// deadline must not be told the scan is making progress.
    #[test]
    fn expiry_does_not_extend_the_deadline() {
        let (mut scanner, _session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);
        scanner
            .pending
            .insert((TARGET, 53), Instant::now() - PROBE_TIMEOUT);

        // A deadline whose silence clock has been reset reports a full tick;
        // capture the value before and after to see whether it moved.
        let before = scanner.deadline.time_until_next_tick();
        scanner.expire_stale_probes();
        let after = scanner.deadline.time_until_next_tick();

        assert!(
            after <= before,
            "silence clock was reset by an expiry ({before:?} -> {after:?})"
        );
    }

    /// While probes are outstanding the loop must not sleep past the point
    /// where the next one can expire - nothing else will wake it, because
    /// silence is exactly the case being timed.
    #[test]
    fn pending_probes_shorten_the_sleep() {
        let (mut scanner, _session) = scanner_with_mock();
        assert!(scanner.pending.is_empty());
        let idle = scanner.tick_delay();

        probe(&mut scanner, TARGET, 53);
        let busy = scanner.tick_delay();

        assert!(
            busy <= PENDING_TICK,
            "sleep not capped while probes are out"
        );
        assert!(idle > PENDING_TICK, "idle tick should follow the deadline");
    }

    /// The UDP profile has to tolerate silence for longer than a host's ICMP
    /// rate-limit interval (~1/sec), or a scan concludes while its answers are
    /// still queued. This is the property that makes it a separate profile from
    /// the SYN one, so it is asserted rather than left to a comment.
    #[test]
    fn silence_floor_outlasts_the_icmp_rate_limit() {
        const ICMP_RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(1);

        assert!(
            DEADLINE_CONFIG.silence_floor > ICMP_RATE_LIMIT_INTERVAL,
            "silence floor {:?} is shorter than one rate-limited answer",
            DEADLINE_CONFIG.silence_floor
        );
        assert!(
            super::super::DEADLINE_CONFIG.silence_floor < ICMP_RATE_LIMIT_INTERVAL,
            "the SYN profile was expected to be the tighter one"
        );
    }

    #[test]
    fn unanswered_probes_resolve_as_filtered() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 161);

        scanner.resolve_remaining_as_filtered();

        assert_eq!(
            port_state(&session, TARGET, 161),
            Some(PortState::OpenFiltered)
        );
        assert!(scanner.pending.is_empty());
    }

    #[test]
    fn non_udp_targets_are_not_probed() {
        let (mut scanner, _session) = scanner_with_mock();
        scanner.send_probe(Target {
            ip: TARGET,
            port: 80,
            protocol: Protocol::Tcp,
        });
        assert!(scanner.pending.is_empty());
    }

    /// Every probe in a scan must leave from the one port the capture filter
    /// and the quoted-datagram check are built around.
    #[test]
    fn every_probe_is_sent_from_the_scan_source_port() {
        let (_session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport =
            ProbeTransport::from_parts(Box::new(sender), reply_rx, CaptureGuard::noop());
        let mut scanner = UdpPortScanner {
            resolver: SourceResolver::from_interfaces(&[on_link_interface()]),
            ctx,
            transport,
            deadline: AdaptiveDeadline::new(DEADLINE_CONFIG, 8),
            pending: PendingProbes::new(),
            src_port: SCAN_SRC_PORT,
        };

        for port in [53, 161, 123] {
            probe(&mut scanner, TARGET, port);
        }

        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 3);
        for (segment, _src, _dst) in sent.iter() {
            let udp = UdpPacket::new(segment).expect("probe is a UDP datagram");
            assert_eq!(udp.get_source(), SCAN_SRC_PORT);
        }
    }
}
