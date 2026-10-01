// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Passive listening
//!
//! The strategy behind [`listen`](crate::scanner::listen). It opens a capture,
//! reads what the link already carries, and records what that proves. It sends
//! nothing at all.
//!
//! ## Only ever a positive claim
//!
//! A listener sent nothing, so it cannot time out. An address it never heard
//! from may be absent, silent, behind a switch that never forwarded a frame
//! this way, or on a VLAN this link does not carry.
//!
//! So this raises claims and never lowers one. It records a host as
//! [`Up`](HostStatus::Up), adds roles, names and hardware addresses, and never
//! contradicts or removes anything. The phase's scope,
//! [`TargetScope::listening_on`](crate::report::TargetScope::listening_on),
//! covers no address, so a comparison cannot read a host that stayed quiet as
//! one that went away.
//!
//! ## What it believes
//!
//! Every frame arrives unauthenticated, with no probe to correlate against;
//! anything on a segment can forge any source and hardware address. So a frame
//! is credited to its sender and nobody else: a claim about a third address is
//! read for what the *sender* is, as `local`'s `note_declaration` does for an
//! overheard router advertisement.
//!
//! ## Bounds
//!
//! A listener asked about nothing and runs until stopped, so what it holds
//! grows with the traffic; on [`Recording::Everything`] over a transit link,
//! that is most of the internet. Three constants bound it: `MAX_RECORDED_HOSTS`
//! (machines recorded), `MAX_DECLARING_MACS` (claims held against unidentified
//! machines) and `LISTEN_QUEUE_DEPTH` (frames waiting to be read). Each reports
//! itself when it bites, as the kernel's drop counter does at the end of every
//! run, since a silent limit looks like a quiet network.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::config::OsDetection;
use crate::fingerprint::os;
use crate::model::host::{Host, HostStatus, NetworkRole, StatusProtocol, StatusReason};
use crate::model::ip::scoped::{ScopedIp, Zone};
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;
use crate::model::port::discovery::{Discovery, ScanResponse};
use crate::model::port::{Port, PortState, Protocol};
use crate::model::technique::TcpReply;
use crate::protocols::ethernet::{self, Frame};
use crate::protocols::{cdp, dhcp, lldp, tcp};
use crate::report::ScannerKind;
use crate::report::{Attachment, AttachmentSource};
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::StrategyError;
use crate::scanner::strategy::frames::{self, DiscoveryProtocol, ProtocolMatch};
use crate::transport::capture::{self, CaptureFilter, CaptureOptions, CapturedFrame, FrameStream};
use crate::transport::frame::{self as transport_frame, LinkType};
use crate::{info, warn};
use pnet_packet::ethernet::{EtherType, EtherTypes};

/// How much of each frame the kernel keeps for a listener.
///
/// This is the payload boundary, enforced by the kernel. A listener sees other
/// people's traffic, and this keeps it from reading session contents even by
/// mistake. Everything this module concludes comes from link, network and
/// transport headers plus the start of a control-plane message.
///
/// Enough for the largest thing read, an LLDP advertisement with a long system
/// description, and far short of a payload.
const LISTEN_SNAP_LEN: u32 = 512;

/// How much the kernel may hold for a listening capture before it discards.
///
/// Larger than a scan's reply path, whose arrivals are bounded by the probes it
/// sent; a listener's are bounded only by the network.
const LISTEN_BUFFER_BYTES: u32 = 4 * 1024 * 1024;

/// How many frames may wait for the reader at once.
///
/// Times [`LISTEN_SNAP_LEN`], this is the queue's memory. A full queue stalls
/// the capture thread, so losses are counted by the kernel; see
/// [`capture::frames`].
const LISTEN_QUEUE_DEPTH: usize = 4096;

/// How many machines may have a claim held against them at once.
///
/// A declaration is filed against the hardware address that made it and applied
/// once that machine has a host record. Until then it grows from frames nobody
/// asked for, so it is capped; past this many distinct speakers the surplus is
/// noise.
const MAX_DECLARING_MACS: usize = 4096;

/// How many machines a watch will record before it stops taking new ones.
///
/// A listener runs until stopped and records whatever arrives, so on
/// [`Recording::Everything`] over a transit link a week-long watch would
/// otherwise run the machine out of memory. A `/16` of machines is far more
/// than a segment carries, so the default [`Recording::Attached`] scope will
/// not reach it on a real link.
///
/// Reaching it stops new records and keeps existing ones: evicting would lower
/// a claim, and a dropped host looks like one never heard. It is reported as a
/// failure, so the report and the run's exit status say the inventory is short.
const MAX_RECORDED_HOSTS: usize = 65_536;

/// How often a listener checks the abort signal while nothing is arriving,
/// since a link can be silent for hours.
const ABORT_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// The address that sent an IP packet of either family, told apart by the
/// version nibble.
fn ip_source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 => Some(IpAddr::V4(
            pnet_packet::ipv4::Ipv4Packet::new(packet)?.get_source(),
        )),
        6 => Some(IpAddr::V6(
            pnet_packet::ipv6::Ipv6Packet::new(packet)?.get_source(),
        )),
        _ => None,
    }
}

/// The TCP segment inside an IP packet, and the address that sent it, where
/// the packet carries one.
///
/// Takes the packet, so it works behind an Ethernet header, a cooked one, or
/// none on a tunnel.
///
/// Reads only the fixed header's protocol field, so a segment behind an IPv6
/// extension header is reported as not-TCP: declined, never misread.
fn tcp_segment(packet: &[u8]) -> Option<(IpAddr, &[u8])> {
    use pnet_packet::ip::IpNextHeaderProtocols;

    let (source, header_len, next) = match packet.first()? >> 4 {
        4 => {
            let ipv4 = pnet_packet::ipv4::Ipv4Packet::new(packet)?;
            (
                IpAddr::V4(ipv4.get_source()),
                usize::from(ipv4.get_header_length()) * 4,
                ipv4.get_next_level_protocol(),
            )
        }
        6 => {
            let ipv6 = pnet_packet::ipv6::Ipv6Packet::new(packet)?;
            (
                IpAddr::V6(ipv6.get_source()),
                crate::protocols::sizes::IP_V6_HDR_LEN,
                ipv6.get_next_header(),
            )
        }
        _ => return None,
    };

    (next == IpNextHeaderProtocols::Tcp).then(|| Some((source, packet.get(header_len..)?)))?
}

/// The address ranges a listener's links carry.
///
/// A frame from an off-link source shows that its sender forwards. Read once
/// per phase, since the answer is fixed and asked per frame.
///
/// Empty means unknown: a listener that could not read its interface table
/// concludes nothing about forwarding (treating it as authoritative would make
/// every sender a forwarder).
#[derive(Debug, Clone, Default)]
pub struct OnLink {
    ranges: IpSet,
}

impl OnLink {
    /// The ranges `links` carry, read from this machine's interface table.
    pub fn of_links(links: &[Zone]) -> Self {
        let mut ranges = IpSet::new();

        for interface in crate::system::interface::interfaces_or_none() {
            if !links.iter().any(|link| link.name() == interface.name()) {
                continue;
            }
            for held in interface.addresses() {
                ranges.insert_range(held.network());
            }
        }

        Self { ranges }
    }

    /// The ranges a caller states, for a listener not reading a real interface.
    pub fn of(ranges: IpSet) -> Self {
        Self { ranges }
    }

    /// Whether `address` is one this link could plausibly have sourced itself.
    ///
    /// These are on-link whatever the ranges say, since a frame from one never
    /// proves forwarding:
    ///
    /// - **unspecified**, a client with no address yet;
    /// - **loopback**, never on a wire at all;
    /// - **link-local**, both families, scoped to this segment by definition;
    /// - **multicast**, not a valid source address, and no basis for a
    ///   conclusion if one appears.
    fn contains(&self, address: IpAddr) -> bool {
        let confined = match address {
            IpAddr::V4(v4) => {
                v4.is_unspecified() || v4.is_loopback() || v4.is_link_local() || v4.is_multicast()
            }
            IpAddr::V6(v6) => {
                v6.is_unspecified()
                    || v6.is_loopback()
                    || v6.is_unicast_link_local()
                    || v6.is_multicast()
            }
        };

        confined || self.ranges.contains(&address)
    }

    /// Whether `address` belongs to a machine attached to this link.
    ///
    /// Differs from [`contains`](Self::contains), which also says yes to the
    /// unspecified address, loopback and multicast: none of those is a machine
    /// to record. A link-local address is admitted whatever the ranges say.
    fn attaches(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(v4) => {
                if v4.is_unspecified() || v4.is_loopback() || v4.is_multicast() {
                    return false;
                }
                v4.is_link_local() || self.ranges.contains(&address)
            }
            IpAddr::V6(v6) => {
                if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() {
                    return false;
                }
                v6.is_unicast_link_local() || self.ranges.contains(&address)
            }
        }
    }

    /// Whether anything is known about this link's addressing at all.
    fn is_stated(&self) -> bool {
        !self.ranges.is_empty()
    }
}

/// Which addresses a listener may record findings about.
///
/// A listener targets nothing and cannot narrow what it receives, so this rule
/// on what reaches the store is its whole scope.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub enum Recording {
    /// Record findings about the machines attached to the links being listened
    /// to, and nothing else.
    ///
    /// The default. A link carrying traffic to elsewhere carries evidence about
    /// elsewhere: on a mirror port, every server a laptop connects to is really
    /// up with a really open port, yet none of it is this network's inventory,
    /// and on a busy uplink it would be most of the report.
    ///
    /// A link with no stated addressing (common for a capture interface on a
    /// mirror port) admits everything, and this is announced when the phase
    /// starts.
    #[default]
    Attached,
    /// Record whatever is heard, wherever it lives: for questions about
    /// traffic, such as which machines elsewhere this network depends on.
    Everything,
    /// Record only findings about these addresses. Other frames are still read
    /// and then dropped before the store.
    Only(IpSet),
}

/// What the equipment on the far end of this machine's cable says about itself,
/// whichever protocol it said it in.
///
/// LLDP and CDP both give the device's name, the port this frame left by, that
/// port's untagged VLAN, and a management address; one shape lets
/// [`read_announcement`] handle both.
///
/// [`read_announcement`]: PassiveListener::read_announcement
struct Announced<'a> {
    /// Which protocol carried it; an attachment records whose word it is on.
    source: AttachmentSource,
    /// What the device calls itself, which on managed equipment is its hostname.
    device_name: Option<&'a str>,
    /// The device's name for the port this frame left by: the port this
    /// machine is plugged into, which no probe can obtain.
    port: Option<&'a str>,
    /// The VLAN this port places untagged traffic in.
    native_vlan: Option<u16>,
    /// An address the device is managed at, where it advertised one.
    management_address: Option<IpAddr>,
    /// What the device says it is **doing**, from the enabled capabilities.
    /// The supported ones would put a router on every access switch with an
    /// unused routing licence.
    roles: Vec<NetworkRole>,
}

impl<'a> Announced<'a> {
    /// Reads `frame` as whichever of the two announcements it is, or `None`
    /// where it is neither.
    ///
    /// LLDP first, as the standard; CDP only where that found nothing, so a
    /// device speaking both is read once.
    fn read(frame: &Frame<'a>) -> Option<Self> {
        if let Some(advertisement) = lldp::parse(frame) {
            let mut roles = Vec::new();
            if let Some(capabilities) = advertisement.capabilities {
                if capabilities.is_bridge() {
                    roles.push(NetworkRole::Switch);
                }
                if capabilities.is_router() {
                    roles.push(NetworkRole::Router);
                }
            }

            return Some(Self {
                source: AttachmentSource::Lldp,
                device_name: advertisement.system_name,
                // Only the text form; a MAC or address identifier cannot be
                // read back to a patch panel.
                port: match advertisement.port_id {
                    Some(lldp::Identifier::Text(port)) => Some(port),
                    _ => None,
                },
                native_vlan: advertisement.port_vlan,
                management_address: advertisement.management_address,
                roles,
            });
        }

        let announcement = cdp::parse(frame)?;

        let mut roles = Vec::new();
        if let Some(capabilities) = announcement.capabilities {
            // CDP's word for LLDP's `is_bridge`.
            if capabilities.is_switch() {
                roles.push(NetworkRole::Switch);
            }
            if capabilities.is_router() {
                roles.push(NetworkRole::Router);
            }
        }

        Some(Self {
            source: AttachmentSource::Cdp,
            device_name: announcement.device_id,
            port: announcement.port_id,
            native_vlan: announcement.native_vlan,
            management_address: announcement.address,
            roles,
        })
    }
}

/// Reads one or more links and records what their traffic proves, having sent
/// nothing.
///
/// Unlike a [`HostScanner`](super::HostScanner) or
/// [`PortScanner`](super::PortScanner), it owns no targets and has no state
/// that can be complete: it finishes when told to, or when its span ends.
///
/// Findings go to the [`ScanContext`] it was built with; the return value says
/// only whether the attempt got to the end.
#[must_use]
pub struct PassiveListener {
    ctx: ScanContext,
    frames: FrameStream,
    /// Dropping this stops the capture threads.
    capture: capture::CaptureGuard,
    recording: Recording,
    on_link: OnLink,
    /// When this listener stops of its own accord, if it was given a span.
    ///
    /// Kept apart from the abort signal, which means a caller asked it to stop
    /// and marks a run interrupted; otherwise `zond listen --for 10m || alert`
    /// would alert every ten minutes.
    deadline: Option<tokio::time::Instant>,

    /// How far this listener may go to name the system behind a host. It sends
    /// nothing either way; `Off` keeps fingerprints out of the report.
    os: OsDetection,
    /// The record each hardware address is kept under: the first address the
    /// machine was seen at.
    ///
    /// Makes a device seen at four addresses one record, and lets a claim about
    /// a *machine* (a router known only by the frames it forwards) be applied
    /// to its host.
    ///
    /// Seeded from the store, so a resumed watch adds to its earlier sittings
    /// (see [`paired_with_known_hosts`]); afterwards it grows only from frames
    /// that produced a finding.
    ///
    /// [`paired_with_known_hosts`]: PassiveListener::paired_with_known_hosts
    mac_to_ip: HashMap<MacAddr, ScopedIp>,
    /// What a machine said about itself before this listener knew which host it
    /// was. Bounded by `MAX_DECLARING_MACS`, since it grows from unsolicited
    /// traffic.
    declared: HashMap<MacAddr, HashSet<NetworkRole>>,
    /// How many records this watch holds, counted from what
    /// [`ScanContext::write_host`] reports as created. Starts at the store's
    /// size, so a resumed watch's earlier sittings count towards the ceiling.
    ///
    /// [`ScanContext::write_host`]: crate::scanner::session::ScanContext::write_host
    held: usize,
    /// Whether the ceiling has been reported, so it is said once.
    said_full: bool,
    /// The same readers a local sweep interprets its replies with.
    protocols: Vec<Box<dyn DiscoveryProtocol>>,
}

impl PassiveListener {
    /// Opens a capture on each of `links` and reads it.
    ///
    /// Fails only when no link could be captured.
    pub fn open(
        links: &[Zone],
        recording: Recording,
        ctx: ScanContext,
    ) -> Result<Self, StrategyError> {
        let options = Self::capture_options();

        // The capture's error names each link and what refused it.
        let (frames, capture) = capture::frames(links, &options, LISTEN_QUEUE_DEPTH)?;

        let on_link = OnLink::of_links(links);

        // The default scope widening to everything; see `Recording::Attached`.
        if matches!(recording, Recording::Attached) && !on_link.is_stated() {
            warn!(
                "no address is configured on {}, so there is nothing to tell this \
                 link's own machines from the traffic merely crossing it; \
                 recording everything heard",
                links.iter().map(Zone::name).collect::<Vec<_>>().join(", "),
            );
        }

        Ok(Self::over(frames, capture, recording, on_link, ctx))
    }

    /// Builds a listener over a caller-supplied frame stream, opening no capture.
    ///
    /// The listening twin of
    /// [`EthernetHandle::from_parts`](crate::transport::channel::EthernetHandle::from_parts):
    /// whatever is pushed onto the sending half of `frames` arrives as though
    /// captured off `on_link`, with no interface or privileges involved. No
    /// sender is needed, since a listener never transmits.
    ///
    /// Requires the `test-support` feature outside this crate.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_parts(
        frames: FrameStream,
        on_link: OnLink,
        recording: Recording,
        ctx: ScanContext,
    ) -> Self {
        Self::over(
            frames,
            capture::CaptureGuard::noop(),
            recording,
            on_link,
            ctx,
        )
    }

    /// Builds a listener over an already-open frame stream and the guard keeping
    /// its capture alive.
    fn over(
        frames: FrameStream,
        capture: capture::CaptureGuard,
        recording: Recording,
        on_link: OnLink,
        ctx: ScanContext,
    ) -> Self {
        let mac_to_ip = Self::paired_with_known_hosts(&ctx);

        Self {
            held: ctx.host_count(),
            ctx,
            frames,
            capture,
            recording,
            on_link,
            os: OsDetection::default(),
            deadline: None,
            mac_to_ip,
            declared: HashMap::new(),
            said_full: false,
            protocols: frames::sweep_protocols(),
        }
    }

    /// The hardware address of every machine the store already knows, paired
    /// with the record it is kept under.
    ///
    /// Makes a resumed watch one watch. A sitting keys each machine by the
    /// first address it hears it at; without seeding, the same laptop restored
    /// under `198.51.100.5` and heard tonight from `fe80::…` would get a second
    /// record. This extends [`record`](Self::record)'s rule across sittings.
    ///
    /// Empty for a watch that was not resumed.
    fn paired_with_known_hosts(ctx: &ScanContext) -> HashMap<MacAddr, ScopedIp> {
        let mut pairs = HashMap::new();

        // Sorted, since the sharded store's key order is arbitrary, so which of
        // two records an earlier sitting split a machine into wins is stable.
        let mut keys = ctx.host_addresses();
        keys.sort_unstable();

        for key in keys {
            let Some(Some(mac)) = ctx.read_host(key.clone(), Host::mac) else {
                // Without a hardware address, `record` merges by address alone.
                continue;
            };
            // The lowest address wins; any stable choice stops the split growing.
            pairs.entry(mac).or_insert(key);
        }

        pairs
    }

    /// Reads the system behind each host at `level`, or at none.
    ///
    /// Defaults to [`OsDetection::Passive`], the most a listener can do: the
    /// readings come from headers already arriving.
    pub fn detecting_os(mut self, level: OsDetection) -> Self {
        self.os = level;
        self
    }

    /// Stops this listener after `span`. Nothing is aborted, so the abort
    /// signal still reports that nobody interrupted the run.
    pub fn stopping_after(mut self, span: std::time::Duration) -> Self {
        self.deadline = Some(tokio::time::Instant::now() + span);
        self
    }

    /// How a listener's capture is opened: promiscuous, narrowed by
    /// [`filter`](Self::filter), and bounded by [`LISTEN_SNAP_LEN`] and
    /// [`LISTEN_BUFFER_BYTES`].
    fn capture_options() -> CaptureOptions {
        CaptureOptions::for_link_traffic(Self::filter())
            .with_snaplen(LISTEN_SNAP_LEN)
            .with_buffer_bytes(LISTEN_BUFFER_BYTES)
    }

    /// What a listener's capture admits.
    ///
    /// Exactly what the readers below can use: a sweep's clauses plus the
    /// announcements and TCP, to see which endpoints serve somebody.
    ///
    /// No DNS or mDNS: their answers name machines other than the sender, and
    /// a frame is credited to its sender alone.
    ///
    /// Built as alternatives ([`CaptureFilter::any_of`]) because a tunnel, PPP
    /// link or loopback has no hardware address; the clauses naming one would
    /// otherwise refuse the whole link, TCP included.
    fn filter() -> CaptureFilter {
        let mut clauses: Vec<&'static str> = frames::sweep_protocols()
            .iter()
            .map(|protocol| protocol.capture_clause())
            .collect();

        clauses.extend([
            // LLDP and CDP.
            "(ether proto 0x88cc)",
            "(ether dst 01:00:0c:cc:cc:cc)",
            // Handshakes; see `read_endpoint`.
            "(tcp)",
        ]);

        clauses.sort_unstable();
        clauses.dedup();
        CaptureFilter::any_of(clauses)
    }

    /// Reads one frame for everything it proves.
    ///
    /// Every applicable reader is tried, since a frame can carry more than one
    /// finding.
    fn read(&mut self, captured: &CapturedFrame) {
        // Without Ethernet there is only IP: a TCP segment, or a neighbour or
        // router advertisement.
        if captured.link != LinkType::Ethernet {
            if let Some(packet) = transport_frame::strip_to_ip(captured.link, &captured.bytes)
                && !self.read_endpoint(packet, None, captured)
            {
                self.read_presence_in(packet, &captured.zone);
            }
            return;
        }
        let Ok(frame) = ethernet::parse(&captured.bytes) else {
            return;
        };

        if self.read_announcement(&frame, captured) {
            return;
        }
        self.read_forwarding(&frame);

        let carries_ip = matches!(
            EtherType(frame.ethertype()),
            EtherTypes::Ipv4 | EtherTypes::Ipv6
        );
        if carries_ip && self.read_endpoint(frame.payload(), Some(frame.source()), captured) {
            return;
        }
        self.read_client(&frame, &captured.zone);
        self.read_presence(&frame, &captured.zone);
    }

    /// Records where this machine is plugged in, where the frame says so.
    ///
    /// Returns whether the frame was an announcement.
    ///
    /// The attachment is recorded whatever [`Recording`] says: it relates this
    /// machine to the equipment on its own cable, and is not about an address.
    fn read_announcement(&mut self, frame: &Frame<'_>, captured: &CapturedFrame) -> bool {
        let source = frame.source();

        let Some(announced) = Announced::read(frame) else {
            return false;
        };

        let mut attachment = Attachment::new(
            captured.zone.clone(),
            announced.source,
            captured.observed_at,
        )
        .with_device_mac(source);
        if let Some(name) = announced.device_name {
            attachment = attachment.with_device_name(name);
        }
        if let Some(port) = announced.port {
            attachment = attachment.with_port(port);
        }
        if let Some(vlan) = announced.native_vlan {
            attachment = attachment.with_native_vlan(vlan);
        }
        if let Some(address) = announced.management_address {
            attachment = attachment.with_management_address(address);
        }
        let roles = announced.roles;

        info!(
            verbosity = 1,
            "{} says this machine is on {}{}",
            captured.zone,
            attachment.device_name().unwrap_or("an unnamed device"),
            match attachment.port() {
                Some(port) => format!(" port {port}"),
                None => String::new(),
            },
        );

        // The management address is the only address an announcement names; the
        // roles go on the host there, where one was advertised.
        let named_itself = match attachment.management_address() {
            Some(address) if self.admits(address) => {
                let mut host = Host::new(address);
                host.record_mac(source);
                for role in roles.iter().copied() {
                    host.add_network_role(role);
                }
                self.record(host, &captured.zone);
                true
            }
            _ => false,
        };

        // A switch usually has no address on the segment it serves. Its roles
        // are then filed against its hardware address until it is heard
        // speaking for itself.
        if !named_itself {
            for role in roles {
                self.note_declaration(source, role);
            }
        }

        self.ctx.record_attachment(attachment);
        true
    }

    /// Records what a TCP segment proves, where the frame is one.
    ///
    /// Returns whether it was.
    ///
    /// Any segment proves its sender has a live stack, which is
    /// [`HostStatus::Up`].
    ///
    /// Only a SYN+ACK proves a listener: the endpoint is its *source* address
    /// and *source port*. A SYN only says a client tried, and recording from
    /// SYNs would let anyone scanning the segment fill the report with every
    /// port of every address.
    ///
    /// Only `Open` is ever recorded. A RST or silence would lower a claim (a
    /// RST only refuses that peer over that path); recording one would break
    /// merging a listen report safely into a scanned one.
    ///
    /// `source_mac` is `None` off a tunnel, PPP link or loopback, and the host
    /// is then recorded by its address alone.
    fn read_endpoint(
        &mut self,
        packet: &[u8],
        source_mac: Option<MacAddr>,
        captured: &CapturedFrame,
    ) -> bool {
        let Some((source, segment)) = tcp_segment(packet) else {
            return false;
        };
        let Ok(parsed) = tcp::parse(segment) else {
            return false;
        };

        if !self.admits(source) {
            // Handled: the presence readers would only decline it again.
            return true;
        }

        let mut host = Host::new(source);

        // **The hardware address is only this host's if this host is on the
        // link.** A forwarded frame carries the router's address, which would
        // credit a distant machine with the router's hardware, vendor and
        // claims. With the link's addressing unknown, none is recorded.
        if let Some(mac) = source_mac
            && self.on_link.is_stated()
            && self.on_link.contains(source)
        {
            host.record_mac(mac);
        }

        // The server's half of a handshake. `classify_probe_response` checks
        // RST first, so a RST+ACK cannot arrive here as `SynAck`.
        let served = matches!(
            tcp::classify_probe_response(&parsed),
            Some(TcpReply::SynAck)
        );

        let detail = if served {
            let port = Port::new(parsed.source_port(), Protocol::Tcp, PortState::Open)
                .with_discovery(
                    Discovery::new(ScanResponse::OverheardSynAck).seen_at(captured.observed_at),
                );
            host.add_port(port);
            "syn-ack overheard, so this endpoint served somebody"
        } else {
            "a segment overheard from this host"
        };

        host.record_evidence(
            HostStatus::Up,
            StatusReason::new(StatusProtocol::Tcp, detail),
        );

        self.record(host, &captured.zone);
        // After the host exists: a stack reading edits a record and is never
        // itself evidence of presence.
        self.read_stack(packet, source);
        true
    }

    /// Records that a machine forwards, where the frame shows it doing so.
    ///
    /// A frame whose hardware source is on this link and whose IP source is not
    /// was forwarded by that machine, which makes it a router: routing observed,
    /// with no probe or protocol needed. On an IPv4-only segment this is the
    /// only such proof, since ARP has nothing like the R flag or a router
    /// advertisement; without it, a second router on the wire goes unseen.
    ///
    /// The IP source belongs to a distant machine, so the claim is filed
    /// against the forwarder's hardware address and applied once that machine
    /// is seen at an address of its own.
    fn read_forwarding(&mut self, frame: &Frame<'_>) {
        // With the link's addressing unknown, every sender would read as a
        // router.
        if !self.on_link.is_stated() {
            return;
        }

        let Ok(source) = crate::protocols::source_address(frame) else {
            return;
        };
        if self.on_link.contains(source) {
            return;
        }

        self.note_declaration(frame.source(), NetworkRole::Router);
    }

    /// Files a claim against the machine that made it, applying it now if that
    /// machine is already a host and holding it if it is not.
    ///
    /// Never creates a host or records an address: the claim attaches only to
    /// a machine heard speaking for itself, as in a local sweep.
    fn note_declaration(&mut self, source_mac: MacAddr, role: NetworkRole) {
        if let Some(key) = self.mac_to_ip.get(&source_mac).cloned() {
            self.ctx.update_host(key, |host| {
                host.add_network_role(role);
            });
            return;
        }

        if self.declared.len() >= MAX_DECLARING_MACS && !self.declared.contains_key(&source_mac) {
            return;
        }
        self.declared.entry(source_mac).or_default().insert(role);
    }

    /// Reads the operating system out of a segment's header shape.
    ///
    /// The same reading the active path takes from a probe's reply, here on a
    /// segment already arriving. A stack's window, option layout, initial hop
    /// count and quirks are near-identical across every packet it sends.
    ///
    /// Only replies (SYN+ACK, reset) are classified, since the rule database
    /// describes what a stack sends in answer. A client's SYN, the richest
    /// passive fingerprint, would need a rule set keyed on requests.
    fn read_stack(&self, packet: &[u8], source: IpAddr) {
        if matches!(self.os, OsDetection::Off) {
            return;
        }

        let Some(observed) = os::StackObservation::from_ip_packet(packet) else {
            return;
        };
        if !observed.is_syn_ack() && !observed.is_reset() {
            return;
        }

        let Some(verdict) = os::classify(os::RuleDb::global(), &observed.into()) else {
            return;
        };

        self.ctx.update_host(source, |host| {
            os::identify(host, [verdict.as_evidence()]);
        });
    }

    /// Records what a machine volunteers about itself while asking for an
    /// address.
    ///
    /// A DHCP client names itself on a broadcast when it joins and whenever its
    /// lease renews. For many devices, such as a printer or camera with no DNS
    /// record and no open port, it is the only name they announce.
    ///
    /// A `DHCPDISCOVER` contributes nothing: it comes from `0.0.0.0`, and the
    /// address in option 50 is one the client wants, not one it holds. Only a
    /// request from a real source address (a renewal, the common case) is
    /// read.
    fn read_client(&mut self, frame: &Frame<'_>, zone: &Zone) {
        let Some(request) = dhcp::client_request(frame) else {
            return;
        };
        let Ok(source) = crate::protocols::source_address(frame) else {
            return;
        };
        if source.is_unspecified() || !self.admits(source) {
            return;
        }

        let mut host = Host::new(source);
        if let Some(mac) = request.client_mac {
            // From the message: a relay replaces the frame's source address.
            host.record_mac(mac);
        }
        if let Some(name) = request.hostname {
            host.set_hostname(Some(name.to_owned()));
        }
        host.record_evidence(
            HostStatus::Up,
            StatusReason::new(
                StatusProtocol::Dhcp,
                "asked for its address and named itself",
            ),
        );

        self.record(host, zone);
    }

    /// Records that whoever sent this frame is present, where a reader
    /// recognises it.
    ///
    /// Uses a local sweep's readers unchanged: a neighbour advertisement, an
    /// ARP frame or a DHCP server's answer proves its sender is there, asked or
    /// not.
    fn read_presence(&mut self, frame: &Frame<'_>, zone: &Zone) {
        let Ok(source) = crate::protocols::source_address(frame) else {
            return;
        };
        let mac = frame.source();
        self.credit_presence(source, Some(mac), zone, |protocol| {
            protocol.interpret(frame).ok()
        });
    }

    /// The same, for an IP packet off a link with no hardware addresses, such
    /// as a tunnel or PPP link. The sender is recorded by its address alone.
    fn read_presence_in(&mut self, packet: &[u8], zone: &Zone) {
        let Some(source) = ip_source(packet) else {
            return;
        };
        self.credit_presence(source, None, zone, |protocol| {
            Some(protocol.interpret_packet(packet))
        });
    }

    /// Records `source` as present where one of the readers recognises what
    /// it sent, reading each with `interpret`.
    fn credit_presence(
        &mut self,
        source: IpAddr,
        mac: Option<MacAddr>,
        zone: &Zone,
        interpret: impl Fn(&dyn DiscoveryProtocol) -> Option<frames::Reading>,
    ) {
        if !self.admits(source) {
            return;
        }

        for protocol in &self.protocols {
            let Some(reading) = interpret(protocol.as_ref()) else {
                continue;
            };
            if matches!(reading.matched, ProtocolMatch::Unhandled) {
                continue;
            }

            // Credited to the sender only. A neighbour advertisement's target
            // or a DHCP server identifier is a claim about somebody else.
            let mut host = Host::new(source);
            if let Some(mac) = mac {
                host.record_mac(mac);
            }
            host.record_evidence(
                HostStatus::Up,
                StatusReason::basic(protocol.status_protocol()),
            );
            if let Some(role) = reading.declared {
                host.add_network_role(role);
            }
            self.record(host, zone);
            return;
        }
    }

    /// Whether a finding about `address` may be recorded.
    ///
    /// Applies [`Recording`], using [`OnLink`] for the default scope.
    fn admits(&self, address: IpAddr) -> bool {
        match &self.recording {
            // See `Recording::Attached` for a link with no addressing.
            Recording::Attached => !self.on_link.is_stated() || self.on_link.attaches(address),
            Recording::Everything => true,
            Recording::Only(addresses) => addresses.contains(&address),
        }
    }

    /// Folds a finding into the store under `key`. Every finding passes through
    /// here, so the ceiling is enforced in one place.
    ///
    /// [`Host::merge`] never lowers a claim: it promotes status, accumulates
    /// addresses, hardware addresses and roles, and on a tie keeps what is
    /// already recorded.
    fn store(&mut self, key: ScopedIp, host: Host) {
        // At the ceiling, existing records still take new findings; only new
        // records are refused.
        if self.held >= MAX_RECORDED_HOSTS && !self.ctx.contains_host(&key) {
            self.report_full();
            return;
        }

        // Counted from `write_host`'s answer, since an excluded address creates
        // nothing.
        if self.ctx.write_host(key, |existing| {
            existing.merge(host);
            true
        }) {
            self.held += 1;
        }
    }

    /// Says once that this watch has stopped taking new machines.
    ///
    /// Through [`record_failure`], so the short inventory shows in the report
    /// and the run exits as partial.
    ///
    /// [`record_failure`]: crate::scanner::session::ScanContext::record_failure
    fn report_full(&mut self) {
        if std::mem::replace(&mut self.said_full, true) {
            return;
        }

        self.ctx.record_failure(
            ScannerKind::Passive,
            format!(
                "this watch is holding the {MAX_RECORDED_HOSTS} machines it will hold, \
                 so the ones heard from here on are not being recorded; a link \
                 carrying traffic to anywhere else carries evidence about everywhere \
                 else, which is what the default recording scope leaves out"
            ),
        );
    }

    /// Folds a finding into the store, and remembers which machine it was about.
    ///
    /// The pairing lets a claim about a *machine* reach its host: a router is
    /// known only by the hardware address on frames it forwards, and an
    /// announcing switch usually has no address on the segment it serves.
    ///
    /// Claims already held against the hardware address are applied here. That
    /// is the common order, since a router forwards constantly and rarely
    /// speaks for itself.
    fn record(&mut self, mut host: Host, zone: &Zone) {
        // Every frame came off a link this listener was pointed at; a
        // link-local address is meaningless without its zone.
        host.set_zone(zone.clone());

        let Some(mac) = host.mac() else {
            // Seen from off the link: nothing to recognise it by again.
            let key = host.scoped_ip();
            self.store(key, host);
            return;
        };

        for role in self.declared.remove(&mac).into_iter().flatten() {
            host.add_network_role(role);
        }

        // **The record is keyed by the machine, not by the address.** A device
        // answers at a v4 address, global v6 addresses and a link-local, each
        // on its own frame; keyed per address, a laptop on a real segment was
        // reported as four hosts and a router as two.
        //
        // The first address seen (across the whole watch, once resumed) keys
        // it; later ones join through [`Host::merge`], which ranks addresses,
        // so arrival order does not decide how the host is reported.
        let known = self.mac_to_ip.get(&mac).cloned();
        let key = known.clone().unwrap_or_else(|| host.scoped_ip());

        self.store(key.clone(), host);

        // Paired only once the store holds a record under this key. The ceiling
        // or the scan's exclusions can decline the write, and a pairing to no
        // record would route every later sighting there to be dropped, while
        // `note_declaration` would write through it, bypassing
        // [`store`](Self::store). With exclusions, a machine that first spoke
        // from an excluded address would lose its frames from allowed ones.
        if known.is_none() && self.ctx.contains_host(&key) {
            self.mac_to_ip.insert(mac, key);
        }
    }

    /// Reads until the abort signal is raised, the span runs out, or the capture
    /// ends.
    ///
    /// Returns `Ok` when the run reached its end, including an end forced by
    /// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort), and
    /// `Err` only where the strategy could not do its job at all.
    pub async fn observe(&mut self) -> Result<(), StrategyError> {
        // A ticker, since there may be no next frame for hours.
        let mut stopping = tokio::time::interval(ABORT_POLL);
        stopping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Senders are recorded by hardware address, which needs the vendor
        // database.
        crate::model::mac::load_vendors().await;

        loop {
            if self.ctx.handle.should_stop() {
                break;
            }
            if self
                .deadline
                .is_some_and(|at| tokio::time::Instant::now() >= at)
            {
                break;
            }

            tokio::select! {
                frame = self.frames.recv() => match frame {
                    Some(frame) => self.read(&frame),
                    // Every capture thread has ended: the end of the run.
                    None => break,
                },
                _ = stopping.tick() => {}
            }
        }

        if let Some(counts) = self.capture.counts()
            && counts.dropped > 0
        {
            warn!(
                "the capture discarded {} of {} frames it admitted, so what this \
                 phase did not hear is larger than what it did",
                counts.dropped, counts.received,
            );
        }

        Ok(())
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
    use crate::scanner::session::ScanSession;
    use crate::scanner::strategy::frames::tests::{
        PEER_MAC, advertisement_body, arp_reply_frame, dhcp_reply_frame, echo_reply_frame,
        ndp_frame,
    };
    use std::net::Ipv4Addr;
    use std::time::SystemTime;

    fn zone() -> Zone {
        Zone::new(7, "sim0")
    }

    fn captured(bytes: Vec<u8>) -> CapturedFrame {
        CapturedFrame {
            zone: zone(),
            link: LinkType::Ethernet,
            bytes,
            observed_at: SystemTime::UNIX_EPOCH,
            received_at: std::time::Instant::now(),
        }
    }

    /// A listener over a stream a test pushes frames onto.
    fn listening(recording: Recording) -> (PassiveListener, ScanContext) {
        over(recording, OnLink::default())
    }

    /// A listener whose link is `198.51.100.0/24`, so any other source address
    /// is evidence of forwarding.
    fn listening_on_a_known_link(recording: Recording) -> (PassiveListener, ScanContext) {
        let mut ranges = IpSet::new();
        ranges.insert_range("198.51.100.0/24".parse().expect("a valid range"));
        over(recording, OnLink::of(ranges))
    }

    fn over(recording: Recording, on_link: OnLink) -> (PassiveListener, ScanContext) {
        let (_session, ctx) = ScanSession::new();
        let (_tx, rx) = tokio::sync::mpsc::channel(16);
        (
            PassiveListener::over(
                rx,
                capture::CaptureGuard::noop(),
                recording,
                on_link,
                ctx.clone(),
            ),
            ctx,
        )
    }

    /// The listener's filter admits everything its readers can use; a reader
    /// never given a frame fails silently.
    #[test]
    fn the_listen_filter_admits_every_frame_a_listener_can_read() {
        let ethernet = pcap::Capture::dead(pcap::Linktype::ETHERNET).expect("a dead capture");
        let (filter, left_out) = PassiveListener::filter()
            .for_link(&ethernet)
            .unwrap_or_else(|e| panic!("the listen filter does not compile: {e}"));
        assert_eq!(
            left_out,
            Vec::<String>::new(),
            "Ethernet expresses every clause"
        );
        let program = ethernet
            .compile(&filter, true)
            .unwrap_or_else(|e| panic!("the listen filter `{filter}` does not compile: {e}"));

        let lldp = crate::protocols::ethernet::build_header(
            PEER_MAC,
            crate::model::mac::MacAddr::new(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E),
            lldp::ETHERTYPE,
        );

        let readable: [(&str, Vec<u8>); 5] = [
            (
                "an ARP frame",
                arp_reply_frame(Ipv4Addr::new(198, 51, 100, 2)),
            ),
            (
                "a neighbour advertisement",
                ndp_frame(&advertisement_body(
                    std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                    0,
                )),
            ),
            (
                "a DHCP server reply",
                dhcp_reply_frame(Ipv4Addr::new(192, 0, 2, 1), None),
            ),
            ("an LLDP advertisement", lldp),
            (
                "a TCP segment, which is how an endpoint is seen serving somebody",
                {
                    let datagram = crate::protocols::craft::Packet::new()
                        .push(crate::protocols::craft::Ipv4::new(
                            Ipv4Addr::new(198, 51, 100, 5),
                            Ipv4Addr::new(198, 51, 100, 9),
                        ))
                        .push(crate::protocols::craft::Tcp::new(443, 51234))
                        .build()
                        .expect("a test segment");
                    [
                        crate::protocols::ethernet::build_header(
                            PEER_MAC,
                            PEER_MAC,
                            pnet_packet::ethernet::EtherTypes::Ipv4.0,
                        ),
                        datagram,
                    ]
                    .concat()
                },
            ),
        ];

        for (what, frame) in readable {
            assert!(
                program.filter(&frame),
                "the listen filter rejects {what}, so a listener would never see \
                 one: {filter}"
            );
        }
    }

    /// The data-link types a listener meets on links without an Ethernet
    /// header, by their `libpcap` numbers: a cooked Linux capture, which is how
    /// a PPP link and a GRE tunnel come up; raw IP, which is how WireGuard and
    /// an IP-in-IP tunnel do; the address-family word of a BSD loopback or
    /// `utun`, in both of its spellings; and PPP's own.
    const LINKS_WITHOUT_ETHERNET: [(i32, &str); 5] = [
        (113, "a cooked Linux link"),
        (12, "a raw IP link"),
        (0, "a BSD loopback or utun"),
        (108, "an OpenBSD loopback"),
        (9, "a PPP link"),
    ];

    /// A listener pointed at a link with no Ethernet header opens on it, with
    /// the part of its filter that link can express. `libpcap` refuses the
    /// clauses naming hardware addresses there; TCP must survive.
    #[test]
    fn a_listener_compiles_what_a_link_without_ethernet_can_express() {
        for (dlt, what) in LINKS_WITHOUT_ETHERNET {
            let link = pcap::Capture::dead(pcap::Linktype(dlt)).expect("a dead capture");
            let (filter, left_out) = PassiveListener::filter()
                .for_link(&link)
                .unwrap_or_else(|e| panic!("a listener refused {what}: {e}"));

            link.compile(&filter, true)
                .unwrap_or_else(|e| panic!("`{filter}` does not compile for {what}: {e}"));
            assert!(filter.contains("(tcp)"), "{what} keeps TCP: {filter}");
            assert!(
                !filter.contains("ether dst"),
                "{what} names no hardware address: {filter}"
            );
            assert!(
                left_out.iter().any(|clause| clause.contains("ether dst")),
                "{what} leaves the hardware address out: {left_out:?}"
            );
        }
    }

    /// The real opening path narrows the same way on macOS's loopback, captured
    /// as `DLT_NULL`. A refusal for lack of capture rights is accepted. Linux
    /// captures loopback as Ethernet, so there it only shows the listener
    /// opens.
    #[test]
    fn a_listener_opens_on_a_loopback_link() {
        let Some(loopback) = crate::system::interface::interfaces()
            .expect("this machine's interfaces")
            .into_iter()
            .find(|link| link.is_loopback())
        else {
            return;
        };

        match capture::frames(
            std::slice::from_ref(&loopback.zone()),
            &PassiveListener::capture_options(),
            1,
        ) {
            Ok(_) => {}
            Err(refused) if refused.is_denied() => {}
            Err(refused) => panic!("a listener refused {}: {refused}", loopback.name()),
        }
    }

    /// A handshake heard on a link without a hardware address records the
    /// endpoint that served it, by address alone.
    #[test]
    fn a_handshake_heard_on_a_tunnel_records_the_endpoint_that_served_it() {
        use crate::protocols::tcp::flags;

        let server = Ipv4Addr::new(198, 51, 100, 5);
        let client = Ipv4Addr::new(198, 51, 100, 9);
        let datagram = crate::protocols::craft::Packet::new()
            .push(crate::protocols::craft::Ipv4::new(server, client))
            .push(crate::protocols::craft::Tcp::new(443, 51234).with_flags(flags::SYN | flags::ACK))
            .build()
            .expect("a test datagram");

        let (mut listener, ctx) = listening_on_a_known_link(Recording::Attached);
        listener.read(&CapturedFrame {
            zone: zone(),
            link: LinkType::Raw,
            bytes: datagram,
            observed_at: SystemTime::UNIX_EPOCH,
            received_at: std::time::Instant::now(),
        });

        let host = ctx
            .hosts_snapshot()
            .into_iter()
            .next()
            .expect("the server was heard");
        assert_eq!(host.primary_ip(), IpAddr::V4(server));
        assert_eq!(host.mac(), None, "a tunnel carries no hardware address");
        let port = host.ports().next().expect("an endpoint was recorded");
        assert_eq!((port.number(), port.state()), (443, PortState::Open));
    }

    /// A neighbour or router advertisement off a link with no Ethernet header
    /// is heard as it is off one with it, and credited to its sender by
    /// address alone.
    #[test]
    fn an_advertisement_heard_on_a_tunnel_records_its_sender() {
        let sender = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));
        let mut router_advert = vec![0u8; 16];
        router_advert[0] = pnet_packet::icmpv6::Icmpv6Types::RouterAdvert.0;
        let target = std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x99);

        for (what, body, role) in [
            ("a router advertisement", router_advert, true),
            (
                "a neighbour advertisement",
                advertisement_body(target, 0),
                false,
            ),
        ] {
            // The Ethernet header taken off, as a tunnel delivers it.
            let packet = ndp_frame(&body).split_off(14);
            let (mut listener, ctx) = listening(Recording::Everything);
            listener.read(&CapturedFrame {
                zone: zone(),
                link: LinkType::Raw,
                bytes: packet,
                observed_at: SystemTime::UNIX_EPOCH,
                received_at: std::time::Instant::now(),
            });

            let hosts = ctx.hosts_snapshot();
            assert_eq!(hosts.len(), 1, "{what}: one sender, one host");
            assert_eq!(hosts[0].primary_ip(), sender, "{what}: its sender");
            assert_eq!(hosts[0].mac(), None, "{what}: no hardware address");
            assert_eq!(
                hosts[0].network_roles().contains(&NetworkRole::Router),
                role,
                "{what}"
            );
        }
    }

    /// An ICMPv6 echo reply to a link-local address is credited the same way
    /// whether framed by Ethernet or delivered bare by a tunnel.
    #[test]
    fn an_echo_reply_is_credited_alike_on_ethernet_and_on_a_tunnel() {
        let sender = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));
        let framed = echo_reply_frame(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let bare = framed[14..].to_vec();

        for (what, link, bytes) in [
            ("framed", LinkType::Ethernet, framed.clone()),
            ("bare", LinkType::Raw, bare),
        ] {
            let (mut listener, ctx) = listening(Recording::Everything);
            listener.read(&CapturedFrame {
                zone: zone(),
                link,
                bytes,
                observed_at: SystemTime::UNIX_EPOCH,
                received_at: std::time::Instant::now(),
            });

            let hosts = ctx.hosts_snapshot();
            assert_eq!(hosts.len(), 1, "{what}: one sender, one host");
            assert_eq!(hosts[0].primary_ip(), sender, "{what}: its sender");
            assert!(
                hosts[0]
                    .reasons()
                    .iter()
                    .any(|reason| reason.protocol == StatusProtocol::IcmpEcho),
                "{what}: credited to the echo reply: {:?}",
                hosts[0].reasons()
            );
        }
    }

    /// The listener's capture admits its readers' frames and no DNS or mDNS
    /// lookups. Compiled with `libpcap` and run against real frames, which
    /// needs no interface.
    #[test]
    fn the_listener_filter_admits_its_readers_frames_and_no_lookups() {
        let filter = PassiveListener::filter().to_string();
        let program = pcap::Capture::dead(pcap::Linktype::ETHERNET)
            .expect("a dead capture")
            .compile(&filter, true)
            .unwrap_or_else(|e| panic!("the listener filter `{filter}` does not compile: {e}"));

        let udp = |port: u16| {
            let datagram = crate::protocols::craft::Packet::new()
                .push(crate::protocols::craft::Ipv4::new(
                    Ipv4Addr::new(198, 51, 100, 7),
                    Ipv4Addr::new(198, 51, 100, 1),
                ))
                .push(crate::protocols::craft::Udp::new(port, port).with_payload(vec![0u8; 12]))
                .build()
                .expect("a test datagram");
            [
                ethernet::build_header(PEER_MAC, PEER_MAC, EtherTypes::Ipv4.0),
                datagram,
            ]
            .concat()
        };

        for (what, frame) in [
            (
                "an ARP frame",
                arp_reply_frame(Ipv4Addr::new(198, 51, 100, 2)),
            ),
            (
                "a neighbour advertisement",
                ndp_frame(&advertisement_body(
                    std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                    0,
                )),
            ),
            (
                "a DHCP server reply",
                dhcp_reply_frame(Ipv4Addr::new(192, 0, 2, 1), None),
            ),
        ] {
            assert!(program.filter(&frame), "{what} is not admitted: {filter}");
        }
        for (what, frame) in [("a DNS lookup", udp(53)), ("an mDNS message", udp(5353))] {
            assert!(!program.filter(&frame), "{what} is admitted: {filter}");
        }
    }

    /// A frame is credited to the machine that sent it, and to no address the
    /// frame merely names: a neighbour advertisement's target, or a relayed
    /// DHCP reply's server identifier.
    #[test]
    fn a_frame_credits_its_sender_and_no_address_it_merely_names() {
        let (mut listener, ctx) = listening(Recording::Everything);

        // Sent from fe80::2, naming fe80::99 as its target.
        let target = std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x99);
        listener.read(&captured(ndp_frame(&advertisement_body(target, 0))));

        let hosts = ctx.hosts_snapshot();
        assert_eq!(hosts.len(), 1, "one frame, one sender, one host");
        assert_eq!(
            hosts[0].primary_ip(),
            IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)),
            "the address the frame came from, not the one it named"
        );

        // A relayed DHCP answer naming a server on another segment.
        let (mut listener, ctx) = listening(Recording::Everything);
        let relay = Ipv4Addr::new(192, 0, 2, 1);
        let elsewhere = Ipv4Addr::new(198, 51, 100, 53);
        listener.read(&captured(dhcp_reply_frame(elsewhere, Some(relay))));

        let hosts = ctx.hosts_snapshot();
        assert_eq!(hosts.len(), 1);
        assert_eq!(
            hosts[0].primary_ip(),
            IpAddr::V4(relay),
            "the machine that sent the frame, not the one option 54 named"
        );
    }

    /// A recording filter declines findings outside its scope at the point
    /// they are written.
    #[test]
    fn a_recording_filter_keeps_out_what_the_link_carries_anyway() {
        let mut wanted = IpSet::new();
        wanted.insert(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));

        let (mut listener, ctx) = listening(Recording::Only(wanted));
        listener.read(&captured(arp_reply_frame(Ipv4Addr::new(198, 51, 100, 2))));

        assert_eq!(
            ctx.host_count(),
            0,
            "the frame was heard, and recording it was declined"
        );

        listener.read(&captured(arp_reply_frame(Ipv4Addr::new(198, 51, 100, 7))));
        assert_eq!(ctx.host_count(), 1, "and the one in scope was kept");
    }

    /// A segment carrying `flags` between two hosts, as a mirror port sees one.
    fn tcp_frame(from: Ipv4Addr, sport: u16, to: Ipv4Addr, dport: u16, flags: u8) -> Vec<u8> {
        tcp_frame_from(PEER_MAC, from, sport, to, dport, flags)
    }

    /// The same, from a stated hardware address, for the forwarding proof.
    fn tcp_frame_from(
        mac: crate::model::mac::MacAddr,
        from: Ipv4Addr,
        sport: u16,
        to: Ipv4Addr,
        dport: u16,
        flags: u8,
    ) -> Vec<u8> {
        let datagram = crate::protocols::craft::Packet::new()
            .push(crate::protocols::craft::Ipv4::new(from, to))
            .push(crate::protocols::craft::Tcp::new(sport, dport).with_flags(flags))
            .build()
            .expect("a test datagram");

        [
            crate::protocols::ethernet::build_header(
                mac,
                PEER_MAC,
                pnet_packet::ethernet::EtherTypes::Ipv4.0,
            ),
            datagram,
        ]
        .concat()
    }

    /// A SYN only says the client tried; the SYN+ACK establishes the listener.
    #[test]
    fn only_the_server_half_of_a_handshake_establishes_a_listener() {
        use crate::protocols::tcp::flags;

        let client = Ipv4Addr::new(198, 51, 100, 9);
        let server = Ipv4Addr::new(198, 51, 100, 5);

        // The client's SYN to a port nothing is listening on.
        let (mut listener, ctx) = listening(Recording::Everything);
        listener.read(&captured(tcp_frame(client, 51234, server, 443, flags::SYN)));

        let hosts = ctx.hosts_snapshot();
        assert_eq!(
            hosts[0].primary_ip(),
            IpAddr::V4(client),
            "the sender is there, which is all a SYN proves"
        );
        assert_eq!(
            hosts[0].port_count(),
            0,
            "and it proves nothing about the port it was aimed at"
        );

        // The server's answer.
        let (mut listener, ctx) = listening(Recording::Everything);
        listener.read(&captured(tcp_frame(
            server,
            443,
            client,
            51234,
            flags::SYN | flags::ACK,
        )));

        let host = ctx.hosts_snapshot().remove(0);
        assert_eq!(host.primary_ip(), IpAddr::V4(server));
        let port = host.ports().next().expect("an endpoint was recorded");
        assert_eq!(port.number(), 443, "the source port, which is the listener");
        assert_eq!(port.state(), PortState::Open);
        assert_eq!(
            port.discovery().map(Discovery::reason),
            Some(&ScanResponse::OverheardSynAck),
            "and it says the handshake was somebody else's"
        );
    }

    /// A RST+ACK is a refusal, not an open port despite its ACK bit, and a
    /// listener records no closed ports either.
    #[test]
    fn a_refusal_records_no_port_in_either_direction() {
        use crate::protocols::tcp::flags;

        let server = Ipv4Addr::new(198, 51, 100, 5);
        let client = Ipv4Addr::new(198, 51, 100, 9);

        let (mut listener, ctx) = listening(Recording::Everything);
        listener.read(&captured(tcp_frame(
            server,
            443,
            client,
            51234,
            flags::RST | flags::ACK,
        )));

        let host = ctx.hosts_snapshot().remove(0);
        assert_eq!(
            host.status(),
            HostStatus::Up,
            "the refusal still proves its sender has a live stack"
        );
        assert_eq!(
            host.port_count(),
            0,
            "a listener records an open port or no port; it never records a shut one"
        );
    }

    /// A renewing client names itself; a discovering one, sending from
    /// `0.0.0.0` and asking for an address in option 50, names no host.
    #[test]
    fn a_client_renewing_its_lease_names_itself_and_one_discovering_does_not() {
        use crate::protocols::dhcp::tests as fixtures;

        let (mut listener, ctx) = listening(Recording::Everything);
        listener.read(&captured(fixtures::renewal_frame(
            Ipv4Addr::new(192, 0, 2, 74),
            "office-printer-3",
        )));

        let host = ctx.hosts_snapshot().remove(0);
        assert_eq!(host.primary_ip(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 74)));
        assert_eq!(host.hostname(), Some("office-printer-3"));

        // The same client before it holds anything.
        let (mut listener, ctx) = listening(Recording::Everything);
        listener.read(&captured(fixtures::discover_frame("office-printer-3")));
        assert_eq!(
            ctx.host_count(),
            0,
            "a client with no address yet names no host"
        );
    }

    /// A machine forwarding off-link traffic onto this segment is recorded as a
    /// router once it speaks for itself; see `read_forwarding`.
    #[test]
    fn a_machine_that_forwards_somebody_elses_packet_is_a_router() {
        use crate::protocols::tcp::flags;

        const ROUTER_MAC: crate::model::mac::MacAddr =
            crate::model::mac::MacAddr::new(2, 0, 0, 0, 0, 0xAA);
        let router = Ipv4Addr::new(198, 51, 100, 1);
        let elsewhere = Ipv4Addr::new(93, 184, 216, 34);
        let local = Ipv4Addr::new(198, 51, 100, 9);

        let (mut listener, ctx) = listening_on_a_known_link(Recording::Everything);

        // Forwarding an answer from off the link; no router address yet.
        listener.read(&captured(tcp_frame_from(
            ROUTER_MAC,
            elsewhere,
            443,
            local,
            51234,
            flags::SYN | flags::ACK,
        )));
        assert!(
            !ctx.hosts_snapshot()
                .iter()
                .any(|host| host.network_roles().contains(&NetworkRole::Router)),
            "the frame names the sender's hardware address and nobody's router address"
        );

        // Now the same machine speaks for itself.
        listener.read(&captured(tcp_frame_from(
            ROUTER_MAC,
            router,
            22,
            local,
            51235,
            flags::SYN | flags::ACK,
        )));

        let host = ctx
            .hosts_snapshot()
            .into_iter()
            .find(|host| host.primary_ip() == IpAddr::V4(router))
            .expect("the router answered at an address of its own");
        assert!(
            host.network_roles().contains(&NetworkRole::Router),
            "the claim held against its hardware address was applied"
        );
    }

    /// A listener that cannot read its own interface table concludes nothing
    /// about forwarding. Common on a mirror port's capture interface, where
    /// every source would otherwise look off-link.
    #[test]
    fn an_unknown_link_makes_nobody_a_router() {
        let (mut listener, ctx) = listening(Recording::Everything);

        // An ordinary ARP frame from a host on the segment.
        listener.read(&captured(arp_reply_frame(Ipv4Addr::new(198, 51, 100, 1))));

        let host = ctx.hosts_snapshot().remove(0);
        assert_eq!(
            host.primary_ip(),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))
        );
        assert!(
            !host.network_roles().contains(&NetworkRole::Router),
            "with no link addressing known, off-link is not a question with an answer"
        );
    }

    /// The default scope records this link's machines and not the remote
    /// servers they talk to.
    #[test]
    fn the_default_records_this_links_machines_and_not_what_merely_crosses_it() {
        use crate::protocols::tcp::flags;

        let local = Ipv4Addr::new(198, 51, 100, 5);
        let elsewhere = Ipv4Addr::new(93, 184, 216, 34);

        let (mut listener, ctx) = listening_on_a_known_link(Recording::Attached);

        // A server on this segment answering somebody: an asset.
        listener.read(&captured(tcp_frame(
            local,
            443,
            Ipv4Addr::new(198, 51, 100, 9),
            51234,
            flags::SYN | flags::ACK,
        )));
        // A server beyond the router answering somebody here.
        listener.read(&captured(tcp_frame(
            elsewhere,
            443,
            Ipv4Addr::new(198, 51, 100, 9),
            51235,
            flags::SYN | flags::ACK,
        )));

        let recorded: Vec<IpAddr> = ctx
            .hosts_snapshot()
            .iter()
            .map(super::Host::primary_ip)
            .collect();
        assert_eq!(recorded, vec![IpAddr::V4(local)]);

        // The same two frames, read for the wider question.
        let (mut listener, ctx) = listening_on_a_known_link(Recording::Everything);
        listener.read(&captured(tcp_frame(
            elsewhere,
            443,
            Ipv4Addr::new(198, 51, 100, 9),
            51235,
            flags::SYN | flags::ACK,
        )));
        assert_eq!(
            ctx.host_count(),
            1,
            "nothing extra was captured; what changed is what may be recorded"
        );
    }

    /// A link that states no addressing admits everything, so a mirror port's
    /// capture interface does not look like a quiet network.
    #[test]
    fn a_link_with_no_addressing_of_its_own_records_what_it_hears() {
        let (mut listener, ctx) = listening(Recording::Attached);

        listener.read(&captured(arp_reply_frame(Ipv4Addr::new(198, 51, 100, 1))));

        assert_eq!(ctx.host_count(), 1);
    }

    /// The stack is read from a reply already arriving, and not at all under
    /// `Off`.
    ///
    /// The packet is a real Linux shape (hop counter 64, options `M,S,T,N,W`,
    /// timestamps and SACK) as `assets/fingerprinting/os/linux.toml` describes;
    /// anything less specific classifies as nothing.
    #[test]
    fn a_stack_is_read_from_a_reply_that_was_arriving_anyway() {
        let frame = || {
            let mut bytes = crate::protocols::ethernet::build_header(
                PEER_MAC,
                PEER_MAC,
                pnet_packet::ethernet::EtherTypes::Ipv4.0,
            );
            bytes.extend_from_slice(&[
                0x45, 0x00, 0x00, 0x3c, 0xbe, 0xef, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc6, 0x33,
                0x64, 0x05, 0xc6, 0x33, 0x64, 0x09, 0x01, 0xbb, 0xc3, 0x50, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x02, 0xa0, 0x12, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04,
                0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x03, 0x03, 0x07,
            ]);
            captured(bytes)
        };

        let (mut listener, ctx) = listening_on_a_known_link(Recording::Attached);
        listener.read(&frame());
        let named = ctx.hosts_snapshot().remove(0);
        assert_eq!(
            named.os().map(|os| os.name().to_owned()),
            Some("Linux".to_owned()),
            "the segment names the stack behind it"
        );

        let (mut listener, ctx) = listening_on_a_known_link(Recording::Attached);
        listener = listener.detecting_os(OsDetection::Off);
        listener.read(&frame());
        let host = ctx.hosts_snapshot().remove(0);

        assert!(
            host.os().is_none(),
            "`off` means nothing looked, and a listener disobeying it for free is \
             still disobeying it"
        );
        assert_eq!(
            host.status(),
            HostStatus::Up,
            "and the frame still proves its sender is there"
        );
    }

    /// A watch that ran out of time leaves the abort signal alone; see
    /// `PassiveListener::deadline`.
    #[tokio::test]
    async fn a_watch_that_runs_out_of_time_was_not_interrupted() {
        let (_session, ctx) = ScanSession::new();
        let (_tx, rx) = tokio::sync::mpsc::channel(16);

        let mut listener = PassiveListener::over(
            rx,
            capture::CaptureGuard::noop(),
            Recording::Everything,
            OnLink::default(),
            ctx.clone(),
        )
        // Already past, so no timer needs to fire.
        .stopping_after(std::time::Duration::ZERO);

        listener.observe().await.expect("the watch runs to its end");

        assert!(
            !ctx.handle.should_stop(),
            "nobody asked it to stop, so nothing may say they did"
        );
    }

    /// A device answering at several addresses is one host, keyed by the
    /// machine as `discover` keys it.
    #[test]
    fn one_machine_answering_at_several_addresses_is_one_host() {
        use crate::protocols::tcp::flags;

        const MAC: crate::model::mac::MacAddr =
            crate::model::mac::MacAddr::new(2, 0, 0, 0, 0, 0xAA);
        let peer = Ipv4Addr::new(198, 51, 100, 9);

        let (mut listener, ctx) = listening_on_a_known_link(Recording::Everything);

        // The same machine at two of its addresses, on two frames.
        let first = Ipv4Addr::new(198, 51, 100, 5);
        let second = Ipv4Addr::new(198, 51, 100, 6);

        listener.read(&captured(tcp_frame_from(
            MAC,
            first,
            443,
            peer,
            51234,
            flags::SYN | flags::ACK,
        )));
        listener.read(&captured(tcp_frame_from(
            MAC,
            second,
            22,
            peer,
            51235,
            flags::SYN | flags::ACK,
        )));

        let hosts = ctx.hosts_snapshot();
        assert_eq!(hosts.len(), 1, "one machine, one record: {hosts:#?}");

        let host = &hosts[0];
        assert!(
            host.ips().contains(&IpAddr::V4(first)) && host.ips().contains(&IpAddr::V4(second)),
            "both addresses are on it: {:?}",
            host.ips()
        );
        assert_eq!(
            host.zone().map(|zone| zone.name().to_owned()),
            Some("sim0".to_owned()),
            "the link it was heard on, without which a link-local names nothing"
        );
        assert_eq!(
            host.ports().count(),
            2,
            "and both endpoints landed on it rather than one being stranded"
        );
    }

    /// A listener may raise a claim and never lower one.
    #[test]
    fn a_listener_never_lowers_a_claim_already_on_the_record() {
        let (mut listener, ctx) = listening(Recording::Everything);

        let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let mut known = Host::new(address);
        known.set_status(HostStatus::Up);
        known.set_hostname(Some("already-known".to_owned()));
        ctx.write_host(known.scoped_ip(), |host| {
            host.merge(known);
            true
        });

        listener.read(&captured(arp_reply_frame(Ipv4Addr::new(198, 51, 100, 2))));

        let host = ctx
            .hosts_snapshot()
            .into_iter()
            .find(|host| host.primary_ip() == address)
            .expect("the host is still there");
        assert_eq!(host.status(), HostStatus::Up);
        assert_eq!(
            host.hostname(),
            Some("already-known"),
            "a listener added to the record and took nothing off it"
        );
    }

    /// A machine restored from an earlier sitting is the same machine tonight,
    /// even when first heard at another address: a week-long watch across
    /// restarts produces one record per machine.
    #[test]
    fn a_machine_restored_from_an_earlier_sitting_is_not_recorded_twice() {
        use crate::protocols::tcp::flags;

        const MAC: crate::model::mac::MacAddr =
            crate::model::mac::MacAddr::new(2, 0, 0, 0, 0, 0xAA);
        let peer = Ipv4Addr::new(198, 51, 100, 9);
        let first = Ipv4Addr::new(198, 51, 100, 5);
        let second = Ipv4Addr::new(198, 51, 100, 6);

        // An earlier sitting restored into the store, as `listen_with_journal`
        // does.
        let (_session, ctx) = ScanSession::new();
        let mut earlier = Host::new(IpAddr::V4(first));
        earlier.record_mac(MAC);
        earlier.set_zone(zone());
        earlier.record_evidence(
            HostStatus::Up,
            StatusReason::new(StatusProtocol::Tcp, "heard last night"),
        );
        ctx.restore_hosts(&[earlier]);
        assert_eq!(ctx.host_count(), 1, "the sitting starts with one machine");

        let (_tx, rx) = tokio::sync::mpsc::channel(16);
        let mut ranges = IpSet::new();
        ranges.insert_range("198.51.100.0/24".parse().expect("a valid range"));
        let mut listener = PassiveListener::over(
            rx,
            capture::CaptureGuard::noop(),
            Recording::Everything,
            OnLink::of(ranges),
            ctx.clone(),
        );

        // Tonight the same machine is heard first at its *other* address.
        listener.read(&captured(tcp_frame_from(
            MAC,
            second,
            22,
            peer,
            51235,
            flags::SYN | flags::ACK,
        )));

        let hosts = ctx.hosts_snapshot();
        assert_eq!(
            hosts.len(),
            1,
            "one machine across two sittings, not one per sitting: {hosts:#?}"
        );

        let host = &hosts[0];
        assert!(
            host.ips().contains(&IpAddr::V4(first)) && host.ips().contains(&IpAddr::V4(second)),
            "tonight's address joined the record rather than opening one: {:?}",
            host.ips()
        );
    }

    /// A restored host with no hardware address (heard off-link; see
    /// `read_endpoint`) is not paired.
    #[test]
    fn seeding_the_pairing_skips_a_restored_host_with_no_hardware_address() {
        let (_session, ctx) = ScanSession::new();

        let mut off_link = Host::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        off_link.record_evidence(
            HostStatus::Up,
            StatusReason::new(StatusProtocol::Tcp, "heard through a router"),
        );
        ctx.restore_hosts(&[off_link]);

        assert!(
            PassiveListener::paired_with_known_hosts(&ctx).is_empty(),
            "a host with no hardware address pairs with nothing"
        );
    }

    /// An address the scan excluded does not take the machine's other addresses
    /// down with it; see the pairing in `record`.
    #[test]
    fn a_machine_that_spoke_from_an_excluded_address_is_still_recorded_at_its_others() {
        use crate::model::exclusion::Exclusions;
        use crate::protocols::tcp::flags;

        const MAC: crate::model::mac::MacAddr =
            crate::model::mac::MacAddr::new(2, 0, 0, 0, 0, 0xAA);
        let excluded = Ipv4Addr::new(198, 51, 100, 5);
        let ordinary = Ipv4Addr::new(198, 51, 100, 6);
        let peer = Ipv4Addr::new(198, 51, 100, 9);

        let mut forbidden = IpSet::new();
        forbidden.insert(IpAddr::V4(excluded));
        let (_session, ctx) = ScanSession::builder()
            .excluding(Exclusions::new(forbidden))
            .build();

        let (_tx, rx) = tokio::sync::mpsc::channel(16);
        let mut ranges = IpSet::new();
        ranges.insert_range("198.51.100.0/24".parse().expect("a valid range"));
        let mut listener = PassiveListener::over(
            rx,
            capture::CaptureGuard::noop(),
            Recording::Everything,
            OnLink::of(ranges),
            ctx.clone(),
        );

        // The excluded address first, so it would have keyed the machine.
        listener.read(&captured(tcp_frame_from(
            MAC,
            excluded,
            443,
            peer,
            51234,
            flags::SYN | flags::ACK,
        )));
        assert_eq!(
            ctx.host_count(),
            0,
            "the excluded address is not recorded, which is the policy working"
        );

        listener.read(&captured(tcp_frame_from(
            MAC,
            ordinary,
            22,
            peer,
            51235,
            flags::SYN | flags::ACK,
        )));

        let hosts = ctx.hosts_snapshot();
        assert_eq!(
            hosts.len(),
            1,
            "the machine's other address is its own host"
        );
        assert_eq!(hosts[0].primary_ip(), IpAddr::V4(ordinary));
        assert!(
            !hosts[0].ips().contains(&IpAddr::V4(excluded)),
            "and the excluded address did not ride in on the merge: {:?}",
            hosts[0].ips()
        );
    }

    /// The other order: heard first at the allowed address, which keys it, then
    /// at the excluded one, which the merge must not carry into the record.
    #[test]
    fn a_machine_heard_at_an_excluded_address_second_does_not_carry_it_into_the_record() {
        use crate::model::exclusion::Exclusions;
        use crate::protocols::tcp::flags;

        const MAC: crate::model::mac::MacAddr =
            crate::model::mac::MacAddr::new(2, 0, 0, 0, 0, 0xAA);
        let excluded = Ipv4Addr::new(198, 51, 100, 5);
        let ordinary = Ipv4Addr::new(198, 51, 100, 6);
        let peer = Ipv4Addr::new(198, 51, 100, 9);

        let mut forbidden = IpSet::new();
        forbidden.insert(IpAddr::V4(excluded));
        let (_session, ctx) = ScanSession::builder()
            .excluding(Exclusions::new(forbidden))
            .build();

        let (_tx, rx) = tokio::sync::mpsc::channel(16);
        let mut ranges = IpSet::new();
        ranges.insert_range("198.51.100.0/24".parse().expect("a valid range"));
        let mut listener = PassiveListener::over(
            rx,
            capture::CaptureGuard::noop(),
            Recording::Everything,
            OnLink::of(ranges),
            ctx.clone(),
        );

        for (from, port, client) in [(ordinary, 22, 51235), (excluded, 443, 51234)] {
            listener.read(&captured(tcp_frame_from(
                MAC,
                from,
                port,
                peer,
                client,
                flags::SYN | flags::ACK,
            )));
        }

        let hosts = ctx.hosts_snapshot();
        assert_eq!(hosts.len(), 1, "one machine, one record");
        assert_eq!(hosts[0].primary_ip(), IpAddr::V4(ordinary));
        assert!(
            !hosts[0].ips().contains(&IpAddr::V4(excluded)),
            "the excluded address rode in on the merge: {:?}",
            hosts[0].ips()
        );
    }

    /// Reaching the ceiling stops new records, keeps enriching existing ones,
    /// and is reported as a failure.
    #[test]
    fn a_watch_at_its_ceiling_stops_taking_machines_and_keeps_enriching_the_ones_it_has() {
        use crate::protocols::tcp::flags;

        const HELD_MAC: crate::model::mac::MacAddr =
            crate::model::mac::MacAddr::new(2, 0, 0, 0, 0, 0xAA);
        const STRANGER_MAC: crate::model::mac::MacAddr =
            crate::model::mac::MacAddr::new(2, 0, 0, 0, 0, 0xBB);

        let (mut listener, ctx) = listening_on_a_known_link(Recording::Everything);
        let peer = Ipv4Addr::new(198, 51, 100, 9);
        let known = Ipv4Addr::new(198, 51, 100, 5);

        // One machine on record, then marked full directly.
        listener.read(&captured(tcp_frame_from(
            HELD_MAC,
            known,
            22,
            peer,
            51234,
            flags::SYN | flags::ACK,
        )));
        assert_eq!(ctx.host_count(), 1);
        listener.held = MAX_RECORDED_HOSTS;

        // A machine it has never heard of, which needs a record of its own.
        listener.read(&captured(tcp_frame_from(
            STRANGER_MAC,
            Ipv4Addr::new(198, 51, 100, 200),
            22,
            peer,
            51235,
            flags::SYN | flags::ACK,
        )));
        assert_eq!(
            ctx.host_count(),
            1,
            "a machine heard at the ceiling is not recorded"
        );

        // And the one it already holds, now serving on a second port.
        listener.read(&captured(tcp_frame_from(
            HELD_MAC,
            known,
            443,
            peer,
            51236,
            flags::SYN | flags::ACK,
        )));

        let host = ctx.hosts_snapshot().remove(0);
        let mut open: Vec<u16> = host.ports().map(Port::number).collect();
        open.sort_unstable();
        assert_eq!(
            open,
            vec![22, 443],
            "a record already held goes on taking what it is told"
        );

        let failures = ctx.failures_snapshot();
        assert_eq!(
            failures.len(),
            1,
            "the ceiling is reported once, not once per frame: {failures:#?}"
        );
    }

    /// LLDP and CDP land in the same four attachment fields. A mismapped field
    /// fails silently: the attachment still records, just wrong.
    #[test]
    fn both_announcement_protocols_land_in_the_same_four_fields() {
        use crate::protocols::{cdp, lldp};

        for (spoken, frame, source, device_mac) in [
            (
                "LLDP",
                lldp::tests::switch_announcement(),
                AttachmentSource::Lldp,
                lldp::tests::SWITCH_MAC,
            ),
            (
                "CDP",
                cdp::tests::switch_announcement(),
                AttachmentSource::Cdp,
                cdp::tests::SWITCH_MAC,
            ),
        ] {
            let (mut listener, ctx) = listening(Recording::Everything);
            listener.read(&captured(frame));

            let attachments = ctx.take_attachments();
            assert_eq!(attachments.len(), 1, "{spoken}: one frame, one attachment");
            let attachment = &attachments[0];

            assert_eq!(attachment.source(), source, "{spoken}: whose word it is");
            assert_eq!(
                attachment.device_mac(),
                Some(device_mac),
                "{spoken}: the machine that sent it"
            );
            assert_eq!(
                attachment.device_name(),
                Some("core-sw-02"),
                "{spoken}: what the device calls itself"
            );
            assert_eq!(
                attachment.port(),
                Some("GigabitEthernet1/0/14"),
                "{spoken}: the port this machine is plugged into"
            );
            assert_eq!(
                attachment.native_vlan(),
                Some(40),
                "{spoken}: the VLAN untagged traffic lands in"
            );
            assert_eq!(
                attachment.management_address(),
                Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
                "{spoken}: where the device is managed"
            );

            // Both advertise bridging (CDP: switching) and routing as enabled.
            let host = ctx
                .hosts_snapshot()
                .into_iter()
                .find(|host| host.primary_ip() == IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)))
                .unwrap_or_else(|| panic!("{spoken}: the device named an address of its own"));
            let roles = host.network_roles();
            assert!(
                roles.contains(&NetworkRole::Switch) && roles.contains(&NetworkRole::Router),
                "{spoken}: both enabled capabilities reached the host: {roles:?}"
            );
        }
    }
}
