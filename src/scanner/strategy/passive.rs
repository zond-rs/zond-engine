// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading a link instead of asking it
//!
//! The strategy behind [`listen`](crate::scanner::listen). It opens a capture,
//! reads what the link already carries, and records what that proves. It sends
//! nothing at all — not a probe, not a solicitation, not a single frame — and
//! that is the property the whole design turns on rather than an implementation
//! detail.
//!
//! ## Only ever a positive claim
//!
//! A scanner learns two things from one probe: what a reply says, and what
//! silence says. Silence is informative because the scanner knows a probe went
//! out and knows how long it waited.
//!
//! A listener has neither. It did not send, so it cannot time out. An address it
//! never heard from may be absent, may be silent, may be behind a switch that
//! never forwarded a frame this way, or may have been talking the whole time on
//! a VLAN this link does not carry — four possibilities with no experiment
//! between them.
//!
//! So this raises claims and never lowers one. It records a host as
//! [`Up`](HostStatus::Up) and never as down; it adds a role, a name, a hardware
//! address; and it never contradicts or removes anything. The phase's scope says
//! the same thing in the report — see
//! [`TargetScope::listening_on`](crate::scanner::report::TargetScope::listening_on),
//! which covers no address, so a comparison cannot read a host that stayed quiet
//! as a host that went away.
//!
//! ## What it believes
//!
//! Everything here arrives unauthenticated from whoever cared to send it, which
//! is unlike every other strategy in this module: they correlate each reply
//! against a probe they sent. Anything on a segment can put any source address
//! and any hardware address into a frame.
//!
//! The rule that follows is narrow and is applied at the one place it can be:
//! **a frame is credited to its sender and to nobody else.** A claim about a
//! third address is read for what the *sender* is and never for what the address
//! it names is, which is the same reasoning `local`'s `note_declaration` already
//! applies to an overheard router advertisement.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::SystemTime;

use async_trait::async_trait;

use crate::config::OsDetection;
use crate::fingerprint::os;
use crate::model::host::{Host, HostStatus, NetworkRole, StatusProtocol, StatusReason};
use crate::model::ip::range::{IpRange, Ipv4Range, Ipv6Range};
use crate::model::ip::scoped::Zone;
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;
use crate::model::port::discovery::{Discovery, ScanResponse};
use crate::model::port::{Port, PortState, Protocol};
use crate::model::technique::TcpReply;
use crate::protocols::ethernet::{self, Frame};
use crate::protocols::{cdp, dhcp, lldp, tcp};
use crate::scanner::report::{Attachment, AttachmentSource};
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::scanner::strategy::StrategyError;
use crate::scanner::strategy::discovery::{self, DiscoveryProtocol, ProtocolMatch};
use crate::transport::capture::{self, CaptureOptions, CapturedFrame, FrameStream};
use crate::transport::frame::LinkType;
use crate::transport::mac::IntoCoreMac;
use crate::{info, warn};

/// How much of each frame the kernel keeps for a listener.
///
/// **This is the payload boundary, and it is enforced by the kernel rather than
/// by discipline here.** A listener sees traffic belonging to other people, and
/// the honest limit on how much of it this process reads is a limit the process
/// cannot exceed even by mistake. Everything this module concludes comes from
/// link, network and transport headers, plus the first stretch of a
/// control-plane message; none of it needs a session's contents, and a snapshot
/// length that cannot hold them is how that stays true.
///
/// Generous enough for the largest thing actually read — an LLDP advertisement
/// with a long system description — and far short of a payload.
const LISTEN_SNAP_LEN: u32 = 512;

/// How much the kernel may hold for a listening capture before it discards.
///
/// Larger than the default a scan's reply path takes, because the two are
/// bounded by different things. A scan's arrivals are bounded by the probes it
/// sent; a listener's are bounded by the network, which does not slow down
/// because this process is busy.
const LISTEN_BUFFER_BYTES: u32 = 4 * 1024 * 1024;

/// How many frames may wait for the reader at once.
///
/// Multiplied by [`LISTEN_SNAP_LEN`] this is the memory the queue costs, which
/// is why the two are stated together. A full queue stalls the capture thread
/// rather than dropping, so what is lost is counted by the kernel — see
/// [`capture::frames`].
const LISTEN_QUEUE_DEPTH: usize = 4096;

/// How many machines may have a claim held against them at once.
///
/// A declaration is filed against the hardware address that made it and applied
/// when that machine turns out to be one this listener has a host for. Until
/// then it costs memory, and it grows from frames nobody asked for — so a
/// segment full of strangers would otherwise set the size of this map. A link
/// with more than this many distinct speakers is one where the surplus is noise.
const MAX_DECLARING_MACS: usize = 4096;

/// How often a listener looks at the abort signal while nothing is arriving.
///
/// It has no schedule of its own to hang the check on. A link can be silent for
/// hours, and a run that noticed the signal only when a frame happened to arrive
/// would be one nobody could stop on exactly the network where stopping matters
/// least urgently and works least well.
const ABORT_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// The TCP segment inside `frame`, where it carries one.
///
/// Reads the fixed header's protocol field rather than walking an IPv6
/// extension chain, so a segment behind one is reported as not-TCP. That is the
/// safe direction: it declines a frame it cannot read rather than reading an
/// option header as a port number.
fn tcp_segment<'a>(frame: &Frame<'a>) -> Option<&'a [u8]> {
    use pnet::packet::ethernet::EtherTypes;
    use pnet::packet::ip::IpNextHeaderProtocols;

    let packet = frame.payload();
    let (header_len, next) = match frame.ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = pnet::packet::ipv4::Ipv4Packet::new(packet)?;
            (
                usize::from(ipv4.get_header_length()) * 4,
                ipv4.get_next_level_protocol(),
            )
        }
        EtherTypes::Ipv6 => (
            crate::protocols::sizes::IP_V6_HDR_LEN,
            pnet::packet::ipv6::Ipv6Packet::new(packet)?.get_next_header(),
        ),
        _ => return None,
    };

    (next == IpNextHeaderProtocols::Tcp).then(|| packet.get(header_len..))?
}

/// The address ranges a listener's links carry.
///
/// What makes a source address *off*-link, and so what turns a frame into
/// evidence that its sender forwards. Held as the ranges rather than as a
/// question asked of the operating system per frame: the answer is fixed for the
/// life of a phase and the question would otherwise be asked millions of times.
///
/// **Empty means unknown, never "nothing is on this link".** A listener that
/// could not read its own interface table concludes nothing about forwarding
/// rather than concluding that every sender forwards, which is what treating an
/// empty set as authoritative would produce.
#[derive(Debug, Clone, Default)]
pub struct OnLink {
    ranges: IpSet,
}

impl OnLink {
    /// The ranges `links` carry, read from this machine's interface table.
    pub fn of_links(links: &[Zone]) -> Self {
        let mut ranges = IpSet::new();

        for interface in pnet::datalink::interfaces() {
            if !links.iter().any(|link| link.name() == interface.name) {
                continue;
            }
            for network in &interface.ips {
                let range = match (network.network(), network.broadcast()) {
                    (IpAddr::V4(start), IpAddr::V4(end)) => {
                        Ipv4Range::new(start, end).map(IpRange::V4)
                    }
                    (IpAddr::V6(start), IpAddr::V6(end)) => {
                        Ipv6Range::new(start, end).map(IpRange::V6)
                    }
                    // A network cannot span two families; the pair is only a
                    // pair because the library reports both ends separately.
                    _ => continue,
                };
                if let Ok(range) = range {
                    ranges.insert_range(range);
                }
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
    /// The four families below are on-link by definition and are answered before
    /// the ranges are consulted, because an interface's prefix list does not
    /// necessarily contain them and a frame from one is never proof of
    /// forwarding:
    ///
    /// - **unspecified** — a client with no address yet, which has nothing to
    ///   forward and nothing that could have been forwarded;
    /// - **loopback** — never on a wire at all;
    /// - **link-local**, both families — scoped to this segment by definition;
    /// - **multicast** — not a source address any stack should emit, and not one
    ///   to draw a conclusion from if it does.
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
    /// **Not the same question as [`contains`](Self::contains)**, and the
    /// difference is the reason both exist. That one asks whether a frame could
    /// have originated here, so it answers yes for every address a wire never
    /// carries as a source — the unspecified address, loopback, multicast —
    /// because none of them is evidence of forwarding. This one asks whether
    /// there is a *machine* here to record, and those three are not machines.
    ///
    /// An IPv6 link-local is, and is admitted whatever the ranges say: it is
    /// scoped to this segment by definition, which is a stronger statement about
    /// where its holder is than any prefix list.
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
/// A listener has no target set, because it targets nothing. What it has instead
/// is a rule about what may reach the store — and that is the *only* control
/// there is, since unlike every other strategy it cannot narrow what it asks.
///
/// This is the distinction `network roles` §4.4 arrived at from the other
/// direction: what makes a targeted run targeted is what it may **record**, not
/// what it may ask. For a listener there is no asking at all, so recording is
/// where the whole of the scope lives.
#[derive(Debug, Clone, Default)]
pub enum Recording {
    /// Record findings about the machines attached to the links being listened
    /// to, and nothing else.
    ///
    /// The default, and the answer to what a listener is usually *for*. A link
    /// carrying traffic to anywhere else carries evidence about everywhere else:
    /// on a mirror port, every server a laptop opens a connection to is a real
    /// host that is really up, with a really open port. All of it true, none of
    /// it an inventory of this network — and on a busy uplink it is most of what
    /// the report would contain.
    ///
    /// **A link that states no addressing cannot narrow anything**, and this
    /// admits everything rather than nothing when that happens. A capture
    /// interface on a mirror port routinely has no address of its own, and a
    /// listener that silently recorded nothing there would be the worst of the
    /// available behaviours. It is announced when the phase starts.
    #[default]
    Attached,
    /// Record whatever is heard, wherever it lives.
    ///
    /// What a listener wants when the question is about traffic rather than
    /// about this segment's inventory — which machines elsewhere this network
    /// depends on, and what they answer.
    Everything,
    /// Record only findings about these addresses.
    ///
    /// Frames from anything else are still read — a listener cannot decline to
    /// receive — and are dropped without reaching the store.
    Only(IpSet),
}

/// A strategy that reads a link and concludes from it, having sent nothing.
///
/// The third trait beside [`HostScanner`](super::HostScanner) and
/// [`PortScanner`](super::PortScanner), and the shape differs from both because
/// what it does differs from both. A `HostScanner` owns targets and finishes
/// when it has asked about all of them; a `PortScanner` is fed targets and
/// finishes when the stream ends. A listener owns no targets, enumerates
/// nothing, and has no state that can be complete — it finishes when it is told
/// to, and not before.
///
/// Findings go to the [`ScanContext`] it was built with, as they do for the
/// other two: a strategy writes what it found and returns only whether the
/// attempt itself got to the end.
#[async_trait]
pub trait Listener: Send {
    /// Identifies the strategy, so a failure can be attributed to it.
    fn kind(&self) -> ScannerKind;

    /// Reads until the abort signal is raised or the capture ends.
    ///
    /// Returns `Ok` when the run reached its end, including an end forced by
    /// [`ScanHandle::abort`], and `Err` only when the strategy could not do its
    /// job at all.
    async fn observe(&mut self) -> Result<(), StrategyError>;
}

/// Reads one or more links and records what their traffic proves.
pub struct PassiveListener {
    ctx: ScanContext,
    frames: FrameStream,
    /// Kept for as long as this listener runs: dropping it stops the capture
    /// threads.
    capture: capture::CaptureGuard,
    recording: Recording,
    on_link: OnLink,
    /// How far this listener may go to name the system behind a host.
    ///
    /// A listener cannot be *active* whatever this says — it sends nothing —
    /// so the only distinction it can honour is between reading the stacks it
    /// hears and not reading them. `Off` is obeyed rather than ignored on the
    /// grounds that it costs no packets to disobey: a caller who asked for a
    /// report containing only what they requested should not find a fingerprint
    /// in it.
    os: OsDetection,
    /// The address each hardware address was first recorded at, so a claim made
    /// about a machine can be applied to the host it turns out to be.
    ///
    /// Grows only from frames that produced a finding, which the recording
    /// filter has already narrowed.
    mac_to_ip: HashMap<MacAddr, IpAddr>,
    /// What a machine said about itself before this listener knew which host it
    /// was.
    ///
    /// Bounded, unlike [`mac_to_ip`](Self::mac_to_ip), and for the reason the
    /// local sweep's equivalent is: this grows from traffic nobody solicited, so
    /// a segment full of strangers decides how large it gets unless something
    /// else does.
    declared: HashMap<MacAddr, HashSet<NetworkRole>>,
    /// The readers, which are the same ones a local sweep interprets its
    /// replies with. A frame that proves a host is there proves it whether or
    /// not this engine asked.
    protocols: Vec<Box<dyn DiscoveryProtocol>>,
}

impl PassiveListener {
    /// Opens a capture on each of `links` and reads it.
    ///
    /// Fails only when no link could be captured, since a listener with nothing
    /// to listen to is not one.
    pub fn open(
        links: &[Zone],
        recording: Recording,
        ctx: ScanContext,
    ) -> Result<Self, StrategyError> {
        let options = CaptureOptions::for_link_traffic(Self::filter())
            .with_snaplen(LISTEN_SNAP_LEN)
            .with_buffer_bytes(LISTEN_BUFFER_BYTES);

        let (frames, capture) =
            capture::frames(links, &options, LISTEN_QUEUE_DEPTH).map_err(|_| {
                StrategyError::Interface {
                    interface: links.iter().map(Zone::name).collect::<Vec<_>>().join(", "),
                    reason: "no link could be captured (listening needs root)",
                }
            })?;

        let on_link = OnLink::of_links(links);

        // The one case where the default scope silently becomes the widest one.
        // A capture interface on a mirror port routinely holds no address, and a
        // listener that recorded nothing there would look like a quiet network.
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

    /// Builds a listener over an already-open frame stream.
    ///
    /// The seam a test drives a listener through: push frames onto the sending
    /// half and they arrive as though captured, with no interface and no
    /// privileges involved.
    pub fn over(
        frames: FrameStream,
        capture: capture::CaptureGuard,
        recording: Recording,
        on_link: OnLink,
        ctx: ScanContext,
    ) -> Self {
        Self {
            ctx,
            frames,
            capture,
            recording,
            on_link,
            os: OsDetection::default(),
            mac_to_ip: HashMap::new(),
            declared: HashMap::new(),
            protocols: discovery::sweep_protocols(),
        }
    }

    /// Reads the system behind each host at `level`, or at none.
    ///
    /// Defaults to [`OsDetection::Passive`], which is what a listener can do and
    /// the whole of it: the readings come out of headers that were arriving
    /// anyway.
    pub fn detecting_os(mut self, level: OsDetection) -> Self {
        self.os = level;
        self
    }

    /// What a listener's capture admits.
    ///
    /// Everything the readers below can use, and nothing else. Wider than a
    /// sweep's — it takes TCP, to see which endpoints are serving somebody —
    /// and still a filter rather than the whole wire, because a capture that
    /// admits everything copies a link into this process to discard almost all
    /// of it.
    fn filter() -> String {
        let mut clauses: Vec<&'static str> = discovery::sweep_protocols()
            .iter()
            .map(|protocol| protocol.capture_clause())
            .collect();

        clauses.extend([
            // The announcements, which are what say where this machine is.
            "(ether proto 0x88cc)",
            "(ether dst 01:00:0c:cc:cc:cc)",
            // Names somebody else's lookup put on the wire.
            "(udp port 5353)",
            "(udp port 53)",
            // The handshakes that say an endpoint served a real client. Only
            // the server's half of one establishes a listener; see
            // `read_tcp`.
            "(tcp)",
        ]);

        clauses.sort_unstable();
        clauses.dedup();
        clauses.join(" or ")
    }

    /// Reads one frame for everything it proves.
    ///
    /// Every reader is tried: a frame can carry more than one finding, and
    /// stopping at the first would make what is recorded depend on the order
    /// they happen to be written in.
    fn read(&mut self, captured: &CapturedFrame) {
        if captured.link != LinkType::Ethernet {
            return;
        }
        let Ok(frame) = ethernet::parse(&captured.bytes) else {
            return;
        };

        if self.read_announcement(&frame, captured) {
            return;
        }
        self.read_forwarding(&frame);

        if self.read_endpoint(&frame, captured.observed_at) {
            return;
        }
        self.read_client(&frame);
        self.read_presence(&frame);
    }

    /// Records where this machine is plugged in, where the frame says so.
    ///
    /// Returns whether the frame was an announcement.
    ///
    /// The attachment is recorded whatever [`Recording`] says, because it is not
    /// a finding about an address: it is a relation between this machine and the
    /// equipment on the far end of its own cable, and no address filter has an
    /// opinion about that.
    fn read_announcement(&mut self, frame: &Frame<'_>, captured: &CapturedFrame) -> bool {
        let source = frame.source().into_core();

        let (attachment, roles) = if let Some(advertisement) = lldp::parse(frame) {
            let mut attachment = Attachment::new(
                captured.zone.clone(),
                AttachmentSource::Lldp,
                captured.observed_at,
            )
            .with_device_mac(source);
            if let Some(name) = advertisement.system_name {
                attachment = attachment.with_device_name(name);
            }
            if let Some(lldp::Identifier::Text(port)) = advertisement.port_id {
                attachment = attachment.with_port(port);
            }
            if let Some(vlan) = advertisement.port_vlan {
                attachment = attachment.with_native_vlan(vlan);
            }
            if let Some(address) = advertisement.management_address {
                attachment = attachment.with_management_address(address);
            }

            let mut roles = Vec::new();
            if let Some(capabilities) = advertisement.capabilities {
                if capabilities.is_bridge() {
                    roles.push(NetworkRole::Switch);
                }
                if capabilities.is_router() {
                    roles.push(NetworkRole::Router);
                }
            }
            (attachment, roles)
        } else if let Some(announcement) = cdp::parse(frame) {
            let mut attachment = Attachment::new(
                captured.zone.clone(),
                AttachmentSource::Cdp,
                captured.observed_at,
            )
            .with_device_mac(source);
            if let Some(name) = announcement.device_id {
                attachment = attachment.with_device_name(name);
            }
            if let Some(port) = announcement.port_id {
                attachment = attachment.with_port(port);
            }
            if let Some(vlan) = announcement.native_vlan {
                attachment = attachment.with_native_vlan(vlan);
            }
            if let Some(address) = announcement.address {
                attachment = attachment.with_management_address(address);
            }

            let mut roles = Vec::new();
            if let Some(capabilities) = announcement.capabilities {
                if capabilities.is_switch() {
                    roles.push(NetworkRole::Switch);
                }
                if capabilities.is_router() {
                    roles.push(NetworkRole::Router);
                }
            }
            (attachment, roles)
        } else {
            return false;
        };

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

        // The device's management address is the only address an announcement
        // names, and the roles belong to the machine that sent the frame. Where
        // it advertised one there is a host to put them on.
        let named_itself = match attachment.management_address() {
            Some(address) if self.admits(address) => {
                let mut host = Host::new(address);
                host.record_mac(source);
                for role in roles.iter().copied() {
                    host.add_network_role(role);
                }
                self.record(host);
                true
            }
            _ => false,
        };

        // A switch usually holds no address on the segment it serves, so the
        // ordinary case is that it named none. The roles are then filed against
        // the hardware address that made the claim, and applied if that machine
        // is ever heard speaking for itself — the same treatment an overheard
        // router advertisement gets, and for the same reason: a claim about a
        // machine needs a machine to attach to.
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
    /// # Two claims, and only one of them needs a handshake
    ///
    /// **Any segment proves its sender is there.** A machine that put a TCP
    /// segment on the wire has a live stack, which is the model's own standard
    /// for [`HostStatus::Up`] and does not care whether the segment was drawn by
    /// a probe of ours.
    ///
    /// **Only a SYN+ACK proves a listener.** A SYN says somebody *tried*, which
    /// is a claim about the client's intent and not about the server: a host
    /// that is not there draws a SYN just as readily as one that is. Recording
    /// from SYNs would mean anybody who scans the segment fills this report with
    /// sixty-five thousand open ports per address — the tarpit problem with no
    /// probe budget to bound it. So the endpoint is taken from the *source* of a
    /// SYN+ACK, at its *source port*, and from nothing else.
    ///
    /// # Only ever `Open`
    ///
    /// A RST is not recorded, and neither is silence. Both would be a passive
    /// path lowering a claim, which §2 of this module forbids: a RST says the
    /// port refused *that peer* over *that path*, and a listener has no probe of
    /// its own that went unanswered. If this ever learns to record a non-open
    /// state, the rule that lets a listen report merge safely into a scanned one
    /// stops holding.
    fn read_endpoint(&mut self, frame: &Frame<'_>, observed_at: SystemTime) -> bool {
        let Some(segment) = tcp_segment(frame) else {
            return false;
        };
        let Ok(source) = crate::protocols::source_address(frame) else {
            return false;
        };
        let Ok(parsed) = tcp::parse(segment) else {
            return false;
        };

        if !self.admits(source) {
            // Heard, and recording it declined. Reported as handled either way:
            // the frame was read and understood, and handing it to the presence
            // readers below would only have it declined again.
            return true;
        }

        let mut host = Host::new(source);

        // **The hardware address is only this host's if this host is on the
        // link.** A forwarded frame carries the last hop's address, not the
        // sender's, and the two are indistinguishable from here — so recording
        // it off-link credits a machine somewhere else with the router's
        // hardware, its vendor, and any claim held against it. That is not a
        // hypothetical: the router's own forwarding is what put this frame here.
        //
        // Where the link's addressing is unknown the question has no answer, and
        // no address is recorded rather than one guessed at.
        if self.on_link.is_stated() && self.on_link.contains(source) {
            host.record_mac(frame.source().into_core());
        }

        // The listener side, where the segment is the server's half of a
        // handshake. `classify_probe_response` reads RST before the SYN+ACK
        // pair, so a RST+ACK — which is a refusal, not an acceptance — cannot
        // arrive here as `SynAck`.
        let served = matches!(
            tcp::classify_probe_response(&parsed),
            Some(TcpReply::SynAck)
        );

        let detail = if served {
            let port = Port::new(parsed.get_source(), Protocol::Tcp, PortState::Open)
                .with_discovery(Discovery::new(ScanResponse::OverheardSynAck).seen_at(observed_at));
            host.add_port(port);
            "syn-ack overheard, so this endpoint served somebody"
        } else {
            "a segment overheard from this host"
        };

        host.record_evidence(
            HostStatus::Up,
            StatusReason::new(StatusProtocol::Tcp, detail),
        );

        self.record(host);
        // After the host exists, since this edits a record rather than making
        // one: a stack reading is never itself evidence that anything is there.
        self.read_stack(frame, source);
        true
    }

    /// Records that a machine forwards, where the frame shows it doing so.
    ///
    /// **A frame whose hardware source is on this link and whose IP source is
    /// not.** That machine put a packet on this segment which it did not
    /// originate — it forwarded somebody else's — and forwarding is what a
    /// router is. Unlike every other proof of the role this needs no probe, no
    /// cooperation and no protocol of its own; it is routing observed rather
    /// than routing claimed.
    ///
    /// It is also the only such proof available on an IPv4-only segment. ARP has
    /// no equivalent of a neighbour advertisement's R flag and none of a router
    /// advertisement, which left this engine reading its own routing table —
    /// finding *your* gateway and missing the second router on the same wire.
    ///
    /// # It names a MAC, not an address
    ///
    /// The IP source belongs to the machine the packet came *from*, somewhere
    /// else entirely. The only thing here identifying the forwarder is its
    /// hardware address, so the claim is filed against that and applied when the
    /// same machine is seen at an address of its own. A router that never speaks
    /// for itself keeps its claim unapplied, which is the honest outcome.
    fn read_forwarding(&mut self, frame: &Frame<'_>) {
        // Nothing known about this link's addressing means nothing can be
        // off it. Concluding otherwise would make every sender a router.
        if !self.on_link.is_stated() {
            return;
        }

        let Ok(source) = crate::protocols::source_address(frame) else {
            return;
        };
        if self.on_link.contains(source) {
            return;
        }

        self.note_declaration(frame.source().into_core(), NetworkRole::Router);
    }

    /// Files a claim against the machine that made it, applying it now if that
    /// machine is already a host and holding it if it is not.
    ///
    /// Never creates a host and never records an address. A declaration is a
    /// claim about a machine, and the machine has to be one this listener has
    /// heard speak for itself before there is anything for the claim to attach
    /// to — which is the rule a local sweep applies to an overheard router
    /// advertisement, for the same reason.
    fn note_declaration(&mut self, source_mac: MacAddr, role: NetworkRole) {
        if let Some(ip) = self.mac_to_ip.get(&source_mac).copied() {
            let mut host = Host::new(ip);
            host.add_network_role(role);
            self.merge(host);
            return;
        }

        if self.declared.len() >= MAX_DECLARING_MACS && !self.declared.contains_key(&source_mac) {
            return;
        }
        self.declared.entry(source_mac).or_default().insert(role);
    }

    /// Reads the operating system out of a segment's header shape.
    ///
    /// The same reading the active path takes from a probe's reply, on a segment
    /// that was arriving anyway — which is the whole of what makes it free. A
    /// stack's window, its option layout, its initial hop count and its quirks
    /// are chosen by whoever wrote it and are near-identical across every packet
    /// it will ever send.
    ///
    /// # Only a reply's shape is classified
    ///
    /// A **client's SYN** is the richest passive fingerprint there is, and it is
    /// deliberately not read here. This engine's rule database describes what a
    /// stack sends *in answer* — a SYN+ACK from an open port, a reset from a
    /// closed one — because that is what a scan draws. Matching a connection
    /// request against rules written for replies would produce a confident
    /// verdict from the wrong evidence, which is worse than no verdict.
    ///
    /// Reading one properly means a second rule set keyed on requests. That is a
    /// corpus rather than a parser, and it is left alone until there is one.
    fn read_stack(&self, frame: &Frame<'_>, source: IpAddr) {
        if matches!(self.os, OsDetection::Off) {
            return;
        }

        let Some(observed) = os::StackObservation::from_ip_packet(frame.payload()) else {
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
    /// A DHCP client names itself on a broadcast every other machine on the
    /// segment can hear, and it does so on joining and then whenever its lease
    /// renews. For a great many devices it is the only name they ever announce:
    /// a printer or a camera with no DNS record and no open port still says this.
    ///
    /// # Why a `DHCPDISCOVER` contributes nothing
    ///
    /// A client with no address yet sends from `0.0.0.0`, and the address it
    /// asks for in option 50 is one it *wants* — not one it holds. Recording a
    /// name against either would be the mistake this module's §"What it
    /// believes" names: crediting a frame to an address it merely mentions.
    ///
    /// So a request is read only when its sender had a real address to send
    /// from, which is the renewal case and is by far the more common one on a
    /// segment that has been up for any length of time. A discover is heard and
    /// declined, and the device is named later by whatever else it says.
    fn read_client(&mut self, frame: &Frame<'_>) {
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
            // The address being configured, from the message rather than from
            // the frame: a relay forwarding a client's request replaces the
            // second and preserves the first.
            host.record_mac(mac.into_core());
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

        self.record(host);
    }

    /// Records that whoever sent this frame is present, where a reader
    /// recognises it.
    ///
    /// The readers are a local sweep's own, used unchanged: a neighbour
    /// advertisement, an ARP frame or a DHCP server's answer proves its sender
    /// is there, and it proves it whether or not this engine asked the question
    /// that drew it.
    fn read_presence(&mut self, frame: &Frame<'_>) {
        let Ok(source) = crate::protocols::source_address(frame) else {
            return;
        };
        if !self.admits(source) {
            return;
        }

        for protocol in &self.protocols {
            let Ok(reading) = protocol.interpret(frame) else {
                continue;
            };
            if matches!(reading.matched, ProtocolMatch::Unhandled) {
                continue;
            }

            // Credited to the sender, never to an address the frame merely
            // names. A neighbour advertisement's target and a DHCP message's
            // server identifier are claims about somebody else, and a listener
            // has no probe outstanding to check either against.
            let mut host = Host::new(source);
            host.record_mac(frame.source().into_core());
            host.record_evidence(
                HostStatus::Up,
                StatusReason::basic(protocol.status_protocol()),
            );
            if let Some(role) = reading.declared {
                host.add_network_role(role);
            }
            self.record(host);
            return;
        }
    }

    /// Whether a finding about `address` may be recorded.
    ///
    /// Where the two halves of a listener's scope meet: [`Recording`] says what
    /// kind of narrowing was asked for, and [`OnLink`] is the only thing that can
    /// answer the default one.
    fn admits(&self, address: IpAddr) -> bool {
        match &self.recording {
            // A link with no addressing of its own cannot narrow by it. See
            // `Recording::Attached`.
            Recording::Attached => !self.on_link.is_stated() || self.on_link.attaches(address),
            Recording::Everything => true,
            Recording::Only(addresses) => addresses.contains(&address),
        }
    }

    /// Folds a finding into the store, promoting rather than replacing.
    ///
    /// [`Host::merge`] is what keeps a listener from ever lowering a claim: it
    /// promotes status and accumulates addresses, hardware addresses and roles,
    /// and where two findings are equally good the one already recorded wins.
    fn merge(&self, host: Host) {
        let key = host.scoped_ip();
        self.ctx.write_host(key, |existing| {
            existing.merge(host);
            true
        });
    }

    /// Folds a finding into the store, and remembers which machine it was about.
    ///
    /// The pairing is what lets a claim made about a *machine* reach the host it
    /// turns out to be: a router is identified by the hardware address on the
    /// frames it forwards and by nothing else, and a switch announcing itself
    /// usually holds no address on the segment it serves.
    ///
    /// Anything already held against that hardware address is applied here, so a
    /// claim that arrived before its sender was identified is not lost — which
    /// is the common order, since a router forwards constantly and speaks for
    /// itself rarely.
    fn record(&mut self, host: Host) {
        let Some(mac) = host.mac() else {
            self.merge(host);
            return;
        };

        let address = host.primary_ip();
        let mut host = host;
        for role in self.declared.remove(&mac).into_iter().flatten() {
            host.add_network_role(role);
        }

        self.mac_to_ip.entry(mac).or_insert(address);
        self.merge(host);
    }
}

#[async_trait]
impl Listener for PassiveListener {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Passive
    }

    async fn observe(&mut self) -> Result<(), StrategyError> {
        // A listener has no schedule of its own, so the abort flag is checked on
        // a ticker rather than between units of work: there may be no next frame
        // for hours, and a run that only noticed the signal when something
        // happened to arrive would be a run nobody could stop on a quiet link.
        let mut stopping = tokio::time::interval(ABORT_POLL);
        stopping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            if self.ctx.handle.should_stop() {
                break;
            }

            tokio::select! {
                frame = self.frames.recv() => match frame {
                    Some(frame) => self.read(&frame),
                    // Every capture thread has ended, which for a listener is
                    // the end of the run rather than a fault: there is nothing
                    // left that could speak.
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
    use crate::scanner::strategy::discovery::tests::{
        PEER_MAC, advertisement_body, arp_reply_frame, dhcp_reply_frame, ndp_frame,
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
        }
    }

    /// A listener over a stream a test pushes frames onto, with no capture
    /// behind it and no privileges involved.
    fn listening(recording: Recording) -> (PassiveListener, ScanContext) {
        over(recording, OnLink::default())
    }

    /// A listener that knows what `10.0.0.0/24` is, which is what makes any
    /// other source address evidence of forwarding.
    fn listening_on_a_known_link(recording: Recording) -> (PassiveListener, ScanContext) {
        let mut ranges = IpSet::new();
        ranges.insert_range("10.0.0.0/24".parse().expect("a valid range"));
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

    /// The listener's filter has to admit everything its readers can use, and it
    /// fails silently otherwise: a reader that is never given a frame and one
    /// that recognises nothing are indistinguishable from the loop.
    ///
    /// The sweep's equivalent lives beside the sweep. This one is wider — it
    /// takes TCP, to see which endpoints are serving somebody — so it needs its
    /// own.
    #[test]
    fn the_listen_filter_admits_every_frame_a_listener_can_read() {
        let filter = PassiveListener::filter();
        let program = pcap::Capture::dead(pcap::Linktype::ETHERNET)
            .expect("a dead capture")
            .compile(&filter, true)
            .unwrap_or_else(|e| panic!("the listen filter `{filter}` does not compile: {e}"));

        let lldp = crate::protocols::ethernet::create_header(
            PEER_MAC,
            pnet::datalink::MacAddr(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E),
            lldp::ETHERTYPE,
        );

        let readable: [(&str, Vec<u8>); 5] = [
            ("an ARP frame", arp_reply_frame(Ipv4Addr::new(10, 0, 0, 2))),
            (
                "a neighbour advertisement",
                ndp_frame(&advertisement_body(
                    std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                    0,
                )),
            ),
            (
                "a DHCP server reply",
                dhcp_reply_frame(Ipv4Addr::new(192, 168, 1, 1), None),
            ),
            ("an LLDP advertisement", lldp),
            (
                "a TCP segment, which is how an endpoint is seen serving somebody",
                {
                    let datagram = crate::protocols::craft::Packet::new()
                        .push(crate::protocols::craft::Ipv4::new(
                            Ipv4Addr::new(10, 0, 0, 5),
                            Ipv4Addr::new(10, 0, 0, 9),
                        ))
                        .push(crate::protocols::craft::Tcp::new(443, 51234))
                        .build()
                        .expect("a test segment");
                    [
                        crate::protocols::ethernet::create_header(
                            PEER_MAC,
                            PEER_MAC,
                            pnet::packet::ethernet::EtherTypes::Ipv4,
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

    /// A frame is credited to the machine that sent it, and to no address the
    /// frame merely names.
    ///
    /// A sweep may credit the address a reply is *about* — it asked about that
    /// address, so a reply from one of the host's other addresses still answers
    /// the question. A listener asked nothing, so it has no question a third
    /// address could be answering and nothing to check the claim against. The
    /// two cases below are the ones where a frame names somebody else:
    /// a neighbour advertisement carries a target, and a DHCP reply carries a
    /// server identifier that a relay agent makes a different machine entirely.
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

        // And the same for a relayed DHCP answer, where the sender is the relay
        // and the message names a server on another segment.
        let (mut listener, ctx) = listening(Recording::Everything);
        let relay = Ipv4Addr::new(192, 168, 1, 1);
        let elsewhere = Ipv4Addr::new(10, 0, 0, 53);
        listener.read(&captured(dhcp_reply_frame(elsewhere, Some(relay))));

        let hosts = ctx.hosts_snapshot();
        assert_eq!(hosts.len(), 1);
        assert_eq!(
            hosts[0].primary_ip(),
            IpAddr::V4(relay),
            "the machine that sent the frame, not the one option 54 named"
        );
    }

    /// The only control a listener has. It cannot narrow what it hears, so a
    /// caller who wants a bounded record gets it at the point findings are
    /// written — which is where `network roles` §4.4 put the same rule.
    #[test]
    fn a_recording_filter_keeps_out_what_the_link_carries_anyway() {
        let mut wanted = IpSet::new();
        wanted.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));

        let (mut listener, ctx) = listening(Recording::Only(wanted));
        listener.read(&captured(arp_reply_frame(Ipv4Addr::new(10, 0, 0, 2))));

        assert_eq!(
            ctx.host_count(),
            0,
            "the frame was heard, and recording it was declined"
        );

        listener.read(&captured(arp_reply_frame(Ipv4Addr::new(10, 0, 0, 7))));
        assert_eq!(ctx.host_count(), 1, "and the one in scope was kept");
    }

    /// A segment carrying `flags` between two hosts, as a mirror port sees one.
    fn tcp_frame(from: Ipv4Addr, sport: u16, to: Ipv4Addr, dport: u16, flags: u8) -> Vec<u8> {
        tcp_frame_from(PEER_MAC, from, sport, to, dport, flags)
    }

    /// The same, from a stated hardware address — which is the half of a frame
    /// the forwarding proof reads.
    fn tcp_frame_from(
        mac: pnet::datalink::MacAddr,
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
            crate::protocols::ethernet::create_header(
                mac,
                PEER_MAC,
                pnet::packet::ethernet::EtherTypes::Ipv4,
            ),
            datagram,
        ]
        .concat()
    }

    /// The rule the endpoint reader turns on.
    ///
    /// A SYN says the *client* tried, which a host that is not there draws just
    /// as readily as one that is. Recording from SYNs means anybody who scans
    /// the segment fills the report with sixty-five thousand open ports per
    /// address — the tarpit problem with no probe budget to bound it.
    #[test]
    fn only_the_server_half_of_a_handshake_establishes_a_listener() {
        use crate::protocols::tcp::flags;

        let client = Ipv4Addr::new(10, 0, 0, 9);
        let server = Ipv4Addr::new(10, 0, 0, 5);

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

        // The server's answer, which is the whole of the evidence.
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

    /// A RST+ACK is a refusal. It carries the ACK bit, so a reader that checks
    /// for SYN and ACK without reading RST first turns every closed port into an
    /// open one — and a listener may not record a closed one either, because it
    /// has no probe of its own that went unanswered.
    #[test]
    fn a_refusal_records_no_port_in_either_direction() {
        use crate::protocols::tcp::flags;

        let server = Ipv4Addr::new(10, 0, 0, 5);
        let client = Ipv4Addr::new(10, 0, 0, 9);

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

    /// A renewing client names itself on a broadcast, which for a great many
    /// devices is the only name they ever announce.
    ///
    /// And a client with no address yet says nothing this can use: it sends from
    /// `0.0.0.0`, and the address in option 50 is one it *wants*. Naming a host
    /// from either would credit a frame to an address it merely mentions.
    #[test]
    fn a_client_renewing_its_lease_names_itself_and_one_discovering_does_not() {
        use crate::protocols::dhcp::tests as fixtures;

        let (mut listener, ctx) = listening(Recording::Everything);
        listener.read(&captured(fixtures::renewal_frame(
            Ipv4Addr::new(192, 168, 1, 74),
            "office-printer-3",
        )));

        let host = ctx.hosts_snapshot().remove(0);
        assert_eq!(
            host.primary_ip(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 74))
        );
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

    /// Routing observed rather than routing claimed.
    ///
    /// A frame whose hardware source is on this link and whose IP source is not
    /// shows that machine putting a packet on the segment it did not originate.
    /// It is the only proof of the role available on an IPv4-only segment: ARP
    /// has no equivalent of a neighbour advertisement's R flag and none of a
    /// router advertisement, which left the engine reading its own routing table
    /// — finding *your* gateway and missing the second router on the same wire.
    #[test]
    fn a_machine_that_forwards_somebody_elses_packet_is_a_router() {
        use crate::protocols::tcp::flags;

        const ROUTER_MAC: pnet::datalink::MacAddr = pnet::datalink::MacAddr(2, 0, 0, 0, 0, 0xAA);
        let router = Ipv4Addr::new(10, 0, 0, 1);
        let elsewhere = Ipv4Addr::new(93, 184, 216, 34);
        let local = Ipv4Addr::new(10, 0, 0, 9);

        let (mut listener, ctx) = listening_on_a_known_link(Recording::Everything);

        // The router forwarding an answer from off the link. Nothing here names
        // the router's own address, so there is no host to put the claim on yet.
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

        // Now the same machine speaks for itself, which is what the held claim
        // was waiting for.
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
    /// about forwarding, rather than concluding that every sender forwards.
    ///
    /// This is not a corner: a capture interface on a mirror port routinely has
    /// no address of its own, and with no ranges known *every* source address
    /// looks off-link. Left ungated, the first ARP frame on the segment would
    /// make its sender a router — and the held-claim map would fill with one
    /// bogus claim per machine on the link.
    #[test]
    fn an_unknown_link_makes_nobody_a_router() {
        let (mut listener, ctx) = listening(Recording::Everything);

        // An ordinary ARP frame from a host on the segment. Its address is
        // on-link in fact, and unknowable as such with no ranges to check it
        // against.
        listener.read(&captured(arp_reply_frame(Ipv4Addr::new(10, 0, 0, 1))));

        let host = ctx.hosts_snapshot().remove(0);
        assert_eq!(host.primary_ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(
            !host.network_roles().contains(&NetworkRole::Router),
            "with no link addressing known, off-link is not a question with an answer"
        );
    }

    /// The default scope, and the difference between an inventory and a
    /// transcript.
    ///
    /// A link carrying traffic to anywhere else carries evidence about
    /// everywhere else. Every server a laptop opens a connection to is a real
    /// host, really up, with a really open port — all true, and on a busy uplink
    /// most of what an unnarrowed report would contain.
    #[test]
    fn the_default_records_this_links_machines_and_not_what_merely_crosses_it() {
        use crate::protocols::tcp::flags;

        let local = Ipv4Addr::new(10, 0, 0, 5);
        let elsewhere = Ipv4Addr::new(93, 184, 216, 34);

        let (mut listener, ctx) = listening_on_a_known_link(Recording::Attached);

        // A server on this segment answering somebody: an asset.
        listener.read(&captured(tcp_frame(
            local,
            443,
            Ipv4Addr::new(10, 0, 0, 9),
            51234,
            flags::SYN | flags::ACK,
        )));
        // A server on the far side of the router answering somebody here:
        // true, and not this network.
        listener.read(&captured(tcp_frame(
            elsewhere,
            443,
            Ipv4Addr::new(10, 0, 0, 9),
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
            Ipv4Addr::new(10, 0, 0, 9),
            51235,
            flags::SYN | flags::ACK,
        )));
        assert_eq!(
            ctx.host_count(),
            1,
            "nothing extra was captured; what changed is what may be recorded"
        );
    }

    /// A link that states no addressing cannot narrow by it, and admits
    /// everything rather than nothing.
    ///
    /// A capture interface on a mirror port routinely holds no address. A
    /// listener that silently recorded nothing there would look exactly like a
    /// quiet network, which is the worst of the available behaviours.
    #[test]
    fn a_link_with_no_addressing_of_its_own_records_what_it_hears() {
        let (mut listener, ctx) = listening(Recording::Attached);

        listener.read(&captured(arp_reply_frame(Ipv4Addr::new(10, 0, 0, 1))));

        assert_eq!(ctx.host_count(), 1);
    }

    /// The stack reading the active path takes from a probe's reply, on a
    /// segment that was arriving anyway.
    ///
    /// The packet is a real Linux shape — hop counter 64, options
    /// `M,S,T,N,W`, timestamps and SACK — which is what
    /// `assets/fingerprinting/os/linux.toml` describes. Anything less specific
    /// classifies as nothing, and a test asserting on it would be measuring the
    /// corpus rather than this wiring.
    ///
    /// `Off` is the half that matters most. It costs no packets to disobey,
    /// which is exactly why it has to be obeyed: a caller who asked for a report
    /// containing only what they requested should not find a fingerprint in it.
    #[test]
    fn a_stack_is_read_from_a_reply_that_was_arriving_anyway() {
        let frame = || {
            let mut bytes = crate::protocols::ethernet::create_header(
                PEER_MAC,
                PEER_MAC,
                pnet::packet::ethernet::EtherTypes::Ipv4,
            );
            bytes.extend_from_slice(&[
                0x45, 0x00, 0x00, 0x3c, 0xbe, 0xef, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00,
                0x00, 0x05, 0x0a, 0x00, 0x00, 0x09, 0x01, 0xbb, 0xc3, 0x50, 0x00, 0x00, 0x00, 0x01,
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

    /// A listener may raise a claim and never lower one.
    ///
    /// It sent nothing, so it cannot have timed anything out, so there is no
    /// silence it is entitled to read as absence. This is the rule the whole
    /// phase turns on, and the one a future edit is most likely to break by
    /// making a reader "correct" a host it disagrees with.
    #[test]
    fn a_listener_never_lowers_a_claim_already_on_the_record() {
        let (mut listener, ctx) = listening(Recording::Everything);

        let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut known = Host::new(address);
        known.set_status(HostStatus::Up);
        known.set_hostname(Some("already-known".to_owned()));
        ctx.write_host(known.scoped_ip(), |host| {
            host.merge(known);
            true
        });

        listener.read(&captured(arp_reply_frame(Ipv4Addr::new(10, 0, 0, 2))));

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
}
