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
//!
//! ## What it costs to run for a week
//!
//! The other two phases are bounded by their own enumeration: a sweep of a
//! `/16` records at most sixty-five thousand hosts because that is how many it
//! asked about. This one asked about nothing and stops when somebody stops it,
//! so what it holds grows with the *traffic* rather than with a plan — and on
//! [`Recording::Everything`] over a link that carries traffic to anywhere else,
//! that is most of the internet.
//!
//! Three things are bounded rather than left to the network to size, each named
//! by a constant at the top of this file: `MAX_RECORDED_HOSTS` is the machines a
//! watch will record, `MAX_DECLARING_MACS` the claims it will hold against
//! machines it has not identified, and `LISTEN_QUEUE_DEPTH` the frames waiting
//! to be read. Each reports itself when it bites, because a limit that is silent
//! is indistinguishable from a quiet network — which is the same reason the drop
//! counter is read at the end of every run.

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

/// How many machines a watch will record before it stops taking new ones.
///
/// **The one phase with no end of its own needs a ceiling somewhere.** The other
/// two are bounded by their own enumeration: a sweep of a `/16` records at most
/// sixty-five thousand hosts because that is how many it asked about. A listener
/// asked about nothing, runs until somebody stops it, and records whatever
/// arrives — so on [`Recording::Everything`] over a transit link the report
/// grows with the *traffic*, and a watch left up for a week is a watch that runs
/// the machine out of memory.
///
/// A `/16` of machines, which is far more than any single segment carries, so
/// the default [`Recording::Attached`] scope will not reach it on a real link.
/// What reaches it is the wide scope on a busy uplink, which is exactly the case
/// this exists for.
///
/// **Reaching it stops new records and never touches the ones already made.**
/// Evicting would be this phase lowering a claim, which §2 of this module
/// forbids — a host dropped to make room is indistinguishable in the report from
/// a host that was never heard. Refusing is visible instead: it is reported as a
/// failure, so the report says the inventory is short and the run's exit status
/// says so too.
const MAX_RECORDED_HOSTS: usize = 65_536;

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
    use pnet_packet::ethernet::EtherTypes;
    use pnet_packet::ip::IpNextHeaderProtocols;

    let packet = frame.payload();
    let (header_len, next) = match frame.ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = pnet_packet::ipv4::Ipv4Packet::new(packet)?;
            (
                usize::from(ipv4.get_header_length()) * 4,
                ipv4.get_next_level_protocol(),
            )
        }
        EtherTypes::Ipv6 => (
            crate::protocols::sizes::IP_V6_HDR_LEN,
            pnet_packet::ipv6::Ipv6Packet::new(packet)?.get_next_header(),
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

        for interface in crate::system::interface::interfaces() {
            if !links.iter().any(|link| link.name() == interface.name()) {
                continue;
            }
            // The prefix already names the range, both ends included, so there
            // is no pair of addresses here to reconcile — and no way for the two
            // halves to disagree about which family they are.
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

/// What the equipment on the far end of this machine's cable says about itself,
/// whichever protocol it said it in.
///
/// LLDP and CDP answer the same four questions in different words — what the
/// device calls itself, which of its ports this frame left by, which VLAN that
/// port places untagged traffic in, and an address the device is managed at —
/// and a listener does exactly the same thing with all four answers. Reading
/// both into one shape here is what keeps [`read_announcement`] from being one
/// routine written twice, which is what it was.
///
/// [`read_announcement`]: PassiveListener::read_announcement
struct Announced<'a> {
    /// Which protocol carried it. The one field that survives *because* the two
    /// differ: an attachment records whose word it is on.
    source: AttachmentSource,
    /// What the device calls itself, which on managed equipment is its hostname.
    device_name: Option<&'a str>,
    /// What the device calls the port this frame left by — which is the port
    /// this machine is plugged into, and the finding no probe can obtain.
    port: Option<&'a str>,
    /// The VLAN this port places untagged traffic in.
    native_vlan: Option<u16>,
    /// An address the device is managed at, where it advertised one.
    management_address: Option<IpAddr>,
    /// What the device says it is **doing**, never merely what it supports.
    ///
    /// Both capability words distinguish the two, and reading the wrong one
    /// would put a router on every access switch with an unused routing
    /// licence. The predicates called below are the enabled ones.
    roles: Vec<NetworkRole>,
}

impl<'a> Announced<'a> {
    /// Reads `frame` as whichever of the two announcements it is, or `None`
    /// where it is neither.
    ///
    /// LLDP first, because it is the standard one and the one a mixed estate
    /// runs; CDP is reached only where that found nothing, so a device speaking
    /// both is read once and under one source.
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
                // Only the text spelling. A chassis-shaped port identifier — a
                // MAC, an address — names the port in a vocabulary nobody can
                // read back to a patch panel, which is what this is read for.
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
            // `is_switch` where LLDP says `is_bridge`: each protocol's own word
            // for the same behaviour, and the reason this normalising step
            // exists rather than one of them being renamed to match the other.
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
/// The third strategy beside [`HostScanner`](super::HostScanner) and
/// [`PortScanner`](super::PortScanner), and its shape differs from both because
/// what it does differs from both. A `HostScanner` owns targets and finishes
/// when it has asked about all of them; a `PortScanner` is fed targets and
/// finishes when the stream ends. A listener owns no targets, enumerates
/// nothing, and has no state that can be complete — it finishes when it is told
/// to, and not before.
///
/// Findings go to the [`ScanContext`] it was built with, as they do for the
/// other two: a strategy writes what it found, and returns only whether the
/// attempt itself got to the end.
pub struct PassiveListener {
    ctx: ScanContext,
    frames: FrameStream,
    /// Kept for as long as this listener runs: dropping it stops the capture
    /// threads.
    capture: capture::CaptureGuard,
    recording: Recording,
    on_link: OnLink,
    /// When this listener stops of its own accord, if it was given a span.
    ///
    /// Held here rather than expressed by aborting the scan, though aborting
    /// would have been fewer lines. The abort signal means *a caller asked this
    /// to stop*, and a front end reads it to decide whether a run was
    /// interrupted — so a watch that reached the end of the time it was asked
    /// for and set the same flag would report itself as interrupted, and
    /// `zond listen --for 10m || alert` would fire an alert every ten minutes.
    ///
    /// One signal, one meaning. A watch ending on schedule is not a watch
    /// somebody stopped.
    deadline: Option<tokio::time::Instant>,

    /// How far this listener may go to name the system behind a host.
    ///
    /// A listener cannot be *active* whatever this says — it sends nothing —
    /// so the only distinction it can honour is between reading the stacks it
    /// hears and not reading them. `Off` is obeyed rather than ignored on the
    /// grounds that it costs no packets to disobey: a caller who asked for a
    /// report containing only what they requested should not find a fingerprint
    /// in it.
    os: OsDetection,
    /// The record each hardware address is kept under: the first address the
    /// machine was seen at.
    ///
    /// Two things depend on it. A device answering at four addresses is one
    /// record rather than four, and a claim made about a *machine* — a router
    /// identified only by the frames it forwards — can be applied to the host it
    /// turns out to be.
    ///
    /// **Seeded from whatever the store already holds**, which is what makes a
    /// resumed watch add to its earlier sittings instead of starting a second
    /// record per machine — see [`paired_with_known_hosts`]. Beyond that it
    /// grows only from frames that produced a finding, which the recording
    /// filter has already narrowed.
    ///
    /// [`paired_with_known_hosts`]: PassiveListener::paired_with_known_hosts
    mac_to_ip: HashMap<MacAddr, ScopedIp>,
    /// What a machine said about itself before this listener knew which host it
    /// was.
    ///
    /// Bounded for the reason the local sweep's equivalent is: this grows from
    /// traffic nobody solicited, so a segment full of strangers decides how
    /// large it gets unless something else does.
    declared: HashMap<MacAddr, HashSet<NetworkRole>>,
    /// How many records this watch is holding, counted as it creates them.
    ///
    /// Counted rather than asked of the store per frame: [`ScanContext::write_host`]
    /// already reports whether a write created a record, so the exact figure is
    /// free where reading the map's length on every finding would not be.
    ///
    /// Starts at whatever the store already holds, so a resumed watch's earlier
    /// sittings count towards the ceiling they contributed to.
    ///
    /// [`ScanContext::write_host`]: crate::scanner::session::ScanContext::write_host
    held: usize,
    /// Whether the ceiling has been reported, so that it is said once rather
    /// than on every frame after it bites.
    said_full: bool,
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

    /// Builds a listener over a caller-supplied frame stream, opening no capture.
    ///
    /// The listening twin of
    /// [`EthernetHandle::from_parts`](crate::transport::channel::EthernetHandle::from_parts):
    /// whatever is pushed onto the sending half of `frames` arrives as though it
    /// had been captured off `on_link`, with no interface, no capture and no
    /// privileges involved. That is what lets a listener be driven against a
    /// synthetic segment from outside this crate.
    ///
    /// There is no sending half to supply, unlike the other two seams. A
    /// listener never transmits, so a fake segment aimed at one only has to
    /// speak.
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
            protocols: discovery::sweep_protocols(),
        }
    }

    /// The hardware address of every machine the store already knows, paired
    /// with the record it is kept under.
    ///
    /// **This is what makes a resumed watch one watch.** A sitting keys each
    /// machine by the first address it hears that machine at, and which address
    /// that is depends only on which frame happened to arrive first. Starting a
    /// second sitting with an empty pairing means the same laptop, restored
    /// under `10.0.0.5` and heard tonight from `fe80::…`, gets a second record
    /// — and a watch resumed three times reports one machine as four.
    ///
    /// Which is the failure [`record`](Self::record) was shaped to avoid within
    /// a sitting. Seeding here extends the same rule across them: the pairing
    /// begins as whatever the earlier sittings concluded rather than as nothing.
    ///
    /// Empty for a watch that was not resumed, since the store is.
    fn paired_with_known_hosts(ctx: &ScanContext) -> HashMap<MacAddr, ScopedIp> {
        let mut pairs = HashMap::new();

        // Sorted, because the store is a sharded map and hands its keys back in
        // no particular order. Two records under one hardware address is a
        // machine some earlier sitting split, and which of them tonight's
        // sighting rejoins should not depend on how a hash landed.
        let mut keys = ctx.host_addresses();
        keys.sort_unstable();

        for key in keys {
            let Some(Some(mac)) = ctx.read_host(key.clone(), Host::mac) else {
                // No hardware address is no way to recognise it again — the
                // same reason `record` merges such a host by address alone.
                continue;
            };
            // The lowest address wins, which is arbitrary and only has to be
            // decidable: what matters is that the split stops growing.
            pairs.entry(mac).or_insert(key);
        }

        pairs
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

    /// Stops this listener after `span`, rather than waiting to be told.
    ///
    /// The watch ends on its own terms: nothing is aborted, so a caller reading
    /// the abort signal still sees the truth, which is that nobody interrupted
    /// anything.
    pub fn stopping_after(mut self, span: std::time::Duration) -> Self {
        self.deadline = Some(tokio::time::Instant::now() + span);
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

        if self.read_endpoint(&frame, captured) {
            return;
        }
        self.read_client(&frame, &captured.zone);
        self.read_presence(&frame, &captured.zone);
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
                self.record(host, &captured.zone);
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
    fn read_endpoint(&mut self, frame: &Frame<'_>, captured: &CapturedFrame) -> bool {
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

        self.record(host, zone);
    }

    /// Records that whoever sent this frame is present, where a reader
    /// recognises it.
    ///
    /// The readers are a local sweep's own, used unchanged: a neighbour
    /// advertisement, an ARP frame or a DHCP server's answer proves its sender
    /// is there, and it proves it whether or not this engine asked the question
    /// that drew it.
    fn read_presence(&mut self, frame: &Frame<'_>, zone: &Zone) {
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
            self.record(host, zone);
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

    /// Folds a finding into the store under `key`, promoting rather than
    /// replacing.
    ///
    /// **Every finding this listener records passes through here**, which is
    /// what lets the ceiling be one branch rather than a rule each reader has to
    /// remember.
    ///
    /// [`Host::merge`] is what keeps a listener from ever lowering a claim: it
    /// promotes status and accumulates addresses, hardware addresses and roles,
    /// and where two findings are equally good the one already recorded wins.
    fn store(&mut self, key: ScopedIp, host: Host) {
        // At the ceiling a record that already exists still takes everything
        // this frame proves — the phase goes on raising claims about what it is
        // holding. What it stops doing is starting new ones.
        if self.held >= MAX_RECORDED_HOSTS && !self.ctx.holds_host(&key) {
            self.report_full();
            return;
        }

        // Counted from the store's own answer rather than from having called it.
        // An address the scan's exclusions forbid is dropped inside `write_host`
        // and creates nothing, and a ceiling counting those would come down
        // early on a run that had excluded a range.
        if self.ctx.write_host(key, |existing| {
            existing.merge(host);
            true
        }) {
            self.held += 1;
        }
    }

    /// Says once that this watch has stopped taking new machines.
    ///
    /// Through [`record_failure`] rather than a bare log line, so it reaches the
    /// report and not only the terminal: a watch that hit its ceiling produced a
    /// short inventory, and a reader coming to that report a month later has no
    /// other way to know it. It is what makes the run exit as a partial one.
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
    /// The pairing is what lets a claim made about a *machine* reach the host it
    /// turns out to be: a router is identified by the hardware address on the
    /// frames it forwards and by nothing else, and a switch announcing itself
    /// usually holds no address on the segment it serves.
    ///
    /// Anything already held against that hardware address is applied here, so a
    /// claim that arrived before its sender was identified is not lost — which
    /// is the common order, since a router forwards constantly and speaks for
    /// itself rarely.
    fn record(&mut self, mut host: Host, zone: &Zone) {
        // Every frame this listener reads came off a link it was pointed at, so
        // a host it records was observed through that interface. A link-local
        // address is meaningless without it.
        host.set_zone(zone.clone());

        let Some(mac) = host.mac() else {
            // Nothing to recognise it by again. A host with no hardware address
            // is one seen from off the link, where the address on the frame
            // belongs to the last hop rather than to the sender.
            let key = host.scoped_ip();
            self.store(key, host);
            return;
        };

        for role in self.declared.remove(&mac).into_iter().flatten() {
            host.add_network_role(role);
        }

        // **The record is keyed by the machine, not by the address.** A device
        // answers at every address it holds — a v4 address, a global v6 address
        // or three, a link-local — and each arrives on its own frame. Keyed by
        // whichever address that frame carried, one machine becomes four
        // records, which is the failure `Host` is shaped to avoid and which
        // this had until the first run against a real segment showed a laptop
        // reported as four hosts and a router as two.
        //
        // The first address the machine was seen at keys it, and every later
        // one joins that record through [`Host::merge`] — which ranks the
        // addresses rather than taking the newest, so which reply arrived first
        // decides nothing about how the host is reported. A resumed watch
        // begins with the earlier sittings' pairings already in hand, so "the
        // first address" spans the whole watch rather than this sitting of it.
        let known = self.mac_to_ip.get(&mac).cloned();
        let key = known.clone().unwrap_or_else(|| host.scoped_ip());

        self.store(key.clone(), host);

        // Filed for a machine that had no record, and only once the store
        // actually holds one under this key.
        //
        // **Two things can decline the write**, and a pairing that survived
        // either would name a record nothing is kept under: every later sighting
        // of the machine would be routed to that key and dropped, and
        // `note_declaration` would write through it — which is the one path into
        // the store that does not come back through [`store`](Self::store).
        //
        // The ceiling is one. The scan's exclusions are the other, and they
        // matter more here than the count does: a machine holding an excluded
        // address alongside an ordinary one would otherwise be keyed by
        // whichever arrived first, and a frame from the address nobody excluded
        // would be thrown away because the machine had once spoken from the
        // address somebody did.
        //
        // Asked once per machine rather than once per frame, since a machine
        // already paired takes neither branch.
        if known.is_none() && self.ctx.holds_host(&key) {
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
            if self
                .deadline
                .is_some_and(|at| tokio::time::Instant::now() >= at)
            {
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
            pnet_base::MacAddr(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E),
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
                            pnet_packet::ethernet::EtherTypes::Ipv4,
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
        mac: pnet_base::MacAddr,
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
                pnet_packet::ethernet::EtherTypes::Ipv4,
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

        const ROUTER_MAC: pnet_base::MacAddr = pnet_base::MacAddr(2, 0, 0, 0, 0, 0xAA);
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
                pnet_packet::ethernet::EtherTypes::Ipv4,
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

    /// A watch that reached the end of the time it was asked for is not a watch
    /// somebody stopped.
    ///
    /// It ends on its own terms, leaving the abort signal alone — because a
    /// front end reads that signal to decide whether a run was interrupted, and
    /// a timed watch raising it would make `zond listen --for 10m || alert` fire
    /// an alert every ten minutes.
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
        // Already past when the loop first looks, so the test costs no
        // wall-clock time and does not depend on a timer firing.
        .stopping_after(std::time::Duration::ZERO);

        listener.observe().await.expect("the watch runs to its end");

        assert!(
            !ctx.handle.should_stop(),
            "nobody asked it to stop, so nothing may say they did"
        );
    }

    /// A device answering at four addresses is one device.
    ///
    /// Found on the first run against a real segment: this laptop was reported
    /// as four hosts and the router as two, because each address arrived on its
    /// own frame and each frame made its own record. `discover` has always keyed
    /// by the machine; this had been keying by whichever address the frame in
    /// hand happened to carry.
    #[test]
    fn one_machine_answering_at_several_addresses_is_one_host() {
        use crate::protocols::tcp::flags;

        const MAC: pnet_base::MacAddr = pnet_base::MacAddr(2, 0, 0, 0, 0, 0xAA);
        let peer = Ipv4Addr::new(10, 0, 0, 9);

        let (mut listener, ctx) = listening_on_a_known_link(Recording::Everything);

        // The same machine answering at two of its addresses, on two frames —
        // which is the only way a listener ever sees it, and the shape that
        // used to produce two records.
        let first = Ipv4Addr::new(10, 0, 0, 5);
        let second = Ipv4Addr::new(10, 0, 0, 6);

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

    /// A machine restored from an earlier sitting is the same machine tonight.
    ///
    /// A sitting keys each machine by the first address it hears it at, and
    /// which address that is depends only on which frame happened to arrive
    /// first. So a second sitting starting with an empty pairing re-keys every
    /// machine it hears — and the laptop restored under `10.0.0.5` and heard
    /// tonight from `10.0.0.6` becomes a second record, with a third waiting
    /// for the next restart.
    ///
    /// Which is `one_machine_answering_at_several_addresses_is_one_host` again,
    /// reintroduced across sittings by the one feature that exists to prevent
    /// it: the whole argument for resuming a watch is that a listener left up
    /// for a week across three restarts produces one record of the week.
    #[test]
    fn a_machine_restored_from_an_earlier_sitting_is_not_recorded_twice() {
        use crate::protocols::tcp::flags;

        const MAC: pnet_base::MacAddr = pnet_base::MacAddr(2, 0, 0, 0, 0, 0xAA);
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let first = Ipv4Addr::new(10, 0, 0, 5);
        let second = Ipv4Addr::new(10, 0, 0, 6);

        // What an earlier sitting wrote down, restored into the store before
        // this one starts — which is what `listen_with_journal` does, and the
        // reason the pairing has to be read from the store rather than begun
        // empty.
        let (_session, ctx) = ScanSession::new();
        let mut earlier = Host::new(IpAddr::V4(first));
        earlier.record_mac(MAC.into_core());
        earlier.set_zone(zone());
        earlier.record_evidence(
            HostStatus::Up,
            StatusReason::new(StatusProtocol::Tcp, "heard last night"),
        );
        ctx.restore_hosts(&[earlier]);
        assert_eq!(ctx.host_count(), 1, "the sitting starts with one machine");

        let (_tx, rx) = tokio::sync::mpsc::channel(16);
        let mut ranges = IpSet::new();
        ranges.insert_range("10.0.0.0/24".parse().expect("a valid range"));
        let mut listener = PassiveListener::over(
            rx,
            capture::CaptureGuard::noop(),
            Recording::Everything,
            OnLink::of(ranges),
            ctx.clone(),
        );

        // Tonight the same machine is heard first at its *other* address, which
        // is the ordinary case: a device answers at everything it holds and
        // nothing decides which frame arrives first.
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

    /// A host with no hardware address cannot be paired, and seeding must not
    /// invent one for it.
    ///
    /// The restored store holds both kinds: machines on the link, which carry a
    /// MAC, and hosts heard from off it through a router, which deliberately do
    /// not — see `read_endpoint`. Reading a MAC off the second kind is the
    /// mistake this guards, and it would be the same one the endpoint reader
    /// refuses: crediting a router's hardware to a machine somewhere else.
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
    /// down with it.
    ///
    /// The exclusion policy is enforced inside the store, so a write naming an
    /// excluded address creates nothing. The pairing has to notice: filed anyway,
    /// it would key the machine by an address nothing is kept under, and every
    /// later frame from the machine — including from the address nobody
    /// excluded — would be routed to that key and dropped. A machine would then
    /// disappear from the report for having once spoken from an address somebody
    /// asked to leave alone.
    #[test]
    fn a_machine_that_spoke_from_an_excluded_address_is_still_recorded_at_its_others() {
        use crate::model::exclusion::Exclusions;
        use crate::protocols::tcp::flags;

        const MAC: pnet_base::MacAddr = pnet_base::MacAddr(2, 0, 0, 0, 0, 0xAA);
        let excluded = Ipv4Addr::new(10, 0, 0, 5);
        let ordinary = Ipv4Addr::new(10, 0, 0, 6);
        let peer = Ipv4Addr::new(10, 0, 0, 9);

        let mut forbidden = IpSet::new();
        forbidden.insert(IpAddr::V4(excluded));
        let (_session, ctx) = ScanSession::with_exclusions(Exclusions::new(forbidden));

        let (_tx, rx) = tokio::sync::mpsc::channel(16);
        let mut ranges = IpSet::new();
        ranges.insert_range("10.0.0.0/24".parse().expect("a valid range"));
        let mut listener = PassiveListener::over(
            rx,
            capture::CaptureGuard::noop(),
            Recording::Everything,
            OnLink::of(ranges),
            ctx.clone(),
        );

        // The excluded address first, so it is the one that would have keyed the
        // machine.
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

    /// The one phase with no end of its own needs a ceiling, and reaching it
    /// stops new records without touching the ones already made.
    ///
    /// Evicting instead would be this phase lowering a claim: a host dropped to
    /// make room reads in the report exactly like a host that was never heard,
    /// and there would be nothing to say which. So the refusal is the visible
    /// half — it is reported as a failure, which is what makes the run's own
    /// exit status say the inventory came up short.
    #[test]
    fn a_watch_at_its_ceiling_stops_taking_machines_and_keeps_enriching_the_ones_it_has() {
        use crate::protocols::tcp::flags;

        const HELD_MAC: pnet_base::MacAddr = pnet_base::MacAddr(2, 0, 0, 0, 0, 0xAA);
        const STRANGER_MAC: pnet_base::MacAddr = pnet_base::MacAddr(2, 0, 0, 0, 0, 0xBB);

        let (mut listener, ctx) = listening_on_a_known_link(Recording::Everything);
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let known = Ipv4Addr::new(10, 0, 0, 5);

        // One machine on record, then already full — without standing up
        // sixty-five thousand hosts to get there. What is under test is the
        // branch, not the arithmetic that reaches it.
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
            Ipv4Addr::new(10, 0, 0, 200),
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

    /// LLDP and CDP say the same four things in different words, and a listener
    /// does the same thing with all four — so they are read through one
    /// normalising step rather than two routines that happen to agree.
    ///
    /// A field mismapped there is silent in a way most parsing mistakes are
    /// not: the attachment still records, just with no port on it, or with the
    /// management address in place of a VLAN. Nothing errors and the line in
    /// the terminal still appears.
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
                Some(device_mac.into_core()),
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
                Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                "{spoken}: where the device is managed"
            );

            // Both frames advertise bridging *and* routing as enabled, which is
            // where the two protocols' vocabularies differ: LLDP calls it a
            // bridge and CDP calls it a switch.
            let host = ctx
                .hosts_snapshot()
                .into_iter()
                .find(|host| host.primary_ip() == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
                .unwrap_or_else(|| panic!("{spoken}: the device named an address of its own"));
            let roles = host.network_roles();
            assert!(
                roles.contains(&NetworkRole::Switch) && roles.contains(&NetworkRole::Router),
                "{spoken}: both enabled capabilities reached the host: {roles:?}"
            );
        }
    }
}
